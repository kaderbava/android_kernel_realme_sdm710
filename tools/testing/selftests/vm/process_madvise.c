// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef MADV_COLD
#define MADV_COLD 20
#endif
#ifndef MADV_PAGEOUT
#define MADV_PAGEOUT 21
#endif
#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif
#ifndef __NR_process_madvise
#define __NR_process_madvise 440
#endif

#define LENGTH (16UL << 20)
#define HUGE (2UL << 20)
static unsigned int passed, failed;
static size_t pagesize;

static void check(bool ok, const char *name)
{
	printf("%s %u - %s", ok ? "ok" : "not ok",
	       passed + failed + 1, name);
	if (!ok)
		printf(" (errno=%d: %s)", errno, strerror(errno));
	putchar('\n');
	if (ok)
		passed++;
	else
		failed++;
}

static unsigned char value(size_t offset)
{
	return 1 + (offset / 64 + offset / pagesize) % 251;
}

static void fill(unsigned char *p, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		p[i] = value(i);
}

static bool intact(const unsigned char *p, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		if (p[i] != value(i))
			return false;
	return true;
}

static unsigned char *mapping(size_t len)
{
	unsigned char *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (p == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}
	madvise(p, len, MADV_NOHUGEPAGE);
	fill(p, len);
	return p;
}

static long swapped(pid_t pid)
{
	char path[64], line[256];
	FILE *f;
	long kb = -1;

	snprintf(path, sizeof(path), "/proc/%d/status", pid);
	f = fopen(path, "r");
	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f))
		if (sscanf(line, "VmSwap: %ld kB", &kb) == 1)
			break;
	fclose(f);
	return kb;
}

static long huge_kb(void *address)
{
	FILE *f = fopen("/proc/self/smaps", "r");
	char line[256];
	unsigned long start, end;
	long kb = 0;
	bool found = false;

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%lx-%lx", &start, &end) == 2)
			found = (uintptr_t)address >= start &&
				(uintptr_t)address < end;
		if (found && sscanf(line, "AnonHugePages: %ld kB", &kb) == 1)
			break;
	}
	fclose(f);
	return kb;
}

static long resident(void *p, size_t len)
{
	size_t n = (len + pagesize - 1) / pagesize, i;
	unsigned char *vec = calloc(n, 1);
	long result = 0;

	if (!vec)
		return -1;
	if (mincore(p, len, vec))
		result = -1;
	else
		for (i = 0; i < n; i++)
			result += !!(vec[i] & 1);
	free(vec);
	return result;
}

static ssize_t advise(int fd, struct iovec *v, size_t n, int advice,
		      unsigned int flags)
{
	return syscall(__NR_process_madvise, fd, v, n, advice, flags);
}

static void local_tests(void)
{
	unsigned char *p = mapping(LENGTH);
	long before = swapped(getpid());

	check(!madvise(p, LENGTH, MADV_COLD), "MADV_COLD accepted");
	check(intact(p, LENGTH), "MADV_COLD preserves every byte");
	check(!madvise(p, LENGTH, MADV_PAGEOUT), "MADV_PAGEOUT accepted");
	printf("# local VmSwap: %ld -> %ld KiB\n",
	       before, swapped(getpid()));
	check(swapped(getpid()) - before >= (long)(LENGTH / 2048),
	      "MADV_PAGEOUT moves private anonymous pages to swap");
	check(resident(p, LENGTH) < (long)(LENGTH / pagesize / 2),
	      "paged-out mapping loses resident pages");
	check(intact(p, LENGTH), "swapped pages return with all bytes intact");
	check(!mlock(p, pagesize), "lock a page");
	errno = 0;
	check(madvise(p, pagesize, MADV_PAGEOUT) == -1 && errno == EINVAL,
	      "MADV_PAGEOUT rejects a locked VMA");
	errno = 0;
	check(madvise(p, pagesize, MADV_COLD) == -1 && errno == EINVAL,
	      "MADV_COLD rejects a locked VMA");
	check(intact(p, pagesize), "locked data remains intact");
	munlock(p, pagesize);
	munmap(p, LENGTH);
}

static void cow_test(void)
{
	unsigned char *p = mapping(LENGTH);
	int ready[2], release[2], status;
	pid_t child;
	char byte;

	if (pipe(ready) || pipe(release))
		exit(1);
	child = fork();
	if (!child) {
		close(ready[0]);
		close(release[1]);
		if (write(ready[1], "r", 1) != 1 ||
		    read(release[0], &byte, 1) != 1)
			_exit(2);
		_exit(intact(p, LENGTH) ? 0 : 1);
	}
	if (child < 0)
		exit(1);
	close(ready[1]);
	close(release[0]);
	check(read(ready[0], &byte, 1) == 1, "child holds CoW mapping");
	check(!madvise(p, LENGTH, MADV_PAGEOUT), "advise CoW mapping");
	check(resident(p, LENGTH) == (long)(LENGTH / pagesize),
	      "shared CoW pages are not evicted");
	check(intact(p, LENGTH), "parent CoW data preserved");
	check(write(release[1], "r", 1) == 1, "release CoW child");
	waitpid(child, &status, 0);
	check(WIFEXITED(status) && !WEXITSTATUS(status),
	      "child CoW data preserved");
	close(ready[0]);
	close(release[1]);
	munmap(p, LENGTH);
}

struct remote {
	unsigned char *p;
	unsigned char *hole;
};

static void remote_tests(void)
{
	int ready[2], release[2], status, fd, self;
	struct remote remote;
	struct iovec vec[3];
	pid_t child, probe;
	char byte;
	long before;

	if (pipe(ready) || pipe(release))
		exit(1);
	child = fork();
	if (!child) {
		close(ready[0]);
		close(release[1]);
		remote.p = mapping(LENGTH);
		remote.hole = mapping(3 * pagesize);
		munmap(remote.hole + pagesize, pagesize);
		if (write(ready[1], &remote, sizeof(remote)) !=
		    sizeof(remote) || read(release[0], &byte, 1) != 1)
			_exit(2);
		_exit(intact(remote.p, LENGTH) ? 0 : 1);
	}
	if (child < 0)
		exit(1);
	close(ready[1]);
	close(release[0]);
	if (read(ready[0], &remote, sizeof(remote)) != sizeof(remote))
		exit(1);
	fd = syscall(__NR_pidfd_open, child, 0);
	check(fd >= 0, "open target pidfd");
	vec[0] = (struct iovec){ remote.p, LENGTH };
	check(advise(fd, vec, 1, MADV_COLD, 0) == LENGTH,
	      "remote MADV_COLD reports advised bytes");
	before = swapped(child);
	check(advise(fd, vec, 1, MADV_PAGEOUT, 0) == LENGTH,
	      "remote MADV_PAGEOUT reports advised bytes");
	printf("# remote VmSwap: %ld -> %ld KiB\n", before, swapped(child));
	check(swapped(child) - before >= (long)(LENGTH / 2048),
	      "reclaim targets the remote address space");
	errno = 0;
	check(advise(fd, vec, 1, MADV_DONTNEED, 0) == -1 &&
	      errno == EINVAL, "remote destructive advice rejected");
	errno = 0;
	check(advise(fd, vec, 1, MADV_COLD, 1) == -1 && errno == EINVAL,
	      "unknown flags rejected");
	errno = 0;
	check(advise(-1, vec, 1, MADV_COLD, 0) == -1 && errno == EBADF,
	      "invalid pidfd rejected");
	errno = 0;
	check(advise(ready[0], vec, 1, MADV_COLD, 0) == -1 &&
	      errno == EBADF, "ordinary file descriptor rejected");
	errno = 0;
	check(advise(fd, vec, 1025, MADV_COLD, 0) == -1 &&
	      errno == EINVAL, "too many iovecs rejected before copying");
#if __SIZEOF_SIZE_T__ == 8
	errno = 0;
	check(advise(fd, vec, (1UL << 32) + 1, MADV_COLD, 0) == -1 &&
	      errno == EINVAL, "64-bit iovec count cannot truncate");
#endif
	errno = 0;
	check(advise(fd, (void *)1, 1, MADV_COLD, 0) == -1 &&
	      errno == EFAULT, "bad iovec pointer rejected");
	check(advise(fd, NULL, 0, MADV_COLD, 0) == 0,
	      "empty vector returns zero");
	vec[0] = (struct iovec){ remote.p, 0 };
	vec[1] = (struct iovec){ remote.p, pagesize };
	check(advise(fd, vec, 2, MADV_COLD, 0) == (ssize_t)pagesize,
	      "zero-length iovec does not stall iteration");
	vec[0].iov_len = pagesize;
	vec[1] = (struct iovec){ remote.p + 1, pagesize };
	check(advise(fd, vec, 2, MADV_COLD, 0) == (ssize_t)pagesize,
	      "partial success takes precedence over later error");
	errno = 0;
	check(advise(fd, &vec[1], 1, MADV_COLD, 0) == -1 &&
	      errno == EINVAL, "unaligned target address rejected");
	vec[0] = (struct iovec){ remote.hole, 3 * pagesize };
	errno = 0;
	check(advise(fd, vec, 1, MADV_COLD, 0) == -1 &&
	      errno == ENOMEM, "unmapped hole retains madvise error semantics");

	probe = fork();
	if (probe < 0)
		exit(1);
	if (!probe) {
		struct __user_cap_header_struct h = {
			.version = _LINUX_CAPABILITY_VERSION_3,
		};
		struct __user_cap_data_struct caps[2];

		if (syscall(SYS_capget, &h, caps))
			_exit(2);
		caps[0].effective &= ~(1U << CAP_SYS_NICE);
		if (syscall(SYS_capset, &h, caps))
			_exit(2);
		vec[0] = (struct iovec){ remote.p, pagesize };
		errno = 0;
		_exit(advise(fd, vec, 1, MADV_COLD, 0) == -1 &&
		      errno == EPERM ? 0 : 1);
	}
	waitpid(probe, &status, 0);
	check(WIFEXITED(status) && !WEXITSTATUS(status),
	      "CAP_SYS_NICE required even with ptrace access");

	check(write(release[1], "r", 1) == 1, "release remote child");
	waitpid(child, &status, 0);
	check(WIFEXITED(status) && !WEXITSTATUS(status),
	      "remote page-out preserves all target data");
	errno = 0;
	check(advise(fd, vec, 1, MADV_COLD, 0) == -1 && errno == ESRCH,
	      "pidfd for reaped process returns ESRCH");
	close(fd);
	close(ready[0]);
	close(release[1]);
	self = syscall(__NR_pidfd_open, getpid(), 0);
	vec[0] = (struct iovec){ NULL, 0 };
	check(advise(self, vec, 1, MADV_COLD, 0) == 0,
	      "same-process pidfd supported");
	close(self);
}

static void huge_tests(void)
{
	unsigned char *base, *p;
	long before;

	if (access("/sys/kernel/mm/transparent_hugepage/enabled", F_OK)) {
		puts("# THP cases skipped: transparent huge pages unavailable");
		return;
	}
	base = mmap(NULL, 2 * HUGE, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (base == MAP_FAILED)
		exit(1);
	p = (void *)(((uintptr_t)base + HUGE - 1) & ~(HUGE - 1));
	check(!madvise(p, HUGE, MADV_HUGEPAGE), "request huge-page mapping");
	fill(p, HUGE);
	check(huge_kb(p) >= (long)(HUGE / 1024),
	      "full reclaim starts with an allocated THP");
	before = swapped(getpid());
	check(!madvise(p, HUGE, MADV_PAGEOUT), "page out full huge mapping");
	check(swapped(getpid()) - before >= (long)(HUGE / 2048),
	      "full huge mapping reaches swap");
	check(intact(p, HUGE), "full huge-page reclaim preserves data");
	munmap(base, 2 * HUGE);

	base = mmap(NULL, 2 * HUGE, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (base == MAP_FAILED)
		exit(1);
	p = (void *)(((uintptr_t)base + HUGE - 1) & ~(HUGE - 1));
	madvise(p, HUGE, MADV_HUGEPAGE);
	fill(p, HUGE);
	check(huge_kb(p) >= (long)(HUGE / 1024),
	      "partial reclaim starts with an allocated THP");
	check(!madvise(p + pagesize, pagesize, MADV_PAGEOUT),
	      "split huge mapping for partial page-out");
	check(intact(p, HUGE), "partial huge-page reclaim preserves neighbors");
	munmap(base, 2 * HUGE);
}

int main(void)
{
	FILE *f;
	char line[256];
	long swap = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	pagesize = sysconf(_SC_PAGESIZE);
	f = fopen("/proc/meminfo", "r");
	if (f) {
		while (fgets(line, sizeof(line), f))
			if (sscanf(line, "SwapTotal: %ld kB", &swap) == 1)
				break;
		fclose(f);
	}
	if (geteuid() || swap < (long)(2 * LENGTH / 1024)) {
		puts("1..0 # SKIP requires root and at least 32 MiB of swap");
		return 4;
	}
	alarm(180);
	puts("TAP version 13");
	local_tests();
	cow_test();
	remote_tests();
	huge_tests();
	printf("1..%u\n# %u passed, %u failed\n",
	       passed + failed, passed, failed);
	return failed ? 1 : 0;
}

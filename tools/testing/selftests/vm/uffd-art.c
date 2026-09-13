// SPDX-License-Identifier: GPL-2.0
/*
 * Exercise the UFFD interfaces used by Android ART on older kernels.
 * Build against the kernel's exported headers and link with pthread.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef MFD_HUGETLB
#define MFD_HUGETLB 4
#endif
#ifndef MREMAP_DONTUNMAP
#define MREMAP_DONTUNMAP 4
#endif
#ifndef UFFDIO_COPY_MODE_MMAP_TRYLOCK
#define UFFDIO_COPY_MODE_MMAP_TRYLOCK ((__u64)1 << 63)
#define UFFDIO_ZEROPAGE_MODE_MMAP_TRYLOCK ((__u64)1 << 63)
#endif

#define CHECK(x) do {                                                   \
	if (!(x)) {                                                     \
		fprintf(stderr, "%s:%d: %s (errno=%d: %s)\n",             \
			__func__, __LINE__, #x, errno, strerror(errno));  \
		exit(1);                                                \
	}                                                               \
} while (0)
#define BIT64(n) ((__u64)1 << (n))
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static size_t ps;
static __u64 available;
static const __u64 needed = UFFD_FEATURE_SIGBUS |
	UFFD_FEATURE_MISSING_SHMEM | UFFD_FEATURE_MINOR_SHMEM;

struct region {
	char *p;
	char *alias;
	size_t len;
	int memfd;
};

static int new_uffd(__u64 features)
{
	struct uffdio_api api = { .api = UFFD_API, .features = features };
	int fd = syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK |
			 UFFD_USER_MODE_ONLY);

	CHECK(fd >= 0);
	CHECK(ioctl(fd, UFFDIO_API, &api) == 0);
	available = api.features;
	CHECK((available & needed) == needed);
	return fd;
}

static struct region region(int type, size_t len)
{
	struct region r = { .len = len, .memfd = -1 };
	int flags = type == 1 ? MAP_SHARED : MAP_PRIVATE;

	if (type) {
		r.memfd = syscall(SYS_memfd_create, "uffd-art", MFD_CLOEXEC);
		CHECK(r.memfd >= 0);
		CHECK(ftruncate(r.memfd, len) == 0);
		r.alias = mmap(NULL, len, PROT_READ | PROT_WRITE,
			       MAP_SHARED, r.memfd, 0);
		CHECK(r.alias != MAP_FAILED);
	} else {
		flags |= MAP_ANONYMOUS;
	}
	r.p = mmap(NULL, len, PROT_READ | PROT_WRITE, flags, r.memfd, 0);
	CHECK(r.p != MAP_FAILED);
	return r;
}

static __u64 reg_range(int fd, void *p, size_t len, __u64 mode)
{
	struct uffdio_register r = {
		.range = { .start = (uintptr_t)p, .len = len },
		.mode = mode,
	};

	CHECK(ioctl(fd, UFFDIO_REGISTER, &r) == 0);
	CHECK(!!(r.ioctls & BIT64(_UFFDIO_CONTINUE)) ==
	      !!(mode & UFFDIO_REGISTER_MODE_MINOR));
	return r.ioctls;
}

static void copy_page(int fd, void *dst, int value, __u64 mode)
{
	char *src = malloc(ps);
	struct uffdio_copy c = {
		.dst = (uintptr_t)dst,
		.src = (uintptr_t)src,
		.len = ps,
		.mode = mode,
	};

	CHECK(src);
	memset(src, value, ps);
	CHECK(ioctl(fd, UFFDIO_COPY, &c) == 0);
	CHECK(c.copy == (long)ps);
	free(src);
}

static void zero_page(int fd, void *dst, __u64 mode)
{
	struct uffdio_zeropage z = {
		.range = { .start = (uintptr_t)dst, .len = ps },
		.mode = mode,
	};

	CHECK(ioctl(fd, UFFDIO_ZEROPAGE, &z) == 0);
	CHECK(z.zeropage == (long)ps);
}

static void cont_page(int fd, void *dst, size_t len)
{
	struct uffdio_continue c = {
		.range = { .start = (uintptr_t)dst, .len = len },
	};

	CHECK(ioctl(fd, UFFDIO_CONTINUE, &c) == 0);
	CHECK(c.mapped == (long)len);
}

static struct uffd_msg message(int fd, unsigned int event)
{
	struct uffd_msg msg;
	struct pollfd p = { .fd = fd, .events = POLLIN };

	CHECK(poll(&p, 1, 5000) == 1);
	CHECK(p.revents & POLLIN);
	CHECK(read(fd, &msg, sizeof(msg)) == sizeof(msg));
	CHECK(msg.event == event);
	return msg;
}

static void expect_child(pid_t pid, int sig)
{
	int status;

	CHECK(waitpid(pid, &status, 0) == pid);
	if (sig)
		CHECK(WIFSIGNALED(status) && WTERMSIG(status) == sig);
	else
		CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void api_test(void)
{
	struct uffdio_api api = { .api = 0 };
	struct pollfd p;
	int fd = syscall(SYS_userfaultfd, O_NONBLOCK |
			 UFFD_USER_MODE_ONLY);

	CHECK(fd >= 0);
	p.fd = fd;
	p.events = POLLIN;
	CHECK(poll(&p, 1, 0) == 1 && (p.revents & POLLERR));
	CHECK(ioctl(fd, UFFDIO_API, &api) == -1 && errno == EINVAL);
	CHECK(api.api == 0 && api.features == 0 && api.ioctls == 0);
	api.api = UFFD_API;
	api.features = BIT64(30);
	CHECK(ioctl(fd, UFFDIO_API, &api) == -1 && errno == EINVAL);
	api.api = UFFD_API;
	api.features = 0;
	CHECK(ioctl(fd, UFFDIO_API, &api) == 0);
	CHECK((api.features & needed) == needed);
	api.api = UFFD_API;
	api.features = 0;
	CHECK(ioctl(fd, UFFDIO_API, &api) == -1 && errno == EINVAL);
	CHECK(close(fd) == 0);
	CHECK(syscall(SYS_userfaultfd, 1 << 29) == -1);
	CHECK(errno == EINVAL);
}

struct api_racer {
	int fd;
	int result;
	pthread_barrier_t *barrier;
};

static void *race_api(void *arg)
{
	struct api_racer *r = arg;
	struct uffdio_api api = { .api = UFFD_API };

	pthread_barrier_wait(r->barrier);
	r->result = ioctl(r->fd, UFFDIO_API, &api);
	CHECK(r->result == 0 || errno == EINVAL);
	return NULL;
}

static void api_race_test(void)
{
	int round;

	for (round = 0; round < 50; round++) {
		pthread_barrier_t barrier;
		pthread_t threads[8];
		struct api_racer racers[8];
		int i, winners = 0;
		int fd = syscall(SYS_userfaultfd, O_NONBLOCK |
				 UFFD_USER_MODE_ONLY);

		CHECK(fd >= 0);
		CHECK(pthread_barrier_init(&barrier, NULL, 8) == 0);
		for (i = 0; i < 8; i++) {
			racers[i] = (struct api_racer){ fd, -2, &barrier };
			CHECK(pthread_create(&threads[i], NULL, race_api,
					     &racers[i]) == 0);
		}
		for (i = 0; i < 8; i++) {
			CHECK(pthread_join(threads[i], NULL) == 0);
			winners += racers[i].result == 0;
		}
		CHECK(winners == 1);
		CHECK(pthread_barrier_destroy(&barrier) == 0);
		close(fd);
	}
}

static void copy_zero_type(int type)
{
	int fd = new_uffd(0);
	struct region r = region(type, 4 * ps);
	__u64 mask = reg_range(fd, r.p, r.len,
			       UFFDIO_REGISTER_MODE_MISSING);
	struct uffdio_copy bad = {
		.dst = (uintptr_t)r.p,
		.src = (uintptr_t)(r.p + ps),
		.len = ps,
		.mode = UFFDIO_COPY_MODE_MMAP_TRYLOCK,
	};

	CHECK(mask & BIT64(_UFFDIO_COPY));
	CHECK(mask & BIT64(_UFFDIO_ZEROPAGE));
	copy_page(fd, r.p, 0x5a, UFFDIO_COPY_MODE_MMAP_TRYLOCK);
	zero_page(fd, r.p + ps, UFFDIO_ZEROPAGE_MODE_MMAP_TRYLOCK);
	CHECK(r.p[0] == 0x5a && r.p[ps - 1] == 0x5a);
	CHECK(r.p[ps] == 0 && r.p[2 * ps - 1] == 0);
	CHECK(ioctl(fd, UFFDIO_COPY, &bad) == -1 && errno == EEXIST);
	CHECK(bad.copy == -EEXIST);
	bad.dst = (uintptr_t)(r.p + 2 * ps);
	bad.mode = UFFDIO_COPY_MODE_WP;
	if (!(available & UFFD_FEATURE_PAGEFAULT_FLAG_WP))
		CHECK(ioctl(fd, UFFDIO_COPY, &bad) == -1 &&
		      errno == EINVAL);
	if (type == 1)
		CHECK(r.alias[0] == 0x5a && r.alias[ps] == 0);
	if (type == 2)
		CHECK(r.alias[0] == 0);
	close(fd);
}

static void anon_copy_test(void) { copy_zero_type(0); }
static void shared_copy_test(void) { copy_zero_type(1); }
static void private_copy_test(void) { copy_zero_type(2); }

struct fault {
	char *p;
	int value;
	int write;
	pid_t tid;
};

static void *fault_thread(void *arg)
{
	struct fault *f = arg;

	f->tid = syscall(SYS_gettid);
	if (f->write)
		*(volatile char *)f->p = f->value;
	else
		CHECK(*(volatile unsigned char *)f->p == f->value);
	return NULL;
}

static void missing_fault_test(void)
{
	int fd = new_uffd(UFFD_FEATURE_THREAD_ID);
	struct region r = region(0, ps);
	struct fault f = { .p = r.p, .value = 0x34 };
	pthread_t t;
	struct uffd_msg msg;

	reg_range(fd, r.p, ps, UFFDIO_REGISTER_MODE_MISSING);
	CHECK(pthread_create(&t, NULL, fault_thread, &f) == 0);
	msg = message(fd, UFFD_EVENT_PAGEFAULT);
	CHECK(msg.arg.pagefault.address == (uintptr_t)r.p);
	CHECK(msg.arg.pagefault.flags == 0);
	copy_page(fd, r.p, 0x34, 0);
	CHECK(pthread_join(t, NULL) == 0);
	CHECK(msg.arg.pagefault.feat.ptid == (__u32)f.tid);
	close(fd);
}

static void minor_type(int type)
{
	int fd = new_uffd(UFFD_FEATURE_THREAD_ID);
	struct region r = region(type, 2 * ps);
	struct fault f = { .p = r.p, .value = 0x41 };
	struct uffdio_continue c = {
		.range = { .start = (uintptr_t)r.p, .len = ps },
	};
	pthread_t t;
	struct uffd_msg msg;

	memset(r.alias, 0x41, 2 * ps);
	reg_range(fd, r.p, 2 * ps, UFFDIO_REGISTER_MODE_MINOR);
	CHECK(pthread_create(&t, NULL, fault_thread, &f) == 0);
	msg = message(fd, UFFD_EVENT_PAGEFAULT);
	CHECK(msg.arg.pagefault.flags & UFFD_PAGEFAULT_FLAG_MINOR);
	cont_page(fd, r.p, ps);
	CHECK(pthread_join(t, NULL) == 0);
	CHECK(msg.arg.pagefault.feat.ptid == (__u32)f.tid);
	CHECK(ioctl(fd, UFFDIO_CONTINUE, &c) == -1 && errno == EEXIST);
	CHECK(c.mapped == -EEXIST);
	cont_page(fd, r.p + ps, ps);
	r.p[0] = 0x42;
	CHECK(r.alias[0] == (type == 1 ? 0x42 : 0x41));
	close(fd);
}

static void shared_minor_test(void) { minor_type(1); }
static void private_minor_test(void) { minor_type(2); }

static void sigbus_test(void)
{
	int fd = new_uffd(UFFD_FEATURE_SIGBUS);
	struct region r = region(0, ps);
	pid_t pid;

	/* Registration is deliberately done after fork. */
	pid = fork();
	CHECK(pid >= 0);
	if (!pid) {
		int child_fd = new_uffd(UFFD_FEATURE_SIGBUS);

		reg_range(child_fd, r.p, ps, UFFDIO_REGISTER_MODE_MISSING);
		*(volatile char *)r.p = 1;
		_exit(1);
	}
	expect_child(pid, SIGBUS);
	close(fd);
}

static void kernel_fault_test(void)
{
	int fd = new_uffd(0), pipefd[2];
	struct region r = region(0, ps);

	reg_range(fd, r.p, ps, UFFDIO_REGISTER_MODE_MISSING);
	CHECK(pipe(pipefd) == 0);
	CHECK(write(pipefd[1], "a", 1) == 1);
	CHECK(read(pipefd[0], r.p, 1) == -1 && errno == EFAULT);
	close(fd);
}

static void unprivileged_test(void)
{
	int fd;
	struct uffdio_api api = { .api = UFFD_API };

	if (geteuid() == 0) {
		CHECK(setgid(10000) == 0);
		CHECK(setuid(10000) == 0);
	}
	fd = syscall(SYS_userfaultfd, O_CLOEXEC | UFFD_USER_MODE_ONLY);
	CHECK(fd >= 0);
	CHECK(ioctl(fd, UFFDIO_API, &api) == 0);
	CHECK(api.features & UFFD_FEATURE_SIGBUS);
	close(fd);
}

static void trylock_probe_test(void)
{
	int fd = new_uffd(0);
	struct region r = region(0, ps);
	struct uffdio_zeropage z = {
		.range = { .start = (uintptr_t)r.p, .len = ps },
		.mode = UFFDIO_ZEROPAGE_MODE_MMAP_TRYLOCK,
		.zeropage = 0,
	};

	CHECK(ioctl(fd, UFFDIO_ZEROPAGE, &z) == -1 && errno == ENOENT);
	CHECK(z.zeropage == -ENOENT);
	z.mode = BIT64(62);
	z.zeropage = 0;
	CHECK(ioctl(fd, UFFDIO_ZEROPAGE, &z) == -1 && errno == EINVAL);
	CHECK(z.zeropage == 0);
	close(fd);
}

static void invalid_range_test(void)
{
	int fd = new_uffd(0);
	struct region r = region(0, ps);
	struct uffdio_register reg = {
		.range = { .start = (uintptr_t)r.p, .len = ps },
		.mode = UFFDIO_REGISTER_MODE_MINOR,
	};

	CHECK(ioctl(fd, UFFDIO_REGISTER, &reg) == -1 && errno == EINVAL);
	reg.mode = UFFDIO_REGISTER_MODE_MISSING;
	reg.range.start++;
	CHECK(ioctl(fd, UFFDIO_REGISTER, &reg) == -1 && errno == EINVAL);
	reg.range.start--;
	reg.range.len = 0;
	CHECK(ioctl(fd, UFFDIO_REGISTER, &reg) == -1 && errno == EINVAL);
	close(fd);
}

static void dontunmap_type(int shared, int fixed)
{
	int flags = MAP_ANONYMOUS | (shared ? MAP_SHARED : MAP_PRIVATE);
	char *p = mmap(NULL, ps, PROT_READ | PROT_WRITE, flags, -1, 0);
	char *dst, *q;
	int mf = MREMAP_MAYMOVE | MREMAP_DONTUNMAP;

	CHECK(p != MAP_FAILED);
	p[0] = 0x57;
	dst = mmap(NULL, ps, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	CHECK(dst != MAP_FAILED);
	if (fixed)
		mf |= MREMAP_FIXED;
	q = mremap(p, ps, ps, mf, dst);
	CHECK(q != MAP_FAILED);
	if (fixed)
		CHECK(q == dst);
	CHECK(q[0] == 0x57);
	CHECK(p[0] == (shared ? 0x57 : 0));
	munmap(p, ps);
	munmap(q, ps);
	if (!fixed)
		munmap(dst, ps);
}

static void private_remap_test(void) { dontunmap_type(0, 0); }
static void shared_remap_test(void) { dontunmap_type(1, 0); }
static void fixed_private_remap_test(void) { dontunmap_type(0, 1); }
static void fixed_shared_remap_test(void) { dontunmap_type(1, 1); }

static void remap_uffd_test(void)
{
	int fd = new_uffd(0);
	struct region r = region(0, ps);
	struct fault f = { .p = r.p, .value = 0x62 };
	pthread_t t;
	char *q;

	r.p[0] = 0x61;
	reg_range(fd, r.p, ps, UFFDIO_REGISTER_MODE_MISSING);
	q = mremap(r.p, ps, ps, MREMAP_MAYMOVE | MREMAP_DONTUNMAP, NULL);
	CHECK(q != MAP_FAILED && q[0] == 0x61);
	CHECK(pthread_create(&t, NULL, fault_thread, &f) == 0);
	message(fd, UFFD_EVENT_PAGEFAULT);
	copy_page(fd, r.p, 0x62, 0);
	CHECK(pthread_join(t, NULL) == 0);
	CHECK(q[0] == 0x61);
	close(fd);
}

static void invalid_remap_test(void)
{
	struct region r = region(0, 2 * ps);

	CHECK(mremap(r.p, ps, ps, MREMAP_DONTUNMAP) == MAP_FAILED);
	CHECK(errno == EINVAL);
	CHECK(mremap(r.p, ps, 2 * ps, MREMAP_MAYMOVE |
		     MREMAP_DONTUNMAP) == MAP_FAILED);
	CHECK(errno == EINVAL);
}

static void release_test(void)
{
	int fd = new_uffd(0);
	struct region r = region(0, ps);
	struct fault f = { .p = r.p, .value = 0 };
	pthread_t t;

	reg_range(fd, r.p, ps, UFFDIO_REGISTER_MODE_MISSING);
	CHECK(pthread_create(&t, NULL, fault_thread, &f) == 0);
	message(fd, UFFD_EVENT_PAGEFAULT);
	CHECK(close(fd) == 0);
	CHECK(pthread_join(t, NULL) == 0);
}

struct event_op {
	char *p;
	char *q;
	int op;
};

static void *event_thread(void *arg)
{
	struct event_op *e = arg;

	if (e->op == UFFD_EVENT_REMOVE)
		CHECK(madvise(e->p, ps, MADV_DONTNEED) == 0);
	else if (e->op == UFFD_EVENT_UNMAP)
		CHECK(munmap(e->p, ps) == 0);
	else {
		e->q = mremap(e->p, ps, ps,
			     MREMAP_MAYMOVE | MREMAP_DONTUNMAP, NULL);
		CHECK(e->q != MAP_FAILED);
	}
	return NULL;
}

static void event_test(int event, __u64 feature)
{
	int fd = new_uffd(feature);
	struct region r = region(0, ps);
	struct event_op e = { .p = r.p, .op = event };
	struct uffd_msg msg;
	pthread_t t;

	r.p[0] = 1;
	reg_range(fd, r.p, ps, UFFDIO_REGISTER_MODE_MISSING);
	CHECK(pthread_create(&t, NULL, event_thread, &e) == 0);
	msg = message(fd, event);
	CHECK(pthread_join(t, NULL) == 0);
	if (event == UFFD_EVENT_REMAP) {
		CHECK(msg.arg.remap.from == (uintptr_t)r.p);
		CHECK(msg.arg.remap.to == (uintptr_t)e.q);
		CHECK(msg.arg.remap.len == ps);
	}
	close(fd);
}

static void remove_event_test(void)
{
	event_test(UFFD_EVENT_REMOVE, UFFD_FEATURE_EVENT_REMOVE);
}

static void unmap_event_test(void)
{
	event_test(UFFD_EVENT_UNMAP, UFFD_FEATURE_EVENT_UNMAP);
}

static void remap_event_test(void)
{
	event_test(UFFD_EVENT_REMAP, UFFD_FEATURE_EVENT_REMAP);
}

static void huge_minor_test(void)
{
	struct region r = { .len = 2 * 1024 * 1024 };
	struct fault f;
	pthread_t t;
	int fd = new_uffd(0);

	if (!(available & UFFD_FEATURE_MINOR_HUGETLBFS))
		exit(4);
	r.memfd = syscall(SYS_memfd_create, "uffd-huge",
			 MFD_CLOEXEC | MFD_HUGETLB);
	if (r.memfd < 0 && errno == EINVAL) {
		r.memfd = open("/huge/uffd-test",
			       O_CREAT | O_RDWR | O_TRUNC, 0600);
	}
	if (r.memfd < 0) {
		perror("hugetlb file");
		exit(4);
	}
	CHECK(ftruncate(r.memfd, r.len) == 0);
	r.alias = mmap(NULL, r.len, PROT_READ | PROT_WRITE,
		       MAP_SHARED, r.memfd, 0);
	r.p = mmap(NULL, r.len, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE, r.memfd, 0);
	if (r.alias == MAP_FAILED || r.p == MAP_FAILED) {
		perror("hugetlb mapping");
		exit(4);
	}
	memset(r.alias, 0x21, r.len);
	reg_range(fd, r.p, r.len, UFFDIO_REGISTER_MODE_MINOR);
	f = (struct fault){ .p = r.p, .value = 0x21 };
	CHECK(pthread_create(&t, NULL, fault_thread, &f) == 0);
	CHECK(message(fd, UFFD_EVENT_PAGEFAULT).arg.pagefault.flags &
	      UFFD_PAGEFAULT_FLAG_MINOR);
	cont_page(fd, r.p, r.len);
	CHECK(pthread_join(t, NULL) == 0);
	r.p[0] = 0x22;
	CHECK(r.alias[0] == 0x21);
	close(fd);
	munmap(r.p, r.len);
	munmap(r.alias, r.len);
	close(r.memfd);
	unlink("/huge/uffd-test");
}

struct test {
	const char *name;
	void (*run)(void);
};

int main(void)
{
	const struct test tests[] = {
		{ "API validation", api_test },
		{ "concurrent API initialization", api_race_test },
		{ "anonymous COPY/ZEROPAGE", anon_copy_test },
		{ "shared shmem COPY/ZEROPAGE", shared_copy_test },
		{ "private shmem COPY/ZEROPAGE", private_copy_test },
		{ "missing fault and thread ID", missing_fault_test },
		{ "shared shmem minor CONTINUE", shared_minor_test },
		{ "private shmem minor CONTINUE and COW", private_minor_test },
		{ "SIGBUS delivery", sigbus_test },
		{ "user-mode-only kernel fault", kernel_fault_test },
		{ "unprivileged user-mode-only UFFD", unprivileged_test },
		{ "ART MMAP_TRYLOCK probe", trylock_probe_test },
		{ "invalid registration ranges", invalid_range_test },
		{ "private DONTUNMAP", private_remap_test },
		{ "shared DONTUNMAP", shared_remap_test },
		{ "fixed private DONTUNMAP", fixed_private_remap_test },
		{ "fixed shared DONTUNMAP", fixed_shared_remap_test },
		{ "DONTUNMAP source faults", remap_uffd_test },
		{ "invalid DONTUNMAP flags", invalid_remap_test },
		{ "release wakes a blocked fault", release_test },
		{ "REMOVE event", remove_event_test },
		{ "UNMAP event", unmap_event_test },
		{ "DONTUNMAP REMAP event", remap_event_test },
		{ "private hugetlb minor CONTINUE and COW", huge_minor_test },
	};
	unsigned int i;
	int failed = 0, skipped = 0;
	struct rlimit core = { 0, 0 };

	ps = sysconf(_SC_PAGESIZE);
	setvbuf(stdout, NULL, _IONBF, 0);
	setrlimit(RLIMIT_CORE, &core);
	printf("TAP version 13\n1..%zu\n", ARRAY_SIZE(tests));
	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		pid_t pid = fork();
		int status;

		CHECK(pid >= 0);
		if (!pid) {
			alarm(20);
			tests[i].run();
			_exit(0);
		}
		CHECK(waitpid(pid, &status, 0) == pid);
		if (WIFEXITED(status) && WEXITSTATUS(status) == 4) {
			printf("ok %u - %s # SKIP unavailable\n",
			       i + 1, tests[i].name);
			skipped++;
		} else if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
			printf("ok %u - %s\n", i + 1, tests[i].name);
		} else {
			printf("not ok %u - %s (status=%d)\n",
			       i + 1, tests[i].name, status);
			failed++;
		}
	}
	printf("# failed=%d skipped=%d\n", failed, skipped);
	return failed ? 1 : 0;
}

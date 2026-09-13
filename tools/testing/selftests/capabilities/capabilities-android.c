// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/bpf.h>
#include <linux/capability.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define SKIP 4
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define CAP_BIT(n) (UINT64_C(1) << (n))
#define BPF_CAP CAP_BIT(CAP_BPF)
#define PERF_CAP CAP_BIT(CAP_PERFMON)
#define ADMIN_CAP CAP_BIT(CAP_SYS_ADMIN)
#define NET_CAP CAP_BIT(CAP_NET_ADMIN)
#define RESTORE_CAP CAP_BIT(CAP_CHECKPOINT_RESTORE)
#define SETPCAP_CAP CAP_BIT(CAP_SETPCAP)
#define INSN(op, dst, src, offval, immval) \
	((struct bpf_insn){ .code = (op), .dst_reg = (dst), \
	 .src_reg = (src), .off = (offval), .imm = (immval) })
#define MOV(dst, imm) INSN(BPF_ALU64 | BPF_MOV | BPF_K, dst, 0, 0, imm)
#define MOV_REG(dst, src) INSN(BPF_ALU64 | BPF_MOV | BPF_X, dst, src, 0, 0)
#define ADD(dst, imm) INSN(BPF_ALU64 | BPF_ADD | BPF_K, dst, 0, 0, imm)
#define CALL(id) INSN(BPF_JMP | BPF_CALL, 0, 0, 0, id)
#define EXIT INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)

enum operation {
	LAST_CAP, BOUNDS, DROP_BOUNDS, AMBIENT, MAP_QUEUE, MAP_ZERO_SEED,
	PROG, SUBPROG, UNINIT_STACK, POINTER_RETURN, PROBE_READ,
	PROBE_WRITE, ARRAY_MASK, MAP_FILES, LAST_PID, EXE_PERMISSION,
};

struct test_case {
	const char *name;
	uint64_t caps;
	enum operation op;
	int arg;
	int expected_errno;
};

static uint64_t available_caps;
static char verifier_log[16384];

static int read_int(const char *path)
{
	FILE *file = fopen(path, "r");
	int value = -1;

	if (file) {
		if (fscanf(file, "%d", &value) != 1)
			value = -1;
		fclose(file);
	}
	return value;
}

static int set_caps(uint64_t caps)
{
	struct __user_cap_header_struct hdr = {
		.version = _LINUX_CAPABILITY_VERSION_3,
	};
	struct __user_cap_data_struct data[2] = { };
	int i;

	for (i = 0; i < 2; i++) {
		data[i].effective = caps >> (i * 32);
		data[i].permitted = data[i].effective;
		data[i].inheritable = data[i].effective;
	}
	return syscall(SYS_capset, &hdr, data);
}

static int check_result(int result, int expected_errno)
{
	int actual = result < 0 ? errno : 0;

	if (actual == expected_errno)
		return 0;
	fprintf(stderr, "expected errno %d, got %d (%s)\n",
		expected_errno, actual, strerror(actual));
	if (verifier_log[0])
		fprintf(stderr, "%s\n", verifier_log);
	return 1;
}

static int load_prog(int type, struct bpf_insn *insns, size_t count)
{
	union bpf_attr attr = { };

	verifier_log[0] = '\0';
	attr.prog_type = type;
	attr.insn_cnt = count;
	attr.insns = (uintptr_t)insns;
	attr.license = (uintptr_t)"GPL";
	attr.log_buf = (uintptr_t)verifier_log;
	attr.log_size = sizeof(verifier_log);
	attr.log_level = 1;
	return syscall(SYS_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
}

static int map_test(const struct test_case *test)
{
	union bpf_attr attr = { };
	int fd, result;

	attr.map_type = test->op == MAP_QUEUE ?
		BPF_MAP_TYPE_QUEUE : BPF_MAP_TYPE_HASH;
	attr.key_size = test->op == MAP_QUEUE ? 0 : 4;
	attr.value_size = 8;
	attr.max_entries = 2;
	if (test->op == MAP_ZERO_SEED)
		attr.map_flags = BPF_F_ZERO_SEED;
	fd = syscall(SYS_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
	result = check_result(fd, test->expected_errno);
	if (fd >= 0)
		close(fd);
	return result;
}

static int program_test(const struct test_case *test)
{
	struct bpf_insn insns[16];
	int n = 0, type = BPF_PROG_TYPE_SOCKET_FILTER;
	int fd, result;

	switch (test->op) {
	case PROG:
		type = test->arg;
		insns[n++] = MOV(0, 0);
		break;
	case SUBPROG:
		insns[n++] = INSN(BPF_JMP | BPF_CALL, 0,
				 BPF_PSEUDO_CALL, 0, 1);
		insns[n++] = EXIT;
		insns[n++] = MOV(0, 42);
		break;
	case UNINIT_STACK:
		/* Allocate a different stack slot first. */
		insns[n++] = INSN(BPF_ST | BPF_DW | BPF_MEM,
				 10, 0, -16, 0);
		insns[n++] = INSN(BPF_LDX | BPF_DW | BPF_MEM,
				 0, 10, -8, 0);
		break;
	case POINTER_RETURN:
		insns[n++] = MOV_REG(0, 10);
		break;
	case PROBE_READ:
		type = BPF_PROG_TYPE_SCHED_CLS;
		insns[n++] = MOV_REG(1, 10);
		insns[n++] = ADD(1, -8);
		insns[n++] = MOV(2, 8);
		insns[n++] = MOV(3, 0);
		insns[n++] = CALL(BPF_FUNC_probe_read_kernel);
		insns[n++] = MOV(0, 0);
		break;
	case PROBE_WRITE:
		type = BPF_PROG_TYPE_KPROBE;
		insns[n++] = INSN(BPF_ST | BPF_DW | BPF_MEM,
				 10, 0, -8, 0);
		insns[n++] = MOV(1, 0);
		insns[n++] = MOV_REG(2, 10);
		insns[n++] = ADD(2, -8);
		insns[n++] = MOV(3, 8);
		insns[n++] = CALL(BPF_FUNC_probe_write_user);
		insns[n++] = MOV(0, 0);
		break;
	default:
		return 1;
	}
	insns[n++] = EXIT;
	fd = load_prog(type, insns, n);
	result = check_result(fd, test->expected_errno);
	if (fd >= 0)
		close(fd);
	return result;
}

static int array_mask_test(const struct test_case *test)
{
	union bpf_attr attr = { };
	struct bpf_prog_info info = { };
	struct bpf_insn translated[128];
	struct bpf_insn insns[16];
	unsigned int i;
	int map_fd, prog_fd, n = 0, result, found = 0;

	if (read_int("/proc/sys/net/core/bpf_jit_enable") <= 0) {
		fprintf(stderr, "BPF JIT is not enabled\n");
		return SKIP;
	}
	attr.map_type = BPF_MAP_TYPE_ARRAY;
	attr.key_size = 4;
	attr.value_size = 4;
	attr.max_entries = 3;
	map_fd = syscall(SYS_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
	if (map_fd < 0)
		return check_result(map_fd, 0);
	insns[n++] = INSN(BPF_LD | BPF_DW | BPF_IMM, 1,
			 BPF_PSEUDO_MAP_FD, 0, map_fd);
	insns[n++] = INSN(0, 0, 0, 0, 0);
	insns[n++] = INSN(BPF_ST | BPF_W | BPF_MEM, 10, 0, -4, 0);
	insns[n++] = MOV_REG(2, 10);
	insns[n++] = ADD(2, -4);
	insns[n++] = CALL(BPF_FUNC_map_lookup_elem);
	insns[n++] = INSN(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 1, 0);
	insns[n++] = INSN(BPF_LDX | BPF_W | BPF_MEM, 0, 0, 0, 0);
	insns[n++] = EXIT;
	prog_fd = load_prog(BPF_PROG_TYPE_SOCKET_FILTER, insns, n);
	close(map_fd);
	if (prog_fd < 0)
		return check_result(prog_fd, 0);
	info.xlated_prog_len = sizeof(translated);
	info.xlated_prog_insns = (uintptr_t)translated;
	memset(&attr, 0, sizeof(attr));
	attr.info.bpf_fd = prog_fd;
	attr.info.info_len = sizeof(info);
	attr.info.info = (uintptr_t)&info;
	result = syscall(SYS_bpf, BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr));
	close(prog_fd);
	if (result < 0)
		return check_result(result, 0);
	if (!info.xlated_prog_len ||
	    info.xlated_prog_len > sizeof(translated))
		return 1;
	for (i = 0; i < info.xlated_prog_len / sizeof(translated[0]); i++)
		if (translated[i].code == (BPF_ALU | BPF_AND | BPF_K) &&
		    translated[i].imm == 3)
			found++;
	if (!!found != !!test->arg) {
		fprintf(stderr, "expected array masking %d, found %d\n",
			test->arg, found);
		return 1;
	}
	return 0;
}

static int map_files_test(const struct test_case *test)
{
	char name[] = "/tmp/capability-map-XXXXXX";
	char link[160];
	size_t size = sysconf(_SC_PAGESIZE);
	void *addr;
	int fd, mapped_fd, result;

	fd = mkstemp(name);
	if (fd < 0)
		return 1;
	unlink(name);
	if (ftruncate(fd, size))
		return 1;
	addr = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);
	if (addr == MAP_FAILED)
		return 1;
	snprintf(link, sizeof(link), "/proc/self/map_files/%" PRIxPTR
		 "-%" PRIxPTR, (uintptr_t)addr, (uintptr_t)addr + size);
	mapped_fd = open(link, O_RDONLY);
	result = check_result(mapped_fd, test->expected_errno);
	if (mapped_fd >= 0)
		close(mapped_fd);
	munmap(addr, size);
	return result;
}

static int last_pid_test(const struct test_case *test)
{
	const char *path = "/proc/sys/kernel/ns_last_pid";
	char value[32];
	int fd, n, result;

	n = read_int(path);
	if (n < 0) {
		fprintf(stderr, "CONFIG_CHECKPOINT_RESTORE is unavailable\n");
		return SKIP;
	}
	fd = open(path, O_WRONLY);
	if (fd < 0)
		return 1;
	n = snprintf(value, sizeof(value), "%d\n", n);
	result = write(fd, value, n);
	result = check_result(result, test->expected_errno);
	close(fd);
	return result;
}

static int exe_permission_test(const struct test_case *test)
{
	struct prctl_mm_map map = { };
	char *line = NULL, *p, *save, *token;
	size_t size = 0;
	unsigned long long fields[52] = { };
	unsigned int map_size;
	FILE *file;
	int field = 3, result;

	/* PR_SET_MM_MAP has a native pointer and no compat handler. */
	if (sizeof(void *) < sizeof(uint64_t)) {
		fprintf(stderr, "PR_SET_MM_MAP needs the native 64-bit ABI\n");
		return SKIP;
	}

	if (prctl(PR_SET_MM, PR_SET_MM_MAP_SIZE, &map_size, 0L, 0L)) {
		fprintf(stderr, "PR_SET_MM_MAP is unavailable\n");
		return SKIP;
	}
	file = fopen("/proc/self/stat", "r");
	if (!file || getline(&line, &size, file) < 0)
		return 1;
	fclose(file);
	p = strrchr(line, ')');
	if (!p)
		return 1;
	for (token = strtok_r(p + 2, " ", &save); token && field < 52;
	     token = strtok_r(NULL, " ", &save))
		fields[field++] = strtoull(token, NULL, 10);
	free(line);
	if (field != 52)
		return 1;
	map.start_code = fields[26];
	map.end_code = fields[27];
	map.start_stack = fields[28];
	map.start_data = fields[45];
	map.end_data = fields[46];
	map.start_brk = fields[47];
	map.brk = (uintptr_t)sbrk(0);
	map.arg_start = fields[48];
	map.arg_end = fields[49];
	map.env_start = fields[50];
	map.env_end = fields[51];
	/* An invalid fd tests the gate without changing exe_file. */
	map.exe_fd = UINT32_MAX - 1;
	result = prctl(PR_SET_MM, PR_SET_MM_MAP, &map, sizeof(map), 0L);
	return check_result(result, test->expected_errno);
}

static int run_operation(const struct test_case *test)
{
	int cap, result;

	switch (test->op) {
	case LAST_CAP:
		return read_int("/proc/sys/kernel/cap_last_cap") !=
			CAP_CHECKPOINT_RESTORE;
	case BOUNDS:
	case DROP_BOUNDS:
		for (cap = 0; cap <= CAP_CHECKPOINT_RESTORE; cap++) {
			result = prctl(PR_CAPBSET_READ, cap, 0L, 0L, 0L);
			if (result < 0) {
				fprintf(stderr, "capability %d: %s\n", cap,
					strerror(errno));
				return 1;
			}
			if (test->op == DROP_BOUNDS && result &&
			    prctl(PR_CAPBSET_DROP, cap, 0L, 0L, 0L))
				return 1;
			if (test->op == DROP_BOUNDS &&
			    prctl(PR_CAPBSET_READ, cap, 0L, 0L, 0L) != 0)
				return 1;
		}
		return check_result(prctl(PR_CAPBSET_READ,
			CAP_CHECKPOINT_RESTORE + 1, 0L, 0L, 0L), EINVAL);
	case AMBIENT:
		if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE,
			  test->arg, 0L, 0L))
			return 1;
		if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET,
			  test->arg, 0L, 0L) != 1)
			return 1;
		return prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER,
			     test->arg, 0L, 0L) != 0;
	case MAP_QUEUE:
	case MAP_ZERO_SEED:
		return map_test(test);
	case ARRAY_MASK:
		return array_mask_test(test);
	case MAP_FILES:
		return map_files_test(test);
	case LAST_PID:
		return last_pid_test(test);
	case EXE_PERMISSION:
		return exe_permission_test(test);
	default:
		return program_test(test);
	}
}

static int child_status(pid_t child)
{
	int status;

	if (waitpid(child, &status, 0) != child || !WIFEXITED(status))
		return 1;
	return WEXITSTATUS(status);
}

static int run_child(const struct test_case *test)
{
	pid_t child;

	if (test->caps & ~available_caps) {
		fprintf(stderr, "required capabilities are not permitted\n");
		return SKIP;
	}
	if (test->op == LAST_PID) {
		/* Isolate PID allocator changes. */
		if (unshare(CLONE_NEWPID)) {
			fprintf(stderr, "private PID namespace: %s\n",
				strerror(errno));
			return SKIP;
		}
		child = fork();
		if (child < 0)
			return 1;
		if (child)
			return child_status(child);
	}
	if (set_caps(test->caps)) {
		perror("capset");
		return 1;
	}
	return run_operation(test);
}

#define CASE(name, caps, op, arg, error) { name, caps, op, arg, error }
static const struct test_case tests[] = {
	CASE("cap_last_cap is 40", 0, LAST_CAP, 0, 0),
	CASE("query 0..40, reject 41", 0, BOUNDS, 0, 0),
	CASE("zygote bounding-set loop", SETPCAP_CAP, DROP_BOUNDS, 0, 0),
	CASE("CAP_BPF ambient interface", BPF_CAP, AMBIENT, CAP_BPF, 0),
	CASE("restore ambient interface", RESTORE_CAP, AMBIENT,
	     CAP_CHECKPOINT_RESTORE, 0),
	CASE("CAP_BPF creates queue map", BPF_CAP, MAP_QUEUE, 0, 0),
	CASE("CAP_SYS_ADMIN creates queue", ADMIN_CAP, MAP_QUEUE, 0, 0),
	CASE("CAP_BPF cannot use zero seed", BPF_CAP, MAP_ZERO_SEED, 0, EPERM),
	CASE("CAP_SYS_ADMIN can use zero seed", ADMIN_CAP, MAP_ZERO_SEED, 0, 0),
	CASE("network load needs NET_ADMIN", BPF_CAP, PROG,
	     BPF_PROG_TYPE_SCHED_CLS, EPERM),
	CASE("network load with BPF and NET_ADMIN", BPF_CAP | NET_CAP,
	     PROG, BPF_PROG_TYPE_SCHED_CLS, 0),
	CASE("SYS_ADMIN network compatibility", ADMIN_CAP, PROG,
	     BPF_PROG_TYPE_SCHED_CLS, 0),
	CASE("tracing load needs PERFMON", BPF_CAP, PROG,
	     BPF_PROG_TYPE_PERF_EVENT, EPERM),
	CASE("tracing load with BPF and PERFMON", BPF_CAP | PERF_CAP,
	     PROG, BPF_PROG_TYPE_PERF_EVENT, 0),
	CASE("SYS_ADMIN tracing compatibility", ADMIN_CAP, PROG,
	     BPF_PROG_TYPE_PERF_EVENT, 0),
	CASE("CAP_BPF permits subprograms", BPF_CAP, SUBPROG, 0, 0),
	CASE("CAP_BPF cannot read uninitialized stack", BPF_CAP,
	     UNINIT_STACK, 0, EACCES),
	CASE("PERFMON permits uninitialized stack", BPF_CAP | PERF_CAP,
	     UNINIT_STACK, 0, 0),
	CASE("CAP_BPF cannot return kernel pointer", BPF_CAP,
	     POINTER_RETURN, 0, EACCES),
	CASE("PERFMON permits pointer return", BPF_CAP | PERF_CAP,
	     POINTER_RETURN, 0, 0),
	CASE("kernel read helper needs PERFMON", BPF_CAP | NET_CAP,
	     PROBE_READ, 0, EINVAL),
	CASE("PERFMON permits kernel read helper", BPF_CAP | NET_CAP | PERF_CAP,
	     PROBE_READ, 0, 0),
	CASE("user write helper needs SYS_ADMIN", BPF_CAP | PERF_CAP,
	     PROBE_WRITE, 0, EINVAL),
	CASE("SYS_ADMIN permits user write helper", ADMIN_CAP,
	     PROBE_WRITE, 0, 0),
	CASE("CAP_BPF retains array masking", BPF_CAP, ARRAY_MASK, 1, 0),
	CASE("PERFMON may bypass array masking", BPF_CAP | PERF_CAP,
	     ARRAY_MASK, 0, 0),
	CASE("CAP_BPF cannot follow map_files", BPF_CAP, MAP_FILES, 0, EPERM),
	CASE("restore can follow map_files", RESTORE_CAP, MAP_FILES, 0, 0),
	CASE("SYS_ADMIN can follow map_files", ADMIN_CAP, MAP_FILES, 0, 0),
	CASE("CAP_BPF cannot change ns_last_pid", BPF_CAP, LAST_PID, 0, EPERM),
	CASE("restore can change ns_last_pid", RESTORE_CAP, LAST_PID, 0, 0),
	CASE("SYS_ADMIN can change ns_last_pid", ADMIN_CAP, LAST_PID, 0, 0),
	CASE("CAP_BPF cannot select exe_file", BPF_CAP,
	     EXE_PERMISSION, 0, EPERM),
	CASE("restore passes exe_file permission check", RESTORE_CAP,
	     EXE_PERMISSION, 0, EBADF),
	CASE("SYS_ADMIN passes exe_file permission check", ADMIN_CAP,
	     EXE_PERMISSION, 0, EBADF),
};

int main(int argc, char **argv)
{
	struct __user_cap_header_struct hdr = {
		.version = _LINUX_CAPABILITY_VERSION_3,
	};
	struct __user_cap_data_struct data[2] = { };
	struct rlimit limit = { RLIM_INFINITY, RLIM_INFINITY };
	bool bounds_only = argc == 2 && !strcmp(argv[1], "--bounds-only");
	int count = bounds_only ? 3 : ARRAY_SIZE(tests);
	int i, result, failed = 0, skipped = 0;
	pid_t child;

	if (argc > 1 && !bounds_only) {
		fprintf(stderr, "usage: %s [--bounds-only]\n", argv[0]);
		return 1;
	}
	if (syscall(SYS_capget, &hdr, data)) {
		perror("capget");
		return 1;
	}
	available_caps = data[0].permitted |
		((uint64_t)data[1].permitted << 32);
	/* Only the child processes drop capabilities. */
	setrlimit(RLIMIT_MEMLOCK, &limit);
	printf("TAP version 13\n1..%d\n", count);
	for (i = 0; i < count; i++) {
		fflush(NULL);
		child = fork();
		if (child == 0)
			_exit(run_child(&tests[i]));
		result = child < 0 ? 1 : child_status(child);
		if (result == SKIP) {
			printf("ok %d - %s # SKIP requirements unavailable\n",
			       i + 1, tests[i].name);
			skipped++;
		} else if (result) {
			printf("not ok %d - %s\n", i + 1, tests[i].name);
			failed++;
		} else {
			printf("ok %d - %s\n", i + 1, tests[i].name);
		}
	}
	printf("# passed %d; failed %d; skipped %d\n",
	       count - failed - skipped, failed, skipped);
	return failed ? 1 : (skipped == count ? SKIP : 0);
}

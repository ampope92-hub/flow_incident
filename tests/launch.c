/* tool_launch <program> <args...>: starts the flowkit binary under a seccomp filter that it
   and every child inherit. execveat is refused with EPERM, and so is every execve except the
   one this launcher makes, recognised by a path pointer placed at a random address in a page
   of its own. All other calls pass. When the filter will not install, the reason is written to
   standard error and nothing starts. */
#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#define ARG0(half) (offsetof(struct seccomp_data, args[0]) + 4 * (half))

int main(int argc, char **argv) {
    size_t n = argc < 2 ? 0 : strlen(argv[1]) + 1;
    if (n == 0 || n > 2048) {
        fprintf(stderr, "tool_launch: need a program to run\n");
        return 2;
    }
    unsigned long long r = 0;
    char *page = MAP_FAILED;
    for (int tries = 0; page == MAP_FAILED && tries < 64; tries++) {
        if (getrandom(&r, sizeof r, 0) != (ssize_t)sizeof r) break;
        char *want = (char *)((0x100000000000ULL + r % 0x600000000000ULL) & ~0xFFFULL);
        page = mmap(want, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (page != MAP_FAILED && page != want) { munmap(page, 4096); page = MAP_FAILED; }
    }
    if (page == MAP_FAILED) {
        fprintf(stderr, "tool_launch: no page for the program path: %s\n", strerror(errno));
        return 111;
    }
    char *path = page + (r >> 52) % (4096 - n);
    memcpy(path, argv[1], n);
    unsigned long long a = (unsigned long long)path;

    struct sock_filter filter[] = {  /* a jump counts from the next instruction */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 9),  /* not x86_64: deny */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000, 7, 0),         /* x32 numbers: deny */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 6, 0),       /* deny */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 0, 4),         /* not execve: allow */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, ARG0(0)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)a, 0, 3),         /* not ours: deny */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, ARG0(1)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (unsigned)(a >> 32), 0, 1), /* not ours: deny */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
    };
    struct sock_fprog prog = { .len = sizeof filter / sizeof filter[0], .filter = filter };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0)) {
        fprintf(stderr, "tool_launch: the exec filter could not be installed: %s\n", strerror(errno));
        return 111;
    }
    execve(path, &argv[1], environ);
    fprintf(stderr, "tool_launch: %s did not start: %s\n", argv[1], strerror(errno));
    return 127;
}

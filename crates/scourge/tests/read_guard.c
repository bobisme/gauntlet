/* Linux process-test guard. An attempted network syscall or child process
 * kills the CLI, even if it would otherwise ignore a connection error. */
#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define FORBID(syscall) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_##syscall, 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)

static int install_guard(void) {
    struct sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        FORBID(socket),
        FORBID(connect),
        FORBID(sendto),
        FORBID(sendmsg),
        FORBID(sendmmsg),
#ifdef SYS_socketcall
        FORBID(socketcall),
#endif
        FORBID(clone),
#ifdef SYS_clone3
        FORBID(clone3),
#endif
#ifdef SYS_fork
        FORBID(fork),
#endif
#ifdef SYS_vfork
        FORBID(vfork),
#endif
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    };
    struct sock_fprog program = { .len = sizeof(code) / sizeof(code[0]), .filter = code };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
        return -1;
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
}

int main(int argc, char **argv) {
    int watch = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (watch == -1) {
        perror("inotify");
        return 126;
    }
    int arg = 1;
    for (; arg < argc && strcmp(argv[arg], "--") != 0; arg++) {
        if (inotify_add_watch(watch, argv[arg], IN_OPEN) == -1) {
            perror("inotify_add_watch");
            return 126;
        }
    }
    arg++;
    if (arg >= argc)
        return 126;

    pid_t child = fork();
    if (child == -1) {
        perror("fork");
        return 126;
    }
    if (child == 0) {
        if (install_guard() == -1) {
            perror("install_guard");
            _exit(126);
        }
        execv(argv[arg], argv + arg);
        perror("execv");
        _exit(126);
    }

    int status;
    if (waitpid(child, &status, 0) == -1) {
        perror("waitpid");
        return 126;
    }
    char events[4096];
    if (read(watch, events, sizeof(events)) != -1 || errno != EAGAIN) {
        fputs("read guard: watched path opened\n", stderr);
        return 126;
    }
    if (WIFSIGNALED(status)) {
        fprintf(stderr, "read guard: child terminated by signal %d\n", WTERMSIG(status));
        return 125;
    }
    return WEXITSTATUS(status);
}

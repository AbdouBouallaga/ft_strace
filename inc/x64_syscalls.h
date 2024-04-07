
#ifndef X64_SYSCALLS_H
# define X64_SYSCALLS_H

#define X64_SYSCALLS_LIST { \
    {0, "read", 3, {UINT, char, size_t}}, \
    {1, "write", 3, {UINT, const char, size_t}}, \
    {2, "open", 3, {const char, int, umode_t}}, \
    {3, "close", 1, {UINT}}, \
    {4, "newstat", 2, {const char, struct stat}}, \
    {5, "newfstat", 2, {UINT, struct stat}}, \
    {6, "newlstat", 2, {const char, struct stat}}, \
    {7, "poll", 3, {struct pollfd, UINT, int}}, \
    {8, "lseek", 3, {UINT, off_t, UINT}}, \
    {9, "mmap", 6, {unsigned long, unsigned long, unsigned long, unsigned long, unsigned long, unsigned long}}, \
    {10, "mprotect", 3, {unsigned long, size_t, unsigned long}}, \
    {11, "munmap", 2, {unsigned long, size_t}}, \
    {12, "brk", 1, {unsigned long}}, \
    {13, "rt_sigaction", 4, {int, const struct sigaction, struct sigaction, size_t}}, \
    {14, "rt_sigprocmask", 4, {int, sigset_t, sigset_t, size_t}}, \
    {15, "rt_sigreturn", 0, {}}, \
    {16, "ioctl", 3, {UINT, UINT, unsigned long}}, \
    {17, "pread64", 4, {UINT, char, size_t, loff_t}}, \
    {18, "pwrite64", 4, {UINT, const char, size_t, loff_t}}, \
    {19, "readv", 3, {unsigned long, const struct iovec, unsigned long}}, \
    {20, "writev", 3, {unsigned long, const struct iovec, unsigned long}}, \
    {21, "access", 2, {const char, int}}, \
    {22, "pipe", 1, {int}}, \
    {23, "select", 5, {int, fd_set, fd_set, fd_set, struct __kernel_old_timeval}}, \
    {24, "sched_yield", 0, {}}, \
    {25, "mremap", 5, {unsigned long, unsigned long, unsigned long, unsigned long, unsigned long}}, \
    {26, "msync", 3, {unsigned long, size_t, int}}, \
    {27, "mincore", 3, {unsigned long, size_t, unsigned char}}, \
    {28, "madvise", 3, {unsigned long, size_t, int}}, \
    {29, "shmget", 3, {key_t, size_t, int}}, \
    {30, "shmat", 3, {int, char, int}}, \
    {31, "shmctl", 3, {int, int, struct shmid_ds}}, \
    {32, "dup", 1, {UINT}}, \
    {33, "dup2", 2, {UINT, UINT}}, \
    {34, "pause", 0, {}}, \
    {35, "nanosleep", 2, {struct __kernel_timespec, struct __kernel_timespec}}, \
    {36, "getitimer", 2, {int, struct __kernel_old_itimerval}}, \
    {37, "alarm", 1, {UINT}}, \
    {38, "setitimer", 3, {int, struct __kernel_old_itimerval, struct __kernel_old_itimerval}}, \
    {39, "getpid", 0, {}}, \
    {40, "sendfile64", 4, {int, int, loff_t, size_t}}, \
    {41, "socket", 3, {int, int, int}}, \
    {42, "connect", 3, {int, struct sockaddr, int}}, \
    {43, "accept", 3, {int, struct sockaddr, int}}, \
    {44, "sendto", 6, {int, void, size_t, UINT, struct sockaddr, int}}, \
    {45, "recvfrom", 6, {int, void, size_t, UINT, struct sockaddr, int}}, \
    {46, "sendmsg", 3, {int, struct user_msghdr, UINT}}, \
    {47, "recvmsg", 3, {int, struct user_msghdr, UINT}}, \
    {48, "shutdown", 2, {int, int}}, \
    {49, "bind", 3, {int, struct sockaddr, int}}, \
    {50, "listen", 2, {int, int}}, \
    {51, "getsockname", 3, {int, struct sockaddr, int}}, \
    {52, "getpeername", 3, {int, struct sockaddr, int}}, \
    {53, "socketpair", 4, {int, int, int, int}}, \
    {54, "setsockopt", 5, {int, int, int, char, int}}, \
    {55, "getsockopt", 5, {int, int, int, char, int}}, \
    {56, "clone", 5, {unsigned long, unsigned long, int, int, unsigned long}}, \
    {57, "fork", 0, {}}, \
    {58, "vfork", 0, {}}, \
    {59, "execve", 3, {const char, const char *const, const char *const}}, \
    {60, "exit", 1, {int}}, \
    {61, "wait4", 4, {pid_t, int, int, struct rusage}}, \
    {62, "kill", 2, {pid_t, int}}, \
    {63, "newuname", 1, {struct new_utsname}}, \
    {64, "semget", 3, {key_t, int, int}}, \
    {65, "semop", 3, {int, struct sembuf, unsigned}}, \
    {66, "semctl", 4, {int, int, int, unsigned long}}, \
    {67, "shmdt", 1, {char}}, \
    {68, "msgget", 2, {key_t, int}}, \
    {69, "msgsnd", 4, {int, struct msgbuf, size_t, int}}, \
    {70, "msgrcv", 5, {int, struct msgbuf, size_t, long, int}}, \
    {71, "msgctl", 3, {int, int, struct msqid_ds}}, \
    {72, "fcntl", 3, {UINT, UINT, unsigned long}}, \
    {73, "flock", 2, {UINT, UINT}}, \
    {74, "fsync", 1, {UINT}}, \
    {75, "fdatasync", 1, {UINT}}, \
    {76, "truncate", 2, {const char, long}}, \
    {77, "ftruncate", 2, {UINT, unsigned long}}, \
    {78, "getdents", 3, {UINT, struct linux_dirent, UINT}}, \
    {79, "getcwd", 2, {char, unsigned long}}, \
    {80, "chdir", 1, {const char}}, \
    {81, "fchdir", 1, {UINT}}, \
    {82, "rename", 2, {const char, const char}}, \
    {83, "mkdir", 2, {const char, umode_t}}, \
    {84, "rmdir", 1, {const char}}, \
    {85, "creat", 2, {const char, umode_t}}, \
    {86, "link", 2, {const char, const char}}, \
    {87, "unlink", 1, {const char}}, \
    {88, "symlink", 2, {const char, const char}}, \
    {89, "readlink", 3, {const char, char, int}}, \
    {90, "chmod", 2, {const char, umode_t}}, \
    {91, "fchmod", 2, {UINT, umode_t}}, \
    {92, "chown", 3, {const char, uid_t, gid_t}}, \
    {93, "fchown", 3, {UINT, uid_t, gid_t}}, \
    {94, "lchown", 3, {const char, uid_t, gid_t}}, \
    {95, "umask", 1, {int}}, \
    {96, "gettimeofday", 2, {struct __kernel_old_timeval, struct timezone}}, \
    {97, "getrlimit", 2, {UINT, struct rlimit}}, \
    {98, "getrusage", 2, {int, struct rusage}}, \
    {99, "sysinfo", 1, {struct sysinfo}}, \
    {100, "times", 1, {struct tms}}, \
    {101, "ptrace", 4, {long, long, unsigned long, unsigned long}}, \
    {102, "getuid", 0, {}}, \
    {103, "syslog", 3, {int, char, int}}, \
    {104, "getgid", 0, {}}, \
    {105, "setuid", 1, {uid_t}}, \
    {106, "setgid", 1, {gid_t}}, \
    {107, "geteuid", 0, {}}, \
    {108, "getegid", 0, {}}, \
    {109, "setpgid", 2, {pid_t, pid_t}}, \
    {110, "getppid", 0, {}}, \
    {111, "getpgrp", 0, {}}, \
    {112, "setsid", 0, {}}, \
    {113, "setreuid", 2, {uid_t, uid_t}}, \
    {114, "setregid", 2, {gid_t, gid_t}}, \
    {115, "getgroups", 2, {int, gid_t}}, \
    {116, "setgroups", 2, {int, gid_t}}, \
    {117, "setresuid", 3, {uid_t, uid_t, uid_t}}, \
    {118, "getresuid", 3, {uid_t, uid_t, uid_t}}, \
    {119, "setresgid", 3, {gid_t, gid_t, gid_t}}, \
    {120, "getresgid", 3, {gid_t, gid_t, gid_t}}, \
    {121, "getpgid", 1, {pid_t}}, \
    {122, "setfsuid", 1, {uid_t}}, \
    {123, "setfsgid", 1, {gid_t}}, \
    {124, "getsid", 1, {pid_t}}, \
    {125, "capget", 2, {cap_user_header_t, cap_user_data_t}}, \
    {126, "capset", 2, {cap_user_header_t, const cap_user_data_t}}, \
    {127, "rt_sigpending", 2, {sigset_t, size_t}}, \
    {128, "rt_sigtimedwait", 4, {const sigset_t, siginfo_t, const struct __kernel_timespec, size_t}}, \
    {129, "rt_sigqueueinfo", 3, {pid_t, int, siginfo_t}}, \
    {130, "rt_sigsuspend", 2, {sigset_t, size_t}}, \
    {131, "sigaltstack", 2, {const stack_t, stack_t}}, \
    {132, "utime", 2, {char, struct utimbuf}}, \
    {133, "mknod", 3, {const char, umode_t, unsigned}}, \
    {135, "personality", 1, {UINT}}, \
    {136, "ustat", 2, {unsigned, struct ustat}}, \
    {137, "statfs", 2, {const char, struct statfs}}, \
    {138, "fstatfs", 2, {UINT, struct statfs}}, \
    {139, "sysfs", 3, {int, unsigned long, unsigned long}}, \
    {140, "getpriority", 2, {int, int}}, \
    {141, "setpriority", 3, {int, int, int}}, \
    {142, "sched_setparam", 2, {pid_t, struct sched_param}}, \
    {143, "sched_getparam", 2, {pid_t, struct sched_param}}, \
    {144, "sched_setscheduler", 3, {pid_t, int, struct sched_param}}, \
    {145, "sched_getscheduler", 1, {pid_t}}, \
    {146, "sched_get_priority_max", 1, {int}}, \
    {147, "sched_get_priority_min", 1, {int}}, \
    {148, "sched_rr_get_interval", 2, {pid_t, struct __kernel_timespec}}, \
    {149, "mlock", 2, {unsigned long, size_t}}, \
    {150, "munlock", 2, {unsigned long, size_t}}, \
    {151, "mlockall", 1, {int}}, \
    {152, "munlockall", 0, {}}, \
    {153, "vhangup", 0, {}}, \
    {154, "modify_ldt", 3, {int, void, unsigned long}}, \
    {155, "pivot_root", 2, {const char, const char}}, \
    {157, "prctl", 5, {int, unsigned long, unsigned long, unsigned long, unsigned long}}, \
    {158, "arch_prctl", 2, {int, unsigned long}}, \
    {159, "adjtimex", 1, {struct __kernel_timex}}, \
    {160, "setrlimit", 2, {UINT, struct rlimit}}, \
    {161, "chroot", 1, {const char}}, \
    {162, "sync", 0, {}}, \
    {163, "acct", 1, {const char}}, \
    {164, "settimeofday", 2, {struct __kernel_old_timeval, struct timezone}}, \
    {165, "mount", 5, {char, char, char, unsigned long, void}}, \
    {166, "umount", 2, {char, int}}, \
    {167, "swapon", 2, {const char, int}}, \
    {168, "swapoff", 1, {const char}}, \
    {169, "reboot", 4, {int, int, UINT, void}}, \
    {170, "sethostname", 2, {char, int}}, \
    {171, "setdomainname", 2, {char, int}}, \
    {172, "iopl", 1, {UINT}}, \
    {173, "ioperm", 3, {unsigned long, unsigned long, int}}, \
    {175, "init_module", 3, {void, unsigned long, const char}}, \
    {176, "delete_module", 2, {const char, UINT}}, \
    {179, "quotactl", 4, {UINT, const char, qid_t, void}}, \
    {186, "gettid", 0, {}}, \
    {187, "readahead", 3, {int, loff_t, size_t}}, \
    {188, "setxattr", 5, {const char, const char, const void, size_t, int}}, \
    {189, "lsetxattr", 5, {const char, const char, const void, size_t, int}}, \
    {190, "fsetxattr", 5, {int, const char, const void, size_t, int}}, \
    {191, "getxattr", 4, {const char, const char, void, size_t}}, \
    {192, "lgetxattr", 4, {const char, const char, void, size_t}}, \
    {193, "fgetxattr", 4, {int, const char, void, size_t}}, \
    {194, "listxattr", 3, {const char, char, size_t}}, \
    {195, "llistxattr", 3, {const char, char, size_t}}, \
    {196, "flistxattr", 3, {int, char, size_t}}, \
    {197, "removexattr", 2, {const char, const char}}, \
    {198, "lremovexattr", 2, {const char, const char}}, \
    {199, "fremovexattr", 2, {int, const char}}, \
    {200, "tkill", 2, {pid_t, int}}, \
    {201, "time", 1, {__kernel_old_time_t}}, \
    {202, "futex", 6, {u32, int, u32, const struct __kernel_timespec, u32, u32}}, \
    {203, "sched_setaffinity", 3, {pid_t, UINT, unsigned long}}, \
    {204, "sched_getaffinity", 3, {pid_t, UINT, unsigned long}}, \
    {206, "io_setup", 2, {unsigned, aio_context_t}}, \
    {207, "io_destroy", 1, {aio_context_t}}, \
    {208, "io_getevents", 5, {aio_context_t, long, long, struct io_event, struct __kernel_timespec}}, \
    {209, "io_submit", 3, {aio_context_t, long, struct iocb *}}, \
    {210, "io_cancel", 3, {aio_context_t, struct iocb, struct io_event}}, \
    {213, "epoll_create", 1, {int}}, \
    {216, "remap_file_pages", 5, {unsigned long, unsigned long, unsigned long, unsigned long, unsigned long}}, \
    {217, "getdents64", 3, {UINT, struct linux_dirent64, UINT}}, \
    {218, "set_tid_address", 1, {int}}, \
    {219, "restart_syscall", 0, {}}, \
    {220, "semtimedop", 4, {int, struct sembuf, UINT, const struct __kernel_timespec}}, \
    {221, "fadvise64", 4, {int, loff_t, loff_t, int}}, \
    {222, "timer_create", 3, {const clockid_t, struct sigevent, timer_t}}, \
    {223, "timer_settime", 4, {timer_t, int, const struct __kernel_itimerspec, struct __kernel_itimerspec}}, \
    {224, "timer_gettime", 2, {timer_t, struct __kernel_itimerspec}}, \
    {225, "timer_getoverrun", 1, {timer_t}}, \
    {226, "timer_delete", 1, {timer_t}}, \
    {227, "clock_settime", 2, {const clockid_t, const struct __kernel_timespec}}, \
    {228, "clock_gettime", 2, {const clockid_t, struct __kernel_timespec}}, \
    {229, "clock_getres", 2, {const clockid_t, struct __kernel_timespec}}, \
    {230, "clock_nanosleep", 4, {const clockid_t, int, const struct __kernel_timespec, struct __kernel_timespec}}, \
    {231, "exit_group", 1, {int}}, \
    {232, "epoll_wait", 4, {int, struct epoll_event, int, int}}, \
    {233, "epoll_ctl", 4, {int, int, int, struct epoll_event}}, \
    {234, "tgkill", 3, {pid_t, pid_t, int}}, \
    {235, "utimes", 2, {char, struct __kernel_old_timeval}}, \
    {237, "mbind", 6, {unsigned long, unsigned long, unsigned long, const unsigned long, unsigned long, UINT}}, \
    {238, "set_mempolicy", 3, {int, const unsigned long, unsigned long}}, \
    {239, "get_mempolicy", 5, {int, unsigned long, unsigned long, unsigned long, unsigned long}}, \
    {240, "mq_open", 4, {const char, int, umode_t, struct mq_attr}}, \
    {241, "mq_unlink", 1, {const char}}, \
    {242, "mq_timedsend", 5, {mqd_t, const char, size_t, UINT, const struct __kernel_timespec}}, \
    {243, "mq_timedreceive", 5, {mqd_t, char, size_t, UINT, const struct __kernel_timespec}}, \
    {244, "mq_notify", 2, {mqd_t, const struct sigevent}}, \
    {245, "mq_getsetattr", 3, {mqd_t, const struct mq_attr, struct mq_attr}}, \
    {246, "kexec_load", 4, {unsigned long, unsigned long, struct kexec_segment, unsigned long}}, \
    {247, "waitid", 5, {int, pid_t, struct siginfo, int, struct rusage}}, \
    {248, "add_key", 5, {const char, const char, const void, size_t, key_serial_t}}, \
    {249, "request_key", 4, {const char, const char, const char, key_serial_t}}, \
    {250, "keyctl", 5, {int, unsigned long, unsigned long, unsigned long, unsigned long}}, \
    {251, "ioprio_set", 3, {int, int, int}}, \
    {252, "ioprio_get", 2, {int, int}}, \
    {253, "inotify_init", 0, {}}, \
    {254, "inotify_add_watch", 3, {int, const char, u32}}, \
    {255, "inotify_rm_watch", 2, {int, __s32}}, \
    {256, "migrate_pages", 4, {pid_t, unsigned long, const unsigned long, const unsigned long}}, \
    {257, "openat", 4, {int, const char, int, umode_t}}, \
    {258, "mkdirat", 3, {int, const char, umode_t}}, \
    {259, "mknodat", 4, {int, const char, umode_t, UINT}}, \
    {260, "fchownat", 5, {int, const char, uid_t, gid_t, int}}, \
    {261, "futimesat", 3, {int, const char, struct __kernel_old_timeval}}, \
    {262, "newfstatat", 4, {int, const char, struct stat, int}}, \
    {263, "unlinkat", 3, {int, const char, int}}, \
    {264, "renameat", 4, {int, const char, int, const char}}, \
    {265, "linkat", 5, {int, const char, int, const char, int}}, \
    {266, "symlinkat", 3, {const char, int, const char}}, \
    {267, "readlinkat", 4, {int, const char, char, int}}, \
    {268, "fchmodat", 3, {int, const char, umode_t}}, \
    {269, "faccessat", 3, {int, const char, int}}, \
    {270, "pselect6", 6, {int, fd_set, fd_set, fd_set, struct __kernel_timespec, void}}, \
    {271, "ppoll", 5, {struct pollfd, UINT, struct __kernel_timespec, const sigset_t, size_t}}, \
    {272, "unshare", 1, {unsigned long}}, \
    {273, "set_robust_list", 2, {struct robust_list_head, size_t}}, \
    {274, "get_robust_list", 3, {int, struct robust_list_head *, size_t}}, \
    {275, "splice", 6, {int, loff_t, int, loff_t, size_t, UINT}}, \
    {276, "tee", 4, {int, int, size_t, UINT}}, \
    {277, "sync_file_range", 4, {int, loff_t, loff_t, UINT}}, \
    {278, "vmsplice", 4, {int, const struct iovec, unsigned long, UINT}}, \
    {279, "move_pages", 6, {pid_t, unsigned long, const void *, const int, int, int}}, \
    {280, "utimensat", 4, {int, const char, struct __kernel_timespec, int}}, \
    {281, "epoll_pwait", 6, {int, struct epoll_event, int, int, const sigset_t, size_t}}, \
    {282, "signalfd", 3, {int, sigset_t, size_t}}, \
    {283, "timerfd_create", 2, {int, int}}, \
    {284, "eventfd", 1, {UINT}}, \
    {285, "fallocate", 4, {int, int, loff_t, loff_t}}, \
    {286, "timerfd_settime", 4, {int, int, const struct __kernel_itimerspec, struct __kernel_itimerspec}}, \
    {287, "timerfd_gettime", 2, {int, struct __kernel_itimerspec}}, \
    {288, "accept4", 4, {int, struct sockaddr, int, int}}, \
    {289, "signalfd4", 4, {int, sigset_t, size_t, int}}, \
    {290, "eventfd2", 2, {UINT, int}}, \
    {291, "epoll_create1", 1, {int}}, \
    {292, "dup3", 3, {UINT, UINT, int}}, \
    {293, "pipe2", 2, {int, int}}, \
    {294, "inotify_init1", 1, {int}}, \
    {295, "preadv", 5, {unsigned long, const struct iovec, unsigned long, unsigned long, unsigned long}}, \
    {296, "pwritev", 5, {unsigned long, const struct iovec, unsigned long, unsigned long, unsigned long}}, \
    {297, "rt_tgsigqueueinfo", 4, {pid_t, pid_t, int, siginfo_t}}, \
    {298, "perf_event_open", 5, {struct perf_event_attr, pid_t, int, int, unsigned long}}, \
    {299, "recvmmsg", 5, {int, struct mmsghdr, UINT, UINT, struct __kernel_timespec}}, \
    {300, "fanotify_init", 2, {UINT, UINT}}, \
    {301, "fanotify_mark", 5, {int, UINT, __u64, int, const char}}, \
    {302, "prlimit64", 4, {pid_t, UINT, const struct rlimit64, struct rlimit64}}, \
    {303, "name_to_handle_at", 5, {int, const char, struct file_handle, int, int}}, \
    {304, "open_by_handle_at", 3, {int, struct file_handle, int}}, \
    {305, "clock_adjtime", 2, {const clockid_t, struct __kernel_timex}}, \
    {306, "syncfs", 1, {int}}, \
    {307, "sendmmsg", 4, {int, struct mmsghdr, UINT, UINT}}, \
    {308, "setns", 2, {int, int}}, \
    {309, "getcpu", 3, {unsigned, unsigned, struct getcpu_cache}}, \
    {310, "process_vm_readv", 6, {pid_t, const struct iovec, unsigned long, const struct iovec, unsigned long, unsigned long}}, \
    {311, "process_vm_writev", 6, {pid_t, const struct iovec, unsigned long, const struct iovec, unsigned long, unsigned long}}, \
    {312, "kcmp", 5, {pid_t, pid_t, int, unsigned long, unsigned long}}, \
    {313, "finit_module", 3, {int, const char, int}}, \
    {314, "sched_setattr", 3, {pid_t, struct sched_attr, UINT}}, \
    {315, "sched_getattr", 4, {pid_t, struct sched_attr, UINT, UINT}}, \
    {316, "renameat2", 5, {int, const char, int, const char, UINT}}, \
    {317, "seccomp", 3, {UINT, UINT, void}}, \
    {318, "getrandom", 3, {char, size_t, UINT}}, \
    {319, "memfd_create", 2, {const char, UINT}}, \
    {320, "kexec_file_load", 5, {int, int, unsigned long, const char, unsigned long}}, \
    {321, "bpf", 3, {int, union bpf_attr, UINT}}, \
    {322, "execveat", 5, {int, const char, const char *const, const char *const, int}}, \
    {323, "userfaultfd", 1, {int}}, \
    {324, "membarrier", 3, {int, UINT, int}}, \
    {325, "mlock2", 3, {unsigned long, size_t, int}}, \
    {326, "copy_file_range", 6, {int, loff_t, int, loff_t, size_t, UINT}}, \
    {327, "preadv2", 6, {unsigned long, const struct iovec, unsigned long, unsigned long, unsigned long, rwf_t}}, \
    {328, "pwritev2", 6, {unsigned long, const struct iovec, unsigned long, unsigned long, unsigned long, rwf_t}}, \
    {329, "pkey_mprotect", 4, {unsigned long, size_t, unsigned long, int}}, \
    {330, "pkey_alloc", 2, {unsigned long, unsigned long}}, \
    {331, "pkey_free", 1, {int}}, \
    {332, "statx", 5, {int, const char, unsigned, UINT, struct statx}}, \
    {333, "io_pgetevents", 6, {aio_context_t, long, long, struct io_event, struct __kernel_timespec, const struct __aio_sigset}}, \
    {334, "rseq", 4, {struct rseq, u32, int, u32}}, \
    {424, "pidfd_send_signal", 4, {int, int, siginfo_t, UINT}}, \
    {425, "io_uring_setup", 2, {u32, struct io_uring_params}}, \
    {426, "io_uring_enter", 6, {UINT, u32, u32, u32, const void, size_t}}, \
    {427, "io_uring_register", 4, {UINT, UINT, void, UINT}}, \
    {428, "open_tree", 3, {int, const char, unsigned}}, \
    {429, "move_mount", 5, {int, const char, int, const char, UINT}}, \
    {430, "fsopen", 2, {const char, UINT}}, \
    {431, "fsconfig", 5, {int, UINT, const char, const void, int}}, \
    {432, "fsmount", 3, {int, UINT, UINT}}, \
    {433, "fspick", 3, {int, const char, UINT}}, \
    {434, "pidfd_open", 2, {pid_t, UINT}}, \
    {435, "clone3", 2, {struct clone_args, size_t}}, \
    {436, "close_range", 3, {UINT, UINT, UINT}}, \
    {437, "openat2", 4, {int, const char, struct open_how, size_t}}, \
    {438, "pidfd_getfd", 3, {int, int, UINT}}, \
    {439, "faccessat2", 4, {int, const char, int, int}}, \
    {440, "process_madvise", 5, {int, const struct iovec, size_t, int, UINT}}, \
    {441, "epoll_pwait2", 6, {int, struct epoll_event, int, const struct __kernel_timespec, const sigset_t, size_t}}, \
    {442, "mount_setattr", 5, {int, const char, UINT, struct mount_attr, size_t}}, \
    {443, "quotactl_fd", 4, {UINT, UINT, qid_t, void}}, \
    {444, "landlock_create_ruleset", 3, {const struct landlock_ruleset_attr *const, const size_t, const __u32}}, \
    {445, "landlock_add_rule", 4, {const int, const enum landlock_rule_type, const void *const, const __u32}}, \
    {446, "landlock_restrict_self", 2, {const int, const __u32}}, \
    {447, "memfd_secret", 1, {UINT}}, \
    {448, "process_mrelease", 2, {int, UINT}}, \
    {449, "futex_waitv", 5, {struct futex_waitv, UINT, UINT, struct __kernel_timespec, clockid_t}}, \
    {450, "set_mempolicy_home_node", 4, {unsigned long, unsigned long, unsigned long, unsigned long}}, \
    {451, "cachestat", 4, {UINT, struct cachestat_range, struct cachestat, UINT}}, \
    {452, "fchmodat2", 4, {int, const char, umode_t, UINT}}, \
    {453, "map_shadow_stack", 3, {unsigned long, unsigned long, UINT}}, \
    {454, "futex_wake", 4, {void, unsigned long, int, UINT}}, \
    {455, "futex_wait", 6, {void, unsigned long, unsigned long, UINT, struct __kernel_timespec, clockid_t}}, \
    {456, "futex_requeue", 4, {struct futex_waitv, UINT, int, int}}, \
    {457, "statmount", 4, {const struct mnt_id_req, struct statmount, size_t, UINT}}, \
    {458, "listmount", 4, {const struct mnt_id_req, u64, size_t, UINT}}, \
    {459, "lsm_get_self_attr", 4, {UINT, struct lsm_ctx, size_t, u32}}, \
    {460, "lsm_set_self_attr", 4, {UINT, struct lsm_ctx, size_t, u32}}, \
    {461, "lsm_list_modules", 3, {u64, size_t, u32}}, \
};

// #define X64_SYSCALLS_LIST { \
// [  0] = {"read", 3, {UINT, CHARP, SIZET}}, \
// [  1] = {"write", 3, {UINT, CHARP, SIZET}}, \
// [  2] = {"open", 3, {CHARP, INT, UMODET}}, \
// [  3] = {"close", 1, {UINT}}, \
// [  4] = {"newstat", 2, {CHARP, STUCTSTAT}}, \
// [  5] = {"newfstat", 2, {UINT, STUCTSTAT}}, \
// [  6] = {"newlstat", 2, {CHARP, STUCTSTAT}}, \
// [  7] = {"poll", 3, {STUCTPOLLFD, UINT, INT}}, \
// [  8] = {"lseek", 3, {UINT, OFFT, UINT}}, \
// [  9] = {"mmap", 6, {ULONG, ULONG, ULONG, ULONG, ULONG, ULONG}}, \
// [ 10] = {"mprotect", 3, {ULONG, SIZET, ULONG}}, \
// [ 11] = {"munmap", 2, {ULONG, SIZET}}, \
// [ 12] = {"brk", 1, {ULONG}}, \
// [ 13] = {"rt_sigaction", 4, {INT, 0, 0, SIZET}}, \
// [ 14] = {"rt_sigprocmask", 4, {INT, SIGSETT, SIGSETT, SIZET}}, \
// [ 15] = {"rt_sigreturn", 0, {}}, \
// [ 16] = {"ioctl", 3, {UINT, UINT, ULONG}}, \
// [ 17] = {"pread64", 4, {UINT, CHARP, SIZET, lOFFT}}, \
// [ 18] = {"pwrite64", 4, {UINT, CHARP, SIZET, lOFFT}}, \
// [ 19] = {"readv", 3, {ULONG, CSTRUCTIOVEC, ULONG}}, \
// [ 20] = {"writev", 3, {ULONG, CSTRUCTIOVEC, ULONG}}, \
// [ 21] = {"access", 2, {CHARP, INT}}, \
// [ 22] = {"pipe", 1, {INT}}, \
// [ 23] = {"select", 5, {INT, fd_set, fd_set, fd_set, 0}}, \
// [ 24] = {"sched_yield", 0, {}}, \
// [ 25] = {"mremap", 5, {ULONG, ULONG, ULONG, ULONG, ULONG}}, \
// [ 26] = {"msync", 3, {ULONG, SIZET, INT}}, \
// [ 27] = {"mincore", 3, {ULONG, SIZET, UCHARP}}, \
// [ 28] = {"madvise", 3, {ULONG, SIZET, INT}}, \
// [ 29] = {"shmget", 3, {0, SIZET, INT}}, \
// [ 30] = {"shmat", 3, {INT, CHARP, INT}}, \
// [ 31] = {"shmctl", 3, {INT, INT, 0}}, \
// [ 32] = {"dup", 1, {UINT}}, \
// [ 33] = {"dup2", 2, {UINT, UINT}}, \
// [ 34] = {"pause", 0, {}}, \
// [ 35] = {"nanosleep", 2, {SKTIME, SKTIME}}, \
// [ 36] = {"getitimer", 2, {INT, 0}}, \
// [ 37] = {"alarm", 1, {UINT}}, \
// [ 38] = {"setitimer", 3, {INT, 0, 0}}, \
// [ 39] = {"getpid", 0, {}}, \
// [ 40] = {"sendfile64", 4, {INT, INT, lOFFT, SIZET}}, \
// [ 41] = {"socket", 3, {INT, INT, INT}}, \
// [ 42] = {"connect", 3, {INT, SSOCKADDR, INT}}, \
// [ 43] = {"accept", 3, {INT, SSOCKADDR, INT}}, \
// [ 44] = {"sendto", 6, {INT, VOID, SIZET, UINT, SSOCKADDR, INT}}, \
// [ 45] = {"recvfrom", 6, {INT, VOID, SIZET, UINT, SSOCKADDR, INT}}, \
// [ 46] = {"sendmsg", 3, {INT, 0, UINT}}, \
// [ 47] = {"recvmsg", 3, {INT, 0, UINT}}, \
// [ 48] = {"shutdown", 2, {INT, INT}}, \
// [ 49] = {"bind", 3, {INT, SSOCKADDR, INT}}, \
// [ 50] = {"listen", 2, {INT, INT}}, \
// [ 51] = {"getsockname", 3, {INT, SSOCKADDR, INT}}, \
// [ 52] = {"getpeername", 3, {INT, SSOCKADDR, INT}}, \
// [ 53] = {"socketpair", 4, {INT, INT, INT, INT}}, \
// [ 54] = {"setsockopt", 5, {INT, INT, INT, CHARP, INT}}, \
// [ 55] = {"getsockopt", 5, {INT, INT, INT, CHARP, INT}}, \
// [ 56] = {"clone", 5, {ULONG, ULONG, INT, INT, ULONG}}, \
// [ 57] = {"fork", 0, {}}, \
// [ 58] = {"vfork", 0, {}}, \
// [ 59] = {"execve", 3, {CHARP, CHARPP, CHARPP}}, \
// [ 60] = {"exit", 1, {INT}}, \
// [ 61] = {"wait4", 4, {PIDT, INT, INT, 0}}, \
// [ 62] = {"kill", 2, {PIDT, INT}}, \
// [ 63] = {"newuname", 1, {0}}, \
// [ 64] = {"semget", 3, {0, INT, INT}}, \
// [ 65] = {"semop", 3, {INT, 0, 0}}, \
// [ 66] = {"semctl", 4, {INT, INT, INT, ULONG}}, \
// [ 67] = {"shmdt", 1, {CHARP}}, \
// [ 68] = {"msgget", 2, {0, INT}}, \
// [ 69] = {"msgsnd", 4, {INT, 0, SIZET, INT}}, \
// [ 70] = {"msgrcv", 5, {INT, 0, SIZET, LONG, INT}}, \
// [ 71] = {"msgctl", 3, {INT, INT, 0}}, \
// [ 72] = {"fcntl", 3, {UINT, UINT, ULONG}}, \
// [ 73] = {"flock", 2, {UINT, UINT}}, \
// [ 74] = {"fsync", 1, {UINT}}, \
// [ 75] = {"fdatasync", 1, {UINT}}, \
// [ 76] = {"truncate", 2, {CHARP, LONG}}, \
// [ 77] = {"ftruncate", 2, {UINT, ULONG}}, \
// [ 78] = {"getdents", 3, {UINT, 0, UINT}}, \
// [ 79] = {"getcwd", 2, {CHARP, ULONG}}, \
// [ 80] = {"chdir", 1, {CHARP}}, \
// [ 81] = {"fchdir", 1, {UINT}}, \
// [ 82] = {"rename", 2, {CHARP, CHARP}}, \
// [ 83] = {"mkdir", 2, {CHARP, UMODET}}, \
// [ 84] = {"rmdir", 1, {CHARP}}, \
// [ 85] = {"creat", 2, {CHARP, UMODET}}, \
// [ 86] = {"link", 2, {CHARP, CHARP}}, \
// [ 87] = {"unlink", 1, {CHARP}}, \
// [ 88] = {"symlink", 2, {CHARP, CHARP}}, \
// [ 89] = {"readlink", 3, {CHARP, CHARP, INT}}, \
// [ 90] = {"chmod", 2, {CHARP, UMODET}}, \
// [ 91] = {"fchmod", 2, {UINT, UMODET}}, \
// [ 92] = {"chown", 3, {CHARP, UIDT, GIDT}}, \
// [ 93] = {"fchown", 3, {UINT, UIDT, GIDT}}, \
// [ 94] = {"lchown", 3, {CHARP, UIDT, GIDT}}, \
// [ 95] = {"umask", 1, {INT}}, \
// [ 96] = {"gettimeofday", 2, {0, 0}}, \
// [ 97] = {"getrlimit", 2, {UINT, 0}}, \
// [ 98] = {"getrusage", 2, {INT, 0}}, \
// [ 99] = {"sysinfo", 1, {0}}, \
// [100] = {"times", 1, {0}}, \
// [101] = {"ptrace", 4, {LONG, LONG, ULONG, ULONG}}, \
// [102] = {"getuid", 0, {}}, \
// [103] = {"syslog", 3, {INT, CHARP, INT}}, \
// [104] = {"getgid", 0, {}}, \
// [105] = {"setuid", 1, {UIDT}}, \
// [106] = {"setgid", 1, {GIDT}}, \
// [107] = {"geteuid", 0, {}}, \
// [108] = {"getegid", 0, {}}, \
// [109] = {"setpgid", 2, {PIDT, PIDT}}, \
// [110] = {"getppid", 0, {}}, \
// [111] = {"getpgrp", 0, {}}, \
// [112] = {"setsid", 0, {}}, \
// [113] = {"setreuid", 2, {UIDT, UIDT}}, \
// [114] = {"setregid", 2, {GIDT, GIDT}}, \
// [115] = {"getgroups", 2, {INT, GIDT}}, \
// [116] = {"setgroups", 2, {INT, GIDT}}, \
// [117] = {"setresuid", 3, {UIDT, UIDT, UIDT}}, \
// [118] = {"getresuid", 3, {UIDT, UIDT, UIDT}}, \
// [119] = {"setresgid", 3, {GIDT, GIDT, GIDT}}, \
// [120] = {"getresgid", 3, {GIDT, GIDT, GIDT}}, \
// [121] = {"getpgid", 1, {PIDT}}, \
// [122] = {"setfsuid", 1, {UIDT}}, \
// [123] = {"setfsgid", 1, {GIDT}}, \
// [124] = {"getsid", 1, {PIDT}}, \
// [125] = {"capget", 2, {0, 0}}, \
// [126] = {"capset", 2, {0, 0}}, \
// [127] = {"rt_sigpending", 2, {SIGSETT, SIZET}}, \
// [128] = {"rt_sigtimedwait", 4, {SIGSETT, SIGINFOT, SKTIME, SIZET}}, \
// [129] = {"rt_sigqueueinfo", 3, {PIDT, INT, SIGINFOT}}, \
// [130] = {"rt_sigsuspend", 2, {SIGSETT, SIZET}}, \
// [131] = {"sigaltstack", 2, {0, 0}}, \
// [132] = {"utime", 2, {CHARP, 0}}, \
// [133] = {"mknod", 3, {CHARP, UMODET, 0}}, \
// [135] = {"personality", 1, {UINT}}, \
// [136] = {"ustat", 2, {0, 0}}, \
// [137] = {"statfs", 2, {CHARP, STUCTSTAT}}, \
// [138] = {"fstatfs", 2, {UINT, STUCTSTAT}}, \
// [139] = {"sysfs", 3, {INT, ULONG, ULONG}}, \
// [140] = {"getpriority", 2, {INT, INT}}, \
// [141] = {"setpriority", 3, {INT, INT, INT}}, \
// [142] = {"sched_setparam", 2, {PIDT, 0}}, \
// [143] = {"sched_getparam", 2, {PIDT, 0}}, \
// [144] = {"sched_setscheduler", 3, {PIDT, INT, 0}}, \
// [145] = {"sched_getscheduler", 1, {PIDT}}, \
// [146] = {"sched_get_priority_max", 1, {INT}}, \
// [147] = {"sched_get_priority_min", 1, {INT}}, \
// [148] = {"sched_rr_get_INTerval", 2, {PIDT, SKTIME}}, \
// [149] = {"mlock", 2, {ULONG, SIZET}}, \
// [150] = {"munlock", 2, {ULONG, SIZET}}, \
// [151] = {"mlockall", 1, {INT}}, \
// [152] = {"munlockall", 0, {}}, \
// [153] = {"vhangup", 0, {}}, \
// [154] = {"modify_ldt", 3, {INT, VOID, ULONG}}, \
// [155] = {"pivot_root", 2, {CHARP, CHARP}}, \
// [157] = {"prctl", 5, {INT, ULONG, ULONG, ULONG, ULONG}}, \
// [158] = {"arch_prctl", 2, {INT, ULONG}}, \
// [159] = {"adjtimex", 1, {0}}, \
// [160] = {"setrlimit", 2, {UINT, 0}}, \
// [161] = {"chroot", 1, {CHARP}}, \
// [162] = {"sync", 0, {}}, \
// [163] = {"acct", 1, {CHARP}}, \
// [164] = {"settimeofday", 2, {0, 0}}, \
// [165] = {"mount", 5, {CHARP, CHARP, CHARP, ULONG, VOID}}, \
// [166] = {"umount", 2, {CHARP, INT}}, \
// [167] = {"swapon", 2, {CHARP, INT}}, \
// [168] = {"swapoff", 1, {CHARP}}, \
// [169] = {"reboot", 4, {INT, INT, UINT, VOID}}, \
// [170] = {"sethostname", 2, {CHARP, INT}}, \
// [171] = {"setdomainname", 2, {CHARP, INT}}, \
// [172] = {"iopl", 1, {UINT}}, \
// [173] = {"ioperm", 3, {ULONG, ULONG, INT}}, \
// [175] = {"init_module", 3, {VOID, ULONG, CHARP}}, \
// [176] = {"delete_module", 2, {CHARP, UINT}}, \
// [179] = {"quotactl", 4, {UINT, CHARP, 0, VOID}}, \
// [186] = {"gettid", 0, {}}, \
// [187] = {"readahead", 3, {INT, lOFFT, SIZET}}, \
// [188] = {"setxattr", 5, {CHARP, CHARP, VOID, SIZET, INT}}, \
// [189] = {"lsetxattr", 5, {CHARP, CHARP, VOID, SIZET, INT}}, \
// [190] = {"fsetxattr", 5, {INT, CHARP, VOID, SIZET, INT}}, \
// [191] = {"getxattr", 4, {CHARP, CHARP, VOID, SIZET}}, \
// [192] = {"lgetxattr", 4, {CHARP, CHARP, VOID, SIZET}}, \
// [193] = {"fgetxattr", 4, {INT, CHARP, VOID, SIZET}}, \
// [194] = {"listxattr", 3, {CHARP, CHARP, SIZET}}, \
// [195] = {"llistxattr", 3, {CHARP, CHARP, SIZET}}, \
// [196] = {"flistxattr", 3, {INT, CHARP, SIZET}}, \
// [197] = {"removexattr", 2, {CHARP, CHARP}}, \
// [198] = {"lremovexattr", 2, {CHARP, CHARP}}, \
// [199] = {"fremovexattr", 2, {INT, CHARP}}, \
// [200] = {"tkill", 2, {PIDT, INT}}, \
// [201] = {"time", 1, {0}}, \
// [202] = {"futex", 6, {u32, INT, u32, SKTIME, u32, u32}}, \
// [203] = {"sched_setaffinity", 3, {PIDT, UINT, ULONG}}, \
// [204] = {"sched_getaffinity", 3, {PIDT, UINT, ULONG}}, \
// [206] = {"io_setup", 2, {0, 0}}, \
// [207] = {"io_destroy", 1, {0}}, \
// [208] = {"io_getevents", 5, {0, LONG, LONG, 0, SKTIME}}, \
// [209] = {"io_submit", 3, {0, LONG, 0}}, \
// [210] = {"io_cancel", 3, {0, 0, 0}}, \
// [213] = {"epoll_create", 1, {INT}}, \
// [216] = {"remap_file_pages", 5, {ULONG, ULONG, ULONG, ULONG, ULONG}}, \
// [217] = {"getdents64", 3, {UINT, 0, UINT}}, \
// [218] = {"set_tid_address", 1, {INT}}, \
// [219] = {"restart_syscall", 0, {}}, \
// [220] = {"semtimedop", 4, {INT, 0, UINT, SKTIME}}, \
// [221] = {"fadvise64", 4, {INT, lOFFT, lOFFT, INT}}, \
// [222] = {"timer_create", 3, {0, 0, 0}}, \
// [223] = {"timer_settime", 4, {0, INT, 0, 0}}, \
// [224] = {"timer_gettime", 2, {0, 0}}, \
// [225] = {"timer_getoverrun", 1, {0}}, \
// [226] = {"timer_delete", 1, {0}}, \
// [227] = {"clock_settime", 2, {0, SKTIME}}, \
// [228] = {"clock_gettime", 2, {0, SKTIME}}, \
// [229] = {"clock_getres", 2, {0, SKTIME}}, \
// [230] = {"clock_nanosleep", 4, {0, INT, SKTIME, SKTIME}}, \
// [231] = {"exit_group", 1, {INT}}, \
// [232] = {"epoll_wait", 4, {INT, 0, INT, INT}}, \
// [233] = {"epoll_ctl", 4, {INT, INT, INT, 0}}, \
// [234] = {"tgkill", 3, {PIDT, PIDT, INT}}, \
// [235] = {"utimes", 2, {CHARP, 0}}, \
// [237] = {"mbind", 6, {ULONG, ULONG, ULONG, ULONG, ULONG, UINT}}, \
// [238] = {"set_mempolicy", 3, {INT, ULONG, ULONG}}, \
// [239] = {"get_mempolicy", 5, {INT, ULONG, ULONG, ULONG, ULONG}}, \
// [240] = {"mq_open", 4, {CHARP, INT, UMODET, 0}}, \
// [241] = {"mq_unlink", 1, {CHARP}}, \
// [242] = {"mq_timedsend", 5, {0, CHARP, SIZET, UINT, SKTIME}}, \
// [243] = {"mq_timedreceive", 5, {0, CHARP, SIZET, UINT, SKTIME}}, \
// [244] = {"mq_notify", 2, {0, 0}}, \
// [245] = {"mq_getsetattr", 3, {0, 0, 0}}, \
// [246] = {"kexec_load", 4, {ULONG, ULONG, 0, ULONG}}, \
// [247] = {"waitid", 5, {INT, PIDT, 0, INT, 0}}, \
// [248] = {"add_key", 5, {CHARP, CHARP, VOID, SIZET, 0}}, \
// [249] = {"request_key", 4, {CHARP, CHARP, CHARP, 0}}, \
// [250] = {"keyctl", 5, {INT, ULONG, ULONG, ULONG, ULONG}}, \
// [251] = {"ioprio_set", 3, {INT, INT, INT}}, \
// [252] = {"ioprio_get", 2, {INT, INT}}, \
// [253] = {"inotify_init", 0, {}}, \
// [254] = {"inotify_add_watch", 3, {INT, CHARP, u32}}, \
// [255] = {"inotify_rm_watch", 2, {INT, __s32}}, \
// [256] = {"migrate_pages", 4, {PIDT, ULONG, ULONG, ULONG}}, \
// [257] = {"openat", 4, {INT, CHARP, INT, UMODET}}, \
// [258] = {"mkdirat", 3, {INT, CHARP, UMODET}}, \
// [259] = {"mknodat", 4, {INT, CHARP, UMODET, UINT}}, \
// [260] = {"fchownat", 5, {INT, CHARP, UIDT, GIDT, INT}}, \
// [261] = {"futimesat", 3, {INT, CHARP, 0}}, \
// [262] = {"newfstatat", 4, {INT, CHARP, STUCTSTAT, INT}}, \
// [263] = {"unlinkat", 3, {INT, CHARP, INT}}, \
// [264] = {"renameat", 4, {INT, CHARP, INT, CHARP}}, \
// [265] = {"linkat", 5, {INT, CHARP, INT, CHARP, INT}}, \
// [266] = {"symlinkat", 3, {CHARP, INT, CHARP}}, \
// [267] = {"readlinkat", 4, {INT, CHARP, CHARP, INT}}, \
// [268] = {"fchmodat", 3, {INT, CHARP, UMODET}}, \
// [269] = {"faccessat", 3, {INT, CHARP, INT}}, \
// [270] = {"pselect6", 6, {INT, fd_set, fd_set, fd_set, SKTIME, VOID}}, \
// [271] = {"ppoll", 5, {STUCTPOLLFD, UINT, SKTIME, SIGSETT, SIZET}}, \
// [272] = {"unshare", 1, {ULONG}}, \
// [273] = {"set_robust_list", 2, {0, SIZET}}, \
// [274] = {"get_robust_list", 3, {INT, 0 *, SIZET}}, \
// [275] = {"splice", 6, {INT, lOFFT, INT, lOFFT, SIZET, UINT}}, \
// [276] = {"tee", 4, {INT, INT, SIZET, UINT}}, \
// [277] = {"sync_file_range", 4, {INT, lOFFT, lOFFT, UINT}}, \
// [278] = {"vmsplice", 4, {INT, CSTRUCTIOVEC, ULONG, UINT}}, \
// [279] = {"move_pages", 6, {PIDT, ULONG, VOID *, INT, INT, INT}}, \
// [280] = {"utimensat", 4, {INT, CHARP, SKTIME, INT}}, \
// [281] = {"epoll_pwait", 6, {INT, 0, INT, INT, SIGSETT, SIZET}}, \
// [282] = {"signalfd", 3, {INT, SIGSETT, SIZET}}, \
// [283] = {"timerfd_create", 2, {INT, INT}}, \
// [284] = {"eventfd", 1, {UINT}}, \
// [285] = {"fallocate", 4, {INT, INT, lOFFT, lOFFT}}, \
// [286] = {"timerfd_settime", 4, {INT, INT, 0, 0}}, \
// [287] = {"timerfd_gettime", 2, {INT, 0}}, \
// [288] = {"accept4", 4, {INT, SSOCKADDR, INT, INT}}, \
// [289] = {"signalfd4", 4, {INT, SIGSETT, SIZET, INT}}, \
// [290] = {"eventfd2", 2, {UINT, INT}}, \
// [291] = {"epoll_create1", 1, {INT}}, \
// [292] = {"dup3", 3, {UINT, UINT, INT}}, \
// [293] = {"pipe2", 2, {INT, INT}}, \
// [294] = {"inotify_init1", 1, {INT}}, \
// [295] = {"preadv", 5, {ULONG, CSTRUCTIOVEC, ULONG, ULONG, ULONG}}, \
// [296] = {"pwritev", 5, {ULONG, CSTRUCTIOVEC, ULONG, ULONG, ULONG}}, \
// [297] = {"rt_tgsigqueueinfo", 4, {PIDT, PIDT, INT, SIGINFOT}}, \
// [298] = {"perf_event_open", 5, {0, PIDT, INT, INT, ULONG}}, \
// [299] = {"recvmmsg", 5, {INT, 0, UINT, UINT, SKTIME}}, \
// [300] = {"fanotify_init", 2, {UINT, UINT}}, \
// [301] = {"fanotify_mark", 5, {INT, UINT, __ULONG, INT, CHARP}}, \
// [302] = {"prlimit64", 4, {PIDT, UINT, 0, 0}}, \
// [303] = {"name_to_handle_at", 5, {INT, CHARP, 0, INT, INT}}, \
// [304] = {"open_by_handle_at", 3, {INT, 0, INT}}, \
// [305] = {"clock_adjtime", 2, {0, 0}}, \
// [306] = {"syncfs", 1, {INT}}, \
// [307] = {"sendmmsg", 4, {INT, 0, UINT, UINT}}, \
// [308] = {"setns", 2, {INT, INT}}, \
// [309] = {"getcpu", 3, {0, 0, 0}}, \
// [310] = {"process_vm_readv", 6, {PIDT, CSTRUCTIOVEC, ULONG, CSTRUCTIOVEC, ULONG, ULONG}}, \
// [311] = {"process_vm_writev", 6, {PIDT, CSTRUCTIOVEC, ULONG, CSTRUCTIOVEC, ULONG, ULONG}}, \
// [312] = {"kcmp", 5, {PIDT, PIDT, INT, ULONG, ULONG}}, \
// [313] = {"finit_module", 3, {INT, CHARP, INT}}, \
// [314] = {"sched_setattr", 3, {PIDT, 0, UINT}}, \
// [315] = {"sched_getattr", 4, {PIDT, 0, UINT, UINT}}, \
// [316] = {"renameat2", 5, {INT, CHARP, INT, CHARP, UINT}}, \
// [317] = {"seccomp", 3, {UINT, UINT, VOID}}, \
// [318] = {"getrandom", 3, {CHARP, SIZET, UINT}}, \
// [319] = {"memfd_create", 2, {CHARP, UINT}}, \
// [320] = {"kexec_file_load", 5, {INT, INT, ULONG, CHARP, ULONG}}, \
// [321] = {"bpf", 3, {INT, 0}}, \
// [322] = {"execveat", 5, {INT, CHARP, CHARPP, CHARPP, INT}}, \
// [323] = {"userfaultfd", 1, {INT}}, \
// [324] = {"membarrier", 3, {INT, UINT, INT}}, \
// [325] = {"mlock2", 3, {ULONG, SIZET, INT}}, \
// [326] = {"copy_file_range", 6, {INT, lOFFT, INT, lOFFT, SIZET, UINT}}, \
// [327] = {"preadv2", 6, {ULONG, CSTRUCTIOVEC, ULONG, ULONG, ULONG, 0}}, \
// [328] = {"pwritev2", 6, {ULONG, CSTRUCTIOVEC, ULONG, ULONG, ULONG, 0}}, \
// [329] = {"pkey_mprotect", 4, {ULONG, SIZET, ULONG, INT}}, \
// [330] = {"pkey_alloc", 2, {ULONG, ULONG}}, \
// [331] = {"pkey_free", 1, {INT}}, \
// [332] = {"statx", 5, {INT, CHARP, 0, UINT, STUCTSTAT}}, \
// [333] = {"io_pgetevents", 6, {0, LONG, LONG, 0, SKTIME, 0}}, \
// [334] = {"rseq", 4, {0, u32, INT, u32}}, \
// [424] = {"pidfd_send_signal", 4, {INT, INT, SIGINFOT, UINT}}, \
// [425] = {"io_uring_setup", 2, {u32, 0}}, \
// [426] = {"io_uring_enter", 6, {UINT, u32, u32, u32, VOID, SIZET}}, \
// [427] = {"io_uring_register", 4, {UINT, UINT, VOID, UINT}}, \
// [428] = {"open_tree", 3, {INT, CHARP, 0}}, \
// [429] = {"move_mount", 5, {INT, CHARP, INT, CHARP, UINT}}, \
// [430] = {"fsopen", 2, {CHARP, UINT}}, \
// [431] = {"fsconfig", 5, {INT, UINT, CHARP, VOID, INT}}, \
// [432] = {"fsmount", 3, {INT, UINT, UINT}}, \
// [433] = {"fspick", 3, {INT, CHARP, UINT}}, \
// [434] = {"pidfd_open", 2, {PIDT, UINT}}, \
// [435] = {"clone3", 2, {0, SIZET}}, \
// [436] = {"close_range", 3, {UINT, UINT, UINT}}, \
// [437] = {"openat2", 4, {INT, CHARP, 0, SIZET}}, \
// [438] = {"pidfd_getfd", 3, {INT, INT, UINT}}, \
// [439] = {"faccessat2", 4, {INT, CHARP, INT, INT}}, \
// [440] = {"process_madvise", 5, {INT, CSTRUCTIOVEC, SIZET, INT, UINT}}, \
// [441] = {"epoll_pwait2", 6, {INT, 0, INT, SKTIME, SIGSETT, SIZET}}, \
// [442] = {"mount_setattr", 5, {INT, CHARP, UINT, 0, SIZET}}, \
// [443] = {"quotactl_fd", 4, {UINT, UINT, 0, VOID}}, \
// [444] = {"landlock_create_ruleset", 3, {0, SIZET, __u32}}, \
// [445] = {"landlock_add_rule", 4, {INT, 0, VOID, __u32}}, \
// [446] = {"landlock_restrict_self", 2, {INT, __u32}}, \
// [447] = {"memfd_secret", 1, {UINT}}, \
// [448] = {"process_mrelease", 2, {INT, UINT}}, \
// [449] = {"futex_waitv", 5, {0, UINT, UINT, SKTIME, 0}}, \
// [450] = {"set_mempolicy_home_node", 4, {ULONG, ULONG, ULONG, ULONG}}, \
// [451] = {"cachestat", 4, {UINT, 0, 0, UINT}}, \
// [452] = {"fchmodat2", 4, {INT, CHARP, UMODET, UINT}}, \
// [453] = {"map_shadow_stack", 3, {ULONG, ULONG, UINT}}, \
// [454] = {"futex_wake", 4, {VOID, ULONG, INT, UINT}}, \
// [455] = {"futex_wait", 6, {VOID, ULONG, ULONG, UINT, SKTIME, 0}}, \
// [456] = {"futex_requeue", 4, {0, UINT, INT, INT}}, \
// [457] = {"statmount", 4, {0, STUCTSTAT, SIZET, UINT}}, \
// [458] = {"listmount", 4, {0, ULONG, SIZET, UINT}}, \
// [459] = {"lsm_get_self_attr", 4, {UINT, 0, SIZET, u32}}, \
// [460] = {"lsm_set_self_attr", 4, {UINT, 0, SIZET, u32}}, \
// [461] = {"lsm_list_modules", 3, {ULONG, SIZET, u32}} \
// }

#endif

#ifndef X64_SYSCALLS_H
# define X64_SYSCALLS_H


#define X64_SYSCALLS_LIST { \
   {0, "read", 3,UINT, CHARP, SIZET}, \
   {1, "write", 3,UINT, CHARP, SIZET}, \
   {2, "open", 3,CHARP, INT, 0}, \
   {3, "close", 1,UINT}, \
   {4, "newstat", 2,CHARP, 0}, \
   {5, "newfstat", 2,UINT, 0}, \
   {6, "newlstat", 2,CHARP, 0}, \
   {7, "poll", 3,0, UINT, INT}, \
   {8, "lseek", 3,UINT, 0, UINT}, \
   {9, "mmap", 6,ULONG, ULONG, ULONG, ULONG, ULONG, ULONG}, \
   {10, "mprotect", 3,ULONG, SIZET, ULONG}, \
   {11, "munmap", 2,ULONG, SIZET}, \
   {12, "brk", 1,0}, \
   {13, "rt_sigaction", 4,INT, 0, 0, SIZET}, \
   {14, "rt_sigprocmask", 4,INT, 0, 0, SIZET}, \
   {15, "rt_sigreturn", 0,}, \
   {16, "ioctl", 3,UINT, UINT, ULONG}, \
   {17, "pread64", 4,UINT, CHARP, SIZET, 0}, \
   {18, "pwrite64", 4,UINT, CHARP, SIZET, 0}, \
   {19, "readv", 3,ULONG, 0, ULONG}, \
   {20, "writev", 3,ULONG, 0, ULONG}, \
   {21, "access", 2,CHARP, INT}, \
   {22, "pipe", 1,0}, \
   {23, "select", 5,INT, 0, 0, 0, 0}, \
   {24, "sched_yield", 0,}, \
   {25, "mremap", 5,ULONG, ULONG, ULONG, ULONG, ULONG}, \
   {26, "msync", 3,ULONG, SIZET, INT}, \
   {27, "mincore", 3,ULONG, SIZET, 0}, \
   {28, "madvise", 3,ULONG, SIZET, INT}, \
   {29, "shmget", 3,INT, SIZET, INT}, \
   {30, "shmat", 3,INT, CHARP, INT}, \
   {31, "shmctl", 3,INT, INT, 0}, \
   {32, "dup", 1,UINT}, \
   {33, "dup2", 2,UINT, UINT}, \
   {34, "pause", 0,}, \
   {35, "nanosleep", 2,0, 0}, \
   {36, "getitimer", 2,INT, 0}, \
   {37, "alarm", 1,UINT}, \
   {38, "setitimer", 3,INT, 0, 0}, \
   {39, "getpid", 0,}, \
   {40, "sendfile64", 4,INT, INT, 0, SIZET}, \
   {41, "socket", 3,INT, INT, INT}, \
   {42, "connect", 3,INT, 0, INT}, \
   {43, "accept", 3,INT, 0, 0}, \
   {44, "sendto", 6,INT, 0, SIZET, UINT, 0, INT}, \
   {45, "recvfrom", 6,INT, 0, SIZET, UINT, 0, 0}, \
   {46, "sendmsg", 3,INT, 0, UINT}, \
   {47, "recvmsg", 3,INT, 0, UINT}, \
   {48, "shutdown", 2,INT, INT}, \
   {49, "bind", 3,INT, 0, INT}, \
   {50, "listen", 2,INT, INT}, \
   {51, "getsockname", 3,INT, 0, 0}, \
   {52, "getpeername", 3,INT, 0, 0}, \
   {53, "socketpair", 4,INT, INT, INT, 0}, \
   {54, "setsockopt", 5,INT, INT, INT, CHARP, INT}, \
   {55, "getsockopt", 5,INT, INT, INT, CHARP, 0}, \
   {56, "clone", 5,ULONG, ULONG, 0, 0, ULONG}, \
   {57, "fork", 0,}, \
   {58, "vfork", 0,}, \
   {59, "execve", 3,CHARP, 0, 0}, \
   {60, "exit", 1,INT}, \
   {61, "wait4", 4,INT, 0, INT, 0}, \
   {62, "kill", 2,INT, INT}, \
   {63, "newuname", 1,0}, \
   {64, "semget", 3,INT, INT, INT}, \
   {65, "semop", 3,INT, 0, 0}, \
   {66, "semctl", 4,INT, INT, INT, ULONG}, \
   {67, "shmdt", 1,CHARP}, \
   {68, "msgget", 2,INT, INT}, \
   {69, "msgsnd", 4,INT, 0, SIZET, INT}, \
   {70, "msgrcv", 5,INT, 0, SIZET, LONG, INT}, \
   {71, "msgctl", 3,INT, INT, 0}, \
   {72, "fcntl", 3,UINT, UINT, ULONG}, \
   {73, "flock", 2,UINT, UINT}, \
   {74, "fsync", 1,UINT}, \
   {75, "fdatasync", 1,UINT}, \
   {76, "truncate", 2,CHARP, LONG}, \
   {77, "ftruncate", 2,UINT, ULONG}, \
   {78, "getdents", 3,UINT, 0, UINT}, \
   {79, "getcwd", 2,CHARP, ULONG}, \
   {80, "chdir", 1,CHARP}, \
   {81, "fchdir", 1,UINT}, \
   {82, "rename", 2,CHARP, CHARP}, \
   {83, "mkdir", 2,CHARP, 0}, \
   {84, "rmdir", 1,CHARP}, \
   {85, "creat", 2,CHARP, 0}, \
   {86, "link", 2,CHARP, CHARP}, \
   {87, "unlink", 1,CHARP}, \
   {88, "symlink", 2,CHARP, CHARP}, \
   {89, "readlink", 3,CHARP, CHARP, INT}, \
   {90, "chmod", 2,CHARP, 0}, \
   {91, "fchmod", 2,UINT, 0}, \
   {92, "chown", 3,CHARP, UINT, UINT}, \
   {93, "fchown", 3,UINT, UINT, UINT}, \
   {94, "lchown", 3,CHARP, UINT, UINT}, \
   {95, "umask", 1,INT}, \
   {96, "gettimeofday", 2,0, 0}, \
   {97, "getrlimit", 2,UINT, 0}, \
   {98, "getrusage", 2,INT, 0}, \
   {99, "sysinfo", 1,0}, \
   {100, "times", 1,0}, \
   {101, "ptrace", 4,LONG, LONG, ULONG, ULONG}, \
   {102, "getuid", 0,}, \
   {103, "syslog", 3,INT, CHARP, INT}, \
   {104, "getgid", 0,}, \
   {105, "setuid", 1,UINT}, \
   {106, "setgid", 1,UINT}, \
   {107, "geteuid", 0,}, \
   {108, "getegid", 0,}, \
   {109, "setpgid", 2,INT, INT}, \
   {110, "getppid", 0,}, \
   {111, "getpgrp", 0,}, \
   {112, "setsid", 0,}, \
   {113, "setreuid", 2,UINT, UINT}, \
   {114, "setregid", 2,UINT, UINT}, \
   {115, "getgroups", 2,INT, UINT }, \
   {116, "setgroups", 2,INT, UINT }, \
   {117, "setresuid", 3,UINT, UINT, UINT}, \
   {118, "getresuid", 3,UINT , UINT , UINT }, \
   {119, "setresgid", 3,UINT, UINT, UINT}, \
   {120, "getresgid", 3,UINT , UINT , UINT }, \
   {121, "getpgid", 1,INT}, \
   {122, "setfsuid", 1,UINT}, \
   {123, "setfsgid", 1,UINT}, \
   {124, "getsid", 1,INT}, \
   {125, "capget", 2,0, 0}, \
   {126, "capset", 2,0, 0}, \
   {127, "rt_sigpending", 2,0, SIZET}, \
   {128, "rt_sigtimedwait", 4,UINT, 0, 0, SIZET}, \
   {129, "rt_sigqueueinfo", 3,INT, INT, 0}, \
   {130, "rt_sigsuspend", 2,0, SIZET}, \
   {131, "sigaltstack", 2,0, 0}, \
   {132, "utime", 2,CHARP, 0}, \
   {133, "mknod", 3,CHARP, 0, 0}, \
   {135, "personality", 1,UINT}, \
   {136, "ustat", 2,0, 0}, \
   {137, "statfs", 2,CHARP, 0}, \
   {138, "fstatfs", 2,UINT, 0}, \
   {139, "sysfs", 3,INT, ULONG, ULONG}, \
   {140, "getpriority", 2,INT, INT}, \
   {141, "setpriority", 3,INT, INT, INT}, \
   {142, "sched_setparam", 2,INT, 0}, \
   {143, "sched_getparam", 2,INT, 0}, \
   {144, "sched_setscheduler", 3,INT, INT, 0}, \
   {145, "sched_getscheduler", 1,INT}, \
   {146, "sched_get_priority_max", 1,INT}, \
   {147, "sched_get_priority_min", 1,INT}, \
   {148, "sched_rr_get_interval", 2,INT, 0}, \
   {149, "mlock", 2,ULONG, SIZET}, \
   {150, "munlock", 2,ULONG, SIZET}, \
   {151, "mlockall", 1,INT}, \
   {152, "munlockall", 0,}, \
   {153, "vhangup", 0,}, \
   {154, "modify_ldt", 3,INT, 0, ULONG}, \
   {155, "pivot_root", 2,CHARP, CHARP}, \
   {157, "prctl", 5,INT, ULONG, ULONG, ULONG, ULONG}, \
   {158, "arch_prctl", 2,INT, ULONG}, \
   {159, "adjtimex", 1,0}, \
   {160, "setrlimit", 2,UINT, 0}, \
   {161, "chroot", 1,CHARP}, \
   {162, "sync", 0,}, \
   {163, "acct", 1,CHARP}, \
   {164, "settimeofday", 2,0, 0}, \
   {165, "mount", 5,CHARP, CHARP, CHARP, ULONG, 0}, \
   {166, "umount", 2,CHARP, INT}, \
   {167, "swapon", 2,CHARP, INT}, \
   {168, "swapoff", 1,CHARP}, \
   {169, "reboot", 4,INT, INT, UINT, 0}, \
   {170, "sethostname", 2,CHARP, INT}, \
   {171, "setdomainname", 2,CHARP, INT}, \
   {172, "iopl", 1,UINT}, \
   {173, "ioperm", 3,ULONG, ULONG, INT}, \
   {175, "init_module", 3,0, ULONG, CHARP}, \
   {176, "delete_module", 2,CHARP, UINT}, \
   {179, "quotactl", 4,UINT, CHARP, 0, 0}, \
   {186, "gettid", 0,}, \
   {187, "readahead", 3,INT, 0, SIZET}, \
   {188, "setxattr", 5,CHARP, CHARP, 0, SIZET, INT}, \
   {189, "lsetxattr", 5,CHARP, CHARP, 0, SIZET, INT}, \
   {190, "fsetxattr", 5,INT, CHARP, 0, SIZET, INT}, \
   {191, "getxattr", 4,CHARP, CHARP, 0, SIZET}, \
   {192, "lgetxattr", 4,CHARP, CHARP, 0, SIZET}, \
   {193, "fgetxattr", 4,INT, CHARP, 0, SIZET}, \
   {194, "listxattr", 3,CHARP, CHARP, SIZET}, \
   {195, "llistxattr", 3,CHARP, CHARP, SIZET}, \
   {196, "flistxattr", 3,INT, CHARP, SIZET}, \
   {197, "removexattr", 2,CHARP, CHARP}, \
   {198, "lremovexattr", 2,CHARP, CHARP}, \
   {199, "fremovexattr", 2,INT, CHARP}, \
   {200, "tkill", 2,INT, INT}, \
   {201, "time", 1,0}, \
   {202, "futex", 6,0, INT, UINT, 0, 0, UINT}, \
   {203, "sched_setaffinity", 3,INT, UINT, 0}, \
   {204, "sched_getaffinity", 3,INT, UINT, 0}, \
   {206, "io_setup", 2,0, 0}, \
   {207, "io_destroy", 1,0}, \
   {208, "io_getevents", 5,0, LONG, LONG, 0, 0}, \
   {209, "io_submit", 3,0, LONG, 0}, \
   {210, "io_cancel", 3,0, 0, 0}, \
   {213, "epoll_create", 1,INT}, \
   {216, "remap_file_pages", 5,ULONG, ULONG, ULONG, ULONG, ULONG}, \
   {217, "getdents64", 3,UINT, 0, UINT}, \
   {218, "set_tid_address", 1,0}, \
   {219, "restart_syscall", 0,}, \
   {220, "semtimedop", 4,INT, 0, UINT, 0}, \
   {221, "fadvise64", 4,INT, 0, 0, INT}, \
   {222, "timer_create", 3,INT, 0, 0}, \
   {223, "timer_settime", 4,0, INT, 0, 0}, \
   {224, "timer_gettime", 2,0, 0}, \
   {225, "timer_getoverrun", 1,0}, \
   {226, "timer_delete", 1,0}, \
   {227, "clock_settime", 2,INT, 0}, \
   {228, "clock_gettime", 2,INT, 0}, \
   {229, "clock_getres", 2,INT, 0}, \
   {230, "clock_nanosleep", 4,INT, INT, 0, 0}, \
   {231, "exit_group", 1,INT}, \
   {232, "epoll_wait", 4,INT, 0, INT, INT}, \
   {233, "epoll_ctl", 4,INT, INT, INT, 0}, \
   {234, "tgkill", 3,INT, INT, INT}, \
   {235, "utimes", 2,CHARP, 0}, \
   {237, "mbind", 6,ULONG, ULONG, ULONG, 0, ULONG, UINT}, \
   {238, "set_mempolicy", 3,INT, 0, ULONG}, \
   {239, "get_mempolicy", 5,0, 0, ULONG, ULONG, ULONG}, \
   {240, "mq_open", 4,CHARP, INT, 0, 0}, \
   {241, "mq_unlink", 1,CHARP}, \
   {242, "mq_timedsend", 5,0, CHARP, SIZET, UINT, 0}, \
   {243, "mq_timedreceive", 5,0, CHARP, SIZET, 0, 0}, \
   {244, "mq_notify", 2,0, 0}, \
   {245, "mq_getsetattr", 3,0, 0, 0}, \
   {246, "kexec_load", 4,ULONG, ULONG, 0, ULONG}, \
   {247, "waitid", 5,INT, INT, 0, INT, 0}, \
   {248, "add_key", 5,CHARP, CHARP, 0, SIZET, 0}, \
   {249, "request_key", 4,CHARP, CHARP, CHARP, 0}, \
   {250, "keyctl", 5,INT, ULONG, ULONG, ULONG, ULONG}, \
   {251, "ioprio_set", 3,INT, INT, INT}, \
   {252, "ioprio_get", 2,INT, INT}, \
   {253, "inotify_init", 0,}, \
   {254, "inotify_add_watch", 3,INT, CHARP, UINT}, \
   {255, "inotify_rm_watch", 2,INT, 0}, \
   {256, "migrate_pages", 4,INT, ULONG, 0, 0}, \
   {257, "openat", 4,INT, CHARP, INT, 0}, \
   {258, "mkdirat", 3,INT, CHARP, 0}, \
   {259, "mknodat", 4,INT, CHARP, 0, UINT}, \
   {260, "fchownat", 5,INT, CHARP, UINT, UINT, INT}, \
   {261, "futimesat", 3,INT, CHARP, 0}, \
   {262, "newfstatat", 4,INT, CHARP, 0, INT}, \
   {263, "unlinkat", 3,INT, CHARP, INT}, \
   {264, "renameat", 4,INT, CHARP, INT, CHARP}, \
   {265, "linkat", 5,INT, CHARP, INT, CHARP, INT}, \
   {266, "symlinkat", 3,CHARP, INT, CHARP}, \
   {267, "readlinkat", 4,INT, CHARP, CHARP, INT}, \
   {268, "fchmodat", 3,INT, CHARP, 0}, \
   {269, "faccessat", 3,INT, CHARP, INT}, \
   {270, "pselect6", 6,INT, 0, 0, 0, 0, 0}, \
   {271, "ppoll", 5,0, UINT, 0, UINT, SIZET}, \
   {272, "unshare", 1,ULONG}, \
   {273, "set_robust_list", 2,0, SIZET}, \
   {274, "get_robust_list", 3,INT, 0 , SIZET }, \
   {275, "splice", 6,INT, 0, INT, 0, SIZET, UINT}, \
   {276, "tee", 4,INT, INT, SIZET, UINT}, \
   {277, "sync_file_range", 4,INT, 0, 0, UINT}, \
   {278, "vmsplice", 4,INT, 0, ULONG, UINT}, \
   {279, "move_pages", 6,INT, ULONG, 0, 0, 0, INT}, \
   {280, "utimensat", 4,INT, CHARP, 0, INT}, \
   {281, "epoll_pwait", 6,INT, 0, INT, INT, UINT, SIZET}, \
   {282, "signalfd", 3,INT, 0, SIZET}, \
   {283, "timerfd_create", 2,INT, INT}, \
   {284, "eventfd", 1,UINT}, \
   {285, "fallocate", 4,INT, INT, 0, 0}, \
   {286, "timerfd_settime", 4,INT, INT, 0, 0}, \
   {287, "timerfd_gettime", 2,INT, 0}, \
   {288, "accept4", 4,INT, 0, 0, INT}, \
   {289, "signalfd4", 4,INT, 0, SIZET, INT}, \
   {290, "eventfd2", 2,UINT, INT}, \
   {291, "epoll_create1", 1,INT}, \
   {292, "dup3", 3,UINT, UINT, INT}, \
   {293, "pipe2", 2,0, INT}, \
   {294, "inotify_init1", 1,INT}, \
   {295, "preadv", 5,ULONG, 0, ULONG, ULONG, ULONG}, \
   {296, "pwritev", 5,ULONG, 0, ULONG, ULONG, ULONG}, \
   {297, "rt_tgsigqueueinfo", 4,INT, INT, INT, 0}, \
   {298, "perf_event_open", 5,0, INT, INT, INT, ULONG}, \
   {299, "recvmmsg", 5,INT, 0, UINT, UINT, 0}, \
   {300, "fanotify_init", 2,UINT, UINT}, \
   {301, "fanotify_mark", 5,INT, UINT, ULONG, INT, CHARP}, \
   {302, "prlimit64", 4,INT, UINT, 0, 0}, \
   {303, "name_to_handle_at", 5,INT, CHARP, 0, 0, INT}, \
   {304, "open_by_handle_at", 3,INT, 0, INT}, \
   {305, "clock_adjtime", 2,INT, 0}, \
   {306, "syncfs", 1,INT}, \
   {307, "sendmmsg", 4,INT, 0, UINT, UINT}, \
   {308, "setns", 2,INT, INT}, \
   {309, "getcpu", 3,0, 0, 0}, \
   {310, "process_vm_readv", 6,INT, 0, ULONG, 0, ULONG, ULONG}, \
   {311, "process_vm_writev", 6,INT, 0, ULONG, 0, ULONG, ULONG}, \
   {312, "kcmp", 5,INT, INT, INT, ULONG, ULONG}, \
   {313, "finit_module", 3,INT, CHARP, INT}, \
   {314, "sched_setattr", 3,INT, 0, UINT}, \
   {315, "sched_getattr", 4,INT, 0, UINT, UINT}, \
   {316, "renameat2", 5,INT, CHARP, INT, CHARP, UINT}, \
   {317, "seccomp", 3,UINT, UINT, 0}, \
   {318, "getrandom", 3,CHARP, SIZET, UINT}, \
   {319, "memfd_create", 2,CHARP, UINT}, \
   {320, "kexec_file_load", 5,INT, INT, ULONG, CHARP, ULONG}, \
   {321, "bpf", 3,INT, 0, UINT}, \
   {322, "execveat", 5,INT, CHARP, 0, 0, INT}, \
   {323, "userfaultfd", 1,INT}, \
   {324, "membarrier", 3,INT, UINT, INT}, \
   {325, "mlock2", 3,ULONG, SIZET, INT}, \
   {326, "copy_file_range", 6,INT, 0, INT, 0, SIZET, UINT}, \
   {327, "preadv2", 6,ULONG, 0, ULONG, ULONG, ULONG, 0}, \
   {328, "pwritev2", 6,ULONG, 0, ULONG, ULONG, ULONG, 0}, \
   {329, "pkey_mprotect", 4,ULONG, SIZET, ULONG, INT}, \
   {330, "pkey_alloc", 2,ULONG, ULONG}, \
   {331, "pkey_free", 1,INT}, \
   {332, "statx", 5,INT, CHARP, 0, UINT, 0}, \
   {333, "io_pgetevents", 6,0, LONG, LONG, 0, 0, 0}, \
   {334, "rseq", 4,0, UINT, INT, UINT}, \
   {424, "pidfd_send_signal", 4,INT, INT, 0, UINT}, \
   {425, "io_uring_setup", 2,UINT, 0}, \
   {426, "io_uring_enter", 6,UINT, UINT, UINT, UINT, 0, SIZET}, \
   {427, "io_uring_register", 4,UINT, UINT, 0, UINT}, \
   {428, "open_tree", 3,INT, CHARP, 0}, \
   {429, "move_mount", 5,INT, CHARP, INT, CHARP, UINT}, \
   {430, "fsopen", 2,CHARP, UINT}, \
   {431, "fsconfig", 5,INT, UINT, CHARP, 0, INT}, \
   {432, "fsmount", 3,INT, UINT, UINT}, \
   {433, "fspick", 3,INT, CHARP, UINT}, \
   {434, "pidfd_open", 2,INT, UINT}, \
   {435, "clone3", 2,0, SIZET}, \
   {436, "close_range", 3,UINT, UINT, UINT}, \
   {437, "openat2", 4,INT, CHARP, 0, SIZET}, \
   {438, "pidfd_getfd", 3,INT, INT, UINT}, \
   {439, "faccessat2", 4,INT, CHARP, INT, INT}, \
   {440, "process_madvise", 5,INT, 0, SIZET, INT, UINT}, \
   {441, "epoll_pwait2", 6,INT, 0, INT, 0, UINT, SIZET}, \
   {442, "mount_setattr", 5,INT, CHARP, UINT, 0, SIZET}, \
   {443, "quotactl_fd", 4,UINT, UINT, 0, 0}, \
   {444, "landlock_create_ruleset", 3,0, SIZET,  UINT}, \
   {445, "landlock_add_rule", 4,INT, 0,  0, UINT}, \
   {446, "landlock_restrict_self", 2,INT, UINT}, \
   {447, "memfd_secret", 1,UINT}, \
   {448, "process_mrelease", 2,INT, UINT}, \
   {449, "futex_waitv", 5,0, UINT, UINT, 0, UINT}, \
   {450, "set_mempolicy_home_node", 4,ULONG, ULONG, ULONG, ULONG}, \
   {451, "cachestat", 4,UINT, 0, 0, UINT}, \
   {452, "fchmodat2", 4,INT, CHARP, 0, UINT}, \
   {453, "map_shadow_stack", 3,ULONG, ULONG, UINT}, \
   {454, "futex_wake", 4,0, ULONG, INT, UINT}, \
   {455, "futex_wait", 6,0, ULONG, ULONG, UINT, 0, UINT}, \
   {456, "futex_requeue", 4,0, UINT, INT, INT}, \
   {457, "statmount", 4,0, 0, SIZET, UINT}, \
   {458, "listmount", 4,0, ULONG, SIZET, UINT}, \
   {459, "lsm_get_self_attr", 4,UINT, 0, SIZET, UINT}, \
   {460, "lsm_set_self_attr", 4,UINT, 0, SIZET, UINT}, \
   {461, "lsm_list_modules", 3,ULONG, SIZET, UINT}, \
};

#define X32_SYSCALLS_LIST { \
   {0, "restart_syscall", 0, }, \
   {1, "exit", 1, INT}, \
   {2, "fork", 0, }, \
   {3, "read", 3, INT, CHARP, SIZET}, \
   {4, "write", 3, INT, CHARP, SIZET}, \
   {5, "open", 3, CHARP, INT, 0}, \
   {6, "close", 1, INT}, \
   {7, "waitpid", 3, INT, 0, INT}, \
   {8, "creat", 2, CHARP, 0}, \
   {9, "link", 2, CHARP, CHARP}, \
   {10, "unlink", 1, CHARP}, \
   {11, "execve", 3, CHARP, 0, 0}, \
   {12, "chdir", 1, CHARP}, \
   {13, "time", 1, 0}, \
   {14, "mknod", 3, CHARP, 0, 0}, \
   {15, "chmod", 2, CHARP, 0}, \
   {16, "lchown16", 3, CHARP, INT, INT}, \
   {18, "stat", 2, CHARP, 0}, \
   {19, "lseek", 3, INT, 0, INT}, \
   {20, "getpid", 0, }, \
   {21, "mount", 5, CHARP, CHARP, CHARP, ULONG, 0}, \
   {22, "oldumount", 1, CHARP}, \
   {23, "setuid16", 1, INT}, \
   {24, "getuid16", 0, }, \
   {25, "stime", 1, 0}, \
   {26, "ptrace", 4, LONG, LONG, ULONG, ULONG}, \
   {27, "alarm", 1, INT}, \
   {28, "fstat", 2, INT, 0}, \
   {29, "pause", 0, }, \
   {30, "utime", 2, CHARP, 0}, \
   {33, "access", 2, CHARP, INT}, \
   {34, "nice", 1, INT}, \
   {36, "sync", 0, }, \
   {37, "kill", 2, INT, INT}, \
   {38, "rename", 2, CHARP, CHARP}, \
   {39, "mkdir", 2, CHARP, 0}, \
   {40, "rmdir", 1, CHARP}, \
   {41, "dup", 1, INT}, \
   {42, "pipe", 1, 0}, \
   {43, "times", 1, 0}, \
   {45, "brk", 1, 0}, \
   {46, "setgid16", 1, INT}, \
   {47, "getgid16", 0, }, \
   {48, "signal", 2, INT, 0}, \
   {49, "geteuid16", 0, }, \
   {50, "getegid16", 0, }, \
   {51, "acct", 1, CHARP}, \
   {52, "umount", 2, CHARP, INT}, \
   {54, "ioctl", 3, INT, INT, ULONG}, \
   {55, "fcntl", 3, INT, INT, ULONG}, \
   {57, "setpgid", 2, INT, INT}, \
   {59, "olduname", 1, 0}, \
   {60, "umask", 1, INT}, \
   {61, "chroot", 1, CHARP}, \
   {62, "ustat", 2, 0, 0}, \
   {63, "dup2", 2, INT, INT}, \
   {64, "getppid", 0, }, \
   {65, "getpgrp", 0, }, \
   {66, "setsid", 0, }, \
   {67, "sigaction", 3, INT, 0, 0}, \
   {68, "sgetmask", 0, }, \
   {69, "ssetmask", 1, INT}, \
   {70, "setreuid16", 2, INT, INT}, \
   {71, "setregid16", 2, INT, INT}, \
   {72, "sigsuspend", 3, INT, INT, 0}, \
   {73, "sigpending", 1, 0}, \
   {74, "sethostname", 2, CHARP, INT}, \
   {75, "setrlimit", 2, INT, 0}, \
   {76, "getrlimit", 2, INT, 0}, \
   {77, "getrusage", 2, INT, 0}, \
   {78, "gettimeofday", 2, 0, 0}, \
   {79, "settimeofday", 2, 0, 0}, \
   {80, "getgroups16", 2, INT, 0}, \
   {81, "setgroups16", 2, INT, 0}, \
   {82, "select", 1, 0}, \
   {83, "symlink", 2, CHARP, CHARP}, \
   {84, "lstat", 2, CHARP, 0}, \
   {85, "readlink", 3, CHARP, CHARP, INT}, \
   {86, "uselib", 1, CHARP}, \
   {87, "swapon", 2, CHARP, INT}, \
   {88, "reboot", 4, INT, INT, INT, 0}, \
   {89, "readdir", 3, INT, 0, INT}, \
   {90, "mmap", 1, 0}, \
   {91, "munmap", 2, ULONG, SIZET}, \
   {92, "truncate", 2, CHARP, LONG}, \
   {93, "ftruncate", 2, INT, ULONG}, \
   {94, "fchmod", 2, INT, 0}, \
   {95, "fchown16", 3, INT, INT, INT}, \
   {96, "getpriority", 2, INT, INT}, \
   {97, "setpriority", 3, INT, INT, INT}, \
   {99, "statfs", 2, CHARP, 0}, \
   {100, "fstatfs", 2, INT, 0}, \
   {101, "ioperm", 3, ULONG, ULONG, INT}, \
   {102, "socketcall", 2, INT, 0}, \
   {103, "syslog", 3, INT, CHARP, INT}, \
   {104, "setitimer", 3, INT, 0, 0}, \
   {105, "getitimer", 2, INT, 0}, \
   {106, "newstat", 2, CHARP, 0}, \
   {107, "newlstat", 2, CHARP, 0}, \
   {108, "newfstat", 2, INT, 0}, \
   {109, "uname", 1, 0}, \
   {110, "iopl", 1, INT}, \
   {111, "vhangup", 0, }, \
   {113, "vm86old", 1, 0}, \
   {114, "wait4", 4, INT, 0, INT, 0}, \
   {115, "swapoff", 1, CHARP}, \
   {116, "sysinfo", 1, 0}, \
   {117, "ipc", 6, INT, INT, ULONG, ULONG, 0, LONG}, \
   {118, "fsync", 1, INT}, \
   {119, "sigreturn", 0, }, \
   {120, "clone", 5, ULONG, ULONG, 0, ULONG, 0}, \
   {121, "setdomainname", 2, CHARP, INT}, \
   {122, "newuname", 1, 0}, \
   {123, "modify_ldt", 3, INT, 0, ULONG}, \
   {124, "adjtimex", 1, 0}, \
   {125, "mprotect", 3, ULONG, SIZET, ULONG}, \
   {126, "sigprocmask", 3, INT, 0, 0}, \
   {128, "init_module", 3, 0, ULONG, CHARP}, \
   {129, "delete_module", 2, CHARP, INT}, \
   {131, "quotactl", 4, INT, CHARP, 0, 0}, \
   {132, "getpgid", 1, INT}, \
   {133, "fchdir", 1, INT}, \
   {135, "sysfs", 3, INT, ULONG, ULONG}, \
   {136, "personality", 1, INT}, \
   {138, "setfsuid16", 1, INT}, \
   {139, "setfsgid16", 1, INT}, \
   {140, "llseek", 5, INT, ULONG, ULONG, 0, INT}, \
   {141, "getdents", 3, INT, 0, INT}, \
   {142, "select", 5, INT, 0, 0, 0, 0}, \
   {143, "flock", 2, INT, INT}, \
   {144, "msync", 3, ULONG, SIZET, INT}, \
   {145, "readv", 3, ULONG, 0, ULONG}, \
   {146, "writev", 3, ULONG, 0, ULONG}, \
   {147, "getsid", 1, INT}, \
   {148, "fdatasync", 1, INT}, \
   {150, "mlock", 2, ULONG, SIZET}, \
   {151, "munlock", 2, ULONG, SIZET}, \
   {152, "mlockall", 1, INT}, \
   {153, "munlockall", 0, }, \
   {154, "sched_setparam", 2, INT, 0}, \
   {155, "sched_getparam", 2, INT, 0}, \
   {156, "sched_setscheduler", 3, INT, INT, 0}, \
   {157, "sched_getscheduler", 1, INT}, \
   {158, "sched_yield", 0, }, \
   {159, "sched_get_priority_max", 1, INT}, \
   {160, "sched_get_priority_min", 1, INT}, \
   {161, "sched_rr_get_interval", 2, INT, 0}, \
   {162, "nanosleep", 2, 0, 0}, \
   {163, "mremap", 5, ULONG, ULONG, ULONG, ULONG, ULONG}, \
   {164, "setresuid16", 3, INT, INT, INT}, \
   {165, "getresuid16", 3, 0, 0, 0}, \
   {166, "vm86", 2, ULONG, ULONG}, \
   {168, "poll", 3, 0, INT, INT}, \
   {170, "setresgid16", 3, INT, INT, INT}, \
   {171, "getresgid16", 3, 0, 0, 0}, \
   {172, "prctl", 5, INT, ULONG, ULONG, ULONG, ULONG}, \
   {173, "rt_sigreturn", 0, }, \
   {174, "rt_sigaction", 4, INT, 0, 0, SIZET}, \
   {175, "rt_sigprocmask", 4, INT, 0, 0, SIZET}, \
   {176, "rt_sigpending", 2, 0, SIZET}, \
   {177, "rt_sigtimedwait", 4, 0, 0, 0, SIZET}, \
   {178, "rt_sigqueueinfo", 3, INT, INT, 0}, \
   {179, "rt_sigsuspend", 2, 0, SIZET}, \
   {180, "pread64", 5, INT, CHARP, UINT, UINT, UINT}, \
   {181, "pwrite64", 5, INT, CHARP, UINT, UINT, UINT}, \
   {182, "chown16", 3, CHARP, INT, INT}, \
   {183, "getcwd", 2, CHARP, ULONG}, \
   {184, "capget", 2, 0, 0}, \
   {185, "capset", 2, 0, 0}, \
   {186, "sigaltstack", 2, 0, 0}, \
   {187, "sendfile", 4, INT, INT, 0, SIZET}, \
   {190, "vfork", 0, }, \
   {191, "getrlimit", 2, INT, 0}, \
   {192, "mmap_pgoff", 6, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG}, \
   {193, "truncate64", 3, CHARP, ULONG, ULONG}, \
   {194, "ftruncate64", 3, INT, ULONG, ULONG}, \
   {195, "stat64", 2, CHARP, 0}, \
   {196, "lstat64", 2, CHARP, 0}, \
   {197, "fstat64", 2, ULONG, 0}, \
   {198, "lchown", 3, CHARP, UINT, UINT}, \
   {199, "getuid", 0, }, \
   {200, "getgid", 0, }, \
   {201, "geteuid", 0, }, \
   {202, "getegid", 0, }, \
   {203, "setreuid", 2, UINT, UINT}, \
   {204, "setregid", 2, UINT, UINT}, \
   {205, "getgroups", 2, INT, 0}, \
   {206, "setgroups", 2, INT, 0}, \
   {207, "fchown", 3, INT, UINT, UINT}, \
   {208, "setresuid", 3, UINT, UINT, UINT}, \
   {209, "getresuid", 3, 0, 0, 0}, \
   {210, "setresgid", 3, UINT, UINT, UINT}, \
   {211, "getresgid", 3, 0, 0, 0}, \
   {212, "chown", 3, CHARP, UINT, UINT}, \
   {213, "setuid", 1, UINT}, \
   {214, "setgid", 1, UINT}, \
   {215, "setfsuid", 1, UINT}, \
   {216, "setfsgid", 1, UINT}, \
   {217, "pivot_root", 2, CHARP, CHARP}, \
   {218, "mincore", 3, ULONG, SIZET, CHARP}, \
   {219, "madvise", 3, ULONG, SIZET, INT}, \
   {220, "getdents64", 3, INT, 0, INT}, \
   {221, "fcntl64", 3, INT, INT, ULONG}, \
   {224, "gettid", 0, }, \
   {225, "readahead", 4, INT, INT, INT, SIZET}, \
   {226, "setxattr", 5, CHARP, CHARP, 0, SIZET, INT}, \
   {227, "lsetxattr", 5, CHARP, CHARP, 0, SIZET, INT}, \
   {228, "fsetxattr", 5, INT, CHARP, 0, SIZET, INT}, \
   {229, "getxattr", 4, CHARP, CHARP, 0, SIZET}, \
   {230, "lgetxattr", 4, CHARP, CHARP, 0, SIZET}, \
   {231, "fgetxattr", 4, INT, CHARP, 0, SIZET}, \
   {232, "listxattr", 3, CHARP, CHARP, SIZET}, \
   {233, "llistxattr", 3, CHARP, CHARP, SIZET}, \
   {234, "flistxattr", 3, INT, CHARP, SIZET}, \
   {235, "removexattr", 2, CHARP, CHARP}, \
   {236, "lremovexattr", 2, CHARP, CHARP}, \
   {237, "fremovexattr", 2, INT, CHARP}, \
   {238, "tkill", 2, INT, INT}, \
   {239, "sendfile64", 4, INT, INT, 0, SIZET}, \
   {240, "futex", 6, 0, INT, UINT, 0, 0, UINT}, \
   {241, "sched_setaffinity", 3, INT, INT, 0}, \
   {242, "sched_getaffinity", 3, INT, INT, 0}, \
   {243, "set_thread_area", 1, 0}, \
   {244, "get_thread_area", 1, 0}, \
   {245, "io_setup", 2, 0, 0}, \
   {246, "io_destroy", 1, 0}, \
   {247, "io_getevents", 5, UINT, INT, INT, 0, 0}, \
   {248, "io_submit", 3, 0, LONG, 0}, \
   {249, "io_cancel", 3, 0, 0, 0}, \
   {250, "fadvise64", 5, INT, INT, INT, SIZET, INT}, \
   {252, "exit_group", 1, INT}, \
   {254, "epoll_create", 1, INT}, \
   {255, "epoll_ctl", 4, INT, INT, INT, 0}, \
   {256, "epoll_wait", 4, INT, 0, INT, INT}, \
   {257, "remap_file_pages", 5, ULONG, ULONG, ULONG, ULONG, ULONG}, \
   {258, "set_tid_address", 1, 0}, \
   {259, "timer_create", 3, 0, 0, 0}, \
   {260, "timer_settime", 4, 0, INT, 0, 0}, \
   {261, "timer_gettime", 2, 0, 0}, \
   {262, "timer_getoverrun", 1, 0}, \
   {263, "timer_delete", 1, 0}, \
   {264, "clock_settime", 2, 0, 0}, \
   {265, "clock_gettime", 2, 0, 0}, \
   {266, "clock_getres", 2, 0, 0}, \
   {267, "clock_nanosleep", 4, 0, INT, 0, 0}, \
   {268, "statfs64", 3, CHARP, SIZET, 0}, \
   {269, "fstatfs64", 3, INT, SIZET, 0}, \
   {270, "tgkill", 3, INT, INT, INT}, \
   {271, "utimes", 2, CHARP, 0}, \
   {272, "fadvise64_64", 6, INT, UINT, UINT, UINT, UINT, INT}, \
   {274, "mbind", 6, ULONG, ULONG, ULONG, 0, ULONG, INT}, \
   {275, "get_mempolicy", 5, 0, 0, ULONG, ULONG, ULONG}, \
   {276, "set_mempolicy", 3, INT, 0, ULONG}, \
   {277, "mq_open", 4, CHARP, INT, 0, 0}, \
   {278, "mq_unlink", 1, CHARP}, \
   {279, "mq_timedsend", 5, 0, CHARP, INT, INT, 0}, \
   {280, "mq_timedreceive", 5, 0, CHARP, INT, 0, 0}, \
   {281, "mq_notify", 2, 0, 0}, \
   {282, "mq_getsetattr", 3, 0, 0, 0}, \
   {283, "kexec_load", 4, ULONG, ULONG, 0, ULONG}, \
   {284, "waitid", 5, INT, INT, 0, INT, 0}, \
   {286, "add_key", 5, CHARP, CHARP, 0, SIZET, 0}, \
   {287, "request_key", 4, CHARP, CHARP, CHARP, 0}, \
   {288, "keyctl", 5, INT, ULONG, ULONG, ULONG, ULONG}, \
   {289, "ioprio_set", 3, INT, INT, INT}, \
   {290, "ioprio_get", 2, INT, INT}, \
   {291, "inotify_init", 0, }, \
   {292, "inotify_add_watch", 3, INT, CHARP, UINT}, \
   {293, "inotify_rm_watch", 2, INT, INT}, \
   {294, "migrate_pages", 4, INT, ULONG, 0, 0}, \
   {295, "openat", 4, INT, CHARP, INT, 0}, \
   {296, "mkdirat", 3, INT, CHARP, 0}, \
   {297, "mknodat", 4, INT, CHARP, 0, INT}, \
   {298, "fchownat", 5, INT, CHARP, UINT, UINT, INT}, \
   {299, "futimesat", 3, INT, CHARP, 0}, \
   {300, "fstatat64", 4, INT, CHARP, 0, INT}, \
   {301, "unlinkat", 3, INT, CHARP, INT}, \
   {302, "renameat", 4, INT, CHARP, INT, CHARP}, \
   {303, "linkat", 5, INT, CHARP, INT, CHARP, INT}, \
   {304, "symlinkat", 3, CHARP, INT, CHARP}, \
   {305, "readlinkat", 4, INT, CHARP, CHARP, INT}, \
   {306, "fchmodat", 3, INT, CHARP, 0}, \
   {307, "faccessat", 3, INT, CHARP, INT}, \
   {308, "pselect6", 6, INT, 0, 0, 0, 0, 0}, \
   {309, "ppoll", 5, 0, INT, 0, 0, SIZET}, \
   {310, "unshare", 1, ULONG}, \
   {311, "set_robust_list", 2, 0, SIZET}, \
   {312, "get_robust_list", 3, INT, 0 , SIZET }, \
   {313, "splice", 6, INT, 0, INT, 0, SIZET, INT}, \
   {314, "sync_file_range", 6, INT, INT, INT, INT, INT, INT}, \
   {315, "tee", 4, INT, INT, SIZET, INT}, \
   {316, "vmsplice", 4, INT, 0, ULONG, INT}, \
   {317, "move_pages", 6, INT, ULONG, 0, 0, 0, INT}, \
   {318, "getcpu", 3, 0, 0, 0}, \
   {319, "epoll_pwait", 6, INT, 0, INT, INT, 0, SIZET}, \
   {320, "utimensat", 4, INT, CHARP, 0, INT}, \
   {321, "signalfd", 3, INT, 0, SIZET}, \
   {322, "timerfd_create", 2, INT, INT}, \
   {323, "eventfd", 1, INT}, \
   {324, "fallocate", 6, INT, INT, INT, INT, INT, INT}, \
   {325, "timerfd_settime", 4, INT, INT, 0, 0}, \
   {326, "timerfd_gettime", 2, INT, 0}, \
   {327, "signalfd4", 4, INT, 0, SIZET, INT}, \
   {328, "eventfd2", 2, INT, INT}, \
   {329, "epoll_create1", 1, INT}, \
   {330, "dup3", 3, INT, INT, INT}, \
   {331, "pipe2", 2, 0, INT}, \
   {332, "inotify_init1", 1, INT}, \
   {333, "preadv", 5, ULONG, 0, ULONG, ULONG, ULONG}, \
   {334, "pwritev", 5, ULONG, 0, ULONG, ULONG, ULONG}, \
   {335, "rt_tgsigqueueinfo", 4, INT, INT, INT, 0}, \
   {336, "perf_event_open", 5, 0, INT, INT, INT, ULONG}, \
   {337, "recvmmsg", 5, INT, 0, INT, INT, 0}, \
   {338, "fanotify_init", 2, INT, INT}, \
   {339, "fanotify_mark", 6, INT, INT, UINT, UINT, INT, CHARP}, \
   {340, "prlimit64", 4, INT, INT, 0, 0}, \
   {341, "name_to_handle_at", 5, INT, CHARP, 0, 0, INT}, \
   {342, "open_by_handle_at", 3, INT, 0, INT}, \
   {343, "clock_adjtime", 2, 0, 0}, \
   {344, "syncfs", 1, INT}, \
   {345, "sendmmsg", 4, INT, 0, INT, INT}, \
   {346, "setns", 2, INT, INT}, \
   {347, "process_vm_readv", 6, INT, 0, ULONG, 0, ULONG, ULONG}, \
   {348, "process_vm_writev", 6, INT, 0, ULONG, 0, ULONG, ULONG}, \
   {349, "kcmp", 5, INT, INT, INT, ULONG, ULONG}, \
   {350, "finit_module", 3, INT, CHARP, INT}, \
   {351, "sched_setattr", 3, INT, 0, INT}, \
   {352, "sched_getattr", 4, INT, 0, INT, INT}, \
   {353, "renameat2", 5, INT, CHARP, INT, CHARP, INT}, \
   {354, "seccomp", 3, INT, INT, 0}, \
   {355, "getrandom", 3, CHARP, SIZET, INT}, \
   {356, "memfd_create", 2, CHARP, INT}, \
   {357, "bpf", 3, INT, 0, INT}, \
   {358, "execveat", 5, INT, CHARP, 0, 0, INT}, \
   {359, "socket", 3, INT, INT, INT}, \
   {360, "socketpair", 4, INT, INT, INT, 0}, \
   {361, "bind", 3, INT, 0, INT}, \
   {362, "connect", 3, INT, 0, INT}, \
   {363, "listen", 2, INT, INT}, \
   {364, "accept4", 4, INT, 0, 0, INT}, \
   {365, "getsockopt", 5, INT, INT, INT, CHARP, 0}, \
   {366, "setsockopt", 5, INT, INT, INT, CHARP, INT}, \
   {367, "getsockname", 3, INT, 0, 0}, \
   {368, "getpeername", 3, INT, 0, 0}, \
   {369, "sendto", 6, INT, 0, SIZET, INT, 0, INT}, \
   {370, "sendmsg", 3, INT, 0, INT}, \
   {371, "recvfrom", 6, INT, 0, SIZET, INT, 0, 0}, \
   {372, "recvmsg", 3, INT, 0, INT}, \
   {373, "shutdown", 2, INT, INT}, \
   {374, "userfaultfd", 1, INT}, \
   {375, "membarrier", 3, INT, INT, INT}, \
   {376, "mlock2", 3, ULONG, SIZET, INT}, \
   {377, "copy_file_range", 6, INT, 0, INT, 0, SIZET, INT}, \
   {378, "preadv2", 6, ULONG, 0, ULONG, ULONG, ULONG, 0}, \
   {379, "pwritev2", 6, ULONG, 0, ULONG, ULONG, ULONG, 0}, \
   {383, "statx", 5, INT, CHARP, 0, INT, 0}, \
   {384, "arch_prctl", 2, INT, ULONG}, \
   {385, "io_pgetevents", 6, 0, LONG, LONG, 0, 0, 0}, \
   {386, "rseq", 4, 0, UINT, INT, UINT}, \
   {393, "semget", 3, 0, INT, INT}, \
   {394, "semctl", 4, INT, INT, INT, ULONG}, \
   {395, "shmget", 3, 0, SIZET, INT}, \
   {396, "shmctl", 3, INT, INT, 0}, \
   {397, "shmat", 3, INT, CHARP, INT}, \
   {398, "shmdt", 1, CHARP}, \
   {399, "msgget", 2, 0, INT}, \
   {400, "msgsnd", 4, INT, 0, SIZET, INT}, \
   {401, "msgrcv", 5, INT, 0, SIZET, LONG, INT}, \
   {402, "msgctl", 3, INT, INT, 0}, \
   {403, "clock_gettime", 2, 0, 0}, \
   {404, "clock_settime", 2, 0, 0}, \
   {405, "clock_adjtime", 2, 0, 0}, \
   {406, "clock_getres", 2, 0, 0}, \
   {407, "clock_nanosleep", 4, 0, INT, 0, 0}, \
   {408, "timer_gettime", 2, 0, 0}, \
   {409, "timer_settime", 4, 0, INT, 0, 0}, \
   {410, "timerfd_gettime", 2, INT, 0}, \
   {411, "timerfd_settime", 4, INT, INT, 0, 0}, \
   {412, "utimensat", 4, INT, CHARP, 0, INT}, \
   {413, "pselect6", 6, INT, 0, 0, 0, 0, 0}, \
   {414, "ppoll", 5, 0, INT, 0, 0, SIZET}, \
   {416, "io_pgetevents", 6, 0, LONG, LONG, 0, 0, 0}, \
   {417, "recvmmsg", 5, INT, 0, INT, INT, 0}, \
   {418, "mq_timedsend", 5, 0, CHARP, SIZET, INT, 0}, \
   {419, "mq_timedreceive", 5, 0, CHARP, SIZET, 0, 0}, \
   {420, "semtimedop", 4, INT, 0, INT, 0}, \
   {421, "rt_sigtimedwait", 4, 0, 0,0, SIZET}, \
   {422, "futex", 6, 0, INT, UINT,0, 0, UINT}, \
   {423, "sched_rr_get_interval", 2, INT, 0}, \
   {424, "pidfd_send_signal", 4, INT, INT, 0, INT}, \
   {425, "io_uring_setup", 2, UINT, 0}, \
   {426, "io_uring_enter", 6, INT, UINT, UINT, UINT, 0, SIZET}, \
   {427, "io_uring_register", 4, INT, INT, 0, INT}, \
   {428, "open_tree", 3, INT, CHARP, 0}, \
   {429, "move_mount", 5, INT, CHARP, INT, CHARP, INT}, \
   {430, "fsopen", 2, CHARP, INT}, \
   {431, "fsconfig", 5, INT, INT, CHARP, 0, INT}, \
   {432, "fsmount", 3, INT, INT, INT}, \
   {433, "fspick", 3, INT, CHARP, INT}, \
   {434, "pidfd_open", 2, INT, INT}, \
   {435, "clone3", 2, 0, SIZET}, \
   {436, "close_range", 3, INT, INT, INT}, \
   {437, "openat2", 4, INT, CHARP, 0, SIZET}, \
   {438, "pidfd_getfd", 3, INT, INT, INT}, \
   {439, "faccessat2", 4, INT, CHARP, INT, INT}, \
   {440, "process_madvise", 5, INT, 0, SIZET, INT, INT}, \
   {441, "epoll_pwait2", 6, INT, 0, INT,0, 0, SIZET}, \
   {442, "mount_setattr", 5, INT, CHARP, INT, 0, SIZET}, \
   {443, "quotactl_fd", 4, INT, INT, 0, 0}, \
   {444, "landlock_create_ruleset", 3, 0, SIZET, UINT}, \
   {445, "landlock_add_rule", 4, INT,  0,  0,  UINT}, \
   {446, "landlock_restrict_self", 2,  INT,  UINT}, \
   {447, "memfd_secret", 1, INT}, \
   {448, "process_mrelease", 2, INT, INT}, \
   {449, "futex_waitv", 5, 0, INT, INT, 0, 0}, \
   {450, "set_mempolicy_home_node", 4, ULONG, ULONG, ULONG, ULONG}, \
   {451, "cachestat", 4, INT, 0, 0, INT}, \
   {452, "fchmodat2", 4, INT, CHARP, 0, INT}, \
   {454, "futex_wake", 4, 0, ULONG, INT, INT}, \
   {455, "futex_wait", 6, 0, ULONG, ULONG, INT, 0, 0}, \
   {456, "futex_requeue", 4, 0, INT, INT, INT}, \
   {457, "statmount", 4,  0, 0, SIZET, INT}, \
   {458, "listmount", 4,  0, ULONG, SIZET, INT}, \
   {459, "lsm_get_self_attr", 4, INT, 0, SIZET , UINT}, \
   {460, "lsm_set_self_attr", 4, INT, 0, SIZET, UINT}, \
   {461, "lsm_list_modules", 3, ULONG, SIZET , UINT}, \
};

#endif
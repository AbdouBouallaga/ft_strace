#include "../inc/ft_strace.h"


int ft_strace(char **argv)
{
    int pid;
    int status = 999;
    siginfo_t siginfo;
    struct iovec ioVec;
    struct user_regs_struct regs;
    // cuser_regs_struct regs;
    struct utsname buf;
    if (uname(&buf) == -1) {
        perror("uname");
        return 1;
    }
    printf("Machine architecture: %s\n", buf.machine);
    // long regs[sizeof(struct user_regs_struct) / sizeof(long)];
    // ioVec.iov_base = &regs;
    // ioVec.iov_len = sizeof(regs);

    pid = fork();
    if (pid == -1)
        return (-1);
    if (pid == 0)
    {
        // sleep(1);
        raise(SIGSTOP);
        execvp(argv[0], argv);
    }
    else{
        printf("pid: %d\n", pid);
        if(ptrace(PTRACE_SEIZE, pid, NULL, NULL) == -1){
            printf("error: %s\nfunction %s line %d\n",strerror(errno), __FUNCTION__, __LINE__-1);
            return(0);
        }
        while(1){
            waitpid(pid, &status, 0);
            // ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);
            // bzero(&status, sizeof(status));
            // if (ptrace(PTRACE_INTERRUPT, pid, 0, 0) == -1)
            //     printf("error: %s\nfunction %s line %d\n",strerror(errno), __FUNCTION__, __LINE__-1);
            // if (ptrace(PTRACE_GETSIGINFO, pid, 0, &siginfo) == -1){
            //     printf("error: %s\nfunction %s line %d\n",strerror(errno), __FUNCTION__, __LINE__-1);
            //     // sleep(120);
            // }
            printf("status: %d\n", status);
            if (WIFSIGNALED(status)){
                printf("killed by signal %s\n", strsignal(WTERMSIG(status)));
                return (1);
            } else if (WIFEXITED(status)){
                printf("exited, status=%s\n", strsignal(WEXITSTATUS(status)));
                return (1);
            } else if (WIFSTOPPED(status)){
                printf("stopped by signal %s\n", strsignal(WSTOPSIG(status)));
            }
            if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &regs) == -1){
                printf("error: %s\nfunction %s line %d\n",strerror(errno), __FUNCTION__, __LINE__-1);
                perror("ptrace");
                // return (1);
                // sleep(120);
            }
            // printf("RIP: 0x%llx\n", ioVec);
            // printf("EAX: %llx\n", regs.rax);
            // printf("EBX: %llx\n", regs.rbx);
            // printf("ECX: %llx\n", regs.rcx);
            ptrace(PTRACE_SYSCALL, pid, 0, 0);
        }
        return (1);
    }
    
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return (printf("Usage: ./ft_strace <command> [args]\n"));
    if (ft_strace(argv + 1) == -1)
        return (printf("ft_strace: error: failed to trace\n"));
    return (0);
}
#include "../inc/ft_strace.h"

int total = 0;
int debug_count = 10;
const syscall_t			syscallsTab[] = X64_SYSCALLS_LIST;
int num_syscalls = 461;
char *get_syscall_name(int syscall_number, struct user_regs_struct regs) {
    int offset = 0;
    for (int i = 0; i < num_syscalls; i++) {
        if (syscallsTab[i].number == syscall_number) {
            printf("%s(", syscallsTab[i].name);
            for (int j = 0; j < syscallsTab[i].args_count; j++){
                printf("%lld", *(&regs.rdi-offset));
                offset++;
                if (j+1 < syscallsTab[i].args_count)
                    printf(",");
            }
            return syscallsTab[i].name;
        }
    }
    return NULL;
}

int ft_strace(char **argv)
{
    int pid;
    int status = 999;
    int waitret = 1;
    // siginfo_t siginfo;
    struct iovec iov;
    struct user_regs_struct regs;
    // cuser_regs_struct regs;

    struct utsname buf;
    if (uname(&buf) == -1) {
        perror("uname");
        return 1;
    }
    printf("Machine architecture: %s\n", buf.machine);
    
    // long regs[sizeof(struct user_regs_struct) / sizeof(long)];
    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);

    pid = fork();
    if (pid == -1)
        return (-1);
    if (pid == 0)
    {
        // sleep(1);
        raise(SIGCHLD);
        execvp(argv[0], argv);
        return(0);
    }
    else{
        printf("pid: %d\n", pid);
        if(ptrace(PTRACE_SEIZE, pid, NULL, NULL) == -1){
            printf("error: %s\nfunction %s line %d\n",strerror(errno), __FUNCTION__, __LINE__-1);
            return(0);
        }
        ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD); // ha zayda ?
        while(1){
            waitForRet:
            waitpid(-1, &status, 0);

            if (WIFSIGNALED(status)){
                printf("killed by signal %s\n", strsignal(WTERMSIG(status)));
                return (1);
            } else if (WIFEXITED(status)){
                // printf("exited, status=%s\n", strsignal(WEXITSTATUS(status)));
                printf("total halts %d\n", total/2);
                return (1);
            } else if (WIFSTOPPED(status)){
                total++;
                // printf("stopped by signal %s\n", strsignal(WSTOPSIG(status)));
            }
            bzero(&regs, sizeof(struct user_regs_struct));
            if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1){
                printf("error: %s\nfunction %s line %d\n",strerror(errno), __FUNCTION__, __LINE__-1);
                perror("ptrace");
            }
            if (waitret){
                waitret = 0;
                // printf("waitret RAX: %d\n", regs.rax);
                ptrace(PTRACE_SYSCALL, pid, 0, 0);
                goto waitForRet;
            }
            // printf("RIP: 0x%llx\n", iov);
            // printf("RIP: %llx\n", regs.rip);
            // printf("len of iov = %zu\n", iov.iov_len);
            // printf("%lX\n", regs.rip );
            
        
            get_syscall_name(regs.orig_rax, regs);
            printf(") =  %d\n", regs.rax);


            // printf("RDI: %llx\n", regs.rdi);
            // printf("EBX: %llx\n", regs.rbx);
            // printf("ECX: %llx\n", regs.rcx);
            // printf("RBX: %016llx (%llx)\n", regs.rbx, regs.rbx);

            // bzero(&regs, sizeof(struct user_regs_struct));
            status = 999;
            ptrace(PTRACE_SYSCALL, pid, 0, 0);
            // sleep(0.1);
            // printf("\n");
            waitret = 0;
        }
        return (1);
    }
    
}

int main(int argc, char **argv)
{
    // must add signals handler, and kill the child process before closing this one with PTRACE_INTERRUPT
    if (argc < 2)
        return (printf("Usage: ./ft_strace <command> [args]\n"));
    if (ft_strace(argv + 1) == -1)
        return (printf("ft_strace: error: failed to trace\n"));
    return (0);
}
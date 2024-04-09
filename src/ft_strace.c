#include "../inc/ft_strace.h"

const syscall_t			syscallsTab[] = X64_SYSCALLS_LIST;
int num_syscalls = 461;
int pid;

void handle_sig(){
    printf("Signal handler kill the child pid %d\n", pid);
    ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);
}

char *get_syscall_name(int syscall_number, struct user_regs_struct regs) {
    int offset = 0;
    int argId = 0;
    for (int i = 0; i < num_syscalls; i++) {
        if (syscallsTab[i].number == syscall_number) {
            printf("%s(", syscallsTab[i].name);
            for (int j = 0; j < syscallsTab[i].args_count; j++){
                argId =  *(&(syscallsTab[i].argI)+offset);
                if (argId == 0){
                    printf("Pointer to: %p", (&regs.rdi-offset));
                } else if (argId == 1){
                    printf("%d", *(&regs.rdi-offset));
                } else if (argId == 2){
                    printf("%ld", *(&regs.rdi-offset));
                } else if (argId == 3){
                    printf("%lu", *(&regs.rdi-offset));
                } else if (argId == 4){
                    printf("%u", *(&regs.rdi-offset));
                } else if (argId == 5){
                    printf("String at: %p", (&regs.rdi-offset));
                } else if (argId == 6){
                    printf("%lu", *(&regs.rdi-offset));
                } else {
                    printf("%u", *(&regs.rdi-offset));
                }
                offset++;
                if (j+1 < syscallsTab[i].args_count)
                    printf(",");
            }
            // printf("RDI %p\nRSI %p\nRDX %p\n", regs.rdi,regs.rsi,regs.rdx);
            return syscallsTab[i].name;
        }
    }
    return NULL;
}

int ft_strace(char **argv)
{
    
    int status = 999;
    struct iovec iov;
    struct user_regs_struct regs;
    int traceret = 999;

    struct utsname buf;
    if (uname(&buf) == -1) {
        perror("uname");
        return 1;
    }
    printf("Machine architecture: %s\n", buf.machine);
    
    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);

    pid = fork();
    if (pid == -1)
        return (-1);
    if (pid == 0)
    {
        raise(SIGCHLD);
        if (execvp(argv[0], argv) == -1){
            printf("error: %s\nfunction %s line %d\n",strerror(errno), __FUNCTION__, __LINE__-1);
            // signal();
        }
        return(0);
    }
    else{
        printf("pid: %d\n", pid);
        traceret = ptrace(PTRACE_SEIZE, pid, NULL, NULL);
        if(traceret == -1){
            printf("error: %s\nfunction %s line %d\n",strerror(errno), __FUNCTION__, __LINE__-1);
            return(-1);
        }
        printf("traceret === %d\n", traceret);
        // ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD); // ha zayda ?
        while(1){
            waitForSyscallExitStop:
            waitpid(-1, &status, 0);

            if (!WIFSTOPPED(status)){
                printf("Exit, status=%s\n", strsignal(WEXITSTATUS(status)));
                return (1);
            }
            bzero(&regs, sizeof(struct user_regs_struct));
            if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1){
                printf("error: %s\nfunction %s line %d\n",strerror(errno), __FUNCTION__, __LINE__-1);
                perror("ptrace");
            }
            // memcpy(&regsCopy, &regs, sizeof(struct user_regs_struct));
            if (regs.rax == -ENOSYS){
                ptrace(PTRACE_SYSCALL, pid, 0, 0);
                goto waitForSyscallExitStop;
            }
            get_syscall_name(regs.orig_rax, regs);
            printf(") =  %d\n", regs.rax);
            ptrace(PTRACE_SYSCALL, pid, 0, 0);
        }
        return (1);
    }
    
}

int main(int argc, char **argv)
{
    // must add signals handler, and kill the child process before closing this one with PTRACE_INTERRUPT
    if (argc < 2)
        return (printf("Usage: ./ft_strace <command> [args]\n"));
    signal(SIGHUP, handle_sig); 
    signal(SIGINT, handle_sig); 
    signal(SIGQUIT, handle_sig); 
    signal(SIGILL, handle_sig); 
    signal(SIGABRT, handle_sig); 
    if (ft_strace(argv + 1) == -1)
        return (printf("ft_strace: error: failed to trace\n"));
    return (0);
}
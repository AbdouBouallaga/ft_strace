#include "../inc/ft_strace.h"

int total = 0;
int debug_count = 10;
const syscall_t			syscallsTab[] = X64_SYSCALLS_LIST;
int num_syscalls = 461;

void initstructs(){

}

char *get_syscall_name(int syscall_number, struct user_regs_struct regs) {
    int offset = 0;
    int argId = 0;
    initstructs();
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
    int pid;
    int status = 999;
    struct iovec iov;
    struct user_regs_struct regs;
    struct user_regs_struct regsCopy; //get a copy at syscall-enter-stop

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
            signal();
        }
        return(0);
    }
    else{
        printf("pid: %d\n", pid);
        if(ptrace(PTRACE_SEIZE, pid, NULL, NULL) == -1){
            printf("error: %s\nfunction %s line %d\n",strerror(errno), __FUNCTION__, __LINE__-1);
            return(-1);
        }
        // ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD); // ha zayda ?
        while(1){
            waitForSyscallExitStop:
            waitpid(-1, &status, 0);

            if (WIFSIGNALED(status)){
                printf("killed by signal %s\n", strsignal(WTERMSIG(status)));
                return (1);
            } else if (WIFEXITED(status)){
                printf("exited, status=%s\n", strsignal(WEXITSTATUS(status)));
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
    if (ft_strace(argv + 1) == -1)
        return (printf("ft_strace: error: failed to trace\n"));
    return (0);
}
#include "../inc/ft_strace.h"

const syscall_t			syscallsTab[] = X64_SYSCALLS_LIST;
int num_syscalls = 461;
int pid;

void handle_sig(int sig){
    printf("Signal handler kill the child pid %d, sig = %d\n", pid, sig);
    ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);
    exit(0);
}

char *get_syscall_name(int syscall_number, struct user_regs_struct_template regs) {
    int offset = 0;
    int argId = 0;
    int i = 0;
    int j = 0;
    while(i < num_syscalls){
        if (syscallsTab[i].number == syscall_number) {
            printf("%s(", syscallsTab[i].name);
            while(j < syscallsTab[i].args_count){
                argId =  *(&(syscallsTab[i].argI)+offset);
                if (argId == 0){
                    printf("Pointer to: %p", (&regs.rdi-offset));
                } else if (argId == 1){
                    printf("%d", (int)*(&regs.rdi-offset));
                } else if (argId == 2){
                    printf("%ld", (long int)*(&regs.rdi-offset));
                } else if (argId == 3){
                    printf("%lu", (long unsigned int)*(&regs.rdi-offset));
                } else if (argId == 4){
                    printf("%u", (unsigned int)*(&regs.rdi-offset));
                } else if (argId == 5){
                    printf("String at: %p", (&regs.rdi-offset));
                } else if (argId == 6){
                    printf("%lu", (long unsigned int)*(&regs.rdi-offset));
                } else {
                    printf("%u", (unsigned int)*(&regs.rdi-offset));
                }

                offset++;
                if (offset == 4)
                    offset++;
                if (j+1 < syscallsTab[i].args_count)
                    printf(",");
                j++;
            }
            return syscallsTab[i].name;
        }
        i++;
    }
    return NULL;
}

int ft_strace(char **argv)
{
    struct regs_offset regs_offset;
    int status = 999;
    struct iovec iov;
    struct user_regs_struct_template regs;
    int traceret = 999;

    struct utsname buf;
    if (uname(&buf) == -1) {
        perror("uname");
        return 1;
    }
    printf("Machine architecture: %s\n", buf.machine);
    if (!strcmp(buf.machine, "x86_64")){
        regs_offset.rax = sizeof(unsigned long) * 1;
    } else {
        regs_offset.rax = 6;
    }
    
    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);

    pid = fork();
    if (pid == -1)
        return (-1);
    if (pid == 0)
    {
        raise(SIGCHLD);
        if (execvp(argv[0], argv) == -1){
            // printf("error: %s\nfunction %s line %d\n",strerror(errno), __FUNCTION__, __LINE__-1);
            printf("error: %s\n",strerror(errno));
            raise(SIGHUP);
            // signal();
        }
        return(0);
    }
    else{
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
            bzero(&regs, sizeof(struct user_regs_struct_template));
            if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1){
                printf("error: %s\nfunction %s line %d\n",strerror(errno), __FUNCTION__, __LINE__-1);
                perror("ptrace");
            }
            // memcpy(&regsCopy, &regs, sizeof(struct user_regs_struct_template));
            if (regs.rax == -ENOSYS){
                ptrace(PTRACE_SYSCALL, pid, 0, 0);
                goto waitForSyscallExitStop;
            }
            get_syscall_name(regs.orig_rax, regs);
            printf(") =  %p\n", (&regs+regs_offset.rax));
            printf(") =  %p\n", (&regs.r15));
            printf(") =  %p\n", (&regs.r14));
            printf(") =  %p\n", (&regs.rax));
            ptrace(PTRACE_SYSCALL, pid, 0, 0);
        }
        return (1);
    }
    
}

void setup_signals_handler(){
    int i = 0;
    while(i++ < 32){
        if (i != 7 && i != 29 && i != 17 && i != 5){
            signal(i, handle_sig); 
        }
    }
}


int main(int argc, char **argv)
{
    // must add signals handler, and kill the child process before closing this one with PTRACE_INTERRUPT
    if (argc < 2)
        return (printf("Usage: ./ft_strace <command> [args]\n"));
    setup_signals_handler();
    if (ft_strace(argv + 1) == -1)
        return (printf("ft_strace: error: failed to trace\n"));
    return (0);
}
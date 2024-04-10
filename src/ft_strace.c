#include "../inc/ft_strace.h"

const syscall_t			syscallsTab64[] = X64_SYSCALLS_LIST;
const syscall_t			syscallsTab32[] = X32_SYSCALLS_LIST;
const syscall_t			*syscallsTab;
int num_syscalls = 461;
int pid;

void handle_sig(int sig){
    printf("Signal handler kill the child pid %d, sig = %d\n", pid, sig);
    ptrace(PTRACE_INTERRUPT, pid, NULL, NULL);
    exit(0);
}

char *get_syscall_name(int syscall_number, unsigned long *regs) {
    int offset = 0;
    int argId = 0;
    int i = 0;
    int j = 0;
    while(i < num_syscalls){
        if (syscallsTab[i].number == syscall_number) {
            printf("%s(", syscallsTab[i].name);
            while(j < syscallsTab[i].args_count){
                argId =  *(&(syscallsTab[i].argI)+j);
                if (argId == 0){
                    printf("Pointer to: %p", (unsigned long *)*(regs-offset));
                } else if (argId == 1){
                    printf("%d", *(int*)(regs-offset));
                } else if (argId == 2){
                    printf("%ld", *(long int*)(regs-offset));
                } else if (argId == 3){
                    printf("%lu", *(long unsigned int*)(regs-offset));
                } else if (argId == 4){
                    printf("%u", *(unsigned int *)(regs-offset));
                } else if (argId == 5){
                    printf("String at: %p", (regs-offset));
                } else if (argId == 6){
                    printf("%lu", *(long unsigned int *)(regs-offset));
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
    struct regs_offset r_off; //r_off
    int status = 999;
    struct iovec iov;
    struct user_regs_struct_template regs;
    void *regshead = NULL;
    int traceret = 999;

    struct utsname buf;
    if (uname(&buf) == -1) {
        perror("uname");
        return 1;
    }
    
    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);

    printf("Machine architecture: %s\n", buf.machine);
    regshead = &regs.r15;
    if (!strcmp(buf.machine, "x86_64")){
        syscallsTab = syscallsTab64;
        r_off.rax = sizeof(unsigned long)*10;
        r_off.rdi = sizeof(unsigned long)*14;
        r_off.orig_rax = sizeof(unsigned long)*15;
    } else {
        syscallsTab = syscallsTab32;
        r_off.rax = sizeof(long int)*6;
        r_off.rdi = sizeof(long int)*4;
        r_off.orig_rax = sizeof(long int)*11;

    }
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
            if ((*(unsigned long *)(regshead+r_off.rax)) == -ENOSYS){
                ptrace(PTRACE_SYSCALL, pid, 0, 0);
                goto waitForSyscallExitStop;
            }
            get_syscall_name(*(int *)(regshead+r_off.orig_rax), (unsigned long *)(regshead+r_off.rdi));
            
            printf(") =  %d\n", *(int *)(regshead+r_off.rax));
            // printf(")RAX =  %p\n", (regshead+r_off.rax));
            // printf(")RAX =  %p\n", (&regs.rax));
            // printf(")RDI =  %p\n", (regshead+r_off.rdi));
            // printf(")RDI =  %p\n", (&regs.rdi));
            // printf(")RDX =  %p\n", (&regs.rdx));
            // printf(")RCX =  %p\n", (&regs.rcx));
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
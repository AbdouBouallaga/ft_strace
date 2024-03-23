#ifndef FT_STRACE_H
#define FT_STRACE_H

#include <stdio.h>
#include <string.h> //strerror
#include <sys/types.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/utsname.h>

#define NT_PRSTATUS 1

typedef struct {
    unsigned long   r15;
    unsigned long   r14;
    unsigned long   r13;
    unsigned long   r12;
    unsigned long   rbp;
    unsigned long   rbx;
    unsigned long   r11;
    unsigned long   r10;
    unsigned long   r9;
    unsigned long   r8;
    unsigned long   rax;
    unsigned long   rcx;
    unsigned long   rdx;
    unsigned long   rsi;
    unsigned long   rdi;
    unsigned long   orig_rax;
    unsigned long   rip;
    unsigned long   cs;
    unsigned long   eflags;
    unsigned long   rsp;
    unsigned long   ss;
    unsigned long   fs_base;
    unsigned long   gs_base;
    unsigned long   ds;
    unsigned long   es;
    unsigned long   fs;
    unsigned long   gs;
}                   cuser_regs_struct;

#endif
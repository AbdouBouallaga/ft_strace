#ifndef FT_STRACE_H
#define FT_STRACE_H

#include "./x64_syscalls.h"
#include <stdio.h>
#include <string.h> //strerror
#include <sys/types.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <elf.h> // Where NT_PRSTATUS is defined
#include <stdlib.h>


# define INT				1
# define LONG				2
# define ULONG				3
# define UINT				4
# define CHARP				5
# define SIZET				6

typedef struct	syscall_s {
	// char		*name;
	// int			argc;
	// char		*type_args[6];
	int number;
    char *name;
	int args_count;
	int argI;
	int argII;
	int argIII;
	int argIV;
	int argVI;
	int argV;
}				syscall_t;

struct regs_offset{
	unsigned int orig_rax;
	unsigned int rax;
	unsigned int rdi;
};

struct user_regs_struct_template
{
  unsigned long r15;
  unsigned long r14;
  unsigned long r13;
  unsigned long r12;
  unsigned long rbp;
  unsigned long rbx;
  unsigned long r11;
  unsigned long r10;
  unsigned long r9;
  unsigned long r8;
  unsigned long rax;
  unsigned long rcx;
  unsigned long rdx;
  unsigned long rsi;
  unsigned long rdi;
  unsigned long orig_rax;
  unsigned long rip;
  unsigned long cs;
  unsigned long eflags;
  unsigned long rsp;
  unsigned long ss;
  unsigned long fs_base;
  unsigned long gs_base;
  unsigned long ds;
  unsigned long es;
  unsigned long fs;
  unsigned long gs;
};

// struct user_regs_struct
// {
//   long int ebx;
//   long int ecx;
//   long int edx;
//   long int esi;
//   long int edi;
//   long int ebp;
//   long int eax;
//   long int xds;
//   long int xes;
//   long int xfs;
//   long int xgs;
//   long int orig_eax;
//   long int eip;
//   long int xcs;
//   long int eflags;
//   long int esp;
//   long int xss;
// };

# endif
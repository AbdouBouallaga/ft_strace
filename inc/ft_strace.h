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
# endif
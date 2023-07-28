#pragma once
#include "../nolibc/nolibc.h"
#include <linux/sched.h>

typedef int (*clone_cb_t)(void);

static pid_t __clone(struct clone_args *cl_args, clone_cb_t cb)
{
	pid_t retval;

	asm volatile("syscall\n\t"
		     "testq %%rax, %%rax\n\t"
		     "jnz 0f\n\t"
		     "movq $39, %%rax\n\t" /* __NR_getpid */
		     "syscall\n\t"
		     "movq %%rax, %%rdi\n\t"
		     "movq $19, %%rsi\n\t" /* SIGSTOP */
		     "movq $62, %%rax\n\t" /* __NR_kill */
		     "syscall\n\t"
		     "call *%4\n\t"
		     "movq %%rax, %%rdi\n\t"
		     "movq $60, %%rax\n\t" /* __NR_exit */
		     "syscall\n\t"
		     "hlt\n\t"
		     "0:\n\t"
		     : "=a"(retval)
		     : "a"(__NR_clone3), "D"(cl_args),
		       "S"(sizeof(struct clone_args)), "r"(cb)
		     : "rcx", "rdx", "r10", "r11", "r8", "r9", "memory");

	if (retval < 0) {
		SET_ERRNO(-retval);
		retval = -1;
	}
	return retval;
}

static pid_t clone_same_vm(clone_cb_t cb, void *stack, unsigned long stack_size)
{
	struct clone_args cl_args = {};
	cl_args.flags = CLONE_FS | CLONE_FILES | CLONE_SYSVSEM | CLONE_SIGHAND |
			CLONE_VM;
	cl_args.stack = (long)stack;
	cl_args.stack_size = stack_size;

	return __clone(&cl_args, cb);
}

static pid_t clone_new_vm(clone_cb_t cb, void *stack, unsigned long stack_size)
{
	struct clone_args cl_args = {};
	cl_args.flags = CLONE_FS | CLONE_FILES | CLONE_SYSVSEM;
	cl_args.stack = (long)stack;
	cl_args.stack_size = stack_size;

	return __clone(&cl_args, cb);
}

#pragma once
#include "../nolibc/nolibc.h"

#define CPU_0 0
#define CPU_1 1

static int __pin_cpu(pid_t pid, unsigned int len, unsigned long *cpu_mask)
{
	int retval;

	retval = my_syscall3(__NR_sched_setaffinity, pid, len, cpu_mask);
	if (retval < 0) {
		SET_ERRNO(-retval);
		retval = -1;
	}

	return retval;
}

static int pin_cpu2(pid_t pid, int cpu_id)
{
	unsigned long cpu_mask;
	int retval;

	cpu_mask = 1UL << cpu_id;
	retval = __pin_cpu(pid, sizeof(cpu_mask), &cpu_mask);

	return retval;
}

static int pin_cpu(int cpu_id)
{
	return pin_cpu2(getpid(), cpu_id);
}

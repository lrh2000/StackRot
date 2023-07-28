#pragma once
#include "../nolibc/nolibc.h"
#include <linux/membarrier.h>

void synchronize_rcu(void)
{
	int retval;

	retval = my_syscall3(__NR_membarrier, MEMBARRIER_CMD_GLOBAL, 0, -1);
	if (retval < 0) {
		SET_ERRNO(-retval);
		perror("rcu membarrier");
	}
}

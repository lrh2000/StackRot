#pragma once
#include "../nolibc/nolibc.h"
#include <linux/uio.h>

static long readv(int fildes, const struct iovec *iov, int iovcnt)
{
	long retval;

	retval = my_syscall3(__NR_readv, fildes, iov, iovcnt);
	if (retval < 0) {
		SET_ERRNO(-retval);
		retval = -1;
	}

	return retval;
}

#pragma once
#include "../nolibc/nolibc.h"
#include <linux/msg.h>

typedef int key_t;

static int msgget(key_t key, int msgflg)
{
	int retval;

	retval = my_syscall2(__NR_msgget, key, msgflg);
	if (retval < 0) {
		SET_ERRNO(-retval);
		retval = -1;
	}

	return retval;
}

static int msgsnd(int msqid, const void *msgp, size_t msgsz, int msgflg)
{
	int retval;

	retval = my_syscall4(__NR_msgsnd, msqid, msgp, msgsz, msgflg);
	if (retval < 0) {
		SET_ERRNO(-retval);
		retval = -1;
	}

	return retval;
}

static int msgctl(int msqid, int cmd, struct msqid_ds *buf)
{
	int retval;

	retval = my_syscall3(__NR_msgctl, msqid, cmd, buf);
	if (retval < 0) {
		SET_ERRNO(-retval);
		retval = -1;
	}

	return retval;
}

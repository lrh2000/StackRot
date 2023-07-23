#pragma once

#define KERNEL_MSGHDR_SIZE    (6 * 8)
#define USERSPACE_MSGHDR_SIZE 8

struct msg_hdr {
	unsigned long type;
	char data[0];
};

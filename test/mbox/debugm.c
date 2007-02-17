/*
 * $CC $CFLAGS -I../.. debugm.c -lclamav -lefence (or what ever memory debugger)
 * If you're going to use HAVE_BACKTRACE, ensure CFLAGS includes -g and doesn't
 * include -fomit-frame-pointer
 *
 * njh@bandsman.co.uk
 */
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <malloc.h>
#include <clamav.h>
#include <sys/resource.h>
#include <signal.h>
#include <features.h>
#include "clamav-config.h"

#if __GLIBC__ == 2 && __GLIBC_MINOR__ >= 1
/*#define HAVE_BACKTRACE	/* Only tested on Linux... */
#endif

#ifdef HAVE_BACKTRACE
#include <execinfo.h>
#endif

static	void	print_trace(void);
static	void	sigsegv(int sig);

static void
sigsegv(int sig)
{
	signal(SIGSEGV, SIG_DFL);
	print_trace();
	_exit(SIGSEGV);
}

static void
print_trace(void)
{
#ifdef HAVE_BACKTRACE
	void *array[10];
	size_t size, i;
	char **strings;

	puts("Segfault caught, backtrace:");

	size = backtrace(array, 10);
	strings = backtrace_symbols(array, size);

	for(i = 0; i < size; i++)
		printf("\t%s\n", strings[i]);

	free(strings);
#endif
}

int
main(int argc, char **argv)
{
	struct rlimit rlim;

	if(argc == 1) {
		fprintf(stderr, "Usage: %s files...\n", argv[0]);
		return 1;
	}
	rlim.rlim_cur = rlim.rlim_max = RLIM_INFINITY;
	if(setrlimit(RLIMIT_CORE, &rlim) < 0)
		perror("setrlimit");

	if(mkdir("/tmp/mboxtest", 0750) < 0) {
		perror("/tmp/mboxtest");
		return errno;
	}
	signal(SIGSEGV, sigsegv);
	while(*++argv) {
		int fd = open(*argv, 0);

		if(fd < 0) {
			perror(*argv);
			return errno;
		}
		printf("cl_mbox(%s) returns %d\n",
			*argv, cl_mbox("/tmp/mboxtest", fd));
		close(fd);
	}
	puts("Finished - don't forget to rm -rf /tmp/mboxtest");

	return 0;
}

/*
 * $CC $CFLAGS debugm.c -lclamav -lefence (or what ever memory debugger)
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

	exit(0);
}

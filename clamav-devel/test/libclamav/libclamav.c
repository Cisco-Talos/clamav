/*
 *  Copyright (C) 2006 Nigel Horne <njh@bandsman.co.uk>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 *
 * $CC $CFLAGS -I../.. -I../../libclamav debugm.c -lclamav
 * Now try a.out /sbin/* or a.out /usr/bin/*
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
#include <features.h>
#include <unistd.h>
#include <memory.h>
#include <pthread.h>
#include "clamav-config.h"
#include "others.h"
#include "mbox.h"
#include "pdf.h"
#include "binhex.h"
#include "untar.h"
#include "special.h"
#include "tnef.h"
#include "pst.h"
#include "pe.h"

struct args {
	cli_ctx	ctx;
	const	char	*filename;
};

static void *
mbox(void *v)
{
	struct args *args = (struct args *)v;
	int fd = open(args->filename, O_RDONLY);

	if(fd < 0) {
		perror(args->filename);
		return NULL;
	}
	printf("cl_mbox(%s) returns %d\n",
		args->filename, cli_mbox("/tmp/libclamav", fd, &args->ctx));
	close(fd);

	return NULL;
}

static void *
pdf(void *v)
{
	struct args *args = (struct args *)v;
	int fd = open(args->filename, O_RDONLY);

	if(fd < 0) {
		perror(args->filename);
		return NULL;
	}
	printf("cl_pdf(%s) returns %d\n",
		args->filename, cli_pdf("/tmp/libclamav", fd, &args->ctx));
	close(fd);

	return NULL;
}

static void *
scandir(void *v)
{
	struct args *args = (struct args *)v;
	int fd = open(args->filename, O_RDONLY);

	if(fd < 0) {
		perror(args->filename);
		return NULL;
	}
	printf("cl_scandir(%s) returns %d\n",
		args->filename, cli_scandir("/tmp/libclamav", &args->ctx));
	close(fd);

	return NULL;
}

static void *
untar(void *v)
{
	struct args *args = (struct args *)v;
	int fd = open(args->filename, O_RDONLY);

	if(fd < 0) {
		perror(args->filename);
		return NULL;
	}
	printf("cl_untar(%s) returns %d\n",
		args->filename, cli_untar("/tmp/libclamav", fd, 1));
	close(fd);

	return NULL;
}

static void *
binhex(void *v)
{
	struct args *args = (struct args *)v;
	int fd = open(args->filename, O_RDONLY);

	if(fd < 0) {
		perror(args->filename);
		return NULL;
	}
	printf("cl_binhex(%s) returns %d\n",
		args->filename, cli_binhex("/tmp/libclamav", fd));
	close(fd);

	return NULL;
}

static void *
jpeg(void *v)
{
	struct args *args = (struct args *)v;
	int fd = open(args->filename, O_RDONLY);

	if(fd < 0) {
		perror(args->filename);
		return NULL;
	}
	printf("cli_check_jpeg_exploit(%s) returns %d\n",
		args->filename, cli_check_jpeg_exploit(fd));
	close(fd);

	return NULL;
}

static void *
tnef(void *v)
{
	struct args *args = (struct args *)v;
	int fd = open(args->filename, O_RDONLY);

	if(fd < 0) {
		perror(args->filename);
		return NULL;
	}
	printf("cli_tnef(%s) returns %d\n",
		args->filename, cli_tnef("/tmp/libclamav", fd));
	close(fd);

	return NULL;
}

static void *
uuencode(void *v)
{
	struct args *args = (struct args *)v;
	int fd = open(args->filename, O_RDONLY);

	if(fd < 0) {
		perror(args->filename);
		return NULL;
	}
	printf("cli_uuencode(%s) returns %d\n",
		args->filename, cli_uuencode("/tmp/libclamav", fd));
	close(fd);

	return NULL;
}

static void *
pst(void *v)
{
	struct args *args = (struct args *)v;
	int fd = open(args->filename, O_RDONLY);

	if(fd < 0) {
		perror(args->filename);
		return NULL;
	}
	printf("cli_pst(%s) returns %d\n",
		args->filename, cli_pst("/tmp/libclamav", fd));
	close(fd);

	return NULL;
}

static void *
pe(void *v)
{
	struct args *args = (struct args *)v;
	int fd = open(args->filename, O_RDONLY);

	if(fd < 0) {
		perror(args->filename);
		return NULL;
	}
	printf("cli_scanpe(%s) returns %d\n",
		args->filename, cli_scanpe(fd, &args->ctx));
	close(fd);

	return NULL;
}

int
main(int argc, char **argv)
{
	struct rlimit rlim;
	const char *virname;
	struct cl_engine engine;
	struct cl_limits limits;
	unsigned long scanned;
	struct args args;

	if(argc == 1) {
		fprintf(stderr, "Usage: %s files...\n", argv[0]);
		return 1;
	}
	rlim.rlim_cur = rlim.rlim_max = RLIM_INFINITY;
	if(setrlimit(RLIMIT_CORE, &rlim) < 0)
		perror("setrlimit");

	if((mkdir("/tmp/libclamav", 0750) < 0) && (errno != EEXIST)) {
		perror("/tmp/libclamav");
		return errno;
	}

	memset(&args.ctx, '\0', sizeof(cli_ctx));
	args.ctx.engine = &engine;
	args.ctx.virname = &virname;
	args.ctx.limits = &limits;
	args.ctx.scanned = &scanned;
	args.ctx.options = 0;

	while(*++argv) {
		pthread_t t;

		args.filename = *argv;

		if(pthread_create(&t, NULL, mbox, &args) != 0)
			perror("pthread_create");
		if(pthread_detach(t) != 0)
			perror("pthread_detach");

		if(pthread_create(&t, NULL, pdf, &args) != 0)
			perror("pthread_create");
		if(pthread_detach(t) != 0)
			perror("pthread_detach");

		if(pthread_create(&t, NULL, untar, &args) != 0)
			perror("pthread_create");
		if(pthread_detach(t) != 0)
			perror("pthread_detach");

		if(pthread_create(&t, NULL, binhex, &args) != 0)
			perror("pthread_create");
		if(pthread_detach(t) != 0)
			perror("pthread_detach");

		if(pthread_create(&t, NULL, jpeg, &args) != 0)
			perror("pthread_create");
		if(pthread_detach(t) != 0)
			perror("pthread_detach");

		if(pthread_create(&t, NULL, tnef, &args) != 0)
			perror("pthread_create");
		if(pthread_detach(t) != 0)
			perror("pthread_detach");

		if(pthread_create(&t, NULL, uuencode, &args) != 0)
			perror("pthread_create");
		if(pthread_detach(t) != 0)
			perror("pthread_detach");

		if(pthread_create(&t, NULL, pst, &args) != 0)
			perror("pthread_create");
		if(pthread_detach(t) != 0)
			perror("pthread_detach");

		if(pthread_create(&t, NULL, pe, &args) != 0)
			perror("pthread_create");
		if(pthread_detach(t) != 0)
			perror("pthread_detach");

		/* TODO: pass through all in cli_magic_scandesc */
		if(pthread_create(&t, NULL, scandir, &args) != 0)
			perror("pthread_create");
		if(pthread_detach(t) != 0)
			perror("pthread_detach");
	}
	puts("Hit SIGINT when all is finished");
	pause();
	puts("Finished - don't forget to rm -rf /tmp/libclamav");

	return 0;
}

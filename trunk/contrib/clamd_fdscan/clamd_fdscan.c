/*	$Id: clamd_fdscan.c,v 1.2 2007/01/18 16:59:50 mbalmer Exp $	*/

/*
 * Copyright (c) 2007 Marc Balmer <mbalmer@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <string.h>

#include <stdio.h>
#include <err.h>
#include <unistd.h>

#include "clamd_fdscan.h"

#define CLAMD_BUFSIZ	256

size_t strlcpy(char *dst, const char *src, size_t siz);
/*
 * clamd_fdscan lets a running clamd process scan the contents of an open
 * filedescriptor by passing the filedescriptor to clamd.  The parameters
 * are as follows:
 * fd		the open filedescriptor to pass for scanning
 * soname	the path to the local clamd listening socket
 * name		virus name, if a virus is found
 * len		max len of the virus name
 *
 * The functions returns 0 if the file was scanned and contains no virus,
 * -1 if an error occurs and 1 if a virus is found.
 */
int
clamd_fdscan(int fd, char *soname, char *name, size_t len)
{
	struct sockaddr_un addr;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	unsigned char fdbuf[CMSG_SPACE(sizeof(int))];
	FILE *sp;
	char buf[CLAMD_BUFSIZ], *p, *q;
	off_t pos;
	int s;
	struct iovec iov[1];

	iov[0].iov_base = "";
	iov[0].iov_len = 1;

	pos = lseek(fd, 0, SEEK_CUR);
	s = socket(AF_UNIX, SOCK_STREAM, 0);
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, soname, sizeof(addr.sun_path));
	if (connect(s, (struct sockaddr *)&addr, sizeof(addr))) {
		perror("connect");
		return -1;
	}

	memset(&msg, 0, sizeof(msg));
	msg.msg_control = fdbuf;
	/* must send/receive at least one byte */
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_controllen = CMSG_LEN(sizeof(int));

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(int *)CMSG_DATA(cmsg) = fd;

	write(s, "FILDES\n", sizeof("FILDES\n")-1);
	if (sendmsg(s, &msg, 0) == -1) {
		perror("sendmsg");
		close(s);
		return -1;
	}

	sp = fdopen(s,"r");
	fgets(buf, sizeof(buf), sp);
	fclose(sp);
	close(s);

	if (pos != -1)
		lseek(fd, pos, SEEK_SET);
	if ((p = strrchr(buf, ' ')) != NULL) {
		++p;
		if (!strncmp(p, "OK", 2))
			return 0;
		else if (!strncmp(p, "FOUND", 5)) {
			if (name != NULL) {
				*--p = '\0';
				q = strrchr(buf, ' ') + 1;
				strlcpy(name, q, len);
			}
			return 1;
		} else {
			puts(buf);
		}
	}
	return -1;
}

int main(int argc, char *argv[])
{
	char virusname[CLAMD_BUFSIZ];
	if(argc != 2) {
		fprintf(stderr,"Usage: %s <clamd_socket>\n", argv[0]);
		return 1;
	}
	virusname[0]=0;
	if(clamd_fdscan(0, argv[1],virusname, sizeof(virusname)) == -1) {
		perror("Error sending fd!");
		return 2;
	} else {
		printf("FOUND: %s\n", virusname);
	}
	return 0;
}

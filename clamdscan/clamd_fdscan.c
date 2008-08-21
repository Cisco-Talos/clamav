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

#ifdef HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifdef HAVE_FD_PASSING
#ifdef FDPASS_NEED_XOPEN
#define _XOPEN_SOURCE 500
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <string.h>

#include <stdio.h>
#include <unistd.h>

#include "clamd_fdscan.h"

#define CLAMD_BUFSIZ	256

size_t cli_strlcpy(char *dst, const char *src, size_t siz);
/*
 * clamd_fdscan lets a running clamd process scan the contents of an open
 * filedescriptor by passing the filedescriptor to clamd.  The parameters
 * are as follows:
 * s            socket connected to clamd
 * fd		the open filedescriptor to pass for scanning
 * name		virus name, if a virus is found
 * len		max len of the virus name
 *
 * The functions returns 0 if the file was scanned and contains no virus,
 * -1 if an error occurs and 1 if a virus is found.
 */
int
clamd_fdscan(int s, int fd, char *name, size_t len)
{
	struct msghdr msg;
	struct cmsghdr *cmsg;
	unsigned char fdbuf[CMSG_SPACE(sizeof(int))];
	FILE *sp;
	char buf[CLAMD_BUFSIZ], *p, *q;
	off_t pos;
	struct iovec iov[1];
	char dummy[]="";

	iov[0].iov_base = dummy;
	iov[0].iov_len = 1;

	pos = lseek(fd, 0, SEEK_CUR);

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

	if(write(s, "FILDES\n", sizeof("FILDES\n")-1) != sizeof("FILDES\n")-1) {
		perror("write");
		close(s);
		return -1;
	}
	if (sendmsg(s, &msg, 0) == -1) {
		perror("sendmsg");
		close(s);
		return -1;
	}

	sp = fdopen(s,"r");
	if(!fgets(buf, sizeof(buf), sp)) {
		fclose(sp);
		close(s);
		return -1;
	}
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
				cli_strlcpy(name, q, len);
			}
			return 1;
		} else {
			puts(buf);
		}
	}
	return -1;
}
#endif

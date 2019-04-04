/*
 *  Copyright (C) 2015 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm, aCaB
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
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
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#if defined(C_SOLARIS)
#ifndef __EXTENSIONS__
#define __EXTENSIONS__
#endif
#endif

/* must be first because it may define _XOPEN_SOURCE */
#include "shared/fdpassing.h"
#include <stdio.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#ifndef _WIN32
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#endif

#include "libclamav/clamav.h"
//#include "libclamav/others.h"
#include "shared/actions.h"
#include "shared/output.h"
#include "shared/misc.h"
#include "shared/clamdcom.h"

#include "onaccess_proto.h"
#include "onaccess_client.h"

//#include "../clamonacc.h"

#ifndef _WIN32
extern struct sockaddr_un nixsock;
#endif

static const char *scancmd[] = { "CONTSCAN", "MULTISCAN", "INSTREAM", "FILDES", "ALLMATCHSCAN" };

/* Connects to clamd
 * Returns a FD or -1 on error */
int onas_dconnect(struct onas_context **ctx) {
	int sockd, res;
	const struct optstruct *opt;
	struct addrinfo hints, *info, *p;
	char port[10];
	char *ipaddr;

#ifndef _WIN32
	opt = optget((*ctx)->clamdopts, "LocalSocket");
	if (opt->enabled) {
		if ((sockd = socket(AF_UNIX, SOCK_STREAM, 0)) >= 0) {
			if (connect(sockd, (struct sockaddr *)&nixsock, sizeof(nixsock)) == 0)
				return sockd;
			else {
				logg("!Could not connect to clamd on LocalSocket %s: %s\n", opt->strarg, strerror(errno));
				close(sockd);
			}
		}
	}
#endif

	snprintf(port, sizeof(port), "%lld", optget((*ctx)->clamdopts, "TCPSocket")->numarg);

	opt = optget((*ctx)->clamdopts, "TCPAddr");
	while (opt) {
		if (opt->enabled) {
			ipaddr = NULL;
			if (opt->strarg)
				ipaddr = (!strcmp(opt->strarg, "any") ? NULL : opt->strarg);

			memset(&hints, 0x00, sizeof(struct addrinfo));
			hints.ai_family = AF_UNSPEC;
			hints.ai_socktype = SOCK_STREAM;

			if ((res = getaddrinfo(ipaddr, port, &hints, &info))) {
				logg("!Could not lookup %s: %s\n", ipaddr ? ipaddr : "", gai_strerror(res));
				opt = opt->nextarg;
				continue;
			}

			for (p = info; p != NULL; p = p->ai_next) {
				if((sockd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0) {
					logg("!Can't create the socket: %s\n", strerror(errno));
					continue;
				}

				if(connect(sockd, p->ai_addr, p->ai_addrlen) < 0) {
					logg("!Could not connect to clamd on %s: %s\n", opt->strarg, strerror(errno));
					closesocket(sockd);
					continue;
				}

				freeaddrinfo(info);
				return sockd;
			}

			freeaddrinfo(info);
		}
		opt = opt->nextarg;
	}

	return -1;
}

/* Issues an INSTREAM command to clamd and streams the given file
 * Returns >0 on success, 0 soft fail, -1 hard fail */
static int onas_send_stream(struct onas_context **ctx, int sockd, const char *filename) {
	uint32_t buf[BUFSIZ/sizeof(uint32_t)];
	int fd, len;
	unsigned long int todo = (*ctx)->maxstream;

	if(filename) {
		if((fd = safe_open(filename, O_RDONLY | O_BINARY))<0) {
			logg("~%s: Access denied. ERROR\n", filename);
			return 0;
		}
	} else fd = 0;

	if(sendln(sockd, "zINSTREAM", 10)) {
		close(fd);
		return -1;
	}

	while((len = read(fd, &buf[1], sizeof(buf) - sizeof(uint32_t))) > 0) {
		if((unsigned int)len > todo) len = todo;
		buf[0] = htonl(len);
		if(sendln(sockd, (const char *)buf, len+sizeof(uint32_t))) {
			close(fd);
			return -1;
		}
		todo -= len;
		if(!todo) {
			len = 0;
			break;
		}
	}
	close(fd);
	if(len) {
		logg("!Failed to read from %s.\n", filename ? filename : "STDIN");
		return 0;
	}
	*buf=0;
	sendln(sockd, (const char *)buf, 4);
	return 1;
}

#ifdef HAVE_FD_PASSING
/* Issues a FILDES command and pass a FD to clamd
 * Returns >0 on success, 0 soft fail, -1 hard fail */
static int onas_send_fdpass(int sockd, const char *filename) {
	struct iovec iov[1];
	struct msghdr msg;
	struct cmsghdr *cmsg;
	unsigned char fdbuf[CMSG_SPACE(sizeof(int))];
	char dummy[]="";
	int fd;

	if(filename) {
		if((fd = open(filename, O_RDONLY))<0) {
			logg("~%s: Access denied. ERROR\n", filename);
			return 0;
		}
	} else fd = 0;
	if(sendln(sockd, "zFILDES", 8)) {
		close(fd);
		return -1;
	}

	iov[0].iov_base = dummy;
	iov[0].iov_len = 1;
	memset(&msg, 0, sizeof(msg));
	msg.msg_control = fdbuf;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_controllen = CMSG_LEN(sizeof(int));
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	*(int *)CMSG_DATA(cmsg) = fd;
	if(sendmsg(sockd, &msg, 0) == -1) {
		logg("!FD send failed: %s\n", strerror(errno));
		close(fd);
		return -1;
	}
	close(fd);
	return 1;
}
#endif

/* 0: scan, 1: skip */
static int chkpath(struct onas_context **ctx, const char *path)
{
	const struct optstruct *opt;

	if((opt = optget((*ctx)->clamdopts, "ExcludePath"))->enabled) {
		while(opt) {
			if(match_regex(path, opt->strarg) == 1) {
				if ((*ctx)->printinfected != 1)
					logg("~%s: Excluded\n", path);
				return 1;
			}
			opt = opt->nextarg;
		}
	}
	return 0;
}

/* Sends a proper scan request to clamd and parses its replies
 * This is used only in non IDSESSION mode
 * Returns the number of infected files or -1 on error
 * NOTE: filename may be NULL for STREAM scantype. */
int onas_dsresult(struct onas_context **ctx, int sockd, int scantype, const char *filename, int *printok, int *errors, cl_error_t *ret_code) {
	int infected = 0, len = 0, beenthere = 0;
	char *bol, *eol;
	struct RCVLN rcv;
	STATBUF sb;

	if(filename && chkpath(ctx, filename))
		return 0;
	recvlninit(&rcv, sockd);

	if (ret_code) {
		*ret_code = CL_SUCCESS;
	}

	switch(scantype) {
		case MULTI:
		case CONT:
		case ALLMATCH:
			if (!filename) {
				logg("Filename cannot be NULL for MULTISCAN or CONTSCAN.\n");
				if (ret_code) {
					*ret_code = CL_ENULLARG;
				}
				return -1;
			}
			len = strlen(filename) + strlen(scancmd[scantype]) + 3;
			if (!(bol = malloc(len))) {
				logg("!Cannot allocate a command buffer: %s\n", strerror(errno));
				if (ret_code) {
					*ret_code = CL_EMEM;
				}
				return -1;
			}
			sprintf(bol, "z%s %s", scancmd[scantype], filename);
			if(sendln(sockd, bol, len)) {
				if (ret_code) {
					*ret_code = CL_EWRITE;
				}
				free(bol);
				return -1;
			}
			free(bol);
			break;

		case STREAM:
			/* NULL filename safe in send_stream() */
			len = onas_send_stream(ctx, sockd, filename);
			break;
#ifdef HAVE_FD_PASSING
		case FILDES:
			/* NULL filename safe in send_fdpass() */
			len = onas_send_fdpass(sockd, filename);
			break;
#endif
	}

	if(len <=0) {
		*printok = 0;
		if(errors)
			(*errors)++;
		return len;
	}

	while((len = recvln(&rcv, &bol, &eol))) {
		if(len == -1) {
			if (ret_code) {
				*ret_code = CL_EREAD;
			}
			return -1;
		}
		beenthere = 1;
		if(!filename) {
			logg("~%s\n", bol);
		}
		if(len > 7) {
			char *colon = strrchr(bol, ':');

			if(colon && colon[1] != ' ') {
				char *br;
				*colon = 0;

				br = strrchr(bol, '(');
				if(br) {
					*br = 0;
				}
				colon = strrchr(bol, ':');
			}

			if(!colon) {
				char * unkco = "UNKNOWN COMMAND";
				if (!strncmp(bol, unkco, sizeof(unkco) - 1)) {
					logg("clamd replied \"UNKNOWN COMMAND\". Command was %s\n",
							(scantype < 0 || scantype > MAX_SCANTYPE) ? "unidentified" :
							scancmd[scantype]);
				} else {
					logg("Failed to parse reply: \"%s\"\n", bol);
				}

				if (ret_code) {
					*ret_code = CL_EPARSE;
				}
				return -1;

			} else if(!memcmp(eol - 7, " FOUND", 6)) {
				static char last_filename[PATH_MAX+1] = {'\0'};
				*(eol - 7) = 0;
				*printok = 0;

				if (scantype != ALLMATCH) {
					infected++;
				} else {
					if (filename != NULL && strcmp(filename, last_filename)) {
						infected++;
						strncpy(last_filename, filename, PATH_MAX);
						last_filename[PATH_MAX] = '\0';
					}
				}

				if(filename) {
					if(scantype >= STREAM) {
						logg("~%s%s FOUND\n", filename, colon);
						if(action) {
							action(filename);
						}
					} else {
						logg("~%s FOUND\n", bol);
						*colon = '\0';
						if(action) {
							action(bol);
						}
					}
				}

				if (ret_code) {
					*ret_code = CL_VIRUS;
				}

			} else if(len > 49 && !memcmp(eol-50, " lstat() failed: No such file or directory. ERROR", 49)) {
				if(errors) {
					(*errors)++;
				}
				*printok = 0;

				if(filename) {
					(scantype >= STREAM) ? logg("*%s%s\n", filename, colon) : logg("*%s\n", bol);
				}

				if (ret_code) {
					*ret_code = CL_ESTAT;
				}

			} else if(!memcmp(eol-7, " ERROR", 6)) {
				if(errors) {
					(*errors)++;
				}
				*printok = 0;

				if(filename) {
					(scantype >= STREAM) ? logg("~%s%s\n", filename, colon) : logg("~%s\n", bol);
				}

				if (ret_code) {
					*ret_code = CL_ESTATE;
				}
			}
		}
	}
	if(!beenthere) {
		if (!filename) {
			logg("STDIN: noreply from clamd\n.");
			if (ret_code) {
				*ret_code = CL_EACCES;
			}
			return -1;
		}
		if(CLAMSTAT(filename, &sb) == -1) {
			logg("~%s: stat() failed with %s, clamd may not be responding\n",
					filename, strerror(errno));
			if (ret_code) {
				*ret_code = CL_EACCES;
			}
			return -1;
		}
		if(!S_ISDIR(sb.st_mode)) {
			logg("~%s: no reply from clamd\n", filename);
			if (ret_code) {
				*ret_code = CL_EACCES;
			}
			return -1;
		}
	}
	return infected;
}


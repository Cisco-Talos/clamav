/*
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
#endif

#include "libclamav/others.h"
#include "shared/actions.h"
#include "shared/output.h"
#include "shared/misc.h"

#include "proto.h"
#include "client.h"

extern struct sockaddr *mainsa;
extern int mainsasz;
extern unsigned long int maxstream;
int printinfected;
extern struct optstruct *clamdopts;

static const char *scancmd[] = { "CONTSCAN", "MULTISCAN" };

/* Connects to clamd 
 * Returns a FD or -1 on error */
int dconnect() {
    int sockd;

    if((sockd = socket(mainsa->sa_family, SOCK_STREAM, 0)) < 0) {
	logg("!Can't create the socket: %s\n", strerror(errno));
	return -1;
    }

    if(connect(sockd, (struct sockaddr *)mainsa, mainsasz) < 0) {
	closesocket(sockd);
	logg("!Can't connect to clamd: %s\n", strerror(errno));
	return -1;
    }
    return sockd;
}

/* Sends bytes over a socket
 * Returns 0 on success */
int sendln(int sockd, const char *line, unsigned int len) {
    while(len) {
	int sent = send(sockd, line, len, 0);
	if(sent <= 0) {
	    if(sent && errno == EINTR) continue;
	    logg("!Can't send to clamd: %s\n", strerror(errno));
	    return 1;
	}
	line += sent;
	len -= sent;
    }
    return 0;
}

/* Inits a RECVLN struct before it can be used in recvln() - see below */
void recvlninit(struct RCVLN *s, int sockd) {
    s->sockd = sockd;
    s->bol = s->cur = s->buf;
    s->r = 0;
}

/* Receives a full (terminated with \0) line from a socket
 * Sets rbol to the begin of the received line, and optionally 
 * reol to the ond of line.
 * Should be called repeatedly untill all input is conumed
 * Returns 
 * - the lenght of the line (a positive number) on success
 * - 0 if the connection is closed
 * - -1 on error
 */
int recvln(struct RCVLN *s, char **rbol, char **reol) {
    char *eol;

    while(1) {
	if(!s->r) {
	    s->r = recv(s->sockd, s->cur, sizeof(s->buf) - (s->cur - s->buf), 0);
	    if(s->r<=0) {
		if(s->r && errno == EINTR) {
		    s->r = 0;
		    continue;
		}
		if(s->r || s->cur!=s->buf) {
		    *s->cur = '\0';
		    if(strcmp(s->buf, "UNKNOWN COMMAND\n"))
			logg("!Communication error\n");
		    else
			logg("!Command rejected by clamd (wrong clamd version?)\n");
		    return -1;
		}
	        return 0;
	    }
	}
	if((eol = memchr(s->cur, 0, s->r))) {
	    int ret = 0;
	    eol++;
	    s->r -= eol - s->cur;
	    *rbol = s->bol;
	    if(reol) *reol = eol;
	    ret = eol - s->bol;
	    if(s->r)
		s->bol = s->cur = eol;
	    else
		s->bol = s->cur = s->buf;
	    return ret;
	}
	s->r += s->cur - s->bol;
	if(!eol && s->r==sizeof(s->buf)) {
	    logg("!Overlong reply from clamd\n");
	    return -1;
	}
	if(!eol) {
	    if(s->buf != s->bol) { /* old memmove sux */
		memmove(s->buf, s->bol, s->r);
		s->bol = s->buf;
	    }
	    s->cur = &s->bol[s->r];
	    s->r = 0;
	}
    }
}

/* Issues an INSTREAM command to clamd and streams the given file
 * Returns >0 on success, 0 soft fail, -1 hard fail */
static int send_stream(int sockd, const char *filename) {
    uint32_t buf[BUFSIZ/sizeof(uint32_t)];
    int fd, len;
    unsigned long int todo = maxstream;

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
static int send_fdpass(int sockd, const char *filename) {
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
static int chkpath(const char *path)
{
	const struct optstruct *opt;

   if((opt = optget(clamdopts, "ExcludePath"))->enabled) {
	while(opt) {
	    if(match_regex(path, opt->strarg) == 1) {
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
 * Returns the number of infected files or -1 on error */
int dsresult(int sockd, int scantype, const char *filename, int *printok, int *errors) {
    int infected = 0, len, beenthere = 0;
    char *bol, *eol;
    struct RCVLN rcv;
    struct stat sb;

    if(chkpath(filename))
	return 0;
    recvlninit(&rcv, sockd);

    switch(scantype) {
    case MULTI:
    case CONT:
    len = strlen(filename) + strlen(scancmd[scantype]) + 3;
    if (!(bol = malloc(len))) {
	logg("!Cannot allocate a command buffer: %s\n", strerror(errno));
	return -1;
    }
    sprintf(bol, "z%s %s", scancmd[scantype], filename);
    if(sendln(sockd, bol, len)) return -1;
    free(bol);
    break;

    case STREAM:
	len = send_stream(sockd, filename);
	break;
#ifdef HAVE_FD_PASSING
    case FILDES:
	len = send_fdpass(sockd, filename);
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
	if(len == -1) return -1;
	beenthere = 1;
	if(!filename) logg("~%s\n", bol);
	if(len > 7) {
	    char *colon = strrchr(bol, ':');
	    if(!colon) {
		logg("Failed to parse reply\n");
		return -1;
	    } else if(!memcmp(eol - 7, " FOUND", 6)) {
		*printok = 0;
		infected++;
		if(filename) {
		    if(scantype >= STREAM) {
			logg("~%s%s\n", filename, colon);
			if(action) action(filename);
		    } else {
			logg("~%s\n", bol);
			*colon = '\0';
			if(action)
			    action(bol);
		    }
		}
	    } else if(!memcmp(eol-7, " ERROR", 6)) {
		if(errors)
		    (*errors)++;
		*printok = 0;
		if(filename) {
		    if(scantype >= STREAM)
			logg("~%s%s\n", filename, colon);
		    else
			logg("~%s\n", bol);
		}
	    }
	}
    }
    if(!beenthere) {
	stat(filename, &sb);
	if(!S_ISDIR(sb.st_mode)) {
	    logg("~%s: no reply from clamd\n", filename ? filename : "STDIN");
	    return -1;
	}
    }
    return infected;
}



/* Used by serial_callback() */
struct client_serial_data {
    int infected;
    int scantype;
    int printok;
    int files;
    int errors;
};

/* FTW callback for scanning in non IDSESSION mode
 * Returns SUCCESS or BREAK on success, CL_EXXX on error */
static int serial_callback(struct stat *sb, char *filename, const char *path, enum cli_ftw_reason reason, struct cli_ftw_cbdata *data) {
    struct client_serial_data *c = (struct client_serial_data *)data->data;
    int sockd, ret;
    const char *f = filename;

    c->files++;
    switch(reason) {
    case error_stat:
	logg("!Can't access file %s\n", path);
	c->errors++;
	return CL_SUCCESS;
    case error_mem:
	logg("!Memory allocation failed in ftw\n");
	c->errors++;
	return CL_EMEM;
    case warning_skipped_dir:
	logg("^Directory recursion limit reached\n");
    case warning_skipped_link:
	return CL_SUCCESS;
    case warning_skipped_special:
	logg("!%s: Not supported file type\n", path);
	c->errors++;
	return CL_SUCCESS;
    case visit_directory_toplev:
	if(c->scantype >= STREAM)
	    return CL_SUCCESS;
	f = path;
	filename = NULL;
    case visit_file:
	break;
    }

    if((sockd = dconnect()) < 0) {
	if(filename) free(filename);
	c->errors++;
	return CL_EOPEN;
    }
    ret = dsresult(sockd, c->scantype, f, &c->printok, &c->errors);
    if(filename) free(filename);
    closesocket(sockd);
    if(ret < 0) {
	c->errors++;
	return CL_EOPEN;
    }
    c->infected += ret;
    if(reason == visit_directory_toplev)
	return CL_BREAK;
    return CL_SUCCESS;
}

/* Non-IDSESSION handler
 * Returns non zero for serious errors, zero otherwise */
int serial_client_scan(char *file, int scantype, int *infected, int *err, int maxlevel, int flags) {
    struct cli_ftw_cbdata data;
    struct client_serial_data cdata;
    int ftw;

    cdata.infected = 0;
    cdata.files = 0;
    cdata.errors = 0;
    cdata.printok = printinfected^1;
    cdata.scantype = scantype;
    data.data = &cdata;

    ftw = cli_ftw(file, flags, maxlevel ? maxlevel : INT_MAX, serial_callback, &data, NULL);
    *infected += cdata.infected;
    *err += cdata.errors;

    if(!cdata.errors && (ftw == CL_SUCCESS || ftw == CL_BREAK)) {
	if(cdata.printok)
	    logg("~%s: OK\n", file);
	return 0;
    } else if(!cdata.files) {
	logg("~%s: No files scanned\n", file);
	return 0;
    }
    return 1;
}

/* Used in IDSESSION mode */
struct client_parallel_data {
    int infected;
    int files;
    int errors;
    int scantype;
    int sockd;
    int lastid;
    int printok;
    struct SCANID {
	unsigned int id;
	const char *file;
	struct SCANID *next;
    } *ids;
};

/* Sends a proper scan request to clamd and parses its replies
 * This is used only in IDSESSION mode
 * Returns 0 on success, 1 on hard failures, 2 on len == 0 (bb#1717) */
static int dspresult(struct client_parallel_data *c) {
    const char *filename;
    char *bol, *eol;
    unsigned int rid;
    int len;
    struct SCANID **id = NULL;
    struct RCVLN rcv;

    recvlninit(&rcv, c->sockd);
    do {
	len = recvln(&rcv, &bol, &eol);
	if(len < 0) return 1;
	if(!len) return 2;
	if((rid = atoi(bol))) {
	    id = &c->ids;
	    while(*id) {
		if((*id)->id == rid) break;
		id = &((*id)->next);
	    }
	    if(!*id) id = NULL;
	}
	if(!id) {
	    logg("!Bogus session id from clamd\n");
	    return 1;
	}
	filename = (*id)->file;
	if(len > 7) {
	    char *colon = strrchr(bol, ':');
	    if(!colon) {
		logg("!Failed to parse reply\n");
		free((void *)filename);
		return 1;
	    } else if(!memcmp(eol - 7, " FOUND", 6)) {
		c->infected++;
		c->printok = 0;
		logg("~%s%s\n", filename, colon);
		if(action) action(filename);
	    } else if(!memcmp(eol-7, " ERROR", 6)) {
		c->errors++;
		c->printok = 0;
		logg("~%s%s\n", filename, colon);
	    }
	}
	free((void *)filename);
	bol = (char *)*id;
	*id = (*id)->next;
	free(bol);
    } while(rcv.cur != rcv.buf); /* clamd sends whole lines, so, on partial lines, we just assume
				    more data can be recv()'d with close to zero latency */
    return 0;
}

/* FTW callback for scanning in IDSESSION mode
 * Returns SUCCESS on success, CL_EXXX or BREAK on error */
static int parallel_callback(struct stat *sb, char *filename, const char *path, enum cli_ftw_reason reason, struct cli_ftw_cbdata *data) {
    struct client_parallel_data *c = (struct client_parallel_data *)data->data;
    struct SCANID *cid;
    int res;

    if(chkpath(filename))
	return 0;
    c->files++;
    switch(reason) {
    case error_stat:
	logg("!Can't access file %s\n", path);
	c->errors++;
	return CL_SUCCESS;
    case error_mem:
	logg("!Memory allocation failed in ftw\n");
	c->errors++;
	return CL_EMEM;
    case warning_skipped_dir:
	logg("^Directory recursion limit reached\n");
	return CL_SUCCESS;
    case warning_skipped_special:
	logg("!%s: Not supported file type\n", path);
	c->errors++;
    case warning_skipped_link:
    case visit_directory_toplev:
	return CL_SUCCESS;
    case visit_file:
	break;
    }

    while(1) {
	/* consume all the available input to let some of the clamd
	 * threads blocked on send() to be dead.
	 * by doing so we shouldn't deadlock on the next recv() */
	fd_set rfds, wfds;
	FD_ZERO(&rfds);
	FD_SET(c->sockd, &rfds);
	FD_ZERO(&wfds);
	FD_SET(c->sockd, &wfds);
	if(select(c->sockd + 1, &rfds, &wfds, NULL, NULL) < 0) {
	    if(errno == EINTR) continue;
	    free(filename);
	    logg("!select() failed during session: %s\n", strerror(errno));
	    return CL_BREAK;
	}
	if(FD_ISSET(c->sockd, &rfds)) {
	    if(dspresult(c)) {
		free(filename);
		return CL_BREAK;
	    } else continue;
	}
	if(FD_ISSET(c->sockd, &wfds)) break;
    }

    cid = (struct SCANID *)malloc(sizeof(struct SCANID));
    if(!cid) {
	free(filename);
	logg("!Failed to allocate scanid entry: %s\n", strerror(errno));
	return CL_BREAK;
    }
    cid->id = ++c->lastid;
    cid->file = filename;
    cid->next = c->ids;
    c->ids = cid;

    switch(c->scantype) {
#ifdef HAVE_FD_PASSING
    case FILDES:
	res = send_fdpass(c->sockd, filename);
	break;
#endif
    case STREAM:
	res = send_stream(c->sockd, filename);
	break;
    }
    if(res <= 0) {
	c->printok = 0;
	c->errors++;
	c->ids = cid->next;
	c->lastid--;
	free(cid);
	free(filename);
	return res ? CL_BREAK : CL_SUCCESS;
    }
    return CL_SUCCESS;
}

/* IDSESSION handler
 * Returns non zero for serious errors, zero otherwise */
int parallel_client_scan(char *file, int scantype, int *infected, int *err, int maxlevel, int flags) {
    struct cli_ftw_cbdata data;
    struct client_parallel_data cdata;
    int ftw;

    if((cdata.sockd = dconnect()) < 0)
	return 1;

    if(sendln(cdata.sockd, "zIDSESSION", 11)) {
	closesocket(cdata.sockd);
	return 1;
    }

    cdata.infected = 0;
    cdata.files = 0;
    cdata.errors = 0;
    cdata.scantype = scantype;
    cdata.lastid = 0;
    cdata.ids = NULL;
    cdata.printok = printinfected^1;
    data.data = &cdata;

    ftw = cli_ftw(file, flags, maxlevel ? maxlevel : INT_MAX, parallel_callback, &data, NULL);

    if(ftw != CL_SUCCESS) {
	*err += cdata.errors;
	*infected += cdata.infected;
	closesocket(cdata.sockd);
	return 1;
    }

    sendln(cdata.sockd, "zEND", 5);
    while(cdata.ids && !dspresult(&cdata));
    closesocket(cdata.sockd);

    *infected += cdata.infected;
    *err += cdata.errors;

    if(cdata.ids) {
	logg("!Clamd closed the connection before scanning all files.\n");
	return 1;
    }
    if(cdata.errors)
	return 1;

    if(!cdata.files)
	return 0;

    if(cdata.printok)
	logg("~%s: OK\n", file);
    return 0;
}

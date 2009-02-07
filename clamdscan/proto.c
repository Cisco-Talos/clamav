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

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>

#include "libclamav/others.h"
#include "shared/output.h"

#include "proto.h"
#include "client.h"

extern struct sockaddr *mainsa;
extern int mainsasz;
extern void (*action)(const char *);

static const char *scancmd[] = { "CONTSCAN", "MULTISCAN" };

/* Connects to clamd 
 * Returns a FD or -1 on error */
int dconnect() {
    int sockd;

    if((sockd = socket(mainsa->sa_family, SOCK_STREAM, 0)) < 0) {
	perror("socket()");
	logg("!Can't create the socket.\n");
	return -1;
    }

    if(connect(sockd, (struct sockaddr *)mainsa, mainsasz) < 0) {
	close(sockd);
	perror("connect()");
	logg("!Can't connect to clamd.\n");
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
	    logg("!Can't send request to clamd\n");
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
		    logg("!Communication error\n");
		    return -1;
		}
		*rbol = NULL;
		if(reol) *reol = eol;
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
 * Returns 0 on success */
static int send_stream(int sockd, const char *filename) {
    uint32_t buf[BUFSIZ/sizeof(uint32_t)];
    int fd, len;

    if(filename) {
	if(!(fd = open(filename, O_RDONLY))) {
	    logg("!Open failed on %s.\n", filename);
	    return 1;
	}
    } else fd = 0;

    if(sendln(sockd, "zINSTREAM", 10)) return 1;

    while((len = read(fd, &buf[1], sizeof(buf) - sizeof(uint32_t))) > 0) {
	buf[0] = htonl(len);
	if(sendln(sockd, (const char *)buf, len+sizeof(uint32_t))) { /* FIXME: need to handle limits */
	    logg("!Can't write to the socket.\n");
	    close(fd);
	    return 1;
	}
    }
    close(fd);
    if(len) {
	logg("!Failed to read from %s.\n", filename);
	return 1;
    }
    return 0;
}

#ifdef HAVE_FD_PASSING
/* Issues a FILDES command and pass a FD to clamd
 * Returns 0 on success */
static int send_fdpass(int sockd, const char *filename) {
    struct iovec iov[1];
    struct msghdr msg;
    struct cmsghdr *cmsg;
    unsigned char fdbuf[CMSG_SPACE(sizeof(int))];
    char dummy[]="";
    int fd;

    if(filename) {
	if(!(fd = open(filename, O_RDONLY))) {
	    logg("!Open failed on %s.\n", filename);
	    return 1;
	}
    } else fd = 0;
    if(sendln(sockd, "zFILDES", 8)) {
      close(fd);
      return 1;
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
	logg("!FD send failed\n");
	close(fd);
	return 1;
    }
    close(fd);
    return 0;
}
#endif

/* Sends a proper scan request to clamd and parses its replies
 * This is used only in non IDSESSION mode
 * Returns the number of infected files or -1 on error */
int dsresult(int sockd, int scantype, const char *filename) {
	int infected = 0, waserror = 0, len;
	char *bol, *eol;
	struct RCVLN rcv;

    recvlninit(&rcv, sockd);

    switch(scantype) {
    case MULTI:
    case CONT:
    len = strlen(filename) + strlen(scancmd[scantype]) + 3;
    if (!(bol = malloc(len))) {
	logg("!Cannot allocate a command buffer\n");
	return -1;
    }
    sprintf(bol, "z%s %s", scancmd[scantype], filename);
    if(sendln(sockd, bol, len)) return -1;
    free(bol);
    break;

    case STREAM:
	if(send_stream(sockd, filename))
	    return -1;

#ifdef HAVE_FD_PASSING
    case FILDES:
	if(send_fdpass(sockd, filename))
	    return -1;
	break;
#endif
    }

    while((len = recvln(&rcv, &bol, &eol))) {
	if(len == -1) {
	    waserror = 1;
	    break;
	}
	if(!filename) logg("~%s\n", bol);
	if(len > 7) {
	    char *colon = strrchr(bol, ':');
	    if(!colon) {
		logg("Failed to parse reply\n");
		waserror = 1;
	    } else if(!memcmp(eol - 7, " FOUND", 6)) {
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
		if(filename) {
		    if(scantype >= STREAM)
			logg("~%s%s\n", filename, colon);
		    else
			logg("~%s\n", bol);
		}
		waserror = 1;
	    }
	}
    }
    return infected ? infected : (waserror ? -1 : 0);
}



/* Used by serial_callback() */
struct client_serial_data {
    int infected;
    int errors;
    int scantype;
    int spam;
};

/* FTW callback for scanning in non IDSESSION mode */
static int serial_callback(struct stat *sb, char *filename, const char *path, enum cli_ftw_reason reason, struct cli_ftw_cbdata *data) {
    struct client_serial_data *c = (struct client_serial_data *)data->data;
    int sockd, ret;
    const char *f = filename;

    switch(reason) {
    case error_stat:
	logg("^Can't access file %s\n", filename);
	return CL_SUCCESS;
    case error_mem:
	logg("^Memory allocation failed in ftw\n");
	return CL_EMEM;
    case warning_skipped_dir:
	logg("^Directory recursion limit reached\n");
	return CL_SUCCESS;
    case warning_skipped_special:
	logg("~%s: Not supported file type. ERROR\n", filename);
	c->errors++;
	return CL_SUCCESS;
    case visit_directory_toplev:
	c->spam = 1;
	if(c->scantype >= STREAM)
	    return CL_SUCCESS;
	f = path;
    default:
	break;
    }

    if((sockd = dconnect()) < 0) {
	free(filename);
	return CL_BREAK;
    }
    if((ret = dsresult(sockd, c->scantype, f)) >= 0)
	c->infected += ret;
    else
	c->errors++;
    close(sockd);
    free(filename);
    if(reason == visit_directory_toplev)
	return CL_BREAK;
    return CL_SUCCESS;
}

/* Non-IDSESSION handler
 * FIXME: returns what ? */
int serial_client_scan(const char *file, int scantype, int *infected, int *errors, int maxlevel) {
    struct cli_ftw_cbdata data;
    struct client_serial_data cdata;

    cdata.infected = 0;
    cdata.errors = 0;
    cdata.scantype = scantype;
    cdata.spam = 0;
    data.data = &cdata;

    cli_ftw(file, CLI_FTW_STD, maxlevel ? maxlevel : INT_MAX, serial_callback, &data);
    /* FIXME: care about return ? */
    if(!cdata.infected && (!cdata.errors || cdata.spam)) logg("~%s: OK\n", file);

    *infected += cdata.infected;
    *errors += cdata.errors;
    return 0;
}

/* Used in IDSESSION mode */
struct client_parallel_data {
    int infected;
    int errors;
    int scantype;
    int spam;
    int sockd;
    int lastid;
    struct SCANID {
	unsigned int id;
	const char *file;
	struct SCANID *next;
    } *ids;
};

/* Sends a proper scan request to clamd and parses its replies
 * This is used only in IDSESSION mode
 * Returns 0 on success, 1 on hard failures */
int dspresult(struct client_parallel_data *c) {
    const char *filename;
    char *bol, *eol;
    unsigned int rid;
    int len;
    struct SCANID **id = NULL;
    struct RCVLN rcv;

    recvlninit(&rcv, c->sockd);
    do {
	len = recvln(&rcv, &bol, &eol);
	if(len == -1) {
	    c->errors++;
	    break;
	}
	if(!bol) return 0;
	if((rid = atoi(bol))) {
	    id = &c->ids;
	    while(*id) {
		if((*id)->id == rid) break;
		id = &((*id)->next);
	    }
	    if(!*id) id = NULL;
	}
	if(!id) {
	    c->errors++;
	    logg("!Bogus session id from clamd\n");
	    return 1; /* this is an hard failure */
	}
	filename = (*id)->file;
	if(len > 7) {
	    char *colon = strrchr(bol, ':');
	    if(!colon) {
		c->errors++;
		logg("Failed to parse reply\n");
	    } else if(!memcmp(eol - 7, " FOUND", 6)) {
		c->infected++;
		logg("~%s%s\n", filename, colon);
		if(action) action(filename);
	    } else if(!memcmp(eol-7, " ERROR", 6)) {
		c->errors++;
		if(filename)
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

/* FTW callback for scanning in IDSESSION mode */
static int parallel_callback(struct stat *sb, char *filename, const char *path, enum cli_ftw_reason reason, struct cli_ftw_cbdata *data) {
    struct client_parallel_data *c = (struct client_parallel_data *)data->data;
    struct SCANID **id = &c->ids, *cid;

    switch(reason) {
    case error_stat:
	logg("^Can't access file %s\n", filename);
	return CL_SUCCESS;
    case error_mem:
	logg("^Memory allocation failed in ftw\n");
	return CL_EMEM;
    case warning_skipped_dir:
	logg("^Directory recursion limit reached\n");
	return CL_SUCCESS;
    case warning_skipped_special:
	logg("~%s: Not supported file type. ERROR\n", filename);
	c->errors++;
	return CL_SUCCESS;
    case visit_directory_toplev:
	c->spam = 1;
	return CL_SUCCESS;
    default:
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
	    c->errors++;
	    free(filename);
	    logg("!select failed during session\n");
	    return CL_BREAK; /* this is an hard failure */
	}
	if(FD_ISSET(c->sockd, &rfds)) {
	    if(dspresult(c)) {
		free(filename);
		return CL_BREAK;
	    } else continue;
	}
	if(FD_ISSET(c->sockd, &wfds)) break;
    }

    while (*id)
	id = &((*id)->next);
    cid = (struct SCANID *)malloc(sizeof(struct SCANID *));
    *id = cid;
    cid->id = ++c->lastid;
    cid->file = filename;
    cid->next = NULL;

    switch(c->scantype) {
    case FILDES:
	send_fdpass(c->sockd, filename); /* FIXME: check return */
	break;
    case STREAM:
	send_stream(c->sockd, filename); /* FIXME: check return */
	break;
    }

    return CL_SUCCESS;
}

/* Non-IDSESSION handler
 * FIXME: returns what ? */
int parallel_client_scan(const char *file, int scantype, int *infected, int *errors, int maxlevel) {
    struct cli_ftw_cbdata data;
    struct client_parallel_data cdata;

    if((cdata.sockd = dconnect()) < 0)
	return 1;

    if(sendln(cdata.sockd, "zIDSESSION", 11)) {
	close(cdata.sockd);
	return 1;
    }

    cdata.infected = 0;
    cdata.errors = 0;
    cdata.scantype = scantype;
    cdata.spam = 0;
    cdata.lastid = 0;
    cdata.ids = NULL;
    data.data = &cdata;

    cli_ftw(file, CLI_FTW_STD, maxlevel ? maxlevel : INT_MAX, parallel_callback, &data);
    /* FIXME: check return */

    while(cdata.ids) {
	if(dspresult(&cdata)) { /* FIXME: return something */ }
    };

    sendln(cdata.sockd, "zEND", 5);
    close(cdata.sockd);

    if(!cdata.infected && (!cdata.errors || cdata.spam)) logg("~%s: OK\n", file);

    *infected += cdata.infected;
    *errors += cdata.errors;
    return 0;
}

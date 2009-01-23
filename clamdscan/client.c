/*
 *  Copyright (C) 2002 - 2007 Tomasz Kojm <tkojm@clamav.net>
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_LIMITS_H
#include <sys/limits.h>
#endif
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <utime.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#include "shared/optparser.h"
#include "shared/output.h"
#include "shared/misc.h"
#include "libclamav/str.h"

#include "client.h"

#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK 0x7f000001
#endif

int notremoved = 0, notmoved = 0;
int printinfected = 0;

static struct sockaddr *mainsa = NULL;
static int mainsasz;
static struct sockaddr_un nixsock;
static struct sockaddr_in tcpsock;
static struct sockaddr_in strmsock;
enum {
    CONT,
    MULTI,
    STREAM,
    FILDES
};

static const char *scancmd[] = { "CONTSCAN", "MULTISCAN", "STREAM", "FILDES" };

static void (*action)(const char *) = NULL;
static char *actarget;
static void move_infected(const char *filename, int move);
static void action_move(const char *filename) {
    move_infected(filename, 1);
}
static void action_copy(const char *filename) {
    move_infected(filename, 0);
}
static void action_remove(const char *filename) {
    if(unlink(filename)) {
	logg("!%s: Can't remove.\n", filename);
	notremoved++;
    } else {
	logg("~%s: Removed.\n", filename);
    }
}

void actsetup(const struct optstruct *opts) {
    if(optget(opts, "move")->enabled) {
	actarget = optget(opts, "move")->strarg;
	action = action_move;
    } else if (optget(opts, "copy")->enabled) {
	actarget = optget(opts, "copy")->strarg;
	action = action_copy;
    } else if(optget(opts, "remove")->enabled) {
	action = action_remove;
    }
}

static int sendln(int sockd, const char *line, unsigned int len) {
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

struct RCVLN {
    char buf[PATH_MAX+1024]; /* FIXME must match that in clamd - bb1349 */
    int sockd;
    int r;
    char *cur;
    char *bol;
};

static void recvlninit(struct RCVLN *s, int sockd) {
    s->sockd = sockd;
    s->bol = s->cur = s->buf;
    s->r = 0;
}

static int recvln(struct RCVLN *s, char **rbol, char **reol) {
    char *eol;
    int ret = 0;

    while(!ret) {
	if(!s->r) {
	    s->r = recv(s->sockd, s->cur, sizeof(s->buf) - (s->cur - s->buf), 0);
	    if(s->r<=0) {
		if(s->r && errno == EINTR) {
		    s->r = 0;
		    continue;
		}
		if(s->r || s->cur!=s->buf) {
		    logg("!Communication error\n");
		    ret = -1;
		}
	        break;
	    }
	}
	if(s->r && (eol = memchr(s->cur, 0, s->r))) {
	    eol++;
	    s->r -= eol - s->cur;
	    *rbol = s->bol;
	    if(reol) *reol = eol;
	    ret = eol - s->bol;
	    s->bol = s->cur = eol;
	}
	s->r += s->cur - s->bol;
	if(s->r==sizeof(s->buf)) {
	    logg("!Overlong reply from clamd\n");
	    ret = -1;
	    break;
	}
	if(s->r && s->bol!=s->buf) /* memmove is stupid in older glibc's */
	    memmove(s->buf, s->bol, s->r);
	s->cur = &s->buf[s->r];
	s->bol = s->buf;
	s->r = 0;
    }
    return ret;
}

static int dsresult(int sockd, int scantype, const char *filename)
{
	int infected = 0, waserror = 0, fd;
	int len;
	char *bol, *eol;
	char buf[BUFSIZ];    
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
	{
	    int wsockd;
	    
	    if(filename) {
		if(!(fd = open(filename, O_RDONLY))) {
		    logg("!Open failed on %s.\n", filename);
		return -1;
		}
	    } else fd = 0;
	    if(sendln(sockd, "zSTREAM", 8)) return -1;
	    if(!(len = recvln(&rcv, &bol, &eol)) || len < 7 || memcmp(bol, "PORT ", 5) || !(len = atoi(bol + 5))) return -1;
	    strmsock.sin_port = htons(len);
	    if((wsockd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket()");
		logg("!Can't create the stream socket.\n");
		close(fd);
		return -1;
	    }
	    if(connect(wsockd, (struct sockaddr *)&strmsock, sizeof(strmsock)) < 0) {
		perror("connect()");
		logg("!Can't connect to clamd for streaming.\n");
		close(wsockd);
		close(fd);
		return -1;
	    }
	    while((len = read(fd, buf, sizeof(buf))) > 0) {
		if(sendln(wsockd, buf, len)) { /* FIXME: conn might be closed unexpectedly due to limits */
		    logg("!Can't write to the socket.\n");
		    close(wsockd);
		    close(fd);
		    return -1;
		}
	    }
	    close(wsockd);
	    close(fd);
	    if(len) {
		logg("!Failed to read from %s.\n", filename);
		return -1;
	    }
	    break;
	}
#ifdef HAVE_FD_PASSING
    case FILDES:
	{
	    struct iovec iov[1];
	    struct msghdr msg;
	    struct cmsghdr *cmsg;
	    unsigned char fdbuf[CMSG_SPACE(sizeof(int))];
	    char dummy[]="";

	    if(filename) {
		if(!(fd = open(filename, O_RDONLY))) {
		    logg("!Open failed on %s.\n", filename);
		    return -1;
		}
	    } else fd = 0;
	    if(sendln(sockd, "zFILDES", 8)) return -1;

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
		return -1;
	    }
	    break;
	}
#endif
    }

    while((len = recvln(&rcv, &bol, &eol))) {
	if(len == -1) {
	    waserror = 1;
	    break;
	}
	logg("~%s\n", bol); /* FIXME: only good for CONT/MULTI */
	if(len > 7) {
	    if(!memcmp(eol - 7, " FOUND", 6)) {
		infected++;
		if(action) {
		    if(scantype >= STREAM) {
			action(filename);
		    } else {
			char *comma = strrchr(bol, ':');
			if(comma) {
			    *comma = '\0';
			    action(bol);
			}
		    }
		}
	    } else if(!memcmp(eol-7, " ERROR", 6)) {
		waserror = 1;
	    }
	}
    }
    return infected ? infected : (waserror ? -1 : 0);
}


#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

static int dconnect()
{
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

static int isremote(const struct optstruct *opts) {
    int s, ret;
    const struct optstruct *opt;
    struct hostent *he;
    struct optstruct *clamdopts;
    const char *clamd_conf = optget(opts, "config-file")->strarg;

    if((clamdopts = optparse(clamd_conf, 0, NULL, 1, OPT_CLAMD, 0, NULL)) == NULL) {
	logg("!Can't parse clamd configuration file %s\n", clamd_conf);
	return 0;
    }
    if(optget(clamdopts, "LocalSocket")->enabled) {
	memset((void *)&nixsock, 0, sizeof(nixsock));
	nixsock.sun_family = AF_UNIX;
	strncpy(nixsock.sun_path, opt->strarg, sizeof(nixsock.sun_path));
	nixsock.sun_path[sizeof(nixsock.sun_path)-1]='\0';
	mainsa = (struct sockaddr *)&nixsock;
	mainsasz = sizeof(nixsock);
	strmsock.sin_family = AF_INET;
	strmsock.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	optfree(clamdopts);
	return 0;
    }
    if(!(opt = optget(clamdopts, "TCPSocket"))->enabled) {
	optfree(clamdopts);
	return 0;
    }
    mainsa = (struct sockaddr *)&tcpsock;
    mainsasz = sizeof(tcpsock);
    memset((void *)&tcpsock, 0, sizeof(tcpsock));
    memset((void *)&strmsock, 0, sizeof(strmsock));
    tcpsock.sin_family = strmsock.sin_family = AF_INET;
    tcpsock.sin_port = htons(opt->numarg);
    if(!(opt = optget(clamdopts, "TCPAddr"))->enabled) {
	tcpsock.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	optfree(clamdopts);
	return 0;
    }
    he = gethostbyname(opt->strarg);
    optfree(clamdopts);
    if(!he) {
	perror("gethostbyname()");
	logg("!Can't lookup clamd hostname.\n");
	mainsa = NULL;
	return 0;
    }
    strmsock.sin_port = htons(INADDR_ANY);
    tcpsock.sin_addr = strmsock.sin_addr = *(struct in_addr *) he->h_addr_list[0];
    if(!(s = socket(tcpsock.sin_family, SOCK_STREAM, 0))) return 0;
    ret = (bind(s, (struct sockaddr *)&strmsock, sizeof(strmsock)) != 0);
    close(s);
    return ret;
}

static int client_scan(const char *file, int scantype, int *infected, int *errors) {
    struct stat sb;
    char *fullpath;
    DIR *dir;
    struct dirent *dent;
    int ret, sockd;

    if(stat(file, &sb) == -1) {
	logg("^Can't access file %s\n", file);
	perror(file);
	(*errors)++;
	return 0;
    }
    if(!(fullpath = malloc(PATH_MAX + 1))) {
	logg("^Can't make room for fullpath.\n");
	(*errors)++;
	return 0;
    }

    if(*file != '/') { /* FIXME: to be unified */
	int namelen;
	if(!getcwd(fullpath, PATH_MAX)) {
	    logg("^Can't get absolute pathname of current working directory.\n");
	    free(fullpath);
	    (*errors)++;
	    return 0;
	}
	namelen = strlen(fullpath);
	snprintf(&fullpath[namelen], PATH_MAX - namelen, "/%s", file);
    } else {
	strncpy(fullpath, file, PATH_MAX);
    }
    fullpath[PATH_MAX] = '\0';

    switch(sb.st_mode & S_IFMT) {
    case S_IFDIR:
	if(scantype >= STREAM) {
	    if(!(dir = opendir(file)))
		break;
	    ret = strlen(fullpath);
	    while((dent = readdir(dir))) {
		if(!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, "..")) continue;
		snprintf(&fullpath[ret], PATH_MAX - ret, "/%s", dent->d_name);
		fullpath[PATH_MAX] = '\0';
		if(client_scan(fullpath, scantype, infected, errors)) {
		    closedir(dir);
		    free(fullpath);
		    return 1;
		}
	    }
	    closedir(dir);
	    break;
	}

    case S_IFREG:
	if((sockd = dconnect()) < 0)
	    return 1;
	if((ret = dsresult(sockd, scantype, fullpath)) >= 0)
	    *infected += ret;
	else
	    (*errors)++;
	close(sockd);
	break;

    default:
	logg("^Not supported file type (%s)\n", fullpath);
	errors++;
    }

    free(fullpath);
    return 0;
}

int get_clamd_version(const struct optstruct *opts)
{
	char *buff;
	int len, sockd;
	struct RCVLN rcv;

    isremote(opts);
    if(!mainsa) return 2;
    if((sockd = dconnect()) < 0) return 2;
    recvlninit(&rcv, sockd);

    if(sendln(sockd, "zVERSION", 9)) {
	logg("!Can't write to the socket.\n");
	close(sockd);
	return 2;
    }

    while((len = recvln(&rcv, &buff, NULL))) {
	if(len == -1) {
	    logg("!Error occoured while receiving version information.\n");
	    break;
	}
	printf("%s\n", buff);
    }

    close(sockd);
    return 0;
}

int reload_clamd_database(const struct optstruct *opts)
{
	char *buff;
	int len, sockd;
	struct RCVLN rcv;

    isremote(opts);
    if(!mainsa) return 2;
    if((sockd = dconnect()) < 0) return 2;
    recvlninit(&rcv, sockd);

    if(sendln(sockd, "zRELOAD", 8)) {
	logg("!Can't write to the socket.\n");
	close(sockd);
	return 2;
    }

    if(!(len = recvln(&rcv, &buff, NULL)) || len < 10 || memcmp(buff, "RELOADING", 9)) {
	logg("!Incorrect reply from clamd\n");
	close(sockd);
	return 2;
    }

    close(sockd);
    return 0;
}

int client(const struct optstruct *opts, int *infected)
{
	const char *clamd_conf = optget(opts, "config-file")->strarg;
	struct optstruct *clamdopts;
	int remote, scantype, session = 0, errors = 0, scandash = 0;

    if((clamdopts = optparse(clamd_conf, 0, NULL, 1, OPT_CLAMD, 0, NULL)) == NULL) {
	logg("!Can't parse clamd configuration file %s\n", clamd_conf);
	return 2;
    }

    scandash = (opts->filename && opts->filename[0] && !strcmp(opts->filename[0], "-") && !opts->filename[1]);
    remote = isremote(opts);
#ifdef HAVE_FD_PASSING
    if(!remote && optget(clamdopts, "LocalSocket")->enabled && (optget(opts, "fdpass")->enabled || scandash)) {
	scantype = FILDES;
	session = optget(opts, "multiscan")->enabled;
	scandash <<= 1;
    } else 
#endif
    if(remote || scandash) {
	scantype = STREAM;
	session = optget(opts, "multiscan")->enabled;
	scandash <<=1;
    } else if(optget(opts, "multiscan")->enabled) scantype = MULTI;
    else scantype = CONT;

    optfree(clamdopts);

    if(!mainsa) {
	logg("!Clamd is not configured properly.\n");
	return 2;
    }

    *infected = 0;

    if(scandash) {
	int sockd, ret;
	if((sockd = dconnect()) >= 0 && (ret = dsresult(sockd, scantype, NULL)) >= 0)
	    *infected += ret;
	else
	    errors++;
	close(sockd);
    } else if(opts->filename) {
	unsigned int i;
	for (i = 0; opts->filename[i]; i++) {
	    if(!strcmp(opts->filename[i], "-")) {
		logg("!Scanning from standard input requires \"-\" to be the only file argument\n");
		continue;
	    }
	    client_scan(opts->filename[i], scantype, infected, &errors);
	}
    } else {
	char cwd[PATH_MAX+1];
	if(!getcwd(cwd, PATH_MAX)) {
	    logg("^Can't get absolute pathname of current working directory.\n");
	    return 2;
	}
	client_scan(cwd, scantype, infected, &errors);
    }
    return *infected ? 1 : (errors ? 2 : 0);
}

void move_infected(const char *filename, int move)
{
	char *movefilename, numext[4 + 1];
	const char *tmp;
	struct stat ofstat, mfstat;
	int n, len, movefilename_size;
	struct utimbuf ubuf;

    if(access(actarget, W_OK|X_OK) == -1) {
        logg("!problem %s file '%s': cannot write to '%s': %s\n", (move) ? "moving" : "copying", filename, actarget, strerror(errno));
        notmoved++;
        return;
    }

    if(stat(filename, &ofstat) == -1) {
        logg("^Can't stat file %s\n", filename);
	logg("Try to run clamdscan with clamd privileges\n");
        notmoved++;
	return;
    }

    if(!(tmp = strrchr(filename, '/')))
	tmp = filename;

    movefilename_size = sizeof(char) * (strlen(actarget) + strlen(tmp) + sizeof(numext) + 2);

    if(!(movefilename = malloc(movefilename_size))) {
        logg("!Memory allocation error\n");
	exit(2);
    }

    if(!(cli_strrcpy(movefilename, actarget))) {
        logg("!cli_strrcpy() returned NULL\n");
        notmoved++;
        free(movefilename);
        return;
    }

    strcat(movefilename, "/");

    if(!(strcat(movefilename, tmp))) {
        logg("!strcat() returned NULL\n");
        notmoved++;
        free(movefilename);
        return;
    }

    if(!stat(movefilename, &mfstat)) {
        if((ofstat.st_dev == mfstat.st_dev) && (ofstat.st_ino == mfstat.st_ino)) { /* It's the same file */
            logg("File excluded '%s'\n", filename);
            notmoved++;
            free(movefilename);
            return;
        } else {
            /* file exists - try to append an ordinal number to the
	     * quranatined file in an attempt not to overwrite existing
	     * files in quarantine  
	     */
            len = strlen(movefilename);
            n = 0;        		        		
            do {
                /* reset the movefilename to it's initial value by
		 * truncating to the original filename length
		 */
                movefilename[len] = 0;
                /* append .XXX */
                sprintf(numext, ".%03d", n++);
                strcat(movefilename, numext);            	
            } while(!stat(movefilename, &mfstat) && (n < 1000));
       }
    }

    if(!move || rename(filename, movefilename) == -1) {
	if(filecopy(filename, movefilename) == -1) {
	    logg("^cannot %s '%s' to '%s': %s\n", (move) ? "move" : "copy", filename, movefilename, strerror(errno));
	    notmoved++;
	    free(movefilename);
	    return;
	}

	chmod(movefilename, ofstat.st_mode);
	if(chown(movefilename, ofstat.st_uid, ofstat.st_gid) == -1)
	    logg("^chown() failed for %s: %s\n", movefilename, strerror(errno));

	ubuf.actime = ofstat.st_atime;
	ubuf.modtime = ofstat.st_mtime;
	utime(movefilename, &ubuf);

	if(move && unlink(filename)) {
	    logg("^cannot unlink '%s': %s\n", filename, strerror(errno));
	    notremoved++;
	    free(movefilename);
	    return;
	}
    }

    logg("%s: %s to '%s'\n", (move)?"moved":"copied", filename, movefilename);

    free(movefilename);
}

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


#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#include "shared/optparser.h"
#include "shared/output.h"
#include "shared/misc.h"
#include "libclamav/str.h"

#include "client.h"
#include "clamd_fdscan.h"

#define SOCKET_INET	AF_INET

int notremoved = 0, notmoved = 0;
int printinfected = 0;

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
    }
    return ret;
}

static int dsresult(int sockd, const char *scantype, const char *filename)
{
	int infected = 0, waserror = 0;
	int len;
	char *bol, *eol;
	struct RCVLN rcv;

    len = strlen(filename) + strlen(scantype) + 3;
    if (!(bol = malloc(len))) {
	logg("!Cannot allocate a command buffer\n");
	return -1;
    }
    sprintf(bol, "z%s %s", scantype, filename);
    if(sendln(sockd, bol, len)) return -1;
    free(bol);

    recvlninit(&rcv, sockd);
    while((len = recvln(&rcv, &bol, &eol))) {
	if(len == -1) {
	    waserror = 1;
	    break;
	}
	logg("~%s\n", bol);
	if(len > 7) {
	    if(!memcmp(eol - 7, " FOUND", 6)) {
		infected++;
		if(action) {
		    char *comma = strrchr(bol, ':');
		    if(comma) {
			*comma = '\0';
			action(bol);
		    }
		}
	    } else if(!memcmp(eol-7, " ERROR", 6)) {
		waserror = 1;
	    }
	}
    }
    return infected ? infected : (waserror ? -1 : 0);
}

static int dsstream(int sockd)
{
	int wsockd, bread, port, infected = 0;
	struct sockaddr_in server;
	struct sockaddr_in peer;
	socklen_t peer_size;
	struct RCVLN rcv;
	char buff[4096], *pt;


    if(sendln(sockd, "zSTREAM", 8)) return 2;
    recvlninit(&rcv, sockd);
    bread = recvln(&rcv, &pt, NULL);
    if(bread < 7 || memcmp(pt, "PORT ", 5) || (port = atoi(&pt[5])) == 0) {
	logg("!Daemon not ready for stream scanning.\n");
	return -1;
    }

    /* connect to clamd */

    if((wsockd = socket(SOCKET_INET, SOCK_STREAM, 0)) < 0) {
	perror("socket()");
	logg("!Can't create the socket.\n");
	return -1;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    peer_size = sizeof(peer);
    if(getpeername(sockd, (struct sockaddr *) &peer, &peer_size) < 0) {
	perror("getpeername()");
	logg("!Can't get socket peer name.\n");
	return -1;
    }

    switch (peer.sin_family) {
	case AF_UNIX:
	    server.sin_addr.s_addr = inet_addr("127.0.0.1");
	    break;
	case AF_INET:
	    server.sin_addr.s_addr = peer.sin_addr.s_addr;
	    break;
	default:
	    logg("!Unexpected socket type: %d.\n", peer.sin_family);
	    return -1;
    }

    if(connect(wsockd, (struct sockaddr *) &server, sizeof(struct sockaddr_in)) < 0) {
	close(wsockd);
	perror("connect()");
	logg("!Can't connect to clamd [port: %d].\n", port);
	return -1;
    }

    while((bread = read(0, buff, sizeof(buff))) > 0) { /* FIXME: this is stdin only, not nice */
	if(sendln(wsockd, buff, bread)) {
	    /* FIXME: we may just be overlimit here */
	    logg("!Can't write to the socket.\n");
	    close(wsockd);
	    return -1;
	}
    }
    close(wsockd);

    bread = recvln(&rcv, &pt, NULL);
    /*    logg("~%s\n", bol); *//* FIXME: btw this is useless spam */

    /* HERE */

    memset(buff, 0, sizeof(buff));

    while((bread = read(sockd, buff, sizeof(buff))) > 0) {
	logg("%s", buff);
	if(strstr(buff, "FOUND\n")) {
	    infected++;

	} else if(strstr(buff, "ERROR\n")) {
	    logg("%s", buff);
	    return -1;
	}
	memset(buff, 0, sizeof(buff));
    }

    return infected;
}

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

static char *abpath(const char *filename)
{
	struct stat foo;
	char *fullpath, cwd[PATH_MAX + 1];

    if(stat(filename, &foo) == -1) {
	logg("^Can't access file %s\n", filename);
	perror(filename);
	return NULL;
    } else {
	fullpath = malloc(PATH_MAX + strlen(filename) + 10);
	if(!getcwd(cwd, PATH_MAX)) {
	    logg("^Can't get absolute pathname of current working directory.\n");
	    return NULL;
	}
	sprintf(fullpath, "%s/%s", cwd, filename);
    }

    return fullpath;
}

static int dconnect(const struct optstruct *opts, int *is_unix)
{
	struct sockaddr_un server;
	struct sockaddr_in server2;
	struct hostent *he;
	struct optstruct *clamdopts;
	const struct optstruct *opt;
	const char *clamd_conf = optget(opts, "config-file")->strarg;
	int sockd;

    if(is_unix)
	*is_unix = 0;

    if((clamdopts = optparse(clamd_conf, 0, NULL, 1, OPT_CLAMD, 0, NULL)) == NULL) {
	logg("!Can't parse clamd configuration file %s\n", clamd_conf);
	return -1;
    }

    memset((char *) &server, 0, sizeof(server));
    memset((char *) &server2, 0, sizeof(server2));

    /* Set default address to connect to */
    server2.sin_addr.s_addr = inet_addr("127.0.0.1");    

    if((opt = optget(clamdopts, "LocalSocket"))->enabled) {

	server.sun_family = AF_UNIX;
	strncpy(server.sun_path, opt->strarg, sizeof(server.sun_path));
	server.sun_path[sizeof(server.sun_path)-1]='\0';

	if((sockd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
	    perror("socket()");
	    logg("!Can't create the socket.\n");
	    optfree(clamdopts);
	    return -1;
	}

	if(connect(sockd, (struct sockaddr *) &server, sizeof(struct sockaddr_un)) < 0) {
	    close(sockd);
	    perror("connect()");
	    logg("!Can't connect to clamd.\n");
	    optfree(clamdopts);
	    return -1;
	}
	if(is_unix)
		*is_unix = 1;
    } else if((opt = optget(clamdopts, "TCPSocket"))->enabled) {

	if((sockd = socket(SOCKET_INET, SOCK_STREAM, 0)) < 0) {
	    perror("socket()");
	    logg("!Can't create the socket.\n");
	    optfree(clamdopts);
	    return -1;
	}

	server2.sin_family = AF_INET;
	server2.sin_port = htons(opt->numarg);

	if((opt = optget(clamdopts, "TCPAddr"))->enabled) {
	    if ((he = gethostbyname(opt->strarg)) == 0) {
		close(sockd);
		perror("gethostbyname()");
		logg("!Can't lookup clamd hostname.\n");
		optfree(clamdopts);
		return -1;
	    }
	    server2.sin_addr = *(struct in_addr *) he->h_addr_list[0];
	}

	if(connect(sockd, (struct sockaddr *) &server2, sizeof(struct sockaddr_in)) < 0) {
	    close(sockd);
	    perror("connect()");
	    logg("!Can't connect to clamd.\n");
	    optfree(clamdopts);
	    return -1;
	}

    } else {
	logg("!Clamd is not configured properly.\n");
	optfree(clamdopts);
	return -1;
    }

    optfree(clamdopts);

    return sockd;
}

int get_clamd_version(const struct optstruct *opts)
{
	char buff[64];
	int bread, sockd;


    if((sockd = dconnect(opts, NULL)) < 0)
	return 2;

    if(write(sockd, "VERSION", 7) <= 0) {
	logg("!Can't write to the socket.\n");
	close(sockd);
	return 2;
    }

    while((bread = read(sockd, buff, sizeof(buff)-1)) > 0) {
	buff[bread] = '\0';
	printf("%s\n", buff);
    }

    close(sockd);
    return 0;
}

int reload_clamd_database(const struct optstruct *opts)
{
	char buff[64];
	int bread, sockd;


    if((sockd = dconnect(opts, NULL)) < 0)
	return 2;

    if(write(sockd, "RELOAD", 6) <= 0) {
	logg("!Can't write to the socket.\n");
	close(sockd);
	return 2;
    }

    bread = read(sockd, buff, sizeof(buff) - 1);
    if(bread == -1 || strncmp(buff, "RELOADING", 9)) {
	logg("!Incorrect reply from clamd\n");
	close(sockd);
	return 2;
    }

    close(sockd);
    return 0;
}

static int client_scan(const char *file, const char *scantype, int *infected, int *errors, const struct optstruct *opts) {
    struct stat sb;
    char *fullpath;
    DIR *dir;
    struct dirent *dent;
    int ret, sockd;

    /* BUF 
       basename/thisname/child */

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

    /* FIXME: i should break out ASAP here for SCAN, continue for MULTISCAN, CONTSCAN */
    switch(sb.st_mode & S_IFMT) {
    case S_IFDIR:
	/* FIXME: if (remote) { */
	if(!(dir = opendir(file)))
	    break;
	ret = strlen(fullpath);
	while((dent = readdir(dir))) {
	    if(!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, "..")) continue;
	    snprintf(&fullpath[ret], PATH_MAX - ret, "/%s", dent->d_name);
	    fullpath[PATH_MAX] = '\0';
	    if(client_scan(fullpath, scantype, infected, errors, opts)) {
		closedir(dir);
		free(fullpath);
		return 1;
	    }
	}
	closedir(dir);
	break;
	/* } else fallback to S_IFREG for external recursion */

    case S_IFREG:
	if((sockd = dconnect(opts, NULL)) < 0)
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

int client(const struct optstruct *opts, int *infected)
{
	char cwd[PATH_MAX+1], *fullpath;
	int sockd, ret, errors = 0;
	struct stat sb;
	const char *scantype = "CONTSCAN";


    *infected = 0;

    if(optget(opts, "multiscan")->enabled)
	scantype = "MULTISCAN";
    client_scan(opts->filename, scantype, infected, &errors, opts);
    return 0; /* FIXME */


    /* parse argument list */
    if(opts->filename == NULL) {
	/* scan current directory */
	if(!getcwd(cwd, PATH_MAX)) {
	    logg("^Can't get absolute pathname of current working directory.\n");
	    return 2;
	}

	if((sockd = dconnect(opts, NULL)) < 0)
	    return 2;

	if((ret = dsresult(sockd, scantype, cwd)) >= 0)
	    *infected += ret;
	else
	    errors++;

	close(sockd);

    } else if(!strcmp(opts->filename[0], "-")) { /* scan data from stdin */
        int is_unix;
	if((sockd = dconnect(opts, &is_unix)) < 0)
	    return 2;

	if(optget(opts,"fdpass")->enabled) {
#ifndef HAVE_FD_PASSING
		logg("^File descriptor pass support not compiled in, falling back to stream scan\n");
		ret = dsstream(sockd);
#else
		if(!is_unix) {
			logg("^File descriptor passing can only work on local (unix) sockets! Falling back to stream scan\n");
			/* fall back to stream */
			ret = dsstream(sockd);
		} else {
			char buff[4096];
			memset(buff, 0, sizeof(buff));
			ret = clamd_fdscan(sockd, 0, buff, sizeof(buff));
			if(ret == 1 || ret == -1)
			    logg("fd: %s%s\n",buff, ret == 1 ? " FOUND" : " ERROR");
			else if(!printinfected)
			    logg("fd: OK\n");
		}
#endif
	} else
		ret = dsstream(sockd);
	if(ret >= 0)
	    *infected += ret;
	else
	    errors++;

	close(sockd);

    } else {
	int x;
	for (x = 0; opts->filename[x] && (fullpath = strdup(opts->filename[x])); x++) {
	    if(stat(fullpath, &sb) == -1) {
		logg("^Can't access file %s\n", fullpath);
		perror(fullpath);
		errors++;
	    } else {
		if(strcmp(fullpath, "/") && (strlen(fullpath) < 2 || (fullpath[0] != '/' && fullpath[0] != '\\' && fullpath[1] != ':'))) {
		    char *pt = abpath(fullpath);
		    free(fullpath);
		    fullpath = pt;
		    if(!fullpath) {
			logg("^Can't determine absolute path.\n");
			return 2;
		    }
		}

		switch(sb.st_mode & S_IFMT) {
		    case S_IFREG:
		    case S_IFDIR:
			if((sockd = dconnect(opts, NULL)) < 0)
			    return 2;

			if((ret = dsresult(sockd, scantype, fullpath)) >= 0)
			    *infected += ret;
			else
			    errors++;

			close(sockd);
			break;

		    default:
			logg("^Not supported file type (%s)\n", fullpath);
			errors++;
		}
	    }
	    free(fullpath);
	}
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

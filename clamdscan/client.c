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
#include <sys/select.h>
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
#include "libclamav/others.h"

#include "client.h"
#include "proto.h"

#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK 0x7f000001
#endif

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

int notremoved = 0, notmoved = 0;
struct sockaddr *mainsa = NULL;
int mainsasz;
static struct sockaddr_un nixsock;
static struct sockaddr_in tcpsock;

/* OnInfected action handlers/wrappers */
void (*action)(const char *) = NULL;
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

/* Inits the OnInfected action */
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

/* Inits the communication layer
 * Returns 0 if clamd is local, non zero if clamd is remote */
static int isremote(const struct optstruct *opts) {
    int s, ret;
    const struct optstruct *opt;
    struct hostent *he;
    struct optstruct *clamdopts;
    const char *clamd_conf = optget(opts, "config-file")->strarg;
    static struct sockaddr_in testsock;

    if((clamdopts = optparse(clamd_conf, 0, NULL, 1, OPT_CLAMD, 0, NULL)) == NULL) {
	logg("!Can't parse clamd configuration file %s\n", clamd_conf);
	return 0;
    }
    if((opt = optget(clamdopts, "LocalSocket"))->enabled) {
	memset((void *)&nixsock, 0, sizeof(nixsock));
	nixsock.sun_family = AF_UNIX;
	strncpy(nixsock.sun_path, opt->strarg, sizeof(nixsock.sun_path));
	nixsock.sun_path[sizeof(nixsock.sun_path)-1]='\0';
	mainsa = (struct sockaddr *)&nixsock;
	mainsasz = sizeof(nixsock);
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
    tcpsock.sin_family = AF_INET;
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
    tcpsock.sin_addr = *(struct in_addr *) he->h_addr_list[0];
    memcpy((void *)&testsock, (void *)&tcpsock, sizeof(testsock));
    testsock.sin_port = htons(INADDR_ANY);
    if(!(s = socket(testsock.sin_family, SOCK_STREAM, 0))) return 0;
    ret = (bind(s, (struct sockaddr *)&testsock, sizeof(testsock)) != 0);
    close(s);
    return ret;
}


/* Turns a relative path into an absolute one
 * Returns a pointer to the path (which must be 
 * freed by the caller) or NULL on error */
static char *makeabs(const char *basepath) {
    int namelen;
    char *ret;

    if(!(ret = malloc(PATH_MAX + 1))) {
	logg("^Can't make room for fullpath.\n");
	return NULL;
    }
    if(*basepath != '/') { /* FIXME: to be unified */
	if(!getcwd(ret, PATH_MAX)) {
	    logg("^Can't get absolute pathname of current working directory.\n");
	    free(ret);
	    return NULL;
	}
	namelen = strlen(ret);
	snprintf(&ret[namelen], PATH_MAX - namelen, "/%s", basepath);
    } else {
	strncpy(ret, basepath, PATH_MAX);
    }
    ret[PATH_MAX] = '\0';
    return ret;
}

/* Recursively scans a path with the given scantype
 * Returns non zero for serious errors, zero otherwise */
static int client_scan(const char *file, int scantype, int *infected, int *errors, int maxlevel, int session) {
    int ret;
    char *fullpath = makeabs(file);

    if(!fullpath)
	return 0;
    if (!session)
	ret = serial_client_scan(fullpath, scantype, infected, errors, maxlevel);
    else
	ret = parallel_client_scan(fullpath, scantype, infected, errors, maxlevel);
    free(fullpath);
    return ret;
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
	close(sockd);
	return 2;
    }

    if(!(len = recvln(&rcv, &buff, NULL)) || len < 10 || memcmp(buff, "RELOADING", 9)) {
	logg("!Clamd did not reload the database\n");
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
	int remote, scantype, session = 0, errors = 0, scandash = 0, maxrec;

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
    } else 
#endif
    if(remote || scandash) {
	scantype = STREAM;
	session = optget(opts, "multiscan")->enabled;
    } else if(optget(opts, "multiscan")->enabled) scantype = MULTI;
    else scantype = CONT;

    maxrec = optget(clamdopts, "MaxDirectoryRecursion")->numarg;
    optfree(clamdopts);

    if(!mainsa) {
	logg("!Clamd is not configured properly.\n");
	return 2;
    }

    *infected = 0;

    if(scandash) {
	int sockd, ret;
	struct stat sb;
	fstat(0, &sb);
	if((sb.st_mode & S_IFMT) != S_IFREG) scantype = STREAM;
	if((sockd = dconnect()) >= 0 && (ret = dsresult(sockd, scantype, NULL)) >= 0)
	    *infected = ret;
	else
	    errors++;
	if(sockd >= 0) close(sockd);
    } else if(opts->filename) {
	unsigned int i;
	for (i = 0; opts->filename[i]; i++) {
	    if(!strcmp(opts->filename[i], "-")) {
		logg("!Scanning from standard input requires \"-\" to be the only file argument\n");
		continue;
	    }
	    if(client_scan(opts->filename[i], scantype, infected, &errors, maxrec, session)) break;
	}
    } else {
	client_scan("", scantype, infected, &errors, maxrec, session);
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

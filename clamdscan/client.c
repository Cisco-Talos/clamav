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
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif
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
#include "shared/actions.h"
#include "libclamav/str.h"
#include "libclamav/others.h"

#include "client.h"
#include "proto.h"

#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK 0x7f000001
#endif

struct sockaddr *mainsa = NULL;
int mainsasz;
unsigned long int maxstream;
static struct sockaddr_un nixsock;
static struct sockaddr_in tcpsock;


/* Inits the communication layer
 * Returns 0 if clamd is local, non zero if clamd is remote */
static int isremote(const struct optstruct *opts) {
    int s, ret;
    const struct optstruct *opt;
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

    if (cfg_tcpsock(clamdopts, &tcpsock, INADDR_LOOPBACK) == -1) {
	logg("!Can't lookup clamd hostname: %s.\n", strerror(errno));
	optfree(clamdopts);
	mainsa = NULL;
	return 0;
    }
    optfree(clamdopts);
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
static int client_scan(const char *file, int scantype, int *infected, int maxlevel, int session, int flags) {
    int ret;
    char *fullpath = makeabs(file);

    if(!fullpath)
	return 0;
    if (!session)
	ret = serial_client_scan(fullpath, scantype, infected, maxlevel, flags);
    else
	ret = parallel_client_scan(fullpath, scantype, infected, maxlevel, flags);
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
	int remote, scantype, session = 0, errors = 0, scandash = 0, maxrec, flags = 0;
	const char *fname;

    if((clamdopts = optparse(clamd_conf, 0, NULL, 1, OPT_CLAMD, 0, NULL)) == NULL) {
	logg("!Can't parse clamd configuration file %s\n", clamd_conf);
	return 2;
    }

    scandash = (opts->filename && opts->filename[0] && !strcmp(opts->filename[0], "-") && !optget(opts, "file-list")->enabled && !opts->filename[1]);
    remote = isremote(opts) | optget(opts, "stream")->enabled;
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
    maxstream = optget(clamdopts, "StreamMaxLength")->numarg;
    if (optget(clamdopts, "FollowDirectorySymlinks")->enabled)
	flags |= CLI_FTW_FOLLOW_DIR_SYMLINK;
    if (optget(clamdopts, "FollowFileSymlinks")->enabled)
	flags |= CLI_FTW_FOLLOW_FILE_SYMLINK;
    flags |= CLI_FTW_TRIM_SLASHES;
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
	if((sockd = dconnect()) >= 0 && (ret = dsresult(sockd, scantype, NULL, &ret)) >= 0)
	    *infected = ret;
	else
	    errors = 1;
	if(sockd >= 0) close(sockd);
    } else if(opts->filename || optget(opts, "file-list")->enabled) {
	if(opts->filename && optget(opts, "file-list")->enabled)
	    logg("^Only scanning files from --file-list (files passed at cmdline are ignored)\n");

	while(!errors && (fname = filelist(opts, NULL))) {
	    if(!strcmp(fname, "-")) {
		logg("!Scanning from standard input requires \"-\" to be the only file argument\n");
		continue;
	    }
	    errors = client_scan(fname, scantype, infected, maxrec, session, flags);
	}
    } else {
	errors = client_scan("", scantype, infected, maxrec, session, flags);
    }
    return *infected ? 1 : (errors ? 2 : 0);
}

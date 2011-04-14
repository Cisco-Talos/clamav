/*
 *  Copyright (C) 2007-2009 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm
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
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifndef _WIN32
#include <sys/socket.h>
#endif
#include <dirent.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>

#include "shared/optparser.h"
#include "shared/output.h"

#include "libclamav/clamav.h"
#include "libclamav/cvd.h"
#include "libclamav/others.h" /* for cli_rmdirs() */
#include "libclamav/regex/regex.h"
#include "libclamav/version.h"
#include "shared/misc.h"

#ifndef REPO_VERSION
#define REPO_VERSION "exported"
#endif

const char *get_version(void)
{
	if(!strncmp("devel-",VERSION,6) && strcmp("exported",REPO_VERSION)) {
		return REPO_VERSION""VERSION_SUFFIX;
	}
	/* it is a release, or we have nothing better */
	return VERSION""VERSION_SUFFIX;
}
const char *filelist(const struct optstruct *opts, int *err)
{
	static char buff[1025];
	static unsigned int cnt = 0;
	const struct optstruct *opt;
	static FILE *fs = NULL;
	size_t len;

    if(!cnt && (opt = optget(opts, "file-list"))->enabled) {
	if(!fs) {
	    fs = fopen(opt->strarg, "r");
	    if(!fs) {
		fprintf(stderr, "ERROR: --file-list: Can't open file %s\n", opt->strarg);
		if(err)
		    *err = 54;
		return NULL;
	    }
	}

	if(fgets(buff, 1024, fs)) {
	    buff[1024] = 0;
	    len = strlen(buff);
	    if(!len) {
		fclose(fs);
		return NULL;
	    }
	    len--;
	    while(len && ((buff[len] == '\n') || (buff[len] == '\r')))
		buff[len--] = '\0';
	    return buff;
	} else {
	    fclose(fs);
	    return NULL;
	}
    }

    return opts->filename ? opts->filename[cnt++] : NULL;
}

int filecopy(const char *src, const char *dest)
{
#ifdef _WIN32
    return (!CopyFileA(src, dest, 0));
#elif defined(C_DARWIN)
	pid_t pid;

    /* On Mac OS X use ditto and copy resource fork, too. */
    switch(pid = fork()) {
	case -1:
	    return -1;
	case 0:
	    execl("/usr/bin/ditto", "ditto", src, dest, NULL);
	    perror("execl(ditto)");
	    break;
	default:
	    wait(NULL);
	    return 0;
    }

    return -1;

#else /* C_DARWIN */
    return cli_filecopy(src, dest);
#endif
}

int daemonize(void)
{
#ifdef _WIN32
    fputs("Background mode is not supported on your operating system\n", stderr);
    return -1;
#else
	int fds[3], i;
	pid_t pid;


    fds[0] = open("/dev/null", O_RDONLY);
    fds[1] = open("/dev/null", O_WRONLY);
    fds[2] = open("/dev/null", O_WRONLY);
    if(fds[0] == -1 || fds[1] == -1 || fds[2] == -1) {
	fputs("Can't open /dev/null\n", stderr);
	for(i = 0; i <= 2; i++)
	    if(fds[i] != -1)
		close(fds[i]);
	return -1;
    }

    for(i = 0; i <= 2; i++) {
	if(dup2(fds[i], i) == -1) {
	    fprintf(stderr, "dup2(%d, %d) failed\n", fds[i], i); /* may not be printed */
	    for(i = 0; i <= 2; i++)
		if(fds[i] != -1)
		    close(fds[i]);
	    return -1;
	}
    }

    for(i = 0; i <= 2; i++)
	if(fds[i] > 2)
	    close(fds[i]);

    pid = fork();

    if(pid == -1)
	return -1;

    if(pid)
	exit(0);

    setsid();
    return 0;
#endif
}

int match_regex(const char *filename, const char *pattern)
{
	regex_t reg;
	int match, flags = REG_EXTENDED | REG_NOSUB;
	char fname[513];
#ifdef _WIN32
	flags |= REG_ICASE; /* case insensitive on Windows */
#endif
	if(cli_regcomp(&reg, pattern, flags) != 0)
	    return 2;

	if(pattern[strlen(pattern) - 1] == *PATHSEP) {
	    snprintf(fname, 511, "%s"PATHSEP, filename);
	    fname[512] = 0;
	} else {
	    strncpy(fname, filename, 513);
	    fname[512]='\0';
	}

	match = (cli_regexec(&reg, fname, 0, NULL, 0) == REG_NOMATCH) ? 0 : 1;
	cli_regfree(&reg);
	return match;
}

int cfg_tcpsock(const struct optstruct *opts, struct sockaddr_in *tcpsock, in_addr_t defaultbind)
{
    struct hostent *he;
    const struct optstruct *opt = optget(opts, "TCPSocket");

    if(opt->numarg > 65535)
	return -1;

    memset(tcpsock, 0, sizeof(*tcpsock));
    tcpsock->sin_family = AF_INET;
    tcpsock->sin_port = htons(opt->numarg);

    if(!(opt = optget(opts, "TCPAddr"))->enabled) {
	tcpsock->sin_addr.s_addr = htonl(defaultbind);
	return 0;
    }
    he = gethostbyname(opt->strarg);
    if(!he)
	return -1;

    tcpsock->sin_addr = *(struct in_addr *) he->h_addr_list[0];
    return 0;
}

int cli_is_abspath(const char *path) {
#ifdef _WIN32
    int len = strlen(path);
    return (len > 2 && path[0] == '\\' && path[1] == '\\') || (len >= 2 && ((*path >= 'a' && *path <= 'z') || (*path >= 'A' && *path <= 'Z')) && path[1] == ':');
#else
    return *path == '/';
#endif
}

unsigned int countlines(const char *filename)
{
	FILE *fh;
	char buff[1024];
	unsigned int lines = 0;


    if((fh = fopen(filename, "r")) == NULL)
	return 0;

    while(fgets(buff, sizeof(buff), fh)) {
	if(buff[0] == '#') continue;
	lines++;
    }

    fclose(fh);
    return lines;
}


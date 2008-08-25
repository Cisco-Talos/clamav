/*
 *  Copyright (C) 2004 - 2007 Tomasz Kojm <tkojm@clamav.net>
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
#ifndef	C_WINDOWS
#include <dirent.h>
#endif
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>

#include "shared/cfgparser.h"
#include "shared/output.h"

#include "libclamav/clamav.h"
#include "libclamav/cvd.h"
#include "libclamav/others.h" /* for cli_rmdirs() */
#include "libclamav/regex/regex.h"
#include "libclamav/version.h"
#include "shared/misc.h"

#ifndef	O_BINARY
#define	O_BINARY	0
#endif

#ifndef REPO_VERSION
#define REPO_VERSION "exported"
#endif

#ifdef CL_EXPERIMENTAL
#define EXP_VER "-exp"
#else
#define EXP_VER
#endif

const char *get_version(void)
{
	if(!strncmp("devel-",VERSION,6) && strcmp("exported",REPO_VERSION)) {
		return REPO_VERSION""EXP_VER;
	}
	/* it is a release, or we have nothing better */
	return VERSION""EXP_VER;
}
/* CL_NOLIBCLAMAV means to omit functions that depends on libclamav */
#ifndef CL_NOLIBCLAMAV
char *freshdbdir(void)
{
	struct cl_cvd *d1, *d2;
	struct cfgstruct *copt;
	const struct cfgstruct *cpt;
	const char *dbdir;
	char *retdir;


    /* try to find fresh directory */
    dbdir = cl_retdbdir();
    if((copt = getcfg(CONFDIR"/freshclam.conf", 0))) {
	if((cpt = cfgopt(copt, "DatabaseDirectory"))->enabled || (cpt = cfgopt(copt, "DataDirectory"))->enabled) {
	    if(strcmp(dbdir, cpt->strarg)) {
		    char *daily = (char *) malloc(strlen(cpt->strarg) + strlen(dbdir) + 30);
		sprintf(daily, "%s/daily.cvd", cpt->strarg);
		if(access(daily, R_OK))
		    sprintf(daily, "%s/daily.cld", cpt->strarg);

		if(!access(daily, R_OK) && (d1 = cl_cvdhead(daily))) {
		    sprintf(daily, "%s/daily.cvd", dbdir);
		    if(access(daily, R_OK))
			sprintf(daily, "%s/daily.cld", dbdir);

		    if(!access(daily, R_OK) && (d2 = cl_cvdhead(daily))) {
			free(daily);
			if(d1->version > d2->version)
			    dbdir = cpt->strarg;
			cl_cvdfree(d2);
		    } else {
			free(daily);
			dbdir = cpt->strarg;
		    }
		    cl_cvdfree(d1);
		} else {
		    free(daily);
		}
	    }
	}
    }

    retdir = strdup(dbdir);

    if(copt)
	freecfg(copt);

    return retdir;
}


void print_version(const char *dbdir)
{
	char *fdbdir, *path;
	const char *pt;
	struct cl_cvd *daily;


    if(dbdir)
	pt = dbdir;
    else
	pt = fdbdir = freshdbdir();

    if(!pt) {
	printf("ClamAV %s\n",get_version());
	return;
    }

    if(!(path = malloc(strlen(pt) + 11))) {
	if(!dbdir)
	    free(fdbdir);
	return;
    }

    sprintf(path, "%s/daily.cvd", pt);
    if(access(path, R_OK))
	sprintf(path, "%s/daily.cld", pt);

    if(!dbdir)
	free(fdbdir);

    if(!access(path, R_OK) && (daily = cl_cvdhead(path))) {
	    time_t t = (time_t) daily->stime;

	printf("ClamAV %s/%d/%s", get_version(), daily->version, ctime(&t));
	cl_cvdfree(daily);
    } else {
	printf("ClamAV %s\n",get_version());
    }

    free(path);
}
#endif
int filecopy(const char *src, const char *dest)
{

#ifdef C_DARWIN
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

#else
	char buffer[FILEBUFF];
	int s, d, bytes, ret;
	struct stat sb;


    if((s = open(src, O_RDONLY|O_BINARY)) == -1)
	return -1;

    if((d = open(dest, O_CREAT|O_WRONLY|O_TRUNC|O_BINARY, 0644)) == -1) {
	close(s);
	return -1;
    }

    while((bytes = read(s, buffer, FILEBUFF)) > 0)
	if(write(d, buffer, bytes) < bytes) {
	    close(s);
	    close(d);
	    return -1;
	}

    close(s);
    /* njh@bandsman.co.uk: check result of close for NFS file */
    ret = close(d);

    stat(src, &sb);
    chmod(dest, sb.st_mode);

    return ret;

#endif

}

#ifndef CL_NOLIBCLAMAV
int dircopy(const char *src, const char *dest)
{
	DIR *dd;
	struct dirent *dent;
	struct stat sb;
	char spath[512], dpath[512];


    if(stat(dest, &sb) == -1) {
	if(mkdir(dest, 0755)) {
	    /* mprintf("!dircopy: Can't create temporary directory %s\n", dest); */
	    return -1;
	}
    }

    if((dd = opendir(src)) == NULL) {
        /* mprintf("!dircopy: Can't open directory %s\n", src); */
        return -1;
    }

    while((dent = readdir(dd))) {
#if (!defined(C_INTERIX)) && (!defined(C_WINDOWS))
	if(dent->d_ino)
#endif
	{
	    if(!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))
		continue;

	    snprintf(spath, sizeof(spath), "%s/%s", src, dent->d_name);
	    snprintf(dpath, sizeof(dpath), "%s/%s", dest, dent->d_name);

	    if(filecopy(spath, dpath) == -1) {
		/* mprintf("!dircopy: Can't copy %s to %s\n", spath, dpath); */
		cli_rmdirs(dest);
		closedir(dd);
		return -1;
	    }
	}
    }

    closedir(dd);
    return 0;
}
#endif

#ifndef CL_NOLIBCLAMAV
int cvd_unpack(const char *cvd, const char *destdir)
{
	int fd;


    if((fd = open(cvd, O_RDONLY|O_BINARY)) == -1)
	return -1;

    if(lseek(fd, 512, SEEK_SET) == -1) {
	close(fd);
	return -1;
    }

    if(cli_untgz(fd, destdir) == -1) {
	close(fd);
	return -1;
    }
    close(fd);

    return 0;
}
#endif

int daemonize(void)
{
#if defined(C_OS2) || defined(C_WINDOWS)
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

#ifndef CL_NOLIBCLAMAV
int match_regex(const char *filename, const char *pattern)
{
	regex_t reg;
	int match, flags = REG_EXTENDED | REG_NOSUB;
	char fname[513];
#if defined(C_OS2) || defined(C_WINDOWS)
	size_t len;

	flags |= REG_ICASE; /* case insensitive on Windows */
#endif
	if(cli_regcomp(&reg, pattern, flags) != 0)
	    return 2;

#if !defined(C_OS2) && !defined(C_WINDOWS)
	if(pattern[strlen(pattern) - 1] == '/') {
	    snprintf(fname, 511, "%s/", filename);
	    fname[512] = 0;
#else
	if(pattern[strlen(pattern) - 1] == '\\') {
	    strncpy(fname, filename, 510);
	    fname[509]='\0';
	    len = strlen(fname);
	    if(fname[len - 1] != '\\') {
		fname[len] = '\\';
		fname[len + 1] = 0;
	    }
#endif
	} else {
	    strncpy(fname, filename, 513);
	    fname[512]='\0';
	}

	match = (cli_regexec(&reg, fname, 0, NULL, 0) == REG_NOMATCH) ? 0 : 1;
	cli_regfree(&reg);
	return match;
}
#endif

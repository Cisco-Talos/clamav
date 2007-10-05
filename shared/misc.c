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
#include "shared/misc.h"

#ifndef	O_BINARY
#define	O_BINARY	0
#endif

#ifdef CL_EXPERIMENTAL
#define VERSION_EXP	VERSION"-exp"
#else
#define VERSION_EXP	VERSION
#endif

char *freshdbdir(void)
{
	struct cl_cvd *d1, *d2;
	struct cfgstruct *copt;
	const struct cfgstruct *cpt;
	struct stat foo;
	const char *dbdir;
	char *retdir;


    /* try to find fresh directory */
    dbdir = cl_retdbdir();
    if((copt = getcfg(CONFDIR"/clamd.conf", 0))) {
	if((cpt = cfgopt(copt, "DatabaseDirectory"))->enabled || (cpt = cfgopt(copt, "DataDirectory"))->enabled) {
	    if(strcmp(dbdir, cpt->strarg)) {
		    char *daily = (char *) malloc(strlen(cpt->strarg) + strlen(dbdir) + 30);
		sprintf(daily, "%s/daily.cvd", cpt->strarg);
		if(stat(daily, &foo) == -1)
		    sprintf(daily, "%s/daily.inc/daily.info", cpt->strarg);

		if((d1 = cl_cvdhead(daily))) {
		    sprintf(daily, "%s/daily.cvd", dbdir);
		    if(stat(daily, &foo) == -1)
			sprintf(daily, "%s/daily.inc/daily.info", dbdir);

		    if((d2 = cl_cvdhead(daily))) {
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

void print_version(void)
{
	char *dbdir;
	char *path;
	struct cl_cvd *daily;
	struct stat foo;


    dbdir = freshdbdir();
    if(!(path = malloc(strlen(dbdir) + 30))) {
	free(dbdir);
	return;
    }

    sprintf(path, "%s/daily.cvd", dbdir);
    if(stat(path, &foo) == -1)
	sprintf(path, "%s/daily.inc/daily.info", dbdir);
    free(dbdir);

    if((daily = cl_cvdhead(path))) {
	    time_t t = (time_t) daily->stime;

	printf("ClamAV "VERSION_EXP"/%d/%s", daily->version, ctime(&t));
	cl_cvdfree(daily);
    } else {
	printf("ClamAV "VERSION_EXP"\n");
    }

    free(path);
}

int filecopy(const char *src, const char *dest)
{

#ifdef C_DARWIN
	pid_t pid;

    /* On Mac OS X use ditto and copy resource fork, too. */
    switch(pid = fork()) {
	case -1:
	    return -1;
	case 0:
	    execl("/usr/bin/ditto", "ditto", "--rsrc", src, dest, NULL);
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

    if((d = open(dest, O_CREAT|O_WRONLY|O_TRUNC|O_BINARY)) == -1) {
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
#if   (!defined(C_CYGWIN)) && (!defined(C_INTERIX)) && (!defined(C_WINDOWS))
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

int isnumb(const char *str)
{
    while(*str) {
	if(!isdigit(*str & 0xff))
	    return 0;
	str++;
    }

    return 1;
}

int cvd_unpack(const char *cvd, const char *destdir)
{
	int fd;


    if((fd = open(cvd, O_RDONLY|O_BINARY)) == -1)
	return -1;

    if(lseek(fd, 512, SEEK_SET) == -1) {
	close(fd);
	return -1;
    }

    if(cli_untgz(fd, destdir) == -1) /* cli_untgz() will close fd */
	return -1;

    return 0;
}

void daemonize(void)
{
#if	defined(C_OS2) || defined(C_WINDOWS)
	fputs("Background mode is not supported on your operating system\n", stderr);
    return;
#else
	int i;


    if((i = open("/dev/null", O_RDWR)) == -1) {
	for(i = 0; i <= 2; i++)
	    close(i);

    } else {
	dup2(i, 0);
	dup2(i, 1);
	dup2(i, 2);
	if(i > 2)
	    close(i);
    }

    if(fork())
	exit(0);

    setsid();
#endif
}

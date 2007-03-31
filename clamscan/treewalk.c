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
#include <string.h>
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/stat.h>
#include <sys/types.h>
#ifndef C_WINDOWS
#include <sys/wait.h>
#endif
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#ifdef HAVE_GRP_H
#include <grp.h>
#endif
#ifndef C_WINDOWS
#include <dirent.h>
#endif
#include <errno.h>

#include "global.h"
#include "manager.h"
#include "others.h"
#include "treewalk.h"

#include "shared/options.h"
#include "shared/output.h"
#include "shared/misc.h"

#include "libclamav/clamav.h"
#include "libclamav/others.h"

int treewalk(const char *dirname, struct cl_engine *engine, const struct passwd *user, const struct optstruct *opt, const struct cl_limits *limits, unsigned int options, unsigned int depth)
{
	DIR *dd;
	struct dirent *dent;
	struct stat statbuf;
	char *fname;
	int scanret = 0, included;
	unsigned int maxdepth;
	const struct optnode *optnode;
	char *argument;


    if(opt_check(opt, "exclude-dir")) {
	argument = opt_firstarg(opt, "exclude-dir", &optnode);
	while(argument) {
	    if(match_regex(dirname, argument) == 1) {
		if(!printinfected)
		    logg("%s: Excluded\n", dirname);
		return 0;
	    }
	    argument = opt_nextarg(&optnode, "exclude-dir");
	}
    }

   if(opt_check(opt, "include-dir")) {
	included = 0;
	argument = opt_firstarg(opt, "include-dir", &optnode);
	while(argument && !included) {
	    if(match_regex(dirname, argument) == 1) {
		included = 1;
		break;
	    }
	    argument = opt_nextarg(&optnode, "include-dir");
	}

	if(!included) {
	    if(!printinfected)
		logg("%s: Excluded\n", dirname);
	    return 0;
	}
    }

    if(opt_check(opt, "max-dir-recursion"))
        maxdepth = atoi(opt_arg(opt, "max-dir-recursion"));
    else
        maxdepth = 15;

    if(depth > maxdepth)
	return 0;

    info.dirs++;
    depth++;

    if((dd = opendir(dirname)) != NULL) {
	while((dent = readdir(dd))) {
#if !defined(C_INTERIX) && !defined(C_WINDOWS) && !defined(C_CYGWIN)
	    if(dent->d_ino)
#endif
	    {
		if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..")) {
		    /* build the full name */
		    fname = malloc(strlen(dirname) + strlen(dent->d_name) + 2);
		    sprintf(fname, "%s/%s", dirname, dent->d_name);

		    /* stat the file */
		    if(lstat(fname, &statbuf) != -1) {
			if(S_ISDIR(statbuf.st_mode) && !S_ISLNK(statbuf.st_mode) && recursion) {
			    if(treewalk(fname, engine, user, opt, limits, options, depth) == 1)
				scanret++;
			} else {
			    if(S_ISREG(statbuf.st_mode))
				scanret += scanfile(fname, engine, user, opt, limits, options);
			}
		    }
		    free(fname);
		}

	    }
	}
    } else {
	if(!printinfected)
	    logg("%s: Can't open directory.\n", dirname);
	return 53;
    }

    closedir(dd);

    if(scanret)
	return 1;
    else
	return 0;

}

#ifdef C_WINDOWS
int clamav_rmdirs(const char *dir)
{
    return cli_rmdirs(dir);
}
#else
int clamav_rmdirs(const char *dir)
{
#ifndef C_CYGWIN
	struct passwd *user;
#endif
	pid_t pid;
	int status;


    switch(pid = fork()) {
	case -1:
	    return -1;
	case 0:
#ifndef C_CYGWIN
	    if(!geteuid()) { 
		if((user = getpwnam(CLAMAVUSER)) == NULL)
		    return -3;

#ifdef HAVE_SETGROUPS
		if(setgroups(1, &user->pw_gid)) {
		    fprintf(stderr, "ERROR: setgroups() failed.\n");
		    return -3;
		}
#endif

		if(setgid(user->pw_gid)) {
		    fprintf(stderr, "ERROR: setgid(%d) failed.\n", (int) user->pw_gid);
		    return -3;
		}

		if(setuid(user->pw_uid)) {
		    fprintf(stderr, "ERROR: setuid(%d) failed.\n", (int) user->pw_uid);
		    return -3;
		}
	    }
#endif
	    cli_rmdirs(dir);
	    exit(0);
	    break;
	default:
	    waitpid(pid, &status, 0);
	    if(WIFEXITED(status))
		return 0;
	    else
		return -2;
    }
}
#endif

int fixperms(const char *dirname)
{
	DIR *dd;
	struct dirent *dent;
	struct stat statbuf;
	char *fname;
	int scanret = 0;

    if((dd = opendir(dirname)) != NULL) {
	while((dent = readdir(dd))) {
#if !defined(C_INTERIX) && !defined(C_WINDOWS) && !defined(C_CYGWIN)
	    if(dent->d_ino)
#endif
	    {
		if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..")) {
		    /* build full name */
		    fname = malloc(strlen(dirname) + strlen(dent->d_name) + 2);
		    sprintf(fname, "%s/%s", dirname, dent->d_name);

		    /* stat the file */
		    if(lstat(fname, &statbuf) != -1) {
			if(S_ISDIR(statbuf.st_mode) && !S_ISLNK(statbuf.st_mode)) {
			    chmod(fname, 0700);
			    fixperms(fname);
			} else if(S_ISREG(statbuf.st_mode))
			    chmod(fname, 0700);
		    }

		    free(fname);
		}
	    }
	}
    } else {
	if(!printinfected)
	    logg("%s: Can't open directory.\n", dirname);
	return 53;
    }

    closedir(dd);

    if(scanret)
	return 1;
    else
	return 0;

}

int du(const char *dirname, struct s_du *n)
{
	DIR *dd;
	struct dirent *dent;
	struct stat statbuf;
	char *fname;

    if((dd = opendir(dirname)) != NULL) {
	while((dent = readdir(dd))) {
#if !defined(C_INTERIX) && !defined(C_WINDOWS) && !defined(C_CYGWIN)
	    if(dent->d_ino)
#endif
	    {
		if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..")) {
		    n->files++;

		    /* build the full name */
		    fname = malloc(strlen(dirname) + strlen(dent->d_name) + 2);
		    sprintf(fname, "%s/%s", dirname, dent->d_name);

		    /* stat the file */
		    if(lstat(fname, &statbuf) != -1) {
			if(S_ISDIR(statbuf.st_mode) && !S_ISLNK(statbuf.st_mode)) {
			    du(fname, n);
			} else {
			    n->space += statbuf.st_size / 1024;
			}
		    }

		    free(fname);
		}
	    }
	}
    } else {
	if(!printinfected)
	    logg("%s: Can't open directory.\n", dirname);
	return 53;
    }

    closedir(dd);

    return 0;
}

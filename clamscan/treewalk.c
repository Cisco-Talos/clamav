/*
 *  Copyright (C) 2002, 2003 Tomasz Kojm <zolw@konarski.edu.pl>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <grp.h>
#include <dirent.h>
#include <errno.h>

#include "shared.h"
#include "manager.h"
#include "others.h"
#include "options.h"
#include "treewalk.h"
#include "defaults.h"
#include "memory.h"
#include "output.h"

/*
 * recursive functions, similar to ftw(), these functions are duplicated below
 * with some small changes.
 */

int treewalk(const char *dirname, struct cl_node *root, const struct passwd *user, const struct optstruct *opt, const struct cl_limits *limits)
{
	DIR *dd;
	struct dirent *dent;
	struct stat statbuf;
	char *fname;
	int scanret = 0;

    claminfo.dirs++;

    if((dd = opendir(dirname)) != NULL) {
	while((dent = readdir(dd))) {
	    if(dent->d_ino) {
		if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..")) {
		    /* build the full name */
		    fname = mcalloc(strlen(dirname) + strlen(dent->d_name) + 2, sizeof(char));
		    sprintf(fname, "%s/%s", dirname, dent->d_name);

		    /* stat the file */
		    if(lstat(fname, &statbuf) != -1) {
			if(S_ISDIR(statbuf.st_mode) && !S_ISLNK(statbuf.st_mode) && recursion)
			    treewalk(fname, root, user, opt, limits);
			else
			    if(S_ISREG(statbuf.st_mode))
				scanret += scanfile(fname, root, user, opt, limits);
		    }
		    free(fname);
		}

	    }
	}
    } else {
	if(!printinfected)
	    mprintf("%s: Can't open directory.\n", dirname);
	return 53;
    }

    closedir(dd);

    if(scanret)
	return 1;
    else
	return 0;

}

int rmdirs(const char *dirname)
{
	DIR *dd;
	struct dirent *dent;
	struct stat maind, statbuf;
	char *fname;

    if((dd = opendir(dirname)) != NULL) {
	while(stat(dirname, &maind) != -1) {
	    if(!rmdir(dirname)) break;

	    while((dent = readdir(dd))) {
		if(dent->d_ino) {
		    if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..")) {
			fname = mcalloc(strlen(dirname) + strlen(dent->d_name) + 2, sizeof(char));
			sprintf(fname, "%s/%s", dirname, dent->d_name);

			/* stat the file */
			if(lstat(fname, &statbuf) != -1) {
			    if(S_ISDIR(statbuf.st_mode) && !S_ISLNK(statbuf.st_mode)) {
				if(rmdir(fname) == -1) { /* can't be deleted */
				    if(errno == EACCES) {
					mprintf("@Can't remove some temporary directories due to access problem.\n");
					closedir(dd);
					return 0;
				    }
				    rmdirs(fname);
				}
			    } else
				unlink(fname);
			}

			free(fname);
		    }
		}
	    }

	    rewinddir(dd);

	}

    } else { 
	if(!printinfected)
	    mprintf("%s: Can't open directory.\n", dirname);
	return 53;
    }

    closedir(dd);
    return 0;
}

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
	    if(!getuid()) { 
		if((user = getpwnam(UNPUSER)) == NULL)
		    return -3;

		setgroups(1, &user->pw_gid);
		setgid(user->pw_gid);
		setuid(user->pw_uid);
	    }
#endif
	    rmdirs(dir);
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

int fixperms(const char *dirname)
{
	DIR *dd;
	struct dirent *dent;
	struct stat statbuf;
	char *fname;
	int scanret = 0;

    if((dd = opendir(dirname)) != NULL) {
	while((dent = readdir(dd))) {
	    if(dent->d_ino) {
		if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..")) {
		    /* build full name */
		    fname = mcalloc(strlen(dirname) + strlen(dent->d_name) + 2, sizeof(char));
		    sprintf(fname, "%s/%s", dirname, dent->d_name);

		    /* stat the file */
		    if(lstat(fname, &statbuf) != -1) {
			if(S_ISDIR(statbuf.st_mode) && !S_ISLNK(statbuf.st_mode)) {
			    chmod(fname, 0700);
			    fixperms(fname);
			} else
			    chmod(fname, 0700);
		    }

		    free(fname);
		}
	    }
	}
    } else {
	if(!printinfected)
	    mprintf("%s: Can't open directory.\n", dirname);
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
	    if(dent->d_ino) {
		if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..")) {
		    n->files++;

		    /* build the full name */
		    fname = mcalloc(strlen(dirname) + strlen(dent->d_name) + 2, sizeof(char));
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
	    mprintf("%s: Can't open directory.\n", dirname);
	return 53;
    }

    closedir(dd);

    return 0;
}

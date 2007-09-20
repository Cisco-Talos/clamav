/*
 *  Copyright (C) 1999 - 2004 Tomasz Kojm <tkojm@clamav.net>
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
 *
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <errno.h>
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#ifndef C_WINDOWS
#include <sys/wait.h>
#include <sys/time.h>
#endif
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <target.h>

#include "regex/regex.h"

#include "shared/output.h"
#include "others.h"

int fileinfo(const char *filename, short i)
{
	struct stat infostruct;

    if(stat(filename, &infostruct) == -1)
	return(-1);

    switch(i) {

	case 1: /* size */
	    return infostruct.st_size;
	case 2: /* permissions */
	    return (mode_t)infostruct.st_mode;
	case 3: /* modification time */
	    return infostruct.st_mtime;
	case 4: /* UID */
	    return infostruct.st_uid;
	case 5: /* GID */
	    return infostruct.st_gid;
	default:
	    logg("!fileinfo(): Unknown option.\n");
	    exit(1);
    }
}

#ifdef C_WINDOWS
/* FIXME: Handle users correctly */
int checkaccess(const char *path, const char *username, int mode)
{
    return _access(path, mode);
}
#else
int checkaccess(const char *path, const char *username, int mode)
{
	struct passwd *user;
	int ret = 0, status;

    if(!geteuid()) {

	if((user = getpwnam(username)) == NULL) {
	    return -1;
	}

	switch(fork()) {
	    case -1:
		return -2;

	    case 0:
		if(setgid(user->pw_gid)) {
		    fprintf(stderr, "ERROR: setgid(%d) failed.\n", (int) user->pw_gid);
		    exit(0);
		}

		if(setuid(user->pw_uid)) {
		    fprintf(stderr, "ERROR: setuid(%d) failed.\n", (int) user->pw_uid);
		    exit(0);
		}

		if(access(path, mode))
		    exit(0);
		else
		    exit(1);

	    default:
		wait(&status);
		if(WIFEXITED(status) && WEXITSTATUS(status) == 1)
		    ret = 1;
	}

    } else {
	if(!access(path, mode))
	    ret = 1;
    }

    return ret;
}
#endif

int match_regex(const char *filename, const char *pattern)
{
	regex_t reg;
	int match, flags;
#if !defined(C_CYGWIN) && !defined(C_OS2)
	flags = REG_EXTENDED;
#else
	flags = REG_EXTENDED | REG_ICASE; /* case insensitive on Windows */
#endif
	if(cli_regcomp(&reg, pattern, flags) != 0) {
	    logg("!%s: Could not parse regular expression %s.\n", filename, pattern);
		return 2;
	}
	match = (cli_regexec(&reg, filename, 0, NULL, 0) == REG_NOMATCH) ? 0 : 1;
	cli_regfree(&reg);
	return match;
}

/*
 *  Copyright (C) 1999 - 2004 Tomasz Kojm <tkojm@clamav.net>
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
 *
 *  Sat May 18 15:20:26 CEST 2002: included detectCpu() from Magnus Ekdahl
 *  Sat Jun 29 12:19:26 CEST 2002: fixed non386 detectCpu (Magnus Ekdahl)
 *
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <target.h>

#ifdef HAVE_REGEX_H
#include <regex.h>
#endif

#include "output.h"
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
	    mprintf("!fileinfo(): Unknown option.\n");
	    exit(1);
    }
}

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

int match_regex(const char *filename, const char *pattern)
{
#ifdef HAVE_REGEX_H
	regex_t reg;
	int match, flags;
#if !defined(C_CYGWIN) && !defined(C_OS2)
	flags = REG_EXTENDED;
#else
	flags = REG_EXTENDED | REG_ICASE; /* case insensitive on Windows */
#endif	
	if(regcomp(&reg, pattern, flags) != 0) {
	    mprintf("!%s: Could not parse regular expression %s.\n", filename, pattern);
	    logg("!%s: Could not parse regular expression %s.\n", filename, pattern);
		return 2;
	}
	match = (regexec(&reg, filename, 0, NULL, 0) == REG_NOMATCH) ? 0 : 1;
	regfree(&reg);
	return match;
#else /* HAVE_REGEX_H */
	return strstr(filename, pattern) ? 1 : 0;
#endif
}

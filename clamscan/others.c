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

int readaccess(const char *path, const char *username)
{
	struct passwd *user;
	unsigned int su = 0, acc = 0;


    if(!getuid())
	su = 1;

    if(su) {
	if((user = getpwnam(username)) == NULL) {
	    return -1;
	}

	/* WARNING: it's not POSIX compliant */

	seteuid(user->pw_uid);
	setegid(user->pw_gid);
    }

    if(!access(path, R_OK))
	acc = 1;

    if(su) {
	seteuid(0);
	setegid(0);
    }

    return acc;
}

int writeaccess(const char *path, const char *username)
{
	struct passwd *user;
	unsigned int su = 0, acc = 0;


    if(!getuid())
	su = 1;

    if(su) {
	if((user = getpwnam(username)) == NULL) {
	    return -1;
	}

	/* WARNING: it's not POSIX compliant */

	seteuid(user->pw_uid);
	setegid(user->pw_gid);
    }

    if(!access(path, W_OK))
	acc = 1;

    if(su) {
	seteuid(0);
	setegid(0);
    }

    return acc;
}

int filecopy(const char *src, const char *dest)
{
	char buffer[FILEBUFF];
	int s, d, bytes;

    if((s = open(src, O_RDONLY)) == -1)
	return -1;

    if((d = open(dest, O_CREAT|O_WRONLY|O_TRUNC)) == -1) {
	close(s);
	return -1;
    }

    while((bytes = read(s, buffer, FILEBUFF)) > 0)
	write(d, buffer, bytes);

    close(s);

    /* njh@bandsman.co.uk: check result of close for NFS file */
    return close(d);
}

int isnumb(const char *str)
{
	int i;

    for(i = 0; i < strlen(str); i++)
	if(!isdigit(str[i]))
	    return 0;

    return 1;
}

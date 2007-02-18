/*
 *  Copyright (C) 2004 - 2005 Tomasz Kojm <tkojm@clamav.net>
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
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>

#include "clamav.h"
#include "cfgparser.h"
#include "memory.h"
#include "output.h"


char *freshdbdir(void)
{
	struct cl_cvd *d1, *d2;
	struct cfgstruct *copt = NULL, *cpt;
	const char *dbdir;
	char *retdir;

    /* try to find fresh directory */
    dbdir = cl_retdbdir();
    if((copt = parsecfg(CONFDIR"/clamd.conf", 0))) {
	if((cpt = cfgopt(copt, "DatabaseDirectory")) || (cpt = cfgopt(copt, "DataDirectory"))) {
	    if(strcmp(dbdir, cpt->strarg)) {
		    char *daily = (char *) mmalloc(strlen(cpt->strarg) + strlen(dbdir) + 15);
		sprintf(daily, "%s/daily.cvd", cpt->strarg);
		if((d1 = cl_cvdhead(daily))) {
		    sprintf(daily, "%s/daily.cvd", dbdir);
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


    dbdir = freshdbdir();
    if(!(path = mmalloc(strlen(dbdir) + 11))) {
	free(dbdir);
	return;
    }

    sprintf(path, "%s/daily.cvd", dbdir);
    free(dbdir);

    if((daily = cl_cvdhead(path))) {
	    time_t t = (time_t) daily->stime;
	printf("ClamAV "VERSION"/%d/%s", daily->version, ctime(&t));
	cl_cvdfree(daily);
    } else {
	printf("ClamAV "VERSION"\n");
    }

    free(path);

    if(strcmp(VERSION, cl_retver())) {
	printf("WARNING: Version mismatch. See http://www.clamav.net/faq.html\n");
	printf("Tool version: "VERSION", Engine version: %s\n", cl_retver());
    }
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
	    perror("execv(ditto)");
	    break;
	default:
	    wait(NULL);
	    return 0;
    }

    return -1;

#else
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

#endif

}

int isnumb(const char *str)
{
    while(*str) {
	if(!isdigit(*str))
	    return 0;
	str++;
    }

    return 1;
}

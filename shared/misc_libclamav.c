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
#include <clamav.h>
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
#include "libclamav/others.h" /* for cli_rmdirs() */

/* CL_NOLIBCLAMAV means to omit functions that depends on libclamav */
char *freshdbdir(void)
{
	struct cl_cvd *d1, *d2;
	struct optstruct *opts;
	const struct optstruct *opt;
	const char *dbdir;
	char *retdir;


    /* try to find the most up-to-date db directory */
    dbdir = cl_retdbdir();
    if((opts = optparse(CONFDIR_FRESHCLAM, 0, NULL, 0, OPT_FRESHCLAM, 0, NULL))) {
	if((opt = optget(opts, "DatabaseDirectory"))->enabled) {
	    if(strcmp(dbdir, opt->strarg)) {
		    char *daily = (char *) malloc(strlen(opt->strarg) + strlen(dbdir) + 30);
		sprintf(daily, "%s"PATHSEP"daily.cvd", opt->strarg);
		if(access(daily, R_OK))
		    sprintf(daily, "%s"PATHSEP"daily.cld", opt->strarg);

		if(!access(daily, R_OK) && (d1 = cl_cvdhead(daily))) {
		    sprintf(daily, "%s"PATHSEP"daily.cvd", dbdir);
		    if(access(daily, R_OK))
			sprintf(daily, "%s"PATHSEP"daily.cld", dbdir);

		    if(!access(daily, R_OK) && (d2 = cl_cvdhead(daily))) {
			free(daily);
			if(d1->version > d2->version)
			    dbdir = opt->strarg;
			cl_cvdfree(d2);
		    } else {
			free(daily);
			dbdir = opt->strarg;
		    }
		    cl_cvdfree(d1);
		} else {
		    free(daily);
		}
	    }
	}
    }

    retdir = strdup(dbdir);

    if(opts)
	optfree(opts);

    return retdir;
}

void print_version(const char *dbdir)
{
	char *fdbdir = NULL, *path;
	const char *pt;
	struct cl_cvd *daily;
	time_t db_time;
	unsigned int db_version = 0;


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

    sprintf(path, "%s"PATHSEP"daily.cvd", pt);
    if(!access(path, R_OK)) {
	daily = cl_cvdhead(path);
	if(daily) {
	    db_version = daily->version;
	    db_time = daily->stime;
	    cl_cvdfree(daily);
	}
    }

    sprintf(path, "%s"PATHSEP"daily.cld", pt);
    if(!access(path, R_OK)) {
	daily = cl_cvdhead(path);
	if(daily) {
	    if(daily->version > db_version) {
		db_version = daily->version;
		db_time = daily->stime;
	    }
	    cl_cvdfree(daily);
	}
    }

    if(!dbdir)
	free(fdbdir);

    if(db_version) {
	printf("ClamAV %s/%u/%s", get_version(), db_version, ctime(&db_time));
    } else {
	printf("ClamAV %s\n",get_version());
    }

    free(path);
}

int check_flevel(void)
{
    if(cl_retflevel() < CL_FLEVEL) {
	fprintf(stderr, "ERROR: This tool requires libclamav with functionality level %u or higher (current f-level: %u)\n", CL_FLEVEL, cl_retflevel());
	return 1;
    }
    return 0;
}

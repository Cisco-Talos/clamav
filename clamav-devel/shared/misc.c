/*
 *  Copyright (C) 2004 Tomasz Kojm <tkojm@clamav.net>
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
#include <string.h>
#include <time.h>

#include "clamav.h"
#include "cfgparser.h"
#include "memory.h"
#include "output.h"


const char *freshdbdir(void)
{
	struct cl_cvd *d1, *d2;
	struct cfgstruct *copt, *cpt;
	const char *dbdir;

    /* try to find fresh directory */
    dbdir = cl_retdbdir();
    if((copt = parsecfg(CONFDIR"/clamd.conf", 0))) {
	if((cpt = cfgopt(copt, "DatabaseDirectory")) || (cpt = cfgopt(copt, "DataDirectory"))) {
	    if(strcmp(cl_retdbdir(), cpt->strarg)) {
		    char *daily = (char *) mmalloc(strlen(cpt->strarg) + strlen(cl_retdbdir()) + 15);
		sprintf(daily, "%s/daily.cvd", cpt->strarg);
		if((d1 = cl_cvdhead(daily))) {
		    sprintf(daily, "%s/daily.cvd", cl_retdbdir());
		    if((d2 = cl_cvdhead(daily))) {
			free(daily);
			if(d1->version > d2->version)
			    dbdir = cpt->strarg;
			else
			    dbdir = cl_retdbdir();
			cl_cvdfree(d2);
		    } else {
			free(daily);
			dbdir = cpt->strarg;
		    }
		    cl_cvdfree(d1);
		} else {
		    free(daily);
		    dbdir = cl_retdbdir();
		}
	    }
	}
	freecfg(copt);
    }

    return dbdir;
}

void print_version(void)
{
	const char *dbdir;
	char *path;
	struct cl_cvd *daily;


    dbdir = freshdbdir();
    if(!(path = mmalloc(strlen(dbdir) + 11)))
	return;

    sprintf(path, "%s/daily.cvd", dbdir);

    if((daily = cl_cvdhead(path))) {
	    time_t t = (time_t) daily->stime;
	mprintf("ClamAV "VERSION"/%d/%s", daily->version, ctime(&t));
	cl_cvdfree(daily);
    } else {
	mprintf("ClamAV "VERSION"\n");
    }

    free(path);
}

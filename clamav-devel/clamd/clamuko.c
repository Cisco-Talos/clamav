/*
 *  Copyright (C) 2002 - 2004 Tomasz Kojm <tkojm@clamav.net>
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

#ifdef CLAMUKO

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <pthread.h>
#include <clamav.h>

#include "server.h"
#include "others.h"
#include "cfgparser.h"
#include "dazukoio.h"
#include "clamuko.h"
#include "defaults.h"
#include "output.h"

struct dazuko_access *acc;

void clamuko_exit(int sig)
{

    logg("*Clamuko: clamuko_exit(), signal %d\n", sig);

    if(clamuko_scanning) {
	logg("*Clamuko: stopped while scanning %s\n", acc->filename);
	acc->deny = 0;
	dazukoReturnAccess(&acc); /* is it needed ? */
    }

    if(dazukoUnregister())
	logg("!Can't unregister with Dazuko\n");

    logg("Clamuko stopped.\n");

    pthread_exit(NULL);
}

void *clamukoth(void *arg)
{
	struct thrarg *tharg = (struct thrarg *) arg;
	sigset_t sigset;
	const char *virname;
        struct sigaction act;
	unsigned long mask = 0;
	const struct cfgstruct *pt;
	short int scan;
	int sizelimit = 0;
	struct stat sb;


    clamuko_scanning = 0;

    /* ignore all signals except SIGUSR1 */
    sigfillset(&sigset);
    sigdelset(&sigset, SIGUSR1);
    sigdelset(&sigset, SIGSEGV);
    pthread_sigmask(SIG_SETMASK, &sigset, NULL);
    act.sa_handler = clamuko_exit;
    sigfillset(&(act.sa_mask));
    sigaction(SIGUSR1, &act, NULL);
    sigaction(SIGSEGV, &act, NULL);

    /* register */
    if(dazukoRegister("ClamAV", "r+")) {
	logg("!Clamuko: Can't register with Dazuko\n");
	return NULL;
    } else
	logg("Clamuko: Correctly registered with Dazuko.\n");

    /* access mask */
    if(cfgopt(tharg->copt, "ClamukoScanOnOpen")) {
	logg("Clamuko: Scan-on-open mode activated.\n");
	mask |= DAZUKO_ON_OPEN;
    }
    if(cfgopt(tharg->copt, "ClamukoScanOnClose")) {
	logg("Clamuko: Scan-on-close mode activated.\n");
	mask |= DAZUKO_ON_CLOSE;
    }
    if(cfgopt(tharg->copt, "ClamukoScanOnExec")) {
	logg("Clamuko: Scan-on-exec mode activated.\n");
	mask |= DAZUKO_ON_EXEC;
    }

    if(!mask) {
	logg("!Access mask is not configured properly.\n");
	dazukoUnregister();
	return NULL;
    }

    if(dazukoSetAccessMask(mask)) {
	logg("!Clamuko: Can't set access mask in Dazuko.\n");
	dazukoUnregister();
	return NULL;
    }

    if((pt = cfgopt(tharg->copt, "ClamukoIncludePath"))) {
	while(pt) {
	    if((dazukoAddIncludePath(pt->strarg))) {
		logg("!Clamuko: Dazuko -> Can't include path %s\n", pt->strarg);
		dazukoUnregister();
		return NULL;
	    } else
		logg("Clamuko: Included path %s\n", pt->strarg);

	    pt = (struct cfgstruct *) pt->nextarg;
	}
    } else {
	logg("!Clamuko: please include at least one path.\n");
	dazukoUnregister();
	return NULL;
    }

    if((pt = cfgopt(tharg->copt, "ClamukoExcludePath"))) {
	while(pt) {
	    if((dazukoAddExcludePath(pt->strarg))) {
		logg("!Clamuko: Dazuko -> Can't exclude path %s\n", pt->strarg);
		dazukoUnregister();
		return NULL;
	    } else
		logg("Clamuko: Excluded path %s\n", pt->strarg);

	    pt = (struct cfgstruct *) pt->nextarg;
	}
    }

    if((pt = cfgopt(tharg->copt, "ClamukoMaxFileSize"))) {
	sizelimit = pt->numarg;
    } else
	sizelimit = CL_DEFAULT_CLAMUKOMAXFILESIZE;

    if(sizelimit)
	logg("Clamuko: Max file size limited to %d bytes.\n", sizelimit);
    else
	logg("Clamuko: File size limit disabled.\n");

    while(1) {

	if(dazukoGetAccess(&acc) == 0) {
	    clamuko_scanning = 1;
	    scan = 1;

	    if(sizelimit) {
		stat(acc->filename, &sb);
		if(sb.st_size > sizelimit) {
		    scan = 0;
		    logg("*Clamuko: %s skipped (too big)\n", acc->filename);
		}
	    }

	    if(scan && cl_scanfile(acc->filename, &virname, NULL, tharg->root, tharg->limits, tharg->options) == CL_VIRUS) {
		logg("Clamuko: %s: %s FOUND\n", acc->filename, virname);
		virusaction(acc->filename, virname, tharg->copt);
		acc->deny = 1;
	    } else
		acc->deny = 0;

	    if(dazukoReturnAccess(&acc)) {
		logg("!Can't return access to Dazuko.\n");
		logg("Clamuko stopped.\n");
		dazukoUnregister();
		clamuko_scanning = 0;
		return NULL;
	    }

	    clamuko_scanning = 0;
	}
    }

    /* can't be ;) */
    return NULL;
}

#endif

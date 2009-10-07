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

#ifdef CLAMUKO

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <pthread.h>
#include <string.h>

#include "libclamav/clamav.h"

#include "shared/optparser.h"
#include "shared/output.h"

#include "server.h"
#include "others.h"
#include "dazukoio.h"
#include "clamukofs.h"
#include "clamuko.h"

struct dazuko_access *acc;
short int clamuko_scanning;
static void clamuko_exit(int sig)
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

static void *clamukolegacyth(void *arg)
{
	struct thrarg *tharg = (struct thrarg *) arg;
	sigset_t sigset;
	const char *virname;
        struct sigaction act;
	unsigned long mask = 0;
	const struct optstruct *pt;
	short int scan;
	int sizelimit = 0;
	struct stat sb;


    clamuko_scanning = 0;

    /* ignore all signals except SIGUSR1 */
    sigfillset(&sigset);
    sigdelset(&sigset, SIGUSR1);
    /* The behavior of a process is undefined after it ignores a 
     * SIGFPE, SIGILL, SIGSEGV, or SIGBUS signal */
    sigdelset(&sigset, SIGFPE);
    sigdelset(&sigset, SIGILL);
    sigdelset(&sigset, SIGSEGV);
#ifdef SIGBUS    
    sigdelset(&sigset, SIGBUS);
#endif
    pthread_sigmask(SIG_SETMASK, &sigset, NULL);
    memset(&act, 0, sizeof(struct sigaction));
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
    if(optget(tharg->opts, "ClamukoScanOnOpen")->enabled) {
	logg("Clamuko: Scan-on-open mode activated.\n");
	mask |= DAZUKO_ON_OPEN;
    }
    if(optget(tharg->opts, "ClamukoScanOnClose")->enabled) {
	logg("Clamuko: Scan-on-close mode activated.\n");
	mask |= DAZUKO_ON_CLOSE;
    }
    if(optget(tharg->opts, "ClamukoScanOnExec")->enabled) {
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

    if((pt = optget(tharg->opts, "ClamukoIncludePath"))->enabled) {
	while(pt) {
	    if((dazukoAddIncludePath(pt->strarg))) {
		logg("!Clamuko: Dazuko -> Can't include path %s\n", pt->strarg);
		dazukoUnregister();
		return NULL;
	    } else
		logg("Clamuko: Included path %s\n", pt->strarg);

	    pt = (struct optstruct *) pt->nextarg;
	}
    } else {
	logg("!Clamuko: please include at least one path.\n");
	dazukoUnregister();
	return NULL;
    }

    if((pt = optget(tharg->opts, "ClamukoExcludePath"))->enabled) {
	while(pt) {
	    if((dazukoAddExcludePath(pt->strarg))) {
		logg("!Clamuko: Dazuko -> Can't exclude path %s\n", pt->strarg);
		dazukoUnregister();
		return NULL;
	    } else
		logg("Clamuko: Excluded path %s\n", pt->strarg);

	    pt = (struct optstruct *) pt->nextarg;
	}
    }

    sizelimit = optget(tharg->opts, "ClamukoMaxFileSize")->numarg;
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

	    if(scan && cl_scanfile(acc->filename, &virname, NULL, tharg->engine, tharg->options) == CL_VIRUS) {
		logg("Clamuko: %s: %s FOUND\n", acc->filename, virname);
		virusaction(acc->filename, virname, tharg->opts);
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

void *clamukoth(void *arg)
{
	struct stat s;

    /* we use DazukoFS if /dev/dazukofs.ctrl exists and it is a
     * character device, otherwise we use Dazuko */
    if(stat("/dev/dazukofs.ctrl", &s) != 0) return clamukolegacyth(arg);
    if(!S_ISCHR(s.st_mode)) return clamukolegacyth(arg);
    return clamukofsth(arg);
}

#endif

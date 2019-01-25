/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *  Copyright (C) 2002-2007 Tomasz Kojm <tkojm@clamav.net>
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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#ifndef	_WIN32
#include <sys/wait.h>
#endif
#include <sys/stat.h>
#include <fcntl.h>
#ifdef	HAVE_PWD_H
#include <pwd.h>
#endif
#ifdef HAVE_GRP_H
#include <grp.h>
#endif

#if defined(USE_SYSLOG) && !defined(C_AIX)
#include <syslog.h>
#endif

#include "target.h"
#include "clamav.h"
#include "freshclam/freshclamcodes.h"

#include "libclamav/others.h"
#include "libclamav/str.h"

#include "shared/optparser.h"
#include "shared/output.h"
#include "shared/misc.h"

#include "freshclam/execute.h"
#include "freshclam/manager.h"
#include "freshclam/mirman.h"
#include "libfreshclam.h"
int sigchld_wait = 1;
char updtmpdir[512], dbdir[512];


static int
download (const struct optstruct *opts, const char *cfgfile)
{
    int ret = 0, try = 1, maxattempts = 0;
    const struct optstruct *opt;
    
    
    maxattempts = (int)optget (opts, "MaxAttempts")->numarg;
    logg ("*Max retries == %d\n", maxattempts);
    
    if (!(opt = optget (opts, "DatabaseMirror"))->enabled)
    {
        logg ("^You must specify at least one database mirror in %s\n",
              cfgfile);
        return FCE_CONFIG;
    }
    else
    {
        while (opt)
        {
            ret = downloadmanager (opts, opt->strarg, try);
#ifndef _WIN32
            alarm (0);
#endif
            if (ret == FCE_CONNECTION || ret == FCE_BADCVD
                || ret == FCE_FAILEDGET || ret == FCE_MIRRORNOTSYNC)
            {
                if (try < maxattempts)
                {
                    logg ("Trying again in 5 secs...\n");
                    try++;
                    sleep (5);
                    continue;
                }
                else
                {
                    logg ("Giving up on %s...\n", opt->strarg);
                    opt = (struct optstruct *) opt->nextarg;
                    if (!opt)
                    {
                        logg ("Update failed. Your network may be down or none of the mirrors listed in %s is working. Check https://www.clamav.net/documents/official-mirror-faq for possible reasons.\n", cfgfile);
                    }
                }
                
            }
            else
            {
                return ret;
            }
        }
    }
    
    return ret;
}



int download_with_opts(struct optstruct *opts, const char* db_path, const char* db_owner) {
    const struct optstruct *opt;
#ifdef HAVE_PWD_H
    const char *dbowner;
    struct passwd *user;
#endif
    struct mirdat mdat;
    int ret;
    
    
#ifdef HAVE_PWD_H
    if (db_owner) {
        dbowner = db_owner;
    }
    else
    {
        /* freshclam shouldn't work with root privileges */
        dbowner = optget (opts, "DatabaseOwner")->strarg;
    }
    
    if (!geteuid ())
    {
        if ((user = getpwnam (dbowner)) == NULL)
        {
            logg ("^Can't get information about user %s.\n", dbowner);
            optfree (opts);
            return FCE_USERINFO;
        }
        
#ifdef HAVE_INITGROUPS
	if (initgroups (dbowner, user->pw_gid))
	{
		logg ("^initgroups() failed.\n");
		optfree (opts);
		return FCE_USERORGROUP;
	}
#endif
    }
#endif /* HAVE_PWD_H */
    
    /* initialize some important variables */
    
    if (optget (opts, "Debug")->enabled || optget (opts, "debug")->enabled)
        cl_debug ();
    
    if (optget (opts, "verbose")->enabled)
        mprintf_verbose = 1;
    
    if (optget (opts, "quiet")->enabled)
        mprintf_quiet = 1;
    
    if (optget (opts, "no-warnings")->enabled)
    {
        mprintf_nowarn = 1;
        logg_nowarn = 1;
    }
    
    if (optget (opts, "stdout")->enabled)
        mprintf_stdout = 1;
    
    /* initialize logger */
    logg_verbose = mprintf_verbose ? 1 : optget (opts, "LogVerbose")->enabled;
    logg_time = optget (opts, "LogTime")->enabled;
    logg_size = optget (opts, "LogFileMaxSize")->numarg;
    if (logg_size)
        logg_rotate = optget(opts, "LogRotate")->enabled;
    
    if ((opt = optget (opts, "UpdateLogFile"))->enabled)
    {
        logg_file = opt->strarg;
        if (logg ("#--------------------------------------\n"))
        {
            mprintf ("!Problem with internal logger (UpdateLogFile = %s).\n",
                     logg_file);
            optfree (opts);
            return FCE_LOGGING;
        }
    }
    else
        logg_file = NULL;
    
#if defined(USE_SYSLOG) && !defined(C_AIX)
    if (optget (opts, "LogSyslog")->enabled)
    {
        int fac = LOG_LOCAL6;
        
        if ((opt = optget (opts, "LogFacility"))->enabled)
        {
            if ((fac = logg_facility (opt->strarg)) == -1)
            {
                mprintf ("!LogFacility: %s: No such facility.\n",
                         opt->strarg);
                optfree (opts);
                return FCE_LOGGING;
            }
        }
        
        openlog ("freshclam", LOG_PID, fac);
        logg_syslog = 1;
    }
#endif
    
    /* change the current working directory */
    if (chdir (optget (opts, "DatabaseDirectory")->strarg))
    {
        logg ("!Can't change dir to %s\n",
              optget (opts, "DatabaseDirectory")->strarg);
        optfree (opts);
        return FCE_DIRECTORY;
    }
    else
    {
        if (db_path)
        {
            if (chdir (db_path))
            {
                logg ("!Can't change dir to %s\n", db_path);
                optfree (opts);
                return FCE_DIRECTORY;
            }
        }
        
        if (!getcwd (dbdir, sizeof (dbdir)))
        {
            logg ("!getcwd() failed\n");
            optfree (opts);
            return FCE_DIRECTORY;
        }
        logg ("*Current working dir is %s\n", dbdir);
    }
    
    
    if (optget (opts, "list-mirrors")->enabled)
    {
        if (mirman_read ("mirrors.dat", &mdat, 1) == -1)
        {
            printf ("Can't read mirrors.dat\n");
            optfree (opts);
            return FCE_FILE;
        }
        mirman_list (&mdat);
        mirman_free (&mdat);
        optfree (opts);
        return 0;
    }
    
    if ((opt = optget (opts, "PrivateMirror"))->enabled)
    {
        struct optstruct *dbm, *opth;
        
        dbm = (struct optstruct *) optget (opts, "DatabaseMirror");
        dbm->active = dbm->enabled = 1;
        do
        {
            if (cli_strbcasestr (opt->strarg, ".clamav.net"))
            {
                logg ("!PrivateMirror: *.clamav.net is not allowed in this mode\n");
                optfree (opts);
                return FCE_PRIVATEMIRROR;
            }
            
            if (dbm->strarg)
                free (dbm->strarg);
            dbm->strarg = strdup (opt->strarg);
            if (!dbm->strarg)
            {
                logg ("!strdup() failed\n");
                optfree (opts);
                return FCE_MEM;
            }
            if (!dbm->nextarg)
            {
                dbm->nextarg =
                (struct optstruct *) calloc (1,
                                             sizeof (struct optstruct));
                if (!dbm->nextarg)
                {
                    logg ("!calloc() failed\n");
                    optfree (opts);
                    return FCE_MEM;
                }
            }
            opth = dbm;
            dbm = dbm->nextarg;
        }
        while ((opt = opt->nextarg));
        
        opth->nextarg = NULL;
        while (dbm)
        {
            free (dbm->name);
            free (dbm->cmd);
            free (dbm->strarg);
            opth = dbm;
            dbm = dbm->nextarg;
            free (opth);
        }
        
        /* disable DNS db checks */
        opth = (struct optstruct *) optget (opts, "no-dns");
        opth->active = opth->enabled = 1;
        
        /* disable scripted updates */
        opth = (struct optstruct *) optget (opts, "ScriptedUpdates");
        opth->active = opth->enabled = 0;
    }
    
    *updtmpdir = 0;
    
    ret = download (opts, NULL);
    optfree (opts);
    return ret;
}

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
#include "freshclamcodes.h"

#include "libclamav/others.h"
#include "libclamav/str.h"

#include "shared/optparser.h"
#include "shared/output.h"
#include "shared/misc.h"

#include "execute.h"
#include "manager.h"
#include "mirman.h"

static short terminate = 0;
extern int active_children;

static short foreground = -1;
char updtmpdir[512], dbdir[512];
int sigchld_wait = 1;
const char *pidfile = NULL;
char hostid[37];

char *get_hostid(void *cbdata);
int is_valid_hostid(void);

static void
sighandler (int sig)
{

    switch (sig)
    {
#ifdef	SIGCHLD
    case SIGCHLD:
        if (sigchld_wait)
            waitpid (-1, NULL, WNOHANG);
        active_children--;
        break;
#endif

#ifdef SIGPIPE
    case SIGPIPE:
        /* no action, app will get EPIPE */
        break;
#endif

#ifdef	SIGALRM
    case SIGALRM:
        terminate = -1;
        break;
#endif
#ifdef	SIGUSR1
    case SIGUSR1:
        terminate = -1;
        break;
#endif

#ifdef	SIGHUP
    case SIGHUP:
        terminate = -2;
        break;
#endif

    default:
        if (*updtmpdir)
            cli_rmdirs (updtmpdir);
        if (pidfile)
            unlink (pidfile);
        logg ("Update process terminated\n");
        exit (0);
    }

    return;
}

static void
writepid (const char *pidfile)
{
    FILE *fd;
    int old_umask;
    old_umask = umask (0006);
    if ((fd = fopen (pidfile, "w")) == NULL)
    {
        logg ("!Can't save PID to file %s: %s\n", pidfile, strerror (errno));
    }
    else
    {
        fprintf (fd, "%d\n", (int) getpid ());
        fclose (fd);
    }
    umask (old_umask);
}

static void
help (void)
{
    mprintf_stdout = 1;

    mprintf("\n");
    mprintf("                      Clam AntiVirus: Database Updater %s\n", get_version());
    mprintf("           By The ClamAV Team: https://www.clamav.net/about.html#credits\n");
    mprintf("           (C) 2019 Cisco Systems, Inc.\n");
    mprintf("\n");
    mprintf("    freshclam [options]\n");
    mprintf("\n");
    mprintf("    --help               -h              Show this help\n");
    mprintf("    --version            -V              Print version number and exit\n");
    mprintf("    --verbose            -v              Be verbose\n");
    mprintf("    --debug                              Enable debug messages\n");
    mprintf("    --quiet                              Only output error messages\n");
    mprintf("    --no-warnings                        Don't print and log warnings\n");
    mprintf("    --stdout                             Write to stdout instead of stderr\n");
    mprintf("    --show-progress                      Show download progress percentage\n");
    mprintf("\n");
    mprintf("    --config-file=FILE                   Read configuration from FILE.\n");
    mprintf("    --log=FILE           -l FILE         Log into FILE\n");
#ifndef _WIN32
    mprintf("    --daemon             -d              Run in daemon mode\n");
    mprintf("    --pid=FILE           -p FILE         Save daemon's pid in FILE\n");
    mprintf("    --user=USER          -u USER         Run as USER\n");
#endif
    mprintf("    --no-dns                             Force old non-DNS verification method\n");
    mprintf("    --checks=#n          -c #n           Number of checks per day, 1 <= n <= 50\n");
    mprintf("    --datadir=DIRECTORY                  Download new databases into DIRECTORY\n");
#ifdef BUILD_CLAMD
    mprintf("    --daemon-notify[=/path/clamd.conf]   Send RELOAD command to clamd\n");
#endif
    mprintf("    --local-address=IP   -a IP           Bind to IP for HTTP downloads\n");
    mprintf("    --on-update-execute=COMMAND          Execute COMMAND after successful update\n");
    mprintf("    --on-error-execute=COMMAND           Execute COMMAND if errors occurred\n");
    mprintf("    --on-outdated-execute=COMMAND        Execute COMMAND when software is outdated\n");
    mprintf("    --list-mirrors                       Print mirrors from mirrors.dat\n");
    mprintf("    --update-db=DBNAME                   Only update database DBNAME\n");
    mprintf ("\n");
}

static int
download (const struct optstruct *opts, const char *cfgfile)
{
    time_t currtime;
    int ret = 0, try = 1, maxattempts = 0;
    const struct optstruct *opt;

    time(&currtime);
    logg("ClamAV update process started at %s", ctime(&currtime));
    logg("*Using IPv6 aware code\n");

    maxattempts = optget (opts, "MaxAttempts")->numarg;
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
                    try = 1;
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

static void
msg_callback (enum cl_msg severity, const char *fullmsg, const char *msg,
              void *ctx)
{
    UNUSEDPARAM(fullmsg);
    UNUSEDPARAM(ctx);

    switch (severity)
    {
    case CL_MSG_ERROR:
        logg ("^[LibClamAV] %s", msg);
        break;
    case CL_MSG_WARN:
        logg ("~[LibClamAV] %s", msg);
	break;
    default:
        logg ("*[LibClamAV] %s", msg);
        break;
    }
}

int
main (int argc, char **argv)
{
    int ret = FCE_CONNECTION, retcl;
    const char *cfgfile, *arg = NULL;
    char *pt;
    struct optstruct *opts;
    const struct optstruct *opt;
#ifndef	_WIN32
    struct sigaction sigact;
    struct sigaction oldact;
#endif
#ifdef HAVE_PWD_H
    const char *dbowner;
    struct passwd *user;
#endif
    STATBUF statbuf;
    struct mirdat mdat;
	int j;

    if (check_flevel ())
        exit (FCE_INIT);

    if ((retcl = cl_init (CL_INIT_DEFAULT)))
    {
        mprintf ("!Can't initialize libclamav: %s\n", cl_strerror (retcl));
        return FCE_INIT;
    }

    if ((opts =
         optparse (NULL, argc, argv, 1, OPT_FRESHCLAM, 0, NULL)) == NULL)
    {
        mprintf ("!Can't parse command line options\n");
        return FCE_INIT;
    }

    if (optget (opts, "help")->enabled)
    {
        help ();
        optfree (opts);
        return FC_SUCCESS;
    }

    /* check foreground option from command line to override config file */
    for(j = 0; j < argc; j += 1)
    {
        if ((memcmp(argv[j], "--foreground", 12) == 0) || (memcmp(argv[j], "-F", 2) == 0))
        {
            /* found */
            break;
        }
    }

	if (j < argc) {
		if(optget(opts, "Foreground")->enabled) {
			foreground = 1;
		}
		else {
			foreground = 0;
		}
	}

    /* parse the config file */
    cfgfile = optget (opts, "config-file")->strarg;
    pt = strdup (cfgfile);
    if ((opts =
         optparse (cfgfile, 0, NULL, 1, OPT_FRESHCLAM, 0, opts)) == NULL)
    {
        fprintf (stderr, "ERROR: Can't open/parse the config file %s\n", pt);
        free (pt);
        return FCE_INIT;
    }
    free (pt);

    if (optget (opts, "version")->enabled)
    {
        print_version (optget (opts, "DatabaseDirectory")->strarg);
        optfree (opts);
        return FC_SUCCESS;
    }

    if (optget (opts, "HTTPProxyPassword")->enabled)
    {
        if (CLAMSTAT (cfgfile, &statbuf) == -1)
        {
            logg ("^Can't stat %s (critical error)\n", cfgfile);
            optfree (opts);
            return FCE_CONFIG;
        }

#ifndef _WIN32
        if (statbuf.
            st_mode & (S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH |
                       S_IXOTH))
        {
            logg ("^Insecure permissions (for HTTPProxyPassword): %s must have no more than 0700 permissions.\n", cfgfile);
            optfree (opts);
            return FCE_CONFIG;
        }
#endif
    }

#ifdef HAVE_PWD_H
    /* freshclam shouldn't work with root privileges */
    dbowner = optget (opts, "DatabaseOwner")->strarg;

    if (!geteuid ())
    {
        if ((user = getpwnam (dbowner)) == NULL)
        {
            logg ("^Can't get information about user %s.\n", dbowner);
            optfree (opts);
            return FCE_USERINFO;
        }

#ifdef HAVE_INITGROUPS
	if (initgroups(dbowner, user->pw_gid)) {
		logg ("^initgroups() failed.\n");
                optfree (opts);
		return FCE_USERORGROUP;
	}
#elif HAVE_SETGROUPS
	if (setgroups(1, &user->pw_gid)) {
		logg ("^setgroups() failed.\n");
                optfree (opts);
		return FCE_USERORGROUP;
	}
#endif

        if (setgid (user->pw_gid))
        {
            logg ("^setgid(%d) failed.\n", (int) user->pw_gid);
            optfree (opts);
            return FCE_USERORGROUP;
        }

        if (setuid (user->pw_uid))
        {
            logg ("^setuid(%d) failed.\n", (int) user->pw_uid);
            optfree (opts);
            return FCE_USERORGROUP;
        }
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

    if (optget (opts, "show-progress")->enabled)
        mprintf_progress = 1;

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

    cl_set_clcb_msg (msg_callback);
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
        if (mirman_read("mirrors.dat", &mdat, 1) != FC_SUCCESS)
        {
            printf ("Can't read mirrors.dat\n");
            optfree (opts);
            return FCE_FILE;
        }
        mirman_list (&mdat);
        mirman_free (&mdat);
        optfree (opts);
        return FC_SUCCESS;
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

#ifdef _WIN32
    signal (SIGINT, sighandler);
#else
    memset (&sigact, 0, sizeof (struct sigaction));
    sigact.sa_handler = sighandler;
    sigaction (SIGINT, &sigact, NULL);
    sigaction (SIGPIPE, &sigact, NULL);
#endif
    if (optget (opts, "daemon")->enabled)
    {
        int bigsleep, checks;
#ifndef	_WIN32
        time_t now, wakeup;

        sigaction (SIGTERM, &sigact, NULL);
        sigaction (SIGHUP, &sigact, NULL);
        sigaction (SIGCHLD, &sigact, NULL);
#endif

        checks = optget (opts, "Checks")->numarg;

        if (checks <= 0)
        {
            logg ("^Number of checks must be a positive integer.\n");
            optfree (opts);
            return FCE_CHECKS;
        }

        if (!optget (opts, "DNSDatabaseInfo")->enabled
            || optget (opts, "no-dns")->enabled)
        {
            if (checks > 50)
            {
                logg ("^Number of checks must be between 1 and 50.\n");
                optfree (opts);
                return FCE_CHECKS;
            }
        }

        bigsleep = 24 * 3600 / checks;

#ifndef _WIN32
        /* fork into background */
        if (foreground == -1)
        {
            if (optget(opts, "Foreground")->enabled)
            {
                foreground = 1;
            }
            else
            {
                foreground = 0;
            }
        }
        if(foreground == 0)
        {
            if (daemonize () == -1)
            {
                logg ("!daemonize() failed\n");
                optfree (opts);
                return FCE_FAILEDUPDATE;
            }
            mprintf_disabled = 1;
        }
#endif

        if ((opt = optget (opts, "PidFile"))->enabled)
        {
            pidfile = opt->strarg;
            writepid (pidfile);
        }

        active_children = 0;

        logg ("#freshclam daemon %s (OS: " TARGET_OS_TYPE ", ARCH: "
              TARGET_ARCH_TYPE ", CPU: " TARGET_CPU_TYPE ")\n",
              get_version ());

        while (!terminate)
        {
            ret = download (opts, cfgfile);

            if (ret > 1)
            {
                if ((opt = optget (opts, "OnErrorExecute"))->enabled)
                    arg = opt->strarg;

                if (arg)
                    execute ("OnErrorExecute", arg, opts);

                arg = NULL;
            }

            logg ("#--------------------------------------\n");
#ifdef	SIGALRM
            sigaction (SIGALRM, &sigact, &oldact);
#endif
#ifdef	SIGUSR1
            sigaction (SIGUSR1, &sigact, &oldact);
#endif

#ifdef	_WIN32
            sleep (bigsleep);
#else
            time (&wakeup);
            wakeup += bigsleep;
            alarm (bigsleep);
            do
            {
                pause ();
                time (&now);
            }
            while (!terminate && now < wakeup);

            if (terminate == -1)
            {
                logg ("Received signal: wake up\n");
                terminate = 0;
            }
            else if (terminate == -2)
            {
                logg ("Received signal: re-opening log file\n");
                terminate = 0;
                logg_close ();
            }
#endif

#ifdef	SIGALRM
            sigaction (SIGALRM, &oldact, NULL);
#endif
#ifdef	SIGUSR1
            sigaction (SIGUSR1, &oldact, NULL);
#endif
        }

    }
    else
    {
        ret = download (opts, cfgfile);
    }

    if (ret > 1)
    {
        if ((opt = optget (opts, "OnErrorExecute"))->enabled)
            execute ("OnErrorExecute", opt->strarg, opts);
    }

    if (pidfile)
    {
        unlink (pidfile);
    }

    optfree (opts);

    cl_cleanup_crypto();

    return ret > 1 ? ret : 0;
}

int is_valid_hostid(void)
{
    int count, i;

    if (strlen(hostid) != 36)
        return 0;

    count=0;
    for (i=0; i < 36; i++)
        if (hostid[i] == '-')
            count++;

    if (count != 4)
        return 0;

    if (hostid[8] != '-' || hostid[13] != '-' || hostid[18] != '-' || hostid[23] != '-')
        return 0;

    return 1;
}

char *get_hostid(void *cbdata)
{
    UNUSEDPARAM(cbdata);

    if (!strcmp(hostid, "none"))
        return NULL;

    if (!is_valid_hostid())
        return strdup(STATS_ANON_UUID);

    logg("HostID is valid: %s\n", hostid);

    return strdup(hostid);
}

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifndef _WIN32
#include <sys/time.h>
#include <sys/resource.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#ifdef HAVE_GRP_H
#include <grp.h>
#endif
#include <signal.h>
#include <errno.h>

#if defined(USE_SYSLOG) && !defined(C_AIX)
#include <syslog.h>
#endif

#ifdef C_LINUX
#include <sys/resource.h>
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "libclamav/crypto.h"

#include "target.h"

#include "libclamav/clamav.h"
#include "libclamav/others.h"
#include "libclamav/matcher-ac.h"
#include "libclamav/readdb.h"

#include "shared/output.h"
#include "shared/optparser.h"
#include "shared/misc.h"

#include "server.h"
#include "tcpserver.h"
#include "localserver.h"
#include "others.h"
#include "shared.h"
#include "scanner.h"

short debug_mode = 0, logok = 0;
short foreground = 0;
char hostid[37];

char *get_hostid(void *cbdata);

static void help(void)
{
    printf("\n");
    printf("                      Clam AntiVirus Daemon %s\n", get_version());
    printf("           By The ClamAV Team: http://www.clamav.net/team\n");
    printf("           (C) 2007-2009 Sourcefire, Inc.\n\n");

    printf("    --help                   -h             Show this help.\n");
    printf("    --version                -V             Show version number.\n");
    printf("    --debug                                 Enable debug mode.\n");
    printf("    --config-file=FILE       -c FILE        Read configuration from FILE.\n\n");
}

static struct optstruct *opts;

/* When running under valgrind and daemonizing, valgrind incorrectly reports
 * leaks from the engine, because it can't see that all the memory is still
 * reachable (some pointers are stored mangled in the JIT). 
 * So free the engine on exit from the parent too (during daemonize)
 */
static struct cl_engine *gengine = NULL;
static void free_engine(void)
{
    if (gengine) {
        cl_engine_free(gengine);
        gengine = NULL;
    }
}

int main(int argc, char **argv)
{
    static struct cl_engine *engine = NULL;
    const struct optstruct *opt;
#ifndef	_WIN32
    struct passwd *user = NULL;
    struct sigaction sa;
    struct rlimit rlim;
#endif
    time_t currtime;
    const char *dbdir, *cfgfile;
    char *pua_cats = NULL, *pt;
    int ret, tcpsock = 0, localsock = 0, i, min_port, max_port;
    unsigned int sigs = 0;
    int *lsockets=NULL;
    unsigned int nlsockets = 0;
    unsigned int dboptions = 0;
#ifdef C_LINUX
    STATBUF sb;
#endif

    if(check_flevel())
        exit(1);

#ifndef _WIN32
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
#endif

    cl_initialize_crypto();

    if((opts = optparse(NULL, argc, argv, 1, OPT_CLAMD, 0, NULL)) == NULL) {
        mprintf("!Can't parse command line options\n");
        return 1;
    }

    if(optget(opts, "help")->enabled) {
        help();
        optfree(opts);
        return 0;
    }

    if(optget(opts, "debug")->enabled) {
#if defined(C_LINUX)
        /* njh@bandsman.co.uk: create a dump if needed */
        rlim.rlim_cur = rlim.rlim_max = RLIM_INFINITY;
        if(setrlimit(RLIMIT_CORE, &rlim) < 0)
            perror("setrlimit");
#endif
        debug_mode = 1;
    }

    /* parse the config file */
    cfgfile = optget(opts, "config-file")->strarg;
    pt = strdup(cfgfile);
    if((opts = optparse(cfgfile, 0, NULL, 1, OPT_CLAMD, 0, opts)) == NULL) {
        fprintf(stderr, "ERROR: Can't open/parse the config file %s\n", pt);
        free(pt);
        return 1;
    }
    free(pt);

    if(optget(opts, "version")->enabled) {
        print_version(optget(opts, "DatabaseDirectory")->strarg);
        optfree(opts);
        return 0;
    }

    /* drop privileges */
#ifndef _WIN32
    if(geteuid() == 0 && (opt = optget(opts, "User"))->enabled) {
        if((user = getpwnam(opt->strarg)) == NULL) {
            fprintf(stderr, "ERROR: Can't get information about user %s.\n", opt->strarg);
            optfree(opts);
            return 1;
        }

        if(optget(opts, "AllowSupplementaryGroups")->enabled) {
#ifdef HAVE_INITGROUPS
            if(initgroups(opt->strarg, user->pw_gid)) {
                fprintf(stderr, "ERROR: initgroups() failed.\n");
                optfree(opts);
                return 1;
            }
#else
            mprintf("!AllowSupplementaryGroups: initgroups() is not available, please disable AllowSupplementaryGroups in %s\n", cfgfile);
            optfree(opts);
            return 1;
#endif
        } else {
#ifdef HAVE_SETGROUPS
            if(setgroups(1, &user->pw_gid)) {
                fprintf(stderr, "ERROR: setgroups() failed.\n");
                optfree(opts);
                return 1;
            }
#endif
        }

        if(setgid(user->pw_gid)) {
            fprintf(stderr, "ERROR: setgid(%d) failed.\n", (int) user->pw_gid);
            optfree(opts);
            return 1;
        }

        if(setuid(user->pw_uid)) {
            fprintf(stderr, "ERROR: setuid(%d) failed.\n", (int) user->pw_uid);
            optfree(opts);
            return 1;
        }
    }
#endif

    /* initialize logger */
    logg_lock = !optget(opts, "LogFileUnlock")->enabled;
    logg_time = optget(opts, "LogTime")->enabled;
    logok = optget(opts, "LogClean")->enabled;
    logg_size = optget(opts, "LogFileMaxSize")->numarg;
    logg_verbose = mprintf_verbose = optget(opts, "LogVerbose")->enabled;
    if (logg_size)
        logg_rotate = optget(opts, "LogRotate")->enabled;
    mprintf_send_timeout = optget(opts, "SendBufTimeout")->numarg;

    do { /* logger initialized */
        if((opt = optget(opts, "LogFile"))->enabled) {
            char timestr[32];
            logg_file = opt->strarg;
            if(!cli_is_abspath(logg_file)) {
                fprintf(stderr, "ERROR: LogFile requires full path.\n");
                ret = 1;
                break;
            }
            time(&currtime);
            if(logg("#+++ Started at %s", cli_ctime(&currtime, timestr, sizeof(timestr)))) {
                fprintf(stderr, "ERROR: Can't initialize the internal logger\n");
                ret = 1;
                break;
            }
        } else {
            logg_file = NULL;
        }

        if (optget(opts,"DevLiblog")->enabled)
            cl_set_clcb_msg(msg_callback);

        if((ret = cl_init(CL_INIT_DEFAULT))) {
            logg("!Can't initialize libclamav: %s\n", cl_strerror(ret));
            ret = 1;
            break;
        }

        if(optget(opts, "Debug")->enabled) {
            /* enable debug messages in libclamav */
            cl_debug();
            logg_verbose = 2;
        }

#if defined(USE_SYSLOG) && !defined(C_AIX)
        if(optget(opts, "LogSyslog")->enabled) {
            int fac = LOG_LOCAL6;

            opt = optget(opts, "LogFacility");
            if((fac = logg_facility(opt->strarg)) == -1) {
                logg("!LogFacility: %s: No such facility.\n", opt->strarg);
                ret = 1;
                break;
            }

            openlog("clamd", LOG_PID, fac);
            logg_syslog = 1;
        }
#endif

#ifdef C_LINUX
        procdev = 0;
        if(CLAMSTAT("/proc", &sb) != -1 && !sb.st_size)
            procdev = sb.st_dev;
#endif

        /* check socket type */

        if(optget(opts, "TCPSocket")->enabled)
            tcpsock = 1;

        if(optget(opts, "LocalSocket")->enabled)
            localsock = 1;

        if(!tcpsock && !localsock) {
            logg("!Please define server type (local and/or TCP).\n");
            ret = 1;
            break;
        }

        logg("#clamd daemon %s (OS: "TARGET_OS_TYPE", ARCH: "TARGET_ARCH_TYPE", CPU: "TARGET_CPU_TYPE")\n", get_version());

#ifndef _WIN32
        if(user)
            logg("#Running as user %s (UID %u, GID %u)\n", user->pw_name, user->pw_uid, user->pw_gid);
#endif

#if defined(RLIMIT_DATA) && defined(C_BSD)
        if (getrlimit(RLIMIT_DATA, &rlim) == 0) {
           /* bb #1941.
            * On 32-bit FreeBSD if you set ulimit -d to >2GB then mmap() will fail
            * too soon (after ~120 MB).
            * Set limit lower than 2G if on 32-bit */
           uint64_t lim = rlim.rlim_cur;
           if (sizeof(void*) == 4 &&
               lim > (1ULL << 31)) {
               rlim.rlim_cur = 1ULL << 31;
               if (setrlimit(RLIMIT_DATA, &rlim) < 0)
                   logg("!setrlimit(RLIMIT_DATA) failed: %s\n", strerror(errno));
               else
                   logg("Running on 32-bit system, and RLIMIT_DATA > 2GB, lowering to 2GB!\n");
           }
        }
#endif


        if(logg_size)
            logg("#Log file size limited to %u bytes.\n", logg_size);
        else
            logg("#Log file size limit disabled.\n");

        min_port = optget(opts, "StreamMinPort")->numarg;
        max_port = optget(opts, "StreamMaxPort")->numarg;
        if (min_port < 1024 || min_port > max_port || max_port > 65535) {
            logg("!Invalid StreamMinPort/StreamMaxPort: %d, %d\n", min_port, max_port);
            ret = 1;
            break;
        }

        if(!(engine = cl_engine_new())) {
            logg("!Can't initialize antivirus engine\n");
            ret = 1;
            break;
        }

        if (optget(opts, "disable-cache")->enabled)
            cl_engine_set_num(engine, CL_ENGINE_DISABLE_CACHE, 1);

        /* load the database(s) */
        dbdir = optget(opts, "DatabaseDirectory")->strarg;
        logg("#Reading databases from %s\n", dbdir);

        if(optget(opts, "DetectPUA")->enabled) {
            dboptions |= CL_DB_PUA;

            if((opt = optget(opts, "ExcludePUA"))->enabled) {
                dboptions |= CL_DB_PUA_EXCLUDE;
                i = 0;
                logg("#Excluded PUA categories:");

                while(opt) {
                    if(!(pua_cats = realloc(pua_cats, i + strlen(opt->strarg) + 3))) {
                        logg("!Can't allocate memory for pua_cats\n");
                        cl_engine_free(engine);
                        ret = 1;
                        break;
                    }

                    logg("# %s", opt->strarg);

                    sprintf(pua_cats + i, ".%s", opt->strarg);
                    i += strlen(opt->strarg) + 1;
                    pua_cats[i] = 0;
                    opt = opt->nextarg;
                }

                if (ret)
                    break;

                logg("#\n");
                pua_cats[i] = '.';
                pua_cats[i + 1] = 0;
            }

            if((opt = optget(opts, "IncludePUA"))->enabled) {
                if(pua_cats) {
                    logg("!ExcludePUA and IncludePUA cannot be used at the same time\n");
                    free(pua_cats);
                    ret = 1;
                    break;
                }

                dboptions |= CL_DB_PUA_INCLUDE;
                i = 0;
                logg("#Included PUA categories:");
                while(opt) {
                    if(!(pua_cats = realloc(pua_cats, i + strlen(opt->strarg) + 3))) {
                        logg("!Can't allocate memory for pua_cats\n");
                        ret = 1;
                        break;
                    }

                    logg("# %s", opt->strarg);

                    sprintf(pua_cats + i, ".%s", opt->strarg);
                    i += strlen(opt->strarg) + 1;
                    pua_cats[i] = 0;
                    opt = opt->nextarg;
                }

                if (ret)
                    break;

                logg("#\n");
                pua_cats[i] = '.';
                pua_cats[i + 1] = 0;
            }

            if(pua_cats) {
                if((ret = cl_engine_set_str(engine, CL_ENGINE_PUA_CATEGORIES, pua_cats))) {
                    logg("!cli_engine_set_str(CL_ENGINE_PUA_CATEGORIES) failed: %s\n", cl_strerror(ret));
                    free(pua_cats);
                    ret = 1;
                    break;
                }
                free(pua_cats);
            }
        } else {
            logg("#Not loading PUA signatures.\n");
        }

        if (optget(opts, "StatsEnabled")->enabled) {
            cl_engine_stats_enable(engine);
        }

        if (optget(opts, "StatsPEDisabled")->enabled) {
            cl_engine_set_num(engine, CL_ENGINE_DISABLE_PE_STATS, 1);
        }

        if (optget(opts, "StatsTimeout")->enabled) {
            cl_engine_set_num(engine, CL_ENGINE_STATS_TIMEOUT, optget(opts, "StatsTimeout")->numarg);
        }

        if (optget(opts, "StatsHostID")->enabled) {
            char *p = optget(opts, "StatsHostID")->strarg;

            if (strcmp(p, "default")) {
                if (!strcmp(p, "none")) {
                    cl_engine_set_clcb_stats_get_hostid(engine, NULL);
                } else if (!strcmp(p, "anonymous")) {
                    strcpy(hostid, STATS_ANON_UUID);
                } else {
                    if (strlen(p) > 36) {
                        logg("!Invalid HostID\n");
                        cl_engine_set_clcb_stats_submit(engine, NULL);
                        cl_engine_free(engine);
                        ret = 1;
                        break;
                    }

                    strcpy(hostid, p);
                }

                cl_engine_set_clcb_stats_get_hostid(engine, get_hostid);
            }
        }

        if(optget(opts, "OfficialDatabaseOnly")->enabled) {
            dboptions |= CL_DB_OFFICIAL_ONLY;
            logg("#Only loading official signatures.\n");
        }

        /* set the temporary dir */
        if((opt = optget(opts, "TemporaryDirectory"))->enabled) {
            if((ret = cl_engine_set_str(engine, CL_ENGINE_TMPDIR, opt->strarg))) {
                logg("!cli_engine_set_str(CL_ENGINE_TMPDIR) failed: %s\n", cl_strerror(ret));
                ret = 1;
                break;
            }
        }

        cl_engine_set_clcb_hash(engine, hash_callback);

        if(optget(opts, "LeaveTemporaryFiles")->enabled)
            cl_engine_set_num(engine, CL_ENGINE_KEEPTMP, 1);

        if(optget(opts, "ForceToDisk")->enabled)
            cl_engine_set_num(engine, CL_ENGINE_FORCETODISK, 1);

        if(optget(opts, "PhishingSignatures")->enabled)
            dboptions |= CL_DB_PHISHING;
        else
            logg("#Not loading phishing signatures.\n");

        if(optget(opts,"Bytecode")->enabled) {
            dboptions |= CL_DB_BYTECODE;
            if((opt = optget(opts,"BytecodeSecurity"))->enabled) {
                enum bytecode_security s;

                if (!strcmp(opt->strarg, "TrustSigned")) {
                    s = CL_BYTECODE_TRUST_SIGNED;
                    logg("#Bytecode: Security mode set to \"TrustSigned\".\n");
                } else if (!strcmp(opt->strarg, "Paranoid")) {
                    s = CL_BYTECODE_TRUST_NOTHING;
                    logg("#Bytecode: Security mode set to \"Paranoid\".\n");
                } else {
                    logg("!Unable to parse bytecode security setting:%s\n",
                        opt->strarg);
                    ret = 1;
                    break;
                }

                if ((ret = cl_engine_set_num(engine, CL_ENGINE_BYTECODE_SECURITY, s))) {
                    logg("^Invalid bytecode security setting %s: %s\n", opt->strarg, cl_strerror(ret));
                    ret = 1;
                    break;
                }
            }
            if((opt = optget(opts,"BytecodeUnsigned"))->enabled) {
                dboptions |= CL_DB_BYTECODE_UNSIGNED;
                logg("#Bytecode: Enabled support for unsigned bytecode.\n");
            }

            if((opt = optget(opts,"BytecodeMode"))->enabled) {
                enum bytecode_mode mode;

                if (!strcmp(opt->strarg, "ForceJIT"))
                    mode = CL_BYTECODE_MODE_JIT;
                else if(!strcmp(opt->strarg, "ForceInterpreter"))
                    mode = CL_BYTECODE_MODE_INTERPRETER;
                else if(!strcmp(opt->strarg, "Test"))
                    mode = CL_BYTECODE_MODE_TEST;
                else
                    mode = CL_BYTECODE_MODE_AUTO;
                cl_engine_set_num(engine, CL_ENGINE_BYTECODE_MODE, mode);
            }

            if((opt = optget(opts,"BytecodeTimeout"))->enabled) {
                cl_engine_set_num(engine, CL_ENGINE_BYTECODE_TIMEOUT, opt->numarg);
            }
        } else {
            logg("#Bytecode support disabled.\n");
        }

        if(optget(opts,"PhishingScanURLs")->enabled)
            dboptions |= CL_DB_PHISHING_URLS;
        else
            logg("#Disabling URL based phishing detection.\n");

        if(optget(opts,"DevACOnly")->enabled) {
            logg("#Only using the A-C matcher.\n");
            cl_engine_set_num(engine, CL_ENGINE_AC_ONLY, 1);
        }

        if((opt = optget(opts, "DevACDepth"))->enabled) {
            cl_engine_set_num(engine, CL_ENGINE_AC_MAXDEPTH, opt->numarg);
            logg("#Max A-C depth set to %u\n", (unsigned int) opt->numarg);
        }

        if((ret = cl_load(dbdir, engine, &sigs, dboptions))) {
            logg("!%s\n", cl_strerror(ret));
            ret = 1;
            break;
        }

        if (optget(opts, "DisableCertCheck")->enabled)
            engine->dconf->pe |= PE_CONF_DISABLECERT;

        logg("#Loaded %u signatures.\n", sigs);

        if((ret = cl_engine_compile(engine)) != 0) {
            logg("!Database initialization error: %s\n", cl_strerror(ret));
            ret = 1;
            break;
        }

        if(tcpsock) {
            int *t;

            opt = optget(opts, "TCPAddr");
            if (opt->enabled) {
                int breakout = 0;

                while (opt && opt->strarg) {
                    char *ipaddr = (!strcmp(opt->strarg, "all") ? NULL : opt->strarg);

                    if (tcpserver(&lsockets, &nlsockets, ipaddr, opts) == -1) {
                        ret = 1;
                        breakout = 1;
                        break;
                    }

                    opt = opt->nextarg;
                }

                if (breakout)
                    break;
            } else {
                if (tcpserver(&lsockets, &nlsockets, NULL, opts) == -1) {
                    ret = 1;
                    break;
                }
            }
        }
#ifndef _WIN32
        if(localsock) {
            int *t;
            mode_t sock_mode, umsk = umask(0777); /* socket is created with 000 to avoid races */

            t = realloc(lsockets, sizeof(int) * (nlsockets + 1));
            if (!(t)) {
                ret = 1;
                break;
            }
            lsockets = t;

            if ((lsockets[nlsockets] = localserver(opts)) == -1) {
                ret = 1;
                umask(umsk);
                break;
            }
            umask(umsk); /* restore umask */

            if(optget(opts, "LocalSocketGroup")->enabled) {
                char *gname = optget(opts, "LocalSocketGroup")->strarg, *end;
                gid_t sock_gid = strtol(gname, &end, 10);

                if(*end) {
                    struct group *pgrp = getgrnam(gname);

                    if(!pgrp) {
                        logg("!Unknown group %s\n", gname);
                        ret = 1;
                        break;
                    }

                    sock_gid = pgrp->gr_gid;
                }
                if(chown(optget(opts, "LocalSocket")->strarg, -1, sock_gid)) {
                    logg("!Failed to change socket ownership to group %s\n", gname);
                    ret = 1;
                    break;
                }
            }
            if(optget(opts, "LocalSocketMode")->enabled) {
                char *end;

                sock_mode = strtol(optget(opts, "LocalSocketMode")->strarg, &end, 8);

                if(*end) {
                    logg("!Invalid LocalSocketMode %s\n", optget(opts, "LocalSocketMode")->strarg);
                    ret = 1;
                    break;
                }
            } else {
                sock_mode = 0777 /* & ~umsk*/; /* conservative default: umask was 0 in clamd < 0.96 */
            }

            if(chmod(optget(opts, "LocalSocket")->strarg, sock_mode & 0666)) {
                logg("!Cannot set socket permission to %s\n", optget(opts, "LocalSocketMode")->strarg);
                ret = 1;
                break;
            }

            nlsockets++;
        }

        /* fork into background */
        if(!optget(opts, "Foreground")->enabled) {
#ifdef C_BSD	    
            /* workaround for OpenBSD bug, see https://wwws.clamav.net/bugzilla/show_bug.cgi?id=885 */
            for(ret=0;ret<nlsockets;ret++) {
                if (fcntl(lsockets[ret], F_SETFL, fcntl(lsockets[ret], F_GETFL) | O_NONBLOCK) == -1) {
                    logg("!fcntl for lsockets[] failed\n");
                    close(lsockets[ret]);
                    ret = 1;
                    break;
                }
            }
#endif
            gengine = engine;
            atexit(free_engine);
            if(daemonize() == -1) {
                logg("!daemonize() failed: %s\n", strerror(errno));
                ret = 1;
                break;
            }
            gengine = NULL;
#ifdef C_BSD
            for(ret=0;ret<nlsockets;ret++) {
                if (fcntl(lsockets[ret], F_SETFL, fcntl(lsockets[ret], F_GETFL) & ~O_NONBLOCK) == -1) {
                    logg("!fcntl for lsockets[] failed\n");
                    close(lsockets[ret]);
                    ret = 1;
                    break;
                }
            }
#endif
            if(!debug_mode)
                if(chdir("/") == -1)
                    logg("^Can't change current working directory to root\n");

        } else {
            foreground = 1;
        }
#endif

        if (nlsockets == 0) {
            logg("!Not listening on any interfaces\n");
            ret = 1;
            break;
        }

        ret = recvloop_th(lsockets, nlsockets, engine, dboptions, opts);

    } while (0);

    logg("*Closing the main socket%s.\n", (nlsockets > 1) ? "s" : "");

    for (i = 0; i < nlsockets; i++) {
        closesocket(lsockets[i]);
    }

#ifndef _WIN32
    if(nlsockets && localsock) {
        opt = optget(opts, "LocalSocket");

        if(unlink(opt->strarg) == -1)
            logg("!Can't unlink the socket file %s\n", opt->strarg);
        else
            logg("Socket file removed.\n");
    }
#endif

    free(lsockets);

    logg_close();
    optfree(opts);

    cl_cleanup_crypto();

    return ret;
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
    if (!strcmp(hostid, "none"))
        return NULL;

    if (!is_valid_hostid())
        return strdup(STATS_ANON_UUID);

    return strdup(hostid);
}

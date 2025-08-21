/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
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
#include <locale.h>

#if defined(USE_SYSLOG) && !defined(C_AIX)
#include <syslog.h>
#endif

#if defined(C_LINUX) || defined(__GLIBC__)
#include <sys/resource.h>
#endif

#include "target.h"

// libclamav
#include "clamav.h"
#include "others.h"
#include "matcher-ac.h"
#include "readdb.h"

// common
#include "output.h"
#include "optparser.h"
#include "misc.h"

#include "server.h"
#include "tcpserver.h"
#include "localserver.h"
#include "clamd_others.h"
#include "shared.h"
#include "scanner.h"

#ifdef _WIN32
#include "service.h"
#endif

#include <sys/types.h>
#ifndef WIN32
#include <sys/wait.h>
#endif

short debug_mode = 0, logok = 0;
short foreground = -1;

static void help(void)
{
    printf("\n");
    printf("                      Clam AntiVirus: Daemon %s\n", get_version());
    printf("           By The ClamAV Team: https://www.clamav.net/about.html#credits\n");
    printf("           (C) 2025 Cisco Systems, Inc.\n");
    printf("\n");
    printf("    clamd [options]\n");
    printf("\n");
    printf("    --help                   -h             Show this help\n");
    printf("    --version                -V             Show version number\n");
#ifdef _WIN32
    printf("    --install-service                       Install Windows Service\n");
    printf("    --uninstall-service                     Uninstall Windows Service\n");
#endif
    printf("    --foreground             -F             Run in foreground; do not daemonize\n");
    printf("    --debug                                 Enable debug mode\n");
    printf("    --log=FILE               -l FILE        Log into FILE\n");
    printf("    --config-file=FILE       -c FILE        Read configuration from FILE\n");
    printf("    --fail-if-cvd-older-than=days           Return with a nonzero error code if virus database outdated\n");
    printf("    --datadir=DIRECTORY                     Load signatures from DIRECTORY\n");
    printf("    --pid=FILE               -p FILE        Write the daemon's pid to FILE\n");
    printf("    --cvdcertsdir=DIRECTORY                 Specify a directory containing the root\n");
    printf("                                            CA cert needed to verify detached CVD digital signatures.\n");
    printf("                                            If not provided, then clamd will look in the default directory.\n");
    printf("\n");
    printf("Environment Variables:\n");
    printf("\n");
    printf("    LD_LIBRARY_PATH                         May be used on startup to find the libclamunrar_iface\n");
    printf("                                            shared library module to enable RAR archive support.\n");
    printf("    CVD_CERTS_DIR                           Specify a directory containing the root CA cert needed\n");
    printf("                                            to verify detached CVD digital signatures.\n");
    printf("                                            If not provided, then clamd will look in the default directory.\n");
    printf("\n");
    printf("Pass in - as the filename for stdin.\n");
    printf("\n");
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
#ifndef _WIN32
    struct passwd *user = NULL;
    struct sigaction sa;
    int dropPrivRet = 0;
#endif
#if defined(C_LINUX) || defined(__GLIBC__) || (defined(RLIMIT_DATA) && defined(C_BSD))
    struct rlimit rlim;
#endif
    time_t currtime;
    const char *dbdir, *cfgfile;
    char *pua_cats = NULL, *pt;
    int ret, tcpsock = 0, localsock = 0, min_port, max_port;
    unsigned int sigs      = 0;
    int *lsockets          = NULL;
    unsigned int nlsockets = 0;
    unsigned int dboptions = 0;
    unsigned int i;
    int j;
    int num_fd;
    pid_t parentPid = getpid();
#ifdef C_LINUX
    STATBUF sb;
#endif
    pid_t mainpid         = 0;
    mode_t old_umask      = 0;
    const char *user_name = NULL;
    char *cvdcertsdir     = NULL;
    STATBUF statbuf;

    if (check_flevel())
        exit(1);

#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#else /* !_WIN32 */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
    if (!setlocale(LC_CTYPE, "")) {
        mprintf(LOGG_WARNING, "Failed to set locale\n");
    }
#endif

    if ((opts = optparse(NULL, argc, argv, 1, OPT_CLAMD, 0, NULL)) == NULL) {
        mprintf(LOGG_ERROR, "Can't parse command line options\n");
        return 1;
    }

    if (optget(opts, "help")->enabled) {
        help();
        optfree(opts);
        return 0;
    }

    if (optget(opts, "debug")->enabled) {
#if defined(C_LINUX) || defined(__GLIBC__)
        /* njh@bandsman.co.uk: create a dump if needed */
        rlim.rlim_cur = rlim.rlim_max = RLIM_INFINITY;
        if (setrlimit(RLIMIT_CORE, &rlim) < 0)
            perror("setrlimit");
#endif
        debug_mode = 1;
    }

    /* check foreground option from command line to override config file */
    for (j = 0; j < argc; j += 1) {
        if ((memcmp(argv[j], "--foreground", 12) == 0) || (memcmp(argv[j], "-F", 2) == 0)) {
            /* found */
            break;
        }
    }

    if (j < argc) {
        if (optget(opts, "Foreground")->enabled) {
            foreground = 1;
        } else {
            foreground = 0;
        }
    }

    num_fd = sd_listen_fds(0);

    /* parse the config file */
    cfgfile = optget(opts, "config-file")->strarg;
    pt      = strdup(cfgfile);
    if (pt == NULL) {
        fprintf(stderr, "ERROR: Unable to allocate memory for config file\n");
        return 1;
    }
    if ((opts = optparse(cfgfile, 0, NULL, 1, OPT_CLAMD, 0, opts)) == NULL) {
        fprintf(stderr, "ERROR: Can't open/parse the config file %s\n", pt);
        free(pt);
        return 1;
    }
    free(pt);

    if ((opt = optget(opts, "User"))->enabled) {
        user_name = opt->strarg;
    }

    if (optget(opts, "version")->enabled) {
        print_version(optget(opts, "DatabaseDirectory")->strarg);
        optfree(opts);
        return 0;
    }

    /* initialize logger */
    logg_lock    = !optget(opts, "LogFileUnlock")->enabled;
    logg_time    = optget(opts, "LogTime")->enabled;
    logok        = optget(opts, "LogClean")->enabled;
    logg_size    = optget(opts, "LogFileMaxSize")->numarg;
    logg_verbose = mprintf_verbose = optget(opts, "LogVerbose")->enabled;
    if (logg_size)
        logg_rotate = optget(opts, "LogRotate")->enabled;
    mprintf_send_timeout = optget(opts, "SendBufTimeout")->numarg;

    if ((opt = optget(opts, "LogFile"))->enabled) {
        char timestr[32];
        logg_file = opt->strarg;
        if (!cli_is_abspath(logg_file)) {
            fprintf(stderr, "ERROR: LogFile requires full path.\n");
            ret = 1;
            return ret;
        }
        time(&currtime);
        if (logg(LOGG_INFO_NF, "+++ Started at %s", cli_ctime(&currtime, timestr, sizeof(timestr)))) {
            fprintf(stderr, "ERROR: Can't initialize the internal logger\n");
            ret = 1;
            return ret;
        }
    } else {
        logg_file = NULL;
    }

#ifndef WIN32
    /* fork into background */
    if (foreground == -1) {
        if (optget(opts, "Foreground")->enabled) {
            foreground = 1;
        } else {
            foreground = 0;
        }
    }
    if (foreground == 0) {
        int daemonizeRet = 0;
#ifdef C_BSD
        /* workaround for OpenBSD bug, see https://wwws.clamav.net/bugzilla/show_bug.cgi?id=885 */
        for (ret = 0; (unsigned int)ret < nlsockets; ret++) {
            if (fcntl(lsockets[ret], F_SETFL, fcntl(lsockets[ret], F_GETFL) | O_NONBLOCK) == -1) {
                logg(LOGG_ERROR, "fcntl for lsockets[] failed\n");
                close(lsockets[ret]);
                ret = 1;
                break;
            }
        }
#endif
        gengine = engine;
        atexit(free_engine);
        daemonizeRet = daemonize_parent_wait(user_name, logg_file);
        if (daemonizeRet < 0) {
            logg(LOGG_ERROR, "daemonize() failed: %s\n", strerror(errno));
            return 1;
        }
        gengine = NULL;
#ifdef C_BSD
        for (ret = 0; (unsigned int)ret < nlsockets; ret++) {
            if (fcntl(lsockets[ret], F_SETFL, fcntl(lsockets[ret], F_GETFL) & ~O_NONBLOCK) == -1) {
                logg(LOGG_ERROR, "fcntl for lsockets[] failed\n");
                close(lsockets[ret]);
                ret = 1;
                break;
            }
        }
#endif
    }

#endif

    /* save the PID */
    mainpid = getpid();
    if ((opt = optget(opts, "PidFile"))->enabled) {
        FILE *fd;
        old_umask = umask(0022);
        if ((fd = fopen(opt->strarg, "w")) == NULL) {
            // logg(LOGG_ERROR, "Can't save PID in file %s\n", opt->strarg);
            logg(LOGG_ERROR, "Can't save PID to file %s: %s\n", opt->strarg, strerror(errno));
            exit(2);
        } else {
            if (fprintf(fd, "%u\n", (unsigned int)mainpid) < 0) {
                logg(LOGG_ERROR, "Can't save PID to file %s: %s\n", opt->strarg, strerror(errno));
                // logg(LOGG_ERROR, "Can't save PID in file %s\n", opt->strarg);
                fclose(fd);
                exit(2);
            }
            fclose(fd);
        }
        umask(old_umask);

#ifndef _WIN32
        /*If the file has already been created by a different user, it will just be
         * rewritten by us, but not change the ownership, so do that explicitly.
         */
        if (0 == geteuid()) {
            struct passwd *pw = getpwuid(0);
            int ret           = lchown(opt->strarg, pw->pw_uid, pw->pw_gid);
            if (ret) {
                logg(LOGG_ERROR, "Can't change ownership of PID file %s '%s'\n", opt->strarg, strerror(errno));
                exit(2);
            }
        }
#endif /* _WIN32 */
    }

#ifdef _WIN32

    if (optget(opts, "install-service")->enabled) {
        svc_install("clamd", "ClamAV ClamD",
                    "Provides virus scanning facilities for ClamAV");
        optfree(opts);
        return 0;
    }

    if (optget(opts, "uninstall-service")->enabled) {
        svc_uninstall("clamd", 1);
        optfree(opts);
        return 0;
    }
#endif

    /* drop privileges */
#ifndef _WIN32
    dropPrivRet = drop_privileges(user_name, logg_file);
    if (dropPrivRet) {
        optfree(opts);
        return dropPrivRet;
    }
#endif /* _WIN32 */

    do { /* logger initialized */

        if (optget(opts, "DevLiblog")->enabled)
            cl_set_clcb_msg(msg_callback);

        if ((ret = cl_init(CL_INIT_DEFAULT))) {
            logg(LOGG_ERROR, "Can't initialize libclamav: %s\n", cl_strerror(ret));
            ret = 1;
            break;
        }

        if (optget(opts, "Debug")->enabled) {
            /* enable debug messages in libclamav */
            cl_debug();
            logg_verbose = 2;
        }

#if defined(USE_SYSLOG) && !defined(C_AIX)
        if (optget(opts, "LogSyslog")->enabled) {
            int fac = LOG_LOCAL6;

            opt = optget(opts, "LogFacility");
            if ((fac = logg_facility(opt->strarg)) == -1) {
                logg(LOGG_ERROR, "LogFacility: %s: No such facility.\n", opt->strarg);
                ret = 1;
                break;
            }

            openlog("clamd", LOG_PID, fac);
            logg_syslog = 1;
        }
#endif

#ifdef C_LINUX
        procdev = 0;
        if (CLAMSTAT("/proc", &sb) != -1 && !sb.st_size)
            procdev = sb.st_dev;
#endif

        /* check socket type */

        if (optget(opts, "TCPSocket")->enabled)
            tcpsock = 1;

        if (optget(opts, "LocalSocket")->enabled)
            localsock = 1;

        logg(LOGG_INFO_NF, "Received %d file descriptor(s) from systemd.\n", num_fd);

        if (!tcpsock && !localsock && num_fd == 0) {
            logg(LOGG_ERROR, "Please define server type (local and/or TCP).\n");
            ret = 1;
            break;
        }

        logg(LOGG_INFO_NF, "clamd daemon %s (OS: " TARGET_OS_TYPE ", ARCH: " TARGET_ARCH_TYPE ", CPU: " TARGET_CPU_TYPE ")\n", get_version());

#ifndef _WIN32
        if (user)
            logg(LOGG_INFO_NF, "Running as user %s (UID %u, GID %u)\n", user->pw_name, user->pw_uid, user->pw_gid);
#endif

#if defined(RLIMIT_DATA) && defined(C_BSD)
        if (getrlimit(RLIMIT_DATA, &rlim) == 0) {
            /* bb #1941.
             * On 32-bit FreeBSD if you set ulimit -d to >2GB then mmap() will fail
             * too soon (after ~120 MB).
             * Set limit lower than 2G if on 32-bit */
            uint64_t lim = rlim.rlim_cur;
            if (sizeof(void *) == 4 &&
                lim > (1ULL << 31)) {
                rlim.rlim_cur = 1ULL << 31;
                if (setrlimit(RLIMIT_DATA, &rlim) < 0)
                    logg(LOGG_ERROR, "setrlimit(RLIMIT_DATA) failed: %s\n", strerror(errno));
                else
                    logg(LOGG_INFO, "Running on 32-bit system, and RLIMIT_DATA > 2GB, lowering to 2GB!\n");
            }
        }
#endif

        if (logg_size)
            logg(LOGG_INFO_NF, "Log file size limited to %lld bytes.\n", (long long int)logg_size);
        else
            logg(LOGG_INFO_NF, "Log file size limit disabled.\n");

        min_port = optget(opts, "StreamMinPort")->numarg;
        max_port = optget(opts, "StreamMaxPort")->numarg;
        if (min_port < 1024 || min_port > max_port || max_port > 65535) {
            logg(LOGG_ERROR, "Invalid StreamMinPort/StreamMaxPort: %d, %d\n", min_port, max_port);
            ret = 1;
            break;
        }

        if (!(engine = cl_engine_new())) {
            logg(LOGG_ERROR, "Can't initialize antivirus engine\n");
            ret = 1;
            break;
        }

        if ((opt = optget(opts, "cache-size"))->enabled)
            cl_engine_set_num(engine, CL_ENGINE_CACHE_SIZE, opt->numarg);
        if (optget(opts, "disable-cache")->enabled)
            cl_engine_set_num(engine, CL_ENGINE_DISABLE_CACHE, 1);

        /* load the database(s) */
        dbdir = optget(opts, "DatabaseDirectory")->strarg;
        logg(LOGG_INFO_NF, "Reading databases from %s\n", dbdir);

        if (optget(opts, "DetectPUA")->enabled) {
            dboptions |= CL_DB_PUA;

            if ((opt = optget(opts, "ExcludePUA"))->enabled) {
                dboptions |= CL_DB_PUA_EXCLUDE;
                i = 0;
                logg(LOGG_INFO_NF, "Excluded PUA categories:");

                while (opt) {
                    if (!(pua_cats = realloc(pua_cats, i + strlen(opt->strarg) + 3))) {
                        logg(LOGG_ERROR, "Can't allocate memory for pua_cats\n");
                        cl_engine_free(engine);
                        ret = 1;
                        break;
                    }

                    logg(LOGG_INFO_NF, " %s", opt->strarg);

                    sprintf(pua_cats + i, ".%s", opt->strarg);
                    i += strlen(opt->strarg) + 1;
                    pua_cats[i] = 0;
                    opt         = opt->nextarg;
                }

                if (ret)
                    break;

                logg(LOGG_INFO_NF, "\n");
                pua_cats[i]     = '.';
                pua_cats[i + 1] = 0;
            }

            if ((opt = optget(opts, "IncludePUA"))->enabled) {
                if (pua_cats) {
                    logg(LOGG_ERROR, "ExcludePUA and IncludePUA cannot be used at the same time\n");
                    free(pua_cats);
                    ret = 1;
                    break;
                }

                dboptions |= CL_DB_PUA_INCLUDE;
                i = 0;
                logg(LOGG_INFO_NF, "Included PUA categories:");
                while (opt) {
                    if (!(pua_cats = realloc(pua_cats, i + strlen(opt->strarg) + 3))) {
                        logg(LOGG_ERROR, "Can't allocate memory for pua_cats\n");
                        ret = 1;
                        break;
                    }

                    logg(LOGG_INFO_NF, " %s", opt->strarg);

                    sprintf(pua_cats + i, ".%s", opt->strarg);
                    i += strlen(opt->strarg) + 1;
                    pua_cats[i] = 0;
                    opt         = opt->nextarg;
                }

                if (ret)
                    break;

                logg(LOGG_INFO_NF, "\n");
                pua_cats[i]     = '.';
                pua_cats[i + 1] = 0;
            }

            if (pua_cats) {
                if ((ret = cl_engine_set_str(engine, CL_ENGINE_PUA_CATEGORIES, pua_cats))) {
                    logg(LOGG_ERROR, "cli_engine_set_str(CL_ENGINE_PUA_CATEGORIES) failed: %s\n", cl_strerror(ret));
                    free(pua_cats);
                    ret = 1;
                    break;
                }
                free(pua_cats);
            }
        } else {
            logg(LOGG_INFO_NF, "Not loading PUA signatures.\n");
        }

        if (optget(opts, "OfficialDatabaseOnly")->enabled) {
            dboptions |= CL_DB_OFFICIAL_ONLY;
            logg(LOGG_INFO_NF, "Only loading official signatures.\n");
        }

        /* set the temporary dir */
        if ((opt = optget(opts, "TemporaryDirectory"))->enabled) {
            if ((ret = cl_engine_set_str(engine, CL_ENGINE_TMPDIR, opt->strarg))) {
                logg(LOGG_ERROR, "cli_engine_set_str(CL_ENGINE_TMPDIR) failed: %s\n", cl_strerror(ret));
                ret = 1;
                break;
            }

            STATBUF sb;
            if (CLAMSTAT(opt->strarg, &sb) != 0 && !S_ISDIR(sb.st_mode)) {
                logg(LOGG_ERROR, "Current configuration of TemporaryDirectory: %s does not exist, or is not valid \n", opt->strarg);
                ret = 1;
                break;
            }
        }

        cvdcertsdir = optget(opts, "cvdcertsdir")->strarg;
        if (NULL != cvdcertsdir) {
            // Config option must override the engine defaults
            // (which would've used the env var or hardcoded path)
            if (LSTAT(cvdcertsdir, &statbuf) == -1) {
                logg(LOGG_ERROR,
                     "ClamAV CA certificates directory is missing: %s"
                     " - It should have been provided as a part of installation.\n",
                     cvdcertsdir);
                ret = 1;
                break;
            }

            if ((ret = cl_engine_set_str(engine, CL_ENGINE_CVDCERTSDIR, cvdcertsdir))) {
                logg(LOGG_ERROR, "cli_engine_set_str(CL_ENGINE_CVDCERTSDIR) failed: %s\n", cl_strerror(ret));
                ret = 1;
                break;
            }
        }

        cl_engine_set_clcb_hash(engine, hash_callback);

        cl_engine_set_clcb_virus_found(engine, clamd_virus_found_cb);

        if (optget(opts, "LeaveTemporaryFiles")->enabled) {
            /* Set the engine to keep temporary files */
            cl_engine_set_num(engine, CL_ENGINE_KEEPTMP, 1);
            /* Also set the engine to create temporary directory structure */
            cl_engine_set_num(engine, CL_ENGINE_TMPDIR_RECURSION, 1);
        }

        if (optget(opts, "ForceToDisk")->enabled)
            cl_engine_set_num(engine, CL_ENGINE_FORCETODISK, 1);

        if (optget(opts, "PhishingSignatures")->enabled)
            dboptions |= CL_DB_PHISHING;
        else
            logg(LOGG_INFO_NF, "Not loading phishing signatures.\n");

        if (optget(opts, "Bytecode")->enabled) {
            dboptions |= CL_DB_BYTECODE;
            if ((opt = optget(opts, "BytecodeSecurity"))->enabled) {
                enum bytecode_security s;

                if (!strcmp(opt->strarg, "TrustSigned")) {
                    s = CL_BYTECODE_TRUST_SIGNED;
                    logg(LOGG_INFO_NF, "Bytecode: Security mode set to \"TrustSigned\".\n");
                } else if (!strcmp(opt->strarg, "Paranoid")) {
                    s = CL_BYTECODE_TRUST_NOTHING;
                    logg(LOGG_INFO_NF, "Bytecode: Security mode set to \"Paranoid\".\n");
                } else {
                    logg(LOGG_ERROR, "Unable to parse bytecode security setting:%s\n",
                         opt->strarg);
                    ret = 1;
                    break;
                }

                if ((ret = cl_engine_set_num(engine, CL_ENGINE_BYTECODE_SECURITY, s))) {
                    logg(LOGG_WARNING, "Invalid bytecode security setting %s: %s\n", opt->strarg, cl_strerror(ret));
                    ret = 1;
                    break;
                }
            }
            if ((opt = optget(opts, "BytecodeUnsigned"))->enabled) {
                dboptions |= CL_DB_BYTECODE_UNSIGNED;
                logg(LOGG_INFO_NF, "Bytecode: Enabled support for unsigned bytecode.\n");
            }

            if ((opt = optget(opts, "BytecodeMode"))->enabled) {
                enum bytecode_mode mode;

                if (!strcmp(opt->strarg, "ForceJIT"))
                    mode = CL_BYTECODE_MODE_JIT;
                else if (!strcmp(opt->strarg, "ForceInterpreter"))
                    mode = CL_BYTECODE_MODE_INTERPRETER;
                else if (!strcmp(opt->strarg, "Test"))
                    mode = CL_BYTECODE_MODE_TEST;
                else
                    mode = CL_BYTECODE_MODE_AUTO;
                cl_engine_set_num(engine, CL_ENGINE_BYTECODE_MODE, mode);
            }

            if ((opt = optget(opts, "BytecodeTimeout"))->enabled) {
                cl_engine_set_num(engine, CL_ENGINE_BYTECODE_TIMEOUT, opt->numarg);
            }
        } else {
            logg(LOGG_INFO_NF, "Bytecode support disabled.\n");
        }

        if (optget(opts, "PhishingScanURLs")->enabled)
            dboptions |= CL_DB_PHISHING_URLS;
        else
            logg(LOGG_INFO_NF, "Disabling URL based phishing detection.\n");

        if (optget(opts, "DevACOnly")->enabled) {
            logg(LOGG_INFO_NF, "Only using the A-C matcher.\n");
            cl_engine_set_num(engine, CL_ENGINE_AC_ONLY, 1);
        }

        if ((opt = optget(opts, "DevACDepth"))->enabled) {
            cl_engine_set_num(engine, CL_ENGINE_AC_MAXDEPTH, opt->numarg);
            logg(LOGG_INFO_NF, "Max A-C depth set to %u\n", (unsigned int)opt->numarg);
        }

#ifdef _WIN32
        if (optget(opts, "daemon")->enabled) {
            cl_engine_set_clcb_sigload(engine, svc_checkpoint, NULL);
            svc_register("clamd");
        }
#endif
        if (optget(opts, "fail-if-cvd-older-than")->enabled) {
            if (check_if_cvd_outdated(dbdir, optget(opts, "fail-if-cvd-older-than")->numarg) != CL_SUCCESS) {
                ret = 1;
                break;
            }
        }

        if (optget(opts, "FIPSCryptoHashLimits")->enabled) {
            dboptions |= CL_DB_FIPS_LIMITS;
            cl_engine_set_num(engine, CL_ENGINE_FIPS_LIMITS, 1);
            logg(LOGG_INFO_NF, "FIPS crypto hash limits enabled.\n");
        }

        if ((ret = cl_load(dbdir, engine, &sigs, dboptions))) {
            logg(LOGG_ERROR, "%s\n", cl_strerror(ret));
            ret = 1;
            break;
        }

        if ((ret = statinidir(dbdir))) {
            logg(LOGG_ERROR, "%s\n", cl_strerror(ret));
            ret = 1;
            break;
        }

        if (optget(opts, "DisableCertCheck")->enabled)
            cl_engine_set_num(engine, CL_ENGINE_DISABLE_PE_CERTS, 1);

        logg(LOGG_INFO_NF, "Loaded %u signatures.\n", sigs);

        /* pcre engine limits - required for cl_engine_compile */
        if ((opt = optget(opts, "PCREMatchLimit"))->active) {
            if ((ret = cl_engine_set_num(engine, CL_ENGINE_PCRE_MATCH_LIMIT, opt->numarg))) {
                logg(LOGG_ERROR, "cli_engine_set_num(PCREMatchLimit) failed: %s\n", cl_strerror(ret));
                cl_engine_free(engine);
                return 1;
            }
        }

        if ((opt = optget(opts, "PCRERecMatchLimit"))->active) {
            if ((ret = cl_engine_set_num(engine, CL_ENGINE_PCRE_RECMATCH_LIMIT, opt->numarg))) {
                logg(LOGG_ERROR, "cli_engine_set_num(PCRERecMatchLimit) failed: %s\n", cl_strerror(ret));
                cl_engine_free(engine);
                return 1;
            }
        }

        if ((ret = cl_engine_compile(engine)) != 0) {
            logg(LOGG_ERROR, "Database initialization error: %s\n", cl_strerror(ret));
            ret = 1;
            break;
        }

        if (tcpsock || num_fd > 0) {
            opt = optget(opts, "TCPAddr");
            if (opt->enabled) {
                int breakout = 0;

                while (opt && opt->strarg) {
                    char *ipaddr = (!strcmp(opt->strarg, "all") ? NULL : opt->strarg);

                    if (tcpserver(&lsockets, &nlsockets, ipaddr, opts) == -1) {
                        ret      = 1;
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
        if (localsock && num_fd == 0) {
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

            if (optget(opts, "LocalSocketGroup")->enabled) {
                char *gname    = optget(opts, "LocalSocketGroup")->strarg, *end;
                gid_t sock_gid = strtol(gname, &end, 10);

                if (*end) {
                    struct group *pgrp = getgrnam(gname);

                    if (!pgrp) {
                        logg(LOGG_ERROR, "Unknown group %s\n", gname);
                        ret = 1;
                        break;
                    }

                    sock_gid = pgrp->gr_gid;
                }
                if (chown(optget(opts, "LocalSocket")->strarg, -1, sock_gid)) {
                    logg(LOGG_ERROR, "Failed to change socket ownership to group %s\n", gname);
                    ret = 1;
                    break;
                }
            }
            if (optget(opts, "LocalSocketMode")->enabled) {
                char *end;

                sock_mode = strtol(optget(opts, "LocalSocketMode")->strarg, &end, 8);

                if (*end) {
                    logg(LOGG_ERROR, "Invalid LocalSocketMode %s\n", optget(opts, "LocalSocketMode")->strarg);
                    ret = 1;
                    break;
                }
            } else {
                sock_mode = 0777 /* & ~umsk*/; /* conservative default: umask was 0 in clamd < 0.96 */
            }

            if (chmod(optget(opts, "LocalSocket")->strarg, sock_mode & 0666)) {
                logg(LOGG_ERROR, "Cannot set socket permission for %s to %3o\n", optget(opts, "LocalSocket")->strarg, sock_mode & 0666);
                ret = 1;
                break;
            }

            nlsockets++;
        }

        /* check for local sockets passed by systemd */
        if (num_fd > 0) {
            int *t;
            t = realloc(lsockets, sizeof(int) * (nlsockets + 1));
            if (!(t)) {
                ret = 1;
                break;
            }
            lsockets = t;

            lsockets[nlsockets] = localserver(opts);
            if (lsockets[nlsockets] == -1) {
                ret = 1;
                break;
            } else if (lsockets[nlsockets] > 0) {
                nlsockets++;
            }
        }

        if (0 == foreground) {
            if (!debug_mode) {
                if (chdir("/") == -1) {
                    logg(LOGG_WARNING, "Can't change current working directory to root\n");
                }
            }

#ifndef _WIN32

            /*Since some of the logging is written to stderr, and some of it
             * is written to a log file, close stdin, stderr, and stdout
             * now, since everything is initialized.*/

            /*signal the parent process.*/
            if (parentPid != getpid()) {
                daemonize_signal_parent(parentPid);
            }
#endif
        }

#elif defined(_WIN32)
        if (optget(opts, "service-mode")->enabled) {
            cl_engine_set_clcb_sigload(engine, NULL, NULL);
            svc_ready();
        }
#endif

        if (nlsockets == 0) {
            logg(LOGG_ERROR, "Not listening on any interfaces\n");
            ret = 1;
            break;
        }

        ret = recvloop(lsockets, nlsockets, engine, dboptions, opts);

    } while (0);

    if (num_fd == 0) {
        logg(LOGG_DEBUG, "Closing the main socket%s.\n", (nlsockets > 1) ? "s" : "");

        for (i = 0; i < nlsockets; i++) {
            closesocket(lsockets[i]);
        }
#ifndef _WIN32
        if (nlsockets && localsock) {
            opt = optget(opts, "LocalSocket");

            if (unlink(opt->strarg) == -1)
                logg(LOGG_ERROR, "Can't unlink the socket file %s\n", opt->strarg);
            else
                logg(LOGG_INFO, "Socket file removed.\n");
        }
#endif
    }

    free(lsockets);

    logg_close();
    optfree(opts);

    return ret;
}

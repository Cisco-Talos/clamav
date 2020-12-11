/*
 *  Copyright (C) 2013-2020 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#ifndef _WIN32
#include <sys/wait.h>
#endif
#include <sys/stat.h>
#include <fcntl.h>
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#ifdef HAVE_GRP_H
#include <grp.h>
#endif

#if defined(USE_SYSLOG) && !defined(C_AIX)
#include <syslog.h>
#endif

#include "target.h"

// libclamav
#include "clamav.h"
#include "others.h"
#include "str.h"

// shared
#include "optparser.h"
#include "output.h"
#include "misc.h"

// libfreshclam
#include "libfreshclam.h"

#include "execute.h"
#include "notify.h"

#define DEFAULT_SERVER_PORT 443

int g_sigchildWait                      = 1;
short g_terminate                       = 0;
short g_foreground                      = -1;
char g_freshclamTempDirectory[PATH_MAX] = {0};

typedef struct fc_ctx_ {
    uint32_t bTestDatabases;
    uint32_t bBytecodeEnabled;
} fc_ctx;

static void
sighandler(int sig)
{
    switch (sig) {
#ifdef SIGCHLD
        case SIGCHLD:
            if (g_sigchildWait)
                waitpid(-1, NULL, WNOHANG);
            g_active_children--;
            break;
#endif
#ifdef SIGPIPE
        case SIGPIPE:
            /* no action, app will get EPIPE */
            break;
#endif
#ifdef SIGALRM
        case SIGALRM:
            g_terminate = -1;
            break;
#endif
#ifdef SIGUSR1
        case SIGUSR1:
            g_terminate = -1;
            break;
#endif
#ifdef SIGHUP
        case SIGHUP:
            g_terminate = -2;
            break;
#endif
        default:
            if (*g_freshclamTempDirectory)
                cli_rmdirs(g_freshclamTempDirectory);
            logg("Update process terminated\n");
            exit(0);
    }

    return;
}

static void help(void)
{
    printf("\n");
    printf("                      Clam AntiVirus: Database Updater %s\n", get_version());
    printf("           By The ClamAV Team: https://www.clamav.net/about.html#credits\n");
    printf("           (C) 2020 Cisco Systems, Inc.\n");
    printf("\n");
    printf("    freshclam [options]\n");
    printf("\n");
    printf("    --help               -h              Show this help\n");
    printf("    --version            -V              Print version number and exit\n");
    printf("    --verbose            -v              Be verbose\n");
    printf("    --debug                              Enable debug messages\n");
    printf("    --quiet                              Only output error messages\n");
    printf("    --no-warnings                        Don't print and log warnings\n");
    printf("    --stdout                             Write to stdout instead of stderr. Does not affect 'debug' messages.\n");
    printf("    --show-progress                      Show download progress percentage\n");
    printf("\n");
    printf("    --config-file=FILE                   Read configuration from FILE.\n");
    printf("    --log=FILE           -l FILE         Log into FILE\n");
    printf("    --daemon             -d              Run in daemon mode\n");
    printf("    --pid=FILE           -p FILE         Save daemon's pid in FILE\n");
#ifndef _WIN32
    printf("    --foreground         -F              Don't fork into background (for use in daemon mode).\n");
    printf("    --user=USER          -u USER         Run as USER\n");
#endif
    printf("    --no-dns                             Force old non-DNS verification method\n");
    printf("    --checks=#n          -c #n           Number of checks per day, 1 <= n <= 50\n");
    printf("    --datadir=DIRECTORY                  Download new databases into DIRECTORY\n");
    printf("    --daemon-notify[=/path/clamd.conf]   Send RELOAD command to clamd\n");
    printf("    --local-address=IP   -a IP           Bind to IP for HTTP downloads\n");
    printf("    --on-update-execute=COMMAND          Execute COMMAND after successful update\n");
    printf("    --on-error-execute=COMMAND           Execute COMMAND if errors occurred\n");
    printf("    --on-outdated-execute=COMMAND        Execute COMMAND when software is outdated\n");
    printf("    --update-db=DBNAME                   Only update database DBNAME\n");
    printf("\n");
}

static void libclamav_msg_callback(enum cl_msg severity, const char *fullmsg, const char *msg, void *ctx)
{
    UNUSEDPARAM(fullmsg);
    UNUSEDPARAM(ctx);

    switch (severity) {
        case CL_MSG_ERROR:
            logg("^[LibClamAV] %s", msg);
            break;
        case CL_MSG_WARN:
            logg("~[LibClamAV] %s", msg);
            break;
        default:
            logg("*[LibClamAV] %s", msg);
            break;
    }
}

static void libclamav_msg_callback_quiet(enum cl_msg severity, const char *fullmsg, const char *msg, void *ctx)
{
    UNUSEDPARAM(fullmsg);
    UNUSEDPARAM(ctx);

    switch (severity) {
        case CL_MSG_ERROR:
            logg("^[LibClamAV] %s", msg);
            break;
        default:
            break;
    }
}

fc_error_t download_complete_callback(const char *dbFilename, void *context)
{
    fc_error_t status = FC_EARG;
    fc_error_t ret;
    fc_ctx *fc_context = (fc_ctx *)context;

#ifndef _WIN32
    char firstline[256];
    char lastline[256];
    int pipefd[2];
    pid_t pid;
    int stat_loc = 0;
    int waitpidret;
#endif

    if ((NULL == context) || (NULL == dbFilename)) {
        logg("^Invalid arguments to download_complete_callback.\n");
        goto done;
    }

    logg("*download_complete_callback: Download complete for database : %s\n", dbFilename);
    logg("*download_complete_callback:   fc_context->bTestDatabases   : %u\n", fc_context->bBytecodeEnabled);
    logg("*download_complete_callback:   fc_context->bBytecodeEnabled : %u\n", fc_context->bBytecodeEnabled);

    logg("Testing database: '%s' ...\n", dbFilename);

    if (fc_context->bTestDatabases) {
#ifdef _WIN32

        __try {
            ret = fc_test_database(dbFilename, fc_context->bBytecodeEnabled);
        } __except (logg("!Exception during database testing, code %08x\n",
                         GetExceptionCode()),
                    EXCEPTION_CONTINUE_SEARCH) {
            ret = FC_ETESTFAIL;
        }
        if (FC_SUCCESS != ret) {
            logg("^Database load exited with \"%s\" (%d)\n", fc_strerror(ret), ret);
            status = FC_ETESTFAIL;
            goto done;
        }

#else

        if (pipe(pipefd) == -1) {
            /*
             * Failed to create pipe.
             * Test database without using pipe & child process.
             */
            logg("^pipe() failed: %s\n", strerror(errno));
            ret = fc_test_database(dbFilename, fc_context->bBytecodeEnabled);
            if (FC_SUCCESS != ret) {
                logg("^Database load exited with \"%s\" (%d)\n", fc_strerror(ret), ret);
                status = FC_ETESTFAIL;
                goto done;
            }
        } else {
            switch (pid = fork()) {
                case -1: {
                    /*
                     * Fork failed.
                     * Test database without using pipe & child process.
                     */
                    close(pipefd[0]);
                    close(pipefd[1]);
                    logg("^fork() to test database failed: %s\n", strerror(errno));

                    /* Test the database without forking. */
                    ret = fc_test_database(dbFilename, fc_context->bBytecodeEnabled);
                    if (FC_SUCCESS != ret) {
                        logg("^Database load exited with \"%s\" (%d)\n", fc_strerror(ret), ret);
                        status = FC_ETESTFAIL;
                        goto done;
                    }
                    break;
                }
                case 0: {
                    /*
                     * Child process.
                     */
                    close(pipefd[0]);

                    /* Redirect stderr to the pipe for the parent process */
                    if (dup2(pipefd[1], 2) == -1) {
                        logg("^dup2() call to redirect stderr to pipe failed: %s\n", strerror(errno));
                    }

                    /* Test the database */
                    status = fc_test_database(dbFilename, fc_context->bBytecodeEnabled);
                    exit(status);
                }
                default: {
                    /*
                     * Original/parent process.
                     */
                    FILE *pipeHandle = NULL;

                    /* read first / last line printed by child */
                    close(pipefd[1]);
                    pipeHandle   = fdopen(pipefd[0], "r");
                    firstline[0] = 0;
                    lastline[0]  = 0;
                    do {
                        if (!fgets(firstline, sizeof(firstline), pipeHandle))
                            break;
                        /* ignore warning messages, otherwise the outdated warning will
                         * make us miss the important part of the error message */
                    } while (!strncmp(firstline, "LibClamAV Warning:", 18));
                    /* must read entire output, child doesn't like EPIPE */
                    while (fgets(lastline, sizeof(firstline), pipeHandle)) {
                        /* print the full output only when LogVerbose or -v is given */
                        logg("*%s", lastline);
                    }
                    fclose(pipeHandle);
                    pipeHandle = NULL;

                    while ((-1 == (waitpidret = waitpid(pid, &stat_loc, 0))) && (errno == EINTR)) {
                        continue;
                    }

                    if ((waitpidret == -1) && (errno != ECHILD))
                        logg("^waitpid() failed: %s\n", strerror(errno));

                    /* Strip trailing whitespace from child error output */
                    cli_chomp(firstline);
                    cli_chomp(lastline);

                    if (firstline[0]) {
                        /* The child process output some error messages */
                        logg("^Stderr output from database load : %s%s%s\n", firstline, lastline[0] ? " [...] " : "", lastline);
                    }

                    if (WIFEXITED(stat_loc)) {
                        ret = (fc_error_t)WEXITSTATUS(stat_loc);
                        if (FC_SUCCESS != ret) {
                            logg("^Database load exited with \"%s\" (%d)\n", fc_strerror(ret), ret);
                            status = FC_ETESTFAIL;
                            goto done;
                        }

                        if (firstline[0])
                            logg("^Database successfully loaded, but there is stderr output\n");

                    } else if (WIFSIGNALED(stat_loc)) {
                        logg("!Database load killed by signal %d\n", WTERMSIG(stat_loc));
                        status = FC_ETESTFAIL;
                        goto done;
                    } else {
                        logg("^Unknown status from wait: %d\n", stat_loc);
                        status = FC_ETESTFAIL;
                        goto done;
                    }
                }
            }
        }
#endif
    }

    status = FC_SUCCESS;

done:

    if (FC_SUCCESS == status) {
        logg("Database test passed.\n");
    } else {
        logg("!Database test FAILED.\n");
    }

    g_sigchildWait = 1;

    return status;
}

/**
 * @brief Adapt server strings to protocol://server:port format.
 *
 * IPv6 addresses must be enclosed with square brackets.
 * Port number and port number delimiter (:) are optional.
 * If port number is omitted, 443 will be assumed.
 *
 * Example server strings:
 *  - database.clamav.net
 *  - http://db.sample.net:5678
 *  - [2001::100a]
 *  - https://[2001:db8:1f70::999:de8:7648:6e8]:7890
 *
 * @param server            Server string
 * @param defaultProtocol   Default protocol if not already specified. Eg: "https"
 * @param defaultPort       Default port if not already specified. Eg: 443
 * @param serverUrl         [out] A malloced string in the protocol://server:port format.
 * @return fc_error_t       FC_SUCCESS if success.
 * @return fc_error_t       FC_EARG if invalid args.
 * @return fc_error_t       FC_EMEM if malloc failed.
 * @return fc_error_t       FC_ECONFIG if a parsing issue occured.
 */
static fc_error_t get_server_node(
    const char *server,
    char *defaultProtocol,
    char **serverUrl)
{
    fc_error_t status = FC_EARG;

    char *url     = NULL;
    size_t urlLen = 0;

    if ((NULL == server) || (NULL == defaultProtocol) || (NULL == serverUrl)) {
        mprintf("!get_server_node: Invalid args!\n");
        goto done;
    }

    *serverUrl = NULL;

    /*
     * Ensure that URL contains protocol.
     */
    if (!strncmp(server, "db.", 3) && strstr(server, ".clamav.net")) {
        url = cli_strdup("https://database.clamav.net");
        if (NULL == url) {
            logg("!get_server_node: Failed to duplicate string for database.clamav.net url.\n");
            status = FC_EMEM;
            goto done;
        }
    } else if (!strstr(server, "://")) {
        urlLen = strlen(defaultProtocol) + strlen("://") + strlen(server);
        url    = malloc(urlLen + 1);
        if (NULL == url) {
            logg("!get_server_node: Failed to allocate memory for server url.\n");
            status = FC_EMEM;
            goto done;
        }
        snprintf(url, urlLen + 1, "%s://%s", defaultProtocol, server);
    } else {
        urlLen = strlen(server);
        url    = cli_strdup(server);
        if (NULL == url) {
            logg("!get_server_node: Failed to duplicate string for server url.\n");
            status = FC_EMEM;
            goto done;
        }
    }

    *serverUrl = url;
    status     = FC_SUCCESS;

done:
    return status;
}

/**
 * @brief Add string to list of strings.
 *
 * @param item          string to add to list.
 * @param stringList    [in/out] String list to add string to.
 * @param nListItems    [in/out] Number of strings in list.
 * @return fc_error_t   FC_SUCCESS if success.
 * @return fc_error_t   FC_EARG if invalid args passed to function.
 * @return fc_error_t   FC_EMEM if failed to allocate memory.
 */
static fc_error_t string_list_add(const char *item, char ***stringList, uint32_t *nListItems)
{
    fc_error_t status = FC_EARG;

    char **newList  = NULL;
    uint32_t nItems = 0;

    if ((NULL == item) || (NULL == stringList) || (NULL == nListItems)) {
        mprintf("!string_list_add: Invalid arguments.\n");
        goto done;
    }

    nItems  = *nListItems + 1;
    newList = (char **)cli_realloc(*stringList, nItems * sizeof(char *));
    if (newList == NULL) {
        mprintf("!string_list_add: Failed to allocate memory for optional database list entry.\n");
        status = FC_EMEM;
        goto done;
    }

    *stringList = newList;

    newList[nItems - 1] = cli_strdup(item);
    if (newList[nItems - 1] == NULL) {
        mprintf("!string_list_add: Failed to allocate memory for optional database list item.\n");
        status = FC_EMEM;
        goto done;
    }

    *nListItems = nItems;
    status      = FC_SUCCESS;

done:

    return status;
}

/**
 * @brief Convenience function to free strings in an array of strings.
 *
 * Will also free the list itself.
 *
 * @param stringList
 * @param nListItems
 */
static void free_string_list(char **stringList, uint32_t nListItems)
{
    uint32_t i;

    if (NULL != stringList) {
        for (i = 0; i < nListItems; i++) {
            if (stringList[i] != NULL) {
                free(stringList[i]);
                stringList[i] = NULL;
            }
        }

        free(stringList);
    }
}

/**
 * @brief Get the database server list object
 *
 * @param opts          Freshclam options struct.
 * @param serverList    [out] List of servers.
 * @param nServers      [out] Number of servers in list.
 * @param bPrivate      [out] Non-zero if PrivateMirror servers were selected.
 * @return fc_error_t
 */
static fc_error_t get_database_server_list(
    struct optstruct *opts,
    char ***serverList,
    uint32_t *nServers,
    int *bPrivate)
{
    fc_error_t ret;
    fc_error_t status = FC_EARG;
    const struct optstruct *opt;
    char **servers      = NULL;
    uint32_t numServers = 0;

    if ((NULL == opts) || (NULL == serverList) || (NULL == nServers) || (NULL == bPrivate)) {
        mprintf("!get_database_server_list: Invalid args!\n");
        goto done;
    }

    *serverList = NULL;
    *nServers   = 0;
    *bPrivate   = 0;

    if ((opt = optget(opts, "PrivateMirror"))->enabled) {
        /* Config specifies at least one PrivateMirror.
         * Ignore the DatabaseMirrors. */
        *bPrivate = 1;

        do {
            char *serverUrl = NULL;

            if (cli_strbcasestr(opt->strarg, ".clamav.net")) {
                logg("!The PrivateMirror config option may not include servers under *.clamav.net.\n");
                status = FC_ECONFIG;
                goto done;
            }

            if (FC_SUCCESS != (ret = get_server_node(opt->strarg, "http", &serverUrl))) {
                mprintf("!get_database_server_list: Failed to read PrivateMirror server %s", opt->strarg);
                status = ret;
                goto done;
            }

            if (FC_SUCCESS != (ret = string_list_add(serverUrl, &servers, &numServers))) {
                free(serverUrl);

                mprintf("!get_database_server_list: Failed to add string to list.\n");
                status = ret;
                goto done;
            }
            free(serverUrl);
        } while (NULL != (opt = opt->nextarg));
    } else {
        /* Check for DatabaseMirrors. */
        if (!(opt = optget(opts, "DatabaseMirror"))->enabled) {
            /* No DatabaseMirror configured. Fail out. */
            logg("!No DatabaseMirror or PrivateMirror servers set in freshclam config file.\n");
            status = FC_ECONFIG;
            goto done;
        }

        do {
            char *serverUrl = NULL;

            if (FC_SUCCESS != (ret = get_server_node(opt->strarg, "https", &serverUrl))) {
                mprintf("!get_database_server_list: Failed to parse DatabaseMirror server %s.", opt->strarg);
                status = ret;
                goto done;
            }

            if (FC_SUCCESS != (ret = string_list_add(serverUrl, &servers, &numServers))) {
                free(serverUrl);

                mprintf("!get_database_server_list: Failed to add string to list.\n");
                status = ret;
                goto done;
            }
            free(serverUrl);
        } while (NULL != (opt = opt->nextarg));
    }

    *serverList = servers;
    *nServers   = numServers;
    status      = FC_SUCCESS;

done:

    if (FC_SUCCESS != status) {
        free_string_list(servers, numServers);
    }

    return status;
}

/**
 * @brief Get a list of strings for a given repeatable opt argument.
 *
 * @param opt           optstruct of repeatable argument to collect in a list.
 * @param stringList    [out] String list.
 * @param nListItems    [out] Number of strings in list.
 * @return fc_error_t   FC_SUCCESS if success.
 * @return fc_error_t   FC_EARG if invalid args passed to function.
 * @return fc_error_t   FC_EMEM if failed to allocate memory.
 */
static fc_error_t get_string_list(const struct optstruct *opt, char ***stringList, uint32_t *nListItems)
{
    fc_error_t ret;
    fc_error_t status = FC_EARG;

    char **newList  = NULL;
    uint32_t nItems = 0;

    if ((NULL == opt) || (NULL == stringList) || (NULL == nListItems)) {
        mprintf("!get_string_list: Invalid arguments.\n");
        goto done;
    }

    *stringList = NULL;
    *nListItems = 0;

    /* handle extra dbs */
    if (opt->enabled) {
        while (opt) {
            if (FC_SUCCESS != (ret = string_list_add(opt->strarg, stringList, nListItems))) {
                mprintf("!get_string_list: Failed to add string to list.\n");
                status = ret;
                goto done;
            }
            opt = opt->nextarg;
        }
    }

    status = FC_SUCCESS;

done:

    if (FC_SUCCESS != status) {
        free_string_list(newList, nItems);
    }

    return status;
}

static fc_error_t initialize(struct optstruct *opts)
{
    fc_error_t ret;
    fc_error_t status = FC_EARG;
    cl_error_t cl_init_retcode;
    fc_config fcConfig;
    char *tempDirectory                = NULL;
    const struct optstruct *logFileOpt = NULL;

    STATBUF statbuf;

    memset(&fcConfig, 0, sizeof(fc_config));

    if (NULL == opts) {
        mprintf("!initialize: Invalid arguments.\n");
        goto done;
    }

    /* Now that the config has been parsed,
       check Foreground again if not already determined. */
    if (g_foreground == -1) {
        if (optget(opts, "Foreground")->enabled) {
            g_foreground = 1;
        } else {
            g_foreground = 0;
        }
    }

    /*
     * Verify that the database directory exists.
     * Create database directory if missing.
     */
    fcConfig.databaseDirectory = optget(opts, "DatabaseDirectory")->strarg;

    if (LSTAT(fcConfig.databaseDirectory, &statbuf) == -1) {
#ifdef HAVE_PWD_H
        struct passwd *user;
#endif

        logg("Creating missing database directory: %s\n", fcConfig.databaseDirectory);

        if (0 != mkdir(fcConfig.databaseDirectory, 0755)) {
            logg("!Failed to create database directory: %s\n", fcConfig.databaseDirectory);
            logg("Manually prepare the database directory, or re-run freshclam with higher privileges.\n");
            status = FC_EDBDIRACCESS;
            goto done;
        }

#ifdef HAVE_PWD_H
        if (!geteuid()) {
            /* Running as root user, will assign ownership of database directory to DatabaseOwner */
            errno = 0;
            if ((user = getpwnam(optget(opts, "DatabaseOwner")->strarg)) == NULL) {
                logg("ERROR: Failed to get information about user \"%s\".\n",
                     optget(opts, "DatabaseOwner")->strarg);
                if (errno == 0) {
                    logg("Create the \"%s\" user account for freshclam to use, or set the DatabaseOwner config option in freshclam.conf to a different user.\n",
                         optget(opts, "DatabaseOwner")->strarg);
                    logg("For more information, see https://www.clamav.net/documents/installing-clamav-on-unix-linux-macos-from-source\n");
                } else {
                    logg("An unexpected error occurred when attempting to query the \"%s\" user account.\n",
                         optget(opts, "DatabaseOwner")->strarg);
                }
                status = FC_EDBDIRACCESS;
                goto done;
            }

            if (chown(fcConfig.databaseDirectory, user->pw_uid, user->pw_gid)) {
                logg("!Failed to change database directory ownership to user %s. Error: %s\n", optget(opts, "DatabaseOwner")->strarg, strerror(errno));
                status = FC_EDBDIRACCESS;
                goto done;
            }

            logg("Assigned ownership of database directory to user \"%s\".\n", optget(opts, "DatabaseOwner")->strarg);
        }
#endif
    }

#ifdef HAVE_PWD_H
    /* Drop database privileges here if we are not planning on daemonizing. */
    if (!optget(opts, "daemon")->enabled) {
        /*
         * freshclam shouldn't work with root privileges.
         * Drop privileges to the DatabaseOwner user, if specified.
         * Pass NULL for the log file name, because it hasn't been created yet.
         */
        ret = drop_privileges(optget(opts, "DatabaseOwner")->strarg, NULL);
        if (ret) {
            logg("!Failed to switch to %s user.\n", optget(opts, "DatabaseOwner")->strarg);
            status = FC_ECONFIG;
            goto done;
        }
    }
#endif /* HAVE_PWD_H */

    /*
     * Initilize libclamav.
     */
    if (CL_SUCCESS != (cl_init_retcode = cl_init(CL_INIT_DEFAULT))) {
        mprintf("!initialize: Can't initialize libclamav: %s\n", cl_strerror(cl_init_retcode));
        status = FC_EINIT;
        goto done;
    }

    /*
     * Identify libfreshclam config options.
     */
    /* Set libclamav Message and [file-based] Logging option flags.
       mprintf and logg options are also directly set, as they are also
       used in freshclam (not only used in libfreshclam) */
    if (optget(opts, "Debug")->enabled || optget(opts, "debug")->enabled)
        fcConfig.msgFlags |= FC_CONFIG_MSG_DEBUG;

    if ((optget(opts, "verbose")->enabled) ||
        (optget(opts, "LogVerbose")->enabled)) {
        fcConfig.msgFlags |= FC_CONFIG_MSG_VERBOSE;
        fcConfig.logFlags |= FC_CONFIG_LOG_VERBOSE;
    }

    if (optget(opts, "quiet")->enabled) {
        fcConfig.msgFlags |= FC_CONFIG_MSG_QUIET;
        /* Silence libclamav messages. */
        cl_set_clcb_msg(libclamav_msg_callback_quiet);
    } else {
        /* Enable libclamav messages, with [LibClamAV] message prefix. */
        cl_set_clcb_msg(libclamav_msg_callback);
    }

    if (optget(opts, "no-warnings")->enabled) {
        fcConfig.msgFlags |= FC_CONFIG_MSG_NOWARN;
        fcConfig.logFlags |= FC_CONFIG_LOG_NOWARN;
    }

    if (optget(opts, "stdout")->enabled) {
        fcConfig.msgFlags |= FC_CONFIG_MSG_STDOUT;
    }

    if (optget(opts, "show-progress")->enabled) {
        fcConfig.msgFlags |= FC_CONFIG_MSG_SHOWPROGRESS;
    }

    if (optget(opts, "LogTime")->enabled) {
        fcConfig.logFlags |= FC_CONFIG_LOG_TIME;
    }
    if (optget(opts, "LogFileMaxSize")->numarg && optget(opts, "LogRotate")->enabled) {
        fcConfig.logFlags |= FC_CONFIG_LOG_ROTATE;
    }
    if (optget(opts, "LogSyslog")->enabled)
        fcConfig.logFlags |= FC_CONFIG_LOG_SYSLOG;

    logFileOpt = optget(opts, "UpdateLogFile");
    if (logFileOpt->enabled) {
        fcConfig.logFile = logFileOpt->strarg;
    }
    if (optget(opts, "LogFileMaxSize")->numarg) {
        fcConfig.maxLogSize = optget(opts, "LogFileMaxSize")->numarg;
    }

#if defined(USE_SYSLOG) && !defined(C_AIX)
    if (optget(opts, "LogSyslog")->enabled) {
        if (optget(opts, "LogFacility")->enabled) {
            fcConfig.logFacility = optget(opts, "LogFacility")->strarg;
        }
    }
#endif

    if ((optget(opts, "LocalIPAddress"))->enabled)
        fcConfig.localIP = (optget(opts, "LocalIPAddress"))->strarg;

    /* Select a path for the temp directory:  databaseDirectory/tmp */
    tempDirectory          = cli_gentemp_with_prefix(fcConfig.databaseDirectory, "tmp");
    fcConfig.tempDirectory = tempDirectory;

    /* Store the path of the temp directory so we can delete it later. */
    strncpy(g_freshclamTempDirectory, fcConfig.tempDirectory, sizeof(g_freshclamTempDirectory));
    g_freshclamTempDirectory[sizeof(g_freshclamTempDirectory) - 1] = '\0';

#ifndef _WIN32
    /*
     * If clamd.conf includes a HTTPProxyPassword,...
     * ...make sure that permissions on the clamd.conf file aren't just wide open.
     * If they are, fail out and warn the user so they will fix it.
     */
    if (optget(opts, "HTTPProxyPassword")->enabled) {
        STATBUF statbuf;
        const char *cfgfile = NULL;

        cfgfile = optget(opts, "config-file")->strarg;
        if (CLAMSTAT(cfgfile, &statbuf) == -1) {
            logg("^Can't stat %s (critical error)\n", cfgfile);
            status = FC_ECONFIG;
            goto done;
        }
        if (statbuf.st_mode & (S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH)) {
            logg("^Insecure permissions (for HTTPProxyPassword): %s must have no more than 0700 permissions.\n", cfgfile);
            status = FC_ECONFIG;
            goto done;
        }
    }
#endif

    /* Initialize proxy settings */
    if (optget(opts, "HTTPProxyServer")->enabled) {
        fcConfig.proxyServer = optget(opts, "HTTPProxyServer")->strarg;
        if (strncasecmp(fcConfig.proxyServer, "http://", strlen("http://")) == 0)
            fcConfig.proxyServer += strlen("http://");

        if (optget(opts, "HTTPProxyUsername")->enabled) {
            fcConfig.proxyUsername = optget(opts, "HTTPProxyUsername")->strarg;
            if (optget(opts, "HTTPProxyPassword")->enabled) {
                fcConfig.proxyPassword = optget(opts, "HTTPProxyPassword")->strarg;
            } else {
                logg("HTTPProxyUsername requires HTTPProxyPassword\n");
                status = FC_ECONFIG;
                goto done;
            }
        }
        if (optget(opts, "HTTPProxyPort")->enabled)
            fcConfig.proxyPort = (uint16_t)optget(opts, "HTTPProxyPort")->numarg;
        logg("Connecting via %s\n", fcConfig.proxyServer);
    }

    if (optget(opts, "HTTPUserAgent")->enabled)
        fcConfig.userAgent = optget(opts, "HTTPUserAgent")->strarg;

    fcConfig.maxAttempts    = optget(opts, "MaxAttempts")->numarg;
    fcConfig.connectTimeout = optget(opts, "ConnectTimeout")->numarg;
    fcConfig.requestTimeout = optget(opts, "ReceiveTimeout")->numarg;

    fcConfig.bCompressLocalDatabase = optget(opts, "CompressLocalDatabase")->enabled;

    /*
     * Initilize libfreshclam.
     */
    if (FC_SUCCESS != (ret = fc_initialize(&fcConfig))) {
        mprintf("!initialize: libfreshclam init failed.\n");
        status = ret;
        goto done;
    }

    /*
     * Set libfreshclam callback functions.
     */
    fc_set_fccb_download_complete(download_complete_callback);

    status = FC_SUCCESS;

done:
    if (NULL != tempDirectory) {
        free(tempDirectory);
    }

    return status;
}

/**
 * @brief Get the official database lists.
 *
 * TODO: Implement system to query list of available standard and optional databases.
 *
 * @param standardDatabases  [out] Standard database string list.
 * @param nStandardDatabases [out] Number of standard databases in list.
 * @param optionalDatabases  [out] Optional database string list.
 * @param nOptionalDatabases [out] Number of optional databases in list.
 * @return fc_error_t        FC_SUCCESS if all databases upddated successfully.
 */
fc_error_t get_official_database_lists(
    char ***standardDatabases,
    uint32_t *nStandardDatabases,
    char ***optionalDatabases,
    uint32_t *nOptionalDatabases)
{
    fc_error_t ret;
    fc_error_t status = FC_EARG;
    uint32_t i;

    const char *hardcodedStandardDatabaseList[] = {"daily", "main", "bytecode"};
    const char *hardcodedOptionalDatabaseList[] = {"safebrowsing", "test"};

    if ((NULL == standardDatabases) || (NULL == nStandardDatabases) || (NULL == optionalDatabases) || (NULL == nOptionalDatabases)) {
        mprintf("!get_official_database_lists: Invalid arguments.\n");
        goto done;
    }

    *standardDatabases  = NULL;
    *nStandardDatabases = 0;
    *optionalDatabases  = NULL;
    *nOptionalDatabases = 0;

    for (i = 0; i < sizeof(hardcodedStandardDatabaseList) / sizeof(hardcodedStandardDatabaseList[0]); i++) {
        if (FC_SUCCESS != (ret = string_list_add(hardcodedStandardDatabaseList[i], standardDatabases, nStandardDatabases))) {
            logg("!Failed to add %s to list of standard databases.\n", hardcodedStandardDatabaseList[i]);
            status = ret;
            goto done;
        }
    }

    for (i = 0; i < sizeof(hardcodedOptionalDatabaseList) / sizeof(hardcodedOptionalDatabaseList[0]); i++) {
        if (FC_SUCCESS != (ret = string_list_add(hardcodedOptionalDatabaseList[i], optionalDatabases, nOptionalDatabases))) {
            logg("!Failed to add %s to list of optional databases.\n", hardcodedOptionalDatabaseList[i]);
            status = ret;
            goto done;
        }
    }

    logg("*Collected lists of official standard and optional databases.\n");

    status = FC_SUCCESS;

done:

    if (FC_SUCCESS != status) {
        if ((NULL != standardDatabases) && (*standardDatabases != NULL) && (nStandardDatabases != NULL)) {
            free_string_list(*standardDatabases, *nStandardDatabases);
            *standardDatabases  = NULL;
            *nStandardDatabases = 0;
        }
        if ((NULL != optionalDatabases) && (*optionalDatabases != NULL) && (nOptionalDatabases != NULL)) {
            free_string_list(*optionalDatabases, *nOptionalDatabases);
            *optionalDatabases  = NULL;
            *nOptionalDatabases = 0;
        }
    }

    return status;
}

/**
 * @brief Select desire databases from standard and optional database lists.
 *
 * Select:
 *   all standard databases excluding those in the opt-out list,
 *   any optional databases includedd in the opt-in list.
 *
 * databaseList should be free'd with free_string_list().
 *
 * @param optInList             List of desired opt-in databases.
 * @param nOptIns               Number of opt-in database strings in list.
 * @param optOutList            List of standard databases that are not desired.
 * @param nOptOuts              Number of opt-out database strings in list.
 * @param databaseList          [out] String list of desired databases.
 * @param nDatabases            [out] Number of desired databases in list.
 * @return fc_error_t
 */
fc_error_t select_from_official_databases(
    char **optInList,
    uint32_t nOptIns,
    char **optOutList,
    uint32_t nOptOuts,
    char ***databaseList,
    uint32_t *nDatabases)
{
    fc_error_t ret;
    fc_error_t status = FC_EARG;

    char **standardDatabases    = NULL;
    uint32_t nStandardDatabases = 0;
    char **optionalDatabases    = NULL;
    uint32_t nOptionalDatabases = 0;
    char **selectedDatabases    = NULL;
    uint32_t nSelectedDatabases = 0;
    uint32_t i;

    if ((NULL == databaseList) || (0 == nDatabases)) {
        mprintf("!select_from_official_databases: Invalid arguments.\n");
        goto done;
    }

    *databaseList = NULL;
    *nDatabases   = 0;

    if ((0 < nOptIns) && (NULL == optInList)) {
        mprintf("!select_from_official_databases: Invalid arguments. Number of opt-in databases does not match empty database array.\n");
        goto done;
    }

    if ((0 < nOptOuts) && (NULL == optOutList)) {
        mprintf("!select_from_official_databases: Invalid arguments. Number of opt-out databases does not match empty database array.\n");
        goto done;
    }

    /*
     * Get lists of available databases.
     */
    if (FC_SUCCESS != (ret = get_official_database_lists(&standardDatabases, &nStandardDatabases, &optionalDatabases, &nOptionalDatabases))) {
        logg("!Failed to get lists of official standard and optional databases.\n");
        status = ret;
        goto done;
    }

    selectedDatabases = cli_calloc(nStandardDatabases + nOptionalDatabases, sizeof(char *));

    /*
     * Select desired standard databases.
     */
    for (i = 0; i < nStandardDatabases; i++) {
        uint32_t j;
        int skip = 0;

        for (j = 0; j < nOptOuts; j++) {
            if (0 == strcasecmp(standardDatabases[i], optOutList[j])) {
                skip = 1;
            }
        }

        if (skip) {
            logg("*Opting out of standard database: %s\n", standardDatabases[i]);
            continue;
        }

        logg("*Selecting standard database: %s\n", standardDatabases[i]);
        if (FC_SUCCESS != (ret = string_list_add(standardDatabases[i], &selectedDatabases, &nSelectedDatabases))) {
            logg("!Failed to add standard database %s to list of selected databases.\n", standardDatabases[i]);
            status = ret;
            goto done;
        }
    }

    /*
     * Select desired optional databases.
     */
    for (i = 0; i < nOptIns; i++) {
        uint32_t j;
        int found = 0;

        for (j = 0; j < nOptionalDatabases; j++) {
            if (0 == strcasecmp(optInList[i], optionalDatabases[j])) {
                found = 1;
            }
        }

        if (!found) {
            logg("^Desired optional database \"%s\" is not available.\n", optInList[i]);
            continue;
        }

        logg("*Selecting optional database: %s\n", optInList[i]);
        if (FC_SUCCESS != (ret = string_list_add(optInList[i], &selectedDatabases, &nSelectedDatabases))) {
            logg("!Failed to add optional database %s to list of selected databases.\n", optInList[i]);
            status = ret;
            goto done;
        }
    }

    *databaseList = selectedDatabases;
    *nDatabases   = nSelectedDatabases;

    status = FC_SUCCESS;

done:

    if (NULL != standardDatabases) {
        free_string_list(standardDatabases, nStandardDatabases);
    }
    if (NULL != optionalDatabases) {
        free_string_list(optionalDatabases, nOptionalDatabases);
    }
    if (FC_SUCCESS != status) {
        if (NULL != selectedDatabases) {
            free_string_list(selectedDatabases, nSelectedDatabases);
        }
    }

    return status;
}

/**
 * @brief Select specific databases provided by standard and optional database lists.
 *
 * Validate that requested databases are available.
 *
 * databaseList should be free'd with free_string_list().
 *
 * @param specificDatabaseList  List of desired databases.
 * @param nSpecificDatabases    Number of databases in list.
 * @param databaseList          [out] String list of desired databases.
 * @param nDatabases            [out] Number of desired databases in list.
 * @param bCustom               [out] "custom" selected.
 * @return fc_error_t
 */
fc_error_t select_specific_databases(
    char **specificDatabaseList,
    uint32_t nSpecificDatabases,
    char ***databaseList,
    uint32_t *nDatabases,
    int *bCustom)
{
    fc_error_t ret;
    fc_error_t status = FC_EARG;

    char **standardDatabases    = NULL;
    uint32_t nStandardDatabases = 0;
    char **optionalDatabases    = NULL;
    uint32_t nOptionalDatabases = 0;
    char **selectedDatabases    = NULL;
    uint32_t nSelectedDatabases = 0;
    uint32_t i;

    if ((NULL == specificDatabaseList) || (0 == nSpecificDatabases) ||
        (NULL == databaseList) || (0 == nDatabases) ||
        (NULL == bCustom)) {
        mprintf("!select_from_official_databases: Invalid arguments.\n");
        goto done;
    }

    *bCustom      = 0;
    *databaseList = NULL;
    *nDatabases   = 0;

    selectedDatabases = cli_calloc(nSpecificDatabases, sizeof(char *));

    /*
     * Get lists of available databases.
     */
    if (FC_SUCCESS != (ret = get_official_database_lists(&standardDatabases, &nStandardDatabases, &optionalDatabases, &nOptionalDatabases))) {
        logg("!Failed to get lists of official standard and optional databases.\n");
        status = ret;
        goto done;
    }

    /*
     * Select desired standard databases.
     */
    for (i = 0; i < nSpecificDatabases; i++) {
        uint32_t j;
        int bFound = 0;

        /* If "custom" requested, then user will be updating unofficial database(s) by URLs. */
        if (0 == strcmp(specificDatabaseList[i], "custom")) {
            *bCustom = 1;
            continue;
        }

        /* Check if provided by standard database list. */
        for (j = 0; j < nStandardDatabases; j++) {
            if (0 == strcmp(specificDatabaseList[i], standardDatabases[j])) {
                if (FC_SUCCESS != (ret = string_list_add(standardDatabases[j], &selectedDatabases, &nSelectedDatabases))) {
                    logg("!Failed to add standard database %s to list of selected databases.\n", standardDatabases[j]);
                    status = ret;
                    goto done;
                }
                bFound = 1;
                break;
            }
        }
        if (!bFound) {
            /* Check if provided by optional database list. */
            for (j = 0; j < nOptionalDatabases; j++) {
                if (0 == strcmp(specificDatabaseList[i], optionalDatabases[j])) {
                    if (FC_SUCCESS != (ret = string_list_add(optionalDatabases[j], &selectedDatabases, &nSelectedDatabases))) {
                        logg("!Failed to add optional database %s to list of selected databases.\n", optionalDatabases[j]);
                        status = ret;
                        goto done;
                    }
                    bFound = 1;
                    break;
                }
            }
        }
        if (!bFound) {
            logg("!Requested database is not available: %s.\n", specificDatabaseList[i]);
            status = FC_ECONFIG;
            goto done;
        }
    }

    *databaseList = selectedDatabases;
    *nDatabases   = nSelectedDatabases;

    status = FC_SUCCESS;

done:

    if (NULL != standardDatabases) {
        free_string_list(standardDatabases, nStandardDatabases);
    }
    if (NULL != optionalDatabases) {
        free_string_list(optionalDatabases, nOptionalDatabases);
    }
    if (FC_SUCCESS != status) {
        if (NULL != selectedDatabases) {
            free_string_list(selectedDatabases, nSelectedDatabases);
        }
    }

    return status;
}

static fc_error_t executeIfNewVersion(
    const char *command,
    char *newVersion,
    int bDaemonized)
{
    fc_error_t status = FC_EARG;

    char *modifiedCommand = NULL;
    char *replace_version = NULL;

    if ((NULL == command) || (NULL == newVersion)) {
        logg("!executeIfNewVersion: Invalid args\n");
        status = FC_EARG;
        goto done;
    }

    if (NULL == (replace_version = strstr(command, "%v"))) {
        /*
         * Execute command as-is.
         */
        execute("OnOutdatedExecute", command, bDaemonized);
    } else {
        /*
         * Replace "%v" with version numbers, then execute command.
         */
        char *after_replace_version = NULL;
        char *version               = newVersion;

        while (*version) {
            if (!strchr("0123456789.", *version)) {
                logg("!executeIfNewVersion: OnOutdatedExecute: Incorrect version number string\n");
                status = FC_EARG;
                goto done;
            }
            version++;
        }
        modifiedCommand = (char *)malloc(strlen(command) + strlen(version) + 10);
        if (NULL == modifiedCommand) {
            logg("!executeIfNewVersion: Can't allocate memory for modifiedCommand\n");
            status = FC_EMEM;
            goto done;
        }

        /* Copy first half of command */
        strncpy(modifiedCommand, command, replace_version - command);
        modifiedCommand[replace_version - command] = '\0'; /* Add null terminator */

        /* Cat on the version number */
        strcat(modifiedCommand, version);

        /* Cat on the rest of the command */
        after_replace_version = replace_version + 2;
        strcat(modifiedCommand, after_replace_version);

        /* Make it so. */
        execute("OnOutdatedExecute", modifiedCommand, bDaemonized);
    }

    status = FC_SUCCESS;

done:

    if (NULL != modifiedCommand) {
        free(modifiedCommand);
    }

    return status;
}

/**
 * @brief Update official databases.
 *
 * Will update select official databases given the configuration.
 *
 * @param databaseList          String list of desired official databases.
 * @param nDatabases            Number of official databases in list.
 * @param urlDatabaseList       String list of desired unofficial databases updated by URL.
 * @param nUrlDatabases         Number of database URLs in list.
 * @param serverList            String list of DatabaseMirror or PrivateMirror servers.
 * @param nServers              Number of servers in list.
 * @param dnsUpdateInfoServer   (optional) DNS update info server.  May be NULl to disable use of DNS.
 * @param bScriptedUpdates      Nonzero to enable incremental/scripted (efficient) updates.
 * @param bPrune                Prune official databases that are no longer desired or avaialable.
 * @param onUpdateExecute       (optional) Command to to run after 1+ databases have been updated.
 * @param onOutdatedExecute     (optional) Command to run if new version of ClamAV is available.
 * @param bDaemonized           Non-zero if process has daemonized.
 * @param notifyClamd           (optional) Path to clamd.conf to notify clamd.
 * @param fc_context            (optional) Context information for callback functions.
 * @return fc_error_t           FC_SUCCESS if all databases upddated successfully.
 */
fc_error_t perform_database_update(
    char **databaseList,
    uint32_t nDatabases,
    char **urlDatabaseList,
    uint32_t nUrlDatabases,
    char **serverList,
    uint32_t nServers,
    int bPrivateMirror,
    const char *dnsUpdateInfoServer,
    int bScriptedUpdates,
    int bPrune,
    const char *onUpdateExecute,
    const char *onOutdatedExecute,
    int bDaemonized,
    char *notifyClamd,
    fc_ctx *fc_context)
{
    fc_error_t ret;
    fc_error_t status = FC_EARG;
    time_t currtime;
    char *dnsUpdateInfo    = NULL;
    char *newVersion       = NULL;
    uint32_t nUpdated      = 0;
    uint32_t nTotalUpdated = 0;

    STATBUF statbuf;

    if (NULL == serverList) {
        mprintf("!perform_database_update: Invalid arguments.\n");
        goto done;
    }
    if (((NULL == databaseList) || (0 == nDatabases)) &&
        ((NULL == urlDatabaseList) || (0 == nUrlDatabases))) {
        mprintf("!perform_database_update: No databases requested.\n");
        goto done;
    }

    time(&currtime);
    logg("ClamAV update process started at %s", ctime(&currtime));

    if (bPrune) {
        /*
         * Prune database directory of official databases
         * that are no longer available or no longer desired.
         */
        (void)fc_prune_database_directory(databaseList, nDatabases);
    }

    /*
     * Query DNS (if enabled) to get Update Info.
     */
    (void)fc_dns_query_update_info(dnsUpdateInfoServer, &dnsUpdateInfo, &newVersion);

    /*
     * Create a temp directory to use for the update process.
     */
    if (LSTAT(g_freshclamTempDirectory, &statbuf) == -1) {
        if (0 != mkdir(g_freshclamTempDirectory, 0700)) {
            logg("!Can't create temporary directory %s\n", g_freshclamTempDirectory);
            logg("Hint: The database directory must be writable for UID %d or GID %d\n", getuid(), getgid());
            status = FC_EDBDIRACCESS;
            goto done;
        }
    }

    if ((NULL != databaseList) && (0 < nDatabases)) {
        /*
        * Download/update the desired official databases.
         */
        ret = fc_update_databases(
            databaseList,
            nDatabases,
            serverList,
            nServers,
            bPrivateMirror,
            dnsUpdateInfo,
            bScriptedUpdates,
            (void *)fc_context,
            &nUpdated);
        if (FC_SUCCESS != ret) {
            logg("!Database update process failed: %s (%d)\n", fc_strerror(ret), ret);
            status = ret;
            goto done;
        }
        nTotalUpdated += nUpdated;
    }

    if ((NULL != urlDatabaseList) && (0 < nUrlDatabases)) {
        /*
         * Download/update the desired unofficial / URL-based databases.
         */
        ret = fc_download_url_databases(
            urlDatabaseList,
            nUrlDatabases,
            (void *)fc_context,
            &nUpdated);
        if (FC_SUCCESS != ret) {
            logg("!Database update process failed: %s (%d)\n", fc_strerror(ret), ret);
            status = ret;
            goto done;
        }
        nTotalUpdated += nUpdated;

        logg("*Database update completed successfully.\n");
    }

    if (0 < nTotalUpdated) {
        if (NULL != notifyClamd)
            notify(notifyClamd);

        if (NULL != onUpdateExecute) {
            execute("OnUpdateExecute", onUpdateExecute, bDaemonized);
        }
    }

    if ((NULL != newVersion) && (NULL != onOutdatedExecute)) {
        executeIfNewVersion(onOutdatedExecute, newVersion, bDaemonized);
    }

    status = FC_SUCCESS;

done:

    if (LSTAT(g_freshclamTempDirectory, &statbuf) != -1) {
        /* Remove temp directory */
        if (*g_freshclamTempDirectory) {
            cli_rmdirs(g_freshclamTempDirectory);
        }
    }
    if (NULL != dnsUpdateInfo) {
        free(dnsUpdateInfo);
    }
    if (NULL != newVersion) {
        free(newVersion);
    }

    return status;
}

int main(int argc, char **argv)
{
    fc_error_t ret;
    fc_error_t status = FC_ECONNECTION;
    char *cfgfile     = NULL;
    const char *arg   = NULL;

    struct optstruct *opts = NULL;
    const struct optstruct *opt;

    char **serverList               = NULL;
    uint32_t nServers               = 0;
    int bPrivate                    = 0;
    const char *dnsUpdateInfoServer = NULL;

    char **databaseList    = NULL;
    uint32_t nDatabases    = 0;
    char **urlDatabaseList = NULL;
    uint32_t nUrlDatabases = 0;

    int bPrune = 1;

#ifdef HAVE_PWD_H
    const struct optstruct *logFileOpt = NULL;
    const char *logFileName            = NULL;
#endif /* HAVE_PWD_H */

    fc_ctx fc_context = {0};

#ifndef _WIN32
    struct sigaction sigact;
    struct sigaction oldact;
#endif
    int i;
    pid_t parentPid = getpid();

    if (check_flevel())
        exit(FC_EINIT);

    if ((opts = optparse(NULL, argc, argv, 1, OPT_FRESHCLAM, 0, NULL)) == NULL) {
        mprintf("!Can't parse command line options\n");
        status = FC_EINIT;
        goto done;
    }

    if (optget(opts, "help")->enabled) {
        help();
        status = FC_SUCCESS;
        goto done;
    }

    /* check foreground option from command line to override config file */
    for (i = 0; i < argc; i += 1) {
        if ((memcmp(argv[i], "--foreground", 12) == 0) || (memcmp(argv[i], "-F", 2) == 0)) {
            /* found */
            break;
        }
    }
    /* If --foreground options was found in command line arguments,
       get the value and set it. */
    if (i < argc) {
        if (optget(opts, "Foreground")->enabled) {
            g_foreground = 1;
        } else {
            g_foreground = 0;
        }
    }

    /*
     * Parse the config file.
     */
    cfgfile = cli_strdup(optget(opts, "config-file")->strarg);
    if ((opts = optparse(cfgfile, 0, NULL, 1, OPT_FRESHCLAM, 0, opts)) == NULL) {
        fprintf(stderr, "ERROR: Can't open/parse the config file %s\n", cfgfile);
        status = FC_EINIT;
        goto done;
    }

    /*
     * Handle options that immediately exit.
     */
    if (optget(opts, "version")->enabled) {
        print_version(optget(opts, "DatabaseDirectory")->strarg);
        status = FC_SUCCESS;
        goto done;
    }
    if (optget(opts, "list-mirrors")->enabled) {
        mprintf("^Deprecated option --list-mirrors. Individual mirrors are no longer tracked, as official signature distribution is now done through the CloudFlare CDN.\n");
        status = FC_SUCCESS;
        goto done;
    }

    /*
     * Collect list of database servers from DatabaseMirror(s) or PrivateMirror(s).
     */
    if (FC_SUCCESS != (ret = get_database_server_list(opts, &serverList, &nServers, &bPrivate))) {
        mprintf("!Unable to find DatabaseMirror or PrivateMirror option(s) that specify database server FQDNs.\n");
        status = ret;
        goto done;
    }

    if (optget(opts, "update-db")->enabled) {
        /*
         * Prep for specific database updates.
         */
        char **specificDatabaseList = NULL;
        uint32_t nSpecificDatabases = 0;
        int bCustom                 = 0;

        /* Don't prune the database directory if only specific dabases were requested from the command line. */
        bPrune = 0;

        /*
         * Get list of specific databases from command line args.
         */
        if (FC_SUCCESS != (ret = get_string_list(optget(opts, "update-db"), &specificDatabaseList, &nSpecificDatabases))) {
            mprintf("!Error when attempting to read ExtraDatabase entries.\n");
            status = ret;
            goto done;
        }

        /*
         * Select specific databases from official lists.
         */
        if (FC_SUCCESS != (ret = select_specific_databases(
                               specificDatabaseList,
                               nSpecificDatabases,
                               &databaseList,
                               &nDatabases,
                               &bCustom))) {
            free_string_list(specificDatabaseList, nSpecificDatabases);
            specificDatabaseList = NULL;

            mprintf("!Failed to select specific databases from available official databases.\n");
            status = ret;
            goto done;
        }
        free_string_list(specificDatabaseList, nSpecificDatabases);
        specificDatabaseList = NULL;

        if (bCustom) {
            /*
             * Collect list of "custom"/unofficial URL-based databases.
             */
            if (FC_SUCCESS != (ret = get_string_list(optget(opts, "DatabaseCustomURL"), &urlDatabaseList, &nUrlDatabases))) {
                mprintf("!Error when attempting to read ExcludeDatabase entries.\n");
                status = ret;
                goto done;
            }
            if ((NULL == urlDatabaseList) || (0 == nUrlDatabases)) {
                mprintf("!--update-db=custom requires at least one DatabaseCustomURL in freshclam.conf\n");
                status = FC_ECONFIG;
                goto done;
            }
        }
    } else {
        /*
         * Prep for standard database updates.
         */
        char **optInList  = NULL;
        uint32_t nOptIns  = 0;
        char **optOutList = NULL;
        uint32_t nOptOuts = 0;

        /*
         * Collect list of database opt-ins.
         */
        if (FC_SUCCESS != (ret = get_string_list(optget(opts, "ExtraDatabase"), &optInList, &nOptIns))) {
            mprintf("!Error when attempting to read ExtraDatabase entries.\n");
            status = ret;
            goto done;
        }
        if (optget(opts, "SafeBrowsing")->enabled) {
            if (FC_SUCCESS != (ret = string_list_add("safebrowsing", &optInList, &nOptIns))) {
                free_string_list(optInList, nOptIns);
                optInList = NULL;

                mprintf("!Failed to add safebrowsing to list of opt-in databases.\n");
                status = ret;
                goto done;
            }
        }

        /*
         * Collect list of database opt-outs.
         */
        if (FC_SUCCESS != (ret = get_string_list(optget(opts, "ExcludeDatabase"), &optOutList, &nOptOuts))) {
            free_string_list(optInList, nOptIns);
            optInList = NULL;

            mprintf("!Error when attempting to read ExcludeDatabase entries.\n");
            status = ret;
            goto done;
        }
        if (!optget(opts, "Bytecode")->enabled) {
            if (FC_SUCCESS != (ret = string_list_add("bytecode", &optOutList, &nOptOuts))) {
                free_string_list(optInList, nOptIns);
                optInList = NULL;
                free_string_list(optOutList, nOptOuts);
                optOutList = NULL;

                mprintf("!Failed to add bytecode to list of opt-out databases.\n");
                status = ret;
                goto done;
            }
        }

        /*
         * Select databases from official lists using opt-ins and opt-outs.
         */
        if (FC_SUCCESS != (ret = select_from_official_databases(
                               optInList,
                               nOptIns,
                               optOutList,
                               nOptOuts,
                               &databaseList,
                               &nDatabases))) {
            free_string_list(optInList, nOptIns);
            optInList = NULL;
            free_string_list(optOutList, nOptOuts);
            optOutList = NULL;

            mprintf("!Failed to select databases from list of official databases.\n");
            status = ret;
            goto done;
        }
        free_string_list(optInList, nOptIns);
        optInList = NULL;
        free_string_list(optOutList, nOptOuts);
        optOutList = NULL;

        /*
         * Collect list of "custom"/unofficial URL-based databases.
         */
        if (FC_SUCCESS != (ret = get_string_list(optget(opts, "DatabaseCustomURL"), &urlDatabaseList, &nUrlDatabases))) {
            mprintf("!Error when attempting to read ExcludeDatabase entries.\n");
            status = ret;
            goto done;
        }
    }

    fc_context.bTestDatabases   = optget(opts, "TestDatabases")->enabled;
    fc_context.bBytecodeEnabled = optget(opts, "Bytecode")->enabled;

    /*
     * Initialize libraries and configuration options.
     */
    if (FC_SUCCESS != initialize(opts)) {
        mprintf("!Initialization error!\n");
        status = FC_EINIT;
        goto done;
    }

    if (!optget(opts, "no-dns")->enabled && optget(opts, "DNSDatabaseInfo")->enabled) {
        dnsUpdateInfoServer = optget(opts, "DNSDatabaseInfo")->strarg;
    }

#ifdef _WIN32
    signal(SIGINT, sighandler);
#else
    memset(&sigact, 0, sizeof(struct sigaction));
    sigact.sa_handler = sighandler;
    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGPIPE, &sigact, NULL);
#endif
    if (!optget(opts, "daemon")->enabled) {
        /*
         * Daemon mode not enabled.
         * Just update and exit.
         */
        ret = perform_database_update(
            databaseList,
            nDatabases,
            urlDatabaseList,
            nUrlDatabases,
            serverList,
            nServers,
            bPrivate,
            bPrivate ? NULL : dnsUpdateInfoServer,
            bPrivate ? 0 : optget(opts, "ScriptedUpdates")->enabled,
            bPrune,
            optget(opts, "OnUpdateExecute")->enabled ? optget(opts, "OnUpdateExecute")->strarg : NULL,
            optget(opts, "OnOutdatedExecute")->enabled ? optget(opts, "OnOutdatedExecute")->strarg : NULL,
            optget(opts, "daemon")->enabled,
            optget(opts, "NotifyClamd")->active ? optget(opts, "NotifyClamd")->strarg : NULL,
            &fc_context);
        if (FC_SUCCESS != ret) {
            logg("!Update failed.\n");
            status = ret;
            goto done;
        }

    } else {
        /*
         * Daemon mode enabled.
         * Keep running after update.
         */
        int bigsleep, checks;
#ifndef _WIN32
        time_t now, wakeup;

        sigaction(SIGTERM, &sigact, NULL);
        sigaction(SIGHUP, &sigact, NULL);
        sigaction(SIGCHLD, &sigact, NULL);
#endif

        /*
         * Determine sleep time based on # of checks per day.
         * If HTTP is used instead of DNS to check for updates,
         * limit the # of checks to 50 per day to restrict bandwidth usage.
         */
        checks = optget(opts, "Checks")->numarg;

        if (checks <= 0) {
            logg("^Number of checks must be a positive integer.\n");
            status = FC_ECONFIG;
            goto done;
        }

        if (!optget(opts, "DNSDatabaseInfo")->enabled || optget(opts, "no-dns")->enabled) {
            if (checks > 50) {
                logg("^Number of checks must be between 1 and 50.\n");
                status = FC_ECONFIG;
                goto done;
            }
        }

        bigsleep = 24 * 3600 / checks;

        /*
         * If not set to foreground mode (and not Windows),
         * daemonize and run in the background.
         */
#ifndef _WIN32
        /* fork into background */
        if (g_foreground == 0) {
            if (-1 == daemonize_parent_wait(NULL, NULL)) {
                logg("!daemonize() failed\n");
                status = FC_EFAILEDUPDATE;
                goto done;
            }
            mprintf_disabled = 1;
        }
#endif

#ifndef _WIN32
        /* Signal the parent process that we have successfully
         * demonized. If it does not get this signal, it will wait 
         * for our exit status (and we don't exit in daemon mode).
         */
        if (parentPid != getpid()) { // we have been daemonized
            daemonize_signal_parent(parentPid);
        }
#endif

#ifdef HAVE_PWD_H
        /*  Get the log file name to pass it into drop_privileges.  */
        logFileOpt = optget(opts, "UpdateLogFile");
        if (logFileOpt->enabled) {
            logFileName = logFileOpt->strarg;
        }

        /*
         * freshclam shouldn't work with root privileges.
         * Drop privileges to the DatabaseOwner user, if specified.
         */
        ret = drop_privileges(optget(opts, "DatabaseOwner")->strarg, logFileName);
        if (0 != ret) {
            logg("!Failed to switch to %s user.\n", optget(opts, "DatabaseOwner")->strarg);
            status = FC_ECONFIG;
            goto done;
        }
#endif /* HAVE_PWD_H */

        g_active_children = 0;

        logg("#freshclam daemon %s (OS: " TARGET_OS_TYPE ", ARCH: " TARGET_ARCH_TYPE ", CPU: " TARGET_CPU_TYPE ")\n", get_version());

        while (!g_terminate) {
            ret = perform_database_update(
                databaseList,
                nDatabases,
                urlDatabaseList,
                nUrlDatabases,
                serverList,
                nServers,
                bPrivate,
                bPrivate ? NULL : dnsUpdateInfoServer,
                bPrivate ? 0 : optget(opts, "ScriptedUpdates")->enabled,
                bPrune,
                optget(opts, "OnUpdateExecute")->enabled ? optget(opts, "OnUpdateExecute")->strarg : NULL,
                optget(opts, "OnOutdatedExecute")->enabled ? optget(opts, "OnUpdateExecute")->strarg : NULL,
                optget(opts, "daemon")->enabled,
                optget(opts, "NotifyClamd")->active ? optget(opts, "NotifyClamd")->strarg : NULL,
                &fc_context);
            if (FC_SUCCESS != ret) {
                logg("!Update failed.\n");
            }

#ifndef _WIN32
            /* Void the current alarm. */
            alarm(0);
#endif

            if (ret > 1) {
                if ((opt = optget(opts, "OnErrorExecute"))->enabled)
                    arg = opt->strarg;

                if (arg)
                    execute("OnErrorExecute", arg, optget(opts, "daemon")->enabled);

                arg = NULL;
            }

            logg("#--------------------------------------\n");
#ifdef SIGALRM
            sigaction(SIGALRM, &sigact, &oldact);
#endif
#ifdef SIGUSR1
            sigaction(SIGUSR1, &sigact, &oldact);
#endif

#ifdef _WIN32
            sleep(bigsleep);
#else
            /* Set a new alarm. */
            time(&wakeup);
            wakeup += bigsleep;
            alarm(bigsleep);
            do {
                pause();
                time(&now);
            } while (!g_terminate && (now < wakeup));

            if (g_terminate == -1) {
                logg("Received signal: wake up\n");
                g_terminate = 0;
            } else if (g_terminate == -2) {
                logg("Received signal: re-opening log file\n");
                g_terminate = 0;
                logg_close();
            }
#endif

#ifdef SIGALRM
            sigaction(SIGALRM, &oldact, NULL);
#endif
#ifdef SIGUSR1
            sigaction(SIGUSR1, &oldact, NULL);
#endif
        }
    }

    status = FC_SUCCESS;

done:

    if ((status > FC_UPTODATE) && (NULL != opts)) {
        if ((opt = optget(opts, "OnErrorExecute"))->enabled)
            execute("OnErrorExecute", opt->strarg, optget(opts, "daemon")->enabled);
    }

    logg_close();

    if (NULL != databaseList) {
        free_string_list(databaseList, nDatabases);
    }
    if (NULL != urlDatabaseList) {
        free_string_list(urlDatabaseList, nUrlDatabases);
    }
    if (NULL != serverList) {
        free_string_list(serverList, nServers);
    }
    if (NULL != opts) {
        optfree(opts);
    }
    if (NULL != cfgfile) {
        free(cfgfile);
    }

    /* Cleanup libfreshclam */
    fc_cleanup();

    /* Remove temp directory */
    if (*g_freshclamTempDirectory) {
        cli_rmdirs(g_freshclamTempDirectory);
    }

    if ((FC_UPTODATE == status) || (FC_SUCCESS == status)) {
        return 0;
    }

    return (int)status;
}

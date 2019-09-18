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
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <dirent.h>
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

#include <curl/curl.h>

#include "target.h"
#include "clamav.h"
#include "libfreshclam.h"
#include "libfreshclam_internal.h"
#include "dns.h"

#include "shared/cert_util.h"
#include "shared/output.h"
#include "shared/misc.h"

#include "libclamav/others.h"
#include "libclamav/regex_list.h"
#include "libclamav/str.h"

/*
 * Private functions
 */

/*
 * libclamav API functions
 */
const char *fc_strerror(fc_error_t fcerror)
{
    switch (fcerror) {
        case FC_SUCCESS:
            return "Success";
        case FC_UPTODATE:
            return "Up-to-date";
        case FC_EINIT:
            return "Failed to initalize";
        case FC_EDIRECTORY:
            return "Invalid, nonexistant, or inaccessible directory";
        case FC_EFILE:
            return "Invalid, nonexistant, or inaccessible file";
        case FC_ECONNECTION:
            return "Connection failed";
        case FC_EEMPTYFILE:
            return "Empty file";
        case FC_EBADCVD:
            return "Invalid or corrupted CVD/CLD database";
        case FC_ETESTFAIL:
            return "Test failed";
        case FC_ECONFIG:
            return "Invalid configuration settings(s)";
        case FC_EDBDIRACCESS:
            return "Failed to read/write file to database directory";
        case FC_EFAILEDGET:
            return "HTTP GET failed";
        case FC_EMIRRORNOTSYNC:
            return "Downloaded database had lower version than advertised";
        case FC_ELOGGING:
            return "Failed to write to log";
        case FC_EFAILEDUPDATE:
            return "Failed to update database";
        case FC_EMEM:
            return "Memory allocation error";
        case FC_EARG:
            return "Invalid argument(s)";
        default:
            return "Unknown libfreshclam error code!";
    }
}

fc_error_t fc_initialize(fc_config *fcConfig)
{
    fc_error_t status = FC_EARG;
    STATBUF statbuf;

    if (NULL == fcConfig) {
        printf("fc_initialize: Invalid arguments.\n");
        return status;
    }

    /* Initilize libcurl */
    curl_global_init(CURL_GLOBAL_ALL);

    /* Initialize mprintf options */
    if (fcConfig->msgFlags & FC_CONFIG_MSG_DEBUG) cl_debug();
    mprintf_verbose  = (fcConfig->msgFlags & FC_CONFIG_MSG_VERBOSE) ? 1 : 0;
    mprintf_quiet    = (fcConfig->msgFlags & FC_CONFIG_MSG_QUIET) ? 1 : 0;
    mprintf_nowarn   = (fcConfig->msgFlags & FC_CONFIG_MSG_NOWARN) ? 1 : 0;
    mprintf_stdout   = (fcConfig->msgFlags & FC_CONFIG_MSG_STDOUT) ? 1 : 0;
    mprintf_progress = (fcConfig->msgFlags & FC_CONFIG_MSG_SHOWPROGRESS) ? 1 : 0;

    /* Initialize logger */
    logg_verbose = (fcConfig->logFlags & FC_CONFIG_LOG_VERBOSE) ? 1 : 0;
    logg_nowarn  = (fcConfig->logFlags & FC_CONFIG_LOG_NOWARN) ? 1 : 0;
    logg_time    = (fcConfig->logFlags & FC_CONFIG_LOG_TIME) ? 1 : 0;
    logg_rotate  = (fcConfig->logFlags & FC_CONFIG_LOG_ROTATE) ? 1 : 0;
    logg_size    = fcConfig->maxLogSize;
    /* Set a log file if requested, and is not already set */
    if ((NULL == logg_file) && (NULL != fcConfig->logFile)) {
        logg_file = cli_strdup(fcConfig->logFile);
        if (0 != logg("#--------------------------------------\n")) {
            mprintf("!Problem with internal logger (UpdateLogFile = %s).\n", logg_file);
            status = FC_ELOGGING;
            goto done;
        }
    }

#if defined(USE_SYSLOG) && !defined(C_AIX)
    /* Initialize syslog if available and requested, and is not already set */
    if (fcConfig->logFlags & FC_CONFIG_LOG_SYSLOG) {
        int logFacility = LOG_LOCAL6;
        if ((0 == logg_syslog) && (NULL != fcConfig->logFacility) && (-1 == (logFacility = logg_facility(fcConfig->logFacility)))) {
            mprintf("!LogFacility: %s: No such facility.\n", fcConfig->logFacility);
            status = FC_ELOGGING;
            goto done;
        }

        openlog("freshclam", LOG_PID, logFacility);
        logg_syslog = 1;
    }
#endif

    /* Optional connection settings. */
    if (NULL != fcConfig->localIP) {
#if !((LIBCURL_VERSION_MAJOR > 7) || ((LIBCURL_VERSION_MAJOR == 7) && (LIBCURL_VERSION_MINOR >= 33)))
        mprintf("!The LocalIP feature was requested but this local IP support is not presently available.\n");
        mprintf("!Your installation was built with libcurl version %u.%u.%u.\n", LIBCURL_VERSION_MAJOR, LIBCURL_VERSION_MINOR, LIBCURL_VERSION_PATCH);
        mprintf("!LocalIP requires libcurl version 7.33.0 or higher and must include the c-ares optional dependency.\n");
#else
        g_localIP = cli_strdup(fcConfig->localIP);
#endif
    }
    if (NULL != fcConfig->userAgent) {
        g_userAgent = cli_strdup(fcConfig->userAgent);
    }
    if (NULL != fcConfig->proxyServer) {
        g_proxyServer = cli_strdup(fcConfig->proxyServer);
        if (0 != fcConfig->proxyPort) {
            g_proxyPort = fcConfig->proxyPort;
        } else {
            /*
             * Proxy port not provided. Look up the default port for
             * webcache in /etc/services.
             * Default to 8080 if not provided.
             */
            const struct servent *webcache = getservbyname("webcache", "TCP");

            if (webcache)
                g_proxyPort = ntohs(webcache->s_port);
            else
                g_proxyPort = 8080;

            endservent();
        }
    }
    if (NULL != fcConfig->proxyUsername) {
        g_proxyUsername = cli_strdup(fcConfig->proxyUsername);
    }
    if (NULL != fcConfig->proxyPassword) {
        g_proxyPassword = cli_strdup(fcConfig->proxyPassword);
    }

#ifdef _WIN32
    if ((fcConfig->databaseDirectory[strlen(fcConfig->databaseDirectory) - 1] != '/') &&
        ((fcConfig->databaseDirectory[strlen(fcConfig->databaseDirectory) - 1] != '\\'))) {
#else
    if (fcConfig->databaseDirectory[strlen(fcConfig->databaseDirectory) - 1] != '/') {
#endif
        g_databaseDirectory = cli_malloc(strlen(fcConfig->databaseDirectory) + strlen(PATHSEP) + 1);
        snprintf(
            g_databaseDirectory,
            strlen(fcConfig->databaseDirectory) + strlen(PATHSEP) + 1,
            "%s" PATHSEP,
            fcConfig->databaseDirectory);
    } else {
        g_databaseDirectory = cli_strdup(fcConfig->databaseDirectory);
    }

    /* Validate that the database directory exists, and store it. */
    if (LSTAT(g_databaseDirectory, &statbuf) == -1) {
        logg("!Database directory does not exist: %s\n", g_databaseDirectory);
        status = FC_EDIRECTORY;
        goto done;
    }
    if (!S_ISDIR(statbuf.st_mode)) {
        logg("!Database directory is not a directory: %s\n", g_databaseDirectory);
        status = FC_EDIRECTORY;
        goto done;
    }

    /* Validate that the temp directory exists, and store it. */
    if (LSTAT(fcConfig->tempDirectory, &statbuf) == -1) {
        logg("!Temp directory does not exist: %s\n", fcConfig->tempDirectory);
        status = FC_EDIRECTORY;
        goto done;
    }
    if (!S_ISDIR(statbuf.st_mode)) {
        logg("!Temp directory is not a directory: %s\n", fcConfig->tempDirectory);
        status = FC_EDIRECTORY;
        goto done;
    }
    g_tempDirectory = cli_strdup(fcConfig->tempDirectory);

    g_maxAttempts    = fcConfig->maxAttempts;
    g_connectTimeout = fcConfig->connectTimeout;
    g_requestTimeout = fcConfig->requestTimeout;

    g_bCompressLocalDatabase = fcConfig->bCompressLocalDatabase;

    status = FC_SUCCESS;

done:
    if (FC_SUCCESS != status) {
        fc_cleanup();
    }

    return status;
}

void fc_cleanup(void)
{
    /* Cleanup libcurl */
    curl_global_cleanup();

    if (NULL != logg_file) {
        free((void *)logg_file);
        logg_file = NULL;
    }
    if (NULL != g_localIP) {
        free(g_localIP);
        g_localIP = NULL;
    }
    if (NULL != g_userAgent) {
        free(g_userAgent);
        g_userAgent = NULL;
    }
    if (NULL != g_proxyServer) {
        free(g_proxyServer);
        g_proxyServer = NULL;
    }
    if (NULL != g_proxyUsername) {
        free(g_proxyUsername);
        g_proxyUsername = NULL;
    }
    if (NULL != g_proxyPassword) {
        free(g_proxyPassword);
        g_proxyPassword = NULL;
    }
    if (NULL != g_databaseDirectory) {
        free(g_databaseDirectory);
        g_databaseDirectory = NULL;
    }
    if (NULL != g_tempDirectory) {
        free(g_tempDirectory);
        g_tempDirectory = NULL;
    }
}

fc_error_t fc_prune_database_directory(char **databaseList, uint32_t nDatabases)
{
    fc_error_t status = FC_EARG;

    DIR *dir = NULL;
    struct dirent *dent;
    char *extension = NULL;

    char currDir[PATH_MAX];

    /* Store CWD */
    if (!getcwd(currDir, PATH_MAX)) {
        logg("!getcwd() failed\n");
        status = FC_EDIRECTORY;
        goto done;
    }

    /* Change directory to database directory */
    if (chdir(g_databaseDirectory)) {
        logg("!Can't change dir to %s\n", g_databaseDirectory);
        status = FC_EDIRECTORY;
        goto done;
    }

    logg("*Current working dir is %s\n", g_databaseDirectory);

    if (!(dir = opendir(g_databaseDirectory))) {
        logg("!checkdbdir: Can't open directory %s\n", g_databaseDirectory);
        status = FC_EDBDIRACCESS;
        goto done;
    }

    while ((dent = readdir(dir))) {
        if (dent->d_ino) {
            if ((NULL != (extension = strstr(dent->d_name, ".cld"))) ||
                (NULL != (extension = strstr(dent->d_name, ".cvd")))) {

                uint32_t i;
                int bFound = 0;
                for (i = 0; i < nDatabases; i++) {
                    if (0 == strncmp(databaseList[i], dent->d_name, extension - dent->d_name)) {
                        bFound = 1;
                    }
                }
                if (!bFound) {
                    /* Prune CVD/CLD */
                    mprintf("Pruning unwanted or deprecated database file %s.\n", dent->d_name);
                    if (unlink(dent->d_name)) {
                        mprintf("!Failed to prune unwanted database file %s, consider removing it manually.\n", dent->d_name);
                        status = FC_EDBDIRACCESS;
                        goto done;
                    }
                }
            }
        }
    }

    status = FC_SUCCESS;

done:
    if (NULL != dir) {
        closedir(dir);
    }

    if (currDir[0] != '\0') {
        /* Restore CWD */
        if (chdir(currDir)) {
            logg("!Failed to change back to original directory %s\n", currDir);
            status = FC_EDIRECTORY;
            goto done;
        }
        logg("*Current working dir restored to %s\n", currDir);
    }

    return status;
}

/**
 * @brief Compare two version strings.
 *
 * @param v1 Version string 1
 * @param v2 Version string 2
 * @return int 1 if v1 is greater, 0 if equal, -1 if smaller.
 */
int version_string_compare(char *v1, size_t v1_len, char *v2, size_t v2_len)
{
    size_t i, j;
    int vnum1 = 0, vnum2 = 0;

    for (i = 0, j = 0; (i < v1_len || j < v2_len);) {
        while (i < v1_len && v1[i] != '.') {
            vnum1 = vnum1 * 10 + (v1[i] - '0');
            i++;
        }

        while (j < v2_len && v2[j] != '.') {
            vnum2 = vnum2 * 10 + (v2[j] - '0');
            j++;
        }

        if (vnum1 > vnum2)
            return 1;
        if (vnum2 > vnum1)
            return -1;

        vnum1 = vnum2 = 0;
        i++;
        j++;
    }
    return 0;
}

fc_error_t fc_test_database(const char *dbFilename, int bBytecodeEnabled)
{
    fc_error_t status        = FC_EARG;
    struct cl_engine *engine = NULL;
    unsigned newsigs         = 0;
    cl_error_t cl_ret;

    if ((NULL == dbFilename)) {
        logg("^fc_test_database: Invalid arguments.\n");
        goto done;
    }

    logg("*Loading signatures from %s\n", dbFilename);
    if (NULL == (engine = cl_engine_new())) {
        status = FC_ETESTFAIL;
        goto done;
    }

    cl_engine_set_clcb_stats_submit(engine, NULL);

    if (CL_SUCCESS != (cl_ret = cl_load(
                           dbFilename, engine, &newsigs,
                           CL_DB_PHISHING | CL_DB_PHISHING_URLS | CL_DB_BYTECODE |
                               CL_DB_PUA | CL_DB_ENHANCED))) {
        logg("!Failed to load new database: %s\n", cl_strerror(cl_ret));
        status = FC_ETESTFAIL;
        goto done;
    }

    if (bBytecodeEnabled && (CL_SUCCESS != (cl_ret = cli_bytecode_prepare2(
                                                engine, &engine->bcs,
                                                engine->dconf->bytecode
                                                /*FIXME: dconf has no sense here */)))) {
        logg("!Failed to compile/load bytecode: %s\n", cl_strerror(cl_ret));
        status = FC_ETESTFAIL;
        goto done;
    }
    logg("*Properly loaded %u signatures from %s\n", newsigs, dbFilename);

    status = FC_SUCCESS;

done:

    if (NULL != engine) {
        if (engine->domainlist_matcher && engine->domainlist_matcher->sha256_pfx_set.keys)
            cli_hashset_destroy(&engine->domainlist_matcher->sha256_pfx_set);

        cl_engine_free(engine);
    }

    return status;
}

fc_error_t fc_dns_query_update_info(
    const char *dnsUpdateInfoServer,
    char **dnsUpdateInfo,
    char **newVersion)
{
    fc_error_t status = FC_EFAILEDGET;
    char *dnsReply    = NULL;

#ifdef HAVE_RESOLV_H
    unsigned int ttl;
    char *reply_token = NULL;
    int recordTime;
    time_t currentTime;
    int vwarning = 1;
    char version_string[32];
#endif /* HAVE_RESOLV_H */

    if ((NULL == dnsUpdateInfo) || (NULL == newVersion)) {
        logg("^dns_query_update_info: Invalid arguments.\n");
        status = FC_EARG;
        goto done;
    }

    *dnsUpdateInfo = NULL;
    *newVersion    = NULL;

#ifdef HAVE_RESOLV_H

    if (dnsUpdateInfoServer == NULL) {
        logg("^DNS Update Info disabled. Falling back to HTTP mode.\n");
        goto done;
    }

    if (NULL == (dnsReply = dnsquery(dnsUpdateInfoServer, T_TXT, &ttl))) {
        logg("^Invalid DNS reply. Falling back to HTTP mode.\n");
        goto done;
    }

    logg("*TTL: %d\n", ttl);

    /*
     * Check Record Time.
     */
    if (NULL == (reply_token = cli_strtok(dnsReply, DNS_UPDATEINFO_RECORDTIME, ":"))) {
        logg("^Failed to find Record Time field in DNS Update Info.\n");
        goto done;
    }

    recordTime = atoi(reply_token);
    free(reply_token);
    reply_token = NULL;

    time(&currentTime);
    if ((int)currentTime - recordTime > 10800) {
        logg("^DNS record is older than 3 hours.\n");
        goto done;
    }

    /*
     * Check Version Warning Flag.
     */
    if (NULL == (reply_token = cli_strtok(dnsReply, DNS_UPDATEINFO_VERSIONWARNING, ":"))) {
        logg("^Failed to find Version Warning Flag in DNS Update Info.\n");
        goto done;
    }

    if (*reply_token == '0')
        vwarning = 0;
    free(reply_token);
    reply_token = NULL;

    /*
     * Check the latest available ClamAV software version.
     */
    if (NULL == (reply_token = cli_strtok(dnsReply, DNS_UPDATEINFO_NEWVERSION, ":"))) {
        logg("^Failed to find New Version field in DNS Update Info.\n");
        goto done;
    }

    logg("*fc_dns_query_update_info: Software version from DNS: %s\n", reply_token);

    /*
     * Compare the latest available ClamAV version with this ClamAV version.
     * Only throw a warning if the Version Warning Flag was set,
     * and this is not a beta, release candidate, or development version.
     */
    strncpy(version_string, get_version(), sizeof(version_string));
    version_string[31] = 0;

    if (vwarning) {
        if (!strstr(version_string, "devel") &&
            !strstr(version_string, "beta") &&
            !strstr(version_string, "rc")) {

            char *suffix = strchr(version_string, '-');

            if ((suffix && (0 > version_string_compare(version_string, suffix - version_string, reply_token, strlen(reply_token)))) ||
                (!suffix && (0 > version_string_compare(version_string, strlen(version_string), reply_token, strlen(reply_token))))) {

                logg("^Your ClamAV installation is OUTDATED!\n");
                logg("^Local version: %s Recommended version: %s\n", version_string, reply_token);
                logg("DON'T PANIC! Read https://www.clamav.net/documents/upgrading-clamav\n");
                *newVersion = cli_strdup(reply_token);
            }
        }
    }

    free(reply_token);
    reply_token = NULL;

    *dnsUpdateInfo = dnsReply;

    status = FC_SUCCESS;

#endif /* HAVE_RESOLV_H */

done:

    if (FC_SUCCESS != status) {
        free(dnsReply);
    }

    return status;
}

fc_error_t fc_update_database(
    const char *database,
    char **serverList,
    uint32_t nServers,
    int bPrivateMirror,
    const char *dnsUpdateInfo,
    int bScriptedUpdates,
    void *context,
    int *bUpdated)
{
    fc_error_t ret;
    fc_error_t status = FC_EARG;

    char *dbFilename = NULL;
    char currDir[PATH_MAX];
    int signo    = 0;
    long attempt = 1;
    uint32_t i;

    currDir[0] = '\0';

    if ((NULL == database) || (NULL == serverList) || (NULL == bUpdated)) {
        logg("^fc_update_database: Invalid arguments.\n");
        goto done;
    }

    *bUpdated = 0;

    /* Store CWD */
    if (!getcwd(currDir, PATH_MAX)) {
        logg("!getcwd() failed\n");
        status = FC_EDIRECTORY;
        goto done;
    }

    /* Change directory to database directory */
    if (chdir(g_databaseDirectory)) {
        logg("!Can't change dir to %s\n", g_databaseDirectory);
        status = FC_EDIRECTORY;
        goto done;
    }
    logg("*Current working dir is %s\n", g_databaseDirectory);

    /*
     * Attempt to update official database using DatabaseMirrors or PrivateMirrors.
     */
    for (i = 0; i < nServers; i++) {
        for (attempt = 1; attempt <= g_maxAttempts; attempt++) {
            ret = updatedb(
                database,
                dnsUpdateInfo,
                serverList[i],
                bPrivateMirror,
                context,
                bScriptedUpdates,
                attempt == g_maxAttempts ? 1 : 0,
                &signo,
                &dbFilename,
                bUpdated);

            switch (ret) {
                case FC_SUCCESS: {
                    if (*bUpdated) {
                        logg("*fc_update_database: %s updated.\n", dbFilename);
                    } else {
                        logg("*fc_update_database: %s already up-to-date.\n", dbFilename);
                    }
                    goto success;
                }
                case FC_ECONNECTION:
                case FC_EBADCVD:
                case FC_EFAILEDGET:
                case FC_EMIRRORNOTSYNC: {
                    if (attempt < g_maxAttempts) {
                        logg("Trying again in 5 secs...\n");
                        sleep(5);
                    } else {
                        logg("Giving up on %s...\n", serverList[i]);
                        if (i == nServers - 1) {
                            logg("!Update failed for database: %s\n", database);
                            status = ret;
                            goto done;
                        }
                    }
                    break;
                }
                default: {
                    logg("!Unexpected error when attempting to update database: %s\n", database);
                    status = ret;
                    goto done;
                }
            }
        }
    }

success:

    status = FC_SUCCESS;

done:

    if (NULL != dbFilename) {
        free(dbFilename);
    }

    if (currDir[0] != '\0') {
        /* Restore CWD */
        if (chdir(currDir)) {
            logg("!Failed to change back to original directory %s\n", currDir);
            status = FC_EDIRECTORY;
            goto done;
        }
        logg("*Current working dir restored to %s\n", currDir);
    }

    return status;
}

fc_error_t fc_update_databases(
    char **databaseList,
    uint32_t nDatabases,
    char **serverList,
    uint32_t nServers,
    int bPrivateMirror,
    const char *dnsUpdateInfo,
    int bScriptedUpdates,
    void *context,
    uint32_t *nUpdated)
{
    fc_error_t ret;
    fc_error_t status = FC_EARG;
    uint32_t i;
    int bUpdated        = 0;
    uint32_t numUpdated = 0;

    if ((NULL == databaseList) || (0 == nDatabases) || (NULL == serverList) || (NULL == nUpdated)) {
        logg("^fc_update_databases: Invalid arguments.\n");
        goto done;
    }

    *nUpdated = 0;

    for (i = 0; i < nDatabases; i++) {
        if (FC_SUCCESS != (ret = fc_update_database(
                               databaseList[i],
                               serverList,
                               nServers,
                               bPrivateMirror,
                               dnsUpdateInfo,
                               bScriptedUpdates,
                               context,
                               &bUpdated))) {
            logg("^fc_update_databases: fc_update_database failed: %s (%d)\n", fc_strerror(ret), ret);
            status = ret;
            goto done;
        }
        if (bUpdated) {
            numUpdated++;
        }
    }

    *nUpdated = numUpdated;
    status    = FC_SUCCESS;

done:

    return status;
}

fc_error_t fc_download_url_database(
    const char *urlDatabase,
    void *context,
    int *bUpdated)
{
    fc_error_t ret;
    fc_error_t status = FC_EARG;

    char currDir[PATH_MAX];
    long attempt     = 1;
    char *dbFilename = NULL;

    currDir[0] = '\0';

    if ((NULL == urlDatabase) || (NULL == bUpdated)) {
        logg("^fc_download_url_database: Invalid arguments.\n");
        goto done;
    }

    *bUpdated = 0;

    /* Store CWD */
    if (!getcwd(currDir, PATH_MAX)) {
        logg("!getcwd() failed\n");
        status = FC_EDIRECTORY;
        goto done;
    }

    /* Change directory to database directory */
    if (chdir(g_databaseDirectory)) {
        logg("!Can't change dir to %s\n", g_databaseDirectory);
        status = FC_EDIRECTORY;
        goto done;
    }
    logg("*Current working dir is %s\n", g_databaseDirectory);

    /*
     * Attempt to update official database using DatabaseMirrors or PrivateMirrors.
     */
    for (attempt = 1; attempt <= g_maxAttempts; attempt++) {
        int signo = 0;

        ret = updatecustomdb(
            urlDatabase,
            context,
            attempt == g_maxAttempts ? 1 : 0,
            &signo,
            &dbFilename,
            bUpdated);

        switch (ret) {
            case FC_SUCCESS: {
                if (*bUpdated) {
                    logg("*fc_download_url_database: %s updated.\n", dbFilename);
                } else {
                    logg("*fc_download_url_database: %s already up-to-date.\n", dbFilename);
                }
                goto success;
            }
            case FC_ECONNECTION:
            case FC_EBADCVD:
            case FC_EFAILEDGET: {
                if (attempt < g_maxAttempts) {
                    logg("Trying again in 5 secs...\n");
                    sleep(5);
                } else {
                    logg("Update failed for custom database URL: %s\n", urlDatabase);
                    status = ret;
                    goto done;
                }
                break;
            }
            default: {
                logg("Unexpected error when attempting to update from custom database URL: %s\n", urlDatabase);
                status = ret;
                goto done;
            }
        }
    }

success:

    status = FC_SUCCESS;

done:

    if (NULL != dbFilename) {
        free(dbFilename);
    }

    if (currDir[0] != '\0') {
        /* Restore CWD */
        if (chdir(currDir)) {
            logg("!Failed to change back to original directory %s\n", currDir);
            status = FC_EDIRECTORY;
            goto done;
        }
        logg("*Current working dir restored to %s\n", currDir);
    }

    return status;
}

fc_error_t fc_download_url_databases(
    char **urlDatabaseList,
    uint32_t nUrlDatabases,
    void *context,
    uint32_t *nUpdated)
{
    fc_error_t ret;
    fc_error_t status   = FC_EARG;
    int bUpdated        = 0;
    uint32_t numUpdated = 0;
    uint32_t i;

    if ((NULL == urlDatabaseList) || (0 == nUrlDatabases) || (NULL == nUpdated)) {
        logg("^fc_download_url_databases: Invalid arguments.\n");
        goto done;
    }

    *nUpdated = 0;

    for (i = 0; i < nUrlDatabases; i++) {
        if (FC_SUCCESS != (ret = fc_download_url_database(
                               urlDatabaseList[i],
                               context,
                               &bUpdated))) {
            logg("^fc_download_url_databases: fc_download_url_database failed: %s (%d)\n", fc_strerror(ret), ret);
            status = ret;
            goto done;
        }
        if (bUpdated) {
            numUpdated++;
        }
    }

    *nUpdated = numUpdated;
    status    = FC_SUCCESS;

done:

    return status;
}

void fc_set_fccb_download_complete(fccb_download_complete callback)
{
    g_cb_download_complete = callback;
}

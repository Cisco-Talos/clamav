/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

// libclamav
#include "clamav.h"
#include "clamav_rust.h"
#include "others.h"
#include "regex_list.h"
#include "str.h"

// common
#include "cert_util.h"
#include "output.h"
#include "misc.h"

#include "libfreshclam.h"
#include "libfreshclam_internal.h"
#include "dns.h"

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
            return "Failed to initialize";
        case FC_EDIRECTORY:
            return "Invalid, nonexistent, or inaccessible directory";
        case FC_EFILE:
            return "Invalid, nonexistent, or inaccessible file";
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
        case FC_EFORBIDDEN:
            return "Forbidden; Blocked by CDN";
        case FC_ERETRYLATER:
            return "Too many requests; Retry later";
        default:
            return "Unknown libfreshclam error code!";
    }
}

fc_error_t fc_initialize(fc_config *fcConfig)
{
    fc_error_t status = FC_EARG;
    STATBUF statbuf;
    char *certsDirectory         = NULL;
    FFIError *new_verifier_error = NULL;

    if (NULL == fcConfig) {
        printf("fc_initialize: Invalid arguments.\n");
        return status;
    }

    /* Rust logging initialization */
    if (!clrs_log_init()) {
        cli_dbgmsg("Unexpected problem occurred while setting up rust logging... continuing without rust logging. \
                    Please submit an issue to https://github.com/Cisco-Talos/clamav");
    }

    /* Initialize libcurl */
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
        logg_file = cli_safer_strdup(fcConfig->logFile);
        if (0 != logg(LOGG_INFO_NF, "--------------------------------------\n")) {
            mprintf(LOGG_ERROR, "Problem with internal logger (UpdateLogFile = %s).\n", logg_file);
            status = FC_ELOGGING;
            goto done;
        }
    }

#if defined(USE_SYSLOG) && !defined(C_AIX)
    /* Initialize syslog if available and requested, and is not already set */
    if (fcConfig->logFlags & FC_CONFIG_LOG_SYSLOG) {
        int logFacility = LOG_LOCAL6;
        if ((0 == logg_syslog) && (NULL != fcConfig->logFacility) && (-1 == (logFacility = logg_facility(fcConfig->logFacility)))) {
            mprintf(LOGG_ERROR, "LogFacility: %s: No such facility.\n", fcConfig->logFacility);
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
        mprintf(LOGG_ERROR, "The LocalIP feature was requested but this local IP support is not presently available.\n");
        mprintf(LOGG_ERROR, "Your installation was built with libcurl version %u.%u.%u.\n", LIBCURL_VERSION_MAJOR, LIBCURL_VERSION_MINOR, LIBCURL_VERSION_PATCH);
        mprintf(LOGG_ERROR, "LocalIP requires libcurl version 7.33.0 or higher and must include the c-ares optional dependency.\n");
#else
        g_localIP = cli_safer_strdup(fcConfig->localIP);
#endif
    }
    if (NULL != fcConfig->userAgent) {
        g_userAgent = cli_safer_strdup(fcConfig->userAgent);
    }
    if (NULL != fcConfig->proxyServer) {
        g_proxyServer = cli_safer_strdup(fcConfig->proxyServer);
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
        g_proxyUsername = cli_safer_strdup(fcConfig->proxyUsername);
    }
    if (NULL != fcConfig->proxyPassword) {
        g_proxyPassword = cli_safer_strdup(fcConfig->proxyPassword);
    }

#ifdef _WIN32
    if ((fcConfig->databaseDirectory[strlen(fcConfig->databaseDirectory) - 1] != '/') &&
        ((fcConfig->databaseDirectory[strlen(fcConfig->databaseDirectory) - 1] != '\\'))) {
#else
    if (fcConfig->databaseDirectory[strlen(fcConfig->databaseDirectory) - 1] != '/') {
#endif
        g_databaseDirectory = malloc(strlen(fcConfig->databaseDirectory) + strlen(PATHSEP) + 1);
        snprintf(
            g_databaseDirectory,
            strlen(fcConfig->databaseDirectory) + strlen(PATHSEP) + 1,
            "%s" PATHSEP,
            fcConfig->databaseDirectory);
    } else {
        g_databaseDirectory = cli_safer_strdup(fcConfig->databaseDirectory);
    }

    /* Validate that the database directory exists, and store it. */
    if (LSTAT(g_databaseDirectory, &statbuf) == -1) {
        logg(LOGG_ERROR, "Database directory does not exist: %s\n", g_databaseDirectory);
        status = FC_EDIRECTORY;
        goto done;
    }
    if (!S_ISDIR(statbuf.st_mode)) {
        logg(LOGG_ERROR, "Database directory is not a directory: %s\n", g_databaseDirectory);
        status = FC_EDIRECTORY;
        goto done;
    }

#ifdef _WIN32
    if ((fcConfig->certsDirectory[strlen(fcConfig->certsDirectory) - 1] != '/') &&
        ((fcConfig->certsDirectory[strlen(fcConfig->certsDirectory) - 1] != '\\'))) {
#else
    if (fcConfig->certsDirectory[strlen(fcConfig->certsDirectory) - 1] != '/') {
#endif
        certsDirectory = malloc(strlen(fcConfig->certsDirectory) + strlen(PATHSEP) + 1);
        snprintf(
            certsDirectory,
            strlen(fcConfig->certsDirectory) + strlen(PATHSEP) + 1,
            "%s" PATHSEP,
            fcConfig->certsDirectory);
    } else {
        certsDirectory = cli_safer_strdup(fcConfig->certsDirectory);
    }

    if (!codesign_verifier_new(certsDirectory, &g_signVerifier, &new_verifier_error)) {
        logg(LOGG_ERROR, "Failed to create a new code-signature verifier: %s\n", ffierror_fmt(new_verifier_error));
        status = FC_EINIT;
        goto done;
    }

    g_tempDirectory = cli_safer_strdup(fcConfig->tempDirectory);

    g_maxAttempts    = fcConfig->maxAttempts;
    g_connectTimeout = fcConfig->connectTimeout;
    g_requestTimeout = fcConfig->requestTimeout;

    g_bCompressLocalDatabase = fcConfig->bCompressLocalDatabase;

    g_bFipsLimits = fcConfig->bFipsLimits;

    /* Load or create freshclam.dat */
    if (FC_SUCCESS != load_freshclam_dat()) {
        logg(LOGG_DEBUG, "Failed to load freshclam.dat; will create a new freshclam.dat\n");

        if (FC_SUCCESS != new_freshclam_dat()) {
            logg(LOGG_WARNING, "Failed to create a new freshclam.dat!\n");
            status = FC_EINIT;
            goto done;
        }
    }

    status = FC_SUCCESS;

done:
    if (FC_SUCCESS != status) {
        fc_cleanup();
    }
    if (NULL != certsDirectory) {
        free(certsDirectory);
    }
    if (NULL != new_verifier_error) {
        ffierror_free(new_verifier_error);
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
    if (NULL != g_freshclamDat) {
        free(g_freshclamDat);
        g_freshclamDat = NULL;
    }
    if (NULL != g_signVerifier) {
        codesign_verifier_free(g_signVerifier);
    }
}

fc_error_t fc_prune_database_directory(char **databaseList, uint32_t nDatabases)
{
    fc_error_t status = FC_EARG;

    DIR *dir = NULL;
    struct dirent *dent;
    char *extension = NULL;

    /* Change directory to database directory */
    if (chdir(g_databaseDirectory)) {
        logg(LOGG_ERROR, "Can't change dir to %s\n", g_databaseDirectory);
        status = FC_EDIRECTORY;
        goto done;
    }

    logg(LOGG_DEBUG, "Current working dir is %s\n", g_databaseDirectory);

    if (!(dir = opendir(g_databaseDirectory))) {
        logg(LOGG_ERROR, "checkdbdir: Can't open directory %s\n", g_databaseDirectory);
        status = FC_EDBDIRACCESS;
        goto done;
    }

    while ((dent = readdir(dir))) {
        if (dent->d_ino) {
            // prune any CVD/CLD files that are not in the database list
            if ((NULL != (extension = strstr(dent->d_name, ".cld"))) ||
                (NULL != (extension = strstr(dent->d_name, ".cvd")))) {

                // find the first '-' or '.' in the filename
                // Use this to determine the database name.
                // We need this so we can ALSO prune the .sign files for unwanted databases.
                // Will also be useful in case the database filename includes a hyphenated version number.
                const char *first_dash_or_dot = strchr(dent->d_name, '-');
                if (NULL == first_dash_or_dot) {
                    first_dash_or_dot = extension;
                }

                uint32_t i;
                int bFound = 0;
                for (i = 0; i < nDatabases; i++) {
                    // check that the database name is in the database list
                    if (0 == strncmp(databaseList[i], dent->d_name, first_dash_or_dot - dent->d_name)) {
                        bFound = 1;
                    }
                }
                if (!bFound) {
                    /* Prune CVD/CLD */
                    mprintf(LOGG_INFO, "Pruning unwanted or deprecated database file %s.\n", dent->d_name);
                    if (unlink(dent->d_name)) {
                        mprintf(LOGG_ERROR, "Failed to prune unwanted database file %s, consider removing it manually.\n", dent->d_name);
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
    unsigned int dboptions = 0;

    if ((NULL == dbFilename)) {
        logg(LOGG_WARNING, "fc_test_database: Invalid arguments.\n");
        goto done;
    }

    logg(LOGG_DEBUG, "Loading signatures from %s\n", dbFilename);
    if (NULL == (engine = cl_engine_new())) {
        status = FC_ETESTFAIL;
        goto done;
    }

    // Disable cache as testing the database doesn't need caching,
    // having cache will only waste time and memory.
    engine->engine_options |= ENGINE_OPTIONS_DISABLE_CACHE;

    cl_engine_set_clcb_stats_submit(engine, NULL);

    dboptions = CL_DB_PHISHING | CL_DB_PHISHING_URLS | CL_DB_BYTECODE | CL_DB_PUA | CL_DB_ENHANCED;
    if (g_bFipsLimits) {
        dboptions |= CL_DB_FIPS_LIMITS;
    }

    if (CL_SUCCESS != (cl_ret = cl_load(
                           dbFilename,
                           engine,
                           &newsigs,
                           dboptions))) {
        logg(LOGG_ERROR, "Failed to load new database: %s\n", cl_strerror(cl_ret));
        status = FC_ETESTFAIL;
        goto done;
    }

    if (bBytecodeEnabled && (CL_SUCCESS != (cl_ret = cli_bytecode_prepare2(
                                                engine, &engine->bcs,
                                                engine->dconf->bytecode
                                                /*FIXME: dconf has no sense here */)))) {
        logg(LOGG_ERROR, "Failed to compile/load bytecode: %s\n", cl_strerror(cl_ret));
        status = FC_ETESTFAIL;
        goto done;
    }
    logg(LOGG_DEBUG, "Properly loaded %u signatures from %s\n", newsigs, dbFilename);

    status = FC_SUCCESS;

done:

    if (NULL != engine) {
        if (engine->domain_list_matcher && engine->domain_list_matcher->sha2_256_pfx_set.keys)
            cli_hashset_destroy(&engine->domain_list_matcher->sha2_256_pfx_set);

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
        logg(LOGG_WARNING, "dns_query_update_info: Invalid arguments.\n");
        status = FC_EARG;
        goto done;
    }

    *dnsUpdateInfo = NULL;
    *newVersion    = NULL;

#ifdef HAVE_RESOLV_H

    if (dnsUpdateInfoServer == NULL) {
        logg(LOGG_WARNING, "DNS Update Info disabled. Falling back to HTTP mode.\n");
        goto done;
    }

    if (NULL == (dnsReply = dnsquery(dnsUpdateInfoServer, T_TXT, &ttl))) {
        logg(LOGG_WARNING, "Invalid DNS reply. Falling back to HTTP mode.\n");
        goto done;
    }

    logg(LOGG_DEBUG, "TTL: %d\n", ttl);

    /*
     * Check Record Time.
     */
    if (NULL == (reply_token = cli_strtok(dnsReply, DNS_UPDATEINFO_RECORDTIME, ":"))) {
        logg(LOGG_WARNING, "Failed to find Record Time field in DNS Update Info.\n");
        goto done;
    }

    recordTime = atoi(reply_token);
    free(reply_token);
    reply_token = NULL;

    time(&currentTime);
    if ((int)currentTime - recordTime > DNS_WARNING_THRESHOLD_SECONDS) {
        logg(LOGG_WARNING, "DNS record is older than %d hours.\n", DNS_WARNING_THRESHOLD_HOURS);
        goto done;
    }

    /*
     * Check Version Warning Flag.
     */
    if (NULL == (reply_token = cli_strtok(dnsReply, DNS_UPDATEINFO_VERSIONWARNING, ":"))) {
        logg(LOGG_WARNING, "Failed to find Version Warning Flag in DNS Update Info.\n");
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
        logg(LOGG_WARNING, "Failed to find New Version field in DNS Update Info.\n");
        goto done;
    }

    logg(LOGG_DEBUG, "fc_dns_query_update_info: Software version from DNS: %s\n", reply_token);

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

                logg(LOGG_WARNING, "Your ClamAV installation is OUTDATED!\n");
                logg(LOGG_WARNING, "Local version: %s Recommended version: %s\n", version_string, reply_token);
                logg(LOGG_INFO, "DON'T PANIC! Read https://docs.clamav.net/manual/Installing.html\n");
                *newVersion = cli_safer_strdup(reply_token);
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
    int signo        = 0;
    long attempt     = 1;
    uint32_t i;

    if ((NULL == database) || (NULL == serverList) || (NULL == bUpdated)) {
        logg(LOGG_WARNING, "fc_update_database: Invalid arguments.\n");
        goto done;
    }

    *bUpdated = 0;

    /* Change directory to database directory */
    if (chdir(g_databaseDirectory)) {
        logg(LOGG_ERROR, "Can't change dir to %s\n", g_databaseDirectory);
        status = FC_EDIRECTORY;
        goto done;
    }
    logg(LOGG_DEBUG, "Current working dir is %s\n", g_databaseDirectory);

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
                        logg(LOGG_DEBUG, "fc_update_database: %s updated.\n", dbFilename);
                    } else {
                        logg(LOGG_DEBUG, "fc_update_database: %s already up-to-date.\n", dbFilename);
                    }
                    goto success;
                }
                case FC_ECONNECTION:
                case FC_EBADCVD:
                case FC_EFAILEDGET: {
                    if (attempt < g_maxAttempts) {
                        logg(LOGG_INFO, "Trying again in 5 secs...\n");
                        sleep(5);
                    } else {
                        logg(LOGG_INFO, "Giving up on %s...\n", serverList[i]);
                        if (i == nServers - 1) {
                            logg(LOGG_ERROR, "Update failed for database: %s\n", database);
                            status = ret;
                            goto done;
                        }
                    }
                    break;
                }
                case FC_EMIRRORNOTSYNC: {
                    logg(LOGG_INFO, "Received an older %s CVD than was advertised. We'll retry so the incremental update will ensure we're up-to-date.\n", database);
                    break;
                }
                case FC_EFORBIDDEN: {
                    char retry_after_string[26];
                    struct tm *tm_info;
                    tm_info = localtime(&g_freshclamDat->retry_after);
                    if (NULL == tm_info) {
                        logg(LOGG_ERROR, "Failed to query the local time for the retry-after date!\n");
                        status = FC_ERROR;
                        goto done;
                    }
                    strftime(retry_after_string, 26, "%Y-%m-%d %H:%M:%S", tm_info);
                    logg(LOGG_WARNING, "FreshClam received error code 403 from the ClamAV Content Delivery Network (CDN).\n");
                    logg(LOGG_INFO, "This could mean several things:\n");
                    logg(LOGG_INFO, " 1. You are running an out-of-date version of ClamAV / FreshClam.\n");
                    logg(LOGG_INFO, "    Ensure you are the most updated version by visiting https://www.clamav.net/downloads\n");
                    logg(LOGG_INFO, " 2. Your network is explicitly denied by the FreshClam CDN.\n");
                    logg(LOGG_INFO, "    In order to rectify this please check that you are:\n");
                    logg(LOGG_INFO, "   a. Running an up-to-date version of FreshClam\n");
                    logg(LOGG_INFO, "   b. Running FreshClam no more than once an hour\n");
                    logg(LOGG_INFO, "   c. Connecting from an IP in a blocked region\n");
                    logg(LOGG_INFO, "      Please see https://www.cisco.com/c/m/en_us/crisissupport.html\n");
                    logg(LOGG_INFO, "   d. If you have checked (a), (b) and (c), please open a ticket at\n");
                    logg(LOGG_INFO, "      https://github.com/Cisco-Talos/clamav/issues\n");
                    logg(LOGG_INFO, "      and we will investigate why your network is blocked.\n");
                    if (0 != g_lastRay[0]) {
                        logg(LOGG_INFO, "      Please provide the following cf-ray id with your ticket: %s\n", g_lastRay);
                        logg(LOGG_INFO, "\n");
                    }
                    logg(LOGG_WARNING, "You are on cool-down until after: %s\n", retry_after_string);
                    status = ret;
                    goto done;
                    break;
                }
                case FC_ERETRYLATER: {
                    char retry_after_string[26];
                    struct tm *tm_info;
                    tm_info = localtime(&g_freshclamDat->retry_after);
                    if (NULL == tm_info) {
                        logg(LOGG_ERROR, "Failed to query the local time for the retry-after date!\n");
                        status = FC_ERROR;
                        goto done;
                    }
                    strftime(retry_after_string, 26, "%Y-%m-%d %H:%M:%S", tm_info);
                    logg(LOGG_WARNING, "FreshClam received error code 429 from the ClamAV Content Delivery Network (CDN).\n");
                    logg(LOGG_INFO, "This means that you have been rate limited by the CDN.\n");
                    logg(LOGG_INFO, " 1. Run FreshClam no more than once an hour to check for updates.\n");
                    logg(LOGG_INFO, "    FreshClam should check DNS first to see if an update is needed.\n");
                    logg(LOGG_INFO, " 2. If you have more than 10 hosts on your network attempting to download,\n");
                    logg(LOGG_INFO, "    it is recommended that you set up a private mirror on your network using\n");
                    logg(LOGG_INFO, "    cvdupdate (https://pypi.org/project/cvdupdate/) to save bandwidth on the\n");
                    logg(LOGG_INFO, "    CDN and your own network.\n");
                    logg(LOGG_INFO, " 3. Please do not open a ticket asking for an exemption from the rate limit,\n");
                    logg(LOGG_INFO, "    it will not be granted.\n");
                    logg(LOGG_WARNING, "You are on cool-down until after: %s\n", retry_after_string);
                    goto success;
                    break;
                }
                default: {
                    logg(LOGG_ERROR, "Unexpected error when attempting to update %s: %s\n", database, fc_strerror(ret));
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
        logg(LOGG_WARNING, "fc_update_databases: Invalid arguments.\n");
        goto done;
    }

    *nUpdated = 0;

    if (g_freshclamDat->retry_after > 0) {
        if (g_freshclamDat->retry_after > time(NULL)) {
            /* We're on cool-down, try again later. */
            char retry_after_string[26];
            struct tm *tm_info;
            tm_info = localtime(&g_freshclamDat->retry_after);
            if (NULL == tm_info) {
                logg(LOGG_ERROR, "Failed to query the local time for the retry-after date!\n");
                status = FC_ERROR;
                goto done;
            }
            strftime(retry_after_string, 26, "%Y-%m-%d %H:%M:%S", tm_info);
            logg(LOGG_WARNING, "FreshClam previously received error code 429 or 403 from the ClamAV Content Delivery Network (CDN).\n");
            logg(LOGG_INFO, "This means that you have been rate limited or blocked by the CDN.\n");
            logg(LOGG_INFO, " 1. Verify that you're running a supported ClamAV version.\n");
            logg(LOGG_INFO, "    See https://docs.clamav.net/faq/faq-eol.html for details.\n");
            logg(LOGG_INFO, " 2. Run FreshClam no more than once an hour to check for updates.\n");
            logg(LOGG_INFO, "    FreshClam should check DNS first to see if an update is needed.\n");
            logg(LOGG_INFO, " 3. If you have more than 10 hosts on your network attempting to download,\n");
            logg(LOGG_INFO, "    it is recommended that you set up a private mirror on your network using\n");
            logg(LOGG_INFO, "    cvdupdate (https://pypi.org/project/cvdupdate/) to save bandwidth on the\n");
            logg(LOGG_INFO, "    CDN and your own network.\n");
            logg(LOGG_INFO, " 4. Please do not open a ticket asking for an exemption from the rate limit,\n");
            logg(LOGG_INFO, "    it will not be granted.\n");
            if (0 != g_lastRay[0]) {
                logg(LOGG_INFO, " 5. If you have verified that you are not blocked due to your region, and have\n");
                logg(LOGG_INFO, "    not exceeded the rate limit, please provide the following cf-ray id when\n");
                logg(LOGG_INFO, "    submitting a ticket: %s\n", g_lastRay);
                logg(LOGG_INFO, "\n");
            }
            logg(LOGG_WARNING, "You are still on cool-down until after: %s\n", retry_after_string);

            status = FC_SUCCESS;
            goto done;
        } else {
            g_freshclamDat->retry_after = 0;
            logg(LOGG_WARNING, "Cool-down expired, ok to try again.\n");
            save_freshclam_dat();
        }
    }

    /* Clear the old cf-ray ids.  This is really only so that
     * we don't have stale ones when we are running in daemon mode. */
    memset(&g_lastRay, 0, sizeof(g_lastRay));

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

    long attempt     = 1;
    char *dbFilename = NULL;

    if ((NULL == urlDatabase) || (NULL == bUpdated)) {
        logg(LOGG_WARNING, "fc_download_url_database: Invalid arguments.\n");
        goto done;
    }

    *bUpdated = 0;

    /* Change directory to database directory */
    if (chdir(g_databaseDirectory)) {
        logg(LOGG_ERROR, "Can't change dir to %s\n", g_databaseDirectory);
        status = FC_EDIRECTORY;
        goto done;
    }
    logg(LOGG_DEBUG, "Current working dir is %s\n", g_databaseDirectory);

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
                    logg(LOGG_DEBUG, "fc_download_url_database: %s updated.\n", dbFilename);
                } else {
                    logg(LOGG_DEBUG, "fc_download_url_database: %s already up-to-date.\n", dbFilename);
                }
                goto success;
            }
            case FC_ECONNECTION:
            case FC_EBADCVD:
            case FC_EFAILEDGET: {
                if (attempt < g_maxAttempts) {
                    logg(LOGG_INFO, "Trying again in 5 secs...\n");
                    sleep(5);
                } else {
                    logg(LOGG_INFO, "Update failed for custom database URL: %s\n", urlDatabase);
                    status = ret;
                    goto done;
                }
                break;
            }
            case FC_EFORBIDDEN: {
                char retry_after_string[26];
                struct tm *tm_info;
                tm_info = localtime(&g_freshclamDat->retry_after);
                if (NULL == tm_info) {
                    logg(LOGG_ERROR, "Failed to query the local time for the retry-after date!\n");
                    status = FC_ERROR;
                    goto done;
                }
                strftime(retry_after_string, 26, "%Y-%m-%d %H:%M:%S", tm_info);
                logg(LOGG_WARNING, "FreshClam received error code 403 from the ClamAV Content Delivery Network (CDN).\n");
                logg(LOGG_INFO, "This could mean several things:\n");
                logg(LOGG_INFO, " 1. You are running an out-of-date version of ClamAV / FreshClam.\n");
                logg(LOGG_INFO, "    Ensure you are the most updated version by visiting https://www.clamav.net/downloads\n");
                logg(LOGG_INFO, " 2. Your network is explicitly denied by the FreshClam CDN.\n");
                logg(LOGG_INFO, "    In order to rectify this please check that you are:\n");
                logg(LOGG_INFO, "   a. Running an up-to-date version of FreshClam\n");
                logg(LOGG_INFO, "   b. Running FreshClam no more than once an hour\n");
                logg(LOGG_INFO, "   c. If you have checked (a) and (b), please open a ticket at\n");
                logg(LOGG_INFO, "      https://github.com/Cisco-Talos/clamav/issues\n");
                logg(LOGG_INFO, "      and we will investigate why your network is blocked.\n");
                if (0 != g_lastRay[0]) {
                    logg(LOGG_INFO, "      Please provide the following cf-ray id with your ticket: %s\n", g_lastRay);
                    logg(LOGG_INFO, "\n");
                }
                logg(LOGG_WARNING, "You are on cool-down until after: %s\n", retry_after_string);

                status = ret;
                goto done;
                break;
            }
            case FC_ERETRYLATER: {
                char retry_after_string[26];
                struct tm *tm_info;
                tm_info = localtime(&g_freshclamDat->retry_after);
                if (NULL == tm_info) {
                    logg(LOGG_ERROR, "Failed to query the local time for the retry-after date!\n");
                    status = FC_ERROR;
                    goto done;
                }
                strftime(retry_after_string, 26, "%Y-%m-%d %H:%M:%S", tm_info);
                logg(LOGG_WARNING, "FreshClam received error code 429 from the ClamAV Content Delivery Network (CDN).\n");
                logg(LOGG_INFO, "This means that you have been rate limited by the CDN.\n");
                logg(LOGG_INFO, " 1. Run FreshClam no more than once an hour to check for updates.\n");
                logg(LOGG_INFO, "    FreshClam should check DNS first to see if an update is needed.\n");
                logg(LOGG_INFO, " 2. If you have more than 10 hosts on your network attempting to download,\n");
                logg(LOGG_INFO, "    it is recommended that you set up a private mirror on your network using\n");
                logg(LOGG_INFO, "    cvdupdate (https://pypi.org/project/cvdupdate/) to save bandwidth on the\n");
                logg(LOGG_INFO, "    CDN and your own network.\n");
                logg(LOGG_INFO, " 3. Please do not open a ticket asking for an exemption from the rate limit,\n");
                logg(LOGG_INFO, "    it will not be granted.\n");
                logg(LOGG_WARNING, "You are on cool-down until after: %s\n", retry_after_string);
                goto success;
                break;
            }
            default: {
                logg(LOGG_INFO, "Unexpected error when attempting to update from custom database URL: %s\n", urlDatabase);
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
        logg(LOGG_WARNING, "fc_download_url_databases: Invalid arguments.\n");
        goto done;
    }

    *nUpdated = 0;

    for (i = 0; i < nUrlDatabases; i++) {
        if (FC_SUCCESS != (ret = fc_download_url_database(
                               urlDatabaseList[i],
                               context,
                               &bUpdated))) {
            logg(LOGG_WARNING, "fc_download_url_databases: fc_download_url_database failed: %s (%d)\n", fc_strerror(ret), ret);
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

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

#ifndef __LIBFRESHCLAM_H
#define __LIBFRESHCLAM_H

#include "clamav-types.h"

/*
 * FreshClam configuration flag options.
 */
// clang-format off
#define FC_CONFIG_MSG_DEBUG        0x1  // Enable debug messages.
#define FC_CONFIG_MSG_VERBOSE      0x2  // Enable verbose mode.
#define FC_CONFIG_MSG_QUIET        0x4  // Only output error messages.
#define FC_CONFIG_MSG_NOWARN       0x8  // Don't output warning messages.
#define FC_CONFIG_MSG_STDOUT       0x10 // Write to stdout instead of stderr.
#define FC_CONFIG_MSG_SHOWPROGRESS 0x20 // Show download progress percentage.

#define FC_CONFIG_LOG_VERBOSE 0x1  // Be verbose in log output as well.
#define FC_CONFIG_LOG_NOWARN  0x2  // Don't log warning messages.
#define FC_CONFIG_LOG_TIME    0x4  // Include timestamp in log messages.
#define FC_CONFIG_LOG_ROTATE  0x8  // Rotate logs if they exceed MaxLogSize.
#define FC_CONFIG_LOG_SYSLOG  0x10 // Enable Syslog.
// clang-format on

/* freshclam config options */
typedef struct fc_config_ {
    uint32_t msgFlags;               /**< FC_CONFIG_MSG bitflag field. */
    uint32_t logFlags;               /**< FC_CONFIG_LOG bitflag field. */
    uint64_t maxLogSize;             /**< Max size of logfile, if enabled. */
    uint32_t maxAttempts;            /**< Max # of download attempts. Must be > 0 */
    uint32_t connectTimeout;         /**< CURLOPT_CONNECTTIMEOUT, Timeout for the. connection phase (seconds). */
    uint32_t requestTimeout;         /**< CURLOPT_LOW_SPEED_TIME, Timeout for libcurl transfer operation (seconds). */
    uint32_t bCompressLocalDatabase; /**< If set, will apply gz compression to CLD databases. */
    const char *logFile;             /**< (optional) Filepath to use for log output, if desired. */
    const char *logFacility;         /**< (optional) System logging facility (I.e. "syslog"), if desired. */
    const char *localIP;             /**< (optional) client IP for multihomed systems. */
    const char *userAgent;           /**< (optional) Alternative User Agent. */
    const char *proxyServer;         /**< (optional) http(s) url for proxy server. */
    uint16_t proxyPort;              /**< (optional) Proxy server port #. */
    const char *proxyUsername;       /**< (optional) Username for proxy server authentication .*/
    const char *proxyPassword;       /**< (optional) Password for proxy server authentication. */
    const char *databaseDirectory;   /**< Filepath of database directory. */
    const char *tempDirectory;       /**< Filepath to store temp files. */
    const char *certsDirectory;      /**< Filepath of clamav ca certificates directory to verify database external
                                      *   digital signatures. */
    bool bFipsLimits;                /**< If true, enable FIPS cryptographic hashing limitations that will require CVDs
                                      *   to be signed with FIPS-compliant external '.sign' file. */
} fc_config;

typedef enum fc_error_tag {
    FC_SUCCESS  = 0,
    FC_UPTODATE = 1,
    FC_EINIT,
    FC_EDIRECTORY,
    FC_EFILE,
    FC_ECONNECTION,
    FC_EEMPTYFILE,
    FC_EBADCVD,
    FC_ETESTFAIL,
    FC_ECONFIG,
    FC_EDBDIRACCESS,
    FC_EFAILEDGET,
    FC_EMIRRORNOTSYNC,
    FC_ELOGGING,
    FC_EFAILEDUPDATE,
    FC_EMEM,
    FC_EARG,
    FC_EFORBIDDEN,
    FC_ERETRYLATER,
    FC_ERROR
} fc_error_t;

/**
 * @brief  Translate an FC_<code> to a human readable message.
 *
 * @param fcerror       fc_error_t code
 * @return const char * message.
 */
const char *fc_strerror(fc_error_t fcerror);

/**
 * @brief Configure libfreshclam.
 *
 * This will initialize libcurl with `curl_global_init`.
 * This should only be called once per application.
 *
 * If you are initializing libfreshclam from a Windows DLL you should not
 * initialize it from DllMain or a static initializer because Windows holds
 * the loader lock during that time and it could cause a deadlock.
 *
 * @param config        Configuration options.
 * @return fc_error_t   FC_SUCCESS if success.
 * @return fc_error_t   FC_ELOGGING if there is an issue writing to the log.
 */
fc_error_t fc_initialize(fc_config *config);

/**
 * @brief Cleanup libfreshclam features.
 *
 * This will call `curl_global_cleanup`.
 * This should only be invoke once at the end of your
 * application.
 */
void fc_cleanup(void);

/**
 * @brief Delete CVD & CLD files from database directory that aren't in the provided list.
 *
 * Will not touch files other than CLD and CVD files.
 *
 * @param databaseList  List of official databases to keep.
 * @param nDatabases    Number of databases in list.
 * @return fc_error_t   FC_SUCCESS if success.
 * @return fc_error_t   FC_EDBDIRACCESS if database access issue occurred.
 * @return fc_error_t   FC_EARG if invalid arguments.
 */
fc_error_t fc_prune_database_directory(
    char **databaseList,
    uint32_t nDatabases);

/**
 * @brief Test if database loads without errors.
 *
 * @param dbFilename   Filename of database.
 * @param bBytecodeEnabled Non-zero if database has bytecode signatures, and should be tested.
 * @return fc_error_t  FC_SUCCESS if loaded correctly.
 * @return fc_error_t  FC_EARG callback was passed invalid arguments.
 */
fc_error_t fc_test_database(
    const char *dbFilename,
    int bBytecodeEnabled);

/**
 * @brief Query Update Info via DNS to get database version info, and ClamAV version info.
 *
 * Caller must free dnsUpdateInfo.
 *
 * @param dnsUpdateInfoServer   (optional) The DNS server to query for Update Info. If NULL, will disable DNS update info query feature.
 * @param[out] dnsUpdateInfo    The Update Info DNS reply string.
 * @param[out] newVersion       New version of ClamAV available.
 * @return fc_error_t           FC_SUCCESS if success.
 * @return fc_error_t           FC_EARG if invalid args.
 * @return fc_error_t           FC_EFAILEDGET if error or disabled and should fall back to HTTP mode for update info.
 */
fc_error_t fc_dns_query_update_info(
    const char *dnsUpdateInfoServer,
    char **dnsUpdateInfo,
    char **newVersion);

/**
 * @brief Download a database directly from a URL.
 *
 * Whole file download.  Does not support incremental update.
 *
 * @param url           Database URL (http, https, file).
 * @param context       Application context to pass to fccb_download_complete callback.
 * @param[out] bUpdated Non-zero if database was updated to new version or is entirely new.
 * @return fc_error_t   FC_SUCCESS if database downloaded and callback executed successfully.
 */
fc_error_t fc_download_url_database(
    const char *urlDatabase,
    void *context,
    int *bUpdated);

/**
 * @brief Download databases directly from a URLs.
 *
 * @param urlDatabaseList List of database URLs
 * @param nUrlDatabases   Number of URLs in list.
 * @param context         Application context to pass to fccb_download_complete callback.
 * @param[out] nUpdated   Number of databases that were updated.
 * @return fc_error_t     FC_SUCCESS if database downloaded and callback executed successfully.
 */
fc_error_t fc_download_url_databases(
    char **urlDatabaseList,
    uint32_t nUrlDatabases,
    void *context,
    uint32_t *nUpdated);

/**
 * @brief Update specific official database, given list of update servers.
 *
 * @param dbName                CVD/CLD database name, excluding file extension.
 * @param serverList            String array of update servers.
 * @param nServers              Number of servers in list.
 * @param dnsUpdateInfoServer   DNS server for update info check. May be NULL to disable use of DNS.
 * @param bScriptedUpdates      Enable incremental/updates (should not be enabled for PrivateMirrors).
 * @param context               Application context to pass to fccb_download_complete callback.
 * @param[out] bUpdated         Non-zero if database was updated to new version or is entirely new.
 * @return fc_error_t           FC_SUCCESS if database downloaded and callback executed successfully.
 */
fc_error_t fc_update_database(
    const char *database,
    char **serverList,
    uint32_t nServers,
    int bPrivateMirror,
    const char *dnsUpdateInfo,
    int bScriptedUpdates,
    void *context,
    int *bUpdated);

/**
 * @brief Update list of official databases, given list of update servers.
 *
 * @param dbNames               String array of CVD/CLD database names, excluding file extensions.
 * @param nDbNames              Number of names in array.
 * @param serverList            String array of update servers.
 * @param nServers              Number of servers in list.
 * @param dnsUpdateInfoServer   DNS server for update info check. May be NULL to disable use of DNS.
 * @param bScriptedUpdates      Enable incremental/updates (should not be enabled for PrivateMirrors).
 * @param context               Application context to pass to fccb_download_complete callback.
 * @param[out] nUpdated         Number of databases that were updated.
 * @return fc_error_t           FC_SUCCESS if database downloaded and callback executed successfully.
 */
fc_error_t fc_update_databases(
    char **databaseList,
    uint32_t nDatabases,
    char **serverList,
    uint32_t nServers,
    int bPrivateMirror,
    const char *dnsUpdateInfo,
    int bScriptedUpdates,
    void *context,
    uint32_t *nUpdated);

/* ----------------------------------------------------------------------------
 * Callback function type definitions.
 */

/**
 * @brief FreshClam callback Download Complete
 *
 * Called after each database has been downloaded or updated.
 *
 * @param dbFilepath   Filename of the downloaded database in database directory.
 * @param context      Opaque application provided data.
 * @return fc_error_t  FC_SUCCESS if callback action was successful.
 * @return fc_error_t  FC_EARG callback was passed invalid arguments.
 * @return fc_error_t  FC_ETESTFAIL if callback action failed and libfreshclam should abort any additional updates.
 */
typedef fc_error_t (*fccb_download_complete)(const char *dbFilename, void *context);
/**
 * @brief Set a custom Download Complete callback function.
 *
 * @param callback  The callback function pointer.
 */
extern void fc_set_fccb_download_complete(fccb_download_complete callback);

#endif // __LIBFRESHCLAM_H

/*
 *  Copyright (C) 2013-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *  Copyright (C) 2002-2007 Tomasz Kojm <tkojm@clamav.net>
 *
 *  HTTP/1.1 compliance by Arkadiusz Miskiewicz <misiek@pld.org.pl>
 *  Proxy support by Nigel Horne <njh@bandsman.co.uk>
 *  Proxy authorization support by Gernot Tenchio <g.tenchio@telco-tech.de>
 *		     (uses fmt_base64() from libowfat (http://www.fefe.de))
 *
 *  CDIFF code (C) 2006 Sensory Networks, Inc.
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
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

/* for strptime, it is POSIX, but defining _XOPEN_SOURCE to 600
 * fails on Solaris because it would require a c99 compiler,
 * 500 fails completely on Solaris, and FreeBSD, and w/o _XOPEN_SOURCE
 * strptime is not defined on Linux */
#define __EXTENSIONS

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <ctype.h>
#ifndef _WIN32
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#endif
#include <sys/types.h>
#include <time.h>
#include <fcntl.h>
#ifndef _WIN32
#include <sys/wait.h>
#endif
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <zlib.h>
#include <math.h>

#include <curl/curl.h>
#include <openssl/rand.h>

#include "target.h"

// libclamav
#include "clamav.h"
#include "others.h"
#include "str.h"
#include "cvd.h"
#include "regex_list.h"

// common
#include "optparser.h"
#include "output.h"
#include "clamav_rust.h"
#include "tar.h"
#include "clamdcom.h"
#include "cert_util.h"

#include "libfreshclam.h"
#include "libfreshclam_internal.h"
#include "dns.h"

#define DB_FILENAME_MAX 60
#define CVD_HEADER_SIZE 512

/*
 * Globals
 */
/* Callback function pointers */
fccb_download_complete g_cb_download_complete = NULL;

/* Configuration options */
char *g_localIP   = NULL;
char *g_userAgent = NULL;

char *g_proxyServer   = NULL;
uint16_t g_proxyPort  = 0;
char *g_proxyUsername = NULL;
char *g_proxyPassword = NULL;

char *g_tempDirectory     = NULL;
char *g_databaseDirectory = NULL;

uint32_t g_maxAttempts    = 0;
uint32_t g_connectTimeout = 0;
uint32_t g_requestTimeout = 0;

uint32_t g_bCompressLocalDatabase = 0;

freshclam_dat_v1_t *g_freshclamDat = NULL;

/** @brief Generate a Version 4 UUID according to RFC-4122
 *
 * Uses the openssl RAND_bytes function to generate a Version 4 UUID.
 *
 * Copyright 2021 Karthik Velakur with some modifications by the ClamAV team.
 * License: MIT
 * From: https://gist.github.com/kvelakur/9069c9896577c3040030
 *
 * @param buffer A buffer that is SIZEOF_UUID_V4
 */
static void uuid_v4_gen(char *buffer)
{
    union {
        struct
        {
            uint32_t time_low;
            uint16_t time_mid;
            uint16_t time_hi_and_version;
            uint8_t clk_seq_hi_res;
            uint8_t clk_seq_low;
            uint8_t node[6];
        };
        uint8_t __rnd[16];
    } uuid;

    if (0 >= RAND_bytes(uuid.__rnd, sizeof(uuid.__rnd))) {
        /* Failed to generate random bytes for new UUID */
        memset(uuid.__rnd, 0, sizeof(uuid.__rnd));
        uuid.time_low = (uint32_t)time(NULL);
    }

    // Refer Section 4.2 of RFC-4122
    // https://tools.ietf.org/html/rfc4122#section-4.2
    uuid.clk_seq_hi_res      = (uint8_t)((uuid.clk_seq_hi_res & 0x3F) | 0x80);
    uuid.time_hi_and_version = (uint16_t)((uuid.time_hi_and_version & 0x0FFF) | 0x4000);

    snprintf(buffer, SIZEOF_UUID_V4, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             uuid.time_low, uuid.time_mid, uuid.time_hi_and_version,
             uuid.clk_seq_hi_res, uuid.clk_seq_low,
             uuid.node[0], uuid.node[1], uuid.node[2],
             uuid.node[3], uuid.node[4], uuid.node[5]);
    buffer[SIZEOF_UUID_V4 - 1] = 0;

    return;
}

fc_error_t load_freshclam_dat(void)
{
    fc_error_t status        = FC_EINIT;
    int handle               = -1;
    ssize_t bread            = 0;
    freshclam_dat_v1_t *mdat = NULL;
    uint32_t version         = 0;
    char magic[13]           = {0};

    /* Change directory to database directory */
    if (chdir(g_databaseDirectory)) {
        logg(LOGG_ERROR, "Can't change dir to %s\n", g_databaseDirectory);
        status = FC_EDIRECTORY;
        goto done;
    }
    logg(LOGG_DEBUG, "Current working dir is %s\n", g_databaseDirectory);

    if (-1 == (handle = open("freshclam.dat", O_RDONLY | O_BINARY))) {
        char currdir[PATH_MAX];

        if (getcwd(currdir, sizeof(currdir)))
            logg(LOGG_DEBUG, "Can't open freshclam.dat in %s\n", currdir);
        else
            logg(LOGG_DEBUG, "Can't open freshclam.dat in the current directory\n");

        logg(LOGG_DEBUG, "It probably doesn't exist yet. That's ok.\n");
        status = FC_EFILE;
        goto done;
    }

    if (strlen(MIRRORS_DAT_MAGIC) != (bread = read(handle, &magic, strlen(MIRRORS_DAT_MAGIC)))) {
        char error_message[260];
        cli_strerror(errno, error_message, 260);
        logg(LOGG_ERROR, "Can't read magic from freshclam.dat. Bytes read: %zi, error: %s\n", bread, error_message);
        goto done;
    }
    if (0 != strncmp(magic, MIRRORS_DAT_MAGIC, strlen(MIRRORS_DAT_MAGIC))) {
        logg(LOGG_DEBUG, "Magic bytes for freshclam.dat did not match expectations.\n");
        goto done;
    }

    if (sizeof(uint32_t) != (bread = read(handle, &version, sizeof(uint32_t)))) {
        char error_message[260];
        cli_strerror(errno, error_message, 260);
        logg(LOGG_ERROR, "Can't read version from freshclam.dat. Bytes read: %zi, error: %s\n", bread, error_message);
        goto done;
    }

    switch (version) {
        case 1: {
            /* Verify that file size is as expected. */
            off_t file_size = lseek(handle, 0L, SEEK_END);

            if (strlen(MIRRORS_DAT_MAGIC) + sizeof(freshclam_dat_v1_t) != (size_t)file_size) {
                logg(LOGG_DEBUG, "freshclam.dat is bigger than expected: %zu != %ld\n", sizeof(freshclam_dat_v1_t), file_size);
                goto done;
            }

            /* Rewind to just after the magic bytes and read data struct */
            if (-1 == lseek(handle, strlen(MIRRORS_DAT_MAGIC), SEEK_SET)) {
                char error_message[260];
                cli_strerror(errno, error_message, 260);
                logg(LOGG_ERROR, "Can't seek to %lu, error: %s\n", strlen(MIRRORS_DAT_MAGIC), error_message);
                goto done;
            }

            mdat = malloc(sizeof(freshclam_dat_v1_t));
            if (NULL == mdat) {
                logg(LOGG_ERROR, "Failed to allocate memory for freshclam.dat\n");
                status = FC_EMEM;
                goto done;
            }

            if (sizeof(freshclam_dat_v1_t) != (bread = read(handle, mdat, sizeof(freshclam_dat_v1_t)))) {
                char error_message[260];
                cli_strerror(errno, error_message, 260);
                logg(LOGG_ERROR, "Can't read from freshclam.dat. Bytes read: %zi, error: %s\n", bread, error_message);
                goto done;
            }

            /* Got it. */
            close(handle);
            handle = -1;

            /* This is the latest version.
               If we change the format in the future, we may wish to create a new
               freshclam.dat struct, import the relevant bits to the new format,
               and then save (overwrite) freshclam.dat with the new data. */
            if (NULL != g_freshclamDat) {
                free(g_freshclamDat);
            }
            g_freshclamDat = mdat;
            mdat           = NULL;
            break;
        }
        default: {
            logg(LOGG_DEBUG, "freshclam.dat version is different than expected: %u != %u\n", 1, version);
            goto done;
        }
    }

    logg(LOGG_DEBUG, "Loaded freshclam.dat:\n");
    logg(LOGG_DEBUG, "  version:    %d\n", g_freshclamDat->version);
    logg(LOGG_DEBUG, "  uuid:       %s\n", g_freshclamDat->uuid);
    if (g_freshclamDat->retry_after > 0) {
        char retry_after_string[26];
        struct tm *tm_info = localtime(&g_freshclamDat->retry_after);
        if (NULL == tm_info) {
            logg(LOGG_ERROR, "Failed to query the local time for the retry-after date!\n");
            goto done;
        }
        strftime(retry_after_string, 26, "%Y-%m-%d %H:%M:%S", tm_info);
        logg(LOGG_DEBUG, "  retry-after: %s\n", retry_after_string);
    }

    status = FC_SUCCESS;

done:
    if (-1 != handle) {
        close(handle);
    }
    if (FC_SUCCESS != status) {
        if (NULL != mdat) {
            free(mdat);
        }
        if (NULL != g_freshclamDat) {
            free(g_freshclamDat);
            g_freshclamDat = NULL;
        }
    }

    return status;
}

fc_error_t save_freshclam_dat(void)
{
    fc_error_t status = FC_EINIT;
    int handle        = -1;

    if (NULL == g_freshclamDat) {
        logg(LOGG_ERROR, "Attempted to save freshclam.dat before initializing data struct!\n");
        goto done;
    }

    if (-1 == (handle = open("freshclam.dat", O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0644))) {
        char currdir[PATH_MAX];

        if (getcwd(currdir, sizeof(currdir)))
            logg(LOGG_ERROR, "Can't create freshclam.dat in %s\n", currdir);
        else
            logg(LOGG_ERROR, "Can't create freshclam.dat in the current directory\n");

        logg(LOGG_INFO, "Hint: The database directory must be writable for UID %d or GID %d\n", getuid(), getgid());
        status = FC_EDBDIRACCESS;
        goto done;
    }
    if (-1 == write(handle, MIRRORS_DAT_MAGIC, strlen(MIRRORS_DAT_MAGIC))) {
        logg(LOGG_ERROR, "Can't write to freshclam.dat\n");
    }
    if (-1 == write(handle, g_freshclamDat, sizeof(freshclam_dat_v1_t))) {
        logg(LOGG_ERROR, "Can't write to freshclam.dat\n");
    }

    logg(LOGG_DEBUG, "Saved freshclam.dat\n");

    status = FC_SUCCESS;
done:
    if (-1 != handle) {
        close(handle);
    }

    return status;
}

fc_error_t new_freshclam_dat(void)
{
    fc_error_t status = FC_EINIT;

    freshclam_dat_v1_t *mdat = calloc(1, sizeof(freshclam_dat_v1_t));
    if (NULL == mdat) {
        logg(LOGG_ERROR, "Failed to allocate memory for freshclam.dat\n");
        status = FC_EMEM;
        goto done;
    }

    mdat->version     = 1;
    mdat->retry_after = 0;
    uuid_v4_gen(mdat->uuid);

    if (NULL != g_freshclamDat) {
        free(g_freshclamDat);
    }
    g_freshclamDat = mdat;

    logg(LOGG_DEBUG, "Creating new freshclam.dat\n");

    if (FC_SUCCESS != save_freshclam_dat()) {
        logg(LOGG_ERROR, "Failed to save freshclam.dat!\n");
        status = FC_EFILE;
        goto done;
    }

    status = FC_SUCCESS;

done:
    if (FC_SUCCESS != status) {
        if (NULL != mdat) {
            free(mdat);
        }
        g_freshclamDat = NULL;
    }
    return status;
}

/**
 * @brief Get DNS text record field # for official databases.
 *
 * @param database  Official database name.
 * @return int      DNS text record field #
 */
static int textrecordfield(const char *database)
{
    if (!strcmp(database, "main")) {
        return 1;
    } else if (!strcmp(database, "daily")) {
        return 2;
    } else if (!strcmp(database, "bytecode")) {
        return 7;
    } else if (!strcmp(database, "safebrowsing")) {
        return 6;
    }
    return 0;
}

#if (LIBCURL_VERSION_MAJOR > 7) || ((LIBCURL_VERSION_MAJOR == 7) && (LIBCURL_VERSION_MINOR >= 61))
/* In libcurl 7.61.0, support was added for extracting the time in plain
   microseconds. Older libcurl versions are stuck in using 'double' for this
   information so we complicate this example a bit by supporting either
   approach. */
#define TIME_IN_US 1
#define TIMETYPE curl_off_t
#define TIMEOPT CURLINFO_TOTAL_TIME_T
#define MINIMAL_PROGRESS_FUNCTIONALITY_INTERVAL 3000000
#else
#define TIMETYPE double
#define TIMEOPT CURLINFO_TOTAL_TIME
#define MINIMAL_PROGRESS_FUNCTIONALITY_INTERVAL 3
#endif

#define STOP_DOWNLOAD_AFTER_THIS_MANY_BYTES 6000

struct xfer_progress {
    TIMETYPE lastRunTime; /* type depends on version, see above */
    uint8_t bComplete;
    CURL *curl;
};

static void printTime(double seconds)
{
    if (seconds >= 3600) {
        fprintf(stdout, "%2.0fh %02.0fm", trunc(seconds / 3600), trunc(fmod(seconds, 3600.0) / 60));
    } else if (seconds >= 60) {
        fprintf(stdout, "%2.0fm %02.0fs", trunc(seconds / 60), trunc(fmod(seconds, 60.0)));
    } else {
        fprintf(stdout, "%6.1fs", seconds);
    }
}

static void printBytes(curl_off_t bytes, int bPad)
{
    if (bytes >= (1024 * 1024)) {
        const char *format = bPad ? "%7.02fMiB" : "%.02fMiB";
        double megabytes   = bytes / (double)(1024 * 1024);
        fprintf(stdout, format, megabytes);
    } else if (bytes >= 1024) {
        const char *format = bPad ? "%7.02fKiB" : "%.02fKiB";
        double kilobytes   = bytes / (double)(1024);
        fprintf(stdout, format, kilobytes);
    } else {
        const char *format = bPad ? "%9" CURL_FORMAT_CURL_OFF_T "B" : "%" CURL_FORMAT_CURL_OFF_T "B";
        fprintf(stdout, format, bytes);
    }
}

/**
 * Function from curl example code, Copyright (C) 1998 - 2018, Daniel Stenberg, see COPYING.curl for license details
 * Progress bar callback function ( CURLOPT_XFERINFOFUNCTION ).
 */
static int xferinfo(void *prog,
                    curl_off_t TotalToDownload, curl_off_t NowDownloaded,
                    curl_off_t TotalToUpload, curl_off_t NowUploaded)
{
    struct xfer_progress *xferProg = (struct xfer_progress *)prog;
    CURL *curl                     = xferProg->curl;
    TIMETYPE curtime               = 0;
    TIMETYPE remtime               = 0;

    uint32_t i                = 0;
    uint32_t totalNumDots     = 25;
    uint32_t numDots          = 0;
    double fractiondownloaded = 0.0;

    UNUSEDPARAM(TotalToUpload);
    UNUSEDPARAM(NowUploaded);

    if ((TotalToDownload <= 0.0) || (xferProg->bComplete)) {
        return 0;
    }

    fractiondownloaded = (double)NowDownloaded / (double)TotalToDownload;
    numDots            = round(fractiondownloaded * totalNumDots);

    curl_easy_getinfo(curl, TIMEOPT, &curtime);

    xferProg->lastRunTime = curtime;

#ifndef _WIN32
    fprintf(stdout, "\e[?7l");
#endif
#ifdef TIME_IN_US
    if (fractiondownloaded <= 0.0) {
        fprintf(stdout, "Time: ");
        printTime(curtime / 1000000.0);
        fprintf(stdout, "               ");
    } else {
        remtime = (curtime / fractiondownloaded) - curtime;
        fprintf(stdout, "Time: ");
        printTime(curtime / 1000000.0);
        fprintf(stdout, ", ETA: ");
        printTime(remtime / 1000000.0);
        fprintf(stdout, " ");
    }
#else
    if (fractiondownloaded <= 0.0) {
        fprintf(stdout, "Time: ");
        printTime(curtime);
        fprintf(stdout, "               ");
    } else {
        remtime = (curtime / fractiondownloaded) - curtime;
        fprintf(stdout, "Time: ");
        printTime(curtime);
        fprintf(stdout, ", ETA: ");
        printTime(remtime);
        fprintf(stdout, " ");
    }
#endif

    fprintf(stdout, "[");
    if (numDots > 0) {
        if (numDots > 1) {
            for (i = 0; i < numDots - 1; i++) {
                fprintf(stdout, "=");
            }
        }
        fprintf(stdout, ">");
        i++;
    }
    for (; i < totalNumDots; i++) {
        fprintf(stdout, " ");
    }

    fprintf(stdout, "] ");

    printBytes(NowDownloaded, 1);
    fprintf(stdout, "/");
    printBytes(TotalToDownload, 0);

    if (NowDownloaded < TotalToDownload) {
        fprintf(stdout, "\r");
    } else {
        fprintf(stdout, "\n");
        xferProg->bComplete = 1;
    }
#ifndef _WIN32
    fprintf(stdout, "\e[?7h");
#endif
    fflush(stdout);

    return 0;
}

#if (LIBCURL_VERSION_MAJOR < 7) || ((LIBCURL_VERSION_MAJOR == 7) && (LIBCURL_VERSION_MINOR < 32))
/**
 * Function from curl example code, Copyright (C) 1998 - 2018, Daniel Stenberg, see COPYING.curl for license details
 * Older style progress bar callback shim; for libcurl older than 7.32.0 ( CURLOPT_PROGRESSFUNCTION ).
 */
static int older_progress(void *prog,
                          double TotalToDownload, double NowDownloaded,
                          double TotalToUpload, double NowUploaded)
{
    return xferinfo(prog,
                    (curl_off_t)TotalToDownload,
                    (curl_off_t)NowDownloaded,
                    (curl_off_t)TotalToUpload,
                    (curl_off_t)NowUploaded);
}
#endif

static fc_error_t create_curl_handle(
    int bHttp,
    int bAllowRedirect,
    CURL **curlHandle)
{
    fc_error_t status = FC_EARG;

    CURL *curl = NULL;

#if (LIBCURL_VERSION_MAJOR > 7) || ((LIBCURL_VERSION_MAJOR == 7) && (LIBCURL_VERSION_MINOR >= 33))
    CURLcode curl_ret = CURLE_OK;
#endif

    char userAgent[128];

    if (NULL == curlHandle) {
        logg(LOGG_ERROR, "create_curl_handle: Invalid arguments!\n");
        goto done;
    }

    *curlHandle = NULL;

    curl = curl_easy_init();
    if (NULL == curl) {
        logg(LOGG_ERROR, "create_curl_handle: curl_easy_init failed!\n");
        status = FC_EINIT;
        goto done;
    }

    if (g_userAgent) {
        strncpy(userAgent, g_userAgent, sizeof(userAgent));
    } else {
        /*
         * Use a randomly generated UUID in the User-Agent
         * We'll try to load it from a file in the database directory.
         * If none exists, we'll create a new one and save it to said file.
         */
        snprintf(userAgent, sizeof(userAgent),
                 PACKAGE "/%s (OS: " TARGET_OS_TYPE ", ARCH: " TARGET_ARCH_TYPE ", CPU: " TARGET_CPU_TYPE ", UUID: %s)",
                 get_version(),
                 g_freshclamDat->uuid);
    }
    userAgent[sizeof(userAgent) - 1] = 0;

    if (mprintf_verbose) {
        /* ask libcurl to show us the verbose output */
        if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L)) {
            logg(LOGG_ERROR, "create_curl_handle: Failed to set CURLOPT_VERBOSE!\n");
        }
        if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_STDERR, stdout)) {
            logg(LOGG_ERROR, "create_curl_handle: Failed to direct curl debug output to stdout!\n");
        }
    }

    if (bHttp) {
        if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_USERAGENT, userAgent)) {
            logg(LOGG_ERROR, "create_curl_handle: Failed to set CURLOPT_USERAGENT (%s)!\n", userAgent);
        }
        if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, g_connectTimeout)) {
            logg(LOGG_ERROR, "create_curl_handle: Failed to set CURLOPT_CONNECTTIMEOUT (%u)!\n", g_connectTimeout);
        }
        if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, g_requestTimeout)) {
            logg(LOGG_ERROR, "create_curl_handle: Failed to set CURLOPT_LOW_SPEED_TIME  (%u)!\n", g_requestTimeout);
        }
        if (g_requestTimeout > 0) {
            /* Minimum speed is 1 byte/second over the previous g_requestTimeout seconds. */
            int minimumSpeed = 1;

            if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, minimumSpeed)) {
                logg(LOGG_ERROR, "create_curl_handle: Failed to set CURLOPT_LOW_SPEED_LIMIT  (%u)!\n", minimumSpeed);
            }
        }

        if (bAllowRedirect) {
            /* allow three redirects */
            if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L)) {
                logg(LOGG_ERROR, "create_curl_handle: Failed to set CURLOPT_FOLLOWLOCATION!\n");
            }
            if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 3L)) {
                logg(LOGG_ERROR, "create_curl_handle: Failed to set CURLOPT_MAXREDIRS!\n");
            }
        }
    }

#if (LIBCURL_VERSION_MAJOR > 7) || ((LIBCURL_VERSION_MAJOR == 7) && (LIBCURL_VERSION_MINOR >= 33))
    if (g_localIP) {
        if (NULL == strchr(g_localIP, ':')) {
            logg(LOGG_DEBUG, "Local IPv4 address requested: %s\n", g_localIP);
            curl_ret = curl_easy_setopt(curl, CURLOPT_DNS_LOCAL_IP4, g_localIP); // Option requires libcurl built with c-ares
            switch (curl_ret) {
                case CURLE_BAD_FUNCTION_ARGUMENT:
                    logg(LOGG_ERROR, "create_curl_handle: Unable to bind DNS resolves to %s. Invalid IPv4 address.\n", g_localIP);
                    status = FC_ECONFIG;
                    goto done;
                    break;
                case CURLE_UNKNOWN_OPTION:
                case CURLE_NOT_BUILT_IN:
                    logg(LOGG_ERROR, "create_curl_handle: Unable to bind DNS resolves to %s. Option requires that libcurl was built with c-ares.\n", g_localIP);
                    status = FC_ECONFIG;
                    goto done;
                default:
                    break;
            }
            if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4)) {
                logg(LOGG_ERROR, "create_curl_handle: Failed to set CURLOPT_IPRESOLVE (IPv4)!\n");
            }
        } else {
            logg(LOGG_DEBUG, "Local IPv6 address requested: %s\n", g_localIP);
            curl_ret = curl_easy_setopt(curl, CURLOPT_DNS_LOCAL_IP6, g_localIP); // Option requires libcurl built with c-ares
            switch (curl_ret) {
                case CURLE_BAD_FUNCTION_ARGUMENT:
                    logg(LOGG_WARNING, "create_curl_handle: Unable to bind DNS resolves to %s. Invalid IPv4 address.\n", g_localIP);
                    status = FC_ECONFIG;
                    goto done;
                    break;
                case CURLE_UNKNOWN_OPTION:
                case CURLE_NOT_BUILT_IN:
                    logg(LOGG_WARNING, "create_curl_handle: Unable to bind DNS resolves to %s. Option requires that libcurl was built with c-ares.\n", g_localIP);
                    status = FC_ECONFIG;
                    goto done;
                default:
                    break;
            }
            if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V6)) {
                logg(LOGG_ERROR, "create_curl_handle: Failed to set CURLOPT_IPRESOLVE (IPv6)!\n");
            }
        }
    }
#endif
    if (g_proxyServer) {
        /*
         * Proxy requested.
         */
        logg(LOGG_DEBUG, "Using proxy: %s:%u\n", g_proxyServer, g_proxyPort);

        if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_PROXY, g_proxyServer)) {
            logg(LOGG_ERROR, "create_curl_handle: Failed to set CURLOPT_PROXY (%s)!\n", g_proxyServer);
        }
        if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_PROXYPORT, g_proxyPort)) {
            logg(LOGG_ERROR, "create_curl_handle: Failed to set CURLOPT_PROXYPORT (%u)!\n", g_proxyPort);
        }
        if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1L)) { // Necessary?
            logg(LOGG_ERROR, "create_curl_handle: Failed to set CURLOPT_HTTPPROXYTUNNEL (1)!\n");
        }
#ifdef CURLOPT_SUPPRESS_CONNECT_HEADERS
        if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_SUPPRESS_CONNECT_HEADERS, 1L)) { // Necessary?
            logg(LOGG_ERROR, "create_curl_handle: Failed to set CURLOPT_SUPPRESS_CONNECT_HEADERS (1)!\n");
        }
#endif

        if (g_proxyUsername) {
            if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_PROXYUSERNAME, g_proxyUsername)) {
                logg(LOGG_ERROR, "create_curl_handle: Failed to set CURLOPT_PROXYUSERNAME (%s)!\n", g_proxyUsername);
            }
            if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_PROXYPASSWORD, g_proxyPassword)) {
                logg(LOGG_ERROR, "create_curl_handle: Failed to set CURLOPT_PROXYPASSWORD (%s)!\n", g_proxyPassword);
            }
        }
    }

#if defined(C_DARWIN) || defined(_WIN32)
    if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, *sslctx_function)) {
        logg(LOGG_DEBUG, "create_curl_handle: Failed to set SSL CTX function. Your libcurl may use an SSL backend that does not support CURLOPT_SSL_CTX_FUNCTION.\n");
    }
#else
    set_tls_ca_bundle(curl);
#endif

    *curlHandle = curl;
    status      = FC_SUCCESS;

done:

    if (FC_SUCCESS != status) {
        if (NULL != curl) {
            curl_easy_cleanup(curl);
        }
    }

    return status;
}

struct MemoryStruct {
    char *buffer;
    size_t size;
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t real_size                  = size * nmemb;
    struct MemoryStruct *receivedData = (struct MemoryStruct *)userp;

    if ((NULL == contents) || (NULL == userp)) {
        return 0;
    }

    char *newBuffer = realloc(receivedData->buffer, receivedData->size + real_size + 1);
    if (NULL == newBuffer) {
        logg(LOGG_ERROR, "remote_cvdhead - recv callback: Failed to allocate memory CVD header data.\n");
        return 0;
    }

    receivedData->buffer = newBuffer;
    memcpy(&(receivedData->buffer[receivedData->size]), contents, real_size);
    receivedData->size += real_size;
    receivedData->buffer[receivedData->size] = 0;

    return real_size;
}

struct FileStruct {
    int handle;
    size_t size;
};

static size_t WriteFileCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t real_size                = size * nmemb;
    struct FileStruct *receivedFile = (struct FileStruct *)userp;
    size_t bytes_written            = 0;

    if ((NULL == contents) || (NULL == userp)) {
        return 0;
    }

    bytes_written = write(receivedFile->handle, contents, real_size);

    receivedFile->size += bytes_written;

    return bytes_written;
}

/**
 * @brief Get the cvd header info struct for the newest available database.
 *
 * The last-modified datetime will be used to set the If-Modified-Since header.
 * If the remote CVD isn't newer, we should get an HTTP 304 and return
 * FC_UPTODATE instead of FC_SUCCESS, and cvd will be NULL.
 *
 * @param cvdfile           database name including extension.
 * @param ifModifiedSince   modified time of local database. May be 0 to always get the CVD header.
 * @param server            server to use to retrieve for database header.
 * @param logerr            non-zero to upgrade warnings to errors.
 * @param[out] cvd          CVD header of newest available CVD, if FC_SUCCESS
 * @return fc_error_t       FC_SUCCESS if CVD header obtained.
 * @return fc_error_t       FC_UPTODATE if received 304 in response to ifModifiedSince date.
 * @return fc_error_t       Another error code if failure occured.
 */
static fc_error_t remote_cvdhead(
    const char *cvdfile,
    uint32_t ifModifiedSince,
    char *server,
    int logerr,
    struct cl_cvd **cvd)
{
    fc_error_t ret;
    fc_error_t status = FC_EARG;

    int bHttpServer = 0;
    char *url       = NULL;
    size_t urlLen   = 0;

    char head[CVD_HEADER_SIZE + 1];

    struct MemoryStruct receivedData = {0};

    unsigned int i;
    struct cl_cvd *cvdhead;

    CURL *curl = NULL;
    CURLcode curl_ret;
    char errbuf[CURL_ERROR_SIZE];
    struct curl_slist *slist = NULL;
    struct xfer_progress prog;

    long http_code = 0;

    if (NULL == cvd) {
        logg(LOGG_ERROR, "remote_cvdhead: Invalid arguments.\n");
        goto done;
    }

    *cvd = NULL;

    if (0 == strncasecmp(server, "http", strlen("http"))) {
        bHttpServer = 1;
    }

    /*
     * Request CVD header.
     */
    urlLen = strlen(server) + strlen("/") + strlen(cvdfile);
    url    = malloc(urlLen + 1);
    snprintf(url, urlLen + 1, "%s/%s", server, cvdfile);

    logg(LOGG_INFO, "Trying to retrieve CVD header from %s\n", url);

    if (FC_SUCCESS != (ret = create_curl_handle(
                           bHttpServer, // Set extra HTTP-specific headers.
                           1,           // Allow redirects.
                           &curl))) {   // [out] curl session handle.
        logg(LOGG_ERROR, "remote_cvdhead: Failed to create curl handle.\n");
        status = ret;
        goto done;
    }

#ifdef HAVE_UNISTD_H
    if (!mprintf_quiet && (mprintf_progress || isatty(fileno(stdout))))
#else
    if (!mprintf_quiet)
#endif
    {
        prog.lastRunTime = 0;
        prog.curl        = curl;
        prog.bComplete   = 0;

#if (LIBCURL_VERSION_MAJOR > 7) || ((LIBCURL_VERSION_MAJOR == 7) && (LIBCURL_VERSION_MINOR >= 32))
        /* xferinfo was introduced in 7.32.0, no earlier libcurl versions will
       compile as they won't have the symbols around.

       If built with a newer libcurl, but running with an older libcurl:
       curl_easy_setopt() will fail in run-time trying to set the new
       callback, making the older callback get used.

       New libcurls will prefer the new callback and instead use that one even
       if both callbacks are set. */

        if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, xferinfo)) {
            logg(LOGG_ERROR, "remote_cvdhead: Failed to set transfer info function!\n");
        }
        /* pass the struct pointer into the xferinfo function, note that this is
           an alias to CURLOPT_PROGRESSDATA */
        if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &prog)) {
            logg(LOGG_ERROR, "remote_cvdhead: Failed to set transfer info data structure!\n");
        }
#else
        if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, older_progress)) {
            logg(LOGG_ERROR, "remote_cvdhead: Failed to set progress function!\n");
        }
        /* pass the struct pointer into the progress function */
        if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_PROGRESSDATA, &prog)) {
            logg(LOGG_ERROR, "remote_cvdhead: Failed to set progress data structure!\n");
        }
#endif

        if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L)) {
            logg(LOGG_ERROR, "remote_cvdhead: Failed to disable progress function!\n");
        }
    }

    if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_URL, url)) {
        logg(LOGG_ERROR, "remote_cvdhead: Failed to set CURLOPT_URL for curl session (%s).\n", url);
        status = FC_EFAILEDGET;
        goto done;
    }

    if (bHttpServer) {
        /*
         * For HTTP, set some extra headers.
         */
        struct curl_slist *temp = NULL;

        if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L)) {
            logg(LOGG_ERROR, "remote_cvdhead: Failed to set CURLOPT_HTTPGET for curl session.\n");
        }

#ifdef FRESHCLAM_NO_CACHE
        if (NULL == (temp = curl_slist_append(slist, "Cache-Control: no-cache"))) { // Necessary?
            logg(LOGG_ERROR, "remote_cvdhead: Failed to append \"Cache-Control: no-cache\" header to custom curl header list.\n");
        } else {
            slist = temp;
        }
#endif
        if (NULL == (temp = curl_slist_append(slist, "Connection: close"))) {
            logg(LOGG_ERROR, "remote_cvdhead: Failed to append \"Connection: close\" header to custom curl header list.\n");
        } else {
            slist = temp;
        }
        if (NULL != slist) {
            if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist)) {
                logg(LOGG_ERROR, "remote_cvdhead: Failed to add custom header list to curl session.\n");
            }
        }
    }

    if (0 != ifModifiedSince) {
        if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_TIMEVALUE, ifModifiedSince)) {
            logg(LOGG_ERROR, "remote_cvdhead: Failed to set if-Modified-Since time value for curl session.\n");
        }
        /* If-Modified-Since the above time stamp */
        else if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_TIMECONDITION, CURL_TIMECOND_IFMODSINCE)) {
            logg(LOGG_ERROR, "remote_cvdhead: Failed to set if-Modified-Since time condition for curl session.\n");
        }
    }

    /* Request only the first 512 bytes (CVD_HEADER_SIZE) */
    if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_RANGE, "0-511")) {
        logg(LOGG_ERROR, "remote_cvdhead: Failed to set CURLOPT_RANGE CVD_HEADER_SIZE for curl session.\n");
    }

    receivedData.buffer = cli_malloc(1); /* will be grown as needed by the realloc above */
    receivedData.size   = 0;             /* no data at this point */

    /* Send all data to this function  */
    if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback)) {
        logg(LOGG_ERROR, "remote_cvdhead: Failed to set write-data memory callback function for curl session.\n");
    }

    /* Pass our 'receivedData' struct to the callback function */
    if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&receivedData)) {
        logg(LOGG_ERROR, "remote_cvdhead: Failed to set receivedData struct for write-data callback function for curl session.\n");
    }

    /*
     * Perform download.
     */
    memset(errbuf, 0, sizeof(errbuf));
    curl_ret = curl_easy_perform(curl);
    if (curl_ret != CURLE_OK) {
        /*
         * Show the error information.
         * If no detailed error information was written to errbuf
         * show the more generic information from curl_easy_strerror instead.
         */
        size_t len = strlen(errbuf);
        logg(logerr ? LOGG_ERROR : LOGG_WARNING, "remote_cvdhead: Download failed (%d) ", curl_ret);
        if (len)
            logg(logerr ? LOGG_ERROR : LOGG_WARNING, " Message: %s%s", errbuf, ((errbuf[len - 1] != '\n') ? "\n" : ""));
        else
            logg(logerr ? LOGG_ERROR : LOGG_WARNING, " Message: %s\n", curl_easy_strerror(curl_ret));
        status = FC_ECONNECTION;
        goto done;
    }

    /* Check HTTP code */
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    switch (http_code) {
        case 200:
        case 206: {
            status = FC_SUCCESS;
            break;
        }
        case 304: {
            status = FC_UPTODATE;
            goto done;
        }
        case 403: {
            status = FC_EFORBIDDEN;

            /* Try again in no less than 24 hours if freshclam received a 403 FORBIDDEN. */
            g_freshclamDat->retry_after = time(NULL) + 60 * 60 * 24;

            (void)save_freshclam_dat();

            break;
        }
        case 429: {
            status = FC_ERETRYLATER;

            curl_off_t retry_after = 0;

#if (LIBCURL_VERSION_MAJOR > 7) || ((LIBCURL_VERSION_MAJOR == 7) && (LIBCURL_VERSION_MINOR >= 66))
            /* CURLINFO_RETRY_AFTER was introduced in libcurl 7.66 */

            /* Find out how long we should wait before allowing a retry. */
            curl_easy_getinfo(curl, CURLINFO_RETRY_AFTER, &retry_after);
#endif

            if (retry_after > 0) {
                /* The response gave us a Retry-After date. Use that. */
                g_freshclamDat->retry_after = time(NULL) + (time_t)retry_after;
            } else {
                /* Try again in no less than 4 hours if the response didn't specify
                   or if CURLINFO_RETRY_AFTER is not supported. */
                g_freshclamDat->retry_after = time(NULL) + 60 * 60 * 4;
            }
            (void)save_freshclam_dat();

            break;
        }
        case 404: {
            if (g_proxyServer)
                logg(LOGG_WARNING, "remote_cvdhead: file not found: %s (Proxy: %s:%u)\n", url, g_proxyServer, g_proxyPort);
            else
                logg(LOGG_WARNING, "remote_cvdhead: file not found: %s\n", url);
            status = FC_EFAILEDGET;
            goto done;
        }
        case 522: {
            logg(LOGG_WARNING, "remote_cvdhead: Origin Connection Time-out. Cloudflare was unable to reach the origin web server and the request timed out. URL: %s\n", url);
            status = FC_EFAILEDGET;
            goto done;
        }
        default: {
            if (g_proxyServer)
                logg(logerr ? LOGG_ERROR : LOGG_WARNING, "remote_cvdhead: Unexpected response (%li) from %s (Proxy: %s:%u)\n",
                     http_code, server, g_proxyServer, g_proxyPort);
            else
                logg(logerr ? LOGG_ERROR : LOGG_WARNING, "remote_cvdhead: Unexpected response (%li) from %s\n",
                     http_code, server);
            status = FC_EFAILEDGET;
            goto done;
        }
    }

    /*
     * Identify start of CVD header in response body.
     */
    if (receivedData.size < CVD_HEADER_SIZE) {
        logg(logerr ? LOGG_ERROR : LOGG_WARNING, "remote_cvdhead: Malformed CVD header (too short)\n");
        status = FC_EFAILEDGET;
        goto done;
    }

    /*
     * Copy CVD header byte-by-byte from response body to CVD header buffer.
     * Validate that data contains only printable characters and no NULL terminators.
     */
    memset(head, 0, sizeof(head));

    for (i = 0; i < CVD_HEADER_SIZE; i++) {
        if (!receivedData.buffer ||
            (receivedData.buffer && !*receivedData.buffer) ||
            (receivedData.buffer && !isprint(receivedData.buffer[i]))) {

            logg(logerr ? LOGG_ERROR : LOGG_WARNING, "remote_cvdhead: Malformed CVD header (bad chars)\n");
            status = FC_EFAILEDGET;
            goto done;
        }
        head[i] = receivedData.buffer[i];
    }

    /*
     * Parse CVD info into CVD info struct.
     */
    if (!(cvdhead = cl_cvdparse(head))) {
        logg(logerr ? LOGG_ERROR : LOGG_WARNING, "remote_cvdhead: Malformed CVD header (can't parse)\n");
        status = FC_EFAILEDGET;
        goto done;
    } else {
        logg(LOGG_INFO, "OK\n");
    }

    *cvd   = cvdhead;
    status = FC_SUCCESS;

done:

    if (NULL != receivedData.buffer) {
        free(receivedData.buffer);
    }
    if (NULL != slist) {
        curl_slist_free_all(slist);
    }
    if (NULL != curl) {
        curl_easy_cleanup(curl);
    }
    if (NULL != url) {
        free(url);
    }

    return status;
}

static fc_error_t downloadFile(
    const char *url,
    const char *destfile,
    int bAllowRedirect,
    int logerr,
    time_t ifModifiedSince)
{
    fc_error_t ret;
    fc_error_t status = FC_EARG;

    int bHttpServer = 0;

    CURL *curl = NULL;
    CURLcode curl_ret;
    char errbuf[CURL_ERROR_SIZE];
    struct curl_slist *slist = NULL;
    struct xfer_progress prog;

    long http_code = 0;

    struct FileStruct receivedFile = {-1, 0};

    if ((NULL == url) || (NULL == destfile)) {
        logg(LOGG_ERROR, "downloadFile: Invalid arguments.\n");
        goto done;
    }

    logg(LOGG_DEBUG, "Retrieving %s\n", url);

    if (0 == strncasecmp(url, "http", strlen("http"))) {
        bHttpServer = 1;
    }

    if (FC_SUCCESS != (ret = create_curl_handle(bHttpServer, bAllowRedirect, &curl))) {
        logg(LOGG_ERROR, "downloadFile: Failed to create curl handle.\n");
        status = ret;
        goto done;
    }

#ifdef HAVE_UNISTD_H
    if (!mprintf_quiet && (mprintf_progress || isatty(fileno(stdout))))
#else
    if (!mprintf_quiet)
#endif
    {
        prog.lastRunTime = 0;
        prog.curl        = curl;
        prog.bComplete   = 0;

#if (LIBCURL_VERSION_MAJOR > 7) || ((LIBCURL_VERSION_MAJOR == 7) && (LIBCURL_VERSION_MINOR >= 32))
        /* xferinfo was introduced in 7.32.0, no earlier libcurl versions will
       compile as they won't have the symbols around.

       If built with a newer libcurl, but running with an older libcurl:
       curl_easy_setopt() will fail in run-time trying to set the new
       callback, making the older callback get used.

       New libcurls will prefer the new callback and instead use that one even
       if both callbacks are set. */

        if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, xferinfo)) {
            logg(LOGG_ERROR, "downloadFile: Failed to set transfer info function!\n");
        }
        /* pass the struct pointer into the xferinfo function, note that this is
       an alias to CURLOPT_PROGRESSDATA */
        if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_XFERINFODATA, &prog)) {
            logg(LOGG_ERROR, "downloadFile: Failed to set transfer info data structure!\n");
        }
#else
        if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, older_progress)) {
            logg(LOGG_ERROR, "downloadFile: Failed to set progress function!\n");
        }
        /* pass the struct pointer into the progress function */
        if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_PROGRESSDATA, &prog)) {
            logg(LOGG_ERROR, "downloadFile: Failed to set progress data structure!\n");
        }
#endif

        if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L)) {
            logg(LOGG_ERROR, "downloadFile: Failed to disable progress function!\n");
        }
    }

    if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_URL, url)) {
        logg(LOGG_ERROR, "downloadFile: Failed to set CURLOPT_URL for curl session (%s).\n", url);
    }
    if (0 != ifModifiedSince) {
        if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_TIMEVALUE, ifModifiedSince)) {
            logg(LOGG_ERROR, "downloadFile: Failed to set if-Modified-Since time value for curl session.\n");
        }
        /* If-Modified-Since the above time stamp */
        else if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_TIMECONDITION, CURL_TIMECOND_IFMODSINCE)) {
            logg(LOGG_ERROR, "downloadFile: Failed to set if-Modified-Since time condition for curl session.\n");
        }
    }

    if (bHttpServer) {
        /*
         * For HTTP, set some extra headers.
         */
        struct curl_slist *temp = NULL;

        if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L)) {
            logg(LOGG_ERROR, "downloadFile: Failed to set CURLOPT_HTTPGET for curl session.\n");
        }

#ifdef FRESHCLAM_NO_CACHE
        if (NULL == (temp = curl_slist_append(slist, "Cache-Control: no-cache"))) { // Necessary?
            logg(LOGG_ERROR, "downloadFile: Failed to append \"Cache-Control: no-cache\" header to custom curl header list.\n");
        } else {
            slist = temp;
        }
#endif
        if (NULL == (temp = curl_slist_append(slist, "Connection: close"))) { // Necessary?
            logg(LOGG_ERROR, "downloadFile: Failed to append \"Connection: close\" header to custom curl header list.\n");
        } else {
            slist = temp;
        }
        if (NULL != slist) {
            if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist)) {
                logg(LOGG_ERROR, "downloadFile: Failed to add custom header list to curl session.\n");
            }
        }
    }

    /* Write the response body to the destination file handle */

    if (-1 == (receivedFile.handle = open(destfile, O_WRONLY | O_CREAT | O_EXCL | O_BINARY, 0644))) {
        char currdir[PATH_MAX];

        if (getcwd(currdir, sizeof(currdir)))
            logg(LOGG_ERROR, "downloadFile: Can't create new file %s in %s\n", destfile, currdir);
        else
            logg(LOGG_ERROR, "downloadFile: Can't create new file %s in the current directory\n", destfile);

        logg(LOGG_INFO, "Hint: The database directory must be writable for UID %d or GID %d\n", getuid(), getgid());
        status = FC_EDBDIRACCESS;
        goto done;
    }
    receivedFile.size = 0;

    /* Send all data to this function  */
    if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteFileCallback)) {
        logg(LOGG_ERROR, "downloadFile: Failed to set write-data fwrite callback function for curl session.\n");
    }

    if (CURLE_OK != curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&receivedFile)) {
        logg(LOGG_ERROR, "downloadFile: Failed to set write-data file handle for curl session.\n");
    }

    logg(LOGG_DEBUG, "downloadFile: Download source:      %s\n", url);
    logg(LOGG_DEBUG, "downloadFile: Download destination: %s\n", destfile);

    /* Perform download */
    memset(errbuf, 0, sizeof(errbuf));
    curl_ret = curl_easy_perform(curl);
    if (curl_ret != CURLE_OK) {
        /*
         * Show the error information.
         * If no detailed error information was written to errbuf
         * show the more generic information from curl_easy_strerror instead.
         */
        size_t len = strlen(errbuf);
        logg(logerr ? LOGG_ERROR : LOGG_WARNING, "Download failed (%d) ", curl_ret);
        if (len)
            logg(logerr ? LOGG_ERROR : LOGG_WARNING, " Message: %s%s", errbuf, ((errbuf[len - 1] != '\n') ? "\n" : ""));
        else
            logg(logerr ? LOGG_ERROR : LOGG_WARNING, " Message: %s\n", curl_easy_strerror(curl_ret));
        status = FC_ECONNECTION;
        goto done;
    }

    /* Check HTTP code */
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    logg(LOGG_WARNING, " ******* RESULT %ld, SIZE: %zu ******* \n", http_code, receivedFile.size);
    switch (http_code) {
        case 200:
        case 206: {
            if (0 == receivedFile.size) {
                status = FC_EEMPTYFILE;
            } else {
                status = FC_SUCCESS;
            }
            break;
        }
        case 304: {
            status = FC_UPTODATE;
            break;
        }
        case 403: {
            status = FC_EFORBIDDEN;

            /* Try again in no less than 24 hours if freshclam received a 403 FORBIDDEN. */
            g_freshclamDat->retry_after = time(NULL) + 60 * 60 * 24;

            (void)save_freshclam_dat();

            break;
        }
        case 429: {
            status = FC_ERETRYLATER;

            curl_off_t retry_after = 0;

#if (LIBCURL_VERSION_MAJOR > 7) || ((LIBCURL_VERSION_MAJOR == 7) && (LIBCURL_VERSION_MINOR >= 66))
            /* CURLINFO_RETRY_AFTER was introduced in libcurl 7.66 */

            /* Find out how long we should wait before allowing a retry. */
            curl_easy_getinfo(curl, CURLINFO_RETRY_AFTER, &retry_after);
#endif

            if (retry_after > 0) {
                /* The response gave us a Retry-After date. Use that. */
                g_freshclamDat->retry_after = time(NULL) + (time_t)retry_after;
            } else {
                /* Try again in no less than 4 hours if the response didn't specify
                   or if CURLINFO_RETRY_AFTER is not supported. */
                g_freshclamDat->retry_after = time(NULL) + 60 * 60 * 4;
            }
            (void)save_freshclam_dat();

            break;
        }
        case 404: {
            if (g_proxyServer)
                logg(LOGG_WARNING, "downloadFile: file not found: %s (Proxy: %s:%u)\n", url, g_proxyServer, g_proxyPort);
            else
                logg(LOGG_WARNING, "downloadFile: file not found: %s\n", url);
            status = FC_EFAILEDGET;
            break;
        }
        case 522: {
            logg(LOGG_WARNING, "downloadFile: Origin Connection Time-out. Cloudflare was unable to reach the origin web server and the request timed out. URL: %s\n", url);
            status = FC_EFAILEDGET;
            break;
        }
        default: {
            if (g_proxyServer)
                logg(logerr ? LOGG_ERROR : LOGG_WARNING, "downloadFile: Unexpected response (%li) from %s (Proxy: %s:%u)\n",
                     http_code, url, g_proxyServer, g_proxyPort);
            else
                logg(logerr ? LOGG_ERROR : LOGG_WARNING, "downloadFile: Unexpected response (%li) from %s\n",
                     http_code, url);
            status = FC_EFAILEDGET;
        }
    }

done:

    if (NULL != slist) {
        curl_slist_free_all(slist);
    }
    if (NULL != curl) {
        curl_easy_cleanup(curl);
    }

    if (-1 != receivedFile.handle) {
        close(receivedFile.handle);
    }

    if (FC_UPTODATE < status) {
        if (NULL != destfile) {
            unlink(destfile);
        }
    }

    return status;
}

static fc_error_t getcvd(
    const char *cvdfile,
    const char *tmpfile,
    char *server,
    uint32_t ifModifiedSince,
    unsigned int remoteVersion,
    int logerr)
{
    fc_error_t ret;
    cl_error_t cl_ret;
    fc_error_t status = FC_EARG;

    struct cl_cvd *cvd           = NULL;
    char *tmpfile_with_extension = NULL;
    char *url                    = NULL;
    size_t urlLen                = 0;

    if ((NULL == cvdfile) || (NULL == tmpfile) || (NULL == server)) {
        logg(LOGG_ERROR, "getcvd: Invalid arguments.\n");
        goto done;
    }

    urlLen = strlen(server) + strlen("/") + strlen(cvdfile);
    url    = malloc(urlLen + 1);
    snprintf(url, urlLen + 1, "%s/%s", server, cvdfile);

    ret = downloadFile(url, tmpfile, 1, logerr, ifModifiedSince);
    if (ret == FC_UPTODATE) {
        logg(LOGG_INFO, "%s is up-to-date.\n", cvdfile);
        status = ret;
        goto done;
    } else if (ret > FC_UPTODATE) {
        logg(logerr ? LOGG_ERROR : LOGG_WARNING, "Can't download %s from %s\n", cvdfile, url);
        status = ret;
        goto done;
    }

    /* Temporarily rename file to correct extension for verification. */
    tmpfile_with_extension = strdup(tmpfile);
    if (!tmpfile_with_extension) {
        logg(LOGG_ERROR, "Can't allocate memory for temp file with extension!\n");
        status = FC_EMEM;
        goto done;
    }
    strncpy(tmpfile_with_extension + strlen(tmpfile_with_extension) - 4, cvdfile + strlen(cvdfile) - 4, 4);
    if (rename(tmpfile, tmpfile_with_extension) == -1) {
        logg(LOGG_ERROR, "Can't rename %s to %s: %s\n", tmpfile, tmpfile_with_extension, strerror(errno));
        status = FC_EDBDIRACCESS;
        goto done;
    }

    if (CL_SUCCESS != (cl_ret = cl_cvdverify(tmpfile_with_extension))) {
        logg(LOGG_ERROR, "Verification: %s\n", cl_strerror(cl_ret));
        status = FC_EBADCVD;
        goto done;
    }

    if (NULL == (cvd = cl_cvdhead(tmpfile_with_extension))) {
        logg(LOGG_ERROR, "Can't read CVD header of new %s database.\n", cvdfile);
        status = FC_EBADCVD;
        goto done;
    }

    /* Rename the file back to the original, since verification passed. */
    if (rename(tmpfile_with_extension, tmpfile) == -1) {
        logg(LOGG_ERROR, "Can't rename %s to %s: %s\n", tmpfile_with_extension, tmpfile, strerror(errno));
        status = FC_EDBDIRACCESS;
        goto done;
    }

    if (cvd->version < remoteVersion) {
        logg(LOGG_DEBUG, "The %s database downloaded from %s is older than the version advertised in the DNS TXT record.\n",
             cvdfile,
             server);
        status = FC_EMIRRORNOTSYNC;
        goto done;
    }

    status = FC_SUCCESS;

done:
    if (NULL != cvd) {
        cl_cvdfree(cvd);
    }
    if (NULL != tmpfile_with_extension) {
        unlink(tmpfile_with_extension);
        free(tmpfile_with_extension);
    }
    if (NULL != url) {
        free(url);
    }
    if (
        (FC_SUCCESS != status) &&
        (FC_EMIRRORNOTSYNC != status) /* Keep older version, it's better than nothing. */
    ) {
        if (NULL != tmpfile) {
            unlink(tmpfile);
        }
    }

    return status;
}

/**
 * @brief Create a temp dir for storing CDIFFs for incremental database update.
 *
 * Will create the temp dir if it does not already exist and populate it with the
 * unpacked CVD. Then it will chdir to that directory.
 *
 * But if that directory already exists, it will simply chdir to it.
 *
 * @param database      The database we're updating.
 * @param[out] tmpdir   The name of the temp dir to use.
 * @return fc_error_t
 */
static fc_error_t mkdir_and_chdir_for_cdiff_tmp(const char *database, const char *tmpdir)
{
    fc_error_t status = FC_EDIRECTORY;

    char cvdfile[DB_FILENAME_MAX];

    if ((NULL == database) || (NULL == tmpdir)) {
        logg(LOGG_ERROR, "mkdir_and_chdir_for_cdiff_tmp: Invalid arguments.\n");
        status = FC_EARG;
        goto done;
    }

    if (-1 == access(tmpdir, R_OK | W_OK)) {
        /*
         * Temp directory for incremental update (cdiff download) does not
         * yet exist.
         */
        int ret;
        bool is_cld = false;

        /*
         * 1) Double-check that we have a CVD or CLD. Without either one, incremental update won't work.
         */
        ret = snprintf(cvdfile, sizeof(cvdfile), "%s.cvd", database);
        if (((int)sizeof(cvdfile) <= ret) || (-1 == ret)) {
            logg(LOGG_ERROR, "mkdir_and_chdir_for_cdiff_tmp: database parameter value too long to create cvd file name: %s\n", database);
            goto done;
        }

        if (-1 == access(cvdfile, R_OK)) {
            ret = snprintf(cvdfile, sizeof(cvdfile), "%s.cld", database);
            if (((int)sizeof(cvdfile) <= ret) || (-1 == ret)) {
                logg(LOGG_ERROR, "mkdir_and_chdir_for_cdiff_tmp: database parameter value too long to create cld file name: %s\n", database);
                goto done;
            }

            if (-1 == access(cvdfile, R_OK)) {
                logg(LOGG_ERROR, "mkdir_and_chdir_for_cdiff_tmp: Can't find (or access) local CVD or CLD for %s database\n", database);
                goto done;
            }

            is_cld = true;
        }

        /*
         * 2) Create the incremental update temp directory.
         */
        if (-1 == mkdir(tmpdir, 0755)) {
            logg(LOGG_ERROR, "mkdir_and_chdir_for_cdiff_tmp: Can't create directory %s\n", tmpdir);
            goto done;
        }

        /*
         * 3) Unpack the existing CVD/CLD database to this directory.
         */
        if (CL_SUCCESS != cl_cvdunpack(cvdfile, tmpdir, is_cld == true)) {
            logg(LOGG_ERROR, "mkdir_and_chdir_for_cdiff_tmp: Can't unpack %s into %s\n", cvdfile, tmpdir);
            cli_rmdirs(tmpdir);
            goto done;
        }
    }

    if (-1 == chdir(tmpdir)) {
        logg(LOGG_ERROR, "mkdir_and_chdir_for_cdiff_tmp: Can't change directory to %s\n", tmpdir);
        goto done;
    }

    status = FC_SUCCESS;

done:

    return status;
}

static fc_error_t downloadPatch(
    const char *database,
    const char *tmpdir,
    int version,
    char *server,
    int logerr)
{
    fc_error_t ret;
    fc_error_t status = FC_EARG;

    char *tempname = NULL;
    char patch[DB_FILENAME_MAX];
    char olddir[PATH_MAX];

    char *url     = NULL;
    size_t urlLen = 0;

    int fd = -1;

    olddir[0] = '\0';

    if ((NULL == database) || (NULL == tmpdir) || (NULL == server) || (0 == version)) {
        logg(LOGG_ERROR, "downloadPatch: Invalid arguments.\n");
        goto done;
    }

    if (NULL == getcwd(olddir, sizeof(olddir))) {
        logg(LOGG_ERROR, "downloadPatch: Can't get path of current working directory\n");
        status = FC_EDIRECTORY;
        goto done;
    }

    if (FC_SUCCESS != mkdir_and_chdir_for_cdiff_tmp(database, tmpdir)) {
        status = FC_EDIRECTORY;
        goto done;
    }

    if (NULL == (tempname = cli_gentemp("."))) {
        status = FC_EMEM;
        goto done;
    }

    snprintf(patch, sizeof(patch), "%s-%d.cdiff", database, version);
    urlLen = strlen(server) + strlen("/") + strlen(patch);
    url    = malloc(urlLen + 1);
    snprintf(url, urlLen + 1, "%s/%s", server, patch);

    if (FC_SUCCESS != (ret = downloadFile(url, tempname, 1, logerr, 0))) {
        if (ret == FC_EEMPTYFILE) {
            logg(LOGG_INFO, "Empty script %s, need to download entire database\n", patch);
        } else {
            logg(logerr ? LOGG_ERROR : LOGG_WARNING, "downloadPatch: Can't download %s from %s\n", patch, url);
        }
        status = ret;
        goto done;
    }

    if (-1 == (fd = open(tempname, O_RDONLY | O_BINARY))) {
        logg(LOGG_ERROR, "downloadPatch: Can't open %s for reading\n", tempname);
        status = FC_EFILE;
        goto done;
    }

    if (-1 == cdiff_apply(fd, 1)) {
        logg(LOGG_ERROR, "downloadPatch: Can't apply patch\n");
        status = FC_EFAILEDUPDATE;
        goto done;
    }

    status = FC_SUCCESS;

done:

    if (NULL != url) {
        free(url);
    }

    if (-1 != fd) {
        close(fd);
    }

    if (NULL != tempname) {
        unlink(tempname);
        free(tempname);
    }

    if ('\0' != olddir[0]) {
        if (-1 == chdir(olddir)) {
            logg(LOGG_ERROR, "downloadPatch: Can't chdir to %s\n", olddir);
            status = FC_EDIRECTORY;
        }
    }

    return status;
}

/**
 * @brief Get CVD header info for local CVD/CLD database.
 *
 * @param database          Database name
 * @param[out] localname    (optional) filename of local database.
 * @return struct cl_cvd*   CVD info struct of local database, if found. NULL if not found.
 */
static struct cl_cvd *currentdb(const char *database, char **localname)
{
    char filename[DB_FILENAME_MAX];
    struct cl_cvd *cvd = NULL;

    if (NULL == database) {
        logg(LOGG_ERROR, "currentdb: Invalid args!\n");
        goto done;
    }

    snprintf(filename, sizeof(filename), "%s.cvd", database);
    filename[sizeof(filename) - 1] = 0;

    if (-1 == access(filename, R_OK)) {
        /* CVD not found. */
        snprintf(filename, sizeof(filename), "%s.cld", database);
        filename[sizeof(filename) - 1] = 0;

        if (-1 == access(filename, R_OK)) {
            /* CLD also not found. Fail out. */
            goto done;
        }
    }

    if (NULL == (cvd = cl_cvdhead(filename))) {
        goto done;
    }

    if (localname) {
        *localname = cli_strdup(filename);
    }

done:

    return cvd;
}

static fc_error_t buildcld(
    const char *tmpdir,
    const char *database,
    const char *newfile,
    int bCompress)
{
    fc_error_t status = FC_EARG;

    char olddir[PATH_MAX] = {0};
    char info[DB_FILENAME_MAX];
    char buff[CVD_HEADER_SIZE + 1];
    char *pt;

    struct dirent *dent = NULL;
    DIR *dir            = NULL;
    gzFile gzs          = NULL;
    int fd              = -1;

    if ((NULL == tmpdir) || (NULL == database) || (NULL == newfile)) {
        logg(LOGG_ERROR, "buildcld: Invalid arguments.\n");
        goto done;
    }

    if (!getcwd(olddir, sizeof(olddir))) {
        logg(LOGG_ERROR, "buildcld: Can't get path of current working directory\n");
        status = FC_EDIRECTORY;
        goto done;
    }

    if (-1 == chdir(tmpdir)) {
        logg(LOGG_ERROR, "buildcld: Can't access directory %s\n", tmpdir);
        status = FC_EDIRECTORY;
        goto done;
    }

    snprintf(info, sizeof(info), "%s.info", database);
    info[sizeof(info) - 1] = 0;
    if (-1 == (fd = open(info, O_RDONLY | O_BINARY))) {
        logg(LOGG_ERROR, "buildcld: Can't open %s\n", info);
        status = FC_EFILE;
        goto done;
    }

    if (-1 == read(fd, buff, CVD_HEADER_SIZE)) {
        logg(LOGG_ERROR, "buildcld: Can't read %s\n", info);
        status = FC_EFILE;
        goto done;
    }
    buff[CVD_HEADER_SIZE] = 0;

    close(fd);
    fd = -1;

    if (NULL == (pt = strchr(buff, '\n'))) {
        logg(LOGG_ERROR, "buildcld: Bad format of %s\n", info);
        status = FC_EFAILEDUPDATE;
        goto done;
    }
    memset(pt, ' ', CVD_HEADER_SIZE + buff - pt);

    if (-1 == (fd = open(newfile, O_WRONLY | O_CREAT | O_EXCL | O_BINARY, 0644))) {
        logg(LOGG_ERROR, "buildcld: Can't open %s for writing\n", newfile);
        status = FC_EFILE;
        goto done;
    }
    if (CVD_HEADER_SIZE != write(fd, buff, CVD_HEADER_SIZE)) {
        logg(LOGG_ERROR, "buildcld: Can't write to %s\n", newfile);
        status = FC_EFILE;
        goto done;
    }

    if (bCompress) {
        close(fd);
        fd = -1;
        if (NULL == (gzs = gzopen(newfile, "ab9f"))) {
            logg(LOGG_ERROR, "buildcld: gzopen() failed for %s\n", newfile);
            status = FC_EFAILEDUPDATE;
            goto done;
        }
    }

    if (-1 == access("COPYING", R_OK)) {
        logg(LOGG_ERROR, "buildcld: COPYING file not found\n");
        status = FC_EFAILEDUPDATE;
        goto done;
    }

    if (-1 == tar_addfile(fd, gzs, "COPYING")) {
        logg(LOGG_ERROR, "buildcld: Can't add COPYING to new %s.cld - please check if there is enough disk space available\n", database);
        status = FC_EFAILEDUPDATE;
        goto done;
    }

    if (-1 != access(info, R_OK)) {
        if (-1 == tar_addfile(fd, gzs, info)) {
            logg(LOGG_ERROR, "buildcld: Can't add %s to new %s.cld - please check if there is enough disk space available\n", info, database);
            status = FC_EFAILEDUPDATE;
            goto done;
        }
    }

    if (-1 != access("daily.cfg", R_OK)) {
        if (-1 == tar_addfile(fd, gzs, "daily.cfg")) {
            logg(LOGG_ERROR, "buildcld: Can't add daily.cfg to new %s.cld - please check if there is enough disk space available\n", database);
            status = FC_EFAILEDUPDATE;
            goto done;
        }
    }

    if (NULL == (dir = opendir(tmpdir))) {
        logg(LOGG_ERROR, "buildcld: Can't open directory %s\n", tmpdir);
        status = FC_EDIRECTORY;
        goto done;
    }

    while (NULL != (dent = readdir(dir))) {
        if (dent->d_ino) {
            if (!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, "..") || !strcmp(dent->d_name, "COPYING") || !strcmp(dent->d_name, "daily.cfg") || !strcmp(dent->d_name, info))
                continue;

            if (tar_addfile(fd, gzs, dent->d_name) == -1) {
                logg(LOGG_ERROR, "buildcld: Can't add %s to new %s.cld - please check if there is enough disk space available\n", dent->d_name, database);
                status = FC_EFAILEDUPDATE;
                goto done;
            }
        }
    }

    status = FC_SUCCESS;

done:

    if (-1 != fd) {
        if (-1 == close(fd)) {
            logg(LOGG_ERROR, "buildcld: close() failed for %s\n", newfile);
        }
    }
    if (NULL != gzs) {
        if (gzclose(gzs)) {
            logg(LOGG_ERROR, "buildcld: gzclose() failed for %s\n", newfile);
        }
    }
    if (NULL != dir) {
        closedir(dir);
    }

    if (FC_SUCCESS != status) {
        if (NULL != newfile) {
            unlink(newfile);
        }
    }

    if ('\0' != olddir[0]) {
        if (-1 == chdir(olddir)) {
            logg(LOGG_ERROR, "buildcld: Can't return to previous directory %s\n", olddir);
            status = FC_EDIRECTORY;
        }
    }

    return status;
}

static fc_error_t query_remote_database_version(
    const char *database,
    uint32_t ifModifiedSince,
    const char *dnsUpdateInfo,
    char *server,
    int bPrivateMirror,
    int logerr,
    uint32_t *remoteVersion,
    char **remoteFilename)
{
    fc_error_t ret;
    fc_error_t status = FC_EARG;

    uint32_t newVersion = 0;
    char cvdfile[DB_FILENAME_MAX];
    char cldfile[DB_FILENAME_MAX];

#ifdef HAVE_RESOLV_H
    char *dnqueryDomain = NULL;
    char *extradnsreply = NULL;
#endif

    struct cl_cvd *remote = NULL;
    int remote_is_cld     = 0;

    if ((NULL == database) || (NULL == server) || (NULL == remoteVersion) || (NULL == remoteFilename)) {
        logg(LOGG_ERROR, "query_remote_database_version: Invalid args!\n");
        goto done;
    }

    *remoteVersion  = 0;
    *remoteFilename = NULL;

    snprintf(cvdfile, sizeof(cvdfile), "%s.cvd", database);
    cvdfile[sizeof(cvdfile) - 1] = 0;
    snprintf(cldfile, sizeof(cldfile), "%s.cld", database);
    cldfile[sizeof(cldfile) - 1] = 0;

    if ((!bPrivateMirror) && (NULL != dnsUpdateInfo)) {
        /*
         * Use Primary DNS Update Info record to find the version.
         */
        int field              = 0;
        char *verStrDnsPrimary = NULL;

        if (0 == (field = textrecordfield(database))) {
            logg(LOGG_DEBUG, "query_remote_database_version: Database name \"%s\" isn't listed in DNS update info.\n", database);
        } else if (NULL == (verStrDnsPrimary = cli_strtok(dnsUpdateInfo, field, ":"))) {
            logg(LOGG_WARNING, "Invalid DNS update info. Falling back to HTTP mode.\n");
        } else if (!cli_isnumber(verStrDnsPrimary)) {
            logg(LOGG_WARNING, "Broken database version in TXT record. Falling back to HTTP mode.\n");
        } else {
            newVersion = atoi(verStrDnsPrimary);
            logg(LOGG_DEBUG, "query_remote_database_version: %s version from DNS: %d\n", cvdfile, newVersion);
        }
        free(verStrDnsPrimary);

#ifdef HAVE_RESOLV_H
        if (newVersion == 0) {
            /*
             * Primary DNS Update Info record didn't have the version # for this database.
             * Try to use a <database>.cvd.clamav.net DNS query to find the version #.
             */
            size_t dnqueryDomainLen = strlen(database) + strlen(".cvd.clamav.net");

            dnqueryDomain = malloc(dnqueryDomainLen + 1);
            snprintf(dnqueryDomain, dnqueryDomainLen + 1, "%s.cvd.clamav.net", database);
            if (NULL == (extradnsreply = dnsquery(dnqueryDomain, T_TXT, NULL))) {
                logg(LOGG_WARNING, "No timestamp in TXT record for %s\n", cvdfile);
            } else {
                char *recordTimeStr  = NULL;
                char *verStrDnsExtra = NULL;

                if (NULL == (recordTimeStr = cli_strtok(extradnsreply, DNS_EXTRADBINFO_RECORDTIME, ":"))) {
                    logg(LOGG_WARNING, "No recordtime field in TXT record for %s\n", cvdfile);
                } else {
                    int recordTime;
                    time_t currentTime;

                    recordTime = atoi(recordTimeStr);
                    free(recordTimeStr);
                    time(&currentTime);
                    if ((int)currentTime - recordTime > DNS_WARNING_THRESHOLD_SECONDS) {
                        logg(LOGG_WARNING, "DNS record is older than %d hours.\n", DNS_WARNING_THRESHOLD_HOURS);
                    } else if (NULL != (verStrDnsExtra = cli_strtok(extradnsreply, 0, ":"))) {
                        if (!cli_isnumber(verStrDnsExtra)) {
                            logg(LOGG_WARNING, "Broken database version in TXT record for %s\n", cvdfile);
                        } else {
                            newVersion = atoi(verStrDnsExtra);
                            logg(LOGG_DEBUG, "%s version from DNS: %d\n", cvdfile, newVersion);
                        }
                        free(verStrDnsExtra);
                    } else {
                        logg(LOGG_WARNING, "Invalid DNS reply. Falling back to HTTP mode.\n");
                    }
                }
            }
        }
#endif
    }

    if (newVersion == 0) {
        /*
         * Was unable to use DNS info records to determine database version.
         * Use HTTP GET to get version info from CVD/CLD header.
         */
        if (bPrivateMirror) {
            /*
             * For a private mirror, get the CLD instead of the CVD.
             *
             * On the mirror, they should have CDIFFs/scripted/incremental
             * updates enabled, so they should have CLD's to distribute.
             */
            ret = remote_cvdhead(cldfile, ifModifiedSince, server, logerr, &remote);
            if ((FC_SUCCESS == ret) || (FC_UPTODATE == ret)) {
                remote_is_cld = 1;
            } else {
                /*
                 * Failed to get CLD update, and it's unknown if the status is up-to-date.
                 *
                 * If it's a relatively new mirror, the CLD won't have been replaced with a CVD yet.
                 * Attempt to get the CVD instead.
                 */
                ret = remote_cvdhead(cvdfile, ifModifiedSince, server, logerr, &remote);
            }
        } else {
            /*
             * Official update servers will only have the CVD.
             */
            ret = remote_cvdhead(cvdfile, ifModifiedSince, server, logerr, &remote);
        }

        switch (ret) {
            case FC_SUCCESS: {
                logg(LOGG_DEBUG, "%s database version obtained using HTTP GET: %u\n", database, remote->version);
                break;
            }
            case FC_UPTODATE: {
                logg(LOGG_DEBUG, "%s database version up-to-date, according to HTTP response code from server.\n", database);
                status = FC_UPTODATE;
                goto done;
            }
            default: {
                logg(LOGG_WARNING, "Failed to get %s database version information from server: %s\n", database, server);
                status = ret;
                goto done;
            }
        }

        newVersion = remote->version;
    }

    if (remote_is_cld) {
        *remoteFilename = cli_strdup(cldfile);
    } else {
        *remoteFilename = cli_strdup(cvdfile);
    }
    *remoteVersion = newVersion;

    status = FC_SUCCESS;

done:

    if (NULL != remote) {
        cl_cvdfree(remote);
    }
#ifdef HAVE_RESOLV_H
    if (NULL != dnqueryDomain) {
        free(dnqueryDomain);
    }
    if (NULL != extradnsreply) {
        free(extradnsreply);
    }
#endif

    return status;
}

static fc_error_t check_for_new_database_version(
    const char *database,
    const char *dnsUpdateInfo,
    char *server,
    int bPrivateMirror,
    int logerr,
    uint32_t *localVersion,
    uint32_t *remoteVersion,
    char **localFilename,
    char **remoteFilename,
    uint32_t *localTimestamp)
{
    fc_error_t ret;
    fc_error_t status = FC_EARG;

    char *localname               = NULL;
    struct cl_cvd *local_database = NULL;
    char *remotename              = NULL;

    uint32_t localver  = 0;
    uint32_t remotever = 0;

    if ((NULL == database) || (NULL == server) ||
        (NULL == localVersion) || (NULL == remoteVersion) ||
        (NULL == localFilename) || (NULL == remoteFilename) ||
        (NULL == localTimestamp)) {
        logg(LOGG_ERROR, "check_for_new_database_version: Invalid args!\n");
        goto done;
    }

    *localVersion   = 0;
    *remoteVersion  = 0;
    *localFilename  = NULL;
    *remoteFilename = NULL;
    *localTimestamp = 0;

    /*
     * Check local database version (if exists)
     */
    if (NULL == (local_database = currentdb(database, &localname))) {
        logg(LOGG_DEBUG, "check_for_new_database_version: No local copy of \"%s\" database.\n", database);
    } else {
        logg(LOGG_DEBUG, "check_for_new_database_version: Local copy of %s found: %s.\n", database, localname);
        *localTimestamp = local_database->stime;
        localver        = local_database->version;
    }

    /*
     * Look up the latest available database version.
     */
    ret = query_remote_database_version(
        database,
        *localTimestamp,
        dnsUpdateInfo,
        server,
        bPrivateMirror,
        logerr,
        &remotever,
        &remotename);
    switch (ret) {
        case FC_SUCCESS:
            if (0 == localver) {
                logg(LOGG_INFO, "%s database available for download (remote version: %d)\n",
                     database, remotever);
                break;
            } else if (localver < remotever) {
                logg(LOGG_INFO, "%s database available for update (local version: %d, remote version: %d)\n",
                     database, localver, remotever);
                break;
            }
            /* fall-through */

        case FC_UPTODATE:
            if (NULL == local_database) {
                logg(LOGG_ERROR, "check_for_new_database_version: server claims we're up-to-date, but we don't have a local database!\n");
                status = FC_EFAILEDGET;
                goto done;
            }
            logg(LOGG_INFO, "%s database is up-to-date (version: %d, sigs: %d, f-level: %d, builder: %s)\n",
                 localname,
                 local_database->version,
                 local_database->sigs,
                 local_database->fl,
                 local_database->builder);

            /* The remote version wouldn't be set if the server returned "Not-Modified".
               We know it will be the same as the local version though. */
            remotever = localver;
            break;

        case FC_EFORBIDDEN:
            /* We tried to look up the version using HTTP and were actively blocked. */
            logg(LOGG_ERROR, "check_for_new_database_version: Blocked from using server %s.\n", server);
            status = FC_EFORBIDDEN;
            goto done;

        default:
            logg(LOGG_ERROR, "check_for_new_database_version: Failed to find %s database using server %s.\n", database, server);
            status = FC_EFAILEDGET;
            goto done;
    }

    *remoteVersion = remotever;
    if (NULL != remotename) {
        *remoteFilename = cli_strdup(remotename);
        if (NULL == *remoteFilename) {
            logg(LOGG_ERROR, "check_for_new_database_version: Failed to allocate memory for remote filename.\n");
            status = FC_EMEM;
            goto done;
        }
    }
    if (NULL != localname) {
        *localVersion  = localver;
        *localFilename = cli_strdup(localname);
        if (NULL == *localFilename) {
            logg(LOGG_ERROR, "check_for_new_database_version: Failed to allocate memory for local filename.\n");
            status = FC_EMEM;
            goto done;
        }
    }

    status = FC_SUCCESS;

done:

    if (NULL != localname) {
        free(localname);
    }
    if (NULL != remotename) {
        free(remotename);
    }
    if (NULL != local_database) {
        cl_cvdfree(local_database);
    }

    return status;
}

fc_error_t updatedb(
    const char *database,
    const char *dnsUpdateInfo,
    char *server,
    int bPrivateMirror,
    void *context,
    int bScriptedUpdates,
    int logerr,
    int *signo,
    char **dbFilename,
    int *bUpdated)
{
    fc_error_t ret;
    fc_error_t status = FC_EARG;

    struct cl_cvd *cvd = NULL;

    uint32_t localTimestamp = 0;
    uint32_t localVersion   = 0;
    uint32_t remoteVersion  = 0;
    char *localFilename     = NULL;
    char *remoteFilename    = NULL;
    char *newLocalFilename  = NULL;

    char *tmpdir  = NULL;
    char *tmpfile = NULL;

    unsigned int flevel;

    unsigned int i, j;

    if ((NULL == database) || (NULL == server) || (NULL == signo) || (NULL == dbFilename) || (NULL == bUpdated)) {
        logg(LOGG_ERROR, "updatedb: Invalid args!\n");
        goto done;
    }

    *signo      = 0;
    *dbFilename = NULL;
    *bUpdated   = 0;

    /*
     * Check if new version exists.
     */
    if (FC_SUCCESS != (ret = check_for_new_database_version(
                           database,
                           dnsUpdateInfo,
                           server,
                           bPrivateMirror,
                           logerr,
                           &localVersion,
                           &remoteVersion,
                           &localFilename,
                           &remoteFilename,
                           &localTimestamp))) {
        logg(LOGG_DEBUG, "updatedb: %s database update failed.\n", database);
        status = ret;
        goto done;
    }

    if ((localVersion >= remoteVersion) && (NULL != localFilename)) {
        *dbFilename = cli_strdup(localFilename);
        goto up_to_date;
    }

    /* Download CVD or CLD to temp file */
    tmpfile = cli_gentemp(g_tempDirectory);
    if (!tmpfile) {
        status = FC_EMEM;
        goto done;
    }

    if ((localVersion == 0) || (!bScriptedUpdates)) {
        /*
         * Download entire file.
         */
        ret = getcvd(remoteFilename, tmpfile, server, localTimestamp, remoteVersion, logerr);
        if (FC_UPTODATE == ret) {
            logg(LOGG_WARNING, "Expected newer version of %s database but the server's copy is not newer than our local file (version %d).\n", database, localVersion);
            if (NULL != localFilename) {
                /* Received a 304 (not modified), must be up-to-date after all */
                *dbFilename = cli_strdup(localFilename);
            }
            goto up_to_date;
        } else if (FC_EMIRRORNOTSYNC == ret) {
            /* Let's accept this older version, but keep the error code.
             * We'll have fc_update_database() retry using CDIFFs.
             */
            logg(LOGG_DEBUG, "Received an older %s CVD than was advertised. We'll keep it and try updating to the latest version with CDIFFs.\n", database);
            status = ret;
        } else if (FC_SUCCESS != ret) {
            status = ret;
            goto done;
        }

        newLocalFilename = cli_strdup(remoteFilename);
    } else {
        /*
         * Attempt scripted/CDIFF incremental update.
         */
        ret                         = FC_SUCCESS;
        uint32_t numPatchesReceived = 0;

        tmpdir = cli_gentemp(g_tempDirectory);
        if (!tmpdir) {
            status = FC_EMEM;
            goto done;
        }

#ifdef HAVE_UNISTD_H
        if (!mprintf_quiet && (mprintf_progress || isatty(fileno(stdout))))
#else
        if (!mprintf_quiet)
#endif
        {
            if (remoteVersion - localVersion == 1) {
                mprintf(LOGG_INFO, "Current database is 1 version behind.\n");
            } else {
                mprintf(LOGG_INFO, "Current database is %u versions behind.\n", remoteVersion - localVersion);
            }
        }
        for (i = localVersion + 1; i <= remoteVersion; i++) {
            for (j = 1; j <= g_maxAttempts; j++) {
                int llogerr = logerr;
                if (logerr)
                    llogerr = (j == g_maxAttempts);

#ifdef HAVE_UNISTD_H
                if (!mprintf_quiet && (mprintf_progress || isatty(fileno(stdout))))
#else
                if (!mprintf_quiet)
#endif
                {
                    mprintf(LOGG_INFO, "Downloading database patch # %u...\n", i);
                }
                ret = downloadPatch(database, tmpdir, i, server, llogerr);
                if (ret == FC_ECONNECTION || ret == FC_EFAILEDGET) {
                    continue;
                } else {
                    break;
                }
            }
            if (FC_SUCCESS == ret) {
                numPatchesReceived += 1;
            } else {
                break;
            }
        }

        if (
            (FC_EEMPTYFILE == ret) ||                                 /* Request a new CVD if we got an empty CDIFF.      */
            (FC_EFAILEDUPDATE == ret) ||                              /* Request a new CVD if we failed to apply a CDIFF. */
            (FC_SUCCESS != ret && (                                   /* Or if the incremental update failed:             */
                                   (0 == numPatchesReceived) &&       /* 1. Ask for the CVD if we didn't get any patches, */
                                   (localVersion < remoteVersion - 1) /* 2. AND if we're more than 1 version out of date. */
                                   ))) {
            /*
             * Incremental update failed or intentionally disabled.
             */
            if (ret == FC_EEMPTYFILE) {
                logg(LOGG_DEBUG, "Empty CDIFF found. Skip incremental updates for this version and download %s\n", remoteFilename);
            } else {
                logg(LOGG_WARNING, "Incremental update failed, trying to download %s\n", remoteFilename);
            }

            ret = getcvd(remoteFilename, tmpfile, server, localTimestamp, remoteVersion, logerr);
            if (FC_SUCCESS != ret) {
                if (FC_EMIRRORNOTSYNC == ret) {
                    /* Note: We can't retry with CDIFF's if FC_EMIRRORNOTSYNC happened here.
                     * If we did there could be an infinite loop.
                     * Best option is to accept the older CVD.
                     */
                    logg(LOGG_WARNING, "Received an older %s CVD than was advertised. Incremental updates either failed or are disabled, so we'll have to settle for a slightly out-of-date database.\n", database);
                    status = FC_SUCCESS;
                } else {
                    status = ret;
                    goto done;
                }
            }

            newLocalFilename = cli_strdup(remoteFilename);
        } else if (0 == numPatchesReceived) {
            logg(LOGG_INFO, "The database server doesn't have the latest patch for the %s database (version %u). The server will likely have updated if you check again in a few hours.\n", database, remoteVersion);
            *dbFilename = cli_strdup(localFilename);
            goto up_to_date;
        } else {
            /*
             * CDIFFs downloaded; Use CDIFFs to turn old CVD/CLD into new updated CLD.
             */
            if (numPatchesReceived < remoteVersion - localVersion) {
                logg(LOGG_INFO, "Downloaded %u patches for %s, which is fewer than the %u expected patches.\n", numPatchesReceived, database, remoteVersion - localVersion);
                logg(LOGG_INFO, "We'll settle for this partial-update, at least for now.\n");
            }

            size_t newLocalFilenameLen = 0;
            if (FC_SUCCESS != buildcld(tmpdir, database, tmpfile, g_bCompressLocalDatabase)) {
                logg(LOGG_ERROR, "updatedb: Incremental update failed. Failed to build CLD.\n");
                status = FC_EBADCVD;
                goto done;
            }

            newLocalFilenameLen = strlen(database) + strlen(".cld");
            newLocalFilename    = malloc(newLocalFilenameLen + 1);
            snprintf(newLocalFilename, newLocalFilenameLen + 1, "%s.cld", database);
        }
    }

    /*
     * Update downloaded.
     * Test database before replacing original database with new database.
     */
    if (NULL != g_cb_download_complete) {
        char *tmpfile_with_extension      = NULL;
        size_t tmpfile_with_extension_len = strlen(tmpfile) + 1 + strlen(newLocalFilename);

        /* Suffix tmpfile with real database name & extension so it can be loaded. */
        tmpfile_with_extension = malloc(tmpfile_with_extension_len + 1);
        if (!tmpfile_with_extension) {
            status = FC_ETESTFAIL;
            goto done;
        }
        snprintf(tmpfile_with_extension, tmpfile_with_extension_len + 1, "%s-%s", tmpfile, newLocalFilename);
        if (rename(tmpfile, tmpfile_with_extension) == -1) {
            logg(LOGG_ERROR, "updatedb: Can't rename %s to %s: %s\n", tmpfile, tmpfile_with_extension, strerror(errno));
            free(tmpfile_with_extension);
            status = FC_EDBDIRACCESS;
            goto done;
        }
        free(tmpfile);
        tmpfile                = tmpfile_with_extension;
        tmpfile_with_extension = NULL;

        /* Run callback to test it. */
        logg(LOGG_DEBUG, "updatedb: Running g_cb_download_complete callback...\n");
        if (FC_SUCCESS != (ret = g_cb_download_complete(tmpfile, context))) {
            logg(LOGG_DEBUG, "updatedb: callback failed: %s (%d)\n", fc_strerror(ret), ret);
            status = ret;
            goto done;
        }
    }

    /*
     * Replace original database with new database.
     */
#ifdef _WIN32
    if (!access(newLocalFilename, R_OK) && unlink(newLocalFilename)) {
        logg(LOGG_ERROR, "Update failed. Can't delete the old database %s to replace it with a new database. Please fix the problem manually and try again.\n", newLocalFilename);
        status = FC_EDBDIRACCESS;
        goto done;
    }
#endif
    if (rename(tmpfile, newLocalFilename) == -1) {
        logg(LOGG_ERROR, "updatedb: Can't rename %s to %s: %s\n", tmpfile, newLocalFilename, strerror(errno));
        status = FC_EDBDIRACCESS;
        goto done;
    }

    /* If we just updated from a CVD to a CLD, delete the old CVD */
    if ((NULL != localFilename) && !access(localFilename, R_OK) && strcmp(newLocalFilename, localFilename))
        if (unlink(localFilename))
            logg(LOGG_WARNING, "updatedb: Can't delete the old database file %s. Please remove it manually.\n", localFilename);

    /* Parse header to record number of sigs. */
    if (NULL == (cvd = cl_cvdhead(newLocalFilename))) {
        logg(LOGG_ERROR, "updatedb: Can't parse new database %s\n", newLocalFilename);
        status = FC_EFILE;
        goto done;
    }

    logg(LOGG_INFO, "%s updated (version: %d, sigs: %d, f-level: %d, builder: %s)\n",
         newLocalFilename, cvd->version, cvd->sigs, cvd->fl, cvd->builder);

    flevel = cl_retflevel();
    if (flevel < cvd->fl) {
        logg(LOGG_WARNING, "Your ClamAV installation is OUTDATED!\n");
        logg(LOGG_WARNING, "Current functionality level = %d, recommended = %d\n", flevel, cvd->fl);
        logg(LOGG_INFO, "DON'T PANIC! Read https://docs.clamav.net/manual/Installing.html\n");
    }

    *signo      = cvd->sigs;
    *bUpdated   = 1;
    *dbFilename = cli_strdup(newLocalFilename);
    if (NULL == *dbFilename) {
        logg(LOGG_ERROR, "updatedb: Failed to allocate memory for database filename.\n");
        status = FC_EMEM;
        goto done;
    }

up_to_date:

    if (status != FC_EMIRRORNOTSYNC) {
        status = FC_SUCCESS;
    }

done:

    if (NULL != cvd) {
        cl_cvdfree(cvd);
    }

    if (NULL != localFilename) {
        free(localFilename);
    }
    if (NULL != remoteFilename) {
        free(remoteFilename);
    }
    if (NULL != newLocalFilename) {
        free(newLocalFilename);
    }

    if (NULL != tmpfile) {
        unlink(tmpfile);
        free(tmpfile);
    }
    if (NULL != tmpdir) {
        cli_rmdirs(tmpdir);
        free(tmpdir);
    }

    return status;
}

fc_error_t updatecustomdb(
    const char *url,
    void *context,
    int logerr,
    int *signo,
    char **dbFilename,
    int *bUpdated)
{
    fc_error_t ret;
    fc_error_t status = FC_EARG;

    unsigned int sigs = 0;
    char *tmpfile     = NULL;
    const char *databaseName;
    STATBUF statbuf;
    time_t dbtime = 0;

    if ((NULL == url) || (NULL == signo) || (NULL == dbFilename) || (NULL == bUpdated)) {
        logg(LOGG_ERROR, "updatecustomdb: Invalid args!\n");
        goto done;
    }

    *signo      = 0;
    *dbFilename = NULL;
    *bUpdated   = 0;

    tmpfile = cli_gentemp(g_tempDirectory);
    if (!tmpfile) {
        status = FC_EFAILEDUPDATE;
        goto done;
    }

    if (!strncasecmp(url, "file://", strlen("file://"))) {
        /*
         * Copy from local file.
         */
        time_t remote_dbtime;
        const char *rpath;

        rpath = &url[strlen("file://")];
#ifdef _WIN32
        databaseName = strrchr(rpath, '\\');
#else
        databaseName = strrchr(rpath, '/');
#endif
        if ((NULL == databaseName) || strlen(databaseName++) < strlen(".ext") + 1) {
            logg(LOGG_INFO, "DatabaseCustomURL: Incorrect URL\n");
            status = FC_EFAILEDUPDATE;
            goto done;
        }

        if (CLAMSTAT(rpath, &statbuf) == -1) {
            logg(LOGG_INFO, "DatabaseCustomURL: file %s missing\n", rpath);
            status = FC_EFAILEDUPDATE;
            goto done;
        }
        remote_dbtime = statbuf.st_mtime;
        dbtime        = (CLAMSTAT(databaseName, &statbuf) != -1) ? statbuf.st_mtime : 0;
        if (dbtime > remote_dbtime) {
            logg(LOGG_INFO, "%s is up-to-date (version: custom database)\n", databaseName);
            goto up_to_date;
        }

        /* FIXME: preserve file permissions, calculate % */
        if (-1 == cli_filecopy(rpath, tmpfile)) {
            logg(LOGG_INFO, "DatabaseCustomURL: Can't copy file %s into database directory\n", rpath);
            status = FC_EFAILEDUPDATE;
            goto done;
        }

        logg(LOGG_INFO, "Downloading %s [100%%]\n", databaseName);
    } else {
        /*
         * Download from URL.  http(s) or ftp(s)
         */
        databaseName = strrchr(url, '/');
        if ((NULL == databaseName) || (strlen(databaseName++) < 5)) {
            logg(LOGG_INFO, "DatabaseCustomURL: Incorrect URL\n");
            status = FC_EFAILEDUPDATE;
            goto done;
        }

        dbtime = (CLAMSTAT(databaseName, &statbuf) != -1) ? statbuf.st_mtime : 0;

        ret = downloadFile(url, tmpfile, 1, logerr, dbtime);
        if (ret == FC_UPTODATE) {
            logg(LOGG_INFO, "%s is up-to-date (version: custom database)\n", databaseName);
            goto up_to_date;
        } else if (ret > FC_UPTODATE) {
            logg(logerr ? LOGG_ERROR : LOGG_WARNING, "Can't download %s from %s\n", databaseName, url);
            status = ret;
            goto done;
        }
    }

    /*
     * Update downloaded.
     * Test database before replacing original database with new database.
     */
    if (NULL != g_cb_download_complete) {
        char *tmpfile_with_extension      = NULL;
        size_t tmpfile_with_extension_len = strlen(tmpfile) + 1 + strlen(databaseName);

        /* Suffix tmpfile with real database name & extension so it can be loaded. */
        tmpfile_with_extension = malloc(tmpfile_with_extension_len + 1);
        if (!tmpfile_with_extension) {
            status = FC_ETESTFAIL;
            goto done;
        }
        snprintf(tmpfile_with_extension, tmpfile_with_extension_len + 1, "%s-%s", tmpfile, databaseName);
        if (rename(tmpfile, tmpfile_with_extension) == -1) {
            logg(LOGG_ERROR, "Custom database update failed: Can't rename %s to %s: %s\n", tmpfile, tmpfile_with_extension, strerror(errno));
            free(tmpfile_with_extension);
            status = FC_EDBDIRACCESS;
            goto done;
        }
        free(tmpfile);
        tmpfile                = tmpfile_with_extension;
        tmpfile_with_extension = NULL;

        /* Run callback to test it. */
        logg(LOGG_DEBUG, "updatecustomdb: Running g_cb_download_complete callback...\n");
        if (FC_SUCCESS != (ret = g_cb_download_complete(tmpfile, context))) {
            logg(LOGG_DEBUG, "updatecustomdb: callback failed: %s (%d)\n", fc_strerror(ret), ret);
            status = ret;
            goto done;
        }
    }

    /*
     * Replace original database with new database.
     */
#ifdef _WIN32
    if (!access(databaseName, R_OK) && unlink(databaseName)) {
        logg(LOGG_ERROR, "Custom database update failed. Can't delete the old database %s to replace it with a new database. Please fix the problem manually and try again.\n", databaseName);
        status = FC_EDBDIRACCESS;
        goto done;
    }
#endif
    if (rename(tmpfile, databaseName) == -1) {
        logg(LOGG_ERROR, "updatecustomdb: Can't rename %s to %s: %s\n", tmpfile, databaseName, strerror(errno));
        status = FC_EDBDIRACCESS;
        goto done;
    }

    /*
     * Record # of signatures in updated database.
     */
    if (cli_strbcasestr(databaseName, ".cld") || cli_strbcasestr(databaseName, ".cvd")) {
        struct cl_cvd *cvd = NULL;
        unsigned int flevel;

        if (NULL == (cvd = cl_cvdhead(databaseName))) {
            logg(LOGG_ERROR, "updatecustomdb: Can't parse new database %s\n", databaseName);
            status = FC_EFILE;
            goto done;
        }

        sigs = cvd->sigs;

        flevel = cl_retflevel();
        if (flevel < cvd->fl) {
            logg(LOGG_WARNING, "Your ClamAV installation is OUTDATED!\n");
            logg(LOGG_WARNING, "Current functionality level = %d, recommended = %d\n", flevel, cvd->fl);
            logg(LOGG_INFO, "DON'T PANIC! Read https://docs.clamav.net/manual/Installing.html\n");
        }

        cl_cvdfree(cvd);
    } else if (cli_strbcasestr(databaseName, ".cbc")) {
        sigs = 1;
    } else {
        sigs = countlines(databaseName);
    }

    logg(LOGG_INFO, "%s updated (version: custom database, sigs: %u)\n", databaseName, sigs);
    *signo    = sigs;
    *bUpdated = 1;

up_to_date:

    *dbFilename = cli_strdup(databaseName);
    if (NULL == *dbFilename) {
        logg(LOGG_ERROR, "Failed to allocate memory for database filename.\n");
        status = FC_EMEM;
        goto done;
    }

    status = FC_SUCCESS;

done:

    if (NULL != tmpfile) {
        unlink(tmpfile);
        free(tmpfile);
    }

    return status;
}

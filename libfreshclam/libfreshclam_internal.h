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

#ifndef __LIBFRESHCLAM_INTERNAL_H
#define __LIBFRESHCLAM_INTERNAL_H

#include "clamav-types.h"

// clang-format off
#define DNS_UPDATEINFO_NEWVERSION       0
#define DNS_UPDATEINFO_RECORDTIME       3
#define DNS_UPDATEINFO_VERSIONWARNING   4
#define DNS_UPDATEINFO_REMOTEFLEVEL     5

#define DNS_EXTRADBINFO_RECORDTIME      1
// clang-format on

/* ----------------------------------------------------------------------------
 * Internal libfreshclam globals
 */

extern fccb_download_complete g_cb_download_complete;

extern char *g_localIP;
extern char *g_userAgent;

extern char *g_proxyServer;
extern uint16_t g_proxyPort;
extern char *g_proxyUsername;
extern char *g_proxyPassword;

extern char *g_tempDirectory;
extern char *g_databaseDirectory;

extern uint32_t g_maxAttempts;
extern uint32_t g_connectTimeout;
extern uint32_t g_requestTimeout;

extern uint32_t g_bCompressLocalDatabase;

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
    int *bUpdated);

fc_error_t updatecustomdb(
    const char *url,
    void *context,
    int logerr,
    int *signo,
    char **dbFilename,
    int *bUpdated);

#endif // __LIBFRESHCLAM_INTERNAL_H

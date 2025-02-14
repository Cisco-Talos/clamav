/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Mickey Sola
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

#ifndef __ONAS_CLAMONACC_H
#define __ONAS_CLAMONACC_H

// libclamav
#include "clamav.h"

#ifndef ONAS_DEBUG
#define ONAS_DEBUG
#endif
/* dev only switch for very noisy output */
#undef ONAS_DEBUG

#ifndef HAVE_ATTRIB_PACKED
#define __attribute__(x)
#endif
#ifdef HAVE_PRAGMA_PACK
#pragma pack(1)
#endif
#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack 1
#endif

struct onas_context {
    const struct optstruct *opts;
    const struct optstruct *clamdopts;

    int printinfected;
    int maxstream;

    uint32_t ddd_enabled;

    int fan_fd;
    uint64_t fan_mask;
    uint8_t retry_on_error;
    uint8_t retry_attempts;
    uint8_t deny_on_error;

    uint64_t sizelimit;
    uint64_t extinfo;

    int scantype;
    int isremote;
    int session;
    int timeout;

    int64_t portnum;

    int32_t maxthreads;
} __attribute__((packed));

#ifdef HAVE_PRAGMA_PACK
#pragma pack()
#endif
#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack
#endif

struct onas_context *onas_init_context(void);
void onas_cleanup(struct onas_context *ctx);
void onas_context_cleanup(struct onas_context *ctx);
cl_error_t onas_check_client_connection(struct onas_context **ctx);
int onas_start_eloop(struct onas_context **ctx);
void help(void);

#endif

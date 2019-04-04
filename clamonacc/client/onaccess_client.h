/*
 *  Copyright (C) 2015-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm, aCaB
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

#ifndef __ONAS_CLIENT_H
#define __ONAS_CLIENT_H

#include "shared/optparser.h"
#include "../clamonacc.h"

enum {
    CONT,
    MULTI,
    STREAM,
    FILDES,
    ALLMATCH,
    MAX_SCANTYPE = ALLMATCH
};


int onas_client_scan(struct onas_context **ctx, const char *fname, STATBUF sb, int *infected, int *err, cl_error_t *ret_code);
int onas_get_clamd_version(struct onas_context **ctx);
cl_error_t onas_setup_client(struct onas_context **ctx);
int onas_check_remote(struct onas_context  **ctx);

#endif

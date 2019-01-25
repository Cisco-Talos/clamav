/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2013 Sourcefire, Inc.
 *
 *  Authors: Steven Morgan (smorgan@sourcefire.com)
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

#ifndef __XZ_IFACE_H
#define __XZ_IFACE_H

#include "7z/Xz.h"
#include "clamav-types.h"
#include "others.h"

struct CLI_XZ {
    CXzUnpacker state;
    ECoderStatus status;
    unsigned char *next_in;
    unsigned char *next_out;
    SizeT avail_in;
    SizeT avail_out;
};

int cli_XzInit(struct CLI_XZ *);
void cli_XzShutdown(struct CLI_XZ *);
int cli_XzDecode(struct CLI_XZ *);

#define XZ_RESULT_OK 0
#define XZ_RESULT_DATA_ERROR 1
#define XZ_STREAM_END 2

#define XZ_DIC_HEURISTIC 3

#define CLI_XZ_OBUF_SIZE 1024*1024
#define CLI_XZ_IBUF_SIZE CLI_XZ_OBUF_SIZE>>2 /* compression ratio 25% */

#endif /* __XZ_IFACE_H */

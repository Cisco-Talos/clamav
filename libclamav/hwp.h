/*
 * HWP Stuff
 * 
 * Copyright (C) 2015-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 * 
 * Authors: Kevin Lin
 * 
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License version 2 as published by the
 * Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 * 
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef __HWP_H__
#define __HWP_H__

#include "others.h"

#define HWP5_COMPRESSED     0x1
#define HWP5_PASSWORD       0x2
#define HWP5_DISTRIBUTABLE  0x4
#define HWP5_SCRIPT         0x8
#define HWP5_DRM            0x10
#define HWP5_XMLTEMPLATE    0x20
#define HWP5_HISTORY        0x40
#define HWP5_CERT_SIGNED    0x80
#define HWP5_CERT_ENCRYPTED 0x100
#define HWP5_CERT_EXTRA     0x200
#define HWP5_CERT_DRM       0x400
#define HWP5_CCL            0x800

typedef struct hwp5_header {
    uint8_t signature[32];
    uint32_t version;
    uint32_t flags;
    /* uint8_t reserved[216] */
} hwp5_header_t;

/* HWP EMBEDDED OLE2 - 4-byte prefixed OLE2 */
int cli_scanhwpole2(cli_ctx *ctx);

/* HWP 5.0 - OLE2 */
int cli_hwp5header(cli_ctx *ctx, hwp5_header_t *hwp5);
int cli_scanhwp5_stream(cli_ctx *ctx, hwp5_header_t *hwp5, char *name, int fd, const char *filepath);

/* HWP 3.0 - UNIQUE FORMAT */
int cli_scanhwp3(cli_ctx *ctx);

/* HWPML - SINGLE XML DOCUMENT (similar to MSXML) */
int cli_scanhwpml(cli_ctx *ctx);

#endif /* __HWP_H__ */

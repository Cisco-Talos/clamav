/*
 *  Copyright (C) 2013-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm <tkojm@clamav.net>
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

#ifndef __CPIO_H
#define __CPIO_H

#include "clamav.h"
#include "others.h"

cl_error_t cli_scancpio_old(cli_ctx *ctx);
cl_error_t cli_scancpio_odc(cli_ctx *ctx);
cl_error_t cli_scancpio_newc(cli_ctx *ctx, int crc);

#endif

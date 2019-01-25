/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
 *
 *  Authors: aCaB <acab@clamav.net>
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

#ifndef __W32_ERRNO_H
#define __W32_ERRNO_H

#include <errno.h>
// Make sure ETIMEDOUT matches with pthread's notion of ETIMEDOUT,
// otherwise we get a mismatch (10060 vs 1110)
#include <pthread.h>
#include "w32_errno_defs.c"

char *w32_strerror(int errnum);
int w32_strerror_r(int errnum, char *buf, size_t buflen);

#endif
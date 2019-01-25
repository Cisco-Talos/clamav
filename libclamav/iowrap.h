/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2012-2013 Sourcefire, Inc.
 *
 *  Authors: Dave Raynor
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

#ifndef __IOWRAP_H
#define __IOWRAP_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#ifdef _WIN32
#include <windows.h>
#include <excpt.h>
#endif

/*
 * cli_memcpy is an io wrapper that will allow ClamAV to minimize impact of
 * adding SEH logic around map accesses where Windows might raise an error
 */
int cli_memcpy(void *target, const void *source, unsigned long size);

#ifdef _WIN32
int filter_memcpy(unsigned int code, struct _EXCEPTION_POINTERS *ep);
#endif

#endif

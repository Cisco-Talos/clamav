/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
 *
 */
#include "clamav.h"
#include "iowrap.h"

#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <excpt.h>
#ifdef __GNUC__
#include <excpt.h>
#endif

#ifndef STATUS_DEVICE_DATA_ERROR
#define STATUS_DEVICE_DATA_ERROR 0xC000009C
#endif
#endif

#ifdef _WIN32
int filter_memcpy(unsigned int code, struct _EXCEPTION_POINTERS *ep)
{
    if ((code == EXCEPTION_IN_PAGE_ERROR) || (code == STATUS_DEVICE_DATA_ERROR)) {
        return EXCEPTION_EXECUTE_HANDLER;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
#endif

cl_error_t cli_memcpy(void *target, const void *source, unsigned long size)
{
    cl_error_t ret = CL_SUCCESS;

#ifdef _WIN32
#if defined(__GNUC__) && !defined(__x86_64__) && !defined(_M_X64)  /* MinGW 32-bit only */
    /* MinGW uses __try1/__except1 for SEH */
    __try1(filter_memcpy) {
        memcpy(target, source, size);
    } __except1 {
        ret = CL_EACCES;
    }
#elif defined(_MSC_VER)  /* MSVC */
    __try {
        memcpy(target, source, size);
    } __except (filter_memcpy(GetExceptionCode(), GetExceptionInformation())) {
        ret = CL_EACCES;
    }
#else  /* MinGW 64-bit or other */
    memcpy(target, source, size);
#endif
#else
    memcpy(target, source, size);
#endif
    return ret;
}

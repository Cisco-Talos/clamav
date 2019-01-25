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
 *
 */

#include "iowrap.h"

#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <excpt.h>

#ifndef STATUS_DEVICE_DATA_ERROR
#define STATUS_DEVICE_DATA_ERROR 0xC000009C
#endif
#endif

#ifdef _WIN32
int filter_memcpy(unsigned int code, struct _EXCEPTION_POINTERS *ep) {
    if ((code == EXCEPTION_IN_PAGE_ERROR) || (code == STATUS_DEVICE_DATA_ERROR)) {
        return EXCEPTION_EXECUTE_HANDLER;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
#endif

int cli_memcpy(void *target, const void *source, unsigned long size)
{
    int ret = 0;

#ifdef _WIN32
    __try {
#endif
    memcpy(target, source, size);
#ifdef _WIN32
    }
    __except (filter_memcpy(GetExceptionCode(), GetExceptionInformation())) {
        ret = 1;
    }
#endif
    return ret;
}


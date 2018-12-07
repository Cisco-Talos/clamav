/*
 *  Copyright (C) 2015-2018 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2008 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm, Micah Snyder
 *
 *  Nota bene: This file was constructed specifically for native Windows builds.
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

#ifndef __CLAMAV_TYPES_H
#define __CLAMAV_TYPES_H

/* <inttypes.h> was added in VS2013, but will
 * continue to use <stdint.h> for now. */
#include <stdint.h>

/* Ensure we have print format types */
/* PRIu64 should be in <inttypes.h> */
#ifndef _SF64_PREFIX
    #define _SF64_PREFIX "ll"
#endif

#ifndef PRIu64
    #define PRIu64 _SF64_PREFIX "u"
#endif
#ifndef PRIx64
    #define PRIx64 _SF64_PREFIX "i"
#endif
#ifndef PRIi64
    #define PRIi64 _SF64_PREFIX "x"
#endif

#ifndef STDu64
    #define STDu64 "%" PRIu64
    #define STDi64 "%" PRIi64
    #define STDx64 "%" PRIx64
#endif

/* PRIu32 should also be in <inttypes.h> */
#ifndef PRIu32
    #ifndef _SF32_PREFIX
        #define _SF32_PREFIX "l"
    #endif

    #define PRIu32 _SF32_PREFIX "u"
    #define PRIi32 _SF32_PREFIX "i"
    #define PRIx32 _SF32_PREFIX "x"
#endif

#ifndef STDu32
    #define STDu32 "%" PRIu32
    #define STDi32 "%" PRIi32
    #define STDx32 "%" PRIx32
#endif

#ifndef INT32_MAX
    #define INT32_MAX 2147483647
#endif

#endif

/*
 *  Copyright (C) 2007-2008 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm
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

#ifndef __CLTYPES_H
#define __CLTYPES_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifdef HAVE_SYS_INT_TYPES_H
/* First to give it higher priority on Solaris */
#include <sys/int_types.h>
#elif defined(HAVE_INTTYPES_H)
/* C99: inttypes.h should include stdint.h; more universal because some
 * older platforms don't provide stdint.h
 */
#include <inttypes.h>
#elif defined(HAVE_STDINT_H)
#include <stdint.h>
#else
    typedef signed char int8_t;
    typedef unsigned char uint8_t;

#if SIZEOF_INT == 2
    typedef signed int int16_t;
    typedef unsigned int uint16_t;
#elif SIZEOF_SHORT == 2
    typedef signed short int16_t;
    typedef unsigned short uint16_t;
#endif

#if SIZEOF_INT == 4
    typedef signed int int32_t;
    typedef unsigned int uint32_t;
#elif SIZEOF_LONG == 4
    typedef signed long int32_t;
    typedef unsigned long uint32_t;
#endif

#if SIZEOF_LONG == 8
    typedef signed long int64_t;
    typedef unsigned long uint64_t;
#elif SIZEOF_LONG_LONG == 8
    typedef signed long long int64_t;
    typedef unsigned long long uint64_t;
#endif
#endif

/* Ensure we have print format types */
/* PRIu64 should be in <inttypes.h> */
#ifndef PRIu64
#ifndef _SF64_PREFIX
#if SIZEOF_LONG == 8
#define _SF64_PREFIX "l"
#elif SIZEOF_LONG_LONG == 8
#define _SF64_PREFIX "ll"
#endif
#endif

#define PRIu64 _SF64_PREFIX "u"
#define PRIi64 _SF64_PREFIX "i"
#define PRIx64 _SF64_PREFIX "x"
#endif

#ifndef STDu64
#define STDu64 "%" PRIu64
#define STDi64 "%" PRIi64
#define STDx64 "%" PRIx64
#endif

/* PRIu32 should also be in <inttypes.h> */
#ifndef PRIu32
#ifndef _SF32_PREFIX
#if SIZEOF_INT == 4
#define _SF32_PREFIX ""
#elif SIZEOF_LONG == 4
#define _SF32_PREFIX "l"
#endif
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

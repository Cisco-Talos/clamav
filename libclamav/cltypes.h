/*
 *  Copyright (C) 2004 - 2005 Tomasz Kojm <tkojm@clamav.net>
 *
 *  Based on zzip-stdint.h
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

#ifdef HAVE_STDINT_H
#include <stdint.h>
#elif defined HAVE_SYS_INT_TYPES_H /*solaris*/
#include <sys/int_types.h>
#elif defined HAVE_INTTYPES_H /*freebsd*/
#include <inttypes.h>
#else
    typedef unsigned char uint8_t;      typedef signed char int8_t;

# if SIZEOF_INT == 2
    typedef unsigned int uint16_t;      typedef signed int int16_t;
# elif SIZEOF_SHORT == 2
    typedef unsigned short uint16_t;    typedef signed short int16_t;
# else
#   error unable to typedef int16_t from either int or short
    typedef unsigned short uint16_t;    typedef signed short int16_t;
# endif

# if SIZEOF_INT == 4
    typedef unsigned int uint32_t;      typedef signed int int32_t;
# elif SIZEOF_LONG == 4
    typedef unsigned long uint32_t;     typedef signed long int32_t;
# else
#   error unable to typedef int32_t from either int or long
    typedef unsigned long uint32_t;     typedef signed long int32_t;
# endif

# if SIZEOF_LONG == 8
    typedef unsigned long uint64_t;      typedef signed long int64_t;
# elif SIZEOF_LONG_LONG == 8
    typedef unsigned long long uint64_t;     typedef signed long long int64_t;
# else
#   error unable to typedef int64_t from either long or long long
    typedef unsigned long long uint64_t;     typedef signed long long int64_t;
# endif

#endif

#endif

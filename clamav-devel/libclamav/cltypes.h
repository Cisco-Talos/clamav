/*
 *  Copyright (C) 2004 Tomasz Kojm <tkojm@clamav.net>
 *
 *  Based on zzip-stdint.h
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
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
#endif

/*
** Interix Support: Brian A. Reiter <breiter@wolfereiter.com>
** In Interix, <sys/typedef.h> defines int64_t but not uint64_t.
** Interix defines u_int64_t instead.
*/
#if __INTERIX
#ifdef __GNUC__
    typedef unsigned long long 	uint64_t;  
#elif MSC_VER
    typedef unsigned __int64 	uint64_t;
#endif/*__GNUC__*/
#endif /*Interix*/

#endif

/*
 *  Copyright (C) 2007 Sourcefire, Inc.
 *
 *  The unRAR sources may be used in any software to handle RAR
 *  archives without limitations free of charge, but cannot be used
 *  to re-create the RAR compression algorithm, which is proprietary.
 *  Distribution of modified unRAR sources in separate form or as a
 *  part of other software is permitted, provided that it is clearly
 *  stated in the documentation and source comments that the code may
 *  not be used to develop a RAR (WinRAR) compatible archiver.
 */

#ifndef __UNRARHLP_H
#define __UNRARHLP_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#elif defined HAVE_SYS_INT_TYPES_H
#include <sys/int_types.h>
#elif defined HAVE_INTTYPES_H
#include <inttypes.h>
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

void *rar_malloc(size_t size);
void *rar_realloc2(void *ptr, size_t size);

#endif /* __UNRARHLP_H */

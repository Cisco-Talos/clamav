/*
 * This file is a part of the zlib compression module for NSIS.
 * 
 * Copyright and license information can be found below.
 * Modifications Copyright (C) 1999-2007 Nullsoft and Contributors
 * 
 * The original zlib source code is available at
 * http://www.zlib.net/
 * 
 * This software is provided 'as-is', without any express or implied
 * warranty.
 */

/* zutil.h -- internal interface and configuration of the compression library
 * Copyright (C) 1995-1998 Jean-loup Gailly.
 * For conditions of distribution and use, see copyright notice in COPYING.nsis.
 */

/* WARNING: this file should *not* be used by applications. It is
   part of the implementation of the compression library and is
   subject to change. Applications should only use zlib.h.
 */

/* @(#) $Id: ZUTIL.H,v 1.6 2007/01/25 18:07:40 kichik Exp $ */

#ifndef _Z_UTIL_H
#define _Z_UTIL_H

#include "nsis_zlib.h"

#ifndef local
#  define local static
#endif

typedef unsigned char  uch;
typedef uch FAR uchf;
typedef unsigned short ush;
typedef ush FAR ushf;
typedef unsigned long  ulg;

#ifndef DEF_WBITS
#  define DEF_WBITS MAX_WBITS
#endif
/* default windowBits for decompression. MAX_WBITS is for compression only */

#define DEF_MEM_LEVEL  MAX_MEM_LEVEL

#define STORED_BLOCK 0
#define STATIC_TREES 1
#define DYN_TREES    2
/* The three kinds of block type */

#define MIN_MATCH  3
#define MAX_MATCH  258
/* The minimum and maximum match lengths */

#define PRESET_DICT 0x20 /* preset dictionary flag in zlib header */


#define zmemcpy memcpy

#define Assert(cond,msg)
#define Trace(x)
#define Tracev(x)
#define Tracevv(x)
#define Tracec(c,x)
#define Tracecv(c,x)

#define ZALLOC(strm, items, size) malloc((items)*(size))
#define ZFREE(strm, addr)  { if (addr) free(addr); }
#define TRY_FREE(s, p) { ZFREE(s, p); }
#define ERR_RETURN(strm,err) return (err)

#endif /* _Z_UTIL_H */

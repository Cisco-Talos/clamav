/*
 *  Copyright (C) 2021-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2006-2008 Gianluigi Tiesi <sherpya@netfarm.it>
 *
 *  Authors: Gianluigi Tiesi
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

#ifndef _EXESCANNER_H_
#define _EXESCANNER_H_

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#ifdef EXESCANNER_STANDALONE
#define DUMP_SIGNATURE
#include <windows.h>
#define logg printf
#define elogg printf
typedef unsigned __int8 uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
typedef __int16 int16_t;
#else
#include "output.h"
#include <others.h>
static inline void elogg(const char *fmt, ...){};
#endif /* EXESCANNER_STANDALONE */

#define ENTROPY_THRESHOLD 4.0
#define EP_SIGNATURE_SIZE 16

#ifndef IMAGE_DOS_SIGNATURE
#define IMAGE_DOS_SIGNATURE 0x5A4D /* MZ */
#endif

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

typedef struct _sigs_t {
    int16_t sig[16];
    const char *name;
    double score;
} sigs_t;

extern int is_packed(const char *filename);

static const char screv[] =
    {
        0x65, 0x78, 0x65, 0x53, 0x63, 0x61, 0x6e, 0x6e,
        0x65, 0x72, 0x7c, 0x47, 0x50, 0x4c, 0x7c, 0x47,
        0x69, 0x61, 0x6e, 0x6c, 0x75, 0x69, 0x67, 0x69,
        0x20, 0x54, 0x69, 0x65, 0x73, 0x69, 0x7c, 0x3c,
        0x73, 0x68, 0x65, 0x72, 0x70, 0x79, 0x61, 0x40,
        0x6e, 0x65, 0x74, 0x66, 0x61, 0x72, 0x6d, 0x2e,
        0x69, 0x74, 0x3e};

#endif /* _EXESCANNER_H_ */

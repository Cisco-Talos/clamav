/*
 *  Copyright (C) 2013-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Michal 'GiM' Spadlinski
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

#ifndef __MEW_H
#define __MEW_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "clamav-types.h"

struct lzmastate {
    const char *p0;
    uint32_t p1, p2;
};

int mew_lzma(char *, const char *, uint32_t, uint32_t, uint32_t);

uint32_t lzma_upack_esi_00(struct lzmastate *, char *, char *, uint32_t);
uint32_t lzma_upack_esi_50(struct lzmastate *, uint32_t, uint32_t, char **, char *, uint32_t *, char *, uint32_t);
uint32_t lzma_upack_esi_54(struct lzmastate *, uint32_t, uint32_t *, char **, uint32_t *, char *, uint32_t);
int unmew11(char *, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, int, int);

#endif

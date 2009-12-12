/*
 *  ClamAV bytecode internal API
 *
 *  Copyright (C) 2009 Sourcefire, Inc.
 *
 *  Authors: Török Edvin
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
#ifndef TYPE_DESC_H
#define TYPE_DESC_H

#include "clambc.h"
struct cli_bc_ctx;

enum derived_t {
  DFunctionType,
  DPointerType,
  DStructType,
  DPackedStructType,
  DArrayType
};

struct cli_bc_type {
    enum derived_t kind;
    uint16_t *containedTypes;
    unsigned numElements;
    uint32_t size;
    unsigned align;
};

typedef uint32_t (*cli_apicall_int2)(struct cli_bc_ctx *, uint32_t, uint32_t);
typedef uint32_t (*cli_apicall_pointer)(struct cli_bc_ctx *, void*, uint32_t);

struct cli_apicall {
    const char *name;
    uint16_t type;/* type id in cli_apicall_types array */
    uint16_t idx;
    uint8_t kind;
};

struct cli_apiglobal {
    const char *name;
    enum bc_global globalid;
    uint16_t type;
    unsigned offset;
};

#ifdef __cplusplus
extern "C" {
#endif
extern const struct cli_bc_type cli_apicall_types[];
extern const unsigned cli_apicall_maxtypes;

extern const struct cli_apiglobal cli_globals[];

extern const struct cli_apicall cli_apicalls[];
extern const cli_apicall_int2 cli_apicalls0[];
extern const cli_apicall_pointer cli_apicalls1[];
extern const unsigned cli_apicall_maxapi;
extern const unsigned cli_apicall_maxglobal;

#ifdef __cplusplus
}
#endif
#endif

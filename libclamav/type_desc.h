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

enum derived_t {
  FunctionType,
  PointerType,
  StructType,
  PackedStructType,
  ArrayType
};

struct cli_bc_type {
    enum derived_t kind;
    uint16_t *containedTypes;
    unsigned numElements;
};

typedef int32_t (*cli_apicall_int2)(int32_t, int32_t);
typedef int32_t (*cli_apicall_pointer)(void*, uint32_t);

struct cli_apicall {
    const char *name;
    uint16_t type;/* type id in cli_apicall_types array */
    uint16_t idx;
    uint8_t kind;
};

extern const struct cli_bc_type cli_apicall_types[];
extern const unsigned cli_apicall_maxtypes;

extern const struct cli_apicall cli_apicalls[];
extern const cli_apicall_int2 cli_apicalls0[];
extern const cli_apicall_pointer cli_apicalls1[];
extern const unsigned cli_apicall_maxapi;
#endif

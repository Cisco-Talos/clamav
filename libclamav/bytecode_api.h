/*
 *  ClamAV bytecode API.
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
#ifndef BYTECODE_API_H
#define BYTECODE_API_H

#ifdef __CLAMBC__
#include "bytecode_execs.h"
#endif

#ifndef __CLAMBC__
#include "execs.h"
#endif

struct foo {
    struct foo *nxt;
};

enum BytecodeKind {
    BC_GENERIC=0,/* generic bytecode, not tied to a specific hook */
    _BC_START_HOOKS=256,
    BC_LOGICAL=256,/* triggered by a logical signature */
    BC_PE_UNPACKER,/* a PE unpacker */
    _BC_LAST_HOOK
};

#ifdef __CLAMBC__

extern const uint32_t __clambc_match_counts[64];
extern const struct cli_exe_info __clambc_exeinfo;

const uint8_t __clambc_kind;

uint32_t test0(struct foo*, uint32_t);
uint32_t test1(uint32_t, uint32_t);

/* reads @size bytes from current file (if any) to @data, returns amount read */
int32_t read(uint8_t *data, int32_t size);

enum {
    SEEK_SET=0,
    SEEK_CUR,
    SEEK_END
};

/* seeks current position to @pos, from @whence, returns current position from
 * start of file */
int32_t seek(int32_t pos, uint32_t whence);

/* Set the name of the virus we have found */
uint32_t setvirusname(const uint8_t *name, uint32_t len);

uint32_t debug_print_str(const uint8_t *str, uint32_t len);
uint32_t debug_print_uint(uint32_t a, uint32_t b);
//const char *LogicalSignature;

#endif
#endif

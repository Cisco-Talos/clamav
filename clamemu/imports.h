/*
 *  ClamAV bytecode emulator VMM
 *
 *  Copyright (C) 2011 Sourcefire, Inc.
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

#ifndef IMPORTS_H
#define IMPORTS_H
#include "vmm.h"
struct import_desc {
    const char *name;
    unsigned bytes;/* 0 means vararg */
};

struct hook_desc {
    const char *name;
    import_handler_t callback;
};

struct dll_desc {
    const char *dllname;
    const struct import_desc *imports;
    const struct hook_desc *hooks;
    const unsigned* imports_n;
    const unsigned* hooks_n;
};

extern const struct dll_desc all_dlls[];
extern const struct hook_desc user32_dll_hooks[];
extern const struct hook_desc kernel32_dll_hooks[];
extern const struct hook_desc wsock32_dll_hooks[];

extern const unsigned all_dlls_n;
extern const unsigned user32_dll_hooks_n;
extern const unsigned kernel32_dll_hooks_n;
extern const unsigned wsock32_dll_hooks_n;
int hook_generic_stdcall(struct cli_emu *emu, const char *desc, unsigned bytes);
#endif

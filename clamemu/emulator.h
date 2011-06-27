/*
 *  ClamAV PE emulator
 *
 *  Copyright (C) 2010 - 2011, Sourcefire, Inc.
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

#ifndef EMULATOR_H
#define EMULATOR_H
#include "vmm.h"
struct cli_emu;
struct cli_pedata;
typedef struct cli_emu cli_emu_t;
cli_emu_t* cli_emulator_new(emu_vmm_t *v, struct cli_pe_hook_data *pedata);
int cli_emulator_step(cli_emu_t *emu);
void cli_emulator_free(cli_emu_t *emu);
void cli_emulator_dbgstate(cli_emu_t *emu);
int cli_emulator_seh(cli_emu_t *emu, int rc);
void mem_push(cli_emu_t *state, unsigned size, uint32_t value);
void mem_pop(cli_emu_t *state, int size, uint32_t *value);
#define LIBMAPPING (MAPPING_END+0x0f000000)
uint32_t map_dll(const struct dll_desc *dll);
void cli_emu_disasm(cli_emu_t *emu, unsigned count);
#endif

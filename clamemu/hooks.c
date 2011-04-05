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
#include "imports.h"
#include "disasm-common.h"
#include "vmm.h"
#include "emulator.h"
#include "others.h"
#include "flags.h"

#define POP32(val) do { if (mem_pop(emu, 4, (val)) < 0) {cli_dbgmsg("pop failed\n"); return -1; }} while(0)
#define POP16(val) do { if (mem_pop(emu, 2, (val)) < 0) {cli_dbgmsg("pop failed\n"); return -1; }} while(0)
static int cb_messagebox(struct cli_emu *emu, const char *desc, unsigned bytes)
{
    uint32_t utype, lpcaption, lptext, hwnd;
    char *caption;
    char *text;
    POP32(&emu->eip);
    POP32(&utype);
    POP32(&lpcaption);
    POP32(&lptext);
    POP32(&hwnd);

    caption = cli_emu_vmm_read_string(emu->mem, lpcaption, 1024);
    text = cli_emu_vmm_read_string(emu->mem, lptext, 1024);

    cli_dbgmsg("MessageBoxA(%x, caption='%s', text='%s', %d)\n", hwnd,
	   caption, text, utype);

    free(caption);
    free(text);
    return 0;
}

static int cb_gettickcount(struct cli_emu *emu, const char *desc, unsigned bytes)
{
    POP32(&emu->eip);
    emu->reg_val[REG_EAX] = emu->tick++;
    return 0;
}

static int cb_exitprocess(struct cli_emu *emu, const char *desc, unsigned bytes)
{
    uint32_t rc;
    POP32(&emu->eip);
    POP32(&rc);
    cli_dbgmsg("ExitProcess(%x)\n", rc);
    emu->eip = MAPPING_END;
    return 0;
}

const struct hook_desc user32_dll_hooks[] = {
    {"MessageBoxA", cb_messagebox}
};

const struct hook_desc kernel32_dll_hooks[] = {
    {"ExitProcess", cb_exitprocess},
    {"GetTickCount", cb_gettickcount}
};

const struct hook_desc wsock32_dll_hooks[] = {
};
const unsigned user32_dll_hooks_n = sizeof(user32_dll_hooks)/sizeof(user32_dll_hooks[0]);
const unsigned kernel32_dll_hooks_n = sizeof(kernel32_dll_hooks)/sizeof(kernel32_dll_hooks[0]);
const unsigned wsock32_dll_hooks_n = sizeof(wsock32_dll_hooks)/sizeof(wsock32_dll_hooks[0]);

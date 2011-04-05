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

#define POP32(val) mem_pop(emu, 4, (val))
#define POP16(val) mem_pop(emu, 2, (val))
static int cb_messagebox(struct cli_emu *emu, const char *desc, unsigned bytes)
{
    uint32_t utype, lpcaption, lptext, hwnd;
    char *caption;
    char *text;
    POP32(&emu->eip);
    POP32(&hwnd);
    POP32(&lptext);
    POP32(&lpcaption);
    POP32(&utype);

    caption = cli_emu_vmm_read_string(emu->mem, lpcaption, 1024);
    text = cli_emu_vmm_read_string(emu->mem, lptext, 1024);

    printf("MessageBoxA(%x, caption='%s', text='%s', %d)\n", hwnd,
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
    printf("ExitProcess(%x)\n", rc);
    emu->eip = MAPPING_END;
    return 0;
}

#define LIBMAPPING (MAPPING_END+0x0f000000)

static int cb_loadlibrary(struct cli_emu *emu, const char *desc, unsigned bytes)
{
    const struct dll_desc *dll;
    char *filename;
    uint32_t lpfilename;
    POP32(&emu->eip);
    POP32(&lpfilename);

    filename = cli_emu_vmm_read_string(emu->mem, lpfilename, 1024);
    dll = lookup_dll(filename);
    printf("LoadLibrary(%s)\n", filename);
    if (dll) {
	unsigned dll_idx = dll - &all_dlls[0];
	/* a fake handle
	 * TODO: this should be a pointer to the mapped memory of a fake dll */
	emu->reg_val[REG_EAX] = LIBMAPPING + dll_idx * 4;
    }
    free(filename);
    return 0;
}

static int cb_getprocaddress(struct cli_emu *emu, const char *desc, unsigned bytes)
{
    uint32_t called_addr = 0;
    char *procname;
    unsigned dll_idx;
    uint32_t lpprocname, hmodule;
    POP32(&emu->eip);
    POP32(&hmodule);
    POP32(&lpprocname);

    procname = cli_emu_vmm_read_string(emu->mem, lpprocname, 1024);
    printf("GetProcAddress(%x,%s)\n", hmodule, procname);
    if (hmodule >= LIBMAPPING && procname) {
	dll_idx = (hmodule - LIBMAPPING)/4;
	if (dll_idx < all_dlls_n) {
	    const struct dll_desc *dll = &all_dlls[dll_idx];
	    unsigned bytes = 0;
	    import_handler_t hook = lookup_function(dll, procname, &bytes);
	    if (!hook)
		hook = hook_generic_stdcall;
	    if (bytes != ~0u) {
		emu_createimportcall(emu->mem, &called_addr, hook, bytes, "<loadmodule> ", procname);
		emu->reg_val[REG_EAX] = called_addr;
	    }
	}
    }
    printf("->%08x\n", called_addr);

    free(procname);

    return 0;
}

enum {
    PAGE_EXECUTE=0x10,
    PAGE_EXECUTE_READ=0x20,
    PAGE_EXECUTE_READWRITE=0x40,
    PAGE_NOACCESS=0x01,
    PAGE_READONLY=0x02,
    PAGE_READWRITE=0x04,
};

static int cb_virtualprotect(struct cli_emu *emu, const char *desc, unsigned bytes)
{
    uint32_t lpaddress;
    uint32_t size;
    uint32_t newprotect;
    uint32_t lpoldprotect;
    unsigned rwx;
    POP32(&emu->eip);
    POP32(&lpaddress);
    POP32(&size);
    POP32(&newprotect);
    POP32(&lpoldprotect);

    printf("VirtualProtect(%08x, %x, %x, %x)\n", lpaddress, size, newprotect, lpoldprotect);
    rwx = cli_emu_vmm_prot_get(emu->mem, lpaddress);
    switch (rwx) {
	case 0:
	    rwx = PAGE_NOACCESS;
	    break;
	case 1:
	    rwx = PAGE_READONLY;
	    break;
	case 2:
	case 3:
	    rwx = PAGE_READWRITE;
	    break;
	case 4:
	    rwx = PAGE_EXECUTE;
	    break;
	case 5:
	    rwx = PAGE_EXECUTE_READ;
	    break;
	case 6:
	case 7:
	    rwx = PAGE_EXECUTE_READWRITE;
	    break;
    }
    if (!(cli_emu_vmm_prot_get(emu->mem, lpoldprotect) & (1 << flag_w)))
	return 0;
    cli_emu_vmm_write32(emu->mem, lpoldprotect, rwx);

    switch (newprotect) {
	case PAGE_NOACCESS:
	    rwx = 0;
	    break;
	case PAGE_READONLY:
	    rwx = 1 << flag_r;
	    break;
	case PAGE_READWRITE:
	    rwx = (1 << flag_r) | (1 << flag_w);
	    break;
	case PAGE_EXECUTE:
	    rwx = 1 << flag_x;
	    break;
	case PAGE_EXECUTE_READ:
	    rwx = (1 << flag_r) | (1 << flag_x);
	    break;
	case PAGE_EXECUTE_READWRITE:
	    rwx = 7;
	    break;
    }
    cli_emu_vmm_prot_set(emu->mem, lpaddress, size, rwx);
    emu->reg_val[REG_EAX] = 1;
    return 0;
}

static const char *cmdline = "executab.exe";

static int cb_getcommandline(struct cli_emu *emu, const char *desc, unsigned bytes)
{
    uint32_t lpcmdline;
    unsigned n;
    POP32(&emu->eip);
    printf("GetCommandLineA()\n");
    n = strlen(cmdline) + 1;
    cli_emu_vmm_alloc(emu->mem, n, &lpcmdline);
    cli_emu_vmm_write(emu->mem, lpcmdline, cmdline, n);
    emu->reg_val[REG_EAX] = lpcmdline;
    return 0;
}

const struct hook_desc user32_dll_hooks[] = {
    {"MessageBoxA", cb_messagebox}
};

const struct hook_desc kernel32_dll_hooks[] = {
    {"ExitProcess", cb_exitprocess},
    {"GetCommandLineA", cb_getcommandline},
    {"GetProcAddress", cb_getprocaddress},
    {"GetTickCount", cb_gettickcount},
    {"LoadLibraryA", cb_loadlibrary},
    {"VirtualProtect", cb_virtualprotect}
};

const struct hook_desc wsock32_dll_hooks[] = {
};
const unsigned user32_dll_hooks_n = sizeof(user32_dll_hooks)/sizeof(user32_dll_hooks[0]);
const unsigned kernel32_dll_hooks_n = sizeof(kernel32_dll_hooks)/sizeof(kernel32_dll_hooks[0]);
const unsigned wsock32_dll_hooks_n = sizeof(wsock32_dll_hooks)/sizeof(wsock32_dll_hooks[0]);

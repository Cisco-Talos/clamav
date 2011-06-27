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
    printf("ExitProcess(%x)\n", rc);
    cli_dbgmsg("ExitProcess(%x)\n", rc);
    emu->eip = MAPPING_END - 0x42;
    return 0;
}


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
    cli_dbgmsg("LoadLibrary(%s)\n", filename);
    if (dll) {
	emu->reg_val[REG_EAX] = map_dll(dll);
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
    cli_dbgmsg("GetProcAddress(%x,%s)\n", hmodule, procname);
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
    cli_dbgmsg("->%08x\n", called_addr);

    free(procname);

    return 0;
}

enum {
    EMU_PAGE_EXECUTE=0x10,
    EMU_PAGE_EXECUTE_READ=0x20,
    EMU_PAGE_EXECUTE_READWRITE=0x40,
    EMU_PAGE_NOACCESS=0x01,
    EMU_PAGE_READONLY=0x02,
    EMU_PAGE_READWRITE=0x04,
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
    cli_dbgmsg("VirtualProtect(%08x, %x, %x, %x)\n", lpaddress, size, newprotect, lpoldprotect);
    rwx = cli_emu_vmm_prot_get(emu->mem, lpaddress);
    switch (rwx) {
	case 0:
	    rwx = EMU_PAGE_NOACCESS;
	    break;
	case 1:
	    rwx = EMU_PAGE_READONLY;
	    break;
	case 2:
	case 3:
	    rwx = EMU_PAGE_READWRITE;
	    break;
	case 4:
	    rwx = EMU_PAGE_EXECUTE;
	    break;
	case 5:
	    rwx = EMU_PAGE_EXECUTE_READ;
	    break;
	case 6:
	case 7:
	    rwx = EMU_PAGE_EXECUTE_READWRITE;
	    break;
    }
    if (!(cli_emu_vmm_prot_get(emu->mem, lpoldprotect) & (1 << flag_w)))
	return 0;
    cli_emu_vmm_write32(emu->mem, lpoldprotect, rwx);

    switch (newprotect) {
	case EMU_PAGE_NOACCESS:
	    rwx = 0;
	    break;
	case EMU_PAGE_READONLY:
	    rwx = 1 << flag_r;
	    break;
	case EMU_PAGE_READWRITE:
	    rwx = (1 << flag_r) | (1 << flag_w);
	    break;
	case EMU_PAGE_EXECUTE:
	    rwx = 1 << flag_x;
	    break;
	case EMU_PAGE_EXECUTE_READ:
	    rwx = (1 << flag_r) | (1 << flag_x);
	    break;
	case EMU_PAGE_EXECUTE_READWRITE:
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
    cli_dbgmsg("GetCommandLineA()\n");
    n = strlen(cmdline) + 1;
    cli_emu_vmm_alloc(emu->mem, n, &lpcmdline);
    cli_emu_vmm_write(emu->mem, lpcmdline, cmdline, n);
    emu->reg_val[REG_EAX] = lpcmdline;
    return 0;
}

static int cb_getmodulefilename(struct cli_emu *emu, const char *desc, unsigned bytes)
{
    uint32_t hmodule, lpfilename, nsize;
    POP32(&emu->eip);
    POP32(&hmodule);
    POP32(&lpfilename);
    POP32(&nsize);

    printf("GetModuleFileName(%x, %x, %d)\n", hmodule, lpfilename, nsize);
    cli_dbgmsg("GetModuleFileName(%x, %x, %d)\n", hmodule, lpfilename, nsize);
    if (hmodule)
	return 0;/* not emulated yet */
    if (strlen(cmdline) + 1 < nsize)
	nsize = strlen(cmdline) + 1;

    cli_emu_vmm_write(emu->mem, lpfilename, cmdline, nsize);
    emu->reg_val[REG_EAX] = nsize;

    return 0;
}

#define HANDLE_SELF 0x41

static int cb_createfile(struct cli_emu *emu, const char *desc, unsigned bytes)
{
    uint32_t lpfilename, dwdesiredaccess, dwsharemode, lpsecurityattributes,
	     dwcreationdisposition, dwflagsandattributes, htemplatefile;
    char *filename;
    POP32(&emu->eip);
    POP32(&lpfilename);
    POP32(&dwdesiredaccess);
    POP32(&dwsharemode);
    POP32(&lpsecurityattributes);
    POP32(&dwcreationdisposition);
    POP32(&dwflagsandattributes);
    POP32(&htemplatefile);

    filename =  cli_emu_vmm_read_string(emu->mem, lpfilename, 1024);
    printf("CreateFileA(%s, %x, %x, %x, %x, %x, %x)\n",
	   filename, dwdesiredaccess, dwsharemode, lpsecurityattributes,
	   dwcreationdisposition, dwflagsandattributes, htemplatefile);
    cli_dbgmsg("CreateFileA(%s, %x, %x, %x, %x, %x, %x)\n",
	   filename, dwdesiredaccess, dwsharemode, lpsecurityattributes,
	   dwcreationdisposition, dwflagsandattributes, htemplatefile);
    /* TODO: only opening self is supported for now */
    if (!strcmp(filename, cmdline)) {
	emu->reg_val[REG_EAX] = HANDLE_SELF;
    } else {
	emu->reg_val[REG_EAX] = -1;
    }
    free(filename);
    return 0;
}

static int cb_getfilesize(struct cli_emu *emu, const char *desc, unsigned bytes)
{
    uint32_t hfile, lpfilesizehigh;
    POP32(&emu->eip);
    POP32(&hfile);
    POP32(&lpfilesizehigh);

    printf("GetFileSize(%x, %x)\n", hfile, lpfilesizehigh);
    cli_dbgmsg("GetFileSize(%x, %x)\n", hfile, lpfilesizehigh);
    if (hfile == HANDLE_SELF) {
	emu->reg_val[REG_EAX] = emu->mem->filesize;
	if (lpfilesizehigh)
	    cli_emu_vmm_write32(emu->mem, lpfilesizehigh, 0);
    } else {
	emu->reg_val[REG_EAX] = -1;
    }
    return 0;
}

static int cb_globalalloc(struct cli_emu *emu, const char *desc, unsigned bytes)
{
    uint32_t uflags, dwbytes, addr;
    POP32(&emu->eip);
    POP32(&uflags);
    POP32(&dwbytes);

    printf("GlobalAlloc(%x, %d)\n", uflags, dwbytes);
    cli_dbgmsg("GlobalAlloc(%x, %d)\n", uflags, dwbytes);
    cli_emu_vmm_alloc(emu->mem, dwbytes, &addr);
    emu->reg_val[REG_EAX] = addr;
    return 0;
}

static uint32_t read_offset = 0; /* TODO: all these hooks need a context! */

static int cb_readfile(struct cli_emu *emu, const char *desc, unsigned bytes)
{
    uint32_t hfile, lpbuffer, numberofbytestoread, lpnumberofbytesread, lpoverlapped;
	int32_t n;

    POP32(&emu->eip);
    POP32(&hfile);
    POP32(&lpbuffer);
    POP32(&numberofbytestoread);
    POP32(&lpnumberofbytesread);
    POP32(&lpoverlapped);

    printf("ReadFile(%x, %x, %d, %x, %x)\n",
	   hfile, lpbuffer, numberofbytestoread, lpnumberofbytesread, lpoverlapped);
    cli_dbgmsg("ReadFile(%x, %x, %d, %x, %x)\n",
	   hfile, lpbuffer, numberofbytestoread, lpnumberofbytesread, lpoverlapped);

    if (hfile == HANDLE_SELF) {
	char *data = cli_malloc(numberofbytestoread);
	if (!data)
	    return -1;
	n = pread(emu->mem->infd, data, numberofbytestoread, read_offset);
	if (n < 0) {
	    free(data);
	    return 0;
	}
	cli_emu_vmm_write32(emu->mem, lpnumberofbytesread, n);
	cli_emu_vmm_write(emu->mem, lpbuffer, data, n);
	free(data);
	emu->reg_val[REG_EAX] = 1;
    } else {
	/* TODO: support other files */
    }
    return 0;
}

const struct hook_desc advapi32_dll_hooks[] = {
	{NULL, NULL}
};

const struct hook_desc comctl32_dll_hooks[] = {
		{NULL, NULL}
};

const struct hook_desc comdlg32_dll_hooks[] = {
		{NULL, NULL}
};

const struct hook_desc gdi32_dll_hooks[] = {
		{NULL, NULL}
};

const struct hook_desc kernel32_dll_hooks[] = {
    {"CreateFileA", cb_createfile},
    {"ExitProcess", cb_exitprocess},
    {"GetCommandLineA", cb_getcommandline},
    {"GetFileSize", cb_getfilesize},
    {"GetModuleFileNameA", cb_getmodulefilename},
    {"GetProcAddress", cb_getprocaddress},
    {"GetTickCount", cb_gettickcount},
    {"GlobalAlloc", cb_globalalloc},
    {"LoadLibraryA", cb_loadlibrary},
    {"ReadFile", cb_readfile},
    {"VirtualProtect", cb_virtualprotect}
};

const struct hook_desc lz32_dll_hooks[] = {
		{NULL, NULL}
};

const struct hook_desc mpr_dll_hooks[] = {
		{NULL, NULL}
};

const struct hook_desc ole32_dll_hooks[] = {
		{NULL, NULL}
};

const struct hook_desc oleaut32_dll_hooks[] = {
		{NULL, NULL}
};

const struct hook_desc rpcrt4_dll_hooks[] = {
		{NULL, NULL}
};

const struct hook_desc shell32_dll_hooks[] = {
		{NULL, NULL}
};

const struct hook_desc user32_dll_hooks[] = {
    {"MessageBoxA", cb_messagebox}
};

const struct hook_desc version_dll_hooks[] = {
		{NULL, NULL}
};

const struct hook_desc winmm_dll_hooks[] = {
		{NULL, NULL}
};

const struct hook_desc wsock32_dll_hooks[] = {
		{NULL, NULL}
};
const unsigned advapi32_dll_hooks_n = sizeof(advapi32_dll_hooks)/sizeof(advapi32_dll_hooks[0]);
const unsigned comctl32_dll_hooks_n = sizeof(comctl32_dll_hooks)/sizeof(comctl32_dll_hooks[0]);
const unsigned comdlg32_dll_hooks_n = sizeof(comdlg32_dll_hooks)/sizeof(comdlg32_dll_hooks[0]);
const unsigned gdi32_dll_hooks_n = sizeof(gdi32_dll_hooks)/sizeof(gdi32_dll_hooks[0]);
const unsigned kernel32_dll_hooks_n = sizeof(kernel32_dll_hooks)/sizeof(kernel32_dll_hooks[0]);
const unsigned lz32_dll_hooks_n = sizeof(lz32_dll_hooks)/sizeof(lz32_dll_hooks[0]);
const unsigned mpr_dll_hooks_n = sizeof(mpr_dll_hooks)/sizeof(mpr_dll_hooks[0]);
const unsigned ole32_dll_hooks_n = sizeof(ole32_dll_hooks)/sizeof(ole32_dll_hooks[0]);
const unsigned oleaut32_dll_hooks_n = sizeof(oleaut32_dll_hooks)/sizeof(oleaut32_dll_hooks[0]);
const unsigned rpcrt4_dll_hooks_n = sizeof(rpcrt4_dll_hooks)/sizeof(rpcrt4_dll_hooks[0]);
const unsigned shell32_dll_hooks_n = sizeof(shell32_dll_hooks)/sizeof(shell32_dll_hooks[0]);
const unsigned user32_dll_hooks_n = sizeof(user32_dll_hooks)/sizeof(user32_dll_hooks[0]);
const unsigned version_dll_hooks_n = sizeof(version_dll_hooks)/sizeof(version_dll_hooks[0]);
const unsigned winmm_dll_hooks_n = sizeof(winmm_dll_hooks)/sizeof(winmm_dll_hooks[0]);
const unsigned wsock32_dll_hooks_n = sizeof(wsock32_dll_hooks)/sizeof(wsock32_dll_hooks[0]);

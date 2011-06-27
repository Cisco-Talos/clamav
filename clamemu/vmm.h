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
#ifndef VMM_H
#define VMM_H

#include "cltypes.h"
#include "others.h"
#include <string.h>
#include <setjmp.h>
#ifdef __GNUC__
#define NORETURN __attribute__((noreturn))
#else
#define NORETURN
#endif

typedef struct {
    unsigned file_offset:23;/* divided by 4k */
    unsigned flag_rwx:3;
    unsigned modified:1;/* 0 - original input file, 1 - stored in temporary file (modified} */
    unsigned init:1;/* 1 - has real data, 0 - zeroinit */
    unsigned cached_page_idx:4;/* 0 - not cached; 1-15 cache idx */
} page_t;

typedef struct {
    uint8_t flag_rwx;
    uint8_t dirty;
    uint16_t reserved0;
    uint32_t pageidx;
    uint8_t data[4096];
} cached_page_t;

struct emu_vmm {
    cached_page_t cached[15];
    unsigned cached_idx;/* idx where we need to read new page (oldest page in LRU) */
    unsigned lastused_page;
    unsigned lastused_page_idx;
    uint32_t imagebase;
    uint32_t ep;
    page_t *page_flags;
    unsigned n_pages;
    unsigned orig_pages;
    unsigned first_free_page;
    char *tempfile;
    int infd;
    int tmpfd;
    uint32_t tmpfd_written;/* in MINALIGN blocks */
    uint32_t imports_n;
    struct import_description *imports;
    jmp_buf* seh_handler;
    uint32_t fs_offset;
    uint32_t except_addr;
    uint32_t filesize;
};

struct cli_exe_section;
struct cli_pe_hook_data;

typedef struct emu_vmm emu_vmm_t;

enum {
    flag_r=0,
    flag_w,
    flag_x
};

enum {
    EMU_ERR_GENERIC=1,
    EMU_ERR_VMM_READ,
    EMU_ERR_VMM_WRITE,
    EMU_ERR_REG,
    EMU_ERR_SIZE,
    EMU_ERR_INT3
};

emu_vmm_t *cli_emu_vmm_new(struct cli_pe_hook_data *pedata, struct cli_exe_section *sections, int fd, jmp_buf *seh_handler);
void cli_emu_vmm_raise(emu_vmm_t *v, int err, uint32_t addr) NORETURN;
cached_page_t *cli_emu_vmm_cache_2page(emu_vmm_t *v, uint32_t va);

static always_inline cached_page_t *vmm_cache_2page(emu_vmm_t *v, uint32_t va)
{
    uint32_t page = (va - v->imagebase)/ 4096;

    if (LIKELY(v->lastused_page == page))
	return &v->cached[v->lastused_page_idx];
    return cli_emu_vmm_cache_2page(v, va);
}

static always_inline void vmm_read(emu_vmm_t *v, uint32_t va, void *value, uint32_t len, uint8_t flags)
{
	cached_page_t *p;
    if (len >= 4096) {
	cli_warnmsg("unexpected read size");
	cli_emu_vmm_raise(v, -EMU_ERR_GENERIC, va);
    }
    /* caches at least 2 pages, so when we read an int32 that crosess page
     * boundary, we can do it fast */
    p = vmm_cache_2page(v, va);
    if (LIKELY(p && (p->flag_rwx & flags))) {
	uint8_t *data = p->data + (va & 0xfff);
	memcpy(value, data, len);
    } else
	cli_emu_vmm_raise(v, -EMU_ERR_VMM_READ, va);
}

static always_inline void cli_emu_vmm_read8(emu_vmm_t *v, uint32_t va, uint32_t *value)
{
    uint8_t a;
    vmm_read(v, va, &a, 1, 1 << flag_r);
    *value = a;
}

static always_inline void cli_emu_vmm_read16(emu_vmm_t *v, uint32_t va, uint32_t *value)
{
    uint16_t a;
    vmm_read(v, va, &a, 2, 1 << flag_r);
    *value = le16_to_host(a);
}

static always_inline void cli_emu_vmm_read32(emu_vmm_t *v, uint32_t va, uint32_t *value)
{
    uint32_t a;
    vmm_read(v, va, &a, 4, 1 << flag_r);
    *value = le32_to_host(a);
}

static always_inline void cli_emu_vmm_read_r(emu_vmm_t *v, uint32_t va, void *value, uint32_t len)
{
   vmm_read(v, va, value, len, 1 << flag_r);
}

void cli_emu_vmm_read_x(emu_vmm_t *v, uint32_t va, void *value, uint32_t len);
char* cli_emu_vmm_read_string(emu_vmm_t *v, uint32_t va, uint32_t maxlen);

static always_inline void cli_emu_vmm_write1(emu_vmm_t *v, uint32_t va, const void *value, uint32_t len)
{
    /* caches at least 2 pages, so when we read an int32 that crosess page
     * boundary, we can do it fast */
    cached_page_t *p = vmm_cache_2page(v, va);
    if (LIKELY(p && (p->flag_rwx & (1 << flag_w)))) {
	uint8_t *data = p->data + (va & 0xfff);
	memcpy(data, value, len);
	p->dirty = 1;
    } else
	cli_emu_vmm_raise(v, -EMU_ERR_VMM_WRITE, va);
}

static always_inline void cli_emu_vmm_write(emu_vmm_t *v, uint32_t va, const void *value, uint32_t len)
{
    const char *val = value;
    while (len >= 4096) {
	cli_emu_vmm_write1(v, va, val, 4096);
	len -= 4096;
	va += 4096;
	val += 4096;
    }
    cli_emu_vmm_write1(v, va, val, len);
}

static always_inline void cli_emu_vmm_write8(emu_vmm_t *v, uint32_t va, uint32_t value)
{
    uint8_t a = value;
    cli_emu_vmm_write1(v, va, &a, 1);
}

static always_inline void cli_emu_vmm_write16(emu_vmm_t *v, uint32_t va, uint32_t value)
{
    uint16_t a = value;
    cli_emu_vmm_write1(v, va, &a, 2);
}

static always_inline void cli_emu_vmm_write32(emu_vmm_t *v, uint32_t va, uint32_t value)
{
    uint32_t a = value;
    cli_emu_vmm_write1(v, va, &a, 4);
}

int cli_emu_vmm_alloc(emu_vmm_t *v, uint32_t amount, uint32_t *va);
int cli_emu_vmm_prot_set(emu_vmm_t *v, uint32_t va, uint32_t len, uint8_t rwx);
int cli_emu_vmm_prot_get(emu_vmm_t *v, uint32_t va);

struct cli_emu;
typedef int (*import_handler_t)(struct cli_emu *, const char *desc, unsigned bytes);
struct import_description {
    import_handler_t handler;
    char *description;
    unsigned bytes;
};

struct import_description *cli_emu_vmm_get_import(const emu_vmm_t *v, uint32_t addr);

uint32_t cli_emu_vmm_rva2va(emu_vmm_t *v, uint32_t rva);
int cli_emu_vmm_rebuild(emu_vmm_t *v);
void cli_emu_vmm_free(emu_vmm_t *v);
const struct dll_desc *lookup_dll(const char *name);
import_handler_t lookup_function(const struct dll_desc *dll, const char *func, unsigned *bytes);
void emu_createimportcall(emu_vmm_t *v, uint32_t *called_addr, import_handler_t hook, unsigned bytes, const char *dll, const char *func);
#define MAPPING_END 0xf0000000
#endif

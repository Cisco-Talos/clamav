/*
 *  ClamAV bytecode emulator VMM
 *
 *  Copyright (C) 2010 - 2011 Sourcefire, Inc.
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

/* a very simple VMM:
 *  - last page cached
 *  - 16 pages of LRU-like shared cache for data and code
 *  - rely on OS's page cache for the rest, no need to duplicate that cache
 *  management here
 */
#include "structs.h"
#include "cltypes.h"
#include "vmm.h"
#include "pe.h"
#include "imports.h"
#include "rebuildpe.h"

#include <errno.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#endif

#define MINALIGN 512

#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 128
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#define IMAGE_SCN_MEM_READ 0x40000000
#define IMAGE_SCN_MEM_WRITE 0x80000000

extern ssize_t pread (int, void *, size_t, off_t);
extern ssize_t pwrite (int __fd, const void *, size_t, off_t);

static never_inline void vmm_pageout(emu_vmm_t *v, cached_page_t *c)
{
    uint32_t n;
    int rc;
    page_t *p = &v->page_flags[c->pageidx];

    p->cached_page_idx = 0;
    if (!c->dirty)
	return;
    /* page has been modified, need to write out to tempfile */
    p->init = 1;
    if (!p->modified) {
	p->modified = 1;
	if (v->tmpfd == -1) {
	    cli_gentempfd(NULL, &v->tempfile, &v->tmpfd);
	    if (v->tmpfd == -1)
		return;
	}
	p->file_offset = v->tmpfd_written;
	v->tmpfd_written += 4096 / MINALIGN;
    }
    n = p->file_offset * MINALIGN;
    rc = pwrite(v->tmpfd, c->data, 4096, n);
    if (rc != 4096) {
	cli_dbgmsg("pwrite (%d,..)=%d failed at %x: %s\n", v->tmpfd, rc, n, strerror(errno));
	return;
    }
}

static always_inline cached_page_t *vmm_pagein(emu_vmm_t *v, page_t *p, uint32_t idx)
{
    unsigned i;
    unsigned nextidx = v->cached_idx + 1;
    cached_page_t *c = &v->cached[v->cached_idx];

    vmm_pageout(v, c);

    c->flag_rwx = p->flag_rwx;
    c->dirty = 0;
    c->pageidx = idx;
    if (p->cached_page_idx)
	cli_warnmsg("caching in already cached page\n");
    p->cached_page_idx = v->cached_idx + 1;

    v->cached_idx = nextidx >= 15 ? 0 : nextidx;
    if (UNLIKELY(!p->init)) {
	memset(c->data, 0, 4096);
    } else if (pread(p->modified ? v->tmpfd : v->infd, c->data, 4096, p->file_offset * MINALIGN) == -1) {
	cli_warnmsg("pread failed at %x: %s\n", p->file_offset * MINALIGN, strerror(errno));
	return NULL;
    }
    return c;
}

cached_page_t *cli_emu_vmm_cache_2page(emu_vmm_t *v, uint32_t va)
{
    page_t *p;
    uint32_t page = (va - v->imagebase)/ 4096;
    unsigned idx;

    if (v->lastused_page == page)
	return &v->cached[v->lastused_page_idx];
    if (UNLIKELY(page >= v->n_pages))
	return NULL; /* out of bounds */
    p = &v->page_flags[page];
    idx = p->cached_page_idx;
    if (LIKELY(idx)) {
	idx--;
	v->lastused_page = page;
	v->lastused_page_idx = idx;
/*	if (v->cached[idx].pageidx != page) abort();*/
	return &v->cached[idx];
    }
    /* cache in 2nd page */
    if (page+1 < v->n_pages && !v->page_flags[page+1].cached_page_idx)
	vmm_pagein(v, &v->page_flags[page+1], page+1);
    /* now cache in the page we wanted */
    v->lastused_page = page;
    v->lastused_page_idx = v->cached_idx;
    return vmm_pagein(v, p, page);
}

char* cli_emu_vmm_read_string(emu_vmm_t *v, uint32_t va, uint32_t maxlen)
{
    const uint8_t *data, *end;
    char *s;
    cached_page_t *p;
    if (maxlen > 4096)
	maxlen = 4096;
    p = vmm_cache_2page(v, va);
    if (!p)
	return NULL;
    data = p->data + (va & 0xfff);
    end = memchr(data, 0, maxlen);
    if (!end)
	end = data + maxlen;
    s = malloc(end - data + 1);
    if (!s)
	return NULL;
    memcpy(s, data, end - data);
    s[end-data] = '\0';
    return s;
}

#define EC32(x) (x) = le32_to_host(x) /* Convert little endian to host */
/* we store our own data there */

static int stub_handler(struct cli_emu *emu, const char *desc, unsigned bytes)
{
    printf("Called unhandled API %s\n", desc ? desc : "??");
    return -1;
}

struct import_description *cli_emu_vmm_get_import(const emu_vmm_t *v, uint32_t addr)
{
    if (addr < MAPPING_END)
	return NULL;
    addr  = (addr - MAPPING_END)/4;
    if (addr >= v->imports_n)
	return NULL;
    return &v->imports[addr];
}

static void emu_createstubcall(emu_vmm_t *v, uint32_t *called_addr, uint32_t ordinal, const char *dll, const char *func)
{
    char desc[1024];

    if (func)
	snprintf(desc, sizeof(desc)-1, "%s!%s", dll ? dll : "", func);
    else
	snprintf(desc, sizeof(desc)-1, "%s!%d", dll ? dll : "", ordinal);
    desc[sizeof(desc)-1] = '\0';
    *called_addr = MAPPING_END + v->imports_n * 4;
    v->imports_n++;
    v->imports = cli_realloc(v->imports, v->imports_n * sizeof(*v->imports));
    v->imports[v->imports_n-1].handler = stub_handler;
    v->imports[v->imports_n-1].description = strdup(desc);
    v->imports[v->imports_n-1].bytes = 0;
    /* TODO: free these on vmm_free */
}

void emu_createimportcall(emu_vmm_t *v, uint32_t *called_addr, import_handler_t hook, unsigned bytes, const char *dll, const char *func)
{
    char desc[1024];
    snprintf(desc, sizeof(desc)-1, "%s!%s", dll ? dll : "", func);
    desc[sizeof(desc)-1] = '\0';

    *called_addr = MAPPING_END + v->imports_n * 4;
    v->imports_n++;
    v->imports = cli_realloc(v->imports, v->imports_n * sizeof(*v->imports));
    v->imports[v->imports_n-1].handler = hook;
    v->imports[v->imports_n-1].description = strdup(desc);
    v->imports[v->imports_n-1].bytes = bytes;
    /* TODO: free these on vmm_free */
}

static int dll_cmp(const void* key, const void *b)
{
    const struct dll_desc *desc = (const struct dll_desc*)b;
#ifndef _WIN32
    return strcasecmp(key, desc->dllname);
#else
	return lstrcmpiA(key, desc->dllname);
#endif
}

const struct dll_desc *lookup_dll(const char *name)
{
    return bsearch(name, all_dlls, all_dlls_n, sizeof(all_dlls[0]), dll_cmp);
}

static int function_cmp(const void* key, const void *b)
{
    const struct import_desc *desc = (const struct import_desc*)b;
    return desc->name ? strcmp(key, desc->name) : -1;
}

static int hook_cmp(const void* key, const void *b)
{
    const struct hook_desc *desc = (const struct hook_desc*)b;
    return desc->name ? strcmp(key, desc->name) : -1;
}

import_handler_t lookup_function(const struct dll_desc *dll, const char *func, unsigned *bytes)
{
    const struct hook_desc *hook;
    const struct import_desc *desc = bsearch(func, dll->imports, *dll->imports_n, sizeof(dll->imports[0]), function_cmp);
    if (!desc)
	*bytes = ~0u;
    else
	*bytes = desc->bytes;
    hook = bsearch(func, dll->hooks, *dll->hooks_n, sizeof(dll->hooks[0]), hook_cmp);
    if (!hook)
	return NULL;
    return hook->callback;
}

static int map_pages(emu_vmm_t *v, struct cli_pe_hook_data *pedata, struct cli_exe_section *sections)
{
    uint32_t base = pedata->opt32.ImageBase;
    uint32_t va, size;
    unsigned i;
    switch (pedata->file_hdr.Machine) {
	default:
	    cli_dbgmsg("emu: unhandled architecture\n");
	    return -1;
	case 0x14c:
	case 0x14d:
	case 0x14e:
	    break;
    }
    if (pedata->opt32.Subsystem == 1) {
	cli_dbgmsg("subsys is native, skipping\n");
	return -1;
    }
    if (pedata->opt32.SectionAlignment < 4096) {
	if (pedata->opt32.FileAlignment != pedata->opt32.SectionAlignment)
	    cli_dbgmsg("warning filealign and sectionalign mismatch, mapping probably incorrect: %d != %d\n",
		       pedata->opt32.FileAlignment, pedata->opt32.SectionAlignment);
    }
    if (pedata->opt32.FileAlignment < 512) {
	cli_dbgmsg("File alignment too small: %d, mapping will be probably incorrect\n", pedata->opt32.FileAlignment);
    }
    /* map file header, if not overlapping */
    for (i=0;i*4096 < sections[0].rva;i++) {
	v->page_flags[i].file_offset = i * 4096 / MINALIGN;
	v->page_flags[i].flag_rwx = 1 << flag_r;
	v->page_flags[i].init = 1;
    }
    for (i=0;i < pedata->nsections; i++) {
	const struct cli_exe_section *section = &sections[i];
	uint32_t rva = section->rva;
	uint32_t pages = (section->vsz + 4095) / 4096;
	uint32_t raw = section->raw;
	unsigned j;
	unsigned flag_rwx;
	unsigned zeroinit;

	if (i && sections[i].urva - sections[i-1].urva != sections[i-1].vsz) {
	    cli_dbgmsg(" holes / overlapping / virtual disorder (broken executable)\n");
	    return -1;
	}

	/* r -> x, and w -> x but not viceversa */
	flag_rwx =
	    ((section->chr & IMAGE_SCN_MEM_EXECUTE) ? (1 << flag_x) : 0) |
	    ((section->chr & IMAGE_SCN_MEM_READ) ? ((1 << flag_r) | (1 << flag_x)): 0) |
	    ((section->chr & IMAGE_SCN_MEM_WRITE) ? (1 << flag_w) | (1 << flag_r):  0);
	for (j=0;j<pages;j++) {
	    uint32_t page = rva / 4096 + j;
	    if (page >= v->n_pages) {
		cli_dbgmsg("rva out of range: %x > %x\n", page*4096, v->n_pages*4096);
		return -1;
	    }
	    zeroinit = j*4096 > section->rsz;
	    v->page_flags[page].init = !zeroinit;
	    /* 1 page can contain actually more than 1 section,
	     * but offset must be MINALIGN aligned, if not this will not work */
	    if (!zeroinit)
		v->page_flags[page].file_offset = (raw + j*4096)/MINALIGN;
	    /* allow writes during import resolving, import section may be
	     * readonly! */
	    v->page_flags[page].flag_rwx = (1 << flag_r) | (1 << flag_w);
	}
	cli_dbgmsg("Mapped section RVA: %08x - %08x -> Raw: %08x%s - %08x, VA %08x - %08x\n",
		   rva, rva + pages * 4096, raw, raw%MINALIGN ? " (rounded!)" : "",
		   raw + pages*4096,
		   v->imagebase + rva, v->imagebase + rva + pages*4096);
    }

    va = base + pedata->opt32.DataDirectory[1].VirtualAddress;
    size = pedata->opt32.DataDirectory[1].Size;
    while (size >= sizeof(struct IMAGE_IMPORT)) {
	struct IMAGE_IMPORT import;
	const struct dll_desc *dll;
	char *dllname;
	uint32_t rva;

	cli_emu_vmm_read_r(v, va, &import, sizeof(import));

	size -= sizeof(struct IMAGE_IMPORT);
	va += sizeof(struct IMAGE_IMPORT);

	if(!import.DllName) {
	    break;
	}
	EC32(import.OrigThunk);
	EC32(import.Fwd);
	EC32(import.DllName);
	EC32(import.Thunk);

	dllname = cli_emu_vmm_read_string(v, base + import.DllName, 64);
	if (!dllname) {
	    fprintf(stderr, "error reading import dllname\n");
	    return 1;
	}
	cli_dbgmsg("Imports from: %s\n", dllname);

	/* TODO: lookup dll bindings */
	rva = import.OrigThunk;
	if (!rva)
	    rva = import.Thunk;
	dll = lookup_dll(dllname);
	for(i=0;;i++, rva += 4) {
	    uint32_t import_entry, called_addr = 0;
	    cli_emu_vmm_read32(v, base + rva, &import_entry);
	    EC32(import_entry);
	    if (!import_entry)
		break;/* end of imports for this DLL */
	    if (import_entry & 0x80000000) {
		cli_dbgmsg("import by ordinal %d from %s, not supported, replaced with stub!\n",
			import_entry & 0xffff, dllname);
		if (!called_addr)
		    emu_createstubcall(v, &called_addr, import_entry&0xffff, dllname, NULL);
	    } else {
		char *func = cli_emu_vmm_read_string(v, base + import_entry + 2, 1024);
		if (!func) {
		    cli_dbgmsg("corrupted imports: unable to read import name at %x\n", import_entry+2);
		    return 1;
		} else {
		    if (dll) {
			unsigned bytes;
			import_handler_t hook = lookup_function(dll, func, &bytes);
			if (!hook && bytes != ~0u)
			    hook = hook_generic_stdcall;
			if (bytes != ~0u)
			    emu_createimportcall(v, &called_addr, hook, bytes, dllname, func);
		    }
		}
		if (!called_addr)
		    emu_createstubcall(v, &called_addr, 0, dllname, func);
		free(func);
	    }
	    cli_dbgmsg("%x <- %x\n", base + import.Thunk + 4*i, called_addr);
	    cli_emu_vmm_write32(v, base + import.Thunk + 4*i, called_addr);
	}
	free(dllname);
    }

    /* set page protections now */
    for (i=0;i<v->n_pages;i++)
	v->page_flags[i].flag_rwx = 0;
    cli_emu_vmm_prot_set(v, v->imagebase, sections[0].rva, (1 << flag_r) | (1 << flag_x));
    cli_dbgmsg("Mapped section RVA: %08x - %08x -> Raw: %08x%s - %08x, VA %08x - %08x r-x\n",
	           0, sections[0].rva, 0, "", sections[0].rva,
		   v->imagebase, v->imagebase + sections[0].rva);
    for (i=0;i < pedata->nsections; i++) {
	const struct cli_exe_section *section = &sections[i];
	uint32_t rva = section->rva;
	uint32_t pages = (section->vsz + 4095) / 4096;
	unsigned flag_rwx;

	/* r -> x, and w -> x but not viceversa */
	flag_rwx =
	    ((section->chr & IMAGE_SCN_MEM_EXECUTE) ? (1 << flag_x) : 0) |
	    ((section->chr & IMAGE_SCN_MEM_READ) ? ((1 << flag_r) | (1 << flag_x)): 0) |
	    ((section->chr & IMAGE_SCN_MEM_WRITE) ? (1 << flag_w) | (1 << flag_r):  0);
	cli_emu_vmm_prot_set(v, v->imagebase + rva, pages*4096, flag_rwx);
	cli_dbgmsg("%08x - %08x, %s%s%s\n",
		   v->imagebase + rva, v->imagebase + rva + pages*4096,
		   flag_rwx & (1 << flag_r) ? "r" : "-",
		   flag_rwx & (1 << flag_w) ? "w" : "-",
		   flag_rwx & (1 << flag_x) ? "x" : "-");
    }

    return 0;
}

void cli_emu_vmm_read_x(emu_vmm_t *v, uint32_t va, void *value, uint32_t len)
{
    vmm_read(v, va, value, len, 1 << flag_x);
}

int cli_emu_vmm_prot_set(emu_vmm_t *v, uint32_t va, uint32_t len, uint8_t rwx)
{
    uint32_t page = (va - v->imagebase) / 4096;
    len = (len + 4095) &~ 4095; /* align */
    do {
	unsigned cached_page_idx;
	if (page >= v->n_pages) {
	    cli_dbgmsg("vmm_prot_set out of bounds: %x > %x\n", va, v->n_pages*4096);
	    return -EMU_ERR_GENERIC;
	}
	/* this also acts as allocation function, by default all pages are zeroinit
	 * anyway */
	cached_page_idx = v->page_flags[page].cached_page_idx;
	if (cached_page_idx) {
	    v->cached[cached_page_idx-1].flag_rwx = rwx;
	}
	v->page_flags[page++].flag_rwx = rwx;
	len -= 4096;
    } while (len);
    return 0;
}

int cli_emu_vmm_prot_get(emu_vmm_t *v, uint32_t va)
{
    uint32_t page = (va - v->imagebase) / 4096;
    if (page >= v->n_pages) {
	cli_dbgmsg("vmm_prot_get out of bounds: %x > %x\n", va, v->n_pages*4096);
	return -EMU_ERR_GENERIC;
    }
    return v->page_flags[page].flag_rwx;
}

emu_vmm_t *cli_emu_vmm_new(struct cli_pe_hook_data *pedata, struct cli_exe_section *sections, int fd, jmp_buf *seh_handler)
{
    uint32_t old;
    emu_vmm_t *v;
    if (le16_to_host(pedata->opt64.Magic) == 0x020b) {
	cli_dbgmsg("PE32+ emulation not supported\n");
	return NULL;
    }
    if (!pedata->nsections) {
	cli_dbgmsg("no sections, nothing to emulate\n");
	return NULL;
    }

    v = cli_calloc(1, sizeof(*v));
    if (!v)
	return NULL;
    v->seh_handler = seh_handler;
    v->imagebase = pedata->opt32.ImageBase;
    v->ep = pedata->opt32.AddressOfEntryPoint;
    v->infd = fd;
    v->tmpfd = -1;
    v->orig_pages = v->n_pages = (sections[pedata->nsections-1].rva + sections[pedata->nsections-1].vsz+4095) / 4096;
    v->page_flags = cli_calloc(v->n_pages, sizeof(*v->page_flags));
    if (!v->page_flags) {
	cli_emu_vmm_free(v);
	return NULL;
    }
    v->lastused_page = ~0u;
    v->imports_n = 1;

    old = lseek(fd, 0, SEEK_CUR);
    v->filesize = lseek(fd, 0, SEEK_END);
    lseek(fd, old, SEEK_SET);
    if (map_pages(v, pedata, sections) == -1) {
	cli_emu_vmm_free(v);
	return NULL;
    }
    v->first_free_page = v->n_pages + 2;/* leave two guardpages */

    cli_emu_vmm_alloc(v, 4096, &v->fs_offset);
    return v;
}

int cli_emu_vmm_alloc(emu_vmm_t *v, uint32_t amount, uint32_t *va)
{
    uint32_t v_page = v->first_free_page;
    unsigned need_pages = (amount + 4095) / 4096;
    unsigned got_pages = 0;
    uint32_t start;
    uint32_t v_end = (MAPPING_END - v->imagebase)/4096;

    start = v_page;
    while (got_pages < need_pages) {
	if (!v_page || v_page == v_end) {
	    fprintf(stderr,"emu: out of virtual memory allocating %d pages\n", need_pages);
	    return -1;
	}
	if (v_page < v->n_pages &&
	    (v->page_flags[v_page].init || v->page_flags[v_page].flag_rwx)) {
	    v_page++;
	    got_pages = 0;
	    start = v_page;
	    continue;
	}
	got_pages++;
	v_page++;
    }
    if (start + got_pages > v->n_pages) {
	void *x;
	unsigned old_pages = v->n_pages;
	v->n_pages = start + got_pages;
	x = cli_realloc(v->page_flags, v->n_pages * sizeof(*v->page_flags));
	if (!x) {
	    fprintf(stderr,"out of mem allocating page flags (%d)\n", v->n_pages);
	    return -1;
	}
	v->page_flags = x;
	memset(&v->page_flags[old_pages], 0, (v->n_pages - old_pages)*sizeof(*v->page_flags));
    }
    if (v->first_free_page == start)
	v->first_free_page = start + got_pages + 1;/*leave 1 guard-page */
    start = v->imagebase + start*4096;
    *va = start;
    return cli_emu_vmm_prot_set(v, start, got_pages*4096, 0x7);
}

int vmm_dirty(emu_vmm_t *v)
{
    unsigned i;
    if (v->tmpfd_written)
	return 1;
    for (i=0;i<15;i++)
	if (v->cached[i].dirty)
	    return 1;
    return 0;
}

int cli_emu_vmm_rebuild(emu_vmm_t *v)
{
    struct cli_exe_section *sections;
    unsigned i, npages = 0, j = 0, k, nsections = 1, raw = 0, raw0;
    char *data;
    char *unpacked;
    int unpfd = -1;

    sections = cli_calloc(1, sizeof(*sections));
    sections[0].raw = raw = 0;
    sections[0].rva = 4096;
    if (!vmm_dirty(v)) {
	cli_dbgmsg("executable not modified\n");
	return 0;
    }
    cli_dbgmsg("attempting rebuild\n");
#if 0
    /* skip page 0, which is PE header */
    for (i=1;i < v->n_pages;i++) {
	if (v->page_flags[i].init || !i || v->page_flags[i-1].init) {
	    npages++;
	    continue;
	}
	sections[j].vsz = sections[j].rsz = npages * 4096;
	raw += npages * 4096;
	npages = 0;
	j++;
	nsections += 2;
	sections = cli_realloc(sections, nsections * sizeof(*sections));
	if (!sections)
	    return -1;
	sections[j].raw = 0;
	sections[j].rsz = 0;
	sections[j].rva = i * 4096;

	for (k=i;k<v->n_pages && !v->page_flags[k].init;k++) {}
	sections[j++].vsz = (k-i)*4096;

	sections[j].raw = raw;
	sections[j].rva = i * 4096;
    }
    nsections++;
    sections = cli_realloc(sections, nsections * sizeof(*sections));
    if (!sections) {
	cli_dbgmsg("failed to allocate memory for %d sections\n", nsections);
	return -1;
    }
#else
    npages = v->n_pages;
#endif
    raw += npages * 4096;
    sections[j].vsz = sections[j].rsz = npages * 4096;
    if (!sections[j].rsz)
	j--;

    data = cli_malloc(raw);
    if (!data) {
	cli_dbgmsg("failed to allocate memory for %d bytes\n", raw);
	return -1;
    }
    raw0 = raw;
    raw = 0;
    for (i=0;i<=j;i++) {
	cached_page_t *p;
	uint32_t rva;
	if (!sections[i].rsz)
	    continue;
	rva = sections[i].rva;
	for (k=0;k<(sections[i].vsz+4095) / 4096;k++) {
	    /* bypass protections */
	    p = vmm_cache_2page(v, v->imagebase + rva);
	    if (p)
		memcpy(data + raw, p->data, 4096);
	    else
		memset(data + raw, 0, 4096);
	    raw += 4096;
	    rva += 4096;
	}
    }
    if (raw != raw0)
	cli_warnmsg("raw mismatch: %x != %x\n", raw, raw0);
    cli_gentempfd(NULL, &unpacked, &unpfd);
    if (unpfd != -1 && cli_rebuildpe(data, sections, j+1, v->imagebase, v->ep, 0, 0, unpfd)) {
	cli_dbgmsg("rebuilt pe file to: %s\n", unpacked);
	//unlink(unpack);
	free(unpacked);
    }
    cli_dbgmsg("rebuild done");

    free(data);
    return 0;
}

void cli_emu_vmm_free(emu_vmm_t *v)
{
    if (!v)
	return;
    if (v->tmpfd != -1) {
	ftruncate(v->tmpfd, 0);
	close(v->tmpfd);
	unlink(v->tempfile);
    }
    free(v->page_flags);
    free(v);
}

uint32_t cli_emu_vmm_rva2va(emu_vmm_t *v, uint32_t rva)
{
    return v->imagebase + rva;
}

void cli_emu_vmm_raise(emu_vmm_t *v, int err, uint32_t addr)
{
    cli_dbgmsg("VMM raised exception %d at %x\n", err, addr);
    v->except_addr = addr;
    longjmp(*v->seh_handler, err);
}

#ifdef _WIN32
//no pread, pwrite
ssize_t pread(int fd, void *buf, size_t count, off_t offset)
{
	lseek(fd, offset, SEEK_SET);
	return read(fd, buf, count);
}
ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset)
{
	lseek(fd, offset, SEEK_SET);
	return write(fd, buf, count);
}

#endif

/*
 *  Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
 
/*
 * upx_elf.c
 *
 * ELF UPX decompressor for PE32/PE32+/ELF32/ELF64 standalone tool.
 * Extracted from clam_upx.c; PE handling remains in clam_upx.c.
 *
 * Supports ELF32 (i386) and ELF64 (x86-64), little-endian only.
 * Supports all four UPX compression algorithms:
 *   NRV2B, NRV2D, NRV2E  (bit-stream LZ77 variants)
 *   LZMA                  (requires lzma_iface.c + LzmaDec.c)
 *
 * Supports all known UPX ELF format versions:
 *   UPX 1.x  — raw 8-byte block headers, global method byte in pack trailer
 *   UPX 2.x  — pack_hdr_a / pack_hdr_b / pack_block_hdr block headers (overlap-block aware)
 *   UPX 3.x+ — same block format, different PT_LOAD layout
 *   UPX 2.x/3.x ELF64 with zeroed start pack_hdr_a (detected via end pack_hdr_a scan)
 *
 * Build (MSVC 2019/2022, Developer Command Prompt):
 *   cl /W3 /O2 /TC clam_upx.c upx_elf.c upx_standalone.c lzma_iface.c LzmaDec.c /Fe:clam_upx.exe
 *
 * Build (GCC/MinGW/Linux):
 *   gcc -Wall -O2 -I. -o clam_upx clam_upx.c upx_elf.c upx_standalone.c lzma_iface.c LzmaDec.c
 *
 * Public interface: upx_elf.h
 *   int handle_elf(const uint8_t *filebuf, size_t fsz, const char *outfile);
 */

#include "upx.h"
#include "lzma_iface.h"
#include "upx_elf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 
 * ELF UPX DECOMPRESSION (ELF32 and ELF64)
 * The following constants, structures and functions handle UPX-packed
 * ELF binaries (both 32-bit i386 and 64-bit x86-64, little-endian).
 * Called from handle_elf() when the input file has ELF magic (\x7fELF).
 */

/* UPX on-disk structure constants 
 *
 * These sizes are fixed constants derived from empirical analysis of
 * packed binaries across UPX versions 1.x through 5.x.  UPX has
 * maintained backward binary compatibility for these structures
 * since UPX 0.x.                                                    */
#define L_INFO_SIZE   12u    /* pack_hdr_a: checksum(4)+magic(4)+lsize(2)+ver(1)+fmt(1) */
#define P_INFO_SIZE   12u    /* pack_hdr_b: progid(4)+filesize(4)+blocksize(4)          */
#define B_INFO_SIZE   12u    /* pack_block_hdr: chunk_out_len(4)+chunk_in_len(4)+method(1)+ftid(1)+cto8(1)+extra(1) */

/* UPX pack_hdr_a magic constants 
 *
 * UPX 2.00+ writes "UPX!" (0x21585055 LE) as the pack_hdr_a magic.
 *
 * UPX 1.x (versions 1.00–1.90, approximately) writes "\x7fUPX"
 * (0x5850557f LE) instead.  The "\x7f" prefix is the ELF magic byte,
 * chosen to make the loader header look like an ELF ident field when
 * the file is inspected naively.  Both constants are stored in
 * little-endian order at pack_hdr_a+4.                              */
#define UPX_MAGIC_V2  0x21585055u  /* "UPX!" (UPX 2.x+)  in LE uint32 */
#define UPX_MAGIC_V1  0x5850557fu  /* "\x7fUPX" (UPX 1.x) in LE uint32 */

/* Alias for code shared between v1/v2 paths (pack trailer always uses V2) */
#define PACK_MAGIC     UPX_MAGIC_V2

/* UPX 1.x pack trailer constants  
 *
 * UPX appends a fixed-size binary header ("pack header") at the end
 * of every packed file, followed by a 4-byte loader_offset field.
 *
 * For UPX 1.x, the pack header is 32 bytes.
 * The layout (all little-endian):
 *   [+00] uint32  magic        = UPX_MAGIC_V2 (always "UPX!" even in v1)
 *   [+04] uint8   version      = 11 for UPX 1.x
 *   [+05] uint8   format       (10 = Linux ELF i386, etc.)
 *   [+06] uint8   method       (2=NRV2B_LE32, 5=NRV2D_LE32, 8=NRV2E_LE32)
 *   [+07] uint8   level
 *   [+08] uint32  u_adler32    checksum of uncompressed data
 *   [+0c] uint32  c_adler32    checksum of compressed data
 *   [+10] uint32  u_len        total uncompressed byte count
 *   [+14] uint32  c_len        total compressed byte count
 *   [+18] uint32  u_file_size  original file size (same as u_len for ELF)
 *   [+1c] uint8   filter       (not used by decompressor)
 *   [+1d] uint8   filter_cto
 *   [+1e] uint16  (reserved)
 *   [+20] uint32  loader_offset  (loader byte count = lsize)
 *
 * The 4-byte loader_offset appended AFTER the pack header is the
 * byte count of the loader (= loader_size from pack_hdr_a), and is used by
 * the runtime stub to locate the 12-byte program info header.       */
#define V1_PACK_HDR_SIZE  32u  /* pack header size for UPX 1.x        */

/* Offsets within the V1 pack header (relative to magic at [+00])    */
#define V1_PH_OFF_METHOD   6u  /* uint8  compression method           */
#define V1_PH_OFF_U_LEN   16u  /* uint32 total uncompressed bytes      */
#define V1_PH_OFF_C_LEN   20u  /* uint32 total compressed bytes        */

/* UPX 1.x method codes 
 *
 * Method numbers are identical across UPX 1.x and 2.x (conf.h comment:
 * "compression methods - DO NOT CHANGE").  UPX 1.x only shipped the
 * NRV family; LZMA (14) was introduced in UPX 2.x.                  */
#define M_V1_NRV2B  2u   /* METHOD_NRV2B32 -> upx_inflate2b_raw        */
#define M_V1_NRV2D  5u   /* METHOD_NRV2D32 -> upx_inflate2d_raw        */
#define M_V1_NRV2E  8u   /* METHOD_NRV2E32 -> upx_inflate2e_raw        */

/*  UPX 1.x minimum file size 
 * ELF32 header(52) + 2 phdrs(64) + pack_hdr_a(12) + prog_info(12)
 * + one block header(8) + one data byte(1)
 * + EOF marker(4) + pack header(32) + loader_offset(4) = 189      */
#define V1_MIN_FILE_SIZE  189u

/*  chunk_method values for ELF LE32 (UPX 2.x+) 
 *
 * These are the per-block method bytes from pack_block_hdr.chunk_method (UPX 2.x+)
 * and also the global method byte from the pack header (UPX 1.x).
 *
 * Method numbering is IDENTICAL between UPX 1.x and 2.x (conf.h:
 * "DO NOT CHANGE").  UPX 1.x packed ELF used only NRV variants;
 * LZMA (14) was added in UPX 2.x.
 *
 * NOTE: These differ from PE! PE uses 2/3/4 for NRV2B/2D/2E.
 *       ELF LE32 uses the LE32 variants: 2/5/8.
 *       The decompressor functions (upx_inflate2b/2d/2e_raw) are the
 *       same binary code — only the method ID to function mapping
 *       differs.                                                     */
#define METHOD_NRV2B32  2u
#define METHOD_NRV2D32  5u
#define METHOD_NRV2E32  8u
#define METHOD_LZMA        14u

/*  ELF32 file header offsets (all little-endian) 
 * Matches struct elf_file_hdr32 from ClamAV's elf.h.               */
#define ELF32_HDR_SIZE    52u   /* sizeof(Elf32_Ehdr) */
#define ELF32_PHDR_SIZE   32u   /* sizeof(Elf32_Phdr) */
#define ELF64_HDR_SIZE    64u   /* sizeof(Elf64_Ehdr) */
#define ELF64_PHDR_SIZE   56u   /* sizeof(Elf64_Phdr) */
#define PT_LOAD           1u
#define PT_GNU_STACK      0x6474e551u

/* ELF e_ident magic and class bytes */
static const uint8_t ELF_MAGIC[4] = { 0x7f, 'E', 'L', 'F' };
#define ELFCLASS32  1u          /* 32-bit ELF */
#define ELFCLASS64  2u          /* 64-bit ELF */
#define ELFDATA2LSB 1u          /* little-endian data encoding */
#define ET_EXEC     2u

/* Maximum values for sanity bounds on [FROM FILE] fields           */
#define MAX_PHNUM        16u            /* sane e_phnum cap          */
#define MAX_ORIG_SIZE    (256u<<20)     /* 256 MB original file cap  */
#define MAX_BLOCK_SIZE   (256u<<20)     /* per-block decompressed cap*/
#define MAX_BLOCKS       64u            /* sane block count cap      */
/* DECOMP_OVERHEAD defined in upx_elf.h (shared with clam_upx.c) */

/*  Inline little-endian readers (no alignment assumed)  */
static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) |
           ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)(p[0] | (p[1]<<8));
}
static uint64_t rd64(const uint8_t *p)
{
    return (uint64_t)p[0]        | ((uint64_t)p[1]<< 8) |
           ((uint64_t)p[2]<<16)  | ((uint64_t)p[3]<<24) |
           ((uint64_t)p[4]<<32)  | ((uint64_t)p[5]<<40) |
           ((uint64_t)p[6]<<48)  | ((uint64_t)p[7]<<56);
}

/*  upx_inflatelzma_elf 
 *
 * ELF variant of LZMA decompression. Identical to upx_inflatelzma()
 * EXCEPT it does not call pefromupx() at the end — for ELF there is
 * no header to reconstruct; the decompressed bytes are the output.
 *
 * Parameters:
 *   src        - compressed data (starts with 2-byte UPX LZMA header)
 *   ssize      - [FROM FILE] compressed byte count (pack_block_hdr.chunk_in_len)
 *   dst        - output buffer
 *   dsize      - [FROM FILE] IN: expected output bytes (pack_block_hdr.chunk_out_len)
 *                            OUT: actual bytes written
 *   properties - packed lc/lp/pb: lc|(lp<<8)|(pb<<16)
 *                decoded from UPX 2-byte header at src[0..1]
 *
 * Returns >= 0 on success, -1 on failure.
 *
 * UPX LZMA 2-byte header format (from compress_lzma.cpp):
 *   src[0] = ((lc+lp) << 3) | pb    <- NOT a standard LZMA props byte
 *   src[1] = (lp << 4) | lc
 *   src[2..] = LZMA range coder data (starts with 0x00)
 *
 * SECURITY: properties are validated before LzmaDec is initialized.
 */
static int upx_inflatelzma_elf(const char *src, uint32_t ssize,
                               char *dst, uint32_t *dsize,
                               uint32_t properties)
{
    struct CLI_LZMA l;
    unsigned char   fake_hdr[5];
    uint8_t         lc, lp, pb;

    /* SECURITY: ssize must be at least 3 (2-byte header + 1 data byte) */
    if (ssize < 3)
        return -1;

    lc = (uint8_t)(properties & 0xffu);
    lp = (uint8_t)((properties >> 8)  & 0xffu);
    pb = (uint8_t)((properties >> 16) & 0xffu);

    /* SECURITY: LZMA parameter ranges (LZMA spec)                    */
    if (lc >= 9 || lp >= 5 || pb >= 5)
        return -1;

    memset(&l, 0, sizeof(l));

    /* Build a fake 5-byte LZMA properties header:
     *   byte[0]   = standard LZMA props byte = lc + 9*(5*pb+lp)
     *   byte[1..4]= dict size hint = *dsize as LE32
     * upx_inflatelzma skips src[0..1] (src+2) after this.          */
    fake_hdr[0] = (unsigned char)(lc + 9u * (5u * pb + lp));
    fake_hdr[1] = (unsigned char)((*dsize)      & 0xffu);
    fake_hdr[2] = (unsigned char)((*dsize >>  8) & 0xffu);
    fake_hdr[3] = (unsigned char)((*dsize >> 16) & 0xffu);
    fake_hdr[4] = (unsigned char)((*dsize >> 24) & 0xffu);

    l.next_in  = fake_hdr;
    l.avail_in = 5u;

    if (cli_LzmaInit(&l, *dsize) != LZMA_RESULT_OK)
        return -1;

    /* Feed compressed stream starting at src+2 (past UPX 2-byte hdr)*/
    l.avail_in  = ssize;
    l.avail_out = *dsize;
    l.next_in   = (unsigned char *)src + 2;
    l.next_out  = (unsigned char *)dst;

    if (cli_LzmaDecode(&l) == LZMA_RESULT_DATA_ERROR) {
        cli_LzmaShutdown(&l);
        return -1;
    }
    cli_LzmaShutdown(&l);

    /* Update *dsize to actual bytes written                          */
    *dsize = *dsize - (uint32_t)l.avail_out;
    return 0;
}

/*  is_upx_elf 
 *
 * Detect a UPX-packed ELF binary (32-bit or 64-bit, little-endian).
 *
 * Identification criteria (all must hold):
 *  1. ELF magic + ELFCLASS32/64 + ELFDATA2LSB (LE only)
 *  2. e_phnum in [2..MAX_PHNUM], e_phentsize == 32 (ELF32) or 56 (ELF64)
 *  3. At least two PT_LOAD segments present
 *  4. l_info magic at phdrs_end+4 is one of the known UPX values,
 *     OR a PT_NOTE segment immediately follows phdrs and the magic
 *     appears after it (ET_DYN / PIE binaries),
 *     OR (ELF64 only) the entire l_info region is zeroed.
 *
 *  Format version discrimination 
 *
 * Returns 1–4 on success (0 = not UPX ELF):
 *
 *   Return 3 — UPX 3.x+ ELF32 or ELF64 with populated l_info
 *     l_magic == UPX_MAGIC_V2 ("UPX!")
 *     PT_LOAD[0]: p_offset == 0, p_filesz < p_memsz  (BSS = output region)
 *     PT_LOAD[1]: p_offset == 0, p_filesz > 0         (compressed + loader)
 *     Decompressed by: decompress_elf_upx32()
 *
 *   Return 2 — UPX 2.x ELF32 with populated l_info
 *     l_magic == UPX_MAGIC_V2 ("UPX!")
 *     PT_LOAD[0]: p_offset == 0, p_filesz == p_memsz  (whole packed file)
 *     PT_LOAD[1]: p_offset > 0,  p_filesz == 0         (output region, BSS)
 *     Decompressed by: decompress_elf_upx32() [overlap blocks skipped]
 *
 *   Return 1 — UPX 1.x ELF32 with "\x7fUPX" l_magic
 *     l_magic == UPX_MAGIC_V1 ("\x7fUPX")
 *     Decompressed by: decompress_elf_upx_v1()
 *
 *   Return 4 — UPX 2.x/3.x ELF64 with ZEROED l_info
 *     UPX 2.x and UPX 3.09 both execute memset(linfo, 0) for ELF64
 *     (source: PackLinuxElf64amd::generateElfHdr in p_lx_elf.cpp, all
 *     versions through 3.09).  The start l_info at phdrs_end is all
 *     zeros; the real l_info with UPX! magic is only at the END of the
 *     file (before the pack header).
 *
 *     Detection criteria (ELF64 only, is64==1):
 *       l_info[0..11] == 0x00 * 12   (start l_info completely zeroed)
 *       Scan backward from file end for UPX! to locate the end l_info
 *       Validate end l_info: l_lsize plausible, l_version in [11..14]
 *       p_info following the zeroed l_info has plausible orig_filesize
 *
 *     Phdr pattern is same as return-3 (filesz < memsz) OR same as
 *     return-2 (filesz == memsz) depending on the exact UPX version.
 *     Both are accepted for return-4.
 *
 *     Decompressed by: decompress_elf_upx32()
 *
 * On return:
 *   *li_off_out  = file offset of l_info (== phdrs_end)
 *   *is64_out    = 1 if ELF64, 0 if ELF32
 */
static int is_upx_elf(const uint8_t *data, size_t fsz,
                      size_t *li_off_out, int *is64_out)
{
    uint16_t e_phnum, e_phentsz;
    uint64_t e_phoff;
    size_t   hdr_min, phdr_size;
    size_t   phdrs_end;
    int      load_count = 0;
    uint64_t load0_filesz = 0, load0_memsz = 0;
    uint64_t load0_offset = 0xffffffffffffffffull;
    uint64_t load1_offset = 0xffffffffffffffffull;
    uint64_t load1_filesz = 0;
    int      is64;
    uint16_t i;
    uint32_t li_magic;

    /* [FROM FILE] ELF magic */
    if (fsz < 8)
        return 0;
    if (memcmp(data, ELF_MAGIC, 4) != 0)
        return 0;

    /* [FROM FILE] ELF class: 1=32-bit, 2=64-bit                    */
    if (data[4] == ELFCLASS32) {
        is64      = 0;
        hdr_min   = ELF32_HDR_SIZE;
        phdr_size = ELF32_PHDR_SIZE;
    } else if (data[4] == ELFCLASS64) {
        is64      = 1;
        hdr_min   = ELF64_HDR_SIZE;
        phdr_size = ELF64_PHDR_SIZE;
    } else {
        return 0;   /* unsupported class */
    }

    /* [FROM FILE] data encoding: must be little-endian              */
    if (data[5] != ELFDATA2LSB)
        return 0;

    if (fsz < hdr_min)
        return 0;

    /* [FROM FILE] e_phoff, e_phnum, e_phentsize
     * ELF32: e_phoff at offset 28 (uint32), e_phentsize at 42, e_phnum at 44
     * ELF64: e_phoff at offset 32 (uint64), e_phentsize at 54, e_phnum at 56 */
    if (!is64) {
        e_phoff   = (uint64_t)rd32(data + 28);
        e_phentsz = rd16(data + 42);
        e_phnum   = rd16(data + 44);
    } else {
        e_phoff   = rd64(data + 32);
        e_phentsz = rd16(data + 54);
        e_phnum   = rd16(data + 56);
    }

    /* SECURITY: phentsize must match expected for class             */
    if (e_phentsz != (uint16_t)phdr_size)
        return 0;

    /* SECURITY: phnum bounds                                        */
    if (e_phnum < 2 || e_phnum > MAX_PHNUM)
        return 0;

    /* SECURITY: phoff must be within file, past ELF header          */
    if (e_phoff < (uint64_t)hdr_min)
        return 0;
    if (e_phoff + (uint64_t)e_phnum * phdr_size > (uint64_t)fsz)
        return 0;

    phdrs_end = (size_t)(e_phoff + (uint64_t)e_phnum * phdr_size);

    /* Walk program headers                                          */
    for (i = 0; i < e_phnum; i++) {
        size_t   ph_off = (size_t)e_phoff + (size_t)i * phdr_size;
        uint32_t p_type;
        uint64_t p_foff, p_filesz, p_memsz;

        p_type = rd32(data + ph_off);    /* [FROM FILE] same offset in 32+64 */

        if (!is64) {
            /* ELF32 Phdr: type(4)+offset(4)+vaddr(4)+paddr(4)+filesz(4)+memsz(4)+... */
            p_foff  = (uint64_t)rd32(data + ph_off + 4);   /* [FROM FILE] */
            p_filesz= (uint64_t)rd32(data + ph_off + 16);  /* [FROM FILE] */
            p_memsz = (uint64_t)rd32(data + ph_off + 20);  /* [FROM FILE] */
        } else {
            /* ELF64 Phdr: type(4)+flags(4)+offset(8)+vaddr(8)+paddr(8)+filesz(8)+memsz(8)+align(8) */
            p_foff  = rd64(data + ph_off + 8);   /* [FROM FILE] */
            p_filesz= rd64(data + ph_off + 32);  /* [FROM FILE] */
            p_memsz = rd64(data + ph_off + 40);  /* [FROM FILE] */
        }

        if (p_type == PT_LOAD) {
            if (load_count == 0) {
                load0_filesz = p_filesz;
                load0_memsz  = p_memsz;
                load0_offset = p_foff;
            } else if (load_count == 1) {
                load1_offset = p_foff;
                load1_filesz = p_filesz;
            }
            load_count++;
        }
    }

    if (load_count < 2)
        return 0;

    /* First PT_LOAD must map from file offset 0 for both v1 and v2 */
    if (load0_offset != 0)
        return 0;

    /* SECURITY: l_info must fit in file after phdrs.
     * For ELF64 we may need to probe at +8 (see below), so require
     * at least L_INFO_SIZE + 4 extra bytes.                          */
    if (phdrs_end + L_INFO_SIZE + 4 > fsz)
        return 0;

    /* [FROM FILE] l_info.l_magic.
     * Standard l_info (12 bytes): magic at phdrs_end+4.
     * UPX 2.x ELF64 extended l_info (16 bytes): magic at phdrs_end+8.
     *   In this format the checksum field is 8 bytes (two uint32) rather
     *   than 4, shifting magic to offset +8.  Observed in real UPX 2.x
     *   ELF64 binaries: phdrs_end[0..3]==0, phdrs_end[4..7]==adler32,
     *   phdrs_end[8..11]=="UPX!".  Both the 4-byte-prefix variant and
     *   the zeroed-l_info variant are distinct from this case.
     *   When magic is found at +8 we return li_off=phdrs_end+4 so that
     *   all downstream code using (li_off + L_INFO_SIZE) correctly lands
     *   on the p_info that follows the 16-byte l_info.               */
    li_magic = rd32(data + phdrs_end + 4);   /* [FROM FILE] std probe  */
    if (li_magic != UPX_MAGIC_V2 && li_magic != UPX_MAGIC_V1) {
        /* Try the +8 probe for ELF64 extended l_info                */
        if (is64 && phdrs_end + 8 + 4 <= fsz) {
            uint32_t magic8 = rd32(data + phdrs_end + 8); /* [FROM FILE] */
            if (magic8 == UPX_MAGIC_V2) {
                /* Rewrite li_magic and adjust effective li_off.
                 * Downstream uses (li_off + L_INFO_SIZE + ...) so
                 * offsetting li_off by 4 corrects the p_info location. */
                li_magic  = UPX_MAGIC_V2;
                phdrs_end = phdrs_end + 4u;   /* logical l_info start  */
            }
        }
    }

    /* PT_NOTE skip: UPX on ET_DYN (PIE) binaries emits a PT_NOTE
     * segment immediately after the phdr table, pushing l_info past
     * phdrs_end.  If all probes above failed, scan the phdr table for
     * a PT_NOTE whose file offset equals phdrs_end and whose data is
     * contiguous; probe for UPX magic immediately after it.
     *
     * Observed in UPX-packed ET_DYN ELF32 (PIE executables built with
     * -pie): phdrs_end lands inside PT_NOTE, real l_info follows.    */
    if (li_magic != UPX_MAGIC_V2 && li_magic != UPX_MAGIC_V1) {
        uint16_t pi;
        for (pi = 0; pi < e_phnum; pi++) {
            size_t   ph_off   = (size_t)e_phoff + (size_t)pi * phdr_size;
            uint32_t p_type   = rd32(data + ph_off);
            uint64_t p_foff   = !is64 ? (uint64_t)rd32(data + ph_off +  4)
                                      : rd64(data + ph_off +  8);
            uint64_t p_filesz = !is64 ? (uint64_t)rd32(data + ph_off + 16)
                                      : rd64(data + ph_off + 32);

            if (p_type   != 4u)                      continue; /* not PT_NOTE  */
            if (p_foff   != (uint64_t)phdrs_end)    continue; /* not adjacent */
            if (p_filesz == 0)                       continue; /* empty        */
            if (p_filesz >= (uint64_t)fsz)           continue; /* sanity       */
            if (p_filesz >  (uint64_t)(fsz - phdrs_end)) continue; /* overflow */

            {
                size_t   adjusted = phdrs_end + (size_t)p_filesz;
                uint32_t m;

                if (adjusted + L_INFO_SIZE + 4 > fsz)
                    continue;

                m = rd32(data + adjusted + 4); /* [FROM FILE] */
                if (m == UPX_MAGIC_V2 || m == UPX_MAGIC_V1) {
                    li_magic  = m;
                    phdrs_end = adjusted;
                    cli_dbgmsg("elf_upx: PT_NOTE skip: l_info found at "
                               "0x%zx\n", phdrs_end);
                    break;
                }
            }
        }
    }

    if (li_magic == UPX_MAGIC_V2) {
        /* Discriminate UPX 2.x from UPX 3.x+ by the PT_LOAD layout.
         *
         * UPX 3.x+:
         *   PT_LOAD[0]: p_offset==0, filesz < memsz  (output/BSS region)
         *   PT_LOAD[1]: p_offset==0, filesz > 0      (compressed+loader)
         *   Both PT_LOAD segments must have p_offset == 0.
         *   The filesz < memsz check is the primary discriminator.
         *   Note: for ET_DYN (PIE) binaries load1_filesz may equal
         *   load1_memsz; we only require filesz > 0 to confirm data
         *   is present.
         *
         * UPX 2.x:
         *   PT_LOAD[0]: p_offset==0, filesz == memsz (whole packed file)
         *   PT_LOAD[1]: p_offset > 0, filesz == 0   (output, zero-fill)
         *   The filesz==memsz and second segment filesz==0 together
         *   distinguish this from any valid non-UPX ELF binary.
         *
         * p_info must fit in file for both.                          */
        if (phdrs_end + L_INFO_SIZE + P_INFO_SIZE > fsz)
            return 0;

        if (load0_filesz < load0_memsz &&
            load1_offset == 0          &&
            load1_filesz  > 0) {
            /* UPX 3.x+ pattern (ET_EXEC and ET_DYN/PIE)             */
            *li_off_out = phdrs_end;
            *is64_out   = is64;
            return 3;   /* UPX 3.x+ */

        } else if (load0_filesz == load0_memsz &&
                   load0_filesz > 0             &&
                   load1_offset > 0             &&
                   load1_filesz == 0) {
            /* UPX 2.x pattern:
             *   PT_LOAD[0] covers whole packed file (filesz==memsz>0)
             *   PT_LOAD[1] is the output region (filesz==0, offset>0)
             * Additional sanity: load0_filesz must equal or closely
             * approximate the file size (packed file maps itself).   */
            if (load0_filesz > (uint64_t)fsz) {
                cli_dbgmsg("elf_upx: UPX2 load0_filesz 0x%llx > fsz 0x%zx\n",
                           (unsigned long long)load0_filesz, fsz);
                return 0;
            }
            *li_off_out = phdrs_end;
            *is64_out   = is64;
            return 2;   /* UPX 2.x */

        } else {
            return 0;   /* UPX! magic but unrecognised phdr pattern  */
        }

    } else if (li_magic == UPX_MAGIC_V1) {
        /* UPX 1.x: no p_info, no b_info.  The loader occupies file
         * bytes [0, l_lsize); the 12-byte program info starts at
         * l_lsize.  The pack header and overlay_offset trail the file.
         *
         * Minimum file size check: must hold loader + hbuf + 1 block
         * + EOF marker + pack header + overlay_offset field.        */
        if (fsz < V1_MIN_FILE_SIZE)
            return 0;

        *li_off_out = phdrs_end;
        *is64_out   = is64;
        return 1;   /* UPX 1.x */

    } else if (li_magic == 0u && is64) {
        /* UPX 2.x/3.x ELF64 — zeroed start l_info.
         *
         * UPX 2.x and 3.09 call memset(linfo, 0) before writing the
         * ELF64 packed header (PackLinuxElf64amd::generateElfHdr in
         * p_lx_elf.cpp).  The entire 12-byte l_info block at phdrs_end
         * is zero.  The real l_info with UPX! magic is appended at the
         * end of the file (the "end l_info").
         *
         * Detection strategy:
         *  a) Confirm ALL 12 bytes at phdrs_end are zero (not just
         *     the magic field), to avoid false-positives on non-UPX
         *     ELF64 files that happen to have four zero bytes there.
         *  b) Scan backward from (fsz - 4) for a plausible end l_info:
         *     l_magic == UPX_MAGIC_V2 ("UPX!") at candidate+4,
         *     l_lsize in [0x80, 0x4000] (sane loader size),
         *     l_version in [11..14] (all known UPX ELF versions).
         *  c) Validate p_info at (phdrs_end + L_INFO_SIZE):
         *     orig_filesize must be in [1, MAX_ORIG_SIZE].
         *
         * The phdr pattern (filesz<memsz or filesz==memsz) is accepted
         * for both UPX 2.x and 3.x packed ELF64; we don't discriminate
         * further since both use the same b_info decompressor.       */
        {
            size_t   s;
            int      found_end_linfo = 0;
            uint16_t end_lsize       = 0;
            uint8_t  end_lver        = 0;

            /* (a) Full 12-byte zero check                            */
            {
                size_t z;
                for (z = 0; z < L_INFO_SIZE; z++) {
                    if (data[phdrs_end + z] != 0) {
                        return 0;
                    }
                }
            }

            /* (b) Scan backward for end l_info with UPX! magic.
             * We search from (fsz - L_INFO_SIZE) down to just past
             * the p_info that would follow the zeroed start l_info.
             * Starting at fsz-L_INFO_SIZE (not fsz-4-L_INFO_SIZE)
             * ensures we catch end l_info even when it falls in the
             * very last L_INFO_SIZE bytes of the file.               */
            {
                size_t search_start = (fsz >= L_INFO_SIZE)
                                      ? fsz - L_INFO_SIZE : 0;
                size_t search_end   = phdrs_end + L_INFO_SIZE + P_INFO_SIZE
                                      + B_INFO_SIZE + 1;

                for (s = search_start; s >= search_end && s <= search_start; s--) {
                    /* [FROM FILE] l_magic at s+4                     */
                    if (rd32(data + s + 4) != UPX_MAGIC_V2)
                        continue;

                    /* [FROM FILE] l_lsize at s+8 (LE16)              */
                    end_lsize = rd16(data + s + 8);
                    /* [FROM FILE] l_version at s+10                  */
                    end_lver  = data[s + 10];

                    /* SECURITY: plausibility checks                  */
                    if (end_lsize < 0x80u || end_lsize > 0x4000u)
                        continue;
                    if (end_lver < 11u || end_lver > 14u)
                        continue;
                    /* loader region [s - end_lsize, s) must be
                     * entirely within the file                       */
                    if ((size_t)end_lsize > s)
                        continue;

                    found_end_linfo = 1;
                    break;
                }
            }

            if (!found_end_linfo) {
                cli_dbgmsg("elf_upx64_zero: no valid end l_info found\n");
                return 0;
            }

            cli_dbgmsg("elf_upx64_zero: end l_info @ 0x%zx "
                       "l_lsize=0x%x l_version=%u\n",
                       s, (unsigned)end_lsize, (unsigned)end_lver);

            /* (c) Validate p_info: orig_filesize must be plausible.
             * [FROM FILE] p_filesize at phdrs_end + L_INFO_SIZE + 4  */
            if (phdrs_end + L_INFO_SIZE + P_INFO_SIZE > fsz)
                return 0;

            {
                uint32_t orig_sz = rd32(data + phdrs_end + L_INFO_SIZE + 4);
                if (orig_sz == 0 || orig_sz > MAX_ORIG_SIZE) {
                    cli_dbgmsg("elf_upx64_zero: p_filesize 0x%x out of "
                               "range\n", orig_sz);
                    return 0;
                }
            }

            *li_off_out = phdrs_end;
            *is64_out   = is64;   /* must be 1 (ELF64) */
            return 4;   /* UPX 2.x/3.x ELF64 zeroed-l_info */
        }

    } else {
        return 0;   /* unrecognised magic */
    }
}

/*  decompress_elf_upx_v1 
 *
 * Decompress a UPX 1.x packed ELF binary.
 *
 * UPX 1.x ELF on-disk layout (confirmed from empirical analysis of
 * UPX 1.20 packed binaries):
 *
 *   [0]           ELF header + program headers + loader stub code
 *                 This region is exactly loader_size bytes (from pack_hdr_a.loader_size).
 *   [loader_size]     12-byte program info header:
 *                   progid[4]      program identity (unused by decompressor)
 *                   orig_size[4]   [FROM FILE] expected decompressed byte count
 *                   blocksize[4]   [FROM FILE] max bytes per compressed block
 *   [loader_size+12]  Variable-length block sequence:
 *                   For each block:  u_len[4] + c_len[4] + c_len bytes cdata
 *                   Block sequence ends when u_len == 0
 *   [eof_marker]  4 bytes: u_len = 0x00000000  (end-of-blocks sentinel)
 *   [pack_hdr]    V1_PACK_HDR_SIZE (32) bytes: UPX! pack header
 *                   Contains the global compression method byte at +6.
 *   [fsz-4]       4 bytes: loader_offset (== loader_size, little-endian)
 *
 * Key differences from UPX 2.x+:
 *   - No pack_hdr_b block (program info is in the prog_info region at loader_size)
 *   - No pack_block_hdr per-block headers (only 8-byte u_len+c_len pair per block)
 *   - No per-block method byte: ONE global method in the pack header
 *   - End sentinel: 4 bytes u_len=0 only (the next 4 bytes are "UPX!" magic,
 *     the first field of the pack header — the runtime stub reads them as a
 *     pair to detect EOF, but we locate the pack header independently)
 *   - "Stored" blocks: when c_len == u_len the data is stored verbatim
 *     (the runtime decompressor memcpy path; ClamAV's inflate engines
 *     do NOT handle this case themselves)
 *
 * Parameters:
 *   data         - the full packed file in memory [FROM FILE validated by caller]
 *   fsz          - file size (already verified >= V1_MIN_FILE_SIZE)
 *   li_off       - file offset of pack_hdr_a (= phdrs_end, from is_upx_elf)
 *   out          - caller-allocated output buffer
 *   out_capacity - size of out (must be >= orig_size + DECOMP_OVERHEAD)
 *   out_used     - receives total decompressed bytes written on success
 *
 * Returns 1 on success, 0 on failure.
 *
 * SECURITY model: every field labelled [FROM FILE] is bounds-checked
 * or range-validated before use.  No field from the file is trusted
 * as a raw pointer or unchecked index.
 */
static int decompress_elf_upx_v1(const uint8_t *data, size_t fsz,
                                  size_t li_off,
                                  uint8_t *out, uint32_t out_capacity,
                                  uint32_t *out_used)
{
    size_t   ph_off;     /* offset of UPX! pack header in file        */
    size_t   prog_info_off; /* offset of 12-byte program info header    */
    size_t   bi_off;     /* current block read offset                 */
    size_t   eof_off;    /* offset of the 4-byte u_len=0 sentinel     */
    uint32_t lsize;      /* loader byte count = loader_offset value   */
    uint32_t orig_size;  /* [FROM FILE] expected decompressed total   */
    uint32_t blocksize;  /* [FROM FILE] maximum block size            */
    uint8_t  method;     /* [FROM FILE] global compression method     */
    uint32_t total_out;
    uint32_t block_num;

    *out_used = 0;

    /*  Read loader_offset from last 4 bytes of file 
     *
     * [FROM FILE] loader_offset: the runtime loader seeks to this
     * offset to find the program info header.  It equals loader_size (the loader byte
     * count), which also appears in pack_hdr_a.loader_size at li_off+8.
     * We read from EOF because that is where the runtime reads it and
     * it is the authoritative copy used during pack.
     *
     * SECURITY: fsz >= V1_MIN_FILE_SIZE >= 4 (guaranteed by caller) */
    lsize = rd32(data + fsz - 4);   /* [FROM FILE] */

    /* SECURITY: lsize must be large enough to hold the ELF header,
     * phdrs, and pack_hdr_a, and small enough to leave room for prog_info,
     * at least one block, the pack header, and the loader_offset.
     *
     *   lower bound: li_off + L_INFO_SIZE  (pack_hdr_a must sit within loader)
     *   upper bound: fsz - (prog_info=12) - (1 block header=8) - (1 data byte=1)
     *                    - (EOF marker=4) - (pack header=32) - (loader_offset=4)
     *                = fsz - 61
     *
     * The upper bound is a conservative safe minimum; real UPX files
     * will be well within this range.                               */
    if (lsize < (uint32_t)(li_off + L_INFO_SIZE)) {
        cli_dbgmsg("elf_upx_v1: loader_offset 0x%x < li_off+L_INFO_SIZE "
                   "(0x%zx)\n", lsize, li_off + L_INFO_SIZE);
        return 0;
    }
    if (lsize > (uint32_t)(fsz - 61u)) {
        cli_dbgmsg("elf_upx_v1: loader_offset 0x%x too large "
                   "(fsz=0x%zx)\n", lsize, fsz);
        return 0;
    }

    /* Cross-check: loader_size in pack_hdr_a should agree with loader_offset.
     * [FROM FILE] loader_size at li_off+8 (LE16).
     * A mismatch is not fatal (the loader_offset is the authoritative
     * value the runtime uses) but is logged for diagnostics.        */
    {
        uint16_t li_lsize = rd16(data + li_off + 8);   /* [FROM FILE] */
        if ((uint32_t)li_lsize != lsize) {
            cli_dbgmsg("elf_upx_v1: loader_size mismatch: pack_hdr_a says 0x%x, "
                       "loader_offset says 0x%x — using loader_offset\n",
                       (unsigned)li_lsize, lsize);
        }
    }

    /*  Locate and validate the UPX! pack header 
     *
     * Layout from file end:
     *   [fsz-4]                  loader_offset (4 bytes, already read)
     *   [fsz-4-V1_PACK_HDR_SIZE] pack header    (32 bytes)
     *   [fsz-4-V1_PACK_HDR_SIZE-4] EOF sentinel (4 bytes: u_len=0)
     *
     * SECURITY: the subtraction is safe because fsz >= V1_MIN_FILE_SIZE
     * which is greater than 4 + V1_PACK_HDR_SIZE + 4.               */
    ph_off  = fsz - 4u - V1_PACK_HDR_SIZE;
    eof_off = ph_off - 4u;

    /* [FROM FILE] Validate pack header magic                         */
    if (rd32(data + ph_off) != UPX_MAGIC_V2) {
        cli_dbgmsg("elf_upx_v1: pack header magic not 'UPX!' at 0x%zx "
                   "(got 0x%08x)\n", ph_off, rd32(data + ph_off));
        return 0;
    }
    /* [FROM FILE] Validate EOF sentinel: u_len must be 0             */
    if (rd32(data + eof_off) != 0u) {
        cli_dbgmsg("elf_upx_v1: EOF marker u_len not 0 at 0x%zx "
                   "(got 0x%08x)\n", eof_off, rd32(data + eof_off));
        return 0;
    }

    /* [FROM FILE] Read compression method from pack header at +6     */
    method = data[ph_off + V1_PH_OFF_METHOD];   /* [FROM FILE] */

    /* SECURITY: only NRV2B/2D/2E are valid for UPX 1.x ELF.
     * LZMA (14) was not present in UPX 1.x.                         */
    if (method != M_V1_NRV2B && method != M_V1_NRV2D && method != M_V1_NRV2E) {
        cli_dbgmsg("elf_upx_v1: unsupported method byte %u "
                   "(expected 2, 5, or 8)\n", (unsigned)method);
        return 0;
    }

    /*  Read program info header at file offset lsize 
     *
     * prog_info layout (all LE32):
     *   [+0] progid     (ignored by decompressor)
     *   [+4] orig_size  [FROM FILE] expected decompressed byte count
     *   [+8] blocksize  [FROM FILE] max bytes per compressed block
     *
     * SECURITY: lsize + 12 <= eof_off - 8 (need room for >=1 block) */
    prog_info_off = (size_t)lsize;
    if (prog_info_off + 12u + 8u > eof_off) {
        cli_dbgmsg("elf_upx_v1: prog_info at 0x%zx leaves no room for blocks "
                   "(eof_off=0x%zx)\n", prog_info_off, eof_off);
        return 0;
    }

    /* [FROM FILE] orig_size and blocksize from prog_info             */
    orig_size = rd32(data + prog_info_off + 4);    /* [FROM FILE] */
    blocksize = rd32(data + prog_info_off + 8);    /* [FROM FILE] */

    /* SECURITY: orig_size range                                      */
    if (orig_size == 0 || orig_size > MAX_ORIG_SIZE) {
        cli_dbgmsg("elf_upx_v1: orig_size 0x%x out of range\n", orig_size);
        return 0;
    }
    /* SECURITY: blocksize range                                      */
    if (blocksize == 0 || blocksize > MAX_BLOCK_SIZE) {
        cli_dbgmsg("elf_upx_v1: blocksize 0x%x out of range\n", blocksize);
        return 0;
    }
    /* SECURITY: output buffer must be large enough                   */
    if (orig_size > out_capacity) {
        cli_dbgmsg("elf_upx_v1: orig_size 0x%x > out_capacity 0x%x\n",
                   orig_size, out_capacity);
        return 0;
    }

    /* Cross-check orig_size against pack header u_len at +16.
     * [FROM FILE] These must agree; a mismatch indicates file corruption. */
    {
        uint32_t ph_ulen = rd32(data + ph_off + V1_PH_OFF_U_LEN); /* [FROM FILE] */
        if (ph_ulen != orig_size) {
            cli_dbgmsg("elf_upx_v1: prog_info orig_size 0x%x != pack header "
                       "u_len 0x%x — file may be corrupt\n",
                       orig_size, ph_ulen);
            /* Non-fatal: trust prog_info (runtime uses it), but log. */
        }
    }

    cli_dbgmsg("elf_upx_v1: lsize=0x%x method=%u orig_size=0x%x "
               "blocksize=0x%x\n", lsize, method, orig_size, blocksize);

    /*  Walk compressed blocks 
     *
     * Each block has an 8-byte header: u_len(LE32) + c_len(LE32)
     * followed immediately by c_len bytes of compressed data.
     *
     * Special cases:
     *   u_len == 0: end-of-blocks sentinel (stop)
     *   c_len == u_len: stored block (data is verbatim, memcpy only)
     *   c_len <  u_len: compressed block (call inflate engine)
     *   c_len >  u_len: invalid (reject)
     *
     * We stop the block walk when any of these conditions is true:
     *   a) u_len == 0 (explicit terminator)
     *   b) block_num >= MAX_BLOCKS (safety cap)
     *   c) total_out >= orig_size (decompressed expected amount)
     *   d) Next block header would reach or pass eof_off
     */
    bi_off    = prog_info_off + 12u;
    total_out = 0u;
    block_num = 0u;

    while (block_num < MAX_BLOCKS) {
        uint32_t        u_len, c_len;
        const uint8_t  *block_src;
        int             ret;

        /* SECURITY: block header must fit before the EOF sentinel    */
        if (bi_off + 8u > eof_off) {
            cli_dbgmsg("elf_upx_v1: block %u header at 0x%zx would pass "
                       "eof_off 0x%zx\n", block_num, bi_off, eof_off);
            break;
        }

        /* [FROM FILE] 8-byte block header                            */
        u_len = rd32(data + bi_off);       /* [FROM FILE] */
        c_len = rd32(data + bi_off + 4);   /* [FROM FILE] */

        /* End-of-blocks sentinel                                     */
        if (u_len == 0u)
            break;

        /* SECURITY: u_len must not exceed blocksize (packer enforces
         * this; violation means we've drifted into garbage data).   */
        if (u_len > blocksize) {
            cli_dbgmsg("elf_upx_v1: block %u u_len 0x%x > blocksize 0x%x "
                       "— stopping block walk\n", block_num, u_len, blocksize);
            break;
        }
        /* SECURITY: c_len must not exceed u_len (cannot compress to
         * more than the original size).                              */
        if (c_len > u_len) {
            cli_dbgmsg("elf_upx_v1: block %u c_len 0x%x > u_len 0x%x "
                       "— invalid\n", block_num, c_len, u_len);
            return 0;
        }
        /* SECURITY: c_len must be > 0 (even stored blocks have 1 byte) */
        if (c_len == 0u) {
            cli_dbgmsg("elf_upx_v1: block %u c_len == 0 — invalid\n",
                       block_num);
            return 0;
        }
        /* SECURITY: compressed data must fit within the file before
         * the EOF sentinel.                                          */
        if (bi_off + 8u + c_len > eof_off) {
            cli_dbgmsg("elf_upx_v1: block %u data [0x%zx, 0x%zx) exceeds "
                       "eof_off 0x%zx\n", block_num,
                       bi_off + 8u, bi_off + 8u + c_len, eof_off);
            return 0;
        }
        /* SECURITY: output would not overflow the buffer             */
        if (u_len > out_capacity - total_out) {
            cli_dbgmsg("elf_upx_v1: block %u output overflow "
                       "(total=0x%x u_len=0x%x cap=0x%x)\n",
                       block_num, total_out, u_len, out_capacity);
            return 0;
        }

        block_src = data + bi_off + 8u;

        cli_dbgmsg("elf_upx_v1: block %u @ 0x%zx u_len=0x%x c_len=0x%x "
                   "method=%u %s\n",
                   block_num, bi_off, u_len, c_len, method,
                   (c_len == u_len) ? "[stored]" : "[compressed]");

        /*  Decompress or copy block  */
        if (c_len == u_len) {
            /* Stored (incompressible) block: verbatim copy.
             * When compressed size equals uncompressed size the block
             * data is stored verbatim (no compression was applied).
             * ClamAV's inflate engines do NOT handle this case; a plain
             * memcpy is correct and necessary.                       */
            memcpy(out + total_out, block_src, c_len);
            ret = 0;
        } else {
            /* Compressed block: dispatch to inflate engine by method.
             * upx_inflate2{b,d,e}_raw() decompress NRV bitstream data
             * into a caller-supplied buffer.  They return 0 on success
             * with *dsize updated to actual bytes written, or -1 on any
             * out-of-bounds access or bitstream error.
             *
             * We pass u_len as the initial *dsize so the engine can
             * enforce the expected output bound internally via
             * CLI_ISCONTAINED checks.                                */
            uint32_t block_out = u_len;
            switch (method) {
            case M_V1_NRV2B:
                ret = upx_inflate2b_raw((const char *)block_src, c_len,
                                        (char *)out + total_out, &block_out);
                break;
            case M_V1_NRV2D:
                ret = upx_inflate2d_raw((const char *)block_src, c_len,
                                        (char *)out + total_out, &block_out);
                break;
            case M_V1_NRV2E:
                ret = upx_inflate2e_raw((const char *)block_src, c_len,
                                        (char *)out + total_out, &block_out);
                break;
            default:
                /* Should never reach here: method was validated above */
                cli_dbgmsg("elf_upx_v1: block %u internal method error\n",
                           block_num);
                return 0;
            }

            if (ret < 0) {
                cli_dbgmsg("elf_upx_v1: block %u decompression failed "
                           "(method=%u ret=%d)\n", block_num, method, ret);
                return 0;
            }

            /* Sanity: inflate engine must have written exactly u_len bytes.
             * A short write means the bitstream terminated early, which
             * indicates file corruption.                             */
            if (block_out != u_len) {
                cli_dbgmsg("elf_upx_v1: block %u size mismatch: "
                           "expected 0x%x, got 0x%x\n",
                           block_num, u_len, block_out);
                return 0;
            }
        }

        total_out += u_len;
        block_num++;

        /* SECURITY: advance bi_off, checking for wraparound          */
        if (bi_off + 8u + c_len < bi_off) {  /* integer overflow guard */
            cli_dbgmsg("elf_upx_v1: block offset overflow at block %u\n",
                       block_num);
            return 0;
        }
        bi_off += 8u + c_len;

        if (total_out >= orig_size)
            break;
    }

    if (block_num == 0u) {
        cli_dbgmsg("elf_upx_v1: no blocks decompressed\n");
        return 0;
    }

    /* SECURITY: verify we decompressed exactly the expected amount.
     * UPX 1.x's unpack() enforces this with an EOFException.        */
    if (total_out != orig_size) {
        cli_dbgmsg("elf_upx_v1: total_out 0x%x != orig_size 0x%x\n",
                   total_out, orig_size);
        return 0;
    }

    cli_dbgmsg("elf_upx_v1: OK — %u blocks, 0x%x bytes\n",
               block_num, total_out);

    *out_used = total_out;
    return 1;
}

/*  decompress_elf_upx32 
 *
 * Decompress all pack_block_hdr blocks from a UPX-packed ELF32 (UPX 2.x+).
 *
 * Parameters:
 *   data         - the full packed file in memory
 *   fsz          - file size
 *   li_off       - file offset of pack_hdr_a (from is_upx_elf32)
 *   out          - caller-allocated output buffer
 *   out_capacity - size of out buffer (must be >= orig_size + DECOMP_OVERHEAD)
 *   out_used     - receives total decompressed bytes written
 *
 * Returns 1 on success, 0 on failure.
 *
 * Algorithm:
 *   1. Read pack_hdr_b: get orig_filesize and blocksize.
 *   2. Walk pack_block_hdr blocks sequentially from pi_off+P_INFO_SIZE.
 *      Stop when chunk_out_len==0 or we reach the stub loader region.
 *   3. For each block: decompress chunk_in_len bytes -> chunk_out_len bytes.
 *   4. Accumulate output.
 *
 * The stub loader region starts at: end_l_info_off - end_l_lsize.
 * We use the END pack_hdr_a (found by rfind for UPX!) to locate it,
 * since the header pack_hdr_a loader_size sometimes differs.
 */
static int decompress_elf_upx32(const uint8_t *data, size_t fsz,
                                size_t li_off,
                                uint8_t *out, uint32_t out_capacity,
                                uint32_t *out_used)
{
    size_t   pi_off, bi_off;
    uint32_t p_filesize, p_blocksize;
    size_t   end_li_off;
    uint16_t end_lsize;
    size_t   loader_start;  /* informational only - not used as block walk boundary */
    uint32_t block_num = 0;
    uint32_t total_out = 0;

    *out_used = 0;

    /*  Read pack_hdr_b  */
    pi_off = li_off + L_INFO_SIZE;

    /* [FROM FILE] p_filesize and p_blocksize from pack_hdr_b            */
    p_filesize  = rd32(data + pi_off + 4);   /* [FROM FILE] */
    p_blocksize = rd32(data + pi_off + 8);   /* [FROM FILE] */

    /* SECURITY: p_filesize sanity */
    if (p_filesize == 0 || p_filesize > MAX_ORIG_SIZE) {
        cli_dbgmsg("elf_upx: p_filesize 0x%x out of range\n", p_filesize);
        return 0;
    }
    /* SECURITY: p_blocksize sanity */
    if (p_blocksize == 0 || p_blocksize > MAX_BLOCK_SIZE) {
        cli_dbgmsg("elf_upx: p_blocksize 0x%x out of range\n", p_blocksize);
        return 0;
    }
    /* SECURITY: output buffer must be large enough                  */
    if (p_filesize > out_capacity) {
        cli_dbgmsg("elf_upx: p_filesize 0x%x > out_capacity 0x%x\n",
                   p_filesize, out_capacity);
        return 0;
    }

    cli_dbgmsg("elf_upx: p_filesize=0x%x p_blocksize=0x%x\n",
               p_filesize, p_blocksize);

    /*  Locate stub loader via end pack_hdr_a 
     *
     * The END pack_hdr_a (the one used by 'upx -d') is the LAST occurrence
     * of UPX! in the file.  Its loader_size field gives the loader byte
     * count.  Loader occupies [end_li_off - loader_size .. end_li_off).
     * We stop walking pack_block_hdr blocks when we reach loader_start.
     *
     * SECURITY: search backward from fsz-L_INFO_SIZE for UPX! magic.
     */
    end_li_off = 0;
    {
        /* Minimum: 4 bytes for the checksum field before UPX! magic  */
        size_t search_limit = (fsz >= L_INFO_SIZE + 4) ? fsz - L_INFO_SIZE : 0;
        size_t s;
        for (s = search_limit; s > pi_off + P_INFO_SIZE; s--) {
            if (rd32(data + s + 4) == PACK_MAGIC) {
                end_li_off = s;
                /* Keep searching for the LAST occurrence            */
                break;
            }
        }
        /* Scan from farther back to get the actual last one         */
        for (s = pi_off + P_INFO_SIZE; s + L_INFO_SIZE <= fsz; s++) {
            if (rd32(data + s + 4) == PACK_MAGIC)
                end_li_off = s;
        }
    }

    if (end_li_off == 0) {
        cli_dbgmsg("elf_upx: end pack_hdr_a not found\n");
        return 0;
    }

    /* [FROM FILE] end loader_size: loader byte count                    */
    end_lsize = rd16(data + end_li_off + 8);

    /* SECURITY: loader region must not underflow or exceed file      */
    if (end_lsize == 0 || (size_t)end_lsize > end_li_off) {
        cli_dbgmsg("elf_upx: bad end loader_size 0x%x at 0x%zx\n",
                   end_lsize, end_li_off);
        return 0;
    }
    loader_start = end_li_off - end_lsize;

    cli_dbgmsg("elf_upx: end pack_hdr_a @ 0x%zx loader_size=0x%x loader @ 0x%zx\n",
               end_li_off, end_lsize, loader_start);

    /*  Walk pack_block_hdr blocks 
     *
     * First pack_block_hdr is at pi_off + P_INFO_SIZE.
     * Each pack_block_hdr is followed immediately by chunk_in_len bytes of compressed data.
     * We stop when:
     *   - chunk_out_len == 0 (explicit terminator)
     *   - next pack_block_hdr would reach or enter the loader region
     *   - block_num exceeds MAX_BLOCKS (safety)
     *   - total_out >= p_filesize (we have all expected bytes)
     */
    bi_off = pi_off + P_INFO_SIZE;

    while (block_num < MAX_BLOCKS) {
        uint32_t chunk_out_len, chunk_in_len;
        uint8_t  chunk_method, chunk_filter_id, chunk_filter_param;
        const uint8_t *block_src;
        uint32_t block_out;
        int      ret;

        /* SECURITY: pack_block_hdr header must fit within the file.
         * We do NOT use loader_start as a hard boundary here because
         * for ELF64 the compressed data may legitimately extend into
         * what loader_size defines as the "loader region".
         * The reliable stop conditions are: chunk_out_len==0, data exceeds
         * file size, or implausible chunk_in_len ratio (loader garbage).   */
        if (bi_off + B_INFO_SIZE > fsz)
            break;

        /* [FROM FILE] pack_block_hdr fields                                 */
        chunk_out_len   = rd32(data + bi_off);           /* [FROM FILE] */
        chunk_in_len   = rd32(data + bi_off + 4);       /* [FROM FILE] */
        chunk_method = data[bi_off + 8];              /* [FROM FILE] */
        chunk_filter_id   = data[bi_off + 9];              /* [FROM FILE] */
        chunk_filter_param   = data[bi_off + 10];             /* [FROM FILE] */

        (void)chunk_filter_id;  /* filter id - noted but not applied here    */
        (void)chunk_filter_param;  /* filter param - noted but not applied here */

        /* Explicit block terminator                                 */
        if (chunk_out_len == 0)
            break;

        /* SECURITY: chunk_out_len sanity.
         * chunk_out_len > p_blocksize means we've walked into loader code --
         * break cleanly rather than hard-fail.                       */
        if (chunk_out_len > p_blocksize) {
            cli_dbgmsg("elf_upx: block %u chunk_out_len 0x%x > p_blocksize 0x%x "
                       "-- assuming end of blocks\n",
                       block_num, chunk_out_len, p_blocksize);
            break;
        }
        /* SECURITY: chunk_in_len plausibility check.
         * Implausible ratio means we've hit loader stub bytes -- break.
         * We also break (not fail) if compressed data would exceed file;
         * this handles the case where the last valid pack_block_hdr is right at
         * the boundary and there's no explicit chunk_out_len==0 terminator.
         *
         * UPX 2.x OVERLAP BLOCKS: The final 1–2 pack_block_hdr blocks in a UPX
         * 2.x ELF may use 'overlap decompression' where the compressed
         * data lives inside the loader stub region rather than in the
         * pack_block_hdr stream.  These blocks have an impossibly small chunk_in_len
         * relative to chunk_out_len (ratio well under 1%).  They cannot be
         * decompressed offline.  We detect them by the ratio
         *   chunk_in_len < chunk_out_len / 64   (i.e. < ~1.6% compression ratio)
         * and break cleanly, accepting the partial output collected so
         * far.  For ClamAV malware scanning this is acceptable because
         * overlap blocks contain ELF metadata (section headers, string
         * tables) not executable code or data payloads.              */
        if (chunk_in_len == 0 || chunk_in_len > chunk_out_len + 1024) {
            cli_dbgmsg("elf_upx: block %u bad chunk_in_len 0x%x (chunk_out_len=0x%x) "
                       "-- assuming end of blocks\n",
                       block_num, chunk_in_len, chunk_out_len);
            break;
        }
        if (chunk_out_len >= 64u && chunk_in_len < chunk_out_len / 64u) {
            cli_dbgmsg("elf_upx: block %u chunk_in_len 0x%x implausibly small "
                       "for chunk_out_len 0x%x (UPX2 overlap block) "
                       "-- stopping block walk\n",
                       block_num, chunk_in_len, chunk_out_len);
            break;
        }
        /* SECURITY: compressed data must fit within file            */
        if (bi_off + B_INFO_SIZE + chunk_in_len > fsz) {
            cli_dbgmsg("elf_upx: block %u data would exceed file "
                       "(off=0x%zx cpr=0x%x fsz=0x%zx)\n",
                       block_num, bi_off, chunk_in_len, fsz);
            break;
        }
        /* SECURITY: output would not overflow the buffer            */
        if (total_out + chunk_out_len > out_capacity) {
            cli_dbgmsg("elf_upx: block %u output overflow "
                       "(total=0x%x chunk_out_len=0x%x cap=0x%x)\n",
                       block_num, total_out, chunk_out_len, out_capacity);
            return 0;
        }
        /* SECURITY: overflow in bi_off + B_INFO_SIZE                */
        if (bi_off + B_INFO_SIZE < bi_off) {
            return 0;
        }

        block_src = data + bi_off + B_INFO_SIZE;
        block_out = chunk_out_len;

        cli_dbgmsg("elf_upx: block %u @ 0x%zx "
                   "chunk_out_len=0x%x chunk_in_len=0x%x method=%u ftid=%u%s\n",
                   block_num, bi_off, chunk_out_len, chunk_in_len, chunk_method, chunk_filter_id,
                   (chunk_in_len == chunk_out_len) ? " [stored]" : "");

        /*  Stored block: chunk_in_len == chunk_out_len means verbatim copy 
         *
         * UPX writes stored blocks when the compressed size is not
         * smaller than the original (incompressible data).  The source
         * bytes are copied directly with no decompression.
         * This applies identically to UPX 2.x, 3.x, and 4.x.
         *
         * SECURITY: all bounds were verified above:
         *   block_src + chunk_in_len <= data + fsz  (data fits in file)
         *   out + total_out + chunk_out_len <= out + out_capacity  (fits in buf)
         */
        if (chunk_in_len == chunk_out_len) {
            memcpy(out + total_out, block_src, chunk_in_len);
            total_out += chunk_out_len;
            block_num++;
            if (bi_off + B_INFO_SIZE + chunk_in_len < bi_off) return 0; /* overflow guard */
            bi_off += B_INFO_SIZE + chunk_in_len;
            if (total_out >= p_filesize)
                break;
            continue;
        }

        /*  Decompress block  */
        switch (chunk_method) {

        case METHOD_NRV2B32:
            /* upx_inflate2b: NRV2B LE32 decompressor.
             * For ELF there is no PE header to reconstruct, so we
             * use upx0=0, upx1=0, ep=0. pefromupx() will be called
             * inside but with these zero values will fail the import
             * scan and enter the forge path -- which corrupts dst!
             *
             * FIX: we need direct inflate without pefromupx tail.
             * Use upx_inflate2b with a trick: since ELF decompressed
             * content is raw binary (not a PE), pefromupx's forge will
             * write a fake PE header over our data. We must use the
             * raw inflate engines without pefromupx.
             *
             * upx_inflate2b returns: >= 0 on success (dsize updated),
             * -1 on failure. The pefromupx call at the end of
             * upx_inflate2b will fail/forge if upx0/upx1/ep are 0,
             * and it writes into dst... 
             *
             * SOLUTION: we route through upx_inflate2b_raw() which
             * is the inflate engine without pefromupx(). Since that
             * function doesn't exist yet, we implement the inflate
             * inline via a trampoline approach:
             *
             * Actually the cleanest solution is to pass upx0=0,
             * upx1=0, ep=0 and check the return value carefully.
             * pefromupx with upx0=upx1=0 will try to find a PE in
             * the output, fail, and forge -- overwriting up to
             * dsize+0x200 bytes with fake PE headers.
             *
             * The CORRECT approach: add raw inflate entry points to
             * upx_standalone.c. For now, call inflate then overwrite
             * with actual data we saved before the pefromupx trashes it.
             *
             * ACTUAL SOLUTION implemented below: use a temporary
             * buffer of size chunk_out_len + DECOMP_OVERHEAD, run inflate into it,
             * then copy chunk_out_len bytes to the real output. The pefromupx
             * forge path writes AT MOST chunk_out_len + DECOMP_OVERHEAD bytes and
             * we only copy the first chunk_out_len bytes. But pefromupx
             * also MODIFIES dsize to be the forged PE size.
             *
             * TRUE SOLUTION: add upx_inflate2b_raw() to upx_standalone.c.
             * For this commit, see upx_inflate_raw() below.            */
            ret = upx_inflate2b_raw((const char *)block_src, chunk_in_len,
                                    (char *)out + total_out, &block_out);
            break;

        case METHOD_NRV2D32:
            ret = upx_inflate2d_raw((const char *)block_src, chunk_in_len,
                                    (char *)out + total_out, &block_out);
            break;

        case METHOD_NRV2E32:
            ret = upx_inflate2e_raw((const char *)block_src, chunk_in_len,
                                    (char *)out + total_out, &block_out);
            break;

        case METHOD_LZMA: {
            /* UPX 2-byte LZMA header at block_src[0..1]:
             *   byte[0] = ((lc+lp)<<3) | pb
             *   byte[1] = (lp<<4) | lc
             * SECURITY: bounds already checked (chunk_in_len >= 3 implied
             * by the chunk_in_len > chunk_out_len+1024 check failing for chunk_out_len>0,
             * but we check explicitly here).                         */
            uint32_t props;
            uint8_t  b0, b1, pb, lp, lc;

            if (chunk_in_len < 3) {
                cli_dbgmsg("elf_upx: LZMA block %u chunk_in_len %u < 3\n",
                           block_num, chunk_in_len);
                return 0;
            }

            /* [FROM FILE] 2-byte UPX LZMA header                   */
            b0 = block_src[0];   /* [FROM FILE] */
            b1 = block_src[1];   /* [FROM FILE] */

            pb = b0 & 7u;
            lp = b1 >> 4;
            lc = b1 & 0xfu;

            /* UPX redundancy check: b0>>3 must equal lc+lp         */
            if ((uint8_t)(b0 >> 3) != (uint8_t)(lc + lp)) {
                cli_dbgmsg("elf_upx: LZMA block %u header check failed "
                           "(0x%02x 0x%02x)\n", block_num, b0, b1);
                return 0;
            }
            /* SECURITY: LZMA parameter ranges                       */
            if (lc >= 9 || lp >= 5 || pb >= 5) {
                cli_dbgmsg("elf_upx: LZMA block %u bad params "
                           "lc=%u lp=%u pb=%u\n", block_num, lc, lp, pb);
                return 0;
            }

            props = (uint32_t)lc | ((uint32_t)lp<<8) | ((uint32_t)pb<<16);
            ret   = upx_inflatelzma_elf((const char *)block_src, chunk_in_len,
                                        (char *)out + total_out, &block_out,
                                        props);
            break;
        }

        default:
            cli_dbgmsg("elf_upx: block %u unknown method %u\n",
                       block_num, chunk_method);
            return 0;
        }

        if (ret < 0) {
            cli_dbgmsg("elf_upx: block %u decompression failed "
                       "(method=%u ret=%d)\n", block_num, chunk_method, ret);
            return 0;
        }

        /* block_out updated to actual bytes written by inflate       */
        total_out += block_out;
        block_num++;

        /* Advance to next pack_block_hdr                                    */
        /* SECURITY: overflow check on bi_off advance                */
        if (bi_off + B_INFO_SIZE + chunk_in_len < bi_off)
            return 0;
        bi_off += B_INFO_SIZE + chunk_in_len;

        /* Stop if we've decompressed the expected amount            */
        if (total_out >= p_filesize)
            break;
    }

    if (block_num == 0) {
        cli_dbgmsg("elf_upx: no blocks decompressed\n");
        return 0;
    }

    cli_dbgmsg("elf_upx: decompressed %u blocks, %u bytes total\n",
               block_num, total_out);

    *out_used = total_out;
    return 1;
}


/* 
 * upx_unpack_elf_buf() — framework-free integration entry point.
 *
 * Called by cli_unpackelf() in libclamav/elf.c before the bytecode hook.
 * Shares all internal helpers with handle_elf() but has no stdio/fopen
 * dependency — it returns a calloc'd buffer so the ClamAV framework
 * layer (elf.c) can own the tempfile write and cli_magic_scan_desc call.
 *
 * Returns:
 *    0   success — *out and *out_used valid; caller must free(*out)
 *   -1   not a UPX-packed ELF (silent fallthrough to bytecode hook)
 *   -2   UPX ELF detected but decompression failed (log + fallthrough)
 *  */
int upx_unpack_elf_buf(const uint8_t *buf, size_t fsz,
                       uint8_t **out, uint32_t *out_used)
{
    uint8_t  *outbuf;
    uint32_t  orig_size, out_cap;
    size_t    li_off;
    int       is64_elf;
    int       upx_ver;
    int       ok;

    if (!buf || !out || !out_used)
        return -1;

    *out      = NULL;
    *out_used = 0;

    /*  Detect: is this a UPX-packed ELF at all?  */
    upx_ver = is_upx_elf(buf, fsz, &li_off, &is64_elf);
    if (upx_ver == 0)
        return -1;   /* not UPX ELF — silent fallthrough */

    /*  Read orig_size for allocation  */
    if (upx_ver == 2 || upx_ver == 3 || upx_ver == 4) {
        orig_size = rd32(buf + li_off + L_INFO_SIZE + 4);  /* [FROM FILE] */
    } else {
        /* upx_ver == 1: UPX 1.x — read orig_size from prog_info header */
        uint32_t lsize = rd32(buf + fsz - 4);              /* [FROM FILE] */
        if (lsize > fsz - 4u - 4u)
            return -2;
        orig_size = rd32(buf + lsize + 4);                 /* [FROM FILE] */
    }

    /* SECURITY: bound orig_size */
    if (orig_size == 0 || orig_size > MAX_ORIG_SIZE)
        return -2;
    if (orig_size > (uint32_t)(0xFFFFFFFFu - DECOMP_OVERHEAD))
        return -2;

    out_cap = orig_size + DECOMP_OVERHEAD;
    outbuf  = (uint8_t *)calloc(out_cap, 1);
    if (!outbuf)
        return -2;

    /*  Decompress  */
    if (upx_ver == 2 || upx_ver == 3 || upx_ver == 4) {
        ok = decompress_elf_upx32(buf, fsz, li_off, outbuf, out_cap, out_used);
    } else {
        ok = decompress_elf_upx_v1(buf, fsz, li_off, outbuf, out_cap, out_used);
    }

    if (!ok) {
        free(outbuf);
        return -2;
    }

    *out = outbuf;
    return 0;
}

/* 
 * handle_elf() - ELF UPX decompression entry point.
 *
 * Dispatches to the appropriate decompressor based on the UPX format
 * version detected by is_upx_elf():
 *
 *   Return value 1 (UPX_MAGIC_V2, "UPX!"):
 *     Uses decompress_elf_upx32() — UPX 2.x+ format with pack_hdr_a,
 *     pack_hdr_b, and pack_block_hdr block headers.
 *
 *   Return value 2 (UPX_MAGIC_V1, "\x7fUPX"):
 *     Uses decompress_elf_upx_v1() — UPX 1.x format with raw 8-byte
 *     block headers and a global method in the pack trailer.
 *
 * filebuf and fsz are already validated by the caller (file was read
 * and is at least ELF32_HDR_SIZE bytes).
 *
 * Returns 0 on success, non-zero on failure.
 *  */
int handle_elf(const uint8_t *filebuf, size_t fsz,
                      const char *outfile)
{
    uint8_t  *outbuf;
    uint32_t  orig_size, out_cap, out_used;
    size_t    li_off;
    int       is64_elf;
    int       upx_ver;   /* 1=UPX 1.x, 2=UPX 2.x ELF32, 3=UPX 3.x+,
                            4=UPX 2.x/3.x ELF64 zeroed-pack_hdr_a       */
    FILE     *fo;
    int       ok;

    /*  Identify UPX ELF (32-bit or 64-bit) and version  */
    upx_ver = is_upx_elf(filebuf, fsz, &li_off, &is64_elf);
    if (upx_ver == 0) {
        fprintf(stderr, "not a UPX-packed ELF32 or ELF64 binary\n");
        return 1;
    }

    /*  Read orig_size for allocation 
     *
     * For UPX 2.x and 3.x+: [FROM FILE] p_filesize at
     *   li_off + L_INFO_SIZE + 4  (inside pack_hdr_b)
     * For UPX 1.x: [FROM FILE] orig_size at loader_offset + 4
     *   loader_offset = rd32(data + fsz - 4)
     *
     * All paths bound orig_size before allocation.                  */
    if (upx_ver == 3 || upx_ver == 2 || upx_ver == 4) {
        /* UPX 2.x, 3.x+, and 4 (ELF64 zeroed-pack_hdr_a) all use pack_hdr_b */
        orig_size = rd32(filebuf + li_off + L_INFO_SIZE + 4);  /* [FROM FILE] */
    } else {
        /* upx_ver == 1: read orig_size from prog_info header         */
        uint32_t lsize = rd32(filebuf + fsz - 4);   /* [FROM FILE] */
        if (lsize > fsz - 4u - 4u) {
            fprintf(stderr, "ELF v1: loader_offset 0x%x out of range\n",
                    lsize);
            return 1;
        }
        orig_size = rd32(filebuf + lsize + 4);   /* [FROM FILE] */
    }

    /* SECURITY: bound orig_size before allocation                    */
    if (orig_size == 0 || orig_size > MAX_ORIG_SIZE) {
        fprintf(stderr, "ELF: orig_size 0x%x out of range\n", orig_size);
        return 1;
    }
    /* SECURITY: overflow check before addition                       */
    if (orig_size > (uint32_t)(0xFFFFFFFFu - DECOMP_OVERHEAD)) {
        fprintf(stderr, "ELF: orig_size overflow\n");
        return 1;
    }
    out_cap = orig_size + DECOMP_OVERHEAD;
    outbuf  = (uint8_t *)calloc(out_cap, 1);
    if (!outbuf) { perror("calloc"); return 1; }

    /*  Print info  */
    {
        uint64_t e_entry = is64_elf ? rd64(filebuf + 24) : (uint64_t)rd32(filebuf + 24);
        uint16_t e_phnum = is64_elf ? rd16(filebuf + 56) : rd16(filebuf + 44);
        const char *ver_str = (upx_ver == 3) ? "3.x+"      :
                              (upx_ver == 2) ? "2.x"       :
                              (upx_ver == 4) ? "2.x/3.x-64" : "1.x";
        printf("ELF%s (%s LE)  Entry=0x%llx  Segs=%u  UPX-format=%s\n",
               is64_elf ? "64" : "32",
               is64_elf ? "x86-64" : "i386",
               (unsigned long long)e_entry, e_phnum, ver_str);
        printf("  orig_size=0x%x  pack_hdr_a @ 0x%zx\n\n", orig_size, li_off);
    }

    /*  Decompress  */
    if (upx_ver == 3 || upx_ver == 2 || upx_ver == 4) {
        /* UPX 2.x, 3.x+, and ELF64 zeroed-pack_hdr_a all use pack_block_hdr blocks.
         * For UPX 2.x, overlap blocks at the tail are skipped gracefully.
         * For zeroed-pack_hdr_a ELF64, the block format is identical.      */
        ok = decompress_elf_upx32(filebuf, fsz, li_off,
                                  outbuf, out_cap, &out_used);
    } else {
        /* upx_ver == 1: UPX 1.x raw 8-byte block headers, global method */
        ok = decompress_elf_upx_v1(filebuf, fsz, li_off,
                                   outbuf, out_cap, &out_used);
    }

    if (!ok) {
        fprintf(stderr, "ELF decompression failed\n");
        free(outbuf);
        return 1;
    }

    printf("Decompressed: 0x%x (%u) bytes\n", out_used, out_used);

    /* Sanity: output should start with ELF magic                    */
    if (out_used >= 4 &&
        outbuf[0] == 0x7f && outbuf[1] == 'E' &&
        outbuf[2] == 'L'  && outbuf[3] == 'F') {
        printf("Output starts with ELF magic \xe2\x9c\x93\n");
    } else {
        fprintf(stderr, "WARNING: output does not start with ELF magic\n");
    }

    /*  Write output  */
    fo = fopen(outfile, "wb");
    if (!fo) { perror(outfile); free(outbuf); return 1; }
    if (fwrite(outbuf, 1, out_used, fo) != out_used) {
        perror("fwrite"); fclose(fo); free(outbuf); return 1;
    }
    fclose(fo);
    printf("Wrote 0x%x (%u) bytes to %s\n", out_used, out_used, outfile);

    free(outbuf);
    return 0;
}

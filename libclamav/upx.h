/*
 *  Copyright (C) 2013-2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Alberto Wu
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

#ifndef __UPX_H
#define __UPX_H

#include "clamav-types.h"
#include <stddef.h>

int upx_inflate2b(const char *, uint32_t, char *, uint32_t *, uint32_t, uint32_t, uint32_t);
int upx_inflate2d(const char *, uint32_t, char *, uint32_t *, uint32_t, uint32_t, uint32_t);
int upx_inflate2e(const char *, uint32_t, char *, uint32_t *, uint32_t, uint32_t, uint32_t);
int upx_inflatelzma(const char *, uint32_t, char *, uint32_t *, uint32_t, uint32_t, uint32_t, uint32_t);

/* PE32+ (x64) variants - call pe64fromupx() instead of pefromupx() */
int upx_inflate2b_pe64(const char *, uint32_t, char *, uint32_t *, uint32_t, uint32_t, uint32_t, uint32_t *);
int upx_inflate2d_pe64(const char *, uint32_t, char *, uint32_t *, uint32_t, uint32_t, uint32_t, uint32_t *);
int upx_inflate2e_pe64(const char *, uint32_t, char *, uint32_t *, uint32_t, uint32_t, uint32_t, uint32_t *);

/* PE32+ (x64) LZMA variant - calls pe64fromupx() with caller-supplied magic[] */
int upx_inflatelzma_pe64(const char *, uint32_t, char *, uint32_t *, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t *);

/* ELF raw inflate entry points (no pefromupx tail call) */
/* Return 0 on success (*dsize = bytes written), -1 on failure.  */
int upx_inflate2b_raw(const char *, uint32_t, char *, uint32_t *);
int upx_inflate2d_raw(const char *, uint32_t, char *, uint32_t *);
int upx_inflate2e_raw(const char *, uint32_t, char *, uint32_t *);

/*  ELF LZMA entry point (no pefromupx tail call) */
/* Decodes UPX 2-byte header from src[0..1], decompresses to dst. */
/* properties arg = lc|(lp<<8)|(pb<<16) decoded from src[0..1].  */
/* Returns 0 on success, -1 on failure.                          */
/* (This function is defined in upx_elf.c as a static; declared  */
/*  here for documentation only -- not linked as a library sym.) */

/*  PE32/PE32+ UPX detection and dispatch */
/*                                                                */
/* Detection logic extracted verbatim from clam_upx.c which was  */
/* validated against 73 samples spanning UPX 1.20 through 5.1.1. */
/* clam_upx.c calls these functions so the test harness exercises */
/* the same code path as libclamav/pe.c.                          */
/*                                                                */
/* Stub type codes (stub_out / stub_type parameter):             */
/*   UPX_STUB_NRV2B    1                                          */
/*   UPX_STUB_NRV2D    2                                          */
/*   UPX_STUB_NRV2E    3                                          */
/*   UPX_STUB_NRV2D_2E 4  (ambiguous; unpack tries both)         */
/*   UPX_STUB_LZMA     5                                          */

#define UPX_STUB_UNKNOWN  0
#define UPX_STUB_NRV2B    1
#define UPX_STUB_NRV2D    2
#define UPX_STUB_NRV2E    3
#define UPX_STUB_NRV2D_2E 4
#define UPX_STUB_LZMA     5
#define UPX_REBUILD_HEADROOM 8192u

 /* ====================================================================
  * Minimal section descriptor for is_upx_pe32/pe64.
  *
  * In the standalone build (clam_upx) the caller populates this from
  * its own SHDR struct.  In the libclamav build (pe.c) the caller
  * populates it from cli_exe_section (execs.h).  Only rsz and vsz are
  * needed for UPX section-pair detection.
  * ==================================================================== */
struct upx_pe_section_t {
	uint32_t rsz;   /* SizeOfRawData  (on-disk size, 0 = UPX0 pattern) */
	uint32_t vsz;   /* VirtualSize    (in-memory size)                  */
};
typedef struct upx_pe_section_t upx_pe_section_t;

/*
 * is_upx_pe32() -- detect UPX PE32 (x86); identify stub variant.
 * Returns 1 on success (i_out, stub_out populated), 0 if not UPX PE32.
 */
int is_upx_pe32(const struct upx_pe_section_t *sections, int nsections,
                const char *epbuff, size_t epbuff_len,
                unsigned int *i_out, int *stub_out);

/*
 * upx_unpack_pe32() -- dispatch to inflate engine for PE32 (x86).
 * Handles skew detection and LZMA property extraction internally.
 * Returns >= 0 on success, -1 on failure.
 */
int upx_unpack_pe32(const char *src, uint32_t ssize,
                    char *dst, uint32_t *dsize,
                    uint32_t upx0_rva, uint32_t upx1_rva, uint32_t ep_rva,
                    uint32_t imagebase,
                    const char *epbuff, size_t epbuff_len);

/*
 * is_upx_pe64() -- detect UPX PE32+ (x64); identify stub variant.
 * Returns 1 on success (i_out, magic_out[3], stub_out populated),
 *         0 if not UPX PE32+.
 */
int is_upx_pe64(const struct upx_pe_section_t *sections, int nsections,
                const char *epbuff, size_t epbuff_len,
                unsigned int *i_out, uint32_t *magic_out, int *stub_out);

/*
 * upx_unpack_pe64() -- dispatch to inflate*_pe64() engine for PE32+.
 * Decodes LZMA properties from src[0..1] and recovers strictdsize
 * from EP push imm32 instructions (LZMA stub only).
 * Returns >= 0 on success, -1 on failure.
 */
int upx_unpack_pe64(const char *src, uint32_t ssize,
                    char *dst, uint32_t *dsize,
                    uint32_t upx0_rva, uint32_t upx1_rva, uint32_t ep_rva,
                    const char *epbuff, size_t epbuff_len,
                    uint32_t *magic, int stub_type);


#endif

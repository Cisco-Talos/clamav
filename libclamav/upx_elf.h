/*
 * upx_elf.h
 *
 * Public interface for ELF UPX decompression (ELF32 i386 and ELF64 x86-64,
 * little-endian only).  Implementation in upx_elf.c.
 *
 * Supports all four UPX compression algorithms:
 *   NRV2B, NRV2D, NRV2E  (bit-stream LZ77 variants)
 *   LZMA                  (requires lzma_iface.c + LzmaDec.c)
 *
 * Supports all known UPX ELF format versions:
 *   UPX 1.x   raw 8-byte block headers, global method byte in pack trailer
 *   UPX 2.x   pack_hdr_a / pack_hdr_b / pack_block_hdr block headers (overlap-block aware)
 *   UPX 3.x+  same block format, different PT_LOAD layout
 *   UPX 2.x/3.x ELF64 with zeroed start pack_hdr_a (detected via end pack_hdr_a scan)
 */

#ifndef UPX_ELF_H
#define UPX_ELF_H

#include <stddef.h>   /* size_t */
#include <stdint.h>   /* uint8_t */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * DECOMP_OVERHEAD extra bytes allocated beyond the declared output size.
 *
 * Both ELF and PE decompressors allocate (expected_size + DECOMP_OVERHEAD)
 * to give the inflate engines a safe landing pad for one-byte overreads at
 * stream end.  Mirrors the headroom used in ClamAV's pe.c.
 */
#define DECOMP_OVERHEAD  8192u

/*
 * upx_unpack_elf_buf() framework-free UPX ELF decompression entry point.
 *
 * Detects and decompresses a UPX-packed ELF binary (all known format
 * versions: UPX 1.x through 5.x, ELF32 i386 and ELF64 x86-64, LE only).
 *
 * Designed for use by cli_unpackelf() in libclamav/elf.c as the native
 * C UPX unpacker, called before the BC_ELF_UNPACKER bytecode hook fallback.
 * Has no dependency on the ClamAV framework (no fmap, no cli_ctx) so
 * upx_elf.c remains buildable standalone.
 *
 * Parameters:
 *   buf      - entire packed file in memory (caller maps via fmap_need_off_once
 *              or equivalent; buffer must be at least fsz bytes)
 *   fsz       byte length of buf
 *   out       on success, receives a calloc'd buffer containing the
 *              decompressed ELF image; caller must free()
 *   out_used  on success, receives the byte count written into *out
 *
 * Returns:
 *    0   success  *out and *out_used are valid; caller owns the buffer
 *   -1   not a UPX-packed ELF  fall through to bytecode hook silently
 *   -2   UPX ELF detected but decompression failed  log and fall through
 *
 * Security model:
 *   Every field read from buf is labelled [FROM FILE] in the implementation
 *   and is bounds-checked or range-validated before use.
 */
int upx_unpack_elf_buf(const uint8_t *buf, size_t fsz,
                       uint8_t **out, uint32_t *out_used);

/*
 * handle_elf()  standalone tool entry point.
 *
 * Detects, decompresses, and writes the recovered ELF image to outfile.
 * Used by the clam_upx standalone binary; not for libclamav integration
 * (use upx_unpack_elf_buf() instead).
 *
 * Parameters:
 *   filebuf    entire packed file in memory (caller owns)
 *   fsz        byte length of filebuf (must be >= ELF header size)
 *   outfile    path to write decompressed output
 *
 * Returns:
 *   0   success  outfile written
 *   1   failure  reason printed to stderr, no output written
 */
int handle_elf(const uint8_t *filebuf, size_t fsz, const char *outfile);

#ifdef __cplusplus
}
#endif

#endif /* UPX_ELF_H */

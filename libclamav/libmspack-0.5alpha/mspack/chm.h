/* This file is part of libmspack.
 * (C) 2003-2004 Stuart Caie.
 *
 * libmspack is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License (LGPL) version 2.1
 *
 * For further details, see the file COPYING.LIB distributed with libmspack
 */

#ifndef MSPACK_CHM_H
#define MSPACK_CHM_H 1

#include <lzx.h>

/* generic CHM definitions */

#define chmhead_Signature   (0x0000)
#define chmhead_Version     (0x0004)
#define chmhead_HeaderLen   (0x0008)
#define chmhead_Unknown1    (0x000C)
#define chmhead_Timestamp   (0x0010)
#define chmhead_LanguageID  (0x0014)
#define chmhead_GUID1       (0x0018)
#define chmhead_GUID2       (0x0028)
#define chmhead_SIZEOF      (0x0038)

#define chmhst_OffsetHS0    (0x0000)
#define chmhst_LengthHS0    (0x0008)
#define chmhst_OffsetHS1    (0x0010)
#define chmhst_LengthHS1    (0x0018)
#define chmhst_SIZEOF       (0x0020)
#define chmhst3_OffsetCS0   (0x0020)
#define chmhst3_SIZEOF      (0x0028)

#define chmhs0_Unknown1     (0x0000)
#define chmhs0_Unknown2     (0x0004)
#define chmhs0_FileLen      (0x0008)
#define chmhs0_Unknown3     (0x0010)
#define chmhs0_Unknown4     (0x0014)
#define chmhs0_SIZEOF       (0x0018)

#define chmhs1_Signature    (0x0000)
#define chmhs1_Version      (0x0004)
#define chmhs1_HeaderLen    (0x0008)
#define chmhs1_Unknown1     (0x000C)
#define chmhs1_ChunkSize    (0x0010)
#define chmhs1_Density      (0x0014)
#define chmhs1_Depth        (0x0018)
#define chmhs1_IndexRoot    (0x001C)
#define chmhs1_FirstPMGL    (0x0020)
#define chmhs1_LastPMGL     (0x0024)
#define chmhs1_Unknown2     (0x0028)
#define chmhs1_NumChunks    (0x002C)
#define chmhs1_LanguageID   (0x0030)
#define chmhs1_GUID         (0x0034)
#define chmhs1_Unknown3     (0x0044)
#define chmhs1_Unknown4     (0x0048)
#define chmhs1_Unknown5     (0x004C)
#define chmhs1_Unknown6     (0x0050)
#define chmhs1_SIZEOF       (0x0054)

#define pmgl_Signature      (0x0000)
#define pmgl_QuickRefSize   (0x0004)
#define pmgl_Unknown1       (0x0008)
#define pmgl_PrevChunk      (0x000C)
#define pmgl_NextChunk      (0x0010)
#define pmgl_Entries        (0x0014)
#define pmgl_headerSIZEOF   (0x0014)

#define pmgi_Signature      (0x0000)
#define pmgi_QuickRefSize   (0x0004)
#define pmgi_Entries        (0x0008)
#define pmgi_headerSIZEOF   (0x000C)

#define lzxcd_Length        (0x0000)
#define lzxcd_Signature     (0x0004)
#define lzxcd_Version       (0x0008)
#define lzxcd_ResetInterval (0x000C)
#define lzxcd_WindowSize    (0x0010)
#define lzxcd_CacheSize     (0x0014)
#define lzxcd_Unknown1      (0x0018)
#define lzxcd_SIZEOF        (0x001C)

#define lzxrt_Unknown1      (0x0000)
#define lzxrt_NumEntries    (0x0004)
#define lzxrt_EntrySize     (0x0008)
#define lzxrt_TableOffset   (0x000C)
#define lzxrt_UncompLen     (0x0010)
#define lzxrt_CompLen       (0x0018)
#define lzxrt_FrameLen      (0x0020)
#define lzxrt_Entries       (0x0028)
#define lzxrt_headerSIZEOF  (0x0028)

/* CHM compression definitions */

struct mschm_compressor_p {
  struct mschm_compressor base;
  struct mspack_system *system;
  char *temp_file;
  int use_temp_file;
  int error;
};

/* CHM decompression definitions */
struct mschmd_decompress_state {
  struct mschmd_header *chm;         /* CHM file being decompressed          */
  off_t offset;                      /* uncompressed offset within folder    */
  off_t inoffset;                    /* offset in input file                 */
  struct lzxd_stream *state;         /* LZX decompressor state               */
  struct mspack_system sys;          /* special I/O code for decompressor    */
  struct mspack_file *infh;          /* input file handle                    */
  struct mspack_file *outfh;         /* output file handle                   */
};

struct mschm_decompressor_p {
  struct mschm_decompressor base;
  struct mspack_system *system;
  struct mschmd_decompress_state *d;
  int error;
};

#endif

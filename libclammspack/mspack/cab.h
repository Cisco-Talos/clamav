/* This file is part of libmspack.
 * (C) 2003-2018 Stuart Caie.
 *
 * libmspack is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License (LGPL) version 2.1
 *
 * For further details, see the file COPYING.LIB distributed with libmspack
 */

#ifndef MSPACK_CAB_H
#define MSPACK_CAB_H 1

/* generic CAB definitions */

/* structure offsets */
#define cfhead_Signature         (0x00)
#define cfhead_CabinetSize       (0x08)
#define cfhead_FileOffset        (0x10)
#define cfhead_MinorVersion      (0x18)
#define cfhead_MajorVersion      (0x19)
#define cfhead_NumFolders        (0x1A)
#define cfhead_NumFiles          (0x1C)
#define cfhead_Flags             (0x1E)
#define cfhead_SetID             (0x20)
#define cfhead_CabinetIndex      (0x22)
#define cfhead_SIZEOF            (0x24)
#define cfheadext_HeaderReserved (0x00)
#define cfheadext_FolderReserved (0x02)
#define cfheadext_DataReserved   (0x03)
#define cfheadext_SIZEOF         (0x04)
#define cffold_DataOffset        (0x00)
#define cffold_NumBlocks         (0x04)
#define cffold_CompType          (0x06)
#define cffold_SIZEOF            (0x08)
#define cffile_UncompressedSize  (0x00)
#define cffile_FolderOffset      (0x04)
#define cffile_FolderIndex       (0x08)
#define cffile_Date              (0x0A)
#define cffile_Time              (0x0C)
#define cffile_Attribs           (0x0E)
#define cffile_SIZEOF            (0x10)
#define cfdata_CheckSum          (0x00)
#define cfdata_CompressedSize    (0x04)
#define cfdata_UncompressedSize  (0x06)
#define cfdata_SIZEOF            (0x08)

/* flags */
#define cffoldCOMPTYPE_MASK            (0x000f)
#define cffoldCOMPTYPE_NONE            (0x0000)
#define cffoldCOMPTYPE_MSZIP           (0x0001)
#define cffoldCOMPTYPE_QUANTUM         (0x0002)
#define cffoldCOMPTYPE_LZX             (0x0003)
#define cfheadPREV_CABINET             (0x0001)
#define cfheadNEXT_CABINET             (0x0002)
#define cfheadRESERVE_PRESENT          (0x0004)
#define cffileCONTINUED_FROM_PREV      (0xFFFD)
#define cffileCONTINUED_TO_NEXT        (0xFFFE)
#define cffileCONTINUED_PREV_AND_NEXT  (0xFFFF)

/* CAB data blocks are <= 32768 bytes in uncompressed form. Uncompressed
 * blocks have zero growth. MSZIP guarantees that it won't grow above
 * uncompressed size by more than 12 bytes. LZX guarantees it won't grow
 * more than 6144 bytes. Quantum has no documentation, but the largest
 * block seen in the wild is 337 bytes above uncompressed size.
 */
#define CAB_BLOCKMAX (32768)
#define CAB_INPUTMAX (CAB_BLOCKMAX+6144)

/* input buffer needs to be CAB_INPUTMAX + 1 byte to allow for max-sized block
 * plus 1 trailer byte added by cabd_sys_read_block() for Quantum alignment.
 *
 * When MSCABD_PARAM_SALVAGE is set, block size is not checked so can be
 * up to 65535 bytes, so max input buffer size needed is 65535 + 1
 */
#define CAB_INPUTMAX_SALVAGE (65535)
#define CAB_INPUTBUF (CAB_INPUTMAX_SALVAGE + 1)

/* There are no more than 65535 data blocks per folder, so a folder cannot
 * be more than 32768*65535 bytes in length. As files cannot span more than
 * one folder, this is also their max offset, length and offset+length limit.
 */
#define CAB_FOLDERMAX (65535)
#define CAB_LENGTHMAX (CAB_BLOCKMAX * CAB_FOLDERMAX)

/* CAB compression definitions */

struct mscab_compressor_p {
  struct mscab_compressor base;
  struct mspack_system *system;
  /* todo */
};

/* CAB decompression definitions */

struct mscabd_decompress_state {
  struct mscabd_folder_p *folder;    /* current folder we're extracting from */
  struct mscabd_folder_data *data;   /* current folder split we're in        */
  unsigned int offset;               /* uncompressed offset within folder    */
  unsigned int block;                /* which block are we decompressing?    */
  off_t outlen;                      /* cumulative sum of block output sizes */
  struct mspack_system sys;          /* special I/O code for decompressor    */
  int comp_type;                     /* type of compression used by folder   */
  int (*decompress)(void *, off_t);  /* decompressor code                    */
  void *state;                       /* decompressor state                   */
  struct mscabd_cabinet_p *incab;    /* cabinet where input data comes from  */
  struct mspack_file *infh;          /* input file handle                    */
  struct mspack_file *outfh;         /* output file handle                   */
  unsigned char *i_ptr, *i_end;      /* input data consumed, end             */
  unsigned char input[CAB_INPUTBUF]; /* one input block of data              */
};

struct mscab_decompressor_p {
  struct mscab_decompressor base;
  struct mscabd_decompress_state *d;
  struct mspack_system *system;
  int buf_size, searchbuf_size, fix_mszip, salvage; /* params */
  int error, read_error;
};

struct mscabd_cabinet_p {
  struct mscabd_cabinet base;
  off_t blocks_off;                  /* offset to data blocks                */
  int block_resv;                    /* reserved space in data blocks        */
};

/* there is one of these for every cabinet a folder spans */
struct mscabd_folder_data {
  struct mscabd_folder_data *next;
  struct mscabd_cabinet_p *cab;      /* cabinet file of this folder span     */
  off_t offset;                      /* cabinet offset of first datablock    */
};

struct mscabd_folder_p {
  struct mscabd_folder base;
  struct mscabd_folder_data data;    /* where are the data blocks?           */
  struct mscabd_file *merge_prev;    /* first file needing backwards merge   */
  struct mscabd_file *merge_next;    /* first file needing forwards merge    */
};

#endif

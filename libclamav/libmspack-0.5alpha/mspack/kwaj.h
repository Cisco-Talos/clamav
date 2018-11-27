/* This file is part of libmspack.
 * (C) 2003-2010 Stuart Caie.
 *
 * libmspack is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License (LGPL) version 2.1
 *
 * For further details, see the file COPYING.LIB distributed with libmspack
 */

#ifndef MSPACK_KWAJ_H
#define MSPACK_KWAJ_H 1

#include <lzss.h>

/* generic KWAJ definitions */
#define kwajh_Signature1 (0x00)
#define kwajh_Signature2 (0x04)
#define kwajh_CompMethod (0x08)
#define kwajh_DataOffset (0x0a)
#define kwajh_Flags      (0x0c)
#define kwajh_SIZEOF     (0x0e)

/* KWAJ compression definitions */

struct mskwaj_compressor_p {
  struct mskwaj_compressor base;
  struct mspack_system *system;
  /* todo */
  int param[2]; /* !!! MATCH THIS TO NUM OF PARAMS IN MSPACK.H !!! */
  int error;
};

/* KWAJ decompression definitions */

struct mskwaj_decompressor_p {
  struct mskwaj_decompressor base;
  struct mspack_system *system;
  int error;
};

struct mskwajd_header_p {
  struct mskwajd_header base;
  struct mspack_file *fh;
};

/* input buffer size during decompression - not worth parameterising IMHO */
#define KWAJ_INPUT_SIZE (2048)

/* huffman codes that are 9 bits or less are decoded immediately */
#define KWAJ_TABLEBITS (9)

/* number of codes in each huffman table */
#define KWAJ_MATCHLEN1_SYMS (16)
#define KWAJ_MATCHLEN2_SYMS (16)
#define KWAJ_LITLEN_SYMS    (32)
#define KWAJ_OFFSET_SYMS    (64)
#define KWAJ_LITERAL_SYMS   (256)

/* define decoding table sizes */
#define KWAJ_TABLESIZE (1 << KWAJ_TABLEBITS)
#if KWAJ_TABLESIZE < (KWAJ_MATCHLEN1_SYMS * 2)
# define KWAJ_MATCHLEN1_TBLSIZE (KWAJ_MATCHLEN1_SYMS * 4)
#else
# define KWAJ_MATCHLEN1_TBLSIZE (KWAJ_TABLESIZE + (KWAJ_MATCHLEN1_SYMS * 2))
#endif
#if KWAJ_TABLESIZE < (KWAJ_MATCHLEN2_SYMS * 2)
# define KWAJ_MATCHLEN2_TBLSIZE (KWAJ_MATCHLEN2_SYMS * 4)
#else
# define KWAJ_MATCHLEN2_TBLSIZE (KWAJ_TABLESIZE + (KWAJ_MATCHLEN2_SYMS * 2))
#endif
#if KWAJ_TABLESIZE < (KWAJ_LITLEN_SYMS * 2)
# define KWAJ_LITLEN_TBLSIZE (KWAJ_LITLEN_SYMS * 4)
#else
# define KWAJ_LITLEN_TBLSIZE (KWAJ_TABLESIZE + (KWAJ_LITLEN_SYMS * 2))
#endif
#if KWAJ_TABLESIZE < (KWAJ_OFFSET_SYMS * 2)
# define KWAJ_OFFSET_TBLSIZE (KWAJ_OFFSET_SYMS * 4)
#else
# define KWAJ_OFFSET_TBLSIZE (KWAJ_TABLESIZE + (KWAJ_OFFSET_SYMS * 2))
#endif
#if KWAJ_TABLESIZE < (KWAJ_LITERAL_SYMS * 2)
# define KWAJ_LITERAL_TBLSIZE (KWAJ_LITERAL_SYMS * 4)
#else
# define KWAJ_LITERAL_TBLSIZE (KWAJ_TABLESIZE + (KWAJ_LITERAL_SYMS * 2))
#endif

struct kwajd_stream {
    /* I/O buffering */
    struct mspack_system *sys;
    struct mspack_file *input;
    struct mspack_file *output;
    unsigned char *i_ptr, *i_end;
    unsigned int bit_buffer, bits_left;
    int input_end;

    /* huffman code lengths */
    unsigned char  MATCHLEN1_len [KWAJ_MATCHLEN1_SYMS];
    unsigned char  MATCHLEN2_len [KWAJ_MATCHLEN2_SYMS];
    unsigned char  LITLEN_len    [KWAJ_LITLEN_SYMS];
    unsigned char  OFFSET_len    [KWAJ_OFFSET_SYMS];
    unsigned char  LITERAL_len   [KWAJ_LITERAL_SYMS];

    /* huffman decoding tables */
    unsigned short MATCHLEN1_table [KWAJ_MATCHLEN1_TBLSIZE];
    unsigned short MATCHLEN2_table [KWAJ_MATCHLEN2_TBLSIZE];
    unsigned short LITLEN_table    [KWAJ_LITLEN_TBLSIZE];
    unsigned short OFFSET_table    [KWAJ_OFFSET_TBLSIZE];
    unsigned short LITERAL_table   [KWAJ_LITERAL_TBLSIZE];

    /* input buffer */
    unsigned char inbuf[KWAJ_INPUT_SIZE];

    /* history window */
    unsigned char window[LZSS_WINDOW_SIZE];
};


#endif

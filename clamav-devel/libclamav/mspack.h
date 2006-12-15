/*
 * This file includes code from libmspack adapted for libclamav by
 * tkojm@clamav.net
 *
 * Copyright (C) 2003-2004 Stuart Caie
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301
 * USA
 */

#ifndef __MSPACK_H
#define __MSPACK_H

#include <sys/types.h>
#include "cab.h"


/***************************************************************************
 *			 MS-ZIP decompression definitions                  *
 ***************************************************************************/

#define MSZIP_FRAME_SIZE          (32768) /* size of LZ history window */
#define MSZIP_MAX_HUFFBITS        (16)    /* maximum huffman code length */
#define MSZIP_LITERAL_MAXSYMBOLS  (288)   /* literal/length huffman tree */
#define MSZIP_LITERAL_TABLEBITS   (9)
#define MSZIP_DISTANCE_MAXSYMBOLS (32)    /* distance huffman tree */
#define MSZIP_DISTANCE_TABLEBITS  (6)

/* if there are less direct lookup entries than symbols, the longer
 * code pointers will be <= maxsymbols. This must not happen, or we
 * will decode entries badly */
#if (1 << MSZIP_LITERAL_TABLEBITS) < (MSZIP_LITERAL_MAXSYMBOLS * 2)
# define MSZIP_LITERAL_TABLESIZE (MSZIP_LITERAL_MAXSYMBOLS * 4)
#else
# define MSZIP_LITERAL_TABLESIZE ((1 << MSZIP_LITERAL_TABLEBITS) + \
				  (MSZIP_LITERAL_MAXSYMBOLS * 2))
#endif

#if (1 << MSZIP_DISTANCE_TABLEBITS) < (MSZIP_DISTANCE_MAXSYMBOLS * 2)
# define MSZIP_DISTANCE_TABLESIZE (MSZIP_DISTANCE_MAXSYMBOLS * 4)
#else
# define MSZIP_DISTANCE_TABLESIZE ((1 << MSZIP_DISTANCE_TABLEBITS) + \
				  (MSZIP_DISTANCE_MAXSYMBOLS * 2))
#endif

struct mszip_stream {
  int fd;		    /* input file descriptor */
  int ofd;                  /* output file descriptor */
  unsigned char wflag;	    /* write flag */

  unsigned int window_posn;             /* offset within window  */

  /* inflate() will call this whenever the window should be emptied. */
  int (*flush_window)(struct mszip_stream *, unsigned int);

  int error, repair_mode, bytes_output, input_end;

  /* I/O buffering */
  unsigned char *inbuf, *i_ptr, *i_end, *o_ptr, *o_end;
  unsigned int bit_buffer, bits_left, inbuf_size;

  /* huffman code lengths */
  unsigned char  LITERAL_len[MSZIP_LITERAL_MAXSYMBOLS];
  unsigned char  DISTANCE_len[MSZIP_DISTANCE_MAXSYMBOLS];

  /* huffman decoding tables */
  unsigned short LITERAL_table [MSZIP_LITERAL_TABLESIZE];
  unsigned short DISTANCE_table[MSZIP_DISTANCE_TABLESIZE];

  /* 32kb history window */
  unsigned char window[MSZIP_FRAME_SIZE];

  /* cabinet related stuff */
  struct cab_file *file;
  int (*read)(struct cab_file *, unsigned char *, int);
};

struct mszip_stream *mszip_init(int fd,
				  int ofd,
				  int input_buffer_size,
				  int repair_mode,
				  struct cab_file *file,
			          int (*read)(struct cab_file *, unsigned char *, int));

extern int mszip_decompress(struct mszip_stream *zip, off_t out_bytes);

void mszip_free(struct mszip_stream *zip);


/***************************************************************************
 *			 Quantum decompression definitions                 *
 ***************************************************************************/

/* Quantum compression / decompression definitions */

#define QTM_FRAME_SIZE (32768)

struct qtm_modelsym {
  unsigned short sym, cumfreq;
};

struct qtm_model {
  int shiftsleft, entries;
  struct qtm_modelsym *syms;
};

struct qtm_stream {
  int fd;                   /* input file descriptor */
  int ofd;                  /* output file descriptor */
  unsigned char wflag;	    /* write flag */

  unsigned char *window;          /* decoding window                         */
  unsigned int window_size;       /* window size                             */
  unsigned int window_posn;       /* decompression offset within window      */
  unsigned int frame_start;       /* start of current frame within window    */

  unsigned short H, L, C;         /* high/low/current: arith coding state    */
  unsigned char header_read;      /* have we started decoding a new frame?   */

  int error;

  /* I/O buffers */
  unsigned char *inbuf, *i_ptr, *i_end, *o_ptr, *o_end;
  unsigned int  bit_buffer, inbuf_size;
  unsigned char bits_left;

  /* data tables */
  unsigned int  position_base[42];
  unsigned char extra_bits[42], length_base[27], length_extra[27];

  /* four literal models, each representing 64 symbols
   * model0 for literals from   0 to  63 (selector = 0)
   * model1 for literals from  64 to 127 (selector = 1)
   * model2 for literals from 128 to 191 (selector = 2)
   * model3 for literals from 129 to 255 (selector = 3) */
  struct qtm_model model0, model1, model2, model3;

  /* three match models.
   * model4 for match with fixed length of 3 bytes
   * model5 for match with fixed length of 4 bytes
   * model6 for variable length match, encoded with model6len model */
  struct qtm_model model4, model5, model6, model6len;

  /* selector model. 0-6 to say literal (0,1,2,3) or match (4,5,6) */
  struct qtm_model model7;

  /* symbol arrays for all models */
  struct qtm_modelsym m0sym[64 + 1];
  struct qtm_modelsym m1sym[64 + 1];
  struct qtm_modelsym m2sym[64 + 1];
  struct qtm_modelsym m3sym[64 + 1];
  struct qtm_modelsym m4sym[24 + 1];
  struct qtm_modelsym m5sym[36 + 1];
  struct qtm_modelsym m6sym[42 + 1], m6lsym[27 + 1];
  struct qtm_modelsym m7sym[7 + 1];

  /* cabinet related stuff */
  struct cab_file *file;
  int (*read)(struct cab_file *, unsigned char *, int);

};

extern struct qtm_stream *qtm_init(int fd,
				     int ofd,
				     int window_bits,
				     int input_buffer_size,
				     struct cab_file *file,
				     int (*read)(struct cab_file *, unsigned char *, int));

extern int qtm_decompress(struct qtm_stream *qtm, off_t out_bytes);

void qtm_free(struct qtm_stream *qtm);

/***************************************************************************
 *			 LZX decompression definitions                     *
 ***************************************************************************/

/* some constants defined by the LZX specification */
#define LZX_MIN_MATCH                (2)
#define LZX_MAX_MATCH                (257)
#define LZX_NUM_CHARS                (256)
#define LZX_BLOCKTYPE_INVALID        (0)   /* also blocktypes 4-7 invalid */
#define LZX_BLOCKTYPE_VERBATIM       (1)
#define LZX_BLOCKTYPE_ALIGNED        (2)
#define LZX_BLOCKTYPE_UNCOMPRESSED   (3)
#define LZX_PRETREE_NUM_ELEMENTS     (20)
#define LZX_ALIGNED_NUM_ELEMENTS     (8)   /* aligned offset tree #elements */
#define LZX_NUM_PRIMARY_LENGTHS      (7)   /* this one missing from spec! */
#define LZX_NUM_SECONDARY_LENGTHS    (249) /* length tree #elements */

/* LZX huffman defines: tweak tablebits as desired */
#define LZX_PRETREE_MAXSYMBOLS  (LZX_PRETREE_NUM_ELEMENTS)
#define LZX_PRETREE_TABLEBITS   (6)
#define LZX_MAINTREE_MAXSYMBOLS (LZX_NUM_CHARS + 50*8)
#define LZX_MAINTREE_TABLEBITS  (12)
#define LZX_LENGTH_MAXSYMBOLS   (LZX_NUM_SECONDARY_LENGTHS+1)
#define LZX_LENGTH_TABLEBITS    (12)
#define LZX_ALIGNED_MAXSYMBOLS  (LZX_ALIGNED_NUM_ELEMENTS)
#define LZX_ALIGNED_TABLEBITS   (7)
#define LZX_LENTABLE_SAFETY (64)  /* table decoding overruns are allowed */

#define LZX_FRAME_SIZE (32768) /* the size of a frame in LZX */

struct lzx_stream {
  int fd;			  /* input file descriptor                   */
  int ofd;			  /* output file descriptor                  */
  unsigned char wflag;		  /* write flag */

  off_t   offset;                 /* number of bytes actually output         */
  off_t   length;                 /* overall decompressed length of stream   */

  unsigned char *window;          /* decoding window                         */
  unsigned int   window_size;     /* window size                             */
  unsigned int   window_posn;     /* decompression offset within window      */
  unsigned int   frame_posn;      /* current frame offset within in window   */
  unsigned int   frame;           /* the number of 32kb frames processed     */
  unsigned int   reset_interval;  /* which frame do we reset the compressor? */

  unsigned int   R0, R1, R2;      /* for the LRU offset system               */
  unsigned int   block_length;    /* uncompressed length of this LZX block   */
  unsigned int   block_remaining; /* uncompressed bytes still left to decode */

  signed int     intel_filesize;  /* magic header value used for transform   */
  signed int     intel_curpos;    /* current offset in transform space       */

  unsigned char  intel_started;   /* has intel E8 decoding started?          */
  unsigned char  block_type;      /* type of the current block               */
  unsigned char  header_read;     /* have we started decoding at all yet?    */
  unsigned char  posn_slots;      /* how many posn slots in stream?          */
  unsigned char  input_end;       /* have we reached the end of input?       */

  int error;

  /* I/O buffering */
  unsigned char *inbuf, *i_ptr, *i_end, *o_ptr, *o_end;
  unsigned int  bit_buffer, bits_left, inbuf_size;

  /* huffman code lengths */
  unsigned char PRETREE_len  [LZX_PRETREE_MAXSYMBOLS  + LZX_LENTABLE_SAFETY];
  unsigned char MAINTREE_len [LZX_MAINTREE_MAXSYMBOLS + LZX_LENTABLE_SAFETY];
  unsigned char LENGTH_len   [LZX_LENGTH_MAXSYMBOLS   + LZX_LENTABLE_SAFETY];
  unsigned char ALIGNED_len  [LZX_ALIGNED_MAXSYMBOLS  + LZX_LENTABLE_SAFETY];

  /* huffman decoding tables */
  unsigned short PRETREE_table [(1 << LZX_PRETREE_TABLEBITS) +
				(LZX_PRETREE_MAXSYMBOLS * 2)];
  unsigned short MAINTREE_table[(1 << LZX_MAINTREE_TABLEBITS) +
				(LZX_MAINTREE_MAXSYMBOLS * 2)];
  unsigned short LENGTH_table  [(1 << LZX_LENGTH_TABLEBITS) +
				(LZX_LENGTH_MAXSYMBOLS * 2)];
  unsigned short ALIGNED_table [(1 << LZX_ALIGNED_TABLEBITS) +
				(LZX_ALIGNED_MAXSYMBOLS * 2)];

  unsigned int  position_base[51];
  unsigned char extra_bits[51];

  /* this is used purely for doing the intel E8 transform */
  unsigned char  e8_buf[LZX_FRAME_SIZE];

  /* cabinet related stuff */
  struct cab_file *file;
  int (*read)(struct cab_file *, unsigned char *, int);
};

struct lzx_stream *lzx_init(int fd,
			      int ofd,
			      int window_bits,
			      int reset_interval,
			      int input_buffer_size,
			      off_t output_length,
			      struct cab_file *file,
			      int (*read)(struct cab_file *, unsigned char *, int));

extern void lzx_set_output_length(struct lzx_stream *lzx,
				   off_t output_length);

extern int lzx_decompress(struct lzx_stream *lzx, off_t out_bytes);

void lzx_free(struct lzx_stream *lzx);

#endif

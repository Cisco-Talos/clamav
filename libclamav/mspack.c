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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <string.h>

#include "others.h"
#include "clamav.h"
#include "mspack.h"

#if HAVE_LIMITS_H
# include <limits.h>
#endif
#ifndef CHAR_BIT
# define CHAR_BIT (8)
#endif


/***************************************************************************
 *			 MS-ZIP decompression implementation 
 ***************************************************************************
 * The LZX method was created by Jonathan Forbes and Tomi Poutanen, adapted
 * by Microsoft Corporation.
 *
 * The deflate method was created by Phil Katz. MSZIP is equivalent to the
 * deflate method.
 *
 */

/* match lengths for literal codes 257.. 285 */
static const unsigned short mszip_lit_lengths[29] = {
  3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27,
  31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258
};

/* match offsets for distance codes 0 .. 29 */
static const unsigned short mszip_dist_offsets[30] = {
  1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385,
  513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577
};

/* extra bits required for literal codes 257.. 285 */
static const unsigned char mszip_lit_extrabits[29] = {
  0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2,
  2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0
};

/* extra bits required for distance codes 0 .. 29 */
static const unsigned char mszip_dist_extrabits[30] = {
  0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6,
  6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13
};

/* the order of the bit length Huffman code lengths */
static const unsigned char mszip_bitlen_order[19] = {
  16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
};

/* ANDing with mszip_bit_mask[n] masks the lower n bits */
static const unsigned short mszip_bit_mask_tab[17] = {
 0x0000, 0x0001, 0x0003, 0x0007, 0x000f, 0x001f, 0x003f, 0x007f, 0x00ff,
 0x01ff, 0x03ff, 0x07ff, 0x0fff, 0x1fff, 0x3fff, 0x7fff, 0xffff
};

#define MSZIP_STORE_BITS do {                                                 \
  zip->i_ptr      = i_ptr;                                              \
  zip->i_end      = i_end;                                              \
  zip->bit_buffer = bit_buffer;                                         \
  zip->bits_left  = bits_left;                                          \
} while (0)

#define MSZIP_RESTORE_BITS do {                                               \
  i_ptr      = zip->i_ptr;                                              \
  i_end      = zip->i_end;                                              \
  bit_buffer = zip->bit_buffer;                                         \
  bits_left  = zip->bits_left;                                          \
} while (0)

#define MSZIP_ENSURE_BITS(nbits) do {                                         \
  while (bits_left < (nbits)) {                                         \
    if (i_ptr >= i_end) {                                               \
      if (mszip_read_input(zip)) return zip->error;                      \
      i_ptr = zip->i_ptr;                                               \
      i_end = zip->i_end;                                               \
    }                                                                   \
    bit_buffer |= *i_ptr++ << bits_left; bits_left  += 8;               \
  }                                                                     \
} while (0)

#define MSZIP_PEEK_BITS(nbits)   (bit_buffer & ((1<<(nbits))-1))
#define MSZIP_PEEK_BITS_T(nbits) (bit_buffer & mszip_bit_mask_tab[(nbits)])

#define MSZIP_REMOVE_BITS(nbits) ((bit_buffer >>= (nbits)), (bits_left -= (nbits)))

#define MSZIP_READ_BITS(val, nbits) do {                                      \
  MSZIP_ENSURE_BITS(nbits); (val) = MSZIP_PEEK_BITS(nbits); MSZIP_REMOVE_BITS(nbits);     \
} while (0)

#define MSZIP_READ_BITS_T(val, nbits) do {                                    \
  MSZIP_ENSURE_BITS(nbits); (val) = MSZIP_PEEK_BITS_T(nbits); MSZIP_REMOVE_BITS(nbits);   \
} while (0)

static int mszip_read_input(struct mszip_stream *zip) {
  int read = zip->read ? zip->read(zip->file, zip->inbuf, (int)zip->inbuf_size) : cli_readn(zip->fd, zip->inbuf, (int)zip->inbuf_size);
  if (read < 0) return zip->error = CL_EIO;

  if (read == 0) {
    if (zip->input_end) {
      cli_dbgmsg("mszip_read_input: out of input bytes\n");
      return zip->error = CL_EIO;
    }
    else {
      read = 1;
      zip->inbuf[0] = 0;
      zip->input_end = 1;
    }
  }

  zip->i_ptr = &zip->inbuf[0];
  zip->i_end = &zip->inbuf[read];

  return CL_SUCCESS;
}

/* inflate() error codes */
#define INF_ERR_BLOCKTYPE   (-1)  /* unknown block type                      */
#define INF_ERR_COMPLEMENT  (-2)  /* block size complement mismatch          */
#define INF_ERR_FLUSH       (-3)  /* error from flush_window() callback      */
#define INF_ERR_BITBUF      (-4)  /* too many bits in bit buffer             */
#define INF_ERR_SYMLENS     (-5)  /* too many symbols in blocktype 2 header  */
#define INF_ERR_BITLENTBL   (-6)  /* failed to build bitlens huffman table   */
#define INF_ERR_LITERALTBL  (-7)  /* failed to build literals huffman table  */
#define INF_ERR_DISTANCETBL (-8)  /* failed to build distance huffman table  */
#define INF_ERR_BITOVERRUN  (-9)  /* bitlen RLE code goes over table size    */
#define INF_ERR_BADBITLEN   (-10) /* invalid bit-length code                 */
#define INF_ERR_LITCODE     (-11) /* out-of-range literal code               */
#define INF_ERR_DISTCODE    (-12) /* out-of-range distance code              */
#define INF_ERR_DISTANCE    (-13) /* somehow, distance is beyond 32k         */
#define INF_ERR_HUFFSYM     (-14) /* out of bits decoding huffman symbol     */

/* mszip_make_decode_table(nsyms, nbits, length[], table[])
 *
 * This function was coded by David Tritscher. It builds a fast huffman
 * decoding table out of just a canonical huffman code lengths table.
 *
 * NOTE: this is NOT identical to the mszip_make_decode_table() in lzxd.c. This
 * one reverses the quick-lookup bit pattern. Bits are read MSB to LSB in LZX,
 * but LSB to MSB in MSZIP.
 *
 * nsyms  = total number of symbols in this huffman tree.
 * nbits  = any symbols with a code length of nbits or less can be decoded
 *          in one lookup of the table.
 * length = A table to get code lengths from [0 to nsyms-1]
 * table  = The table to fill up with decoded symbols and pointers.
 *
 * Returns 0 for OK or 1 for error
 */
static int mszip_make_decode_table(unsigned int nsyms, unsigned int nbits,
			     unsigned char *length, unsigned short *table)
{
  register unsigned int leaf, reverse, fill;
  register unsigned short sym, next_sym;
  register unsigned char bit_num;
  unsigned int pos         = 0; /* the current position in the decode table */
  unsigned int table_mask  = 1 << nbits;
  unsigned int mszip_bit_mask    = table_mask >> 1; /* don't do 0 length codes */

  /* fill entries for codes short enough for a direct mapping */
  for (bit_num = 1; bit_num <= nbits; bit_num++) {
    for (sym = 0; sym < nsyms; sym++) {
      if (length[sym] != bit_num) continue;

      /* reverse the significant bits */
      fill = length[sym]; reverse = pos >> (nbits - fill); leaf = 0;
      do {leaf <<= 1; leaf |= reverse & 1; reverse >>= 1;} while (--fill);

      if((pos += mszip_bit_mask) > table_mask) return 1; /* table overrun */

      /* fill all possible lookups of this symbol with the symbol itself */
      fill = mszip_bit_mask; next_sym = 1 << bit_num;
      do { table[leaf] = sym; leaf += next_sym; } while (--fill);
    }
    mszip_bit_mask >>= 1;
  }

  /* exit with success if table is now complete */
  if (pos == table_mask) return 0;

  /* mark all remaining table entries as unused */
  for (sym = pos; sym < table_mask; sym++) {
    reverse = sym; leaf = 0; fill = nbits;
    do { leaf <<= 1; leaf |= reverse & 1; reverse >>= 1; } while (--fill);
    table[leaf] = 0xFFFF;
  }

  /* where should the longer codes be allocated from? */
  next_sym = ((table_mask >> 1) < nsyms) ? nsyms : (table_mask >> 1);

  /* give ourselves room for codes to grow by up to 16 more bits.
   * codes now start at bit nbits+16 and end at (nbits+16-codelength) */
  pos <<= 16;
  table_mask <<= 16;
  mszip_bit_mask = 1 << 15;

  for (bit_num = nbits+1; bit_num <= MSZIP_MAX_HUFFBITS; bit_num++) {
    for (sym = 0; sym < nsyms; sym++) {
      if (length[sym] != bit_num) continue;

      /* leaf = the first nbits of the code, reversed */
      reverse = pos >> 16; leaf = 0; fill = nbits;
      do {leaf <<= 1; leaf |= reverse & 1; reverse >>= 1;} while (--fill);

      for (fill = 0; fill < (bit_num - nbits); fill++) {
	/* if this path hasn't been taken yet, 'allocate' two entries */
	if (table[leaf] == 0xFFFF) {
	  table[(next_sym << 1)     ] = 0xFFFF;
	  table[(next_sym << 1) + 1 ] = 0xFFFF;
	  table[leaf] = next_sym++;
	}
	/* follow the path and select either left or right for next bit */
	leaf = (table[leaf] << 1) | ((pos >> (15 - fill)) & 1);
      }
      table[leaf] = sym;

      if ((pos += mszip_bit_mask) > table_mask) return 1; /* table overflow */
    }
    mszip_bit_mask >>= 1;
  }

  /* full table? */
  return (pos != table_mask) ? 1 : 0;
}

/* MSZIP_READ_HUFFSYM(tablename, var) decodes one huffman symbol from the
 * bitstream using the stated table and puts it in var.
 */
#define MSZIP_READ_HUFFSYM(tbl, var) do {                                     \
  /* huffman symbols can be up to 16 bits long */                       \
  MSZIP_ENSURE_BITS(MSZIP_MAX_HUFFBITS);                                      \
  /* immediate table lookup of [tablebits] bits of the code */          \
  sym = zip->tbl##_table[MSZIP_PEEK_BITS(MSZIP_##tbl##_TABLEBITS)];		\
  /* is the symbol is longer than [tablebits] bits? (i=node index) */   \
  if (sym >= MSZIP_##tbl##_MAXSYMBOLS) {                                \
    /* decode remaining bits by tree traversal */                       \
    i = MSZIP_##tbl##_TABLEBITS - 1;					\
    do {                                                                \
      /* check next bit. error if we run out of bits before decode */	\
      if (i++ > MSZIP_MAX_HUFFBITS) {					\
        cli_dbgmsg("zip_inflate: out of bits in huffman decode\n");	\
        return INF_ERR_HUFFSYM;                                         \
      }                                                                 \
      sym = (sym << 1) | ((bit_buffer >> i) & 1);			\
      if(sym >= MSZIP_##tbl##_TABLESIZE) {				\
	cli_dbgmsg("zip_inflate: index out of table\n");		\
        return INF_ERR_HUFFSYM;                                         \
      }									\
      /* double node index and add 0 (left branch) or 1 (right) */	\
      sym = zip->tbl##_table[sym];					\
      /* while we are still in node indicies, not decoded symbols */    \
    } while (sym >= MSZIP_##tbl##_MAXSYMBOLS);                          \
  }                                                                     \
  /* result */                                                          \
  (var) = sym;                                                          \
  /* look up the code length of that symbol and discard those bits */   \
  i = zip->tbl##_len[sym];                                              \
  MSZIP_REMOVE_BITS(i);                                                       \
} while (0)

static int mszip_read_lens(struct mszip_stream *zip) {
  /* for the bit buffer and huffman decoding */
  register unsigned int bit_buffer;
  register int bits_left;
  unsigned char *i_ptr, *i_end;

  /* bitlen Huffman codes -- immediate lookup, 7 bit max code length */
  unsigned short bl_table[(1 << 7)];
  unsigned char bl_len[19];

  unsigned char lens[MSZIP_LITERAL_MAXSYMBOLS + MSZIP_DISTANCE_MAXSYMBOLS];
  unsigned int lit_codes, dist_codes, code, last_code=0, bitlen_codes, i, run;

  MSZIP_RESTORE_BITS;

  /* read the number of codes */
  MSZIP_READ_BITS(lit_codes,    5); lit_codes    += 257;
  MSZIP_READ_BITS(dist_codes,   5); dist_codes   += 1;
  MSZIP_READ_BITS(bitlen_codes, 4); bitlen_codes += 4;
  if (lit_codes  > MSZIP_LITERAL_MAXSYMBOLS)  return INF_ERR_SYMLENS;
  if (dist_codes > MSZIP_DISTANCE_MAXSYMBOLS) return INF_ERR_SYMLENS;

  /* read in the bit lengths in their unusual order */
  for (i = 0; i < bitlen_codes; i++) MSZIP_READ_BITS(bl_len[mszip_bitlen_order[i]], 3);
  while (i < 19) bl_len[mszip_bitlen_order[i++]] = 0;

  /* create decoding table with an immediate lookup */
  if (mszip_make_decode_table(19, 7, &bl_len[0], &bl_table[0])) {
    return INF_ERR_BITLENTBL;
  }

  /* read literal / distance code lengths */
  for (i = 0; i < (lit_codes + dist_codes); i++) {
    /* single-level huffman lookup */
    MSZIP_ENSURE_BITS(7);
    code = bl_table[MSZIP_PEEK_BITS(7)];
    MSZIP_REMOVE_BITS(bl_len[code]);

    if (code < 16) lens[i] = last_code = code;
    else {
      switch (code) {
      case 16: MSZIP_READ_BITS(run, 2); run += 3;  code = last_code; break;
      case 17: MSZIP_READ_BITS(run, 3); run += 3;  code = 0;         break;
      case 18: MSZIP_READ_BITS(run, 7); run += 11; code = 0;         break;
      default: cli_dbgmsg("zip_read_lens: bad code!: %u\n", code); return INF_ERR_BADBITLEN;
      }
      if ((i + run) > (lit_codes + dist_codes)) return INF_ERR_BITOVERRUN;
      while (run--) lens[i++] = code;
      i--;
    }
  }

  /* copy LITERAL code lengths and clear any remaining */
  i = lit_codes;
  memcpy(&zip->LITERAL_len[0], &lens[0], i);
  while (i < MSZIP_LITERAL_MAXSYMBOLS) zip->LITERAL_len[i++] = 0;

  i = dist_codes;
  memcpy(&zip->DISTANCE_len[0], &lens[lit_codes], i);
  while (i < MSZIP_DISTANCE_MAXSYMBOLS) zip->DISTANCE_len[i++] = 0;

  MSZIP_STORE_BITS;
  return 0;
}

/* a clean implementation of RFC 1951 / inflate */
static int mszip_inflate(struct mszip_stream *zip) {
  unsigned int last_block, block_type, distance, length, this_run, i;

  /* for the bit buffer and huffman decoding */
  register unsigned int bit_buffer;
  register int bits_left;
  register unsigned short sym;
  unsigned char *i_ptr, *i_end;

  MSZIP_RESTORE_BITS;

  do {
    /* read in last block bit */
    MSZIP_READ_BITS(last_block, 1);

    /* read in block type */
    MSZIP_READ_BITS(block_type, 2);

    if (block_type == 0) {
      /* uncompressed block */
      unsigned char lens_buf[4];

      /* go to byte boundary */
      i = bits_left & 7; MSZIP_REMOVE_BITS(i);

      /* read 4 bytes of data, emptying the bit-buffer if necessary */
      for (i = 0; (bits_left >= 8); i++) {
	if (i == 4) return INF_ERR_BITBUF;
	lens_buf[i] = MSZIP_PEEK_BITS(8);
	MSZIP_REMOVE_BITS(8);
      }
      if (bits_left != 0) return INF_ERR_BITBUF;
      while (i < 4) {
	if (i_ptr >= i_end) {
	  if (mszip_read_input(zip)) return zip->error;
	  i_ptr = zip->i_ptr;
	  i_end = zip->i_end;
	}
	lens_buf[i++] = *i_ptr++;
      }

      /* get the length and its complement */
      length = lens_buf[0] | (lens_buf[1] << 8);
      i      = lens_buf[2] | (lens_buf[3] << 8);
      if (length != (~i & 0xFFFF)) return INF_ERR_COMPLEMENT;

      /* read and copy the uncompressed data into the window */
      while (length > 0) {
	if (i_ptr >= i_end) {
	  if (mszip_read_input(zip)) return zip->error;
	  i_ptr = zip->i_ptr;
	  i_end = zip->i_end;
	}

	this_run = length;
	if (this_run > (unsigned int)(i_end - i_ptr)) this_run = i_end - i_ptr;
	if (this_run > (MSZIP_FRAME_SIZE - zip->window_posn))
	  this_run = MSZIP_FRAME_SIZE - zip->window_posn;

	memcpy(&zip->window[zip->window_posn], i_ptr, this_run);
	zip->window_posn += this_run;
	i_ptr    += this_run;
	length   -= this_run;

	if (zip->window_posn == MSZIP_FRAME_SIZE) {
	  if (zip->flush_window(zip, MSZIP_FRAME_SIZE)) return INF_ERR_FLUSH;
	  zip->window_posn = 0;
	}
      }
    }
    else if ((block_type == 1) || (block_type == 2)) {
      /* Huffman-compressed LZ77 block */
      unsigned int window_posn, match_posn, code;

      if (block_type == 1) {
	/* block with fixed Huffman codes */
	i = 0;
	while (i < 144) zip->LITERAL_len[i++] = 8;
	while (i < 256) zip->LITERAL_len[i++] = 9;
	while (i < 280) zip->LITERAL_len[i++] = 7;
	while (i < 288) zip->LITERAL_len[i++] = 8;
	for (i = 0; i < 32; i++) zip->DISTANCE_len[i] = 5;
      }
      else {
	/* block with dynamic Huffman codes */
	MSZIP_STORE_BITS;
	if ((i = mszip_read_lens(zip))) return i;
	MSZIP_RESTORE_BITS;
      }

      /* now huffman lengths are read for either kind of block, 
       * create huffman decoding tables */
      if (mszip_make_decode_table(MSZIP_LITERAL_MAXSYMBOLS, MSZIP_LITERAL_TABLEBITS,
			    &zip->LITERAL_len[0], &zip->LITERAL_table[0]))
      {
	return INF_ERR_LITERALTBL;
      }

      if (mszip_make_decode_table(MSZIP_DISTANCE_MAXSYMBOLS,MSZIP_DISTANCE_TABLEBITS,
			    &zip->DISTANCE_len[0], &zip->DISTANCE_table[0]))
      {
	return INF_ERR_DISTANCETBL;
      }

      /* decode forever until end of block code */
      window_posn = zip->window_posn;
      while (1) {
	MSZIP_READ_HUFFSYM(LITERAL, code);
	if (code < 256) {
	  zip->window[window_posn++] = (unsigned char) code;
	  if (window_posn == MSZIP_FRAME_SIZE) {
	    if (zip->flush_window(zip, MSZIP_FRAME_SIZE)) return INF_ERR_FLUSH;
	    window_posn = 0;
	  }
	}
	else if (code == 256) {
	  /* END OF BLOCK CODE: loop break point */
	  break;
	}
	else {
	  code -= 257;
	  if (code > 29) return INF_ERR_LITCODE;
	  MSZIP_READ_BITS_T(length, mszip_lit_extrabits[code]);
	  length += mszip_lit_lengths[code];

	  MSZIP_READ_HUFFSYM(DISTANCE, code);
	  if (code > 30) return INF_ERR_DISTCODE;
	  MSZIP_READ_BITS_T(distance, mszip_dist_extrabits[code]);
	  distance += mszip_dist_offsets[code];

	  /* match position is window position minus distance. If distance
	   * is more than window position numerically, it must 'wrap
	   * around' the frame size. */ 
	  match_posn = ((distance > window_posn) ? MSZIP_FRAME_SIZE : 0)
	    + window_posn - distance;

	  /* copy match */
	  if (length < 12) {
	    /* short match, use slower loop but no loop setup code */
	    while (length--) {
	      zip->window[window_posn++] = zip->window[match_posn++];
	      match_posn &= MSZIP_FRAME_SIZE - 1;

	      if (window_posn == MSZIP_FRAME_SIZE) {
		if (zip->flush_window(zip, MSZIP_FRAME_SIZE))
		  return INF_ERR_FLUSH;
		window_posn = 0;
	      }
	    }
	  }
	  else {
	    /* longer match, use faster loop but with setup expense */
	    unsigned char *runsrc, *rundest;
	    do {
	      this_run = length;
	      if ((match_posn + this_run) > MSZIP_FRAME_SIZE)
		this_run = MSZIP_FRAME_SIZE - match_posn;
	      if ((window_posn + this_run) > MSZIP_FRAME_SIZE)
		this_run = MSZIP_FRAME_SIZE - window_posn;

	      rundest = &zip->window[window_posn]; window_posn += this_run;
	      runsrc  = &zip->window[match_posn];  match_posn  += this_run;
	      length -= this_run;
	      while (this_run--) *rundest++ = *runsrc++;

	      /* flush if necessary */
	      if (window_posn == MSZIP_FRAME_SIZE) {
		if (zip->flush_window(zip, MSZIP_FRAME_SIZE))
		  return INF_ERR_FLUSH;
		window_posn = 0;
	      }
	      if (match_posn == MSZIP_FRAME_SIZE) match_posn = 0;
	    } while (length > 0);
	  }

	} /* else (code >= 257) */

      } /* while (forever) -- break point at 'code == 256' */
      zip->window_posn = window_posn;
    }
    else {
      /* block_type == 3 -- bad block type */
      return INF_ERR_BLOCKTYPE;
    }
  } while (!last_block);

  /* flush the remaining data */
  if (zip->window_posn) {
    if (zip->flush_window(zip, zip->window_posn)) return INF_ERR_FLUSH;
  }
  MSZIP_STORE_BITS;

  /* return success */
  return 0;
}

/* inflate() calls this whenever the window should be flushed. As
 * MSZIP only expands to the size of the window, the implementation used
 * simply keeps track of the amount of data flushed, and if more than 32k
 * is flushed, an error is raised.
 */  
static int mszip_flush_window(struct mszip_stream *zip,
			       unsigned int data_flushed)
{
  zip->bytes_output += data_flushed;
  if (zip->bytes_output > MSZIP_FRAME_SIZE) {
    cli_dbgmsg("mszip_flush_window: overflow: %u bytes flushed, total is now %u\n", data_flushed, zip->bytes_output);
    return 1;
  }
  return 0;
}

struct mszip_stream *mszip_init(int fd,
				  int ofd,
				  int input_buffer_size,
				  int repair_mode,
				  struct cab_file *file,
			          int (*read)(struct cab_file *, unsigned char *, int))
{
  struct mszip_stream *zip;

  input_buffer_size = (input_buffer_size + 1) & -2;
  if (!input_buffer_size) return NULL;

  /* allocate decompression state */
  if (!(zip = cli_malloc(sizeof(struct mszip_stream)))) {
    return NULL;
  }

  /* allocate input buffer */
  zip->inbuf  = cli_malloc((size_t) input_buffer_size);
  if (!zip->inbuf) {
    free(zip);
    return NULL;
  }

  /* initialise decompression state */
  zip->fd	       = fd;
  zip->ofd	       = ofd;
  zip->wflag	       = 1;
  zip->inbuf_size      = input_buffer_size;
  zip->error           = CL_SUCCESS;
  zip->repair_mode     = repair_mode;
  zip->flush_window    = &mszip_flush_window;
  zip->input_end       = 0;

  zip->i_ptr = zip->i_end = &zip->inbuf[0];
  zip->o_ptr = zip->o_end = NULL;
  zip->bit_buffer = 0; zip->bits_left = 0;

  zip->file = file;
  zip->read = read;

  return zip;
}

int mszip_decompress(struct mszip_stream *zip, off_t out_bytes) {
  /* for the bit buffer */
  register unsigned int bit_buffer;
  register int bits_left;
  unsigned char *i_ptr, *i_end;

  int i, state, error;

  /* easy answers */
  if (!zip || (out_bytes < 0)) return CL_ENULLARG;
  if (zip->error) return zip->error;

  /* flush out any stored-up bytes before we begin */
  i = zip->o_end - zip->o_ptr;
  if ((off_t) i > out_bytes) i = (int) out_bytes;
  if (i) {
    if (zip->wflag && cli_writen(zip->ofd, zip->o_ptr, i) != i) {
      return zip->error = CL_EIO;
    }
    zip->o_ptr  += i;
    out_bytes   -= i;
  }
  if (out_bytes == 0) return CL_SUCCESS;

  while (out_bytes > 0) {
    /* unpack another block */
    MSZIP_RESTORE_BITS;

    /* skip to next read 'CK' header */
    i = bits_left & 7; MSZIP_REMOVE_BITS(i); /* align to bytestream */
    state = 0;
    do {
      MSZIP_READ_BITS(i, 8);
      if (i == 'C') state = 1;
      else if ((state == 1) && (i == 'K')) state = 2;
      else state = 0;
    } while (state != 2);

    /* inflate a block, repair and realign if necessary */
    zip->window_posn = 0;
    zip->bytes_output = 0;
    MSZIP_STORE_BITS;
    if ((error = mszip_inflate(zip))) {
      cli_dbgmsg("mszip_decompress: inflate error %d\n", error);
      if (zip->repair_mode) {
	cli_dbgmsg("mszip_decompress: MSZIP error, %u bytes of data lost\n",
			  MSZIP_FRAME_SIZE - zip->bytes_output);
	for (i = zip->bytes_output; i < MSZIP_FRAME_SIZE; i++) {
	  zip->window[i] = '\0';
	}
	zip->bytes_output = MSZIP_FRAME_SIZE;
      }
      else {
	return zip->error = (error > 0) ? error : CL_EFORMAT;
      }
    }
    zip->o_ptr = &zip->window[0];
    zip->o_end = &zip->o_ptr[zip->bytes_output];

    /* write a frame */
    i = (out_bytes < (off_t)zip->bytes_output) ?
      (int)out_bytes : zip->bytes_output;
    if (zip->wflag && cli_writen(zip->ofd, zip->o_ptr, i) != i) {
      return zip->error = CL_EIO;
    }

    /* mspack errors (i.e. read errors) are fatal and can't be recovered */
    if ((error > 0) && zip->repair_mode) return error;

    zip->o_ptr  += i;
    out_bytes   -= i;
  }

  if (out_bytes) {
    cli_dbgmsg("mszip_decompress: bytes left to output\n");
    return zip->error = CL_EFORMAT;
  }
  return CL_SUCCESS;
}

void mszip_free(struct mszip_stream *zip) {
  if (zip) {
    free(zip->inbuf);
    free(zip);
  }
}

/***************************************************************************
 *			 LZX decompression implementation 
 ***************************************************************************
 * The LZX method was created by Jonathan Forbes and Tomi Poutanen, adapted
 * by Microsoft Corporation.
 *
 */

/* LZX decompressor input macros
 *
 * LZX_STORE_BITS        stores bitstream state in lzx_stream structure
 * LZX_RESTORE_BITS      restores bitstream state from lzx_stream structure
 * LZX_READ_BITS(var,n)  takes N bits from the buffer and puts them in var
 * LZX_ENSURE_BITS(n)    ensures there are at least N bits in the bit buffer.
 * LZX_PEEK_BITS(n)      extracts without removing N bits from the bit buffer
 * LZX_REMOVE_BITS(n)    removes N bits from the bit buffer
 *
 */

#define LZX_BITBUF_WIDTH (sizeof(bit_buffer) * CHAR_BIT)

#define LZX_STORE_BITS do {                                                 \
  lzx->i_ptr      = i_ptr;                                              \
  lzx->i_end      = i_end;                                              \
  lzx->bit_buffer = bit_buffer;                                         \
  lzx->bits_left  = bits_left;                                          \
} while (0)

#define LZX_RESTORE_BITS do {                                               \
  i_ptr      = lzx->i_ptr;                                              \
  i_end      = lzx->i_end;                                              \
  bit_buffer = lzx->bit_buffer;                                         \
  bits_left  = lzx->bits_left;                                          \
} while (0)

#define LZX_ENSURE_BITS(nbits)                                              \
  while (bits_left < (nbits)) {                                         \
    if (i_ptr + 1 >= i_end) {                                               \
      if (lzx_read_input(lzx)) return lzx->error;                      \
      i_ptr = lzx->i_ptr;                                               \
      i_end = lzx->i_end;                                               \
    }                                                                   \
    bit_buffer |= ((i_ptr[1] << 8) | i_ptr[0])                          \
                  << (LZX_BITBUF_WIDTH - 16 - bits_left);                   \
    bits_left  += 16;                                                   \
    i_ptr      += 2;                                                    \
  }

#define LZX_PEEK_BITS(nbits) (bit_buffer >> (LZX_BITBUF_WIDTH - (nbits)))

#define LZX_REMOVE_BITS(nbits) ((bit_buffer <<= (nbits)), (bits_left -= (nbits)))

#define LZX_READ_BITS(val, nbits) do {                                      \
  LZX_ENSURE_BITS(nbits);                                                   \
  (val) = LZX_PEEK_BITS(nbits);                                             \
  LZX_REMOVE_BITS(nbits);                                                   \
} while (0)

static int lzx_read_input(struct lzx_stream *lzx) {
  int bread = lzx->read ? lzx->read(lzx->file, &lzx->inbuf[0], (int)lzx->inbuf_size) : cli_readn(lzx->fd, &lzx->inbuf[0], (int)lzx->inbuf_size);
  if (bread < 0) return lzx->error = CL_EIO;

  /* huff decode's ENSURE_BYTES(16) might overrun the input stream, even
   * if those bits aren't used, so fake 2 more bytes */
  if (bread == 0) {
    if (lzx->input_end) {
      cli_dbgmsg("lzx_read_input: out of input bytes\n");
      return lzx->error = CL_EIO;
    }
    else {
      bread = 2;
      lzx->inbuf[0] = lzx->inbuf[1] = 0;
      lzx->input_end = 1;
    }
  }

  lzx->i_ptr = &lzx->inbuf[0];
  lzx->i_end = &lzx->inbuf[bread];

  return CL_SUCCESS;
}

/* Huffman decoding macros */

/* LZX_READ_HUFFSYM(tablename, var) decodes one huffman symbol from the
 * bitstream using the stated table and puts it in var.
 */
#define LZX_READ_HUFFSYM(tbl, var) do {                                     \
  /* huffman symbols can be up to 16 bits long */                       \
  LZX_ENSURE_BITS(16);                                                      \
  /* immediate table lookup of [tablebits] bits of the code */          \
  sym = lzx->tbl##_table[LZX_PEEK_BITS(LZX_##tbl##_TABLEBITS)];             \
  /* is the symbol is longer than [tablebits] bits? (i=node index) */   \
  if (sym >= LZX_##tbl##_MAXSYMBOLS) {                                  \
    /* decode remaining bits by tree traversal */                       \
    i = 1 << (LZX_BITBUF_WIDTH - LZX_##tbl##_TABLEBITS);                    \
    do {                                                                \
      /* one less bit. error if we run out of bits before decode */     \
      i >>= 1;                                                          \
      if (i == 0) {                                                     \
        cli_dbgmsg("lzx: out of bits in huffman decode\n");             \
        return lzx->error = CL_EFORMAT;					\
      }                                                                 \
      /* double node index and add 0 (left branch) or 1 (right) */      \
      sym <<= 1; sym |= (bit_buffer & i) ? 1 : 0;                       \
      /* hop to next node index / decoded symbol */                     \
      if(sym >= (1 << LZX_##tbl##_TABLEBITS) + (LZX_##tbl##_MAXSYMBOLS * 2)) { \
	cli_dbgmsg("lzx: index out of table\n");			\
	return lzx->error = CL_EFORMAT;					\
      }									\
      sym = lzx->tbl##_table[sym];                                    \
      /* while we are still in node indicies, not decoded symbols */    \
    } while (sym >= LZX_##tbl##_MAXSYMBOLS);                            \
  }                                                                     \
  /* result */                                                          \
  (var) = sym;                                                          \
  /* look up the code length of that symbol and discard those bits */   \
  i = lzx->tbl##_len[sym];                                              \
  LZX_REMOVE_BITS(i);                                                       \
} while (0)

/* LZX_BUILD_TABLE(tbl) builds a huffman lookup table from code lengths */
#define LZX_BUILD_TABLE(tbl)                                                \
  if (lzx_make_decode_table(LZX_##tbl##_MAXSYMBOLS, LZX_##tbl##_TABLEBITS,  \
			&lzx->tbl##_len[0], &lzx->tbl##_table[0]))      \
  {                                                                     \
    cli_dbgmsg("lzx: failed to build %s table\n", #tbl);                \
    return lzx->error = CL_EFORMAT;					\
  }

/* lzx_make_decode_table(nsyms, nbits, length[], table[])
 *
 * This function was coded by David Tritscher. It builds a fast huffman
 * decoding table from a canonical huffman code lengths table.
 *
 * nsyms  = total number of symbols in this huffman tree.
 * nbits  = any symbols with a code length of nbits or less can be decoded
 *          in one lookup of the table.
 * length = A table to get code lengths from [0 to syms-1]
 * table  = The table to fill up with decoded symbols and pointers.
 *
 * Returns 0 for OK or 1 for error
 */

static int lzx_make_decode_table(unsigned int nsyms, unsigned int nbits,
			     unsigned char *length, unsigned short *table)
{
  register unsigned short sym;
  register unsigned int leaf, fill;
  register unsigned char bit_num;
  unsigned int pos         = 0; /* the current position in the decode table */
  unsigned int table_mask  = 1 << nbits;
  unsigned int bit_mask    = table_mask >> 1; /* don't do 0 length codes */
  unsigned int next_symbol = bit_mask; /* base of allocation for long codes */

  /* fill entries for codes short enough for a direct mapping */
  for (bit_num = 1; bit_num <= nbits; bit_num++) {
    for (sym = 0; sym < nsyms; sym++) {
      if (length[sym] != bit_num) continue;
      leaf = pos;
      if((pos += bit_mask) > table_mask) return 1; /* table overrun */
      /* fill all possible lookups of this symbol with the symbol itself */
      for (fill = bit_mask; fill-- > 0;) table[leaf++] = sym;
    }
    bit_mask >>= 1;
  }

  /* full table already? */
  if (pos == table_mask) return 0;

  /* clear the remainder of the table */
  for (sym = pos; sym < table_mask; sym++) table[sym] = 0xFFFF;

  /* allow codes to be up to nbits+16 long, instead of nbits */
  pos <<= 16;
  table_mask <<= 16;
  bit_mask = 1 << 15;

  for (bit_num = nbits+1; bit_num <= 16; bit_num++) {
    for (sym = 0; sym < nsyms; sym++) {
      if (length[sym] != bit_num) continue;

      leaf = pos >> 16;
      for (fill = 0; fill < bit_num - nbits; fill++) {
	/* if this path hasn't been taken yet, 'allocate' two entries */
	if (table[leaf] == 0xFFFF) {
	  table[(next_symbol << 1)] = 0xFFFF;
	  table[(next_symbol << 1) + 1] = 0xFFFF;
	  table[leaf] = next_symbol++;
	}
	/* follow the path and select either left or right for next bit */
	leaf = table[leaf] << 1;
	if ((pos >> (15-fill)) & 1) leaf++;
      }
      table[leaf] = sym;

      if ((pos += bit_mask) > table_mask) return 1; /* table overflow */
    }
    bit_mask >>= 1;
  }

  /* full table? */
  if (pos == table_mask) return 0;

  /* either erroneous table, or all elements are 0 - let's find out. */
  for (sym = 0; sym < nsyms; sym++) if (length[sym]) return 1;
  return 0;
}

/* LZX_READ_LENGTHS(tablename, first, last) reads in code lengths for symbols
 * first to last in the given table. The code lengths are stored in their
 * own special LZX way.
 */
#define LZX_READ_LENGTHS(tbl, first, last) do {                            \
  LZX_STORE_BITS;                                                          \
  if (lzx_read_lens(lzx, &lzx->tbl##_len[0], (first),                 \
    (unsigned int)(last))) return lzx->error;                          \
  LZX_RESTORE_BITS;                                                        \
} while (0)

static int lzx_read_lens(struct lzx_stream *lzx, unsigned char *lens,
			  unsigned int first, unsigned int last)
{
  /* bit buffer and huffman symbol decode variables */
  register unsigned int bit_buffer;
  register int bits_left, i;
  register unsigned short sym;
  unsigned char *i_ptr, *i_end;

  unsigned int x, y;
  int z;

  LZX_RESTORE_BITS;
  
  /* read lengths for pretree (20 symbols, lengths stored in fixed 4 bits) */
  for (x = 0; x < 20; x++) {
    LZX_READ_BITS(y, 4);
    lzx->PRETREE_len[x] = y;
  }
  LZX_BUILD_TABLE(PRETREE);

  for (x = first; x < last; ) {
    LZX_READ_HUFFSYM(PRETREE, z);
    if (z == 17) {
      /* code = 17, run of ([read 4 bits]+4) zeros */
      LZX_READ_BITS(y, 4); y += 4;
      while (y--) lens[x++] = 0;
    }
    else if (z == 18) {
      /* code = 18, run of ([read 5 bits]+20) zeros */
      LZX_READ_BITS(y, 5); y += 20;
      while (y--) lens[x++] = 0;
    }
    else if (z == 19) {
      /* code = 19, run of ([read 1 bit]+4) [read huffman symbol] */
      LZX_READ_BITS(y, 1); y += 4;
      LZX_READ_HUFFSYM(PRETREE, z);
      z = lens[x] - z; if (z < 0) z += 17;
      while (y--) lens[x++] = z;
    }
    else {
      /* code = 0 to 16, delta current length entry */
      z = lens[x] - z; if (z < 0) z += 17;
      lens[x++] = z;
    }
  }

  LZX_STORE_BITS;

  return CL_SUCCESS;
}

static void lzx_reset_state(struct lzx_stream *lzx) {
  int i;

  lzx->R0              = 1;
  lzx->R1              = 1;
  lzx->R2              = 1;
  lzx->header_read     = 0;
  lzx->block_remaining = 0;
  lzx->block_type      = LZX_BLOCKTYPE_INVALID;

  /* initialise tables to 0 (because deltas will be applied to them) */
  for (i = 0; i < LZX_MAINTREE_MAXSYMBOLS; i++) lzx->MAINTREE_len[i] = 0;
  for (i = 0; i < LZX_LENGTH_MAXSYMBOLS; i++)   lzx->LENGTH_len[i]   = 0;
}

/*-------- main LZX code --------*/

struct lzx_stream *lzx_init(int fd,
			      int ofd,
			      int window_bits,
			      int reset_interval,
			      int input_buffer_size,
			      off_t output_length,
			      struct cab_file *file,
			      int (*read)(struct cab_file *, unsigned char *, int))
{
  unsigned int window_size = 1 << window_bits;
  struct lzx_stream *lzx;
  int i, j;

  /* LZX supports window sizes of 2^15 (32Kb) through 2^21 (2Mb) */
  if (window_bits < 15 || window_bits > 21) return NULL;

  input_buffer_size = (input_buffer_size + 1) & -2;
  if (!input_buffer_size) return NULL;

  /* allocate decompression state */
  if (!(lzx = cli_calloc(1, sizeof(struct lzx_stream)))) {
    return NULL;
  }

  for (i = 0, j = 0; i < 51; i += 2) {
    lzx->extra_bits[i]   = j; /* 0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7... */
    if(i < 50)
	lzx->extra_bits[i+1] = j;
    if ((i != 0) && (j < 17)) j++; /* 0,0,1,2,3,4...15,16,17,17,17,17... */
  }

  for (i = 0, j = 0; i < 51; i++) {
    lzx->position_base[i] = j; /* 0,1,2,3,4,6,8,12,16,24,32,... */
    j += 1 << lzx->extra_bits[i]; /* 1,1,1,1,2,2,4,4,8,8,16,16,32,32,... */
  }

  /* allocate decompression window and input buffer */
  lzx->window = cli_calloc(1, (size_t) window_size);
  if(!lzx->window) {
    free(lzx);
    return NULL;
  }

  lzx->inbuf  = cli_calloc(1, (size_t) input_buffer_size);
  if (!lzx->inbuf) {
    free(lzx->window);
    free(lzx);
    return NULL;
  }

  /* initialise decompression state */
  lzx->fd              = fd;
  lzx->ofd	       = ofd;
  lzx->wflag	       = 1;
  lzx->offset          = 0;
  lzx->length          = output_length;
  lzx->file	       = file;
  lzx->read	       = read;

  lzx->inbuf_size      = input_buffer_size;
  lzx->window_size     = 1 << window_bits;
  lzx->window_posn     = 0;
  lzx->frame_posn      = 0;
  lzx->frame           = 0;
  lzx->reset_interval  = reset_interval;
  lzx->intel_filesize  = 0;
  lzx->intel_curpos    = 0;

  /* window bits:    15  16  17  18  19  20  21
   * position slots: 30  32  34  36  38  42  50  */
  lzx->posn_slots      = ((window_bits == 21) ? 50 :
			  ((window_bits == 20) ? 42 : (window_bits << 1)));
  lzx->intel_started   = 0;
  lzx->input_end       = 0;

  lzx->error = CL_SUCCESS;

  lzx->i_ptr = lzx->i_end = &lzx->inbuf[0];
  lzx->o_ptr = lzx->o_end = &lzx->e8_buf[0];
  lzx->bit_buffer = lzx->bits_left = 0;

  lzx_reset_state(lzx);
  return lzx;
}

void lzx_set_output_length(struct lzx_stream *lzx, off_t out_bytes) {
  if (lzx) lzx->length = out_bytes;
}

int lzx_decompress(struct lzx_stream *lzx, off_t out_bytes) {
  /* bitstream reading and huffman variables */
  register unsigned int bit_buffer;
  register int bits_left, i=0;
  register unsigned short sym;
  unsigned char *i_ptr, *i_end;

  int match_length, length_footer, extra, verbatim_bits, bytes_todo;
  int this_run, main_element, aligned_bits, j;
  unsigned char *window, *runsrc, *rundest, buf[12];
  unsigned int frame_size=0, end_frame, match_offset, window_posn;
  unsigned int R0, R1, R2;

  /* easy answers */
  if (!lzx || (out_bytes < 0)) return CL_ENULLARG;
  if (lzx->error) return lzx->error;

  /* flush out any stored-up bytes before we begin */
  i = lzx->o_end - lzx->o_ptr;
  if ((off_t) i > out_bytes) i = (int) out_bytes;
  if (i) {
    if (lzx->wflag && cli_writen(lzx->ofd, lzx->o_ptr, i) != i) {
      return lzx->error = CL_EIO;
    }
    lzx->o_ptr  += i;
    lzx->offset += i;
    out_bytes   -= i;
  }
  if (out_bytes == 0) return CL_SUCCESS;

  /* restore local state */
  LZX_RESTORE_BITS;
  window = lzx->window;
  window_posn = lzx->window_posn;
  R0 = lzx->R0;
  R1 = lzx->R1;
  R2 = lzx->R2;

  end_frame = (unsigned int)((lzx->offset + out_bytes) / LZX_FRAME_SIZE) + 1;

  while (lzx->frame < end_frame) {
    /* have we reached the reset interval? (if there is one?) */
    if (lzx->reset_interval && ((lzx->frame % lzx->reset_interval) == 0)) {
      if (lzx->block_remaining) {
	cli_dbgmsg("lzx_decompress: %d bytes remaining at reset interval\n", lzx->block_remaining);
	return lzx->error = CL_EFORMAT;
      }

      /* re-read the intel header and reset the huffman lengths */
      lzx_reset_state(lzx);
    }

    /* read header if necessary */
    if (!lzx->header_read) {
      /* read 1 bit. if bit=0, intel filesize = 0.
       * if bit=1, read intel filesize (32 bits) */
      j = 0; LZX_READ_BITS(i, 1); if (i) { LZX_READ_BITS(i, 16); LZX_READ_BITS(j, 16); }
      lzx->intel_filesize = (i << 16) | j;
      lzx->header_read = 1;
    } 

    /* calculate size of frame: all frames are 32k except the final frame
     * which is 32kb or less. this can only be calculated when lzx->length
     * has been filled in. */
    frame_size = LZX_FRAME_SIZE;
    if (lzx->length && (lzx->length - lzx->offset) < (off_t)frame_size) {
      frame_size = lzx->length - lzx->offset;
    }

    /* decode until one more frame is available */
    bytes_todo = lzx->frame_posn + frame_size - window_posn;
    while (bytes_todo > 0) {
      /* initialise new block, if one is needed */
      if (lzx->block_remaining == 0) {
	/* realign if previous block was an odd-sized UNCOMPRESSED block */
	if ((lzx->block_type == LZX_BLOCKTYPE_UNCOMPRESSED) &&
	    (lzx->block_length & 1))
	{
	  if (i_ptr == i_end) {
	    if (lzx_read_input(lzx)) return lzx->error;
	    i_ptr = lzx->i_ptr;
	    i_end = lzx->i_end;
	  }
	  i_ptr++;
	}

	/* read block type (3 bits) and block length (24 bits) */
	LZX_READ_BITS(lzx->block_type, 3);
	LZX_READ_BITS(i, 16); LZX_READ_BITS(j, 8);
	lzx->block_remaining = lzx->block_length = (i << 8) | j;

	/* read individual block headers */
	switch (lzx->block_type) {
	case LZX_BLOCKTYPE_ALIGNED:
	  /* read lengths of and build aligned huffman decoding tree */
	  for (i = 0; i < 8; i++) { LZX_READ_BITS(j, 3); lzx->ALIGNED_len[i] = j; }
	  LZX_BUILD_TABLE(ALIGNED);
	  /* no break -- rest of aligned header is same as verbatim */
	case LZX_BLOCKTYPE_VERBATIM:
	  /* read lengths of and build main huffman decoding tree */
	  LZX_READ_LENGTHS(MAINTREE, 0, 256);
	  LZX_READ_LENGTHS(MAINTREE, 256, LZX_NUM_CHARS + (lzx->posn_slots << 3));
	  LZX_BUILD_TABLE(MAINTREE);
	  /* if the literal 0xE8 is anywhere in the block... */
	  if (lzx->MAINTREE_len[0xE8] != 0) lzx->intel_started = 1;
	  /* read lengths of and build lengths huffman decoding tree */
	  LZX_READ_LENGTHS(LENGTH, 0, LZX_NUM_SECONDARY_LENGTHS);
	  LZX_BUILD_TABLE(LENGTH);
	  break;

	case LZX_BLOCKTYPE_UNCOMPRESSED:
	  /* because we can't assume otherwise */
	  lzx->intel_started = 1;

	  /* read 1-16 (not 0-15) bits to align to bytes */
	  LZX_ENSURE_BITS(16);
	  if (bits_left > 16) i_ptr -= 2;
	  bits_left = 0; bit_buffer = 0;

	  /* read 12 bytes of stored R0 / R1 / R2 values */
	  for (rundest = &buf[0], i = 0; i < 12; i++) {
	    if (i_ptr == i_end) {
	      if (lzx_read_input(lzx)) return lzx->error;
	      i_ptr = lzx->i_ptr;
	      i_end = lzx->i_end;
	    }
	    *rundest++ = *i_ptr++;
	  }
	  R0 = buf[0] | (buf[1] << 8) | (buf[2]  << 16) | (buf[3]  << 24);
	  R1 = buf[4] | (buf[5] << 8) | (buf[6]  << 16) | (buf[7]  << 24);
	  R2 = buf[8] | (buf[9] << 8) | (buf[10] << 16) | (buf[11] << 24);
	  break;

	default:
	  cli_dbgmsg("lzx_decompress: bad block type (0x%x)\n", lzx->block_type);
	  return lzx->error = CL_EFORMAT;
	}
      }

      /* decode more of the block:
       * run = min(what's available, what's needed) */
      this_run = lzx->block_remaining;
      if (this_run > bytes_todo) this_run = bytes_todo;

      /* assume we decode exactly this_run bytes, for now */
      bytes_todo           -= this_run;
      lzx->block_remaining -= this_run;

      /* decode at least this_run bytes */
      switch (lzx->block_type) {
      case LZX_BLOCKTYPE_VERBATIM:
	while (this_run > 0) {
	  LZX_READ_HUFFSYM(MAINTREE, main_element);
	  if (main_element < LZX_NUM_CHARS) {
	    /* literal: 0 to LZX_NUM_CHARS-1 */
	    window[window_posn++] = main_element;
	    this_run--;
	  }
	  else {
	    /* match: LZX_NUM_CHARS + ((slot<<3) | length_header (3 bits)) */
	    main_element -= LZX_NUM_CHARS;

	    /* get match length */
	    match_length = main_element & LZX_NUM_PRIMARY_LENGTHS;
	    if (match_length == LZX_NUM_PRIMARY_LENGTHS) {
	      LZX_READ_HUFFSYM(LENGTH, length_footer);
	      match_length += length_footer;
	    }
	    match_length += LZX_MIN_MATCH;
	  
	    /* get match offset */
	    switch ((match_offset = (main_element >> 3))) {
	    case 0: match_offset = R0;                                  break;
	    case 1: match_offset = R1; R1=R0;        R0 = match_offset; break;
	    case 2: match_offset = R2; R2=R0;        R0 = match_offset; break;
	    case 3: match_offset = 1;  R2=R1; R1=R0; R0 = match_offset; break;
	    default:
	      extra = lzx->extra_bits[match_offset];
	      LZX_READ_BITS(verbatim_bits, extra);
	      match_offset = lzx->position_base[match_offset] - 2 + verbatim_bits;
	      R2 = R1; R1 = R0; R0 = match_offset;
	    }

	    if ((window_posn + match_length) > lzx->window_size) {
	      cli_dbgmsg("lzx_decompress: match ran over window wrap\n");
	      return lzx->error = CL_EFORMAT;
	    }
	    
	    /* copy match */
	    rundest = &window[window_posn];
	    i = match_length;
	    /* does match offset wrap the window? */
	    if (match_offset > window_posn) {
	      /* j = length from match offset to end of window */
	      j = match_offset - window_posn;
	      if (j > (int) lzx->window_size) {
	        cli_dbgmsg("lzx_decompress: match offset beyond window boundaries\n");
		return lzx->error = CL_EFORMAT;
	      }
	      runsrc = &window[lzx->window_size - j];
	      if (j < i) {
		/* if match goes over the window edge, do two copy runs */
		i -= j; while (j-- > 0) *rundest++ = *runsrc++;
		runsrc = window;
	      }
	      while (i-- > 0) *rundest++ = *runsrc++;
	    }
	    else {
	      runsrc = rundest - match_offset;
	      while (i-- > 0) *rundest++ = *runsrc++;
	    }

	    this_run    -= match_length;
	    window_posn += match_length;
	  }
	} /* while (this_run > 0) */
	break;

      case LZX_BLOCKTYPE_ALIGNED:
	while (this_run > 0) {
	  LZX_READ_HUFFSYM(MAINTREE, main_element);
	  if (main_element < LZX_NUM_CHARS) {
	    /* literal: 0 to LZX_NUM_CHARS-1 */
	    window[window_posn++] = main_element;
	    this_run--;
	  }
	  else {
	    /* match: LZX_NUM_CHARS + ((slot<<3) | length_header (3 bits)) */
	    main_element -= LZX_NUM_CHARS;

	    /* get match length */
	    match_length = main_element & LZX_NUM_PRIMARY_LENGTHS;
	    if (match_length == LZX_NUM_PRIMARY_LENGTHS) {
	      LZX_READ_HUFFSYM(LENGTH, length_footer);
	      match_length += length_footer;
	    }
	    match_length += LZX_MIN_MATCH;

	    /* get match offset */
	    switch ((match_offset = (main_element >> 3))) {
	    case 0: match_offset = R0;                             break;
	    case 1: match_offset = R1; R1 = R0; R0 = match_offset; break;
	    case 2: match_offset = R2; R2 = R0; R0 = match_offset; break;
	    default:
	      extra = lzx->extra_bits[match_offset];
	      match_offset = lzx->position_base[match_offset] - 2;
	      if (extra > 3) {
		/* verbatim and aligned bits */
		extra -= 3;
		LZX_READ_BITS(verbatim_bits, extra);
		match_offset += (verbatim_bits << 3);
		LZX_READ_HUFFSYM(ALIGNED, aligned_bits);
		match_offset += aligned_bits;
	      }
	      else if (extra == 3) {
		/* aligned bits only */
		LZX_READ_HUFFSYM(ALIGNED, aligned_bits);
		match_offset += aligned_bits;
	      }
	      else if (extra > 0) { /* extra==1, extra==2 */
		/* verbatim bits only */
		LZX_READ_BITS(verbatim_bits, extra);
		match_offset += verbatim_bits;
	      }
	      else /* extra == 0 */ {
		/* ??? not defined in LZX specification! */
		match_offset = 1;
	      }
	      /* update repeated offset LRU queue */
	      R2 = R1; R1 = R0; R0 = match_offset;
	    }

	    if ((window_posn + match_length) > lzx->window_size) {
	      cli_dbgmsg("lzx_decompress: match ran over window wrap\n");
	      return lzx->error = CL_EFORMAT;
	    }

	    /* copy match */
	    rundest = &window[window_posn];
	    i = match_length;
	    /* does match offset wrap the window? */
	    if (match_offset > window_posn) {
	      /* j = length from match offset to end of window */
	      j = match_offset - window_posn;
	      if (j > (int) lzx->window_size) {
	        cli_dbgmsg("lzx_decompress: match offset beyond window boundaries\n");
		return lzx->error = CL_EFORMAT;
	      }
	      runsrc = &window[lzx->window_size - j];
	      if (j < i) {
		/* if match goes over the window edge, do two copy runs */
		i -= j; while (j-- > 0) *rundest++ = *runsrc++;
		runsrc = window;
	      }
	      while (i-- > 0) *rundest++ = *runsrc++;
	    }
	    else {
	      runsrc = rundest - match_offset;
	      while (i-- > 0) *rundest++ = *runsrc++;
	    }

	    this_run    -= match_length;
	    window_posn += match_length;
	  }
	} /* while (this_run > 0) */
	break;

      case LZX_BLOCKTYPE_UNCOMPRESSED:
	/* as this_run is limited not to wrap a frame, this also means it
	 * won't wrap the window (as the window is a multiple of 32k) */
	rundest = &window[window_posn];
	window_posn += this_run;
	while (this_run > 0) {
	  if ((i = i_end - i_ptr)) {
	    if (i > this_run) i = this_run;
	    memcpy(rundest, i_ptr, (size_t) i);
	    rundest  += i;
	    i_ptr    += i;
	    this_run -= i;
	  }
	  else {
	    if (lzx_read_input(lzx)) return lzx->error;
	    i_ptr = lzx->i_ptr;
	    i_end = lzx->i_end;
	  }
	}
	break;

      default:
	return lzx->error = CL_EFORMAT; /* might as well */
      }

      /* did the final match overrun our desired this_run length? */
      if (this_run < 0) {
	if ((unsigned int)(-this_run) > lzx->block_remaining) {
	  cli_dbgmsg("lzx_decompress: overrun went past end of block by %d (%d remaining)\n", -this_run, lzx->block_remaining);
	  return lzx->error = CL_EFORMAT;
	}
	lzx->block_remaining -= -this_run;
      }
    } /* while (bytes_todo > 0) */

    /* streams don't extend over frame boundaries */
    if ((window_posn - lzx->frame_posn) != frame_size) {
      cli_dbgmsg("lzx_decompress: decode beyond output frame limits! %d != %d\n", window_posn - lzx->frame_posn, frame_size);
      return lzx->error = CL_EFORMAT;
    }

    /* re-align input bitstream */
    if (bits_left > 0) LZX_ENSURE_BITS(16);
    if (bits_left & 15) LZX_REMOVE_BITS(bits_left & 15);

    /* check that we've used all of the previous frame first */
    if (lzx->o_ptr != lzx->o_end) {
      cli_dbgmsg("lzx_decompress: %d avail bytes, new %d frame\n", lzx->o_end-lzx->o_ptr, frame_size);
      return lzx->error = CL_EFORMAT;
    }

    /* does this intel block _really_ need decoding? */
    if (lzx->intel_started && lzx->intel_filesize &&
	(lzx->frame <= 32768) && (frame_size > 10))
    {
      unsigned char *data    = &lzx->e8_buf[0];
      unsigned char *dataend = &lzx->e8_buf[frame_size - 10];
      signed int curpos      = lzx->intel_curpos;
      signed int filesize    = lzx->intel_filesize;
      signed int abs_off, rel_off;

      /* copy e8 block to the e8 buffer and tweak if needed */
      lzx->o_ptr = data;
      memcpy(data, &lzx->window[lzx->frame_posn], frame_size);

      while (data < dataend) {
	if (*data++ != 0xE8) { curpos++; continue; }
	abs_off = data[0] | (data[1]<<8) | (data[2]<<16) | (data[3]<<24);
	if ((abs_off >= -curpos) && (abs_off < filesize)) {
	  rel_off = (abs_off >= 0) ? abs_off - curpos : abs_off + filesize;
	  data[0] = (unsigned char) rel_off;
	  data[1] = (unsigned char) (rel_off >> 8);
	  data[2] = (unsigned char) (rel_off >> 16);
	  data[3] = (unsigned char) (rel_off >> 24);
	}
	data += 4;
	curpos += 5;
      }
      lzx->intel_curpos += frame_size;
    }
    else {
      lzx->o_ptr = &lzx->window[lzx->frame_posn];
      if (lzx->intel_filesize) lzx->intel_curpos += frame_size;
    }
    lzx->o_end = &lzx->o_ptr[frame_size];

    /* write a frame */
    i = (out_bytes < (off_t)frame_size) ? (unsigned int)out_bytes : frame_size;
    if (lzx->wflag && cli_writen(lzx->ofd, lzx->o_ptr, i) != i) {
      return lzx->error = CL_EIO;
    }
    lzx->o_ptr  += i;
    lzx->offset += i;
    out_bytes   -= i;

    /* advance frame start position */
    lzx->frame_posn += frame_size;
    lzx->frame++;

    /* wrap window / frame position pointers */
    if (window_posn == lzx->window_size)     window_posn = 0;
    if (lzx->frame_posn == lzx->window_size) lzx->frame_posn = 0;

  } /* while (lzx->frame < end_frame) */

  if (out_bytes) {
    cli_dbgmsg("lzx_decompress: bytes left to output\n");
    return lzx->error = CL_EFORMAT;
  }

  /* store local state */
  LZX_STORE_BITS;
  lzx->window_posn = window_posn;
  lzx->R0 = R0;
  lzx->R1 = R1;
  lzx->R2 = R2;

  return CL_SUCCESS;
}

void lzx_free(struct lzx_stream *lzx) {
  if (lzx) {
    free(lzx->inbuf);
    free(lzx->window);
    free(lzx);
  }
}

/***************************************************************************
 *			 Quantum decompression implementation 
 ***************************************************************************
 * The Quantum method was created by David Stafford, adapted by Microsoft
 * Corporation.
 *
 * This decompressor is based on an implementation by Matthew Russotto, used
 * with permission.
 *
 * This decompressor was researched and implemented by Matthew Russotto. It
 * has since been tidied up by Stuart Caie. More information can be found at
 * http://www.speakeasy.org/~russotto/quantumcomp.html
 */

/* Quantum decompressor bitstream reading macros
 *
 * QTM_STORE_BITS        stores bitstream state in qtm_stream structure
 * QTM_RESTORE_BITS      restores bitstream state from qtm_stream structure
 * QTM_READ_BITS(var,n)  takes N bits from the buffer and puts them in var
 * QTM_FILL_BUFFER       if there is room for another 16 bits, reads another
 *                   16 bits from the input stream.
 * QTM_PEEK_BITS(n)      extracts without removing N bits from the bit buffer
 * QTM_REMOVE_BITS(n)    removes N bits from the bit buffer
 *
 * These bit access routines work by using the area beyond the MSB and the
 * LSB as a free source of zeroes. This avoids having to mask any bits.
 * So we have to know the bit width of the bitbuffer variable.
 */

#define QTM_BITBUF_WIDTH (sizeof(unsigned int) * CHAR_BIT)

#define QTM_STORE_BITS do {                                                 \
  qtm->i_ptr      = i_ptr;                                              \
  qtm->i_end      = i_end;                                              \
  qtm->bit_buffer = bit_buffer;                                         \
  qtm->bits_left  = bits_left;                                          \
} while (0)

#define QTM_RESTORE_BITS do {                                               \
  i_ptr      = qtm->i_ptr;                                              \
  i_end      = qtm->i_end;                                              \
  bit_buffer = qtm->bit_buffer;                                         \
  bits_left  = qtm->bits_left;                                          \
} while (0)

/* adds 16 bits to bit buffer, if there's space for the new bits */
#define QTM_FILL_BUFFER do {                                                \
  if (bits_left <= (QTM_BITBUF_WIDTH - 16)) {                               \
    if (i_ptr >= i_end) {                                               \
      if (qtm_read_input(qtm)) return qtm->error;                      \
      i_ptr = qtm->i_ptr;                                               \
      i_end = qtm->i_end;                                               \
    }                                                                   \
    bit_buffer |= ((i_ptr[0] << 8) | i_ptr[1])                          \
                  << (QTM_BITBUF_WIDTH - 16 - bits_left);                   \
    bits_left  += 16;                                                   \
    i_ptr      += 2;                                                    \
  }                                                                     \
} while (0)

#define QTM_PEEK_BITS(n)   (bit_buffer >> (QTM_BITBUF_WIDTH - (n)))
#define QTM_REMOVE_BITS(n) ((bit_buffer <<= (n)), (bits_left -= (n)))

#define QTM_READ_BITS(val, bits) do {                                       \
  (val) = 0;                                                            \
  for (bits_needed = (bits); bits_needed > 0; bits_needed -= bit_run) { \
    QTM_FILL_BUFFER;                                                        \
    bit_run = (bits_left < bits_needed) ? bits_left : bits_needed;      \
    (val) = ((val) << bit_run) | QTM_PEEK_BITS(bit_run);                    \
    QTM_REMOVE_BITS(bit_run);                                               \
  }                                                                     \
} while (0)

static int qtm_read_input(struct qtm_stream *qtm) {
  int read = qtm->read ? qtm->read(qtm->file, &qtm->inbuf[0], (int)qtm->inbuf_size) : cli_readn(qtm->fd, &qtm->inbuf[0], (int)qtm->inbuf_size);
  if (read < 0) return qtm->error = CL_EIO;

  qtm->i_ptr = &qtm->inbuf[0];
  qtm->i_end = &qtm->inbuf[read];
  return CL_SUCCESS;
}

/* Arithmetic decoder:
 * 
 * QTM_GET_SYMBOL(model, var) fetches the next symbol from the stated model
 * and puts it in var.
 *
 * If necessary, qtm_update_model() is called.
 */
#define QTM_GET_SYMBOL(model, var) do {                                     \
  range = ((H - L) & 0xFFFF) + 1;                                       \
  symf = ((((C - L + 1) * model.syms[0].cumfreq)-1) / range) & 0xFFFF;  \
                                                                        \
  for (i = 1; i < model.entries; i++) {                                 \
    if (model.syms[i].cumfreq <= symf) break;                           \
  }                                                                     \
  (var) = model.syms[i-1].sym;                                          \
                                                                        \
  range = (H - L) + 1;                                                  \
  symf = model.syms[0].cumfreq;                                         \
  H = L + ((model.syms[i-1].cumfreq * range) / symf) - 1;               \
  L = L + ((model.syms[i].cumfreq   * range) / symf);                   \
                                                                        \
  do { model.syms[--i].cumfreq += 8; } while (i > 0);                   \
  if (model.syms[0].cumfreq > 3800) qtm_update_model(&model);          \
                                                                        \
  while (1) {                                                           \
    if ((L & 0x8000) != (H & 0x8000)) {                                 \
      if ((L & 0x4000) && !(H & 0x4000)) {                              \
        /* underflow case */                                            \
        C ^= 0x4000; L &= 0x3FFF; H |= 0x4000;                          \
      }                                                                 \
      else break;                                                       \
    }                                                                   \
    L <<= 1; H = (H << 1) | 1;                                          \
    QTM_FILL_BUFFER;                                                        \
    C  = (C << 1) | QTM_PEEK_BITS(1);                                       \
    QTM_REMOVE_BITS(1);                                                     \
  }                                                                     \
} while (0)

static void qtm_update_model(struct qtm_model *model) {
  struct qtm_modelsym tmp;
  int i, j;

  if (--model->shiftsleft) {
    for (i = model->entries - 1; i >= 0; i--) {
      /* -1, not -2; the 0 entry saves this */
      model->syms[i].cumfreq >>= 1;
      if (model->syms[i].cumfreq <= model->syms[i+1].cumfreq) {
	model->syms[i].cumfreq = model->syms[i+1].cumfreq + 1;
      }
    }
  }
  else {
    model->shiftsleft = 50;
    for (i = 0; i < model->entries; i++) {
      /* no -1, want to include the 0 entry */
      /* this converts cumfreqs into frequencies, then shifts right */
      model->syms[i].cumfreq -= model->syms[i+1].cumfreq;
      model->syms[i].cumfreq++; /* avoid losing things entirely */
      model->syms[i].cumfreq >>= 1;
    }

    /* now sort by frequencies, decreasing order -- this must be an
     * inplace selection sort, or a sort with the same (in)stability
     * characteristics */
    for (i = 0; i < model->entries - 1; i++) {
      for (j = i + 1; j < model->entries; j++) {
	if (model->syms[i].cumfreq < model->syms[j].cumfreq) {
	  tmp = model->syms[i];
	  model->syms[i] = model->syms[j];
	  model->syms[j] = tmp;
	}
      }
    }

    /* then convert frequencies back to cumfreq */
    for (i = model->entries - 1; i >= 0; i--) {
      model->syms[i].cumfreq += model->syms[i+1].cumfreq;
    }
  }
}

/* Initialises a model to decode symbols from [start] to [start]+[len]-1 */
static void qtm_init_model(struct qtm_model *model,
			    struct qtm_modelsym *syms, int start, int len)
{
  int i;

  model->shiftsleft = 4;
  model->entries    = len;
  model->syms       = syms;

  for (i = 0; i <= len; i++) {
    syms[i].sym     = start + i; /* actual symbol */
    syms[i].cumfreq = len - i;   /* current frequency of that symbol */
  }
}


/*-------- main Quantum code --------*/

struct qtm_stream *qtm_init(int fd, int ofd,
			      int window_bits, int input_buffer_size,
			      struct cab_file *file,
			      int (*read)(struct cab_file *, unsigned char *, int))
{
  unsigned int window_size = 1 << window_bits;
  struct qtm_stream *qtm;
  unsigned offset;
  int i;

  /* Quantum supports window sizes of 2^10 (1Kb) through 2^21 (2Mb) */

  /* tk: temporary fix: only process 32KB+ window sizes */
  if (window_bits < 15 || window_bits > 21) return NULL;

  input_buffer_size = (input_buffer_size + 1) & -2;
  if (input_buffer_size < 2) return NULL;

  /* allocate decompression state */
  if (!(qtm = cli_malloc(sizeof(struct qtm_stream)))) {
    return NULL;
  }

  for (i = 0, offset = 0; i < 42; i++) {
    qtm->position_base[i] = offset;
    qtm->extra_bits[i] = ((i < 2) ? 0 : (i - 2)) >> 1;
    offset += 1 << qtm->extra_bits[i];
  }

  for (i = 0, offset = 0; i < 26; i++) {
    qtm->length_base[i] = offset;
    qtm->length_extra[i] = (i < 2 ? 0 : i - 2) >> 2;
    offset += 1 << qtm->length_extra[i];
  }
  qtm->length_base[26] = 254; qtm->length_extra[26] = 0;

  /* allocate decompression window and input buffer */
  qtm->window = cli_malloc((size_t) window_size);
  if (!qtm->window) {
    free(qtm);
    return NULL;
  }

  qtm->inbuf  = cli_malloc((size_t) input_buffer_size);
  if (!qtm->inbuf) {
    free(qtm->window);
    free(qtm);
    return NULL;
  }

  /* initialise decompression state */
  qtm->fd	   = fd;
  qtm->ofd	   = ofd;
  qtm->wflag	   = 1;
  qtm->inbuf_size  = input_buffer_size;
  qtm->window_size = window_size;
  qtm->window_posn = 0;
  qtm->frame_start = 0;
  qtm->header_read = 0;
  qtm->error       = CL_SUCCESS;

  qtm->i_ptr = qtm->i_end = &qtm->inbuf[0];
  qtm->o_ptr = qtm->o_end = &qtm->window[0];
  qtm->bits_left = 0;
  qtm->bit_buffer = 0;

  /* initialise arithmetic coding models
   * - model 4    depends on window size, ranges from 20 to 24
   * - model 5    depends on window size, ranges from 20 to 36
   * - model 6pos depends on window size, ranges from 20 to 42
   */
  i = window_bits * 2;
  qtm_init_model(&qtm->model0,    &qtm->m0sym[0],   0, 64);
  qtm_init_model(&qtm->model1,    &qtm->m1sym[0],  64, 64);
  qtm_init_model(&qtm->model2,    &qtm->m2sym[0], 128, 64);
  qtm_init_model(&qtm->model3,    &qtm->m3sym[0], 192, 64);
  qtm_init_model(&qtm->model4,    &qtm->m4sym[0],   0, (i > 24) ? 24 : i);
  qtm_init_model(&qtm->model5,    &qtm->m5sym[0],   0, (i > 36) ? 36 : i);
  qtm_init_model(&qtm->model6,    &qtm->m6sym[0],   0, i);
  qtm_init_model(&qtm->model6len, &qtm->m6lsym[0],  0, 27);
  qtm_init_model(&qtm->model7,    &qtm->m7sym[0],   0, 7);

  qtm->file = file;
  qtm->read = read;

  /* all ok */
  return qtm;
}

int qtm_decompress(struct qtm_stream *qtm, off_t out_bytes) {
  unsigned int frame_start, frame_end, window_posn, match_offset, range;
  unsigned char *window, *i_ptr, *i_end, *runsrc, *rundest;
  int i, j, selector, extra, sym, match_length;
  unsigned short H, L, C, symf;

  register unsigned int bit_buffer;
  register unsigned char bits_left;
  unsigned char bits_needed, bit_run;

  /* easy answers */
  if (!qtm || (out_bytes < 0)) return CL_ENULLARG;
  if (qtm->error) return qtm->error;

  /* flush out any stored-up bytes before we begin */
  i = qtm->o_end - qtm->o_ptr;
  if ((off_t) i > out_bytes) i = (int) out_bytes;
  if (i) {
    if (qtm->wflag && cli_writen(qtm->ofd, qtm->o_ptr, i) != i) {
      return qtm->error = CL_EIO;
    }
    qtm->o_ptr  += i;
    out_bytes   -= i;
  }
  if (out_bytes == 0) return CL_SUCCESS;

  /* restore local state */
  QTM_RESTORE_BITS;
  window = qtm->window;
  window_posn = qtm->window_posn;
  frame_start = qtm->frame_start;
  H = qtm->H;
  L = qtm->L;
  C = qtm->C;

  /* while we do not have enough decoded bytes in reserve: */
  while ((qtm->o_end - qtm->o_ptr) < out_bytes) {

    /* read header if necessary. Initialises H, L and C */
    if (!qtm->header_read) {
      H = 0xFFFF; L = 0; QTM_READ_BITS(C, 16);
      qtm->header_read = 1;
    }

    /* decode more, at most up to to frame boundary */
    frame_end = window_posn + (out_bytes - (qtm->o_end - qtm->o_ptr));
    if ((frame_start + QTM_FRAME_SIZE) < frame_end) {
      frame_end = frame_start + QTM_FRAME_SIZE;
    }

    while (window_posn < frame_end) {
      QTM_GET_SYMBOL(qtm->model7, selector);
      if (selector < 4) {
	struct qtm_model *mdl = (selector == 0) ? &qtm->model0 :
	                        ((selector == 1) ? &qtm->model1 :
				((selector == 2) ? &qtm->model2 :
                                                   &qtm->model3));
	QTM_GET_SYMBOL((*mdl), sym);
	window[window_posn++] = sym;
      }
      else {
	switch (selector) {
	case 4: /* selector 4 = fixed length match (3 bytes) */
	  QTM_GET_SYMBOL(qtm->model4, sym);
	  QTM_READ_BITS(extra, qtm->extra_bits[sym]);
	  match_offset = qtm->position_base[sym] + extra + 1;
	  match_length = 3;
	  break;

	case 5: /* selector 5 = fixed length match (4 bytes) */
	  QTM_GET_SYMBOL(qtm->model5, sym);
	  QTM_READ_BITS(extra, qtm->extra_bits[sym]);
	  match_offset = qtm->position_base[sym] + extra + 1;
	  match_length = 4;
	  break;

	case 6: /* selector 6 = variable length match */
	  QTM_GET_SYMBOL(qtm->model6len, sym);
	  QTM_READ_BITS(extra, qtm->length_extra[sym]);
	  match_length = qtm->length_base[sym] + extra + 5;

	  QTM_GET_SYMBOL(qtm->model6, sym);
	  QTM_READ_BITS(extra, qtm->extra_bits[sym]);
	  match_offset = qtm->position_base[sym] + extra + 1;
	  break;

	default:
	  /* should be impossible, model7 can only return 0-6 */
	  return qtm->error = CL_EFORMAT;
	}

	rundest = &window[window_posn];
	i = match_length;
	/* does match offset wrap the window? */
	if (match_offset > window_posn) {
	  /* j = length from match offset to end of window */
	  j = match_offset - window_posn;
	  if (j > (int) qtm->window_size) {
	    cli_dbgmsg("qtm_decompress: match offset beyond window boundaries\n");
	    return qtm->error = CL_EFORMAT;
	  }
	  runsrc = &window[qtm->window_size - j];
	  if (j < i) {
	    /* if match goes over the window edge, do two copy runs */
	    i -= j; while (j-- > 0) *rundest++ = *runsrc++;
	    runsrc = window;
	  }
	  while (i-- > 0) *rundest++ = *runsrc++;
	}
	else {
	  runsrc = rundest - match_offset;
	  while (i-- > 0) *rundest++ = *runsrc++;
	}
	window_posn += match_length;
      }
    } /* while (window_posn < frame_end) */

    qtm->o_end = &window[window_posn];

    /* another frame completed? */
    if ((window_posn - frame_start) >= QTM_FRAME_SIZE) {
      if ((window_posn - frame_start) != QTM_FRAME_SIZE) {
	cli_dbgmsg("qtm_decompress: overshot frame alignment\n");
	return qtm->error = CL_EFORMAT;
      }

      /* re-align input */
      if (bits_left & 7) QTM_REMOVE_BITS(bits_left & 7);
      do { QTM_READ_BITS(i, 8); } while (i != 0xFF);
      qtm->header_read = 0;

      /* window wrap? */
      if (window_posn == qtm->window_size) {
	/* flush all currently stored data */
	i = (qtm->o_end - qtm->o_ptr);
	if (qtm->wflag && cli_writen(qtm->ofd, qtm->o_ptr, i) != i) {
	  return qtm->error = CL_EIO;
	}
	out_bytes -= i;
	qtm->o_ptr = &window[0];
	qtm->o_end = &window[0];
	window_posn = 0;
      }

      frame_start = window_posn;
    }

  } /* while (more bytes needed) */

  if (out_bytes) {
    i = (int) out_bytes;
    if (qtm->wflag && cli_writen(qtm->ofd, qtm->o_ptr, i) != i) {
      return qtm->error = CL_EIO;
    }
    qtm->o_ptr += i;
  }

  /* store local state */
  QTM_STORE_BITS;
  qtm->window_posn = window_posn;
  qtm->frame_start = frame_start;
  qtm->H = H;
  qtm->L = L;
  qtm->C = C;

  return CL_SUCCESS;
}

void qtm_free(struct qtm_stream *qtm) {
  if (qtm) {
    free(qtm->window);
    free(qtm->inbuf);
    free(qtm);
  }
}

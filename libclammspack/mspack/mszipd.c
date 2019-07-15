/* This file is part of libmspack.
 * (C) 2003-2010 Stuart Caie.
 *
 * The deflate method was created by Phil Katz. MSZIP is equivalent to the
 * deflate method.
 *
 * libmspack is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License (LGPL) version 2.1
 *
 * For further details, see the file COPYING.LIB distributed with libmspack
 */

/* MS-ZIP decompression implementation. */

#include <system.h>
#include <mszip.h>

/* import bit-reading macros and code */
#define BITS_TYPE struct mszipd_stream
#define BITS_VAR zip
#define BITS_ORDER_LSB
#define BITS_LSB_TABLE
#define READ_BYTES do {         \
    READ_IF_NEEDED;             \
    INJECT_BITS(*i_ptr++, 8);   \
} while (0)
#include <readbits.h>

/* import huffman macros and code */
#define TABLEBITS(tbl)      MSZIP_##tbl##_TABLEBITS
#define MAXSYMBOLS(tbl)     MSZIP_##tbl##_MAXSYMBOLS
#define HUFF_TABLE(tbl,idx) zip->tbl##_table[idx]
#define HUFF_LEN(tbl,idx)   zip->tbl##_len[idx]
#define HUFF_ERROR          return INF_ERR_HUFFSYM
#include <readhuff.h>

#define FLUSH_IF_NEEDED do {                            \
    if (zip->window_posn == MSZIP_FRAME_SIZE) {         \
        if (zip->flush_window(zip, MSZIP_FRAME_SIZE)) { \
            return INF_ERR_FLUSH;                       \
        }                                               \
        zip->window_posn = 0;                           \
    }                                                   \
} while (0)

/* match lengths for literal codes 257.. 285 */
static const unsigned short lit_lengths[29] = {
  3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27,
  31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258
};

/* match offsets for distance codes 0 .. 29 */
static const unsigned short dist_offsets[30] = {
  1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385,
  513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577
};

/* extra bits required for literal codes 257.. 285 */
static const unsigned char lit_extrabits[29] = {
  0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2,
  2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0
};

/* extra bits required for distance codes 0 .. 29 */
static const unsigned char dist_extrabits[30] = {
  0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6,
  6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13
};

/* the order of the bit length Huffman code lengths */
static const unsigned char bitlen_order[19] = {
  16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
};

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

static int zip_read_lens(struct mszipd_stream *zip) {
  /* for the bit buffer and huffman decoding */
  register unsigned int bit_buffer;
  register int bits_left;
  unsigned char *i_ptr, *i_end;

  /* bitlen Huffman codes -- immediate lookup, 7 bit max code length */
  unsigned short bl_table[(1 << 7)];
  unsigned char bl_len[19];

  unsigned char lens[MSZIP_LITERAL_MAXSYMBOLS + MSZIP_DISTANCE_MAXSYMBOLS];
  unsigned int lit_codes, dist_codes, code, last_code=0, bitlen_codes, i, run;

  RESTORE_BITS;

  /* read the number of codes */
  READ_BITS(lit_codes,    5); lit_codes    += 257;
  READ_BITS(dist_codes,   5); dist_codes   += 1;
  READ_BITS(bitlen_codes, 4); bitlen_codes += 4;
  if (lit_codes  > MSZIP_LITERAL_MAXSYMBOLS)  return INF_ERR_SYMLENS;
  if (dist_codes > MSZIP_DISTANCE_MAXSYMBOLS) return INF_ERR_SYMLENS;

  /* read in the bit lengths in their unusual order */
  for (i = 0; i < bitlen_codes; i++) READ_BITS(bl_len[bitlen_order[i]], 3);
  while (i < 19) bl_len[bitlen_order[i++]] = 0;

  /* create decoding table with an immediate lookup */
  if (make_decode_table(19, 7, &bl_len[0], &bl_table[0])) {
    return INF_ERR_BITLENTBL;
  }

  /* read literal / distance code lengths */
  for (i = 0; i < (lit_codes + dist_codes); i++) {
    /* single-level huffman lookup */
    ENSURE_BITS(7);
    code = bl_table[PEEK_BITS(7)];
    REMOVE_BITS(bl_len[code]);

    if (code < 16) lens[i] = last_code = code;
    else {
      switch (code) {
      case 16: READ_BITS(run, 2); run += 3;  code = last_code; break;
      case 17: READ_BITS(run, 3); run += 3;  code = 0;         break;
      case 18: READ_BITS(run, 7); run += 11; code = 0;         break;
      default: D(("bad code!: %u", code)) return INF_ERR_BADBITLEN;
      }
      if ((i + run) > (lit_codes + dist_codes)) return INF_ERR_BITOVERRUN;
      while (run--) lens[i++] = code;
      i--;
    }
  }

  /* copy LITERAL code lengths and clear any remaining */
  i = lit_codes;
  zip->sys->copy(&lens[0], &zip->LITERAL_len[0], i);
  while (i < MSZIP_LITERAL_MAXSYMBOLS) zip->LITERAL_len[i++] = 0;

  i = dist_codes;
  zip->sys->copy(&lens[lit_codes], &zip->DISTANCE_len[0], i);
  while (i < MSZIP_DISTANCE_MAXSYMBOLS) zip->DISTANCE_len[i++] = 0;

  STORE_BITS;
  return 0;
}

/* a clean implementation of RFC 1951 / inflate */
static int inflate(struct mszipd_stream *zip) {
  unsigned int last_block, block_type, distance, length, this_run, i;

  /* for the bit buffer and huffman decoding */
  register unsigned int bit_buffer;
  register int bits_left;
  register unsigned short sym;
  unsigned char *i_ptr, *i_end;

  RESTORE_BITS;

  do {
    /* read in last block bit */
    READ_BITS(last_block, 1);

    /* read in block type */
    READ_BITS(block_type, 2);

    if (block_type == 0) {
      /* uncompressed block */
      unsigned char lens_buf[4];

      /* go to byte boundary */
      i = bits_left & 7; REMOVE_BITS(i);

      /* read 4 bytes of data, emptying the bit-buffer if necessary */
      for (i = 0; (bits_left >= 8); i++) {
        if (i == 4) return INF_ERR_BITBUF;
        lens_buf[i] = PEEK_BITS(8);
        REMOVE_BITS(8);
      }
      if (bits_left != 0) return INF_ERR_BITBUF;
      while (i < 4) {
        READ_IF_NEEDED;
        lens_buf[i++] = *i_ptr++;
      }

      /* get the length and its complement */
      length = lens_buf[0] | (lens_buf[1] << 8);
      i      = lens_buf[2] | (lens_buf[3] << 8);
      if (length != (~i & 0xFFFF)) return INF_ERR_COMPLEMENT;

      /* read and copy the uncompressed data into the window */
      while (length > 0) {
        READ_IF_NEEDED;

        this_run = length;
        if (this_run > (unsigned int)(i_end - i_ptr)) this_run = i_end - i_ptr;
        if (this_run > (MSZIP_FRAME_SIZE - zip->window_posn))
          this_run = MSZIP_FRAME_SIZE - zip->window_posn;

        zip->sys->copy(i_ptr, &zip->window[zip->window_posn], this_run);
        zip->window_posn += this_run;
        i_ptr    += this_run;
        length   -= this_run;
        FLUSH_IF_NEEDED;
      }
    }
    else if ((block_type == 1) || (block_type == 2)) {
      /* Huffman-compressed LZ77 block */
      unsigned int match_posn, code;

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
        STORE_BITS;
        if ((i = zip_read_lens(zip))) return i;
        RESTORE_BITS;
      }

      /* now huffman lengths are read for either kind of block, 
       * create huffman decoding tables */
      if (make_decode_table(MSZIP_LITERAL_MAXSYMBOLS, MSZIP_LITERAL_TABLEBITS,
                            &zip->LITERAL_len[0], &zip->LITERAL_table[0]))
      {
        return INF_ERR_LITERALTBL;
      }

      if (make_decode_table(MSZIP_DISTANCE_MAXSYMBOLS,MSZIP_DISTANCE_TABLEBITS,
                            &zip->DISTANCE_len[0], &zip->DISTANCE_table[0]))
      {
        return INF_ERR_DISTANCETBL;
      }

      /* decode forever until end of block code */
      for (;;) {
        READ_HUFFSYM(LITERAL, code);
        if (code < 256) {
          zip->window[zip->window_posn++] = (unsigned char) code;
          FLUSH_IF_NEEDED;
        }
        else if (code == 256) {
          /* END OF BLOCK CODE: loop break point */
          break;
        }
        else {
          code -= 257; /* codes 257-285 are matches */
          if (code >= 29) return INF_ERR_LITCODE; /* codes 286-287 are illegal */
          READ_BITS_T(length, lit_extrabits[code]);
          length += lit_lengths[code];

          READ_HUFFSYM(DISTANCE, code);
          if (code >= 30) return INF_ERR_DISTCODE;
          READ_BITS_T(distance, dist_extrabits[code]);
          distance += dist_offsets[code];

          /* match position is window position minus distance. If distance
           * is more than window position numerically, it must 'wrap
           * around' the frame size. */ 
          match_posn = ((distance > zip->window_posn) ? MSZIP_FRAME_SIZE : 0)
            + zip->window_posn - distance;

          /* copy match */
          if (length < 12) {
            /* short match, use slower loop but no loop setup code */
            while (length--) {
              zip->window[zip->window_posn++] = zip->window[match_posn++];
              match_posn &= MSZIP_FRAME_SIZE - 1;
              FLUSH_IF_NEEDED;
            }
          }
          else {
            /* longer match, use faster loop but with setup expense */
            unsigned char *runsrc, *rundest;
            do {
              this_run = length;
              if ((match_posn + this_run) > MSZIP_FRAME_SIZE)
                this_run = MSZIP_FRAME_SIZE - match_posn;
              if ((zip->window_posn + this_run) > MSZIP_FRAME_SIZE)
                this_run = MSZIP_FRAME_SIZE - zip->window_posn;

              rundest = &zip->window[zip->window_posn]; zip->window_posn += this_run;
              runsrc  = &zip->window[match_posn];  match_posn  += this_run;
              length -= this_run;
              while (this_run--) *rundest++ = *runsrc++;
              if (match_posn == MSZIP_FRAME_SIZE) match_posn = 0;
              FLUSH_IF_NEEDED;
            } while (length > 0);
          }

        } /* else (code >= 257) */

      } /* for(;;) -- break point at 'code == 256' */
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
  STORE_BITS;

  /* return success */
  return 0;
}

/* inflate() calls this whenever the window should be flushed. As
 * MSZIP only expands to the size of the window, the implementation used
 * simply keeps track of the amount of data flushed, and if more than 32k
 * is flushed, an error is raised.
 */  
static int mszipd_flush_window(struct mszipd_stream *zip,
                               unsigned int data_flushed)
{
  zip->bytes_output += data_flushed;
  if (zip->bytes_output > MSZIP_FRAME_SIZE) {
    D(("overflow: %u bytes flushed, total is now %u",
       data_flushed, zip->bytes_output))
    return 1;
  }
  return 0;
}

struct mszipd_stream *mszipd_init(struct mspack_system *system,
                                  struct mspack_file *input,
                                  struct mspack_file *output,
                                  int input_buffer_size,
                                  int repair_mode)
{
  struct mszipd_stream *zip;

  if (!system) return NULL;

  /* round up input buffer size to multiple of two */
  input_buffer_size = (input_buffer_size + 1) & -2;
  if (input_buffer_size < 2) return NULL;

  /* allocate decompression state */
  if (!(zip = (struct mszipd_stream *) system->alloc(system, sizeof(struct mszipd_stream)))) {
    return NULL;
  }

  /* allocate input buffer */
  zip->inbuf  = (unsigned char *) system->alloc(system, (size_t) input_buffer_size);
  if (!zip->inbuf) {
    system->free(zip);
    return NULL;
  }

  /* initialise decompression state */
  zip->sys             = system;
  zip->input           = input;
  zip->output          = output;
  zip->inbuf_size      = input_buffer_size;
  zip->input_end       = 0;
  zip->error           = MSPACK_ERR_OK;
  zip->repair_mode     = repair_mode;
  zip->flush_window    = &mszipd_flush_window;

  zip->i_ptr = zip->i_end = &zip->inbuf[0];
  zip->o_ptr = zip->o_end = NULL;
  zip->bit_buffer = 0; zip->bits_left = 0;
  return zip;
}

int mszipd_decompress(struct mszipd_stream *zip, off_t out_bytes) {
  /* for the bit buffer */
  register unsigned int bit_buffer;
  register int bits_left;
  unsigned char *i_ptr, *i_end;

  int i, state, error;

  /* easy answers */
  if (!zip || (out_bytes < 0)) return MSPACK_ERR_ARGS;
  if (zip->error) return zip->error;

  /* flush out any stored-up bytes before we begin */
  i = zip->o_end - zip->o_ptr;
  if ((off_t) i > out_bytes) i = (int) out_bytes;
  if (i) {
    if (zip->sys->write(zip->output, zip->o_ptr, i) != i) {
      return zip->error = MSPACK_ERR_WRITE;
    }
    zip->o_ptr  += i;
    out_bytes   -= i;
  }
  if (out_bytes == 0) return MSPACK_ERR_OK;


  while (out_bytes > 0) {
    /* unpack another block */
    RESTORE_BITS;

    /* skip to next read 'CK' header */
    i = bits_left & 7; REMOVE_BITS(i); /* align to bytestream */
    state = 0;
    do {
      READ_BITS(i, 8);
      if (i == 'C') state = 1;
      else if ((state == 1) && (i == 'K')) state = 2;
      else state = 0;
    } while (state != 2);

    /* inflate a block, repair and realign if necessary */
    zip->window_posn = 0;
    zip->bytes_output = 0;
    STORE_BITS;
    if ((error = inflate(zip))) {
      D(("inflate error %d", error))
      if (zip->repair_mode) {
        /* recover partially-inflated buffers */
        if (zip->bytes_output == 0 && zip->window_posn > 0) {
          zip->flush_window(zip, zip->window_posn);
        }
        zip->sys->message(NULL, "MSZIP error, %u bytes of data lost.",
                          MSZIP_FRAME_SIZE - zip->bytes_output);
        for (i = zip->bytes_output; i < MSZIP_FRAME_SIZE; i++) {
          zip->window[i] = '\0';
        }
        zip->bytes_output = MSZIP_FRAME_SIZE;
      }
      else {
        return zip->error = (error > 0) ? error : MSPACK_ERR_DECRUNCH;
      }
    }
    zip->o_ptr = &zip->window[0];
    zip->o_end = &zip->o_ptr[zip->bytes_output];

    /* write a frame */
    i = (out_bytes < (off_t)zip->bytes_output) ?
      (int)out_bytes : zip->bytes_output;
    if (zip->sys->write(zip->output, zip->o_ptr, i) != i) {
      return zip->error = MSPACK_ERR_WRITE;
    }

    /* mspack errors (i.e. read errors) are fatal and can't be recovered */
    if ((error > 0) && zip->repair_mode) return error;

    zip->o_ptr  += i;
    out_bytes   -= i;
  }

  if (out_bytes) {
    D(("bytes left to output"))
    return zip->error = MSPACK_ERR_DECRUNCH;
  }
  return MSPACK_ERR_OK;
}

int mszipd_decompress_kwaj(struct mszipd_stream *zip) {
    /* for the bit buffer */
    register unsigned int bit_buffer;
    register int bits_left;
    unsigned char *i_ptr, *i_end;

    int i, error, block_len;

    /* unpack blocks until block_len == 0 */
    for (;;) {
        RESTORE_BITS;

        /* align to bytestream, read block_len */
        i = bits_left & 7; REMOVE_BITS(i);
        READ_BITS(block_len, 8);
        READ_BITS(i, 8); block_len |= i << 8;

        if (block_len == 0) break;

        /* read "CK" header */
        READ_BITS(i, 8); if (i != 'C') return MSPACK_ERR_DATAFORMAT;
        READ_BITS(i, 8); if (i != 'K') return MSPACK_ERR_DATAFORMAT;

        /* inflate block */
        zip->window_posn = 0;
        zip->bytes_output = 0;
        STORE_BITS;
        if ((error = inflate(zip))) {
            D(("inflate error %d", error))
            return zip->error = (error > 0) ? error : MSPACK_ERR_DECRUNCH;
        }

        /* write inflated block */
        if (zip->sys->write(zip->output, &zip->window[0], zip->bytes_output)
            != zip->bytes_output) return zip->error = MSPACK_ERR_WRITE;
    }
    return MSPACK_ERR_OK;
}

void mszipd_free(struct mszipd_stream *zip) {
  struct mspack_system *sys;
  if (zip) {
    sys = zip->sys;
    sys->free(zip->inbuf);
    sys->free(zip);
  }
}

/* This file is part of libmspack.
 * (C) 2003-2004 Stuart Caie.
 *
 * The Quantum method was created by David Stafford, adapted by Microsoft
 * Corporation.
 *
 * This decompressor is based on an implementation by Matthew Russotto, used
 * with permission.
 *
 * libmspack is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License (LGPL) version 2.1
 *
 * For further details, see the file COPYING.LIB distributed with libmspack
 */

/* Quantum decompression implementation */

/* This decompressor was researched and implemented by Matthew Russotto. It
 * has since been tidied up by Stuart Caie. More information can be found at
 * http://www.speakeasy.org/~russotto/quantumcomp.html
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <mspack.h>
#include <system.h>
#include <qtm.h>

/* Quantum decompressor bitstream reading macros
 *
 * STORE_BITS        stores bitstream state in qtmd_stream structure
 * RESTORE_BITS      restores bitstream state from qtmd_stream structure
 * READ_BITS(var,n)  takes N bits from the buffer and puts them in var
 * FILL_BUFFER       if there is room for another 16 bits, reads another
 *                   16 bits from the input stream.
 * PEEK_BITS(n)      extracts without removing N bits from the bit buffer
 * REMOVE_BITS(n)    removes N bits from the bit buffer
 *
 * These bit access routines work by using the area beyond the MSB and the
 * LSB as a free source of zeroes. This avoids having to mask any bits.
 * So we have to know the bit width of the bitbuffer variable.
 */

#ifdef HAVE_LIMITS_H
# include <limits.h>
#endif
#ifndef CHAR_BIT
# define CHAR_BIT (8)
#endif
#define BITBUF_WIDTH (sizeof(unsigned int) * CHAR_BIT)

#define STORE_BITS do {                                                 \
  qtm->i_ptr      = i_ptr;                                              \
  qtm->i_end      = i_end;                                              \
  qtm->bit_buffer = bit_buffer;                                         \
  qtm->bits_left  = bits_left;                                          \
} while (0)

#define RESTORE_BITS do {                                               \
  i_ptr      = qtm->i_ptr;                                              \
  i_end      = qtm->i_end;                                              \
  bit_buffer = qtm->bit_buffer;                                         \
  bits_left  = qtm->bits_left;                                          \
} while (0)

/* adds 16 bits to bit buffer, if there's space for the new bits */
#define FILL_BUFFER do {                                                \
  if (bits_left <= (BITBUF_WIDTH - 16)) {                               \
    if (i_ptr >= i_end) {                                               \
      if (qtmd_read_input(qtm)) return qtm->error;                      \
      i_ptr = qtm->i_ptr;                                               \
      i_end = qtm->i_end;                                               \
    }                                                                   \
    bit_buffer |= ((i_ptr[0] << 8) | i_ptr[1])                          \
                  << (BITBUF_WIDTH - 16 - bits_left);                   \
    bits_left  += 16;                                                   \
    i_ptr      += 2;                                                    \
  }                                                                     \
} while (0)

#define PEEK_BITS(n)   (bit_buffer >> (BITBUF_WIDTH - (n)))
#define REMOVE_BITS(n) ((bit_buffer <<= (n)), (bits_left -= (n)))

#define READ_BITS(val, bits) do {                                       \
  (val) = 0;                                                            \
  for (bits_needed = (bits); bits_needed > 0; bits_needed -= bit_run) { \
    FILL_BUFFER;                                                        \
    bit_run = (bits_left < bits_needed) ? bits_left : bits_needed;      \
    (val) = ((val) << bit_run) | PEEK_BITS(bit_run);                    \
    REMOVE_BITS(bit_run);                                               \
  }                                                                     \
} while (0)

static int qtmd_read_input(struct qtmd_stream *qtm) {
  int read = qtm->sys->read(qtm->input, &qtm->inbuf[0], (int)qtm->inbuf_size);
  if (read < 0) return qtm->error = MSPACK_ERR_READ;

  qtm->i_ptr = &qtm->inbuf[0];
  qtm->i_end = &qtm->inbuf[read];
  return MSPACK_ERR_OK;
}

/* Quantum static data tables:
 *
 * Quantum uses 'position slots' to represent match offsets.  For every
 * match, a small 'position slot' number and a small offset from that slot
 * are encoded instead of one large offset.
 *
 * position_base[] is an index to the position slot bases
 *
 * extra_bits[] states how many bits of offset-from-base data is needed.
 *
 * length_base[] and length_extra[] are equivalent in function, but are
 * used for encoding selector 6 (variable length match) match lengths,
 * instead of match offsets.
 */
static unsigned int  position_base[42];
static unsigned char extra_bits[42], length_base[27], length_extra[27];

static void qtmd_static_init() {
  unsigned int i, offset;

  for (i = 0, offset = 0; i < 42; i++) {
    position_base[i] = offset;
    extra_bits[i] = ((i < 2) ? 0 : (i - 2)) >> 1;
    offset += 1 << extra_bits[i];
  }

  for (i = 0, offset = 0; i < 26; i++) {
    length_base[i] = offset;
    length_extra[i] = (i < 2 ? 0 : i - 2) >> 2;
    offset += 1 << length_extra[i];
  }
  length_base[26] = 254; length_extra[26] = 0;
}


/* Arithmetic decoder:
 * 
 * GET_SYMBOL(model, var) fetches the next symbol from the stated model
 * and puts it in var.
 *
 * If necessary, qtmd_update_model() is called.
 */
#define GET_SYMBOL(model, var) do {                                     \
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
  if (model.syms[0].cumfreq > 3800) qtmd_update_model(&model);          \
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
    FILL_BUFFER;                                                        \
    C  = (C << 1) | PEEK_BITS(1);                                       \
    REMOVE_BITS(1);                                                     \
  }                                                                     \
} while (0)

static void qtmd_update_model(struct qtmd_model *model) {
  struct qtmd_modelsym tmp;
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
static void qtmd_init_model(struct qtmd_model *model,
			    struct qtmd_modelsym *syms, int start, int len)
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

struct qtmd_stream *qtmd_init(struct mspack_system *system,
			      struct mspack_file *input,
			      struct mspack_file *output,
			      int window_bits, int input_buffer_size)
{
  unsigned int window_size = 1 << window_bits;
  struct qtmd_stream *qtm;
  int i;

  if (!system) return NULL;

  /* Quantum supports window sizes of 2^10 (1Kb) through 2^21 (2Mb) */
  if (window_bits < 10 || window_bits > 21) return NULL;

  input_buffer_size = (input_buffer_size + 1) & -2;
  if (input_buffer_size < 2) return NULL;

  /* initialise static data */
  qtmd_static_init();

  /* allocate decompression state */
  if (!(qtm = system->alloc(system, sizeof(struct qtmd_stream)))) {
    return NULL;
  }

  /* allocate decompression window and input buffer */
  qtm->window = system->alloc(system, (size_t) window_size);
  qtm->inbuf  = system->alloc(system, (size_t) input_buffer_size);
  if (!qtm->window || !qtm->inbuf) {
    system->free(qtm->window);
    system->free(qtm->inbuf);
    system->free(qtm);
    return NULL;
  }

  /* initialise decompression state */
  qtm->sys         = system;
  qtm->input       = input;
  qtm->output      = output;
  qtm->inbuf_size  = input_buffer_size;
  qtm->window_size = window_size;
  qtm->window_posn = 0;
  qtm->frame_start = 0;
  qtm->header_read = 0;
  qtm->error       = MSPACK_ERR_OK;

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
  qtmd_init_model(&qtm->model0,    &qtm->m0sym[0],   0, 64);
  qtmd_init_model(&qtm->model1,    &qtm->m1sym[0],  64, 64);
  qtmd_init_model(&qtm->model2,    &qtm->m2sym[0], 128, 64);
  qtmd_init_model(&qtm->model3,    &qtm->m3sym[0], 192, 64);
  qtmd_init_model(&qtm->model4,    &qtm->m4sym[0],   0, (i > 24) ? 24 : i);
  qtmd_init_model(&qtm->model5,    &qtm->m5sym[0],   0, (i > 36) ? 36 : i);
  qtmd_init_model(&qtm->model6,    &qtm->m6sym[0],   0, i);
  qtmd_init_model(&qtm->model6len, &qtm->m6lsym[0],  0, 27);
  qtmd_init_model(&qtm->model7,    &qtm->m7sym[0],   0, 7);

  /* all ok */
  return qtm;
}

int qtmd_decompress(struct qtmd_stream *qtm, off_t out_bytes) {
  unsigned int frame_start, frame_end, window_posn, match_offset, range;
  unsigned char *window, *i_ptr, *i_end, *runsrc, *rundest;
  int i, j, selector, extra, sym, match_length;
  unsigned short H, L, C, symf;

  register unsigned int bit_buffer;
  register unsigned char bits_left;
  unsigned char bits_needed, bit_run;

  /* easy answers */
  if (!qtm || (out_bytes < 0)) return MSPACK_ERR_ARGS;
  if (qtm->error) return qtm->error;

  /* flush out any stored-up bytes before we begin */
  i = qtm->o_end - qtm->o_ptr;
  if ((off_t) i > out_bytes) i = (int) out_bytes;
  if (i) {
    if (qtm->sys->write(qtm->output, qtm->o_ptr, i) != i) {
      return qtm->error = MSPACK_ERR_WRITE;
    }
    qtm->o_ptr  += i;
    out_bytes   -= i;
  }
  if (out_bytes == 0) return MSPACK_ERR_OK;

  /* restore local state */
  RESTORE_BITS;
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
      H = 0xFFFF; L = 0; READ_BITS(C, 16);
      qtm->header_read = 1;
    }

    /* decode more, at most up to to frame boundary */
    frame_end = window_posn + (out_bytes - (qtm->o_end - qtm->o_ptr));
    if ((frame_start + QTM_FRAME_SIZE) < frame_end) {
      frame_end = frame_start + QTM_FRAME_SIZE;
    }

    while (window_posn < frame_end) {
      GET_SYMBOL(qtm->model7, selector);
      if (selector < 4) {
	struct qtmd_model *mdl = (selector == 0) ? &qtm->model0 :
	                        ((selector == 1) ? &qtm->model1 :
				((selector == 2) ? &qtm->model2 :
                                                   &qtm->model3));
	GET_SYMBOL((*mdl), sym);
	window[window_posn++] = sym;
      }
      else {
	switch (selector) {
	case 4: /* selector 4 = fixed length match (3 bytes) */
	  GET_SYMBOL(qtm->model4, sym);
	  READ_BITS(extra, extra_bits[sym]);
	  match_offset = position_base[sym] + extra + 1;
	  match_length = 3;
	  break;

	case 5: /* selector 5 = fixed length match (4 bytes) */
	  GET_SYMBOL(qtm->model5, sym);
	  READ_BITS(extra, extra_bits[sym]);
	  match_offset = position_base[sym] + extra + 1;
	  match_length = 4;
	  break;

	case 6: /* selector 6 = variable length match */
	  GET_SYMBOL(qtm->model6len, sym);
	  READ_BITS(extra, length_extra[sym]);
	  match_length = length_base[sym] + extra + 5;

	  GET_SYMBOL(qtm->model6, sym);
	  READ_BITS(extra, extra_bits[sym]);
	  match_offset = position_base[sym] + extra + 1;
	  break;

	default:
	  /* should be impossible, model7 can only return 0-6 */
	  return qtm->error = MSPACK_ERR_DECRUNCH;
	}

	rundest = &window[window_posn];
	i = match_length;
	/* does match offset wrap the window? */
	if (match_offset > window_posn) {
	  /* j = length from match offset to end of window */
	  j = match_offset - window_posn;
	  if (j > (int) qtm->window_size) {
	    D(("match offset beyond window boundaries"))
	    return qtm->error = MSPACK_ERR_DECRUNCH;
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
	D(("overshot frame alignment"))
	return qtm->error = MSPACK_ERR_DECRUNCH;
      }

      /* re-align input */
      if (bits_left & 7) REMOVE_BITS(bits_left & 7);
      do { READ_BITS(i, 8); } while (i != 0xFF);
      qtm->header_read = 0;

      /* window wrap? */
      if (window_posn == qtm->window_size) {
	/* flush all currently stored data */
	i = (qtm->o_end - qtm->o_ptr);
	if (qtm->sys->write(qtm->output, qtm->o_ptr, i) != i) {
	  return qtm->error = MSPACK_ERR_WRITE;
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
    if (qtm->sys->write(qtm->output, qtm->o_ptr, i) != i) {
      return qtm->error = MSPACK_ERR_WRITE;
    }
    qtm->o_ptr += i;
  }

  /* store local state */
  STORE_BITS;
  qtm->window_posn = window_posn;
  qtm->frame_start = frame_start;
  qtm->H = H;
  qtm->L = L;
  qtm->C = C;

  return MSPACK_ERR_OK;
}

void qtmd_free(struct qtmd_stream *qtm) {
  struct mspack_system *sys;
  if (qtm) {
    sys = qtm->sys;
    sys->free(qtm->window);
    sys->free(qtm->inbuf);
    sys->free(qtm);
  }
}

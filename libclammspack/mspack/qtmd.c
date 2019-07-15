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

#include <system.h>
#include <qtm.h>

/* import bit-reading macros and code */
#define BITS_TYPE struct qtmd_stream
#define BITS_VAR qtm
#define BITS_ORDER_MSB
#define READ_BYTES do {                 \
    unsigned char b0, b1;               \
    READ_IF_NEEDED; b0 = *i_ptr++;      \
    READ_IF_NEEDED; b1 = *i_ptr++;      \
    INJECT_BITS((b0 << 8) | b1, 16);    \
} while (0)
#include <readbits.h>

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
 *
 * They are generated with the following code:
 *   unsigned int i, offset;
 *   for (i = 0, offset = 0; i < 42; i++) {
 *     position_base[i] = offset;
 *     extra_bits[i] = ((i < 2) ? 0 : (i - 2)) >> 1;
 *     offset += 1 << extra_bits[i];
 *   }
 *   for (i = 0, offset = 0; i < 26; i++) {
 *     length_base[i] = offset;
 *     length_extra[i] = (i < 2 ? 0 : i - 2) >> 2;
 *     offset += 1 << length_extra[i];
 *   }
 *   length_base[26] = 254; length_extra[26] = 0;
 */
static const unsigned int position_base[42] = {
  0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768,
  1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152,
  65536, 98304, 131072, 196608, 262144, 393216, 524288, 786432, 1048576, 1572864
};
static const unsigned char extra_bits[42] = {
  0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10,
  11, 11, 12, 12, 13, 13, 14, 14, 15, 15, 16, 16, 17, 17, 18, 18, 19, 19
};
static const unsigned char length_base[27] = {
  0, 1, 2, 3, 4, 5, 6, 8, 10, 12, 14, 18, 22, 26,
  30, 38, 46, 54, 62, 78, 94, 110, 126, 158, 190, 222, 254
};
static const unsigned char length_extra[27] = {
  0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
  3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0
};


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
    ENSURE_BITS(1);                                                     \
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

  /* round up input buffer size to multiple of two */
  input_buffer_size = (input_buffer_size + 1) & -2;
  if (input_buffer_size < 2) return NULL;

  /* allocate decompression state */
  if (!(qtm = (struct qtmd_stream *) system->alloc(system, sizeof(struct qtmd_stream)))) {
    return NULL;
  }

  /* allocate decompression window and input buffer */
  qtm->window = (unsigned char *) system->alloc(system, (size_t) window_size);
  qtm->inbuf  = (unsigned char *) system->alloc(system, (size_t) input_buffer_size);
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
  qtm->frame_todo  = QTM_FRAME_SIZE;
  qtm->header_read = 0;
  qtm->error       = MSPACK_ERR_OK;

  qtm->i_ptr = qtm->i_end = &qtm->inbuf[0];
  qtm->o_ptr = qtm->o_end = &qtm->window[0];
  qtm->input_end = 0;
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
  unsigned int frame_todo, frame_end, window_posn, match_offset, range;
  unsigned char *window, *i_ptr, *i_end, *runsrc, *rundest;
  int i, j, selector, extra, sym, match_length;
  unsigned short H, L, C, symf;

  register unsigned int bit_buffer;
  register unsigned char bits_left;

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
  frame_todo = qtm->frame_todo;
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

    /* decode more, up to the number of bytes needed, the frame boundary,
     * or the window boundary, whichever comes first */
    frame_end = window_posn + (out_bytes - (qtm->o_end - qtm->o_ptr));
    if ((window_posn + frame_todo) < frame_end) {
      frame_end = window_posn + frame_todo;
    }
    if (frame_end > qtm->window_size) {
      frame_end = qtm->window_size;
    }

    while (window_posn < frame_end) {
      GET_SYMBOL(qtm->model7, selector);
      if (selector < 4) {
        /* literal byte */
        struct qtmd_model *mdl = (selector == 0) ? &qtm->model0 :
                                ((selector == 1) ? &qtm->model1 :
                                ((selector == 2) ? &qtm->model2 :
                                                   &qtm->model3));
        GET_SYMBOL((*mdl), sym);
        window[window_posn++] = sym;
        frame_todo--;
      }
      else {
        /* match repeated string */
        switch (selector) {
        case 4: /* selector 4 = fixed length match (3 bytes) */
          GET_SYMBOL(qtm->model4, sym);
          READ_MANY_BITS(extra, extra_bits[sym]);
          match_offset = position_base[sym] + extra + 1;
          match_length = 3;
          break;

        case 5: /* selector 5 = fixed length match (4 bytes) */
          GET_SYMBOL(qtm->model5, sym);
          READ_MANY_BITS(extra, extra_bits[sym]);
          match_offset = position_base[sym] + extra + 1;
          match_length = 4;
          break;

        case 6: /* selector 6 = variable length match */
          GET_SYMBOL(qtm->model6len, sym);
          READ_MANY_BITS(extra, length_extra[sym]);
          match_length = length_base[sym] + extra + 5;

          GET_SYMBOL(qtm->model6, sym);
          READ_MANY_BITS(extra, extra_bits[sym]);
          match_offset = position_base[sym] + extra + 1;
          break;

        default:
          /* should be impossible, model7 can only return 0-6 */
          D(("got %d from selector", selector))
          return qtm->error = MSPACK_ERR_DECRUNCH;
        }

        rundest = &window[window_posn];
        frame_todo -= match_length;

        /* does match destination wrap the window? This situation is possible
         * where the window size is less than the 32k frame size, but matches
         * must not go beyond a frame boundary */
        if ((window_posn + match_length) > qtm->window_size) {
          /* copy first part of match, before window end */
          i = qtm->window_size - window_posn;
          j = window_posn - match_offset;
          while (i--) *rundest++ = window[j++ & (qtm->window_size - 1)];

          /* flush currently stored data */
          i = (&window[qtm->window_size] - qtm->o_ptr);

          /* this should not happen, but if it does then this code
           * can't handle the situation (can't flush up to the end of
           * the window, but can't break out either because we haven't
           * finished writing the match). bail out in this case */
          if (i > out_bytes) {
            D(("during window-wrap match; %d bytes to flush but only need %d",
               i, (int) out_bytes))
            return qtm->error = MSPACK_ERR_DECRUNCH;
          }
          if (qtm->sys->write(qtm->output, qtm->o_ptr, i) != i) {
            return qtm->error = MSPACK_ERR_WRITE;
          }
          out_bytes -= i;
          qtm->o_ptr = &window[0];
          qtm->o_end = &window[0]; 

          /* copy second part of match, after window wrap */
          rundest = &window[0];
          i = match_length - (qtm->window_size - window_posn);
          while (i--) *rundest++ = window[j++ & (qtm->window_size - 1)];
          window_posn = window_posn + match_length - qtm->window_size;

          break; /* because "window_posn < frame_end" has now failed */
        }
        else {
          /* normal match - output won't wrap window or frame end */
          i = match_length;

          /* does match _offset_ wrap the window? */
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
      } /* if (window_posn+match_length > frame_end) */
    } /* while (window_posn < frame_end) */

    qtm->o_end = &window[window_posn];

   /* if we subtracted too much from frame_todo, it will
    * wrap around past zero and go above its max value */
   if (frame_todo > QTM_FRAME_SIZE) {
     D(("overshot frame alignment"))
     return qtm->error = MSPACK_ERR_DECRUNCH;
   }

    /* another frame completed? */
    if (frame_todo == 0) {
      /* re-align input */
      if (bits_left & 7) REMOVE_BITS(bits_left & 7);

      /* special Quantum hack -- cabd.c injects a trailer byte to allow the
       * decompressor to realign itself. CAB Quantum blocks, unlike LZX
       * blocks, can have anything from 0 to 4 trailing null bytes. */
      do { READ_BITS(i, 8); } while (i != 0xFF);

      qtm->header_read = 0;

      frame_todo = QTM_FRAME_SIZE;
    }

    /* window wrap? */
    if (window_posn == qtm->window_size) {
      /* flush all currently stored data */
      i = (qtm->o_end - qtm->o_ptr);
      /* break out if we have more than enough to finish this request */
      if (i >= out_bytes) break;
      if (qtm->sys->write(qtm->output, qtm->o_ptr, i) != i) {
        return qtm->error = MSPACK_ERR_WRITE;
      }
      out_bytes -= i;
      qtm->o_ptr = &window[0];
      qtm->o_end = &window[0]; 
      window_posn = 0;
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
  qtm->frame_todo = frame_todo;
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

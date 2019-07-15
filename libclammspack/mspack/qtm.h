/* This file is part of libmspack.
 * (C) 2003-2004 Stuart Caie.
 *
 * The Quantum method was created by David Stafford, adapted by Microsoft
 * Corporation.
 *
 * libmspack is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License (LGPL) version 2.1
 *
 * For further details, see the file COPYING.LIB distributed with libmspack
 */

#ifndef MSPACK_QTM_H
#define MSPACK_QTM_H 1

#ifdef __cplusplus
extern "C" {
#endif

/* Quantum compression / decompression definitions */

#define QTM_FRAME_SIZE (32768)

struct qtmd_modelsym {
  unsigned short sym, cumfreq;
};

struct qtmd_model {
  int shiftsleft, entries;
  struct qtmd_modelsym *syms;
};

struct qtmd_stream {
  struct mspack_system *sys;      /* I/O routines                            */
  struct mspack_file   *input;    /* input file handle                       */
  struct mspack_file   *output;   /* output file handle                      */

  unsigned char *window;          /* decoding window                         */
  unsigned int window_size;       /* window size                             */
  unsigned int window_posn;       /* decompression offset within window      */
  unsigned int frame_todo;        /* bytes remaining for current frame       */

  unsigned short H, L, C;         /* high/low/current: arith coding state    */
  unsigned char header_read;      /* have we started decoding a new frame?   */

  int error;

  /* I/O buffers */
  unsigned char *inbuf, *i_ptr, *i_end, *o_ptr, *o_end;
  unsigned int  bit_buffer, inbuf_size;
  unsigned char bits_left, input_end;

  /* four literal models, each representing 64 symbols
   * model0 for literals from   0 to  63 (selector = 0)
   * model1 for literals from  64 to 127 (selector = 1)
   * model2 for literals from 128 to 191 (selector = 2)
   * model3 for literals from 129 to 255 (selector = 3) */
  struct qtmd_model model0, model1, model2, model3;

  /* three match models.
   * model4 for match with fixed length of 3 bytes
   * model5 for match with fixed length of 4 bytes
   * model6 for variable length match, encoded with model6len model */
  struct qtmd_model model4, model5, model6, model6len;

  /* selector model. 0-6 to say literal (0,1,2,3) or match (4,5,6) */
  struct qtmd_model model7;

  /* symbol arrays for all models */
  struct qtmd_modelsym m0sym[64 + 1];
  struct qtmd_modelsym m1sym[64 + 1];
  struct qtmd_modelsym m2sym[64 + 1];
  struct qtmd_modelsym m3sym[64 + 1];
  struct qtmd_modelsym m4sym[24 + 1];
  struct qtmd_modelsym m5sym[36 + 1];
  struct qtmd_modelsym m6sym[42 + 1], m6lsym[27 + 1];
  struct qtmd_modelsym m7sym[7 + 1];
};

/* allocates Quantum decompression state for decoding the given stream.
 *
 * - returns NULL if window_bits is outwith the range 10 to 21 (inclusive).
 *
 * - uses system->alloc() to allocate memory
 *
 * - returns NULL if not enough memory
 *
 * - window_bits is the size of the Quantum window, from 1Kb (10) to 2Mb (21).
 *
 * - input_buffer_size is the number of bytes to use to store bitstream data.
 */
extern struct qtmd_stream *qtmd_init(struct mspack_system *system,
                                     struct mspack_file *input,
                                     struct mspack_file *output,
                                     int window_bits,
                                     int input_buffer_size);

/* decompresses, or decompresses more of, a Quantum stream.
 *
 * - out_bytes of data will be decompressed and the function will return
 *   with an MSPACK_ERR_OK return code.
 *
 * - decompressing will stop as soon as out_bytes is reached. if the true
 *   amount of bytes decoded spills over that amount, they will be kept for
 *   a later invocation of qtmd_decompress().
 *
 * - the output bytes will be passed to the system->write() function given in
 *   qtmd_init(), using the output file handle given in qtmd_init(). More
 *   than one call may be made to system->write()
 *
 * - Quantum will read input bytes as necessary using the system->read()
 *   function given in qtmd_init(), using the input file handle given in
 *   qtmd_init(). This will continue until system->read() returns 0 bytes,
 *   or an error.
 */
extern int qtmd_decompress(struct qtmd_stream *qtm, off_t out_bytes);

/* frees all state associated with a Quantum data stream
 *
 * - calls system->free() using the system pointer given in qtmd_init()
 */
void qtmd_free(struct qtmd_stream *qtm);

#ifdef __cplusplus
}
#endif

#endif

/* This file is part of libmspack.
 * (C) 2003-2004 Stuart Caie.
 *
 * The deflate method was created by Phil Katz. MSZIP is equivalent to the
 * deflate method.
 *
 * libmspack is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License (LGPL) version 2.1
 *
 * For further details, see the file COPYING.LIB distributed with libmspack
 */

#ifndef MSPACK_MSZIP_H
#define MSPACK_MSZIP_H 1

#ifdef __cplusplus
extern "C" {
#endif

/* MSZIP (deflate) compression / (inflate) decompression definitions */

#define MSZIP_FRAME_SIZE          (32768) /* size of LZ history window */
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

struct mszipd_stream {
  struct mspack_system *sys;            /* I/O routines          */
  struct mspack_file   *input;          /* input file handle     */
  struct mspack_file   *output;         /* output file handle    */
  unsigned int window_posn;             /* offset within window  */

  /* inflate() will call this whenever the window should be emptied. */
  int (*flush_window)(struct mszipd_stream *, unsigned int);

  int error, repair_mode, bytes_output;

  /* I/O buffering */
  unsigned char *inbuf, *i_ptr, *i_end, *o_ptr, *o_end, input_end;
  unsigned int bit_buffer, bits_left, inbuf_size;


  /* huffman code lengths */
  unsigned char  LITERAL_len[MSZIP_LITERAL_MAXSYMBOLS];
  unsigned char  DISTANCE_len[MSZIP_DISTANCE_MAXSYMBOLS];

  /* huffman decoding tables */
  unsigned short LITERAL_table [MSZIP_LITERAL_TABLESIZE];
  unsigned short DISTANCE_table[MSZIP_DISTANCE_TABLESIZE];

  /* 32kb history window */
  unsigned char window[MSZIP_FRAME_SIZE];
};

/* allocates MS-ZIP decompression stream for decoding the given stream.
 *
 * - uses system->alloc() to allocate memory
 *
 * - returns NULL if not enough memory
 *
 * - input_buffer_size is how many bytes to use as an input bitstream buffer
 *
 * - if repair_mode is non-zero, errors in decompression will be skipped
 *   and 'holes' left will be filled with zero bytes. This allows at least
 *   a partial recovery of erroneous data.
 */
extern struct mszipd_stream *mszipd_init(struct mspack_system *system,
                                        struct mspack_file *input,
                                        struct mspack_file *output,
                                        int input_buffer_size,
                                        int repair_mode);

/* decompresses, or decompresses more of, an MS-ZIP stream.
 *
 * - out_bytes of data will be decompressed and the function will return
 *   with an MSPACK_ERR_OK return code.
 *
 * - decompressing will stop as soon as out_bytes is reached. if the true
 *   amount of bytes decoded spills over that amount, they will be kept for
 *   a later invocation of mszipd_decompress().
 *
 * - the output bytes will be passed to the system->write() function given in
 *   mszipd_init(), using the output file handle given in mszipd_init(). More
 *   than one call may be made to system->write()
 *
 * - MS-ZIP will read input bytes as necessary using the system->read()
 *   function given in mszipd_init(), using the input file handle given in
 *   mszipd_init(). This will continue until system->read() returns 0 bytes,
 *   or an error.
 */
extern int mszipd_decompress(struct mszipd_stream *zip, off_t out_bytes);

/* decompresses an entire MS-ZIP stream in a KWAJ file. Acts very much
 * like mszipd_decompress(), but doesn't take an out_bytes parameter
 */
extern int mszipd_decompress_kwaj(struct mszipd_stream *zip);

/* frees all stream associated with an MS-ZIP data stream
 *
 * - calls system->free() using the system pointer given in mszipd_init()
 */
void mszipd_free(struct mszipd_stream *zip);

#ifdef __cplusplus
}
#endif

#endif

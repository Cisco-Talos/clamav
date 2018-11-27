/* This file is part of libmspack.
 * (C) 2003-2004 Stuart Caie.
 *
 * libmspack is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License (LGPL) version 2.1
 *
 * For further details, see the file COPYING.LIB distributed with libmspack
 */

#ifndef MSPACK_LZSS_H
#define MSPACK_LZSS_H 1

#ifdef __cplusplus
extern "C" {
#endif

/* LZSS compression / decompression definitions */

#define LZSS_WINDOW_SIZE (4096)
#define LZSS_WINDOW_FILL (0x20)

#define LZSS_MODE_EXPAND  (0)
#define LZSS_MODE_MSHELP  (1)
#define LZSS_MODE_QBASIC  (2)

/**
 * Decompresses an LZSS stream.
 *
 * Input bytes will be read in as necessary using the system->read()
 * function with the input file handle given. This will continue until
 * system->read() returns 0 bytes, or an error. Errors will be passed
 * out of the function as MSPACK_ERR_READ errors. Input streams should
 * convey an "end of input stream" by refusing to supply all the bytes
 * that LZSS asks for when they reach the end of the stream, rather
 * than return an error code.
 *
 * Output bytes will be passed to the system->write() function, using
 * the output file handle given. More than one call may be made to
 * system->write().
 *
 * As EXPAND.EXE (SZDD/KWAJ), Microsoft Help and QBasic have slightly
 * different encodings for the control byte and matches, a "mode"
 * parameter is allowed, to choose the encoding.
 *
 * @param system             an mspack_system structure used to read from
 *                           the input stream and write to the output
 *                           stream, also to allocate and free memory.
 * @param input              an input stream with the LZSS data.
 * @param output             an output stream to write the decoded data to.
 * @param input_buffer_size  the number of bytes to use as an input
 *                           bitstream buffer.
 * @param mode               one of #LZSS_MODE_EXPAND, #LZSS_MODE_MSHELP or
 *                           #LZSS_MODE_QBASIC
 * @return an error code, or MSPACK_ERR_OK if successful
 */
extern int lzss_decompress(struct mspack_system *system,
			   struct mspack_file *input,
			   struct mspack_file *output,
			   int input_buffer_size,
			   int mode);

#ifdef __cplusplus
}
#endif

#endif

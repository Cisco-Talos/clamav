/*
 * Extract RAR archives
 *
 * Copyright (C) 2005-2006 trog@uncon.org
 *
 * This code is based on the work of Alexander L. Roshal (C)
 *
 * The unRAR sources may be used in any software to handle RAR
 * archives without limitations free of charge, but cannot be used
 * to re-create the RAR compression algorithm, which is proprietary.
 * Distribution of modified unRAR sources in separate form or as a
 * part of other software is permitted, provided that it is clearly
 * stated in the documentation and source comments that the code may
 * not be used to develop a RAR (WinRAR) compatible archiver.
 *
 */


#ifndef UNRAR20_H
#define UNRAR20_H 1

#define BC20 19
#define DC20 48
#define RC20 28
#define MC20 257
#define NC20 298  /* alphabet = {0, 1, 2, ..., NC - 1} */

void unpack_init_data20(int solid, unpack_data_t *unpack_data);
int rar_unpack20(int fd, int solid, unpack_data_t *unpack_data);

#endif

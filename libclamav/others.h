/*
 *  Copyright (C) 1999 - 2005 Tomasz Kojm <tkojm@clamav.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef __OTHERS_H_LC
#define __OTHERS_H_LC

#include <stdio.h>
#include <stdlib.h>
#include "cltypes.h"

#define CLI_ISCONTAINED(bb, bb_size, sb, sb_size)	\
    (bb_size > 0 && sb_size > 0 && sb_size <= bb_size	\
     && sb >= bb && sb + sb_size <= bb + bb_size && sb + sb_size > bb)

#define CLI_ISCONTAINED2(bb, bb_size, sb, sb_size)	\
    (bb_size > 0 && sb_size >= 0 && sb_size <= bb_size	\
     && sb >= bb && sb + sb_size <= bb + bb_size && sb + sb_size >= bb)

#define CLI_MAX_ALLOCATION 134217728

typedef struct bitset_tag {
    unsigned char *bitset;
    unsigned long length;
} bitset_t;

void cli_warnmsg(const char *str, ...);
void cli_errmsg(const char *str, ...);
void cli_dbgmsg(const char *str, ...);
void *cli_malloc(size_t nmemb);
void *cli_calloc(size_t nmemb, size_t size);
void *cli_realloc(void *ptr, size_t size);
int cli_rmdirs(const char *dirname);
unsigned char *cli_md5digest(int desc);
char *cli_md5stream(FILE *fs, unsigned char *digcpy);
char *cli_md5file(const char *filename);
int cli_readn(int fd, void *buff, unsigned int count);
int cli_writen(int fd, void *buff, unsigned int count);
int32_t cli_readint32(const char *buff);
void cli_writeint32(char *offset, uint32_t value);
char *cli_gentemp(const char *dir);
unsigned int cli_rndnum(unsigned int max);
int cli_filecopy(const char *src, const char *dest);
bitset_t *cli_bitset_init();
void cli_bitset_free(bitset_t *bs);
int cli_bitset_set(bitset_t *bs, unsigned long bit_offset);
int cli_bitset_test(bitset_t *bs, unsigned long bit_offset);

#endif

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
int cli_writen(int fd, const void *buff, unsigned int count);
int32_t cli_readint32(const char *buff);
void cli_writeint32(char *offset, uint32_t value);
char *cli_gentemp(const char *dir);
char *cli_gentempdir(const char *dir);
char *cli_gentempdesc(const char *dir, int *fd);
char *cli_gentempstream(const char *dir, FILE **fs);
unsigned int cli_rndnum(unsigned int max);
int cli_filecopy(const char *src, const char *dest);

#endif

/*
 *  Copyright (C) 1999-2002 Tomasz Kojm <zolw@konarski.edu.pl>
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

#ifndef __OTHERS_H
#define __OTHERS_H

#include <stdio.h>
#include <stdlib.h>

void cli_warnmsg(const char *str, ...);
void cli_errmsg(const char *str, ...);
void cli_dbgmsg(const char *str, ...);
void *cli_malloc(size_t nmemb);
void *cli_calloc(size_t nmemb, size_t size);
void *cli_realloc(void *ptr, size_t size);
int cli_rmdirs(const char *dirname);
char *cli_md5stream(FILE *fd);
int cli_readn(int fd, void *buff, unsigned int count);
int cli_writen(int fd, void *buff, unsigned int count);

#endif

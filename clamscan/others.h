/*
 *  Copyright (C) 1999-2003 Tomasz Kojm <zolw@konarski.edu.pl>
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

#include "pwd.h"
#include "options.h"

void mprintf(const char *str, ...);
int logg(const char *str, ...);
void texit(int no);
int isnumb(const char *str);
void *mmalloc(size_t nmemb);
void *mcalloc(size_t nmemb, size_t size);
void chomp(char *string);
int detectcpu(void);
int fileinfo(const char *filename, short i);
int strbcasestr(const char *haystack, const char *needle);
int readaccess(const char *path, const char *username);
int writeaccess(const char *path, const char *username);
int filecopy(const char *src, const char *dest);

/* njh@bandsman.co.uk: for BeOS */
/* TODO: configure should see if sete[ug]id is set on the target */
#if defined(C_BEOS) || defined(C_HPUX)
#define       seteuid(u)      (-1)
#define       setegid(g)      (-1)
#endif

#endif

/*
 *  Copyright (C) 2002 Tomasz Kojm <zolw@konarski.edu.pl>
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

#include <stdlib.h>

int mdprintf(int desc, const char *str, ...);
int isnumb(const char *str);
void *mmalloc(size_t size);
void *mcalloc(size_t nmemb, size_t size);
void chomp(char *string);

short int logverbose, logcompressed, loglock, logtime;
int logsize;
const char *logfile;
int logg(const char *str, ...);
int rndnum(unsigned int max);

#if defined(CLAMD_USE_SYSLOG) && !defined(C_AIX)
short use_syslog;
#endif

#endif

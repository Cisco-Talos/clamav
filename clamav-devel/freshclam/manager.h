/*
 *  Copyright (C) 2002, 2003 Tomasz Kojm <zolw@konarski.edu.pl>
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

#ifndef __MANAGER_H
#define __MANAGER_H

#include "options.h"
#include "clamav.h"

int downloadmanager(const struct optstruct *opt, const char *hostname);

int downloaddb(const char *localname, const char *remotename, const char *hostname, int *signo, const struct optstruct *opt);

int wwwconnect(const char *server, const char *proxy);

struct cl_cvd *remote_cvdhead(const char *file, int socketfd, const char *hostname, const char *proxy, const char *user);

int get_database(const char *dbfile, int socketfd, const char *file, const char *hostname, const char *proxy, const char *user);

unsigned int fmt_base64(char* dest,const char* src,unsigned int len);

#endif

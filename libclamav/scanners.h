/*
 *  Copyright (C) 2002 - 2004 Tomasz Kojm <tkojm@clamav.net>
 *  With enhancements from Thomas Lamy <Thomas.Lamy@in-online.net>
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

#ifndef __SCANNERS_H
#define __SCANNERS_H

typedef enum {
    CL_UNKNOWN_TYPE = 0,
    CL_MAILFILE,
    CL_GZFILE,
    CL_ZIPFILE,
    CL_BZFILE,
    CL_RARFILE,
    CL_OLE2FILE
} cli_file_t;

cli_file_t cli_filetype(const char *buf, size_t buflen);

#endif

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

#ifndef __FILETYPES_H
#define __FILETYPES_H

#define MAGIC_BUFFER_SIZE 262
#define CL_TYPENO 500

typedef enum {
    CL_TYPE_UNKNOWN_TEXT = CL_TYPENO,
    CL_TYPE_UNKNOWN_DATA,
    CL_TYPE_MSEXE,
    CL_TYPE_DATA,
    CL_TYPE_TAR,
    CL_TYPE_GZ,
    CL_TYPE_ZIP,
    CL_TYPE_BZ,
    CL_TYPE_RAR,
    CL_TYPE_MSSZDD,
    CL_TYPE_MSOLE2,
    CL_TYPE_MSCAB,
    CL_TYPE_MSCHM,
    CL_TYPE_SCRENC,
    CL_TYPE_GRAPHICS,

    /* bigger numbers have higher priority (in o-t-f detection) */
    CL_TYPE_HTML, /* on the fly */
    CL_TYPE_MAIL  /* magic + on the fly */

} cli_file_t;

cli_file_t cli_filetype(const char *buf, size_t buflen);
int cli_addtypesigs(struct cl_node *root);

#endif

/*
 *  Copyright (C) 2002 - 2005 Tomasz Kojm <tkojm@clamav.net>
 *  With enhancements from Thomas Lamy <Thomas.Lamy@in-online.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

#ifndef __FILETYPES_H
#define __FILETYPES_H

#include <sys/types.h>

#define MAGIC_BUFFER_SIZE 256
#define CL_TYPENO 500
#define MAX_EMBEDDED_OBJ 10

typedef enum {
    CL_TYPE_UNKNOWN_TEXT = CL_TYPENO,
    CL_TYPE_UNKNOWN_DATA,
    CL_TYPE_MSEXE,
    CL_TYPE_ELF,
    CL_TYPE_DATA,
    CL_TYPE_POSIX_TAR,
    CL_TYPE_OLD_TAR,
    CL_TYPE_GZ,
    CL_TYPE_ZIP,
    CL_TYPE_BZ,
    CL_TYPE_RAR,
    CL_TYPE_ARJ,
    CL_TYPE_MSSZDD,
    CL_TYPE_MSOLE2,
    CL_TYPE_MSCAB,
    CL_TYPE_MSCHM,
    CL_TYPE_SIS,
    CL_TYPE_SCRENC,
    CL_TYPE_GRAPHICS,
    CL_TYPE_RIFF,
    CL_TYPE_BINHEX,
    CL_TYPE_TNEF,
    CL_TYPE_CRYPTFF,
    CL_TYPE_PDF,
    CL_TYPE_UUENCODED,
    CL_TYPE_PST,	/* Microsoft Outlook binary email folder (.pst file) */
    CL_TYPE_HTML_UTF16,
    CL_TYPE_RTF,

    /* bigger numbers have higher priority (in o-t-f detection) */
    CL_TYPE_HTML, /* on the fly */
    CL_TYPE_MAIL,  /* magic + on the fly */
    CL_TYPE_SFX, /* foo SFX marker */
    CL_TYPE_ZIPSFX, /* on the fly */
    CL_TYPE_RARSFX, /* on the fly */
    CL_TYPE_CABSFX,
    CL_TYPE_ARJSFX,
    CL_TYPE_NULSFT, /* on the fly */
    CL_TYPE_AUTOIT
} cli_file_t;

struct cli_matched_type {
    cli_file_t type;
    off_t offset;
    unsigned short cnt;
    struct cli_matched_type *next;
};

cli_file_t cli_filetype(const unsigned char *buf, size_t buflen);
cli_file_t cli_filetype2(int desc, const struct cl_engine *engine);
int cli_addtypesigs(struct cl_engine *engine);

#endif

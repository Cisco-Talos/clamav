/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm
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

#include "clamav.h"
#include "fmap.h"

#define CL_FILE_MBUFF_SIZE 1024
#define CL_PART_MBUFF_SIZE 1028
/* MAGIC_BUFFER_SIZE must be the bigger of the two sizes above */
#define MAGIC_BUFFER_SIZE 1028

#define CL_TYPENO 500
#define MAX_EMBEDDED_OBJ 10

typedef enum {
    CL_TYPE_ANY = 0,
    CL_TYPE_TEXT_ASCII = CL_TYPENO, /* X3.4, ISO-8859, non-ISO ext. ASCII */
    CL_TYPE_TEXT_UTF8,
    CL_TYPE_TEXT_UTF16LE,
    CL_TYPE_TEXT_UTF16BE,
    CL_TYPE_BINARY_DATA,
    /* Please do not add any new types above this line */
    CL_TYPE_ERROR,
    CL_TYPE_MSEXE,
    CL_TYPE_ELF,
    CL_TYPE_MACHO,
    CL_TYPE_MACHO_UNIBIN,
    CL_TYPE_POSIX_TAR,
    CL_TYPE_OLD_TAR,
    CL_TYPE_CPIO_OLD,
    CL_TYPE_CPIO_ODC,
    CL_TYPE_CPIO_NEWC,
    CL_TYPE_CPIO_CRC,
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
    CL_TYPE_SCRIPT,
    CL_TYPE_HTML_UTF16,
    CL_TYPE_RTF,
    CL_TYPE_7Z,
    CL_TYPE_SWF,
    CL_TYPE_JAVA,
    CL_TYPE_XAR,
    CL_TYPE_XZ,
    CL_TYPE_OOXML_WORD,
    CL_TYPE_OOXML_PPT,
    CL_TYPE_OOXML_XL,
    CL_TYPE_INTERNAL,
    CL_TYPE_HWP3,
    CL_TYPE_OOXML_HWP,
    CL_TYPE_PS,

    /* Section for partition types */
    CL_TYPE_PART_ANY, /* unknown partition type */
    CL_TYPE_PART_HFSPLUS,

    /* bigger numbers have higher priority (in o-t-f detection) */
    CL_TYPE_MBR,
    CL_TYPE_HTML, /* on the fly */
    CL_TYPE_MAIL,  /* magic + on the fly */
    CL_TYPE_SFX, /* foo SFX marker */
    CL_TYPE_ZIPSFX, /* on the fly */
    CL_TYPE_RARSFX, /* on the fly */
    CL_TYPE_7ZSFX,
    CL_TYPE_CABSFX,
    CL_TYPE_ARJSFX,
    CL_TYPE_NULSFT, /* on the fly */
    CL_TYPE_AUTOIT,
    CL_TYPE_ISHIELD_MSI,
    CL_TYPE_ISO9660,
    CL_TYPE_DMG,
    CL_TYPE_GPT,
    CL_TYPE_APM,
    CL_TYPE_XDP,
    CL_TYPE_XML_WORD,
    CL_TYPE_XML_XL,
    CL_TYPE_XML_HWP,
    CL_TYPE_HWPOLE2,
    CL_TYPE_MHTML,
    CL_TYPE_LNK,

    CL_TYPE_OTHER, /* on-the-fly, used for target 14 (OTHER) */
    CL_TYPE_IGNORED /* please don't add anything below */
} cli_file_t;

struct cli_ftype {
    cli_file_t type;
    uint32_t offset;
    unsigned char *magic;
    char *tname;
    struct cli_ftype *next;
    uint16_t length;
};

struct cli_matched_type {
    struct cli_matched_type *next;
    off_t offset;
    cli_file_t type;
    unsigned short cnt;
};

cli_file_t cli_ftcode(const char *name);
const char *cli_ftname(cli_file_t code);
void cli_ftfree(const struct cl_engine *engine);
cli_file_t cli_filetype(const unsigned char *buf, size_t buflen, const struct cl_engine *engine);
cli_file_t cli_filetype2(fmap_t *map, const struct cl_engine *engine, cli_file_t basetype);
int cli_addtypesigs(struct cl_engine *engine);

#endif

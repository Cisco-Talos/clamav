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

#ifndef __DCONF_H
#define __DCONF_H

#include <stdio.h>
#include <zlib.h>

#include "clamav.h"
#include "cvd.h"

#include "mpool.h"

struct cli_dconf {
    uint32_t pe;
    uint32_t elf;
    uint32_t macho;
    uint32_t archive;
    uint32_t doc;
    uint32_t mail;
    uint32_t other;
    uint32_t phishing;
    uint32_t bytecode;
    uint32_t stats;
    uint32_t pcre;
};

/* PE flags */
#define PE_CONF_PARITE	    0x1
#define PE_CONF_KRIZ	    0x2
#define PE_CONF_MAGISTR	    0x4
#define PE_CONF_POLIPOS	    0x8
#define PE_CONF_MD5SECT	    0x10
#define PE_CONF_UPX	    0x20
#define PE_CONF_FSG	    0x40
#define PE_CONF_SWIZZOR     0x80
#define PE_CONF_PETITE	    0x100
#define PE_CONF_PESPIN	    0x200
#define PE_CONF_YC	    0x400
#define PE_CONF_WWPACK	    0x800
#define PE_CONF_NSPACK	    0x1000
#define PE_CONF_MEW	    0x2000
#define PE_CONF_UPACK	    0x4000
#define PE_CONF_ASPACK	    0x8000
#define PE_CONF_CATALOG	    0x10000
#define PE_CONF_CERTS       0x20000
#define PE_CONF_MATCHICON   0x40000
#define PE_CONF_IMPTBL      0x80000

/* Archive flags */
#define ARCH_CONF_RAR	    0x1
#define ARCH_CONF_ZIP	    0x2
#define ARCH_CONF_GZ	    0x4
#define ARCH_CONF_BZ	    0x8
#define ARCH_CONF_SZDD	    0x10
#define ARCH_CONF_CAB	    0x20
#define ARCH_CONF_CHM	    0x40
#define ARCH_CONF_OLE2	    0x80
#define ARCH_CONF_TAR	    0x100
#define ARCH_CONF_BINHEX    0x200
#define ARCH_CONF_SIS	    0x400
#define ARCH_CONF_NSIS	    0x800
#define ARCH_CONF_ARJ       0x1000
#define ARCH_CONF_AUTOIT    0x2000
#define ARCH_CONF_CPIO	    0x4000
#define ARCH_CONF_ISHIELD   0x8000
#define ARCH_CONF_7Z        0x10000
#define ARCH_CONF_ISO9660   0x20000
#define ARCH_CONF_DMG       0x40000
#define ARCH_CONF_XAR       0x80000
#define ARCH_CONF_HFSPLUS   0x100000
#define ARCH_CONF_XZ        0x200000
#define ARCH_CONF_PASSWD    0x400000
#define ARCH_CONF_MBR       0x800000
#define ARCH_CONF_GPT       0x1000000
#define ARCH_CONF_APM       0x2000000

/* Document flags */
#define DOC_CONF_HTML		0x1
#define DOC_CONF_RTF		0x2
#define DOC_CONF_PDF		0x4
#define DOC_CONF_SCRIPT 	0x8
#define DOC_CONF_HTML_SKIPRAW	0x10
#define DOC_CONF_JSNORM         0x20
#define DOC_CONF_SWF		0x40
#define DOC_CONF_MSXML		0x80
#define DOC_CONF_OOXML		0x100
#define DOC_CONF_HWP		0x200

/* Mail flags */
#define MAIL_CONF_MBOX	    0x1
#define MAIL_CONF_TNEF	    0x2

/* Other flags */
#define OTHER_CONF_UUENC    0x1
#define OTHER_CONF_SCRENC   0x2
#define OTHER_CONF_RIFF	    0x4
#define OTHER_CONF_JPEG	    0x8
#define OTHER_CONF_CRYPTFF  0x10
#define OTHER_CONF_DLP	    0x20
#define OTHER_CONF_MYDOOMLOG	0x40
#define OTHER_CONF_PREFILTERING 0x80
#define OTHER_CONF_PDFNAMEOBJ	0x100
#define OTHER_CONF_PRTNINTXN	0x200
#define OTHER_CONF_LZW		0x400

/* Phishing flags */
#define PHISHING_CONF_ENGINE   0x1
#define PHISHING_CONF_ENTCONV  0x2

/* Bytecode flags */
#define BYTECODE_INTERPRETER 0x1
#define BYTECODE_JIT_X86 0x2
#define BYTECODE_JIT_PPC 0x4
#define BYTECODE_JIT_ARM 0x8

/* Stats/Intel flags */
#define DCONF_STATS_DISABLED            0x1
#define DCONF_STATS_PE_SECTION_DISABLED 0x2

/* PCRE flags */
#define PCRE_CONF_SUPPORT 0x1
#define PCRE_CONF_OPTIONS 0x2
#define PCRE_CONF_GLOBAL  0x4

#define BYTECODE_ENGINE_MASK (BYTECODE_INTERPRETER | BYTECODE_JIT_X86 | BYTECODE_JIT_PPC | BYTECODE_JIT_ARM)

#ifdef USE_MPOOL
struct cli_dconf *cli_dconf_init(mpool_t *);
#define cli_mpool_dconf_init(a) cli_dconf_init(a)
#else
struct cli_dconf *cli_dconf_init(void);
#define cli_mpool_dconf_init(a) cli_dconf_init()
#endif
void cli_dconf_print(struct cli_dconf *dconf);
int cli_dconf_load(FILE *fs, struct cl_engine *engine, unsigned int options, struct cli_dbio *dbio);
#endif

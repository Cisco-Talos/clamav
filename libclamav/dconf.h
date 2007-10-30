/*
 *  Copyright (C) 2007 Tomasz Kojm <tkojm@clamav.net>
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

#include "clamav.h"
#include "cltypes.h"

struct cli_dconf {
    uint32_t pe;
    uint32_t elf;
    uint32_t archive;
    uint32_t doc;
    uint32_t mail;
    uint32_t other;
    uint32_t phishing;
};

/* PE flags */
#define PE_CONF_PARITE	    0x1
#define PE_CONF_KRIZ	    0x2
#define PE_CONF_MAGISTR	    0x4
#define PE_CONF_POLIPOS	    0x8
#define PE_CONF_MD5SECT	    0x10
#define PE_CONF_UPX	    0x20
#define PE_CONF_FSG	    0x40
/*#define PE_CONF_REUSEME	    0x80 */
#define PE_CONF_PETITE	    0x100
#define PE_CONF_PESPIN	    0x200
#define PE_CONF_YC	    0x400
#define PE_CONF_WWPACK	    0x800
#define PE_CONF_NSPACK	    0x1000
#define PE_CONF_MEW	    0x2000
#define PE_CONF_UPACK	    0x4000
#define PE_CONF_ASPACK	    0x8000

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

/* Document flags */
#define DOC_CONF_HTML	    0x1
#define DOC_CONF_RTF	    0x2
#define DOC_CONF_PDF	    0x4

/* Mail flags */
#define MAIL_CONF_MBOX	    0x1
#define MAIL_CONF_TNEF	    0x2
#define MAIL_CONF_PST	    0x4

/* Other flags */
#define OTHER_CONF_UUENC    0x1
#define OTHER_CONF_SCRENC   0x2
#define OTHER_CONF_RIFF	    0x4
#define OTHER_CONF_JPEG	    0x8
#define OTHER_CONF_CRYPTFF  0x10

/* Phishing flags */
#define PHISHING_CONF_ENGINE   0x1
#define PHISHING_CONF_ENTCONV  0x2

struct cli_dconf *cli_dconf_init(void);
void cli_dconf_print(struct cli_dconf *dconf);
int cli_dconf_load(FILE *fd, struct cl_engine **engine, unsigned int options);

#endif

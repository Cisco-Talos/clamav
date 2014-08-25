/*
 *  Support for PCRE regex variant
 *
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *  Copyright (C) 2014 Cisco Systems, Inc.
 *  All Rights Reserved.
 *
 *  Authors: Kevin Lin
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

#if HAVE_PCRE
#ifndef _REGEX_PCRE_H_
#define _REGEX_PCRE_H_

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <pcre.h>

#include "cltypes.h"
#include "mpool.h"

/* temporary macros to be replaced with engine options */
#define CLAMAV_PCRE_MATCH_LIMIT     10000
/* pointless unless less than CLAMAV_PCRE_MATCH_LIMIT by significant margin */
#define CLAMAV_PCRE_REC_MATCH_LIMIT 10000
/* must be multiple of 3 */
#define OVECCOUNT 300

struct cli_pcre_data {
    pcre *re;               /* compiled pcre regex */
    pcre_extra *ex;         /* pcre extra data - limits */
    int options;            /* pcre options */
    char *expression;       /* copied regular expression */
    uint32_t search_offset; /* start offset to search at for pcre_exec */
};

int cli_pcre_parse(struct cli_pcre_data *pd, const char *pattern, unsigned int options);
int cli_pcre_match(struct cli_pcre_data *pd, const unsigned char *buffer, uint32_t buflen, int *ovector, size_t ovlen);
void cli_pcre_free_single(struct cli_pcre_data *pd);

#endif /*_REGEX_PCRE_H_*/
#endif /* HAVE_PCRE */

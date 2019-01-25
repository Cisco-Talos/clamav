/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Török Edvin
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


#ifndef _PHISH_CHECK_H
#define _PHISH_CHECK_H

#include "regex/regex.h"
#include "htmlnorm.h"

#define CL_PHISH_BASE 100
enum phish_status {CL_PHISH_NODECISION=0, CL_PHISH_CLEAN=CL_PHISH_BASE,
	CL_PHISH_CLOAKED_UIU, CL_PHISH_NUMERIC_IP, CL_PHISH_HEX_URL, CL_PHISH_CLOAKED_NULL, CL_PHISH_SSL_SPOOF, CL_PHISH_NOMATCH,
        CL_PHISH_HASH0, CL_PHISH_HASH1, CL_PHISH_HASH2};

#define CHECK_SSL         1
#define CHECK_CLOAKING    2
#define CLEANUP_URL       4
#define CHECK_IMG_URL     8

#define LINKTYPE_IMAGE     1

#define CL_PHISH_ALL_CHECKS (CLEANUP_URL|CHECK_SSL|CHECK_CLOAKING|CHECK_IMG_URL)

struct string {
	struct string* ref;
	char* data;
	int refcount;
};

struct phishcheck {
	regex_t preg_numeric;
	int      is_disabled;
};

struct pre_fixup_info {
	/* pre_* url before fixup_spaces */
	struct string pre_displayLink;
	size_t host_start;
	size_t host_end;
};

struct url_check {
	struct string realLink;
	struct string displayLink;
	struct pre_fixup_info pre_fixup;
	unsigned short       flags;
	unsigned short always_check_flags;
	unsigned short       link_type;
};

int phishingScan(cli_ctx* ctx,tag_arguments_t* hrefs);

void phish_disable(struct cl_engine* engine,const char* reason);
/* Global, non-thread-safe functions, call only once! */
int phishing_init(struct cl_engine* engine);
void phishing_done(struct cl_engine* engine);
int cli_url_canon(const char *inurl, size_t len, char *urlbuff, size_t dest_len, char **host, size_t *hostlen, const char **path, size_t *pathlen);
/* end of non-thread-safe functions */


#endif


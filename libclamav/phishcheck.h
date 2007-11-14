/*
 *  Copyright (C) 2006-2007 Török Edvin <edwin@clamav.net>
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

#define CL_PHISH_BASE 100
enum phish_status {CL_PHISH_NODECISION=0,CL_PHISH_CLEAN=CL_PHISH_BASE, CL_PHISH_CLEANUP_OK,CL_PHISH_HOST_OK, CL_PHISH_DOMAIN_OK,
	CL_PHISH_HOST_NOT_LISTED,
	CL_PHISH_REDIR_OK, CL_PHISH_HOST_REDIR_OK, CL_PHISH_DOMAIN_REDIR_OK,
	CL_PHISH_HOST_REVERSE_OK,CL_PHISH_DOMAIN_REVERSE_OK,
	CL_PHISH_WHITELISTED,CL_PHISH_HOST_WHITELISTED,
	CL_PHISH_CLEAN_CID,
	CL_PHISH_TEXTURL, CL_PHISH_MAILTO_OK,
	CL_PHISH_CLOAKED_UIU, CL_PHISH_NUMERIC_IP,CL_PHISH_HEX_URL,CL_PHISH_CLOAKED_NULL,CL_PHISH_SSL_SPOOF, CL_PHISH_NOMATCH};

#define HOST_SUFFICIENT   1
#define DOMAIN_SUFFICIENT (HOST_SUFFICIENT | 2)
#define DO_REVERSE_LOOKUP 4
#define CHECK_REDIR       8
#define CHECK_SSL         16
#define CHECK_CLOAKING    32
#define CLEANUP_URL       64
#define CHECK_DOMAIN_REVERSE 128
#define CHECK_IMG_URL        256
#define DOMAINLIST_REQUIRED  512
/* img checking disabled by default */

#define LINKTYPE_IMAGE     1

#define CL_PHISH_ALL_CHECKS (CLEANUP_URL|DOMAIN_SUFFICIENT|CHECK_SSL|CHECK_CLOAKING|CHECK_IMG_URL)

struct string {
	int refcount;
	struct string* ref;
	char* data;
};

struct phishcheck {
	regex_t preg;
	regex_t preg_realurl;
	regex_t preg_tld;
	regex_t preg_cctld;
	regex_t preg_numeric;
	regex_t preg_hexurl;
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

#ifdef _MESSAGE_H
int phishingScan(message* m,const char* dir,cli_ctx* ctx,tag_arguments_t* hrefs);
#endif

void phish_disable(struct cl_engine* engine,const char* reason);
/* Global, non-thread-safe functions, call only once! */
int phishing_init(struct cl_engine* engine);
void phishing_done(struct cl_engine* engine);
/* end of non-thread-safe functions */


#endif


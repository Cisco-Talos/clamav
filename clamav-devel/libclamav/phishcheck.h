/*
 *  Copyright (C) 2006 Török Edvin <edwintorok@gmail.com>
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
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

#ifdef CL_EXPERIMENTAL

#ifndef _PHISH_CHECK_H
#define _PHISH_CHECK_H


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


#define CL_PHISH_ALL_CHECKS (CLEANUP_URL|DOMAIN_SUFFICIENT|CHECK_SSL|CHECK_CLOAKING|DOMAINLIST_REQUIRED|CHECK_IMG_URL)

struct string {
	int refcount;
	struct string* ref;
	char* data;
};

struct url_check {
	struct string realLink;
	struct string displayLink;
	unsigned short       flags;
};

int phishingScan(message* m,const char* dir,cli_ctx* ctx,tag_arguments_t* hrefs);
enum phish_status phishingCheck(const struct cl_engine* engine,struct url_check* urls);

int whitelist_check(const struct cl_engine* engine,struct url_check* urls,int hostOnly);
void url_check_init(struct url_check* urls);
void get_host(struct string* dest,const char* URL,int isReal,int* phishy);
void string_free(struct string* str);
void string_assign(struct string* dest,struct string* src);
void string_assign_c(struct string* dest,char* data);
void string_assign_dup(struct string* dest,const char* start,const char* end);
void string_assign_ref(struct string* dest,struct string* ref,char* data);
void free_if_needed(struct url_check* url);
void get_host(struct string* dest,const char* URL,int isReal,int* phishy);
int isCountryCode(const char* str);
int isTLD(const char* str,int len);
void get_domain(struct string* dest,struct string* host);
int ip_reverse(struct url_check* urls,int isReal);
void reverse_lookup(struct url_check* url,int isReal);
int isNumeric(const char* host);
int isSSL(const char* URL);
void cleanupURL(struct string* URL,int isReal);
void get_redirected_URL(struct string* URL);
int isURL(const char* URL);
enum phish_status cleanupURLs(struct url_check* urls);
int isNumericURL(const char* URL);
enum phish_status url_get_host(struct url_check* url,struct url_check* host_url,int isReal,int* phishy);
void url_get_domain(struct url_check* url,struct url_check* domains);
enum phish_status phishy_map(int phishy,enum phish_status fallback);
int isEncoded(const char* url);

void phish_disable(const char* reason);
/* Global, non-thread-safe functions, call only once! */
void phishint_init(struct cl_engine* engine);
void phishing_done(struct cl_engine* engine);
/* end of non-thread-safe functions */


static inline int isPhishing(enum phish_status rc)
{
	switch(rc) {
		case CL_PHISH_CLEAN:
		case CL_PHISH_CLEANUP_OK:
		case CL_PHISH_WHITELISTED:
		case CL_PHISH_HOST_WHITELISTED:
		case CL_PHISH_HOST_OK:
		case CL_PHISH_DOMAIN_OK:
		case CL_PHISH_REDIR_OK:
		case CL_PHISH_HOST_REDIR_OK:
		case CL_PHISH_DOMAIN_REDIR_OK:
		case CL_PHISH_HOST_REVERSE_OK:
		case CL_PHISH_DOMAIN_REVERSE_OK:
		case CL_PHISH_MAILTO_OK:
		case CL_PHISH_TEXTURL:
		case CL_PHISH_HOST_NOT_LISTED:
		case CL_PHISH_CLEAN_CID:
			return 0;
		case CL_PHISH_HEX_URL:
		case CL_PHISH_CLOAKED_NULL:
		case CL_PHISH_SSL_SPOOF:
		case CL_PHISH_CLOAKED_UIU:
		case CL_PHISH_NUMERIC_IP:
		case CL_PHISH_NOMATCH:
			return 1;
		default:
			return 1;
	}
}
const char* phishing_ret_toString(enum phish_status rc);
#endif

#endif

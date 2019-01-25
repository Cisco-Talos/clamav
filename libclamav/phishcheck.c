/*
 *  Detect phishing, based on URL spoofing detection.
 *
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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifdef CL_THREAD_SAFE
#ifndef _REENTRANT
#define _REENTRANT
#endif
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "clamav.h"
#include "others.h"
#include "htmlnorm.h"
#include "phishcheck.h"
#include "phish_domaincheck_db.h"
#include "phish_whitelist.h"
#include "regex_list.h"
#include "iana_tld.h"
#include "iana_cctld.h"
#include "scanners.h"
#include <assert.h>

#include "mpool.h"

#define DOMAIN_REAL 1
#define DOMAIN_DISPLAY 0

#define PHISHY_USERNAME_IN_URL 1
#define PHISHY_NUMERIC_IP      2
#define REAL_IS_MAILTO	       4
/* this is just a flag, so that the displayed url will be parsed as mailto too, for example
 * <a href='mailto:somebody@yahoo.com'>to:somebody@yahoo.com</a>*/
#define DOMAIN_LISTED		 8
#define PHISHY_CLOAKED_NULL	16


/*
 * Phishing design documentation
 * -----------------------------

TODO: update this doc whenever behaviour changes

phishingCheck() determines if @displayedLink is  a legit representation of @realLink.

Steps:

1. if _realLink_ == _displayLink_ => CLEAN

2. url cleanup (normalization)
- whitespace elimination
 strip all spaces, and leading and trailing garbage.
 When matching we have to keep in account whether we stripped any spaces or not.
 See str_fixup_spaces.
- html entity conversion
- handle hex-encoded characters
- convert hostname to lowercase
- normalize \ to /

3. Matched the urls against a _whitelist_:
a _realLink_, _displayedLink_ pair is matched against the _whitelist_.
the _whitelist_ is a list of pairs of realLink, displayedLink. Any of the elements of those pairs can be a _regex_.
 if url *is found* in _whitelist_ --> *CLEAN*

4. URL is looked up in the _domainlist_
The _domainlist_ is a list of pairs of realLink, displayedLink (any of which can be regex).
This is the list of domains we do phishing detection for (such as ebay,paypal,chase,....)
We can't decide to stop processing here or not, so we just set a flag.

Note(*!*): the flags are modified by the the domainlist checker. If domain is found, then the flags associated with it filter the default compile-time flags.

5. _Hostname_ is extracted from the _displayed URL_.
It is checked against the _whitelist_, and _domainlist_.

6. Now we know if we want to stop processing.
If we are only scanning domains in the _domainlist_ (default behaviour), and the url/domain
isn't found in it, we return (and mark url as not_list/clean).
If we scan all domains, then the domainlist isn't even checked.

7. URL cloak check.
check for %00, and hex-encoded IPs in URL.

8. Skip empty displayedURLs

9. SSL mismatch detection.
Checks if realLink is http, but displayedLink is https or viceversa.
(by default the SSL detection is done for hrefs only, not for imgs)

10. Hostname of real URL is extracted.

12. Numeric IP detection.
If url is a numeric IP, then -> phish.
Maybe we should do DNS lookup?

13. isURL(displayedLink).
Checks if displayedLink is really a url.
if not -> clean

14. Hostnames of real, displayedLink are compared. If equal -> clean

15. Extract domain names, and compare. If equal -> clean

16. Do DNS lookups/reverse lookups. Disabled now (too much load/too many lookups). *

For the Whitelist(.wdb)/Domainlist(.pdb) format see regex_list.c (search for Flags)
 *
 */

/* Constant strings and tables */ 
static char empty_string[]="";

static const char dotnet[] = ".net";
static const char adonet[] = "ado.net";
static const char aspnet[] = "asp.net";
/* ; is replaced by ' ' so omit it here*/
static const char lt[]="&lt";
static const char gt[]="&gt";
static const char src_text[] = "src";
static const char href_text[] = "href";
static const char mailto[] = "mailto:";
static const char mailto_proto[] = "mailto://";
static const char https[]="https:";
static const char http[]="http:";
static const char ftp[] = "ftp:";

static const size_t href_text_len = sizeof(href_text);
static const size_t src_text_len = sizeof(src_text);
static const size_t dotnet_len = sizeof(dotnet)-1;
static const size_t adonet_len = sizeof(adonet)-1;
static const size_t aspnet_len = sizeof(aspnet)-1;
static const size_t lt_len = sizeof(lt)-1;
static const size_t gt_len = sizeof(gt)-1;
static const size_t mailto_len = sizeof(mailto)-1;
static const size_t mailto_proto_len = sizeof(mailto_proto)-1;
static const size_t https_len  = sizeof(https)-1;
static const size_t http_len  = sizeof(http)-1;
static const size_t ftp_len  = sizeof(ftp)-1;

/* for urls, including mailto: urls, and (broken) http:www... style urls*/
/* refer to: http://www.w3.org/Addressing/URL/5_URI_BNF.html
 * Modifications: don't allow empty domains/subdomains, such as www..com <- that is no url
 * So the 'safe' char class has been split up
 * */
/* character classes */
#define URI_digit	"0-9"
#define URI_IP_digits "["URI_digit"]{1,3}"
#define URI_path_start "[/?:]?"
#define URI_numeric_path URI_IP_digits"(\\."URI_IP_digits"){3}"URI_path_start
#define URI_numeric_URI "(http|https|ftp:(//)?)?"URI_numeric_path
#define URI_numeric_fragmentaddress URI_numeric_URI


/*Warning: take care when modifying this regex, it has been tweaked, and tuned, just don't break it please.
 * there is fragmentaddress1, and 2  to work around the ISO limitation of 509 bytes max length for string constants*/
static const char numeric_url_regex[] = "^ *"URI_numeric_fragmentaddress" *$";

/* generated by contrib/phishing/generate_tables.c */
static const short int hextable[256] = {
       0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
       0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
       0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
       0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
       0x0, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
       0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
       0x0, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
       0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
       0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
       0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
       0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
       0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
       0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
       0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
       0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
       0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
};

/* Prototypes*/
static void string_init_c(struct string* dest,char* data);
static int string_assign_concatenated(struct string* dest, const char* prefix, const char* begin, const char* end);
static void string_assign_null(struct string* dest);
static char *rfind(char *start, char c, size_t len);
static char hex2int(const unsigned char* src);
static enum phish_status phishingCheck(const struct cl_engine* engine,struct url_check* urls);
static const char* phishing_ret_toString(enum phish_status rc);

static void url_check_init(struct url_check* urls)
{
	string_init_c(&urls->realLink, NULL);
	string_init_c(&urls->displayLink, NULL);
	string_init_c(&urls->pre_fixup.pre_displayLink, NULL);
}

/* string reference counting implementation,
 * so that: we don't have to keep in mind who allocated what, and when needs to be freed,
 * and thus we won't leak memory*/

static void string_free(struct string* str)
{
	for(;;){
		str->refcount--;
		if(!str->refcount) {
			if(str->ref)/* don't free, this is a portion of another string */
				str=str->ref;/* try to free that one*/
			else {
				if(str->data)
					free(str->data);
				break;
			}
		}
		else break;
	}
}

/* always use the string_assign when assigning to a string, this makes sure the old one's reference count is incremented*/
static void string_assign(struct string* dest,struct string* src)
{
	string_free(dest);
	src->refcount++;
	dest->data=src->data;
	dest->refcount=1;
	dest->ref=src;
}

/* data will be freed when string freed */
/* it doesn't free old string, use only for initialization
 * Doesn't allow NULL pointers, they are replaced by pointer to empty string
 * */
static void string_init_c(struct string* dest,char* data)
{
	dest->refcount = data ? 1 : 0;
	dest->data = data ? data : empty_string;
	dest->ref = NULL;
}

/* assigns to @dest the string made from concatenating @prefix with the string between @begin and @end */
static int string_assign_concatenated(struct string* dest, const char* prefix, const char* begin, const char* end)
{
	const size_t prefix_len = strlen(prefix);
	char* ret = cli_malloc(prefix_len + end - begin + 1);
	if(!ret) {
        cli_errmsg("Phishcheck: Unable to allocate memory for string_assign_concatenated\n");
		return CL_EMEM;
    }
	strncpy(ret, prefix, prefix_len);
	strncpy(ret+prefix_len, begin, end-begin);
	ret[prefix_len+end-begin]='\0';
	string_free(dest);
	string_init_c(dest, ret);
	return CL_SUCCESS;
}

/* make a copy of the string between start -> end*/
static int string_assign_dup(struct string* dest,const char* start,const char* end)
{
	char* ret  = cli_malloc(end-start+1);
	if(!ret) {
        cli_errmsg("Phishcheck: Unable to allocate memory for string_assign_dup\n");
		return CL_EMEM;
    }
	strncpy(ret,start,end-start);
	ret[end-start]='\0';

	string_free(dest);
	string_init_c(dest, ret);
	return CL_SUCCESS;
}

static void string_assign_null(struct string* dest)
{
	if(dest) {
		string_free(dest);
		dest->data=empty_string;
		dest->refcount=-1;/* don't free it! */
		dest->ref=NULL;
	}
}

/* this string uses portion of another string*/
static void string_assign_ref(struct string* dest,struct string* ref,char* data)
{
	string_free(dest);
	ref->refcount++;
	dest->data=data;
	dest->refcount=1;
	dest->ref=ref;
}

static void free_if_needed(struct url_check* url)
{
	string_free(&url->realLink);
	string_free(&url->displayLink);
	string_free(&url->pre_fixup.pre_displayLink);
}

static int build_regex(regex_t* preg,const char* regex,int nosub)
{
	int rc;
	cli_dbgmsg("Phishcheck: Compiling regex: %s\n",regex);
	rc = cli_regcomp(preg,regex,REG_EXTENDED|REG_ICASE|(nosub ? REG_NOSUB :0));
	if(rc) {

		size_t buflen =	cli_regerror(rc,preg,NULL,0);
		char *errbuf = cli_malloc(buflen);

		if(errbuf) {
			cli_regerror(rc,preg,errbuf,buflen);
			cli_errmsg("Phishcheck: Error in compiling regex:%s\nDisabling phishing checks\n",errbuf);
			free(errbuf);
		} else
			cli_errmsg("Phishcheck: Error in compiling regex, disabling phishing checks. Additionally an Out-of-memory error was encountered while generating a detailed error message\n");
		return 1;
	}
	return CL_SUCCESS;
}

/* allocates memory */
static int get_host(const char* URL,int isReal,int* phishy,const char **hstart, const char **hend)
{
	int rc,ismailto = 0;
	const char* start;
	const char* end=NULL;
	if(!URL) {
		*hstart=*hend=NULL;
		return 0;
	}
	start = strstr(URL,"://");
	if(!start) {
		if(!strncmp(URL,mailto,mailto_len)) {
			start = URL + mailto_len;
			ismailto = 1;
		}
		else if (!isReal && *phishy&REAL_IS_MAILTO) {
			/* it is not required to use mailto: in the displayed url, they might use to:, or whatever */
			end = URL+strlen(URL)+1;
			start = URL + strcspn(URL,": ")+1;
			if (start==end)
				start = URL;
			ismailto = 1;
		}
		else {
			start=URL;/*URL without protocol*/
			if(isReal)
				cli_dbgmsg("Phishcheck: Real URL without protocol: %s\n",URL);
			else ismailto=2;/*no-protocol, might be mailto, @ is no problem*/
		}
	}
	else
		start += 3;	/* :// */

	if(!ismailto || !isReal) {
		const char *realhost,*tld;

		do {
			end  = start + strcspn(start,":/?");
			realhost = strchr(start,'@');

			if(realhost == NULL || (start!=end && realhost>end)) {
				/*don't check beyond end of hostname*/ 
				break;
			}

			tld = strrchr(realhost,'.');
			rc = tld ? !!in_tld_set(tld,strlen(tld)) : 0;
			if(rc < 0)
				return rc;
			if(rc)
				*phishy |= PHISHY_USERNAME_IN_URL;/* if the url contains a username that is there just to fool people,
			     					     like http://banksite@example.com/ */
			start = realhost+1;/*skip the username*/
		} while(realhost);/*skip over multiple @ characters, text following last @ character is the real host*/
	}
	else if (ismailto && isReal)
		*phishy |= REAL_IS_MAILTO;

	if(!end) {
		end  = start + strcspn(start,":/?");/*especially important for mailto:somebody@yahoo.com?subject=...*/
		if(!end)
			end  = start + strlen(start);
	}
	*hstart = start;
	*hend = end;
	return 0;
}


/*
 * memrchr isn't standard, so I use this
 */
static char *
rfind(char *start, char c, size_t len)
{
	char *p;

	if(start == NULL)
		return NULL;

	for(p = start + len; (p >= start) && (*p != c); p--)
		;
	return (p < start) ? NULL : p;
}

static void get_domain(struct string* dest,struct string* host)
{
	char* domain;
	char* tld = strrchr(host->data,'.');
	if(!tld) {
		cli_dbgmsg("Phishcheck: Encountered a host without a tld? (%s)\n",host->data);
		string_assign(dest,host);
		return;
	}
	if(in_cctld_set(tld+1, strlen(tld+1))) {
		const char* countrycode = tld+1;
		tld = rfind(host->data,'.',tld-host->data-1);
		if(!tld) {
			cli_dbgmsg("Phishcheck: Weird, a name with only 2 levels (%s)\n",
				host->data);
			string_assign(dest,host);
			return;
		}
		if(!in_tld_set(tld+1, countrycode-tld-2)) {
			string_assign_ref(dest,host,tld+1);
			return;/*it was a name like: subdomain.domain.uk, return domain.uk*/
		}
	}
	/*we need to strip one more level, this is the actual domain*/
	domain = rfind(host->data,'.',tld-host->data-1);
	if(!domain) {
		string_assign(dest,host);
		return;/* it was like sourceforge.net?*/
	}
	string_assign_ref(dest,host,domain+1);
}

static int isNumeric(const char* host)
{
	int len = strlen(host);
	int a,b,c,d,n=0;
	/* 1.2.3.4 -> 7*/
	/* 127.127.127.127 -> 15*/
	if(len<7 || len>15)
		return 0;
	sscanf(host,"%d.%d.%d.%d%n",&a,&b,&c,&d,&n);
	if(n==len)
		if(a>=0 && a<=256 && b>=0 && b<=256 && c>=0 && c<=256 && d>=0 && d<=256)
			return 1;
	return 0;
}

static int isSSL(const char* URL)
{
	return URL ? !strncmp(https,URL,https_len) : 0;
}

/* deletes @what from the string @begin.
 * @what_len: length of @what, excluding the terminating \0 */
static void
str_hex_to_char(char **begin, const char **end)
{
	char *firsthex, *sbegin_;
	char *sbegin = *begin;
	const char *str_end = *end;

	if(str_end <= &sbegin[1])
		return;

	/* convert leading %xx*/
	if (sbegin[0] == '%') {
		sbegin[2] = hex2int((unsigned char*)sbegin+1);
		sbegin += 2;
	}
	*begin = sbegin++;
	do {
	    sbegin_ = sbegin;
	    firsthex = NULL;
	    while(sbegin+3 <= str_end) {
		if (sbegin+3<=str_end && sbegin[0]=='%') {
		    const char* src = sbegin+3;
		    if (isxdigit(sbegin[1]) && isxdigit(sbegin[2])) {
			*sbegin = hex2int((unsigned char*)sbegin+1);
			if (*sbegin == '%' && !firsthex)
			    firsthex = sbegin;
			/* move string */
			memmove(sbegin+1,src,str_end-src+1);
			str_end -= 2;
		    }
		}
		sbegin++;
	    }
	    sbegin = sbegin_;
	} while (firsthex);
	*end = str_end;
}

/*
 * deletes @what from the string @begin.
 * @what_len: length of @what, excluding the terminating \0
 */
static void
str_strip(char **begin, const char **end, const char *what, size_t what_len)
{
	char *sbegin = *begin;
	const char *str_end = *end;
	const char *str_end_what;
	size_t cmp_len = what_len;

	if(begin == NULL || str_end <= sbegin)
		return;

	/*if(str_end < (sbegin + what_len))
		return;*/
	if(strlen(sbegin) < what_len)
		return;

	/* strip leading @what */
	while(cmp_len && !strncmp(sbegin,what,cmp_len)) {
		sbegin += what_len;

		if(cmp_len > what_len)
			cmp_len -= what_len;
		else
			cmp_len = 0;
	}

	/* strip trailing @what */
	if(what_len <= (size_t)(str_end - sbegin)) {
		str_end_what = str_end - what_len + 1;
		while((str_end_what > sbegin) &&
		      (strncmp(str_end_what, what, what_len) == 0)) {
			str_end -= what_len;
			str_end_what -= what_len;
		}
	}

	*begin = sbegin++;
	while(sbegin+what_len <= str_end) {
		while(sbegin+what_len<=str_end && !strncmp(sbegin,what,what_len)) {
			const char* src = sbegin+what_len;
			/* move string */
			memmove(sbegin,src,str_end-src+1);
			str_end -= what_len;
		}
		sbegin++;
	}
	*end = str_end;
}


/* replace every occurrence of @c in @str with @r*/
static void str_replace(char* str,const char* end,char c,char r)
{
	for(;str<=end;str++) {
		if(*str==c)
			*str=r;
	}
}
static void str_make_lowercase(char* str,size_t len)
{
	for(;len;str++,len--) {
		*str = tolower(*str);
	}
}

#define fix32(x) ((x)<32 ? 32 : (x))
static void clear_msb(char* begin)
{
	for(;*begin;begin++)
		*begin = fix32((*begin)&0x7f);
}

/*
 * Particularly yahoo puts links like this in mails:
 * http:/ /www.example.com
 * So first step: delete space between / /
 *
 * Next there could be possible links like this:
 * <a href="phishlink">w  w w . e b a y . c o m</a>
 * Here we need to strip spaces to get this picked up.
 *
 * Next there are links like:
 * <a href="www.yahoo.com">Check out yahoo.com</a>
 * Here we add a ., so we get: check.out.yahoo.com (it won't trigger)
 *
 * Old Rule for adding .: if substring from right contains dot, then add dot,
 *	otherwise strip space
 * New Rule: strip all spaces
 *  strip leading and trailing garbage
 *
 */
static void
str_fixup_spaces(char **begin, const char **end)
{
	char* sbegin = *begin;
	const char* send = *end;
	if(!sbegin || !send || send < sbegin)
		return;
	/* strip spaces */
	str_strip(&sbegin, &send, " ",1);
	/* strip leading/trailing garbage */
	while(!isalnum(sbegin[0]&0xff) && sbegin <= send) sbegin++;
	while(!isalnum(send[0]&0xff) && send >= sbegin) send--;

	/* keep terminating slash character*/
	if(send[1] == '/') send++;
	*begin = sbegin;
	*end = send;
}

/* allocates memory */
static int
cleanupURL(struct string *URL,struct string *pre_URL, int isReal)
{
	char *begin = URL->data;
	const char *end;
	size_t len;

	clear_msb(begin);
	/*if(begin == NULL)
		return;*/
	/*TODO: handle hex-encoded IPs*/
	while(isspace(*begin))
		begin++;

	len = strlen(begin);
	if(len == 0) {
		string_assign_null(URL);
		string_assign_null(pre_URL);
		return 0;
	}

	end = begin + len - 1;
	/*cli_dbgmsg("%d %d\n", end-begin, len);*/
	if(begin >= end) {
		string_assign_null(URL);
		string_assign_null(pre_URL);
		return 0;
	}
	while(isspace(*end))
		end--;
	/* From mailscanner, my comments enclosed in {} */
	if(!strncmp(begin,dotnet,dotnet_len) || !strncmp(begin,adonet,adonet_len) || !strncmp(begin,aspnet,aspnet_len)) {
		string_assign_null(URL);
		string_assign_null(pre_URL);
	}
	else {
		size_t host_len;
		char* host_begin;
		int rc;

		str_replace(begin,end,'\\','/');
		/* find beginning of hostname, because:
		 * - we want to keep only protocol, host, and 
		 *  strip path & query parameter(s) 
		 * - we want to make hostname lowercase*/
		host_begin = strchr(begin,':');
		while(host_begin && (host_begin < end) && (host_begin[1] == '/'))  host_begin++;
		if(!host_begin) host_begin=begin;
		else host_begin++;
		host_len = strcspn(host_begin,":/?");
	        if(host_begin + host_len > end + 1) {
			/* prevent hostname extending beyond end, it can happen
			 * if we have spaces at the end, we don't want those part of 
			 * the hostname */
			host_len = end - host_begin + 1;
		} else {
			/* cut the URL after the hostname */
			/* @end points to last character we want to be part of the URL */
			end = host_begin + host_len - 1;
		}
		host_begin[host_len] = '\0';
		/* convert hostname to lowercase, but only hostname! */
		str_make_lowercase(host_begin, host_len);
		/* some broken MUAs put > in the href, and then
		 * we get a false positive, so remove them */
		str_replace(begin,end,'<',' ');
		str_replace(begin,end,'>',' ');
		str_replace(begin,end,'\"',' ');
		str_replace(begin,end,';',' ');
		str_strip(&begin,&end,lt,lt_len);
		str_strip(&begin,&end,gt,gt_len);
		/* convert %xx to real value */
		str_hex_to_char(&begin,&end);
		if(isReal) {
			/* htmlnorm converts \n to space, so we have to strip spaces */
			str_strip(&begin, &end, " ", 1);
		}
		else {
			/* trim space */
			while((begin <= end) && (begin[0]==' '))  begin++;
			while((begin <= end) && (end[0]==' ')) end--;
		}
		if (( rc = string_assign_dup(isReal ? URL : pre_URL,begin,end+1) )) {
			string_assign_null(URL);
			return rc;
		}
		if(!isReal) {
			str_fixup_spaces(&begin,&end);
			if (( rc = string_assign_dup(URL, begin, end+1) )) {
				return rc;
			}
		}
	}
	return 0;
}

/* -------end runtime disable---------*/
int phishingScan(cli_ctx* ctx,tag_arguments_t* hrefs)
{
	/* TODO: get_host and then apply regex, etc. */
	int i;
	struct phishcheck* pchk = (struct phishcheck*) ctx->engine->phishcheck;
	/* check for status of whitelist fatal error, etc. */
	if(!pchk || pchk->is_disabled)
		return CL_CLEAN;

	if(!ctx->found_possibly_unwanted && !SCAN_ALLMATCHES)
		*ctx->virname=NULL;
#if 0
	FILE *f = fopen("/home/edwin/quarantine/urls","r");
	if(!f)
		abort();
	while(!feof(f)) {
		struct url_check urls;
		char line1[4096];
		char line2[4096];
		char line3[4096];

		fgets(line1, sizeof(line1), f);
		fgets(line2, sizeof(line2), f);
		fgets(line3, sizeof(line3), f);
		if(strcmp(line3, "\n") != 0) {
			strcpy(line1, line2);
			strcpy(line2, line3);
			fgets(line3, sizeof(line3), f);
			while(strcmp(line3, "\n") != 0) {
				fgets(line3, sizeof(line3),f);
			}
		}
		urls.flags = CL_PHISH_ALL_CHECKS;
		urls.link_type = 0;
		string_init_c(&urls.realLink, line1);
		string_init_c(&urls.displayLink, line2);
		string_init_c(&urls.pre_fixup.pre_displayLink, NULL);
		urls.realLink.refcount=-1;
		urls.displayLink.refcount=-1;
		int rc = phishingCheck(ctx->engine, &urls);
	}
	fclose(f);
	return 0;
#endif
	for(i=0;i<hrefs->count;i++) {
			struct url_check urls;
			enum phish_status rc;
			urls.flags	 = strncmp((char*)hrefs->tag[i],href_text,href_text_len)? (CL_PHISH_ALL_CHECKS&~CHECK_SSL): CL_PHISH_ALL_CHECKS;
			urls.link_type   = 0;
			if(!strncmp((char*)hrefs->tag[i],src_text,src_text_len)) {
				if (!(urls.flags&CHECK_IMG_URL))
				continue;
				urls.link_type |= LINKTYPE_IMAGE;
			}
			urls.always_check_flags = 0;
			if (SCAN_HEURISTIC_PHISHING_SSL_MISMATCH) {
				urls.always_check_flags |= CHECK_SSL;
			}
			if (SCAN_HEURISTIC_PHISHING_CLOAK) {
				urls.always_check_flags |= CHECK_CLOAKING;
			}
			string_init_c(&urls.realLink,(char*)hrefs->value[i]);
			string_init_c(&urls.displayLink, (char*)hrefs->contents[i]);
			string_init_c(&urls.pre_fixup.pre_displayLink, NULL);

			urls.realLink.refcount=-1;
			urls.displayLink.refcount=-1;/*don't free these, caller will free*/
			if(strcmp((char*)hrefs->tag[i],"href")) {
				char *url;
				url = urls.realLink.data;
				urls.realLink.data = urls.displayLink.data;
				urls.displayLink.data = url;
			}

			rc = phishingCheck(ctx->engine,&urls);
			if(pchk->is_disabled)
				return CL_CLEAN;
			free_if_needed(&urls);
			cli_dbgmsg("Phishcheck: Phishing scan result: %s\n",phishing_ret_toString(rc));
			switch(rc)/*TODO: support flags from ctx->options,*/
			{
				case CL_PHISH_CLEAN:
					continue;
				case CL_PHISH_NUMERIC_IP:
				    cli_append_possibly_unwanted(ctx, "Heuristics.Phishing.Email.Cloaked.NumericIP");
					break;
				case CL_PHISH_CLOAKED_NULL:
				    cli_append_possibly_unwanted(ctx, "Heuristics.Phishing.Email.Cloaked.Null");/*fakesite%01%00@fake.example.com*/
					break;
				case CL_PHISH_SSL_SPOOF:
				    cli_append_possibly_unwanted(ctx, "Heuristics.Phishing.Email.SSL-Spoof");
					break;
				case CL_PHISH_CLOAKED_UIU:
				    cli_append_possibly_unwanted(ctx, "Heuristics.Phishing.Email.Cloaked.Username");/*http://banksite@fake.example.com*/
					break;
				case CL_PHISH_HASH0:
				    cli_append_possibly_unwanted(ctx, "Heuristics.Safebrowsing.Suspected-malware_safebrowsing.clamav.net");
					break;
				case CL_PHISH_HASH1:
				    cli_append_possibly_unwanted(ctx, "Heuristics.Phishing.URL.Blacklisted");
					break;
				case CL_PHISH_HASH2:
				    cli_append_possibly_unwanted(ctx, "Heuristics.Safebrowsing.Suspected-phishing_safebrowsing.clamav.net");
					break;
				case CL_PHISH_NOMATCH:
				default:
				    cli_append_possibly_unwanted(ctx, "Heuristics.Phishing.Email.SpoofedDomain");
					break;
			}
	}
	return CL_CLEAN;
}

static char hex2int(const unsigned char* src)
{
	return (src[0] == '0' && src[1] == '0') ? 
		0x1 :/* don't convert %00 to \0, use 0x1
 		      * this value is also used by cloak check*/
		hextable[src[0]]<<4 | hextable[src[1]];
}

static void free_regex(regex_t* p)
{
	if(p) {
		cli_regfree(p);
	}
}

int phishing_init(struct cl_engine* engine)
{
	struct phishcheck* pchk;
	if(!engine->phishcheck) {
		pchk = engine->phishcheck = mpool_malloc(engine->mempool, sizeof(struct phishcheck));
		if(!pchk) {
            cli_errmsg("Phishcheck: Unable to allocate memory for initialization\n");
			return CL_EMEM;
        }
		pchk->is_disabled=1;
	}
	else {
		pchk = engine->phishcheck;
		if(!pchk)
			return CL_ENULLARG;
		if(!pchk->is_disabled) {
			/* already initialized */
			return CL_SUCCESS;
		}
	}

	cli_dbgmsg("Initializing phishcheck module\n");

	if(build_regex(&pchk->preg_numeric,numeric_url_regex,1)) {
		mpool_free(engine->mempool, pchk);
		engine->phishcheck = NULL;
		return CL_EFORMAT;
	}
	pchk->is_disabled = 0;
	cli_dbgmsg("Phishcheck module initialized\n");
	return CL_SUCCESS;
}

void phishing_done(struct cl_engine* engine)
{
	struct phishcheck* pchk = engine->phishcheck;
	cli_dbgmsg("Cleaning up phishcheck\n");
	if(pchk && !pchk->is_disabled) {
		free_regex(&pchk->preg_numeric);
	}
	whitelist_done(engine);
	domainlist_done(engine);
	if(pchk) {
		cli_dbgmsg("Freeing phishcheck struct\n");
		mpool_free(engine->mempool, pchk);
	}
	cli_dbgmsg("Phishcheck cleaned up\n");
}


/*ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz*/
static const uint8_t URI_alpha[256] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
        0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*!"$%&'()*,-0123456789@ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz*/
static const uint8_t URI_xalpha_nodot[256] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1,
        0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*!"#$%&'()*+,-0123456789@ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz*/
static const uint8_t URI_xpalpha_nodot[256] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1,
        0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static inline int validate_uri_xalphas_nodot(const char *start, const char *end)
{
	const unsigned char *p;
	for(p=(const unsigned char*)start;p < (const unsigned char*)end; p++) {
		if(!URI_xalpha_nodot[*p])
			return 0;
	}
	return 1;
}

static inline int validate_uri_xpalphas_nodot(const char *start, const char *end)
{
	const unsigned char *p;
	for(p=(const unsigned char*)start;p < (const unsigned char*)end; p++) {
		if(!URI_xpalpha_nodot[*p])
			return 0;
	}
	/* must have at least on char */
	return p > (const unsigned char*)start;
}


static inline int validate_uri_ialpha(const char *start, const char *end)
{
	const unsigned char *p = (const unsigned char*) start;
	if(start >= end || !URI_alpha[*p])
		return 0;
	return validate_uri_xalphas_nodot(start + 1, end);
}

/*
 * Only those URLs are identified as URLs for which phishing detection can be performed.
 */
static int isURL(char* URL, int accept_anyproto)
{
	char *last_tld_end = NULL, *q;
	const char *start = NULL, *p, *end;
	int has_proto = 0;
	if(!URL)
		return 0;

	while (*URL == ' ') URL++;
	switch (URL[0]) {
		case 'h':
			if (strncmp(URL, https, https_len) == 0)
				start = URL + https_len - 1;
			else if (strncmp(URL, http, http_len) == 0)
				start = URL + http_len - 1;
			break;
		case 'f':
		       if (strncmp(URL, ftp, ftp_len) == 0)
			       start = URL + ftp_len - 1;
		       break;
		case 'm':
		       if (strncmp(URL, mailto_proto, mailto_proto_len) == 0)
			       start = URL + mailto_proto_len - 1;
		       break;
	}
	if(start && start[1] == '/' && start[2] == '/') {
		/* has a valid protocol, it is a URL */
		return 1;
	}
	start = accept_anyproto ?  strchr(URL, ':') : start;
	if(start) {
		/* validate URI scheme */
		if(validate_uri_ialpha(URL, start)) {
			/* skip :// */
			if (start[1] == '/') {
			    start += 2;
			    if (*start == '/')
				start++;
			} else
			    start++;
			has_proto = 1;
		}
		else
			start = URL; /* scheme invalid */
	} else
		start = URL;
	p = start;
	end = strchr(p, '/');
	if (!end)
		end = p + strlen(p);

	if (!has_proto && (q = memchr(p, '@', end-p))) {
	    /* don't phishcheck if displayed URL is email, but do phishcheck if
	     * foo.TLD@host is used */
	    const char *q2 = q-1;
	    while (q2 > p && *q2 != '.') q2--;
	    if (q2 == p || !in_tld_set(q2+1, q-q2-1))
		return 0;
	}

	do {
		q = strchr(p, '.');
		if (q > end)
			break;
		if(q) {
			if(!validate_uri_xpalphas_nodot(p, q))
				return 0;
			if (accept_anyproto && in_tld_set(p, q-p))
			    last_tld_end = q;
			p = q+1;
		}
	} while(q);
	if (p == start) /* must have at least one dot in the URL */
		return 0;
	if (end < p)
		end = p;
	while (*end == ' ' && end > p) --end;

	if (in_tld_set(p, end - p))
	    return 1;
	if (!accept_anyproto)
	    return 0;
	if (last_tld_end) {
	    *last_tld_end = '\0';
	    return 1;
	}
	return 0;
}

/*
 * Check if this is a real URL, which basically means to check if it has a known URL scheme (http,https,ftp).
 * This prevents false positives with outbind:// and blocked:: links.
 */
#if 0
static int isRealURL(const struct phishcheck* pchk,const char* URL)
{
	return URL ? !cli_regexec(&pchk->preg_realurl,URL,0,NULL,0) : 0;
}
#endif

static int isNumericURL(const struct phishcheck* pchk,const char* URL)
{
	return URL ? !cli_regexec(&pchk->preg_numeric,URL,0,NULL,0) : 0;
}

/* Cleans up @urls
 * If URLs are identical after cleanup it will return CL_PHISH_CLEANUP_OK.
 * */
static enum phish_status cleanupURLs(struct url_check* urls)
{
	if(urls->flags&CLEANUP_URL) {
		cleanupURL(&urls->realLink,NULL,1);
		cleanupURL(&urls->displayLink,&urls->pre_fixup.pre_displayLink,0);
		if(!urls->displayLink.data || !urls->realLink.data)
			return CL_PHISH_NODECISION;
		if(!strcmp(urls->realLink.data,urls->displayLink.data))
			return CL_PHISH_CLEAN;
	}
	return CL_PHISH_NODECISION;
}

static int url_get_host(struct url_check* url,struct url_check* host_url,int isReal,int* phishy)
{
	const char *start, *end;
	struct string* host = isReal ? &host_url->realLink : &host_url->displayLink;
	const char* URL = isReal ? url->realLink.data : url->displayLink.data;
	int rc;
	if ((rc = get_host(URL, isReal, phishy, &start, &end))) {
		return rc;
	}
	if(!start || !end) {
		string_assign_null(host);
	}
	else if(( rc = string_assign_concatenated(host, ".", start, end) )) {
		return rc;
	}

	cli_dbgmsg("Phishcheck:host:%s\n", host->data);

	if(!host->data || (isReal && (host->data[0]=='\0' || strstr(host->data,".."))) || *phishy&REAL_IS_MAILTO || strchr(host->data,' ')) {
		/* no host,
		 * link without domain, such as: href="/isapi.dll?...
		 * mailto:
		 * spaces in hostname
		 * double dots
		 */
		cli_dbgmsg("Phishcheck:skipping invalid host\n");
		return CL_PHISH_CLEAN;
	}
	if(isNumeric(host->data)) {
		*phishy |= PHISHY_NUMERIC_IP;
	}
	if(!isReal) {
		url->pre_fixup.host_start = start - URL;
		url->pre_fixup.host_end = end - URL;
		url->pre_fixup.pre_displayLink.data[url->pre_fixup.host_end] = '\0';
	}
	return CL_PHISH_NODECISION;
}

static void url_get_domain(struct url_check* url,struct url_check* domains)
{
	get_domain(&domains->realLink, &url->realLink);
	get_domain(&domains->displayLink, &url->displayLink);
	domains->flags = url->flags;
}

static enum phish_status phishy_map(int phishy,enum phish_status fallback)
{
	if(phishy&PHISHY_USERNAME_IN_URL)
		return CL_PHISH_CLOAKED_UIU;
	else if(phishy&PHISHY_NUMERIC_IP)
		return CL_PHISH_NUMERIC_IP;
	else
		return fallback;
}

static int whitelist_check(const struct cl_engine* engine,struct url_check* urls,int hostOnly)
{
	return whitelist_match(engine,urls->realLink.data,urls->displayLink.data,hostOnly);
}

static int hash_match(const struct regex_matcher *rlist, const char *host, size_t hlen, const char *path, size_t plen, int *prefix_matched)
{
	const char *virname;
#if 0
	char s[1024];
	strncpy(s, host, hlen);
	strncpy(s+hlen, path, plen);
	s[hlen+plen] = '\0';
	cli_dbgmsg("hash lookup for: %s\n",s);
#endif
    UNUSEDPARAM(prefix_matched);

	if(rlist->sha256_hashes.bm_patterns) {
	    const char hexchars[] = "0123456789ABCDEF";
	    unsigned char h[65];
	    unsigned char sha256_dig[32];
	    unsigned i;
        void *sha256;

        sha256 = cl_hash_init("sha256");
        if (!(sha256))
            return CL_EMEM;

        cl_update_hash(sha256, (void *)host, hlen);
        cl_update_hash(sha256, (void *)path, plen);
        cl_finish_hash(sha256, sha256_dig);

	    for(i=0;i<32;i++) {
		h[2*i] = hexchars[sha256_dig[i]>>4];
		h[2*i+1] = hexchars[sha256_dig[i]&0xf];
	    }
	    h[64]='\0';
	    cli_dbgmsg("Looking up hash %s for %s(%u)%s(%u)\n", h, host, (unsigned)hlen, path, (unsigned)plen);
#if 0
	    if (prefix_matched) {
		if (cli_bm_scanbuff(sha256_dig, 4, &virname, NULL, &rlist->hostkey_prefix,0,NULL,NULL,NULL) == CL_VIRUS) {
		    cli_dbgmsg("prefix matched\n");
		    *prefix_matched = 1;
		} else
		    return CL_SUCCESS;
	    }
#endif
	    if (cli_bm_scanbuff(sha256_dig, 32, &virname, NULL, &rlist->sha256_hashes,0,NULL,NULL,NULL) == CL_VIRUS) {
		cli_dbgmsg("This hash matched: %s\n", h);
		switch(*virname) {
		    case 'W':
			cli_dbgmsg("Hash is whitelisted, skipping\n");
			break;
		    case '1':
			return CL_PHISH_HASH1;
		    case '2':
			return CL_PHISH_HASH2;
		    default:
			return CL_PHISH_HASH0;
		}
	    }
	}
	return CL_SUCCESS;
}

#define URL_MAX_LEN 1024
#define COMPONENTS 4
int cli_url_canon(const char *inurl, size_t len, char *urlbuff, size_t dest_len, char **host, size_t *hostlen, const char **path, size_t *pathlen)
{
	char *url, *p, *last;
	char *host_begin, *path_begin;
	const char *urlend = urlbuff + len;
	size_t host_len, path_len;

	dest_len -= 3;
	strncpy(urlbuff, inurl, dest_len);
	urlbuff[dest_len] = urlbuff[dest_len+1] = urlbuff[dest_len+2] = '\0';
	url = urlbuff;

	/* canonicalize only real URLs, with a protocol */
	host_begin = strchr(url, ':');
	if(!host_begin)
		return CL_PHISH_CLEAN;
	++host_begin;

	/* ignore username in URL */
	while((host_begin < urlend) && *host_begin == '/') ++host_begin;
	host_len = strcspn(host_begin, ":/?");
	p = memchr(host_begin, '@', host_len);
	if (p)
	    host_begin = p+1;
	url = host_begin;
	/* repeatedly % unescape characters */
	str_hex_to_char(&url, &urlend);
	host_begin = url;
	len = urlend - url;
	/* skip to beginning of hostname */
	while((host_begin < urlend) && *host_begin == '/') ++host_begin;
	while(*host_begin == '.' && host_begin < urlend) ++host_begin;

	last = strchr(host_begin, '/');
	p = host_begin;
	while (p < urlend) {
	    if (p+2 < urlend && *p == '/' && p[1] == '.' ) {
		if (p[2] == '/') {
		    /* remove /./ */
		    if (p + 3 < urlend)
			memmove(p+1, p+3, urlend - p - 3);
		    urlend -= 2;
		}
		else if (p[2] == '.' && (p[3] == '/' || p[3] == '\0') && last) {
		    /* remove /component/../ */
		    if (p+4 < urlend)
			memmove(last+1, p+4, urlend - p - 4);
		    urlend -= 3 + (p - last);
		}
	    }
	    if (*p == '/')
		last = p;
	    p++;
	}
	p = &url[urlend - url];
	*p = '\0';

	p = host_begin;
	while (p < urlend && p+2 < url + dest_len && urlend < urlbuff+dest_len) {
	    unsigned char c = *p;
	    if (c <= 32 || c >= 127 || c == '%' || c == '#') {
		/* convert non-ascii characters back to % escaped */
		const char hexchars[] = "0123456789ABCDEF";
		memmove(p+3, p+1, urlend - p - 1);
		*p++ = '%';
		*p++ = hexchars[c>>4];
		*p = hexchars[c&0xf];
		urlend += 2;
	    }
	    p++;
	}
	*p = '\0';
	urlend = p;
	len = urlend - url;
	/* determine end of hostname */
	host_len = strcspn(host_begin, ":/?");
	path_begin = host_begin + host_len;
	if(host_len <= len) {
		/* url without path, use a single / */
		memmove(path_begin + 2, path_begin + 1, len - host_len);
		*path_begin++ = '/';
		*path_begin++ = '\0';
	} else path_begin = url+len;
	if(url + len >= path_begin) {
		path_len = url + len - path_begin + 1;
		p = strchr(path_begin, '#');
		if (p) {
		    /* ignore anchor */
		    *p = '\0';
		    path_len = p - path_begin;
		}
		*path = path_begin;
	} else {
		path_len = 0;
		*path = "";
	}
	/* lowercase entire URL */
	str_make_lowercase(host_begin, host_len);
	*host = host_begin;
	*hostlen = host_len;
	*pathlen = path_len;
	return CL_PHISH_NODECISION;
}

static int url_hash_match(const struct regex_matcher *rlist, const char *inurl, size_t len)
{
	size_t j, k, ji, ki;
	char *host_begin;
	const char *path_begin;
	const char *component;
	size_t path_len;
	size_t host_len;
	char *p;
	int rc, prefix_matched=0;
	const char *lp[COMPONENTS+1];
	size_t pp[COMPONENTS+2];
	char urlbuff[URL_MAX_LEN+3];/* htmlnorm truncates at 1024 bytes + terminating null + slash + host end null */
	unsigned count;

	if(!rlist || !rlist->sha256_hashes.bm_patterns) {
		/* no hashes loaded -> don't waste time canonicalizing and
		 * looking up */
		return CL_SUCCESS;
	}
	if(!inurl)
		return CL_EMEM;

	rc = cli_url_canon(inurl, len, urlbuff, sizeof(urlbuff), &host_begin, &host_len, &path_begin, &path_len);
	if (rc == CL_PHISH_CLEAN)
	    return rc;

	/* get last 5 components of hostname */
	j=COMPONENTS;
	component = strrchr(host_begin, '.');
	while(component && j > 0) {
		do {
			--component;
		} while(*component != '.' && component > host_begin);
		if(*component != '.')
			component = NULL;
		if(component)
			lp[j--] = component + 1;
	}
	lp[j] = host_begin;

	/* get first 5 components of path */
	pp[0] = path_len;
	if(path_len) {
		pp[1] = strcspn(path_begin, "?");
		if(pp[1] != pp[0]) k = 2;
		else k = 1;
		pp[k++] = 0;
		while(k < COMPONENTS+2) {
			p = strchr(path_begin + pp[k-1] + 1, '/');
			if(p && p > path_begin) {
				pp[k++] = p - path_begin + 1;
			} else
				break;
		}
	} else
		k = 1;
	count = 0;
	for(ki=k;ki > 0;) {
	    --ki;
	    for(ji=COMPONENTS+1;ji > j;) {
		/* lookup last 2 and 3 components of host, as hostkey prefix,
		 * if not matched, shortcircuit lookups */
		int need_prefixmatch = (count<2 && !prefix_matched) &&
				       rlist->hostkey_prefix.bm_patterns;
		--ji;
		assert(pp[ki] <= path_len);
		/* lookup prefix/suffix hashes of URL */
		rc = hash_match(rlist, lp[ji], host_begin + host_len - lp[ji] + 1, path_begin, pp[ki], 
				need_prefixmatch ? &prefix_matched : NULL);
		if(rc) {
		    return rc;
		}
		count++;
#if 0
		if (count == 2 && !prefix_matched && rlist->hostkey_prefix.bm_patterns) {
		    /* if hostkey is not matched, don't bother calculating
		     * hashes for other parts of the URL, they are not in the DB
		     */
		    cli_dbgmsg("hostkey prefix not matched, short-circuiting lookups\n");
		    return CL_SUCCESS;
		}
#endif
	    }
	}
	return CL_SUCCESS;
}

/* urls can't contain null pointer, caller must ensure this */
static enum phish_status phishingCheck(const struct cl_engine* engine,struct url_check* urls)
{
	struct url_check host_url;
	int rc = CL_PHISH_NODECISION;
	int phishy=0;
	const struct phishcheck* pchk = (const struct phishcheck*) engine->phishcheck;

	if(!urls->realLink.data)
		return CL_PHISH_CLEAN;

	cli_dbgmsg("Phishcheck:Checking url %s->%s\n", urls->realLink.data,
		urls->displayLink.data);

	if(!isURL(urls->realLink.data, 0)) {
		cli_dbgmsg("Real 'url' is not url:%s\n",urls->realLink.data);
		return CL_PHISH_CLEAN;
	}

	if(( rc = url_hash_match(engine->domainlist_matcher, urls->realLink.data, strlen(urls->realLink.data)) )) {
	    if (rc == CL_PHISH_CLEAN) {
		cli_dbgmsg("not analyzing, not a real url: %s\n", urls->realLink.data);
		return CL_PHISH_CLEAN;
	    } else {
		cli_dbgmsg("Hash matched for: %s\n", urls->realLink.data);
		return rc;
	    }
	}

	if(!strcmp(urls->realLink.data,urls->displayLink.data))
		return CL_PHISH_CLEAN;/* displayed and real URL are identical -> clean */

	if (urls->displayLink.data[0] == '\0') {
	    return CL_PHISH_CLEAN;
	}

	if((rc = cleanupURLs(urls))) {
		/* it can only return an error, or say its clean;
		 * it is not allowed to decide it is phishing */
		return rc < 0 ? rc : CL_PHISH_CLEAN;
	}

	cli_dbgmsg("Phishcheck:URL after cleanup: %s->%s\n", urls->realLink.data,
		urls->displayLink.data);

	if((!isURL(urls->displayLink.data, 1) ) &&
			( (phishy&PHISHY_NUMERIC_IP && !isNumericURL(pchk, urls->displayLink.data)) ||
			  !(phishy&PHISHY_NUMERIC_IP))) {
		cli_dbgmsg("Displayed 'url' is not url:%s\n",urls->displayLink.data);
		return CL_PHISH_CLEAN;
	}

	if(whitelist_check(engine, urls, 0))
		return CL_PHISH_CLEAN;/* if url is whitelisted don't perform further checks */

	url_check_init(&host_url);

	if((rc = url_get_host(urls, &host_url, DOMAIN_DISPLAY, &phishy))) {
		free_if_needed(&host_url);
		return rc < 0 ? rc : CL_PHISH_CLEAN;
	}

	if (domainlist_match(engine, host_url.displayLink.data,host_url.realLink.data,&urls->pre_fixup,1)) {
		phishy |= DOMAIN_LISTED;
	} else {
		urls->flags &= urls->always_check_flags;
		/* don't return, we may need to check for ssl/cloaking */
	}

	/* link type filtering must occur after last domainlist_match */
	if(urls->link_type & LINKTYPE_IMAGE && !(urls->flags&CHECK_IMG_URL)) {
		free_if_needed(&host_url);
		return CL_PHISH_CLEAN;/* its listed, but this link type is filtered */
	}

	if(urls->flags&CHECK_CLOAKING) {
		/*Checks if URL is cloaked.
		Should we check if it contains another http://, https://?
		No because we might get false positives from redirect services.*/
		if(strchr(urls->realLink.data,0x1)) {
			free_if_needed(&host_url);
			return CL_PHISH_CLOAKED_NULL;
		}
	}

	if(urls->flags&CHECK_SSL && isSSL(urls->displayLink.data) && !isSSL(urls->realLink.data)) {
		free_if_needed(&host_url);
		return CL_PHISH_SSL_SPOOF;
	}

	if (!(phishy & DOMAIN_LISTED)) {
		free_if_needed(&host_url);
		return CL_PHISH_CLEAN;
	}

	if((rc = url_get_host(urls,&host_url,DOMAIN_REAL,&phishy)))
	{
		free_if_needed(&host_url);
		return rc < 0 ? rc : CL_PHISH_CLEAN;
	}

	if(whitelist_check(engine,&host_url,1)) {
		free_if_needed(&host_url);
		return CL_PHISH_CLEAN;
	}

	if(!strcmp(urls->realLink.data,urls->displayLink.data)) {
		free_if_needed(&host_url);
		return CL_PHISH_CLEAN;
	}

	{
		struct url_check domain_url;
		url_check_init(&domain_url);
		url_get_domain(&host_url,&domain_url);
		if(!strcmp(domain_url.realLink.data,domain_url.displayLink.data)) {
			free_if_needed(&host_url);
			free_if_needed(&domain_url);
			return CL_PHISH_CLEAN;
		}
		free_if_needed(&domain_url);
	}

	free_if_needed(&host_url);
	/*we failed to find a reason why the 2 URLs are different, this is definitely phishing*/
	return phishy_map(phishy,CL_PHISH_NOMATCH);
}

static const char* phishing_ret_toString(enum phish_status rc)
{
	switch(rc) {
		case CL_PHISH_CLEAN:
			return "Clean";
		case CL_PHISH_CLOAKED_NULL:
			return "Link URL is cloaked (null byte %00)";
		case CL_PHISH_CLOAKED_UIU:
			return "Link URL contains username, and real<->displayed hosts don't match.";
			/*username is a legit domain, and after the @ comes the evil one*/
		case CL_PHISH_SSL_SPOOF:
			return "Visible links is SSL, real link is not";
		case CL_PHISH_NOMATCH:
			return "URLs are way too different";
		case CL_PHISH_HASH0:
		case CL_PHISH_HASH1:
		case CL_PHISH_HASH2:
			return "Blacklisted";
		default:
			return "Unknown return code";
	}
}


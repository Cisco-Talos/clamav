/*
 *  Detect phishing, based on URL spoofing detection.
 *
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
 *
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifndef CL_DEBUG
#define NDEBUG
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
#include "mbox.h"
#include "message.h"
#include "htmlnorm.h"
#include "phishcheck.h"
#include "phish_domaincheck_db.h"
#include "phish_whitelist.h"
#include "iana_tld.h"


#define DOMAIN_REAL 1
#define DOMAIN_DISPLAY 0

#define PHISHY_USERNAME_IN_URL 1
#define PHISHY_NUMERIC_IP      2
#define REAL_IS_MAILTO	       4
/* this is just a flag, so that the displayed url will be parsed as mailto too, for example
 * <a href='mailto:somebody@yahoo.com'>to:somebody@yahoo.com</a>*/
#define DOMAIN_LISTED		 8
#define PHISHY_CLOAKED_NULL	16
#define PHISHY_HEX_URL		32

/*
* Phishing design documentation,
(initially written at http://wiki.clamav.net/index.php/phishing_design as discussed with aCaB)

TODO:update this doc

*Warning*: if flag *--phish-scan-alldomains* (or equivalent clamd/clamav-milter config option) isn't given, then phishing scanning is done only for domains listed in daily.pdb.
If your daily.pdb is empty, then by default NO PHISHING is DONE, UNLESS you give the *--phish-scan-alldomains*
This is just a side-effect, daily.pdb is empty, because it isn't yet officialy in daily.cvd.

phishingCheck() determines if @displayedLink is  a legit representation of @realLink.

Steps:

1. if _realLink_ *==* _displayLink_ => *CLEAN*

2. url cleanup (normalization)
- whitespace elimination
- html entity conversion
- convert hostname to lowercase
- normalize \ to /
If there is a dot after the last space, then all spaces are replaced with dots,
otherwise spaces are stripped.
So both: 'Go to yahoo.com', and 'Go to e b a y . c o m', and 'Go to ebay. com' will work.


3. Matched the urls against a _whitelist_:
a _realLink_, _displayedLink_ pair is matched against the _whitelist_.
the _whitelist_ is a list of pairs of realLink, displayedLink. Any of the elements of those pairs can be a _regex_.
 if url *is found* in _whitelist_ --> *CLEAN*

4. URL is looked up in the _domainlist_, unless disabled via flags (_--phish-scan-alldomains_).
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
Maybe we should disable numericIP checks for --phish-scan-alldomains?

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


#define ANY_CLOAK "(0[xX][0-9a-fA-F]+|[0-9]+)"
#define CLOAKED_URL "^"ANY_CLOAK"(\\."ANY_CLOAK"){0,3}$"

static const char cloaked_host_regex[] = CLOAKED_URL;
static const char tld_regex[] = "^"iana_tld"$";
static const char cctld_regex[] = "^"iana_cctld"$";
static const char dotnet[] = ".net";
static const char adonet[] = "ado.net";
static const char aspnet[] = "asp.net";
/* ; is replaced by ' ' so omit it here*/
static const char lt[]="&lt";
static const char gt[]="&gt";
static const char src_text[] = "src";
static const char href_text[] = "href";
static const char mailto[] = "mailto:";
static const char https[]="https://";

static const size_t href_text_len = sizeof(href_text);
static const size_t src_text_len = sizeof(src_text);
static const size_t dotnet_len = sizeof(dotnet)-1;
static const size_t adonet_len = sizeof(adonet)-1;
static const size_t aspnet_len = sizeof(aspnet)-1;
static const size_t lt_len = sizeof(lt)-1;
static const size_t gt_len = sizeof(gt)-1;
static const size_t mailto_len = sizeof(mailto)-1;
static const size_t https_len  = sizeof(https)-1;

/* for urls, including mailto: urls, and (broken) http:www... style urls*/
/* refer to: http://www.w3.org/Addressing/URL/5_URI_BNF.html
 * Modifications: don't allow empty domains/subdomains, such as www..com <- that is no url
 * So the 'safe' char class has been split up
 * */
/* character classes */
#define URI_alpha	"a-zA-Z"
#define URI_digit	"0-9"
#define URI_safe_nodot  "-$_@&"
#define URI_safe	"-$_@.&"
#define URI_extra	"!*\"'(),"
#define URI_reserved    "=;/#?: "
#define URI_national    "{}|[]\\^~"
#define URI_punctuation "<>"

#define URI_hex		 "[0-9a-fA-f]"
#define URI_escape      "%"URI_hex"{2}"
#define URI_xalpha "([" URI_safe URI_alpha URI_digit  URI_extra "]|"URI_escape")" /* URI_safe has to be first, because it contains - */
#define URI_xalpha_nodot "([" URI_safe_nodot URI_alpha URI_digit URI_extra "]|"URI_escape")"

#define URI_xalphas URI_xalpha"+"
#define URI_xalphas_nodot URI_xalpha_nodot"*"

#define URI_ialpha  "["URI_alpha"]"URI_xalphas_nodot""
#define URI_xpalpha URI_xalpha"|\\+"
#define URI_xpalpha_nodot URI_xalpha_nodot"|\\+"
#define URI_xpalphas "("URI_xpalpha")+"
#define URI_xpalphas_nodot "("URI_xpalpha_nodot")+"
#define optional_URI_xpalphas "("URI_xpalpha"|=)*"

#define URI_scheme URI_ialpha
#define URI_tld iana_tld
#define URI_path1 URI_xpalphas_nodot"\\.("URI_xpalphas_nodot"\\.)*"
#define URI_path2 URI_tld
#define URI_path3 "(/"optional_URI_xpalphas")*"

#define URI_search "("URI_xalphas")*"
#define URI_fragmentid URI_xalphas

#define URI_IP_digits "["URI_digit"]{1,3}"
#define URI_numeric_path URI_IP_digits"(\\."URI_IP_digits"){3}(:"URI_xpalphas_nodot")?(/("URI_xpalphas"/?)*)?"
#define URI_numeric_URI "("URI_scheme":(//)?)?"URI_numeric_path"(\\?" URI_search")?"
#define URI_numeric_fragmentaddress URI_numeric_URI"(#"URI_fragmentid")?"

#define URI_URI1 "("URI_scheme":(//)?)?"URI_path1
#define URI_URI2 URI_path2
#define URI_URI3 URI_path3"(\\?" URI_search")?"

#define URI_fragmentaddress1 URI_URI1
#define URI_fragmentaddress2 URI_URI2
#define URI_fragmentaddress3 URI_URI3"(#"URI_fragmentid")?"

#define URI_CHECK_PROTOCOLS "(http|https|ftp|mailto)://.+"

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
static void string_assign_null(struct string* dest);
static char *rfind(char *start, char c, size_t len);
static char hex2int(const unsigned char* src);
static int isTLD(const struct phishcheck* pchk,const char* str,int len);
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

/* make a copy of the string between start -> end*/
static int string_assign_dup(struct string* dest,const char* start,const char* end)
{
	char*	    ret  = cli_malloc(end-start+1);
	if(!ret)
		return CL_EMEM;
	strncpy(ret,start,end-start);
	ret[end-start]='\0';

	string_free(dest);
	dest->data=ret;
	dest->refcount=1;
	dest->ref=NULL;
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
	
#ifdef	C_WINDOWS
		cli_errmsg("Phishcheck: Error in compiling regex, disabling phishing checks\n");
#else
		size_t buflen =	cli_regerror(rc,preg,NULL,0);
		char *errbuf = cli_malloc(buflen);
		
		if(errbuf) {
			cli_regerror(rc,preg,errbuf,buflen);
			cli_errmsg("Phishcheck: Error in compiling regex:%s\nDisabling phishing checks\n",errbuf);
			free(errbuf);
		} else
			cli_errmsg("Phishcheck: Error in compiling regex, disabling phishing checks. Additionally an Out-of-memory error was encountered while generating a detailed error message\n");
#endif
		return 1;
	}
	return CL_SUCCESS;
}

/* allocates memory */
static int get_host(const struct phishcheck* s,const char* URL,int isReal,int* phishy,const char **hstart, const char **hend)
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
			rc = tld ? isTLD(s,tld,tld-realhost-1) : 0;
			if(rc < 0)
				return rc;
			if(rc)
				*phishy |= PHISHY_USERNAME_IN_URL;/* if the url contains a username that is there just to fool people,
			     					     like http://www.ebay.com@somevilplace.someevildomain.com/ */
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

static int isCountryCode(const struct phishcheck* s,const char* str)
{
	return str ? !cli_regexec(&s->preg_cctld,str,0,NULL,0) : 0;
}

static int isTLD(const struct phishcheck* pchk,const char* str,int len)
{
	if (!str)
		return 0;
	else {
		char*	s  = cli_malloc(len+1);
		int rc;

		if(!s)
			return CL_EMEM;
		strncpy(s,str,len);
		s[len]='\0';
		rc = !cli_regexec(&pchk->preg_tld,s,0,NULL,0);
		free(s);
		return rc ? 1 : 0;
	}
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

static void get_domain(const struct phishcheck* pchk,struct string* dest,struct string* host)
{
	char* domain;
	char* tld = strrchr(host->data,'.');
	if(!tld) {
		cli_dbgmsg("Phishcheck: Encountered a host without a tld? (%s)\n",host->data);
		string_assign(dest,host);
		return;
	}
	if(isCountryCode(pchk,tld+1)) {
		const char* countrycode = tld+1;
		tld = rfind(host->data,'.',tld-host->data-1);
		if(!tld) {
			cli_dbgmsg("Phishcheck: Weird, a name with only 2 levels (%s)\n",
				host->data);
			string_assign(dest,host);
			return;
		}
		if(!isTLD(pchk,tld+1,countrycode-tld-1)) {
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
	char *sbegin = *begin;
	const char *str_end = *end;

	if(str_end <= sbegin)
		return;

	if(strlen(sbegin) <= 2)
		return;

	/* convert leading %xx*/
	if (sbegin[0] == '%') {
		sbegin[2] = hex2int((unsigned char*)sbegin+1);
		sbegin += 2;
	}
	*begin = sbegin++;
	while(sbegin+3 < str_end) {
		while(sbegin+3<str_end && sbegin[0]=='%') {
			const char* src = sbegin+3;
			*sbegin = hex2int((unsigned char*)sbegin+1);
			/* move string */
			memmove(sbegin+1,src,str_end-src+1);
			str_end -= 2;
		}
		sbegin++;
	}
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
 * http:/ /mail.yahoo.com
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
	while(!isalnum(sbegin[0]) && sbegin <= send) sbegin++;
	while(!isalnum(send[0]) && send >= sbegin) send--;
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
	/*TODO: convert \ to /, and stuff like that*/
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
		/* some broken MUAs put > in the href, and then
		 * we get a false positive, so remove them */
		str_replace(begin,end,'<',' ');
		str_replace(begin,end,'>',' ');
		str_replace(begin,end,'\"',' ');
		str_replace(begin,end,';',' ');
		str_strip(&begin,&end,lt,lt_len);
		str_strip(&begin,&end,gt,gt_len);
		/* convert hostname to lowercase, but only hostname! */
		host_begin = strchr(begin,':');
		while(host_begin && host_begin[1]=='/') host_begin++;
		if(!host_begin) host_begin=begin;
		else host_begin++;
		host_len = strcspn(host_begin,"/?");
		str_make_lowercase(host_begin,host_len);
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
			if (( rc = string_assign_dup(URL,begin,end+1) )) {
				return rc;
			}
		}
		/*cli_dbgmsg("%p::%s\n",URL->data,URL->data);*/
	}
	return 0;
}


/* -------end runtime disable---------*/
static int found_possibly_unwanted(cli_ctx* ctx)
{
	ctx->found_possibly_unwanted = 1;
	cli_dbgmsg("Phishcheck: found Possibly Unwanted: %s\n",*ctx->virname);
	return CL_CLEAN;
}

int phishingScan(message* m,const char* dir,cli_ctx* ctx,tag_arguments_t* hrefs)
{
	int i;
	struct phishcheck* pchk = (struct phishcheck*) ctx->engine->phishcheck;
	/* check for status of whitelist fatal error, etc. */
	if(!pchk || pchk->is_disabled)
		return CL_CLEAN;

	if(!ctx->found_possibly_unwanted)
		*ctx->virname=NULL;
	for(i=0;i<hrefs->count;i++)
		if(hrefs->contents[i]) {
			struct url_check urls;
			enum phish_status rc;
			urls.always_check_flags = DOMAINLIST_REQUIRED;/* required to work correctly */
			urls.flags	 = strncmp((char*)hrefs->tag[i],href_text,href_text_len)? (CL_PHISH_ALL_CHECKS&~CHECK_SSL): CL_PHISH_ALL_CHECKS;
			urls.link_type   = 0;
			if(!strncmp((char*)hrefs->tag[i],src_text,src_text_len)) {
				if (!(urls.flags&CHECK_IMG_URL))
				continue;
				urls.link_type |= LINKTYPE_IMAGE; 
			}
			if (ctx->options&CL_SCAN_PHISHING_DOMAINLIST)
				urls.flags |= DOMAINLIST_REQUIRED;
			if (ctx->options & CL_SCAN_PHISHING_BLOCKSSL) {
				urls.always_check_flags |= CHECK_SSL;
			}
			if (ctx->options & CL_SCAN_PHISHING_BLOCKCLOAK) {
				urls.always_check_flags |= CHECK_CLOAKING;
			}
			string_init_c(&urls.realLink,(char*)hrefs->value[i]);
			string_init_c(&urls.displayLink,(char*)blobGetData(hrefs->contents[i]));
			string_init_c(&urls.pre_fixup.pre_displayLink, NULL);
			if (urls.displayLink.data[blobGetDataSize(hrefs->contents[i])-1]) {
				cli_warnmsg("urls.displayLink.data[...]");
				return CL_CLEAN;
			}

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
					case CL_PHISH_CLEANUP_OK:
					case CL_PHISH_HOST_OK:
					case CL_PHISH_DOMAIN_OK:
					case CL_PHISH_REDIR_OK:
					case CL_PHISH_HOST_REDIR_OK:
					case CL_PHISH_DOMAIN_REDIR_OK:
					case CL_PHISH_HOST_REVERSE_OK:
					case CL_PHISH_DOMAIN_REVERSE_OK:
					case CL_PHISH_WHITELISTED:
					case CL_PHISH_HOST_WHITELISTED:
					case CL_PHISH_MAILTO_OK:
					case CL_PHISH_TEXTURL:
					case CL_PHISH_HOST_NOT_LISTED:
					case CL_PHISH_CLEAN_CID:
						continue;
/*						break;*/
					case CL_PHISH_HEX_URL:
						*ctx->virname="Phishing.Heuristics.Email.HexURL";
						return found_possibly_unwanted(ctx);
/*						break;*/
					case CL_PHISH_NUMERIC_IP:
						*ctx->virname="Phishing.Heuristics.Email.Cloaked.NumericIP";
						return found_possibly_unwanted(ctx);
					case CL_PHISH_CLOAKED_NULL:
						*ctx->virname="Phishing.Heuristics.Email.Cloaked.Null";/*http://www.real.com%01%00@www.evil.com*/
						return found_possibly_unwanted(ctx);
					case CL_PHISH_SSL_SPOOF:
						*ctx->virname="Phishing.Heuristics.Email.SSL-Spoof";
						return found_possibly_unwanted(ctx);
					case CL_PHISH_CLOAKED_UIU:
						*ctx->virname="Phishing.Heuristics.Email.Cloaked.Username";/*http://www.ebay.com@www.evil.com*/
						return found_possibly_unwanted(ctx);
					case CL_PHISH_NOMATCH:
					default:
						*ctx->virname="Phishing.Heuristics.Email.SpoofedDomain";
						return found_possibly_unwanted(ctx);
				}
		}
		else
			if(strcmp((char*)hrefs->tag[i],"href"))
					cli_dbgmsg("Phishcheck: href with no contents?\n");
	return CL_CLEAN;
}

static char* str_compose(const char* a,const char* b,const char* c)
{
	const size_t a_len = strlen(a);
	const size_t b_len = strlen(b);
	const size_t c_len = strlen(c);
	const size_t r_len = a_len+b_len+c_len+1;
	char* concated = cli_malloc(r_len);
	if(!concated)
		return NULL;
	strncpy(concated,a,a_len);
	strncpy(concated+a_len,b,b_len);
	strncpy(concated+a_len+b_len,c,c_len);
	concated[r_len-1]='\0';
	return concated;
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
	char *url_regex, *realurl_regex;
	struct phishcheck* pchk;
	if(!engine->phishcheck) {
		pchk = engine->phishcheck = cli_malloc(sizeof(struct phishcheck));
		if(!pchk)
			return CL_EMEM;
		pchk->is_disabled = 1;
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

	if(build_regex(&pchk->preg_hexurl,cloaked_host_regex,1)) {
		free(pchk);
		engine->phishcheck = NULL;
		return CL_EFORMAT;
	}

	if(build_regex(&pchk->preg_cctld,cctld_regex,1)) {
		free(pchk);
		engine->phishcheck = NULL;
		return CL_EFORMAT;
	}
	if(build_regex(&pchk->preg_tld,tld_regex,1)) {
		free_regex(&pchk->preg_cctld);
		free(pchk);
		engine->phishcheck = NULL;
		return CL_EFORMAT;	
	}
	url_regex = str_compose("^ *(("URI_CHECK_PROTOCOLS")|("URI_fragmentaddress1,URI_fragmentaddress2,URI_fragmentaddress3")) *$");
	if(build_regex(&pchk->preg,url_regex,1)) {
		free_regex(&pchk->preg_cctld);
		free_regex(&pchk->preg_tld);
		free(url_regex);
		free(pchk);
		engine->phishcheck = NULL;
		return CL_EFORMAT;
	}
	free(url_regex);
	realurl_regex = str_compose("^ *(("URI_CHECK_PROTOCOLS")|("URI_path1,URI_fragmentaddress2,URI_fragmentaddress3")) *$");
	if(build_regex(&pchk->preg_realurl, realurl_regex,1)) {
		free_regex(&pchk->preg_cctld);
		free_regex(&pchk->preg_tld);
		free_regex(&pchk->preg);
		free(url_regex);
		free(realurl_regex);
		free(pchk);
		engine->phishcheck = NULL;
		return CL_EFORMAT;
	}
	free(realurl_regex);
	if(build_regex(&pchk->preg_numeric,numeric_url_regex,1)) {
		free_regex(&pchk->preg_cctld);
		free_regex(&pchk->preg_tld);
		free_regex(&pchk->preg);
		free_regex(&pchk->preg_realurl);
		free(pchk);
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
		free_regex(&pchk->preg);
		free_regex(&pchk->preg_hexurl);
		free_regex(&pchk->preg_cctld);
		free_regex(&pchk->preg_tld);
		free_regex(&pchk->preg_numeric);
		free_regex(&pchk->preg_realurl);
		pchk->is_disabled = 1;
	}
	whitelist_done(engine);
	domainlist_done(engine);
	if(pchk) {
		cli_dbgmsg("Freeing phishcheck struct\n");
		free(pchk);
		engine->phishcheck = NULL;
	}		
	cli_dbgmsg("Phishcheck cleaned up\n");
}

/*
 * Only those URLs are identified as URLs for which phishing detection can be performed.
 */
static int isURL(const struct phishcheck* pchk,const char* URL)
{
	return URL ? !cli_regexec(&pchk->preg,URL,0,NULL,0) : 0;
}

/*
 * Check if this is a real URL, which basically means to check if it has a known URL scheme (http,https,ftp).
 * This prevents false positives with outbind:// and blocked:: links.
 */
static int isRealURL(const struct phishcheck* pchk,const char* URL)
{
	return URL ? !cli_regexec(&pchk->preg_realurl,URL,0,NULL,0) : 0;
}

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
			return CL_PHISH_CLEANUP_OK;
	}
	return CL_PHISH_NODECISION;
}

static int url_get_host(const struct phishcheck* pchk, struct url_check* url,struct url_check* host_url,int isReal,int* phishy)
{
	const char *start, *end;
	struct string* host = isReal ? &host_url->realLink : &host_url->displayLink;
	const char* URL = isReal ? url->realLink.data : url->displayLink.data;
	int rc;
	if ((rc = get_host(pchk, URL, isReal, phishy, &start, &end))) {
		return rc;
	}
	if(!start || !end) {
		string_assign_null(host);
	}
	else {
		if(( rc = string_assign_dup(host,start,end) ))
			return rc;
	}
	cli_dbgmsg("Phishcheck:host:%s\n", host->data);
	if(!isReal) {
		url->pre_fixup.host_start = start - URL;
		url->pre_fixup.host_end = end - URL;
	}
	if(!host->data)
		return CL_PHISH_CLEANUP_OK;
	if(*phishy&REAL_IS_MAILTO)
		return CL_PHISH_MAILTO_OK;
	if(strchr(host->data,' ')) {
		string_free(host);
		return CL_PHISH_TEXTURL;
	}
	if(url->flags&CHECK_CLOAKING && !cli_regexec(&pchk->preg_hexurl,host->data,0,NULL,0)) {
		/* uses a regex here, so that we don't accidentally block 0xacab.net style hosts */
		string_free(host);
		return CL_PHISH_HEX_URL;
	}
	if(isReal && host->data[0]=='\0')
		return CL_PHISH_CLEAN;/* link without domain, such as: href="/isapi.dll?... */
	if(isNumeric(host->data)) {
		*phishy |= PHISHY_NUMERIC_IP;
	}
	return CL_PHISH_NODECISION;
}

static void url_get_domain(const struct phishcheck* pchk, struct url_check* url,struct url_check* domains)
{
	get_domain(pchk, &domains->realLink, &url->realLink);
	get_domain(pchk, &domains->displayLink, &url->displayLink);
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

static int isEncoded(const char* url)
{
	const char* start=url;
	size_t cnt=0;
	do{
		cnt++;
		start=strstr(start,"&#");
		if(start)
			start=strstr(start,";");
	} while(start);
	return (cnt-1 >strlen(url)*7/10);/*more than 70% made up of &#;*/
}

static int whitelist_check(const struct cl_engine* engine,struct url_check* urls,int hostOnly)
{
	return whitelist_match(engine,urls->realLink.data,urls->displayLink.data,hostOnly);
}

static int isPhishing(enum phish_status rc)
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
/* urls can't contain null pointer, caller must ensure this */
static enum phish_status phishingCheck(const struct cl_engine* engine,struct url_check* urls)
{
	struct url_check host_url;
	enum phish_status rc=CL_PHISH_NODECISION;
	int phishy=0;
	const struct phishcheck* pchk = (const struct phishcheck*) engine->phishcheck;

	if(!urls->realLink.data)
		return CL_PHISH_CLEAN;

	cli_dbgmsg("Phishcheck:Checking url %s->%s\n", urls->realLink.data,
		urls->displayLink.data);

	if(!strcmp(urls->realLink.data,urls->displayLink.data))
		return CL_PHISH_CLEAN;/* displayed and real URL are identical -> clean */

	if((rc = cleanupURLs(urls))) {
		if(isPhishing(rc))/* not allowed to decide this is phishing */
			return CL_PHISH_CLEAN;
		return rc;/* URLs identical after cleanup */
	}

	if(whitelist_check(engine,urls,0))
		return CL_PHISH_WHITELISTED;/* if url is whitelist don't perform further checks */

	if((!isURL(pchk, urls->displayLink.data) || !isRealURL(pchk, urls->realLink.data) )&&
			( (phishy&PHISHY_NUMERIC_IP && !isNumericURL(pchk, urls->displayLink.data)) ||
			  !(phishy&PHISHY_NUMERIC_IP))) {
		cli_dbgmsg("Displayed 'url' is not url:%s\n",urls->displayLink.data);
		return CL_PHISH_TEXTURL;
	}

	if(urls->flags&DOMAINLIST_REQUIRED && domainlist_match(engine,urls->realLink.data,urls->displayLink.data,NULL,0,&urls->flags))
		phishy |= DOMAIN_LISTED;
	else {
		/* although entire url is not listed, the host might be,
		 * so defer phishing decisions till we know if host is listed*/
	}

	
	url_check_init(&host_url);

	if((rc = url_get_host(pchk, urls,&host_url,DOMAIN_DISPLAY,&phishy))) {
		free_if_needed(&host_url);
		if(isPhishing(rc))
			return CL_PHISH_CLEAN;
		return rc;
	}


	if(urls->flags&DOMAINLIST_REQUIRED) {
		if(!(phishy&DOMAIN_LISTED)) {
			if(domainlist_match(engine,host_url.displayLink.data,host_url.realLink.data,&urls->pre_fixup,1,&urls->flags))
				phishy |= DOMAIN_LISTED;
			else {
			}
		}
	}

	/* link type filtering must occur after last domainlist_match */
	if(urls->link_type & LINKTYPE_IMAGE && !(urls->flags&CHECK_IMG_URL))
		return CL_PHISH_HOST_NOT_LISTED;/* its listed, but this link type is filtered */

	if(urls->flags & DOMAINLIST_REQUIRED && !(phishy & DOMAIN_LISTED) ) {
		urls->flags &= urls->always_check_flags;
		if(!urls->flags) {
				free_if_needed(&host_url);
				return CL_PHISH_HOST_NOT_LISTED;
			}
		}

	if(urls->flags&CHECK_CLOAKING) {
		/*Checks if URL is cloaked.
		Should we check if it contains another http://, https://?
		No because we might get false positives from redirect services.*/
		if(strchr(urls->realLink.data,0x1)) {
			free_if_needed(&host_url);
			return CL_PHISH_CLOAKED_NULL;
		}
		if(isEncoded(urls->displayLink.data)) {
			free_if_needed(&host_url);
			return CL_PHISH_HEX_URL;
		}
	}


	if(urls->displayLink.data[0]=='\0') {
		free_if_needed(&host_url);
		return CL_PHISH_CLEAN;
	}

	if(urls->flags&CHECK_SSL && isSSL(urls->displayLink.data) && !isSSL(urls->realLink.data)) {
		free_if_needed(&host_url);
		return CL_PHISH_SSL_SPOOF;
	}

	if(!urls->flags&CHECK_CLOAKING && urls->flags & DOMAINLIST_REQUIRED && !(phishy&DOMAIN_LISTED) ) {
		free_if_needed(&host_url);
		return CL_PHISH_HOST_NOT_LISTED;
	}

	if((rc = url_get_host(pchk, urls,&host_url,DOMAIN_REAL,&phishy)))
	{
		free_if_needed(&host_url);
		return rc;
	}

	if(urls->flags&DOMAINLIST_REQUIRED && !(phishy&DOMAIN_LISTED)) {
		free_if_needed(&host_url);
		return CL_PHISH_HOST_NOT_LISTED;
	}

	if(whitelist_check(engine,&host_url,1)) {
		free_if_needed(&host_url);
		return CL_PHISH_HOST_WHITELISTED;
	}


	if(urls->flags&HOST_SUFFICIENT) {
		if(!strcmp(urls->realLink.data,urls->displayLink.data)) {
			free_if_needed(&host_url);
			return CL_PHISH_HOST_OK;
		}


		if(urls->flags&DOMAIN_SUFFICIENT) {
			struct url_check domain_url;
			url_check_init(&domain_url);
			url_get_domain(pchk, &host_url,&domain_url);
			if(!strcmp(domain_url.realLink.data,domain_url.displayLink.data)) {
				free_if_needed(&host_url);
				free_if_needed(&domain_url);
				return CL_PHISH_DOMAIN_OK;
			}
			free_if_needed(&domain_url);
		}

		free_if_needed(&host_url);
	}/*HOST_SUFFICIENT*/
	/*we failed to find a reason why the 2 URLs are different, this is definitely phishing*/
	if(urls->flags&DOMAINLIST_REQUIRED && !(phishy&DOMAIN_LISTED))
		return CL_PHISH_HOST_NOT_LISTED;
	return phishy_map(phishy,CL_PHISH_NOMATCH);
}

static const char* phishing_ret_toString(enum phish_status rc)
{
	switch(rc) {
		case CL_PHISH_CLEAN:
			return "Clean";
		case CL_PHISH_CLEANUP_OK:
			return "URLs match after cleanup";
		case CL_PHISH_WHITELISTED:
			return "URL is whitelisted";
		case CL_PHISH_HOST_WHITELISTED:
			return "host part of URL is whitelist";
		case CL_PHISH_HOST_OK:
			return "Hosts match";
		case CL_PHISH_DOMAIN_OK:
			return "Domains match";
		case CL_PHISH_REDIR_OK:
			return "After redirecting realURL, they match";
		case CL_PHISH_HOST_REDIR_OK:
			return "After redirecting realURL, hosts match";
		case CL_PHISH_DOMAIN_REDIR_OK:
			return "After redirecting the domains match";
		case CL_PHISH_MAILTO_OK:
			return "URL is mailto";
		case CL_PHISH_NUMERIC_IP:
			return "IP address encountered in hostname";
		case CL_PHISH_TEXTURL:
			return "Displayed link is not an URL, can't check if phishing or not";
		case CL_PHISH_CLOAKED_NULL:
			return "Link URL is cloaked (null byte %00)";
		case CL_PHISH_CLOAKED_UIU:
			return "Link URL contains username, and real<->displayed hosts don't match.";
			/*username is a legit domain, and after the @ comes the evil one*/
		case CL_PHISH_SSL_SPOOF:
			return "Visible links is SSL, real link is not";
		case CL_PHISH_NOMATCH:
			return "URLs are way too different";
		case CL_PHISH_HOST_NOT_LISTED:
			return "Host not listed in .pdb -> not checked";
		case CL_PHISH_CLEAN_CID:
			return "Embedded image in mail -> clean";
		case CL_PHISH_HEX_URL:
			return "Embedded hex urls";
		default:
			return "Unknown return code";
	}
}


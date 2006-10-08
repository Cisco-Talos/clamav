/*
 *  Detect phishing, based on URL spoofing detection.
 *
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
 *
 *  $Log: phishcheck.c,v $
 *  Revision 1.12  2006/10/08 18:55:15  tkojm
 *  fix crash in phishing code on database reload (Edvin Torok)
 *
 *  Revision 1.11  2006/10/07 11:00:46  tkojm
 *  make the experimental anti-phishing code more thread safe
 *
 *  Revision 1.10  2006/09/27 14:23:14  njh
 *  Ported to VS2005
 *
 *  Revision 1.9  2006/09/26 18:55:36  njh
 *  Fixed portability issues
 *
 *  Revision 1.8  2006/09/19 16:52:09  njh
 *  Fixed inconsistency between phishcheck.c and phishcheck.h
 *
 *  Revision 1.7  2006/09/18 17:10:07  njh
 *  Fix compilation error on Solaris 10
 *
 *  Revision 1.6  2006/09/16 15:49:27  acab
 *  phishing: fixed bugs and updated docs
 *
 *  Revision 1.5  2006/09/16 05:59:14  njh
 *  Fixed compiler warning
 *
 *  Revision 1.4  2006/09/16 05:39:54  njh
 *  Tidied print statement
 *
 *  Revision 1.3  2006/09/15 16:27:50  njh
 *  Better way to find string length in str_strip
 *
 *  Revision 1.2  2006/09/14 08:59:37  njh
 *  Fixed some NULL pointers
 *
 *  Revision 1.1  2006/09/12 19:38:39  acab
 *  Phishing module merge - libclamav
 *
 *  Revision 1.28  2006/09/09 09:49:27  edwin
 *  Fix Solaris compilation problem
 *
 *  Revision 1.27  2006/08/28 08:43:06  edwin
 *  Fixed a few minor leaks.
 *  Valgrind now says:"All heap blocks were freed -- no leaks are possible"
 *
 *  Revision 1.26  2006/08/20 21:18:11  edwin
 *  Added the script used to generate iana_tld.sh
 *  Added checks for phish_domaincheck_db
 *  Added phishing module design document from wiki (as discussed with aCaB).
 *  Updated .wdb/.pdb format documentation (in regex_list.c)
 *  Fixed some memory leaks in regex_list.c
 *  IOW: cleanups before the deadline.
 *  I consider my module to be ready for evaluation now.
 *
 *  Revision 1.25  2006/08/19 21:08:47  edwin
 *  Fixed:Forgot to add form tag handling when it contains images.
 *  Various fixes to get rid of gcc warnings.
 *
 *  Revision 1.24  2006/08/19 13:30:34  edwin
 *  iana_tld.h was missing from the list of header files.
 *  commentedout network code (unused currently)
 *
 *  Revision 1.23  2006/08/17 20:31:43  edwin
 *  Disable extracting hrefs from mails in mbox, if: we aren't scanning for phish, and mailfollowurls is off.
 *  Fix a still reachable leak. Remove unneeded build_regex_list export.
 *
 *  Revision 1.22  2006/08/12 14:35:34  edwin
 *  Fix some compiler warnings.
 *  Fix an assertion failure in regex_list.
 *  Interpret display links that start with http|https|ftp, always as an URL.
 *
 *  Revision 1.21  2006/08/06 20:27:07  edwin
 *  New option to enable phish scan for all domains (disabled by default).
 *  You will now have to run clamscan --phish-scan-alldomains to have any phishes detected.
 *  Updated phishcheck control flow to better incorporate the domainlist.
 *  Updated manpage with new options.
 *
 *  TODO:there is a still-reachable leak in regex_list.c
 *
 *  Revision 1.20  2006/08/01 20:19:14  edwin
 *  Integrate domainlist check into phishcheck. Warning: enabled by default.
 *  Regex bracket handling update.
 *  Better regex paranthesized & alternate expression handling.
 *

case CL_PHISH_HOST_NOT_LISTED:
 return "Host not listed in .pdb -> not checked";*  Revision 1.19  2006/07/31 20:12:30  edwin
 *  Preliminary support for domain databases (domains to check by phishmodule)
 *  Better memory allocation failure handling in regex_list
 *
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifdef CL_EXPERIMENTAL

#ifndef CL_DEBUG
#define NDEBUG
#endif

#ifdef CL_THREAD_SAFE
#ifndef _REENTRANT
#define _REENTRANT
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#ifdef	HAVE_STRINGS_H
#include <strings.h>
#endif
#include <ctype.h>
#include <limits.h>
#include <clamav.h>
#ifndef	C_WINDOWS
#include <netdb.h>
#include <netinet/in.h>
#endif

#if defined(HAVE_READDIR_R_3) || defined(HAVE_READDIR_R_2)
#include <stddef.h>
#endif

#include <sys/types.h>
#ifndef	C_WINDOWS
#include <sys/socket.h>
#endif
#ifdef	HAVE_REGEX_H
#include <regex.h>
#endif

#include <pthread.h>

#include "others.h"
#include "defaults.h"
#include "str.h"
#include "filetypes.h"
#include "mbox.h"
#include "htmlnorm.h"
#include "phishcheck.h"
#include "phish_whitelist.h"
#include "phish_domaincheck_db.h"
#include "iana_tld.h"

#define DOMAIN_REAL 1
#define DOMAIN_DISPLAY 0

#define PHISHY_USERNAME_IN_URL 1
#define PHISHY_NUMERIC_IP      2
#define REAL_IS_MAILTO		 4
/* this is just a flag, so that the displayed url will be parsed as mailto too, for example
 * <a href='mailto:somebody@yahoo.com'>to:somebody@yahoo.com</a>*/
#define DOMAIN_LISTED		 8
#define PHISHY_CLOAKED_NULL	16
#define PHISHY_HEX_URL		32


/*
* Phishing design documentation,
(initially written at http://wiki.clamav.net/index.php/phishing_design as discussed with aCaB)

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

11. Skip cid: displayedLink urls (images embedded in mails).

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
static char empty_string[]="";

static	inline	void string_init_c(struct string* dest,char* data);
static	void	string_assign_null(struct string* dest);
static	char	*rfind(char *start, char c, size_t len);

void url_check_init(struct url_check* urls)
{
	urls->realLink.refcount=0;
	urls->realLink.data=empty_string;
	urls->realLink.ref=NULL;
	urls->displayLink.refcount=0;
	urls->displayLink.data=empty_string;
	urls->displayLink.ref=NULL;
}

/* string reference counting implementation,
 * so that: we don't have to keep in mind who allocated what, and when needs to be freed,
 * and thus we won't leak memory*/

void string_free(struct string* str)
{
	for(;;){
		str->refcount--;
		if(!str->refcount) {
			if(str->ref)/* don't free, this is a portion of another string */
				str=str->ref;/* try to free that one*/
			else {
				free(str->data);
				break;
			}
		}
		else break;
	}
}

/* always use the string_assign when assigning to a string, this makes sure the old one's refcount is decremented*/
void string_assign(struct string* dest,struct string* src)
{
	string_free(dest);
	src->refcount++;
	dest->data=src->data;
	dest->refcount=1;
	dest->ref=src;
}

/* data will be freed when string freed */
void string_assign_c(struct string* dest,char* data)
{
	string_free(dest);
	dest->data=data;
	dest->ref=NULL;
	dest->refcount=1;
}

/* same as above, but it doesn't free old string, use only for initialization
 * Doesn't allow NULL pointers, they are replaced by pointer to empty string
 * */
static inline void string_init_c(struct string* dest,char* data)
{
	dest->refcount = 1;
	dest->data = data ? data : empty_string;
	dest->ref = NULL;
}

/* make a copy of the string between start -> end*/
void string_assign_dup(struct string* dest,const char* start,const char* end)
{
	char*	    ret  = cli_malloc(end-start+1);
	strncpy(ret,start,end-start);
	ret[end-start]='\0';

	string_free(dest);
	dest->data=ret;
	dest->refcount=1;
	dest->ref=NULL;
}

static inline void string_assign_null(struct string* dest)
{
	string_free(dest);
	dest->data=empty_string;
	dest->refcount=-1;/* don't free it! */
	dest->ref=NULL;
}

/* this string uses portion of another string*/
void string_assign_ref(struct string* dest,struct string* ref,char* data)
{
	string_free(dest);
	ref->refcount++;
	dest->data=data;
	dest->refcount=1;
	dest->ref=ref;
}

void free_if_needed(struct url_check* url)
{
	string_free(&url->realLink);
	string_free(&url->displayLink);
}


static int build_regex(regex_t** preg,const char* regex,int nosub)
{
	int rc;
	*preg = cli_malloc(sizeof(**preg));
	cli_dbgmsg("Compiling regex:%s\n",regex);
	rc = regcomp(*preg,regex,REG_EXTENDED|REG_ICASE|(nosub ? REG_NOSUB :0));
	if(rc) {
	
#ifdef	C_WINDOWS
		cli_errmsg("Error in compiling regex, disabling phishing checks\n");
#else
		size_t buflen =	regerror(rc,*preg,NULL,0);
		char *errbuf = cli_malloc(buflen);
		
		if(errbuf) {
			regerror(rc,*preg,errbuf,buflen);
			cli_errmsg("Error in compiling regex:%s\nDisabling phishing checks\n",errbuf);
			free(errbuf);
		} else
			cli_errmsg("Error in compiling regex, disabling phishing checks\n");
#endif
		free(*preg);
		*preg=NULL;
		phish_disable("problem in compiling regex");
		return 1;
	}
	return 0;
}


/*static regex_t* host_preg = NULL;
static const char* host_regex="cid:.+|mailto:(.+)|([[:alpha:]]+://)?(([^:/?]+@)+([^:/?]+)([:/?].+)?|([^@:/?]+)([:/?].+)?)"; <- this is slower than the function below
*/
/* allocates memory */
void get_host(struct string* dest,const char* URL,int isReal,int* phishy)
{
	const char mailto[] = "mailto:";
	int ismailto = 0;
	const char* start;
	const char* end=NULL;
	if(!URL) {
		string_assign_null(dest);
		return;
	}
	start = strstr(URL,"://");
	if(!start) {
		if(!strncmp(URL,mailto,sizeof(mailto)-1)) {
			start = URL + sizeof(mailto)-1;
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
/*			if(!strncmp(URL,"cid:",4)) {handled in phishcheck
				string_assign_null(dest);
				return;* cid: image, nothing to verify
			}
*/
			start=URL;/*URL without protocol*/
			if(isReal)
				cli_dbgmsg("PH:Real URL without protocol:%s\n",URL);
			else ismailto=2;/*no-protocol, might be mailto, @ is no problem*/
		}
	}
	else
		start += 3;	/* :// */

	if(!ismailto || !isReal) {
		const char *realhost;

		do {
			end  = start + strcspn(start,":/?");
			realhost = strchr(start,'@');

			if(realhost == NULL)
				break;

			if(start!=end && realhost>end)
				/*don't check beyond end of hostname*/
				realhost = NULL;

			if(realhost) {
				const char* tld = strrchr(realhost,'.');
				if(tld && isTLD(tld,tld-realhost-1))
					*phishy |= PHISHY_USERNAME_IN_URL;/* if the url contains a username that is there just to fool people,
					like http://www.ebay.com@somevilplace.someevildomain.com/ */
				start=realhost+1;/*skip the username*/
			}
		} while(realhost);/*skip over multiple @ characters, text following last @ character is the real host*/
	}
	else
	if (ismailto && isReal)
		*phishy |= REAL_IS_MAILTO;

	if(!end) {
		end  = start+strcspn(start,":/?");/*especially important for mailto:somebody@yahoo.com?subject=...*/
		if(!end)
			end  = start + strlen(start);
	}

	string_assign_dup(dest,start,end);
}

static regex_t* preg = NULL;
static regex_t* preg_tld = NULL;
static regex_t* preg_cctld = NULL;
static regex_t* preg_numeric = NULL;

static const char tld_regex[] = "^"iana_tld"$";
static const char cctld_regex[] = "^"iana_cctld"$";

int isCountryCode(const char* str)
{
	return str ? !regexec(preg_cctld,str,0,NULL,0) : 0;
}

int isTLD(const char* str,int len)
{
	if (!str)
		return 0;
	else {
		char*	s  = cli_malloc(len+1);
		int rc;
		strncpy(s,str,len);
		s[len]='\0';
		rc = !regexec(preg_tld,s,0,NULL,0);
		free(s);
		return rc;
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

void get_domain(struct string* dest,struct string* host)
{
	char* domain;
	char* tld = strrchr(host->data,'.');
	if(!tld) {
		cli_dbgmsg("PH:What? A host without a tld? (%s)\n",host->data);
		string_assign(dest,host);
		return;
	}
	if(isCountryCode(tld+1)) {
		const char* countrycode=tld+1;
		tld = rfind(host->data,'.',tld-host->data-1);
		if(!tld) {
			cli_dbgmsg("PH:Weird, a name with only 2 levels (%s)\n",host);
			string_assign(dest,host);
			return;
		}
		if(!isTLD(tld+1,countrycode-tld-1)) {
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


/*
int ip_reverse(struct url_check* urls,int isReal)
{
	const char* host = isReal ? urls->realLink.data : urls->displayLink.data;
	struct hostent *he = gethostbyname (host);
	if (he)
	{
		char *addr = 0;
		switch (he->h_addrtype)
		{
			case AF_INET:
			  addr = inet_ntoa (*(struct in_addr *) he->h_addr);
			  break;
		}
		if (addr && strcmp (he->h_name, addr) == 0)
		{
			char *h_addr_copy = strdup (he->h_addr);
			if (h_addr_copy == NULL)
			    he = NULL;
			else
			{
			      he = gethostbyaddr (h_addr_copy, he->h_length, he->h_addrtype);
			      free (h_addr_copy);
			}
		}
	     if (he)
		string_assign_dup(isReal ? &urls->realLink : &urls->displayLink,he->h_name,he->h_name+strlen(he->h_name));
    }
    return 0;
}
* frees its argument, and allocates memory*
void reverse_lookup(struct url_check* url,int isReal)
{
	ip_reverse(url,isReal);
}
*/
int isNumeric(const char* host)
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

int isSSL(const char* URL)
{
	const char https[]="https://";
	return URL ? !strncmp(https,URL,sizeof(https)-1) : 0;
}



static inline char hex2int(const unsigned char* src);

/* deletes @what from the string @begin.
 * @what_len: length of @what, excluding the terminating \0 */
static void
str_hex_to_char(char **begin, const char **end)
{
	char *sbegin = *begin;
	const char *str_end = *end;

	assert(str_end>sbegin);

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

	if(begin == NULL)
		return;

	assert(str_end > sbegin);

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

static const char dotnet[] = ".net";
static const char adonet[] = "ado.net";
static const char aspnet[] = "asp.net";
static const char lt[]="&lt;";
static const char gt[]="&gt;";
static const size_t dotnet_len = sizeof(dotnet)-1;
static const size_t adonet_len = sizeof(adonet)-1;
static const size_t aspnet_len = sizeof(aspnet)-1;
static const size_t lt_len = sizeof(lt)-1;
static const size_t gt_len = sizeof(gt)-1;

/* replace every occurence of @c in @str with @r*/
static inline void str_replace(char* str,const char* end,char c,char r)
{
	for(;str<end;str++) {
		if(*str==c)
			*str=r;
	}
}
static inline void str_make_lowercase(char* str,size_t len)
{
	for(;len;str++,len--) {
		*str = tolower(*str);
	}
}

#define fix32(x) ((x)<32 ? 32 : (x))
static inline void clear_msb(char* begin)
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
 * Rule for adding .: if substring from right contains dot, then add dot,
 *	otherwise strip space
 *
 */
static inline void
str_fixup_spaces(char **begin, const char **end)
{
	char *space = strchr(*begin, ' ');

	if(space == NULL)
		return;

	/* strip any number of spaces after / */
	while((space > *begin) && (space[-1] == '/') && (space[0] == ' ') && (space < *end)) {
		memmove(space, space+1, *end-space+1);
		(*end)--;
	}

	for(space = rfind(*begin,' ',*end-*begin);space && space[0]!='.' && space<*end;space++)
		;
	if(space && space[0]=='.')
		str_replace(*begin,*end,' ','.');
	else
		str_strip(begin,end," ",1);
}

/* allocates memory */
void
cleanupURL(struct string *URL, int isReal)
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
		return;
	}

	end = begin + len - 1;
	/*cli_dbgmsg("%d %d\n", end-begin, len);*/
	if(begin >= end) {
		string_assign_null(URL);
		return;
	}
	while(isspace(*end))
		end--;
	/*TODO: convert \ to /, and stuff like that*/
	/* From mailscanner, my comments enclosed in {} */
	if(!strncmp(begin,dotnet,dotnet_len) || !strncmp(begin,adonet,adonet_len) || !strncmp(begin,aspnet,aspnet_len))
		string_assign_null(URL);
	else {
		size_t host_len;
		char* host_begin;
		str_replace(begin,end,'\\','/');
		str_strip(&begin,&end,"\"",1);
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
		str_fixup_spaces(&begin,&end);
		string_assign_dup(URL,begin,end+1);
		/*cli_dbgmsg("%p::%s\n",URL->data,URL->data);*/
	}
}

void get_redirected_URL(struct string* URL)
{
	/*TODO: see if URL redirects sowhere, if so, then follow
	returns redirected URL*/
}


/* ---- runtime disable ------*/
static int phish_disabled = 0;
static pthread_mutex_t phish_disabled_lock = PTHREAD_MUTEX_INITIALIZER;

void phish_disable(const char* reason)
{
	cli_warnmsg("Disabling phishing checks, reason:%s\n",reason);
	pthread_mutex_lock(&phish_disabled_lock);
		phish_disabled = 1;
	pthread_mutex_unlock(&phish_disabled_lock);
}

static inline int is_phish_disabled(const struct cl_engine* engine)
{
	int rc;
	if (!is_whitelist_ok(engine)) 
		phish_disable("whitelist is not ok");
	if (!is_domainlist_ok(engine))
		phish_disable("domainlist is not ok");
	pthread_mutex_lock(&phish_disabled_lock);
	rc = phish_disabled;
	pthread_mutex_unlock(&phish_disabled_lock);
	return rc;
}
/* -------end runtime disable---------*/

int phishingScan(message* m,const char* dir,cli_ctx* ctx,tag_arguments_t* hrefs)
{
	const char src_text[]="src";
	const char href_text[]="href";
	const size_t href_text_len = sizeof(href_text);
	const size_t src_text_len = sizeof(src_text);
	int i;
	if(is_phish_disabled(ctx->engine))
		return 0;

	*ctx->virname=NULL;
	for(i=0;i<hrefs->count;i++)
		if(hrefs->contents[i]) {
			struct url_check urls;
			enum phish_status rc;
			urls.flags	 = strncmp((char*)hrefs->tag[i],href_text,href_text_len)? (CL_PHISH_ALL_CHECKS&~CHECK_SSL): CL_PHISH_ALL_CHECKS;
			if (!(urls.flags&CHECK_IMG_URL) && !strncmp((char*)hrefs->tag[i],src_text,src_text_len))
				continue;
			if (ctx->options&CL_PHISH_NO_DOMAINLIST)
				urls.flags &= ~DOMAINLIST_REQUIRED;
			string_init_c(&urls.realLink,(char*)hrefs->value[i]);
/*			if(!hrefs->contents[i]->isClosed) {
				blobAddData(hrefs->contents[i],empty_string,1);
				blobClose(hrefs->contents[i]);
			}*/
			string_init_c(&urls.displayLink,(char*)blobGetData(hrefs->contents[i]));
			assert(!urls.displayLink.data[blobGetDataSize(hrefs->contents[i])-1]);
/*			assert(strlen(urls.displayLink.data) < blobGetDataSize(hrefs->contents[i]));*/
			urls.realLink.refcount=-1;
			urls.displayLink.refcount=-1;/*don't free these, caller will free*/
			if(strcmp((char*)hrefs->tag[i],"href")) {
				char *url;
				url = urls.realLink.data;
				urls.realLink.data = urls.displayLink.data;
				urls.displayLink.data = url;
			}

			rc = phishingCheck(ctx->engine,&urls);
			if(is_phish_disabled(ctx->engine))
				return 0;
			free_if_needed(&urls);
			cli_dbgmsg("Phishing scan result:%s\n",phishing_ret_toString(rc));
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
						*ctx->virname="Phishing.Email.HexURL";
						return CL_VIRUS;
/*						break;*/
					case CL_PHISH_NUMERIC_IP:
						*ctx->virname="Phishing.Email.Cloaked.NumericIP";
						return CL_VIRUS;
					case CL_PHISH_CLOAKED_NULL:
						*ctx->virname="Phishing.Email.Cloaked.Null";/*http://www.real.com%01%00@www.evil.com*/
						return CL_VIRUS;
					case CL_PHISH_SSL_SPOOF:
						*ctx->virname="Phishing.Email.SSL-Spoof";
						return CL_VIRUS;
					case CL_PHISH_CLOAKED_UIU:
						*ctx->virname="Phishing.Email.Cloaked.Username";/*http://www.ebay.com@www.evil.com*/
						return CL_VIRUS;
					case CL_PHISH_NOMATCH:
					default:
						*ctx->virname="Phishing.Email";
						return CL_VIRUS;
				}
		}
		else
			if(strcmp((char*)hrefs->tag[i],"href"))
					cli_dbgmsg("PH:href with no contents?\n");
	return 0;/*texturlfound?CL_VIRUS:0;*/
}

static char* str_compose(const char* a,const char* b,const char* c)
{
	const size_t a_len = strlen(a);
	const size_t b_len = strlen(b);
	const size_t c_len = strlen(c);
	const size_t r_len = a_len+b_len+c_len+1;
	char* concated = malloc(r_len);
	strncpy(concated,a,a_len);
	strncpy(concated+a_len,b,b_len);
	strncpy(concated+a_len+b_len,c,c_len);
	concated[r_len-1]='\0';
	return concated;
}

/*static const char* url_regex="^ *([[:alnum:]%_-]+:(//)?)?([[:alnum:]%_-]@)*[[:alnum:]%_-]+\\.([[:alnum:]%_-]+\\.)*[[:alnum:]_%-]+(/[[:alnum:];:@$=?&/.,%_-]+) *$";*/
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

#define URI_scheme URI_ialpha
#define URI_tld iana_tld
#define URI_path1 URI_xpalphas_nodot"\\.("URI_xpalphas_nodot"\\.)*"
#define URI_path2 URI_tld
#define URI_path3 "(/("URI_xpalphas"/?)*)?"

#define URI_search "("URI_xalphas"\\+)*"
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

#define URI_CHECK_PROTOCOLS "(http|https|ftp)://.+"

/*Warning: take care when modifying this regex, it has been tweaked, and tuned, just don't break it please.
 * there is fragmentaddress1, and 2  to work around the ISO limitation of 509 bytes max length for string constants*/
static const char numeric_url_regex[] = "^ *"URI_numeric_fragmentaddress" *$";
static char* url_regex = NULL;

static int hexinited=0;
static short int hextable[256];

static inline char hex2int(const unsigned char* src)
{
	assert(hexinited);
	return hextable[src[0]]<<4 | hextable[src[1]];
}

static void free_regex(regex_t** p)
{
	if(p) {
		if(*p) {
			regfree(*p);
			free(*p);
			*p=NULL;
		}
	}
}
/* --------non-thread-safe functions--------*/
static void init_hextable(void)
{
	unsigned char c;
	memset(hextable,0,256);
	for(c='0';c<='9';c++)
		hextable[c] = c-'0';
	for(c='a';c<='z';c++)
		hextable[c] = 10+c-'a';
	for(c='A';c<='Z';c++)
		hextable[c] = 10+c-'A';
	hexinited=1;
}

int phishing_init(engine)
{
	cli_dbgmsg("Initializing phishcheck module\n");
	setup_matcher_engine();
	if(build_regex(&preg_cctld,cctld_regex,1))
		return -1;
	if(build_regex(&preg_tld,tld_regex,1))
		return -1;	
	url_regex = str_compose("^ *("URI_fragmentaddress1,URI_fragmentaddress2,URI_fragmentaddress3"|"URI_CHECK_PROTOCOLS") *$");
	if(build_regex(&preg,url_regex,1))
		return -1;
	if(build_regex(&preg_numeric,numeric_url_regex,1))
		return -1;
	init_hextable();
	cli_dbgmsg("Phishcheck module initialized\n");
	return 0;
}


void phishing_done(struct cl_engine* engine)
{
	cli_dbgmsg("Cleaning up phishcheck\n");
	free_regex(&preg);
	free_regex(&preg_cctld);
	free_regex(&preg_tld);
	free_regex(&preg_numeric);
	if(url_regex) {
		free(url_regex);
		url_regex = NULL;
	}

	whitelist_done(engine);
	domainlist_done(engine);
	matcher_engine_done();
	cli_dbgmsg("Phishcheck cleaned up\n");
}

/* ---------------end of non-thread-safe function-----------*/
/*
 * Only those URLs are identified as URLs for which phishing detection can be performed.
 * This means that no attempt is made to properly recognize 'cid:' URLs
 */
int isURL(const char* URL)
{
	return URL ? !regexec(preg,URL,0,NULL,0) : 0;
}

int isNumericURL(const char* URL)
{
	return URL ? !regexec(preg_numeric,URL,0,NULL,0) : 0;
}

/* Cleans up @urls
 * If URLs are identical after cleanup it will return CL_PHISH_CLEANUP_OK.
 * */
enum phish_status cleanupURLs(struct url_check* urls)
{
	if(urls->flags&CLEANUP_URL) {
		cleanupURL(&urls->realLink,1);
		cleanupURL(&urls->displayLink,0);
		if(!urls->displayLink.data || !urls->realLink.data)
			return CL_PHISH_NODECISION;
		if(!strcmp(urls->realLink.data,urls->displayLink.data))
			return CL_PHISH_CLEANUP_OK;
	}
	return CL_PHISH_NODECISION;
}


enum phish_status url_get_host(struct url_check* url,struct url_check* host_url,int isReal,int* phishy)
{
	struct string* host = isReal ? &host_url->realLink : &host_url->displayLink;
	get_host(host,isReal ? url->realLink.data : url->displayLink.data, isReal,phishy);
	if(!host->data)
		return CL_PHISH_CLEANUP_OK;
	if(*phishy&REAL_IS_MAILTO)
		return CL_PHISH_MAILTO_OK;
	if(strchr(host->data,' ')) {
		string_free(host);
		return CL_PHISH_TEXTURL;
	}
	if(isReal && (!strncmp(host->data,"0x",2) || !strncmp(host->data,"0X",2))) {
		string_free(host);
		return CL_PHISH_HEX_URL;
	}
	if(isReal && host->data[0]=='\0')
		return CL_PHISH_CLEAN;/* link without domain, such as: href="/isapi.dll?... */
	if(isNumeric(host->data)) {
		*phishy |= PHISHY_NUMERIC_IP;
/*		if(url->flags&DO_REVERSE_LOOKUP)
			reverse_lookup(host_url,isReal);*/
	}
	return CL_PHISH_NODECISION;
}


void url_get_domain(struct url_check* url,struct url_check* domains)
{
	get_domain(&domains->realLink, &url->realLink);
	get_domain(&domains->displayLink, &url->displayLink);
	domains->flags	     = url->flags;
}

enum phish_status phishy_map(int phishy,enum phish_status fallback)
{
	if(phishy&PHISHY_USERNAME_IN_URL)
		return CL_PHISH_CLOAKED_UIU;
	else if(phishy&PHISHY_NUMERIC_IP)
		return CL_PHISH_NUMERIC_IP;
	else
		return fallback;
}

int isEncoded(const char* url)
{
	const char* start=url;
	size_t cnt=0;
	do{
		cnt++;
		/*last=start;*/
		start=strstr(start,"&#");
		if(start)
			start=strstr(start,";");
	} while(start);
	return (cnt-1 >strlen(url)*7/10);/*more than 70% made up of &#;*/
}



int whitelist_check(const struct cl_engine* engine,struct url_check* urls,int hostOnly)
{
	return whitelist_match(engine,urls->realLink.data,urls->displayLink.data,hostOnly);
}

/* urls can't contain null pointer, caller must ensure this */
enum phish_status phishingCheck(const struct cl_engine* engine,struct url_check* urls)
{
	struct url_check host_url;
	const char cid[] = "cid:";
	const size_t cid_len = sizeof(cid)-1;
	enum phish_status rc=CL_PHISH_NODECISION;
	int phishy=0;

	if(!urls->realLink.data)
		return CL_PHISH_CLEAN;

	cli_dbgmsg("PH:Checking url %s->%s\n", urls->realLink.data,
		urls->displayLink.data);

	if(!strcmp(urls->realLink.data,urls->displayLink.data))
		return CL_PHISH_CLEAN;/* displayed and real URL are identical -> clean */

	if((rc = cleanupURLs(urls))) {
		assert(!isPhishing(rc));/* not allowed to decide this is phishing */
		return rc;/* URLs identical after cleanup */
	}

	if(whitelist_check(engine,urls,0))
		return CL_PHISH_WHITELISTED;/* if url is whitelist don't perform further checks */

	if(urls->flags&DOMAINLIST_REQUIRED && domainlist_match(engine,urls->realLink.data,urls->displayLink.data,0,&urls->flags))
		phishy |= DOMAIN_LISTED;
	else {
		/* although entire url is not listed, the host might be,
		 * so defer phishing decisions till we know if host is listed*/
	}

	url_check_init(&host_url);

	if((rc = url_get_host(urls,&host_url,DOMAIN_DISPLAY,&phishy))) {
		free_if_needed(&host_url);
		assert(!isPhishing(rc));
		return rc;
	}

	if(whitelist_check(engine,&host_url,1)) {
		free_if_needed(&host_url);
		return CL_PHISH_HOST_WHITELISTED;
	}

	if(urls->flags&DOMAINLIST_REQUIRED) {
		if(!(phishy&DOMAIN_LISTED)) {
			if(domainlist_match(engine,urls->displayLink.data,urls->realLink.data,1,&urls->flags))
				phishy |= DOMAIN_LISTED;
			else {
				free_if_needed(&host_url);
				return CL_PHISH_HOST_NOT_LISTED;
			}
		}
	}

	if(urls->flags&CHECK_CLOAKING) {
		/*Checks if URL is cloaked.
		Should we check if it containts another http://, https://?
		No because we might get false positives from redirect services.*/
		if(strstr(urls->realLink.data,"%00")) {
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

	if((rc = url_get_host(urls,&host_url,DOMAIN_REAL,&phishy)))
	{
		free_if_needed(&host_url);
		return rc;
	}

	if(!strncmp(urls->displayLink.data,cid,cid_len))/* cid: image */{
		free_if_needed(&host_url);
		return CL_PHISH_CLEAN_CID;
	}

	if(!isURL(urls->displayLink.data) &&
			( (phishy&PHISHY_NUMERIC_IP && !isNumericURL(urls->displayLink.data)) ||
			  !(phishy&PHISHY_NUMERIC_IP))) {
		free_if_needed(&host_url);
		return CL_PHISH_TEXTURL;
	}

	if(urls->flags&HOST_SUFFICIENT) {
		if(!strcmp(urls->realLink.data,urls->displayLink.data)) {
			free_if_needed(&host_url);
			return CL_PHISH_HOST_OK;
		}


		if(urls->flags&DOMAIN_SUFFICIENT) {
			struct url_check domain_url;
			url_check_init(&domain_url);
			url_get_domain(&host_url,&domain_url);
			if(!strcmp(domain_url.realLink.data,domain_url.displayLink.data)) {
				free_if_needed(&host_url);
				free_if_needed(&domain_url);
				return CL_PHISH_DOMAIN_OK;
			}
			free_if_needed(&domain_url);
		}

		/*if(urls->flags&CHECK_REDIR) {
			//see where the realLink redirects, and compare that with the displayed Link
			const uchar* redirectedURL  = getRedirectedURL(urls->realLink);
			if(urls->needsfree)
				free(urls->realLink);
			urls->realLink = redirectedURL;

			if(!strcmp(urls->realLink,urls->displayLink))
				return CL_PHISH_REDIR_OK;

			if(urls->flags&HOST_SUFFICIENT) {
				if(rc = url_get_host(urls,&host_url,DOMAIN_REAL))
				if(!strcmp(host_url.realLink,host_url.displayLink)) {
					free_if_needed(&host_url);
					return CL_PHISH_HOST_REDIR_OK;
				}
				if(urls->flags&DOMAIN_SUFFICIENT) {
					struct url_check domain_url;
					url_get_domain(&host_url,&domain_url);
					if(!strcmp(domain_url.realLink,domain_url.displayLink)) {
						free_if_needed(&host_url);
						free_if_needed(&domain_url);
						return CL_PHISH_DOMAIN_REDIR_OK;
					}
				}
			}//HOST_SUFFICIENT&CHECK_REDIR
		}
		free_if_needed(&host_url);*/
	/*	if(urls->flags&CHECK_DOMAIN_REVERSE) {
			//do a DNS lookup of the domain, and see what IP it corresponds to
			//then do a reverse lookup on the IP, and see what domain you get
			//There are some corporate signatures that mix different domains belonging to same company
			struct url_check domain_url;
			url_check_init(&domain_url);
			if(!dns_to_ip_and_reverse(&host_url,DOMAIN_DISPLAY)) {
				if(!strcmp(host_url.realLink.data,host_url.displayLink.data)) {
					free_if_needed(&host_url);
					return CL_PHISH_HOST_REVERSE_OK;
				}
				if(urls->flags&DOMAIN_SUFFICIENT) {
					url_get_domain(&host_url,&domain_url);
					if(!strcmp(domain_url.realLink.data,domain_url.displayLink.data)) {
						free_if_needed(&host_url);
						free_if_needed(&domain_url);
						return CL_PHISH_DOMAIN_REVERSE_OK;
					}
					free_if_needed(&domain_url);
				}
			}
		}*/
		free_if_needed(&host_url);
	}/*HOST_SUFFICIENT*/
	/*we failed to find a reason why the 2 URLs are different, this is definetely phishing*/
	return phishy_map(phishy,CL_PHISH_NOMATCH);
}

const char* phishing_ret_toString(enum phish_status rc)
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
		default:
			return "Unknown return code";
	}
}

#endif

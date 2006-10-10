/*
 *  Phishing module: whitelist implementation.
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
 *  $Log: phish_whitelist.c,v $
 *  Revision 1.6  2006/10/10 23:51:49  tkojm
 *  apply patches for the anti-phish code from Edwin
 *
 *  Revision 1.5  2006/10/07 13:55:01  tkojm
 *  fix handlers
 *
 *  Revision 1.4  2006/10/07 11:00:46  tkojm
 *  make the experimental anti-phishing code more thread safe
 *
 *  Revision 1.3  2006/09/26 18:55:36  njh
 *  Fixed portability issues
 *
 *  Revision 1.2  2006/09/17 14:50:58  njh
 *  Sync with latest CVS
 *
 *  Revision 1.2  2006/09/14 07:05:06  njh
 *  Fix 'multiple main' definitions
 *
 *  Revision 1.1  2006/09/12 19:38:39  acab
 *  Phishing module merge - libclamav
 *
 *  Revision 1.16  2006/08/06 20:27:07  edwin
 *  New option to enable phish scan for all domains (disabled by default).
 *  You will now have to run clamscan --phish-scan-alldomains to have any phishes detected.
 *  Updated phishcheck control flow to better incorporate the domainlist.
 *  Updated manpage with new options.
 *
 *  TODO:there is a still-reachable leak in regex_list.c
 *
 *  Revision 1.15  2006/07/31 20:12:30  edwin
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
#include <string.h>
#ifdef	HAVE_STRINGS_H
#include <strings.h>
#endif
#include <ctype.h>

#include <limits.h>
#include "clamav.h"
#include <sys/types.h>

#ifdef	HAVE_REGEX_H
/*#define USE_PCRE*/
#include <regex.h>
#endif

#if defined(HAVE_READDIR_R_3) || defined(HAVE_READDIR_R_2)
#include <stddef.h>
#endif

#include "others.h"
#include "defaults.h"
#include "str.h"
#include "filetypes.h"
#include "mbox.h"
#include "phish_whitelist.h"
#include "regex_list.h"
#include "matcher-ac.h"

int whitelist_match(const struct cl_engine* engine,const char* real_url,const char* display_url,int hostOnly)
{
	const char* info;/*unused*/
	return	engine->whitelist_matcher ? regex_list_match(engine->whitelist_matcher,real_url,display_url,hostOnly,&info,1) : 0;
}

int init_whitelist(struct cl_engine* engine)
{
	if(engine) {
		engine->whitelist_matcher = (struct regex_matcher *) cli_malloc(sizeof(struct regex_matcher));
		if(!engine->whitelist_matcher)
			return CL_EMEM;
		return	init_regex_list(engine->whitelist_matcher);
	}
	else
		return CL_ENULLARG;
}

int is_whitelist_ok(const struct cl_engine* engine)
{
	return (engine && engine->whitelist_matcher) ? is_regex_ok(engine->whitelist_matcher) : 1;
}

void whitelist_cleanup(const struct cl_engine* engine)
{
	if(engine && engine->whitelist_matcher) {
		regex_list_cleanup(engine->whitelist_matcher);
	}
}

void whitelist_done(struct cl_engine* engine)
{
	if(engine && engine->whitelist_matcher) {
		regex_list_done(engine->whitelist_matcher);	
		free(engine->whitelist_matcher);
		engine->whitelist_matcher = NULL;
	}
}

#endif

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
#include <assert.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>

#include <limits.h>
#include "clamav.h"
#include <sys/types.h>

/*#define USE_PCRE*/
#include <regex.h>

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


static struct regex_matcher whitelist_matcher;

int whitelist_match(const char* real_url,const char* display_url,int hostOnly)
{
	const char* info;/*unused*/
	return	regex_list_match(&whitelist_matcher,real_url,display_url,hostOnly,&info);
}

int init_whitelist(void)
{
	return	init_regex_list(&whitelist_matcher);
}

int is_whitelist_ok(void)
{
	return is_regex_ok(&whitelist_matcher);
}

int cli_loadwdb(FILE* fd,unsigned int options)
{
	return load_regex_matcher(&whitelist_matcher,fd,options);
}

void whitelist_cleanup(void)
{
	regex_list_cleanup(&whitelist_matcher);
}

void whitelist_done(void)
{
	regex_list_done(&whitelist_matcher);
}

#define WHITELIST_TEST
#ifdef WHITELIST_TEST
int main(int argc,char* argv[])
{
/*	struct tree_node* root=tree_node_alloc(NULL,1);
	const  char* info;
	const  unsigned char test[]="tesxt";
	setup_matcher();
	root->op=OP_ROOT;
	root->c=0;
	root->next=NULL;
	root->listend=1;
	dump_tree(root);
	add_pattern(&root,"test","1");
	dump_tree(root);
	add_pattern(&root,"tesv","2");
	dump_tree(root);
	add_pattern(&root,"tert","3");
	dump_tree(root);
	add_pattern(&root,"terr+","4");
	dump_tree(root);
	add_pattern(&root,"tes[xy]t","5");
	dump_tree(root);
	match_node(root,test,sizeof(test),&info);
	destroy_tree(root);
	if(info)
		printf("%s\n",info);
	else printf("not found\n");*/
	/*FILE* f=fopen("w.wdb","r");
	init_whitelist();
	load_whitelist(f);
	fclose(f);
	dump_tree(root_regex);
	build_whitelist();
	printf("%d\n",whitelist_match("http://www.google.ro","http://www.google.me.ro",0));
	whitelist_done();*/
	return 0;
}
#endif

#endif

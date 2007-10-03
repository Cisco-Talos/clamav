/*
 *  Match a string against a list of patterns/regexes.
 *
 *  Copyright (C) 2006 Török Edvin <edwin@clamav.net>
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


#ifndef _REGEX_LIST_H
#define _REGEX_LIST_H

#ifdef NDEBUG
#define massert(x) (void)(0)
#else
/*debug version, massert enabled*/

#define __massert_fail(expr,file,line) (void)cli_errmsg("Assertion failed at %s:%d\n %s\n",file,line,expr)

#define massert(expr) ((void) ((expr) ? (void)0 : (__massert_fail (#expr,__FILE__,__LINE__))))
#endif

#include "phishcheck.h"
struct node_stack {
	struct tree_node** data;
	size_t capacity;
	size_t cnt;
};

struct regex_matcher {
	struct cli_matcher* root_hosts;
	struct tree_node* root_regex;
	struct tree_node* root_regex_hostonly; 
	size_t root_hosts_cnt;
	int list_inited;
	int list_loaded;
	int list_built;
	struct node_stack node_stack;
	struct node_stack node_stack_alt;
};

int regex_list_match(struct regex_matcher* matcher, char* real_url,const char* display_url,const struct pre_fixup_info* pre_fixup, int hostOnly,const char** info,int is_whitelist);
int init_regex_list(struct regex_matcher* matcher);
int load_regex_matcher(struct regex_matcher* matcher,FILE* fd,unsigned int options,int is_whitelist);
void regex_list_cleanup(struct regex_matcher* matcher);
void regex_list_done(struct regex_matcher* matcher);
int is_regex_ok(struct regex_matcher* matcher);

#endif


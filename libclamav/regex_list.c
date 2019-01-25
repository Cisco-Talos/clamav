/*
 *  Match a string against a list of patterns/regexes.
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
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <zlib.h>

#include <limits.h>
#include <sys/types.h>
#include <assert.h>

#include "regex/regex.h"

#include "clamav.h"
#include "others.h"
#include "regex_list.h"
#include "matcher-ac.h"
#include "matcher.h"
#include "str.h"
#include "readdb.h"
#include "jsparse/textbuf.h"
#include "regex_suffix.h"
#include "default.h"
#include "hashtab.h"

#include "mpool.h"

/* Prototypes */
static regex_t *new_preg(struct regex_matcher *matcher);
static size_t reverse_string(char *pattern);
static int add_pattern_suffix(void *cbdata, const char *suffix, size_t suffix_len, const struct regex_list *regex);
static int add_static_pattern(struct regex_matcher *matcher, char* pattern);
/* ---------- */

#define MATCH_SUCCESS 0
#define MATCH_FAILED  -1

/*
 * Call this function when an unrecoverable error has occurred, (instead of exit).
 */
static void fatal_error(struct regex_matcher* matcher)
{
	regex_list_done(matcher);
	matcher->list_inited = -1;/* the phishing module will know we tried to load a whitelist, and failed, so it will disable itself too*/
}


static inline char get_char_at_pos_with_skip(const struct pre_fixup_info* info, const char* buffer, size_t pos)
{
	const char* str;
	size_t realpos = 0;
	if(!info) {
		return (pos <= strlen(buffer)) ? buffer[pos>0 ? pos-1:0] : '\0';
	}
	str = info->pre_displayLink.data;
	cli_dbgmsg("calc_pos_with_skip: skip:%llu, %llu - %llu \"%s\",\"%s\"\n", (long long unsigned)pos, (long long unsigned)info->host_start,
               (long long unsigned)info->host_end, str, buffer);
	pos += info->host_start;
	while(str[realpos] && !isalnum(str[realpos])) realpos++;
	for(; str[realpos] && (pos>0); pos--) {
		while(str[realpos]==' ') realpos++;
		realpos++;
	}
	while(str[realpos]==' ') realpos++;
	cli_dbgmsg("calc_pos_with_skip:%s\n",str+realpos);
	return (pos>0 && !str[realpos]) ? '\0' : str[realpos>0?realpos-1:0];
}

static int validate_subdomain(const struct regex_list *regex, const struct pre_fixup_info *pre_fixup, const char *buffer, size_t buffer_len, char *real_url, size_t real_len, char *orig_real_url)
{
	char c;
	size_t match_len;

	if(!regex || !regex->pattern)
		return 0;
	match_len = strlen(regex->pattern);
	if(((c=get_char_at_pos_with_skip(pre_fixup,buffer,buffer_len+1))==' ' || c=='\0' || c=='/' || c=='?') &&
			(match_len == buffer_len || /* full match */
			 (match_len < buffer_len &&
			  ((c=get_char_at_pos_with_skip(pre_fixup,buffer,buffer_len-match_len))=='.' || (c==' ')) )
			 /* subdomain matched*/)) {
		/* we have an extra / at the end */
		if(match_len > 0) match_len--;
		cli_dbgmsg("Got a match: %s with %s\n", buffer, regex->pattern);
		cli_dbgmsg("Before inserting .: %s\n", orig_real_url);
		if(real_len >= match_len + 1) {
			const size_t pos = real_len - match_len - 1;
			if(real_url[pos] != '.') {
				/* we need to shift left, and insert a '.'
				 * we have an extra '.' at the beginning inserted by get_host to have room,
				 * orig_real_url has to be used here, 
				 * because we want to overwrite that extra '.' */
				size_t orig_real_len = strlen(orig_real_url);
				cli_dbgmsg("No dot here:%s\n",real_url+pos);
				real_url = orig_real_url;
				memmove(real_url, real_url+1, orig_real_len-match_len-1);
				real_url[orig_real_len-match_len-1]='.';
				cli_dbgmsg("After inserting .: %s\n", real_url);
			}
		}
		return 1;
	}
	cli_dbgmsg("Ignoring false match: %s with %s, mismatched character: %c\n", buffer, regex->pattern, c);
	return 0;
}

/*
 * @matcher - matcher structure to use
 * @real_url - href target
 * @display_url - <a> tag contents
 * @hostOnly - if you want to match only the host part
 * @is_whitelist - is this a lookup in whitelist?
 *
 * @return - CL_SUCCESS - url doesn't match
 *         - CL_VIRUS - url matches list
 *
 * Do not send NULL pointers to this function!!
 *
 */
int regex_list_match(struct regex_matcher* matcher,char* real_url,const char* display_url,const struct pre_fixup_info* pre_fixup,int hostOnly,const char **info, int is_whitelist)
{
	char* orig_real_url = real_url;
	struct regex_list *regex;
	size_t real_len, display_len, buffer_len;

	assert(matcher);
	assert(real_url);
	assert(display_url);
	*info = NULL;
	if(!matcher->list_inited)
		return 0;
	assert(matcher->list_built);
	/* skip initial '.' inserted by get_host */
	if(real_url[0] == '.') real_url++;
	if(display_url[0] == '.') display_url++;
	real_len    = strlen(real_url);
	display_len = strlen(display_url);
	buffer_len  = (hostOnly && !is_whitelist) ? real_len + 1 : real_len + display_len + 1 + 1;
	if(buffer_len < 3) {
		/* too short, no match possible */
		return 0;
	}
	{
		char *buffer = cli_malloc(buffer_len+1);
		char *bufrev;
		int rc = 0, root;
		struct cli_ac_data mdata;
		struct cli_ac_result *res = NULL;

		if(!buffer) {
            cli_errmsg("regex_list_match: Unable to allocate memory for buffer\n");
			return CL_EMEM;
        }

		strncpy(buffer,real_url,real_len);
		buffer[real_len]= (!is_whitelist && hostOnly) ? '/' : ':';
		if(!hostOnly || is_whitelist) {
			strncpy(buffer+real_len+1,display_url,display_len);
		}
		buffer[buffer_len - 1] = '/';
		buffer[buffer_len]=0;
		cli_dbgmsg("Looking up in regex_list: %s\n", buffer);

		if((rc = cli_ac_initdata(&mdata, 0, 0, 0, CLI_DEFAULT_AC_TRACKLEN)))
			return rc;

		bufrev = cli_strdup(buffer);
		if(!bufrev)
			return CL_EMEM;
		reverse_string(bufrev);
		rc = filter_search(&matcher->filter, (const unsigned char*)bufrev, buffer_len) != -1;
		if(rc == -1) {
			free(buffer);
			free(bufrev);
			/* filter says this suffix doesn't match.
			 * The filter has false positives, but no false
			 * negatives */
			return 0;
		}
		rc = cli_ac_scanbuff((const unsigned char*)bufrev,buffer_len, NULL, (void*)&regex, &res, &matcher->suffixes,&mdata,0,0,NULL,AC_SCAN_VIR,NULL);
		free(bufrev);
		cli_ac_freedata(&mdata);

		rc = 0;
		root = matcher->root_regex_idx;
		while(res || root) {
			struct cli_ac_result *q;
			if (!res) {
			    regex = matcher->suffix_regexes[root].head;
			    root = 0;
			} else {
			    regex = res->customdata;
			}
			while(!rc && regex) {
				/* loop over multiple regexes corresponding to
				 * this suffix */
				if (!regex->preg) {
					/* we matched a static pattern */
					rc = validate_subdomain(regex, pre_fixup, buffer, buffer_len, real_url, real_len, orig_real_url);
				} else {
					rc = !cli_regexec(regex->preg, buffer, 0, NULL, 0);
				}
				if(rc) *info = regex->pattern;
				regex = regex->nxt;
			}
			if (res) {
			    q = res;
			    res = res->next;
			    free(q);
			}
		}
		free(buffer);
		if(!rc)
			cli_dbgmsg("Lookup result: not in regex list\n");
		else
			cli_dbgmsg("Lookup result: in regex list\n");
		return rc;
	}
}


/* Initialization & loading */
/* Initializes @matcher, allocating necessary substructures */
int init_regex_list(struct regex_matcher* matcher, uint8_t dconf_prefiltering)
{
#ifdef USE_MPOOL
	mpool_t *mp = matcher->mempool;
#endif
	int rc;

	assert(matcher);
	memset(matcher, 0, sizeof(*matcher));

	matcher->list_inited=1;
	matcher->list_built=0;
	matcher->list_loaded=0;
	cli_hashtab_init(&matcher->suffix_hash, 512);
#ifdef USE_MPOOL
	matcher->mempool = mp;
	matcher->suffixes.mempool = mp;
	assert(mp && "mempool must be initialized");
#endif
	if((rc = cli_ac_init(&matcher->suffixes, 2, 32, dconf_prefiltering))) {
		return rc;
	}
#ifdef USE_MPOOL
	matcher->sha256_hashes.mempool = mp;
	matcher->hostkey_prefix.mempool = mp;
#endif
	if((rc = cli_bm_init(&matcher->sha256_hashes))) {
		return rc;
	}
	if((rc = cli_bm_init(&matcher->hostkey_prefix))) {
		return rc;
	}
	filter_init(&matcher->filter);
	return CL_SUCCESS;
}

static int functionality_level_check(char* line)
{
	char* ptmin;
	char* ptmax;
	size_t j;

	ptmin = strrchr(line,':');
	if(!ptmin) 
		return CL_SUCCESS;
	
	ptmin++;

	ptmax = strchr(ptmin,'-');
	if(!ptmax) 
		return CL_SUCCESS;/* there is no functionality level specified, so we're ok */
	else {
		size_t min, max;
		ptmax++;
		for(j=0;j+ptmin+1 < ptmax;j++)
			if(!isdigit(ptmin[j])) 
				return CL_SUCCESS;/* not numbers, not functionality level */
		for(j=0;j<strlen(ptmax);j++)
			if(!isdigit(ptmax[j])) 
				return CL_SUCCESS;/* see above */
		ptmax[-1]='\0';
		min = atoi(ptmin);
		if(strlen(ptmax)==0)
 			max = INT_MAX; 		
		else
			max = atoi(ptmax);

		if(min > cl_retflevel()) {
			cli_dbgmsg("regex list line %s not loaded (required f-level: %u)\n",line,(unsigned int)min);
			return CL_EMALFDB; 
		}

		if(max < cl_retflevel()) 
			return CL_EMALFDB;
		ptmin[-1]='\0';
		return CL_SUCCESS;
	}
}

static int add_hash(struct regex_matcher *matcher, char* pattern, const char fl, int is_prefix)
{
	int rc;
	struct cli_bm_patt *pat = mpool_calloc(matcher->mempool, 1, sizeof(*pat));
	struct cli_matcher *bm;
	const char *vname = NULL;
	if(!pat)
		return CL_EMEM;
	pat->pattern = (unsigned char*)cli_mpool_hex2str(matcher->mempool, pattern);
	if(!pat->pattern)
		return CL_EMALFDB;
	pat->length = 32;
	if (is_prefix) {
	    pat->length=4;
	    bm = &matcher->hostkey_prefix;
	} else {
	    bm = &matcher->sha256_hashes;
	}

	if (!matcher->sha256_pfx_set.keys) {
	    if((rc = cli_hashset_init(&matcher->sha256_pfx_set, 1048576, 90))) {
		return rc;
	    }
	}

	if (fl != 'W' && pat->length == 32 &&
	    cli_hashset_contains(&matcher->sha256_pfx_set, cli_readint32(pat->pattern)) &&
	    cli_bm_scanbuff(pat->pattern, 32, &vname, NULL, &matcher->sha256_hashes,0,NULL,NULL,NULL) == CL_VIRUS) {
	    if (*vname == 'W') {
		/* hash is whitelisted in local.gdb */
		cli_dbgmsg("Skipping hash %s\n", pattern);
		mpool_free(matcher->mempool, pat->pattern);
		mpool_free(matcher->mempool, pat);
		return CL_SUCCESS;
	    }
	}
	pat->virname = mpool_malloc(matcher->mempool, 1);
	if(!pat->virname) {
		free(pat);
        cli_errmsg("add_hash: Unable to allocate memory for path->virname\n");
		return CL_EMEM;
	}
	*pat->virname = fl;
	cli_hashset_addkey(&matcher->sha256_pfx_set, cli_readint32(pat->pattern));
	if((rc = cli_bm_addpatt(bm, pat, "*"))) {
		cli_errmsg("add_hash: failed to add BM pattern\n");
		free(pat->pattern);
		free(pat->virname);
		free(pat);
		return CL_EMALFDB;
	}
	return CL_SUCCESS;
}


/* Load patterns/regexes from file */
int load_regex_matcher(struct cl_engine *engine,struct regex_matcher* matcher,FILE* fd,unsigned int *signo,unsigned int options,int is_whitelist,struct cli_dbio *dbio, uint8_t dconf_prefiltering)
{
	int rc,line=0,entry=0;
	char buffer[FILEBUFF];

	assert(matcher);

	if(matcher->list_inited==-1)
		return CL_EMALFDB; /* already failed to load */
	if(!fd && !dbio) {
		cli_errmsg("Unable to load regex list (null file)\n");
		return CL_ENULLARG;
	}

	cli_dbgmsg("Loading regex_list\n");
	if(!matcher->list_inited) {
		rc = init_regex_list(matcher, dconf_prefiltering);
		if (!matcher->list_inited) {
			cli_errmsg("Regex list failed to initialize!\n");
			fatal_error(matcher);
			return rc;
		}
	}
	/*
	 * Regexlist db format (common to .wdb(whitelist) and .pdb(domainlist) files:
	 * Multiple lines of form, (empty lines are skipped):
 	 * Flags RealURL DisplayedURL
	 * Where:
	 * Flags: 
	 *
	 * .pdb files:
	 * R - regex, H - host-only, followed by (optional) 3-digit hexnumber representing 
	 * flags that should be filtered.
	 * [i.e. phishcheck urls.flags that we don't want to be done for this particular host]
	 * 
	 * .wdb files:
	 * X - full URL regex 
	 * Y - host-only regex
	 * M - host simple pattern
	 *
	 * If a line in the file doesn't conform to this format, loading fails
	 * 
	 */
	while(cli_dbgets(buffer, FILEBUFF, fd, dbio)) {
		char* pattern;
		char* flags;
		size_t pattern_len;

		cli_chomp(buffer);
		line++;
		if(!*buffer)
			continue;/* skip empty lines */

		if(functionality_level_check(buffer))
			continue;

		if(engine->cb_sigload && engine->cb_sigload("phishing", buffer, ~options & CL_DB_OFFICIAL, engine->cb_sigload_ctx)) {
			cli_dbgmsg("load_regex_matcher: skipping %s due to callback\n", buffer);
			continue;
		}

		entry++;
		pattern = strchr(buffer,':');
		if(!pattern) {
			cli_errmsg("Malformed regex list line %d\n",line);
			fatal_error(matcher);
			return CL_EMALFDB;
		}
		/*pattern[0]='\0';*/
		flags = buffer+1;
		pattern++;

		pattern_len = strlen(pattern);
		if(pattern_len < FILEBUFF) {
			pattern[pattern_len] = '/';
			pattern[pattern_len+1] = '\0';
		}
		else {
			cli_errmsg("Overlong regex line %d\n",line);
			fatal_error(matcher);
			return CL_EMALFDB;
		}

		if((buffer[0] == 'R' && !is_whitelist) || ((buffer[0] == 'X' || buffer[0] == 'Y') && is_whitelist)) {
			/* regex for hostname*/
			if (( rc = regex_list_add_pattern(matcher, pattern) ))
				return rc==CL_EMEM ? CL_EMEM : CL_EMALFDB;
		}
		else if( ( buffer[0] == 'H' && !is_whitelist) || (buffer[0] == 'M' && is_whitelist)) {
			/*matches displayed host*/
			if (( rc = add_static_pattern(matcher, pattern) ))
				return rc==CL_EMEM ? CL_EMEM : CL_EMALFDB;
		} else if (buffer[0] == 'S' && (!is_whitelist || pattern[0]=='W')) {
			pattern[pattern_len] = '\0';
			if (pattern[0]=='W')
			    flags[0]='W';
			if((pattern[0]=='W' || pattern[0]=='F' || pattern[0]=='P') && pattern[1]==':') {
			    pattern += 2;
			    if (( rc = add_hash(matcher, pattern, flags[0], pattern[-2] == 'P') )) {
				cli_errmsg("Error loading at line: %d\n", line);
				return rc==CL_EMEM ? CL_EMEM : CL_EMALFDB;
			    }
			} else {
			    cli_errmsg("Error loading line: %d, %c\n", line, *pattern);
			    return CL_EMALFDB;
			}
		} else {
			return CL_EMALFDB;
		}
	}
	matcher->list_loaded = 1;
	if(signo)
	    *signo += entry;

	return CL_SUCCESS;
}


/* Build the matcher list */
int cli_build_regex_list(struct regex_matcher* matcher)
{
	int rc;
	if(!matcher)
		return CL_SUCCESS;
	if(!matcher->list_inited || !matcher->list_loaded) {
		cli_errmsg("Regex list not loaded!\n");
		return -1;/*TODO: better error code */
	}
	cli_dbgmsg("Building regex list\n");
	cli_hashtab_free(&matcher->suffix_hash);
	if(( rc = cli_ac_buildtrie(&matcher->suffixes) ))
		return rc;
	matcher->list_built=1;
	cli_hashset_destroy(&matcher->sha256_pfx_set);

	return CL_SUCCESS;
}

/* Done with this matcher, free resources */
void regex_list_done(struct regex_matcher* matcher)
{
	assert(matcher);

	if(matcher->list_inited == 1) {
		size_t i;
		cli_ac_free(&matcher->suffixes);
		if(matcher->suffix_regexes) {
			for(i=0;i<matcher->suffix_cnt;i++) {
				struct regex_list *r = matcher->suffix_regexes[i].head;
				while(r) {
					struct regex_list *q = r;
					r = r->nxt;
					free(q->pattern);
					free(q);
				}
			}
			free(matcher->suffix_regexes);
			matcher->suffix_regexes = NULL;
		}
		if(matcher->all_pregs) {
			for(i=0;i<matcher->regex_cnt;i++) {
				regex_t *r = matcher->all_pregs[i];
				cli_regfree(r);
				mpool_free(matcher->mempool, r);
			}
			mpool_free(matcher->mempool, matcher->all_pregs);
		}
		cli_hashtab_free(&matcher->suffix_hash);
		cli_bm_free(&matcher->sha256_hashes);
		cli_bm_free(&matcher->hostkey_prefix);
	}
}

int is_regex_ok(struct regex_matcher* matcher)
{
	assert(matcher);
	return (!matcher->list_inited || matcher->list_inited!=-1);/* either we don't have a regexlist, or we initialized it successfully */
}

static int add_newsuffix(struct regex_matcher *matcher, struct regex_list *info, const char *suffix, size_t len)
{
	struct cli_matcher *root = &matcher->suffixes;
	struct cli_ac_patt *new = mpool_calloc(matcher->mempool,1,sizeof(*new));
	size_t i;
	int ret;

	if(!new)
		return CL_EMEM;
	assert(root && suffix);

	new->rtype = 0;
	new->type = 0;
	new->sigid = 0;
	new->parts = 0;
	new->partno = 0;
	new->mindist = 0;
	new->maxdist = 0;
	new->offset_min = CLI_OFF_ANY;
	new->length[0] = (uint16_t)len;

	new->ch[0] = new->ch[1] |= CLI_MATCH_IGNORE;
	if(new->length[0] > root->maxpatlen)
		root->maxpatlen = new->length[0];

	new->pattern = mpool_malloc(matcher->mempool, sizeof(new->pattern[0])*len);
	if(!new->pattern) {
		mpool_free(matcher->mempool, new);
        cli_errmsg("add_newsuffix: Unable to allocate memory for new->pattern\n");
		return CL_EMEM;
	}
	for(i=0;i<len;i++)
		new->pattern[i] = suffix[i];/*new->pattern is short int* */

	new->customdata = info;
	new->virname = NULL;
	if((ret = cli_ac_addpatt(root,new))) {
		mpool_free(matcher->mempool, new->pattern);
		mpool_free(matcher->mempool, new);
		return ret;
	}
	filter_add_static(&matcher->filter, (const unsigned char*)suffix, len, "regex");
	return CL_SUCCESS;
}

#define MODULE "regex_list: "
/* ------ load a regex, determine suffix, determine suffix2regexlist map ---- */

static void list_add_tail(struct regex_list_ht *ht, struct regex_list *regex)
{
	if(!ht->head)
		ht->head = regex;
	if(ht->tail) {
		ht->tail->nxt = regex;
	}
	ht->tail = regex;
}

/* returns 0 on success, clamav error code otherwise */
static int add_pattern_suffix(void *cbdata, const char *suffix, size_t suffix_len, const struct regex_list *iregex)
{
	struct regex_matcher *matcher = cbdata;
	struct regex_list *regex = cli_malloc(sizeof(*regex));
	const struct cli_element *el;
	void *tmp_matcher;  /*	save original address if OOM occurs */

	assert(matcher);
	if(!regex) {
        cli_errmsg("add_pattern_suffix: Unable to allocate memory for regex\n");
		return CL_EMEM;
    }
	regex->pattern = iregex->pattern ? cli_strdup(iregex->pattern) : NULL;
	regex->preg = iregex->preg;
	regex->nxt = NULL;
	el = cli_hashtab_find(&matcher->suffix_hash, suffix, suffix_len);
	/* TODO: what if suffixes are prefixes of eachother and only one will
	 * match? */
	if(el) {
		/* existing suffix */
		assert((size_t)el->data < matcher->suffix_cnt);
		list_add_tail(&matcher->suffix_regexes[el->data], regex);
	} else {
		/* new suffix */
		size_t n = matcher->suffix_cnt++;
		el = cli_hashtab_insert(&matcher->suffix_hash, suffix, suffix_len, n);
		tmp_matcher = matcher->suffix_regexes;	/*  save the current value before cli_realloc()	*/
		tmp_matcher = cli_realloc(matcher->suffix_regexes, (n+1)*sizeof(*matcher->suffix_regexes));
		if(!tmp_matcher) {
			free (regex);
			return CL_EMEM;
		}
		matcher->suffix_regexes = tmp_matcher;	/*  success, point at new memory location   */
		matcher->suffix_regexes[n].tail = regex;
		matcher->suffix_regexes[n].head = regex;
		if (suffix[0] == '/' && suffix[1] == '\0')
		    matcher->root_regex_idx = n;
		add_newsuffix(matcher, regex, suffix, suffix_len);
	}
	return 0;
}

static size_t reverse_string(char *pattern)
{
	size_t len = strlen(pattern);
	size_t i;
	for(i=0; i < (len/2); i++) {
		char aux = pattern[i];
		pattern[i] = pattern[len-i-1];
		pattern[len-i-1] = aux;
	}
	return len;
}

static regex_t *new_preg(struct regex_matcher *matcher)
{
	regex_t *r;
	matcher->all_pregs = mpool_realloc(matcher->mempool, matcher->all_pregs, ++matcher->regex_cnt * sizeof(*matcher->all_pregs));
	if(!matcher->all_pregs) {
        cli_errmsg("new_preg: Unable to reallocate memory\n");
		return NULL;
    }
	r = mpool_malloc(matcher->mempool, sizeof(*r));
	if(!r) {
        cli_errmsg("new_preg: Unable to allocate memory\n");
		return NULL;
    }
	matcher->all_pregs[matcher->regex_cnt-1] = r;
	return r;
}

static int add_static_pattern(struct regex_matcher *matcher, char* pattern)
{
	size_t len;
	struct regex_list regex;
	int rc;

	len = reverse_string(pattern);
	regex.nxt = NULL;
	regex.pattern = cli_strdup(pattern);
	regex.preg = NULL;
	rc = add_pattern_suffix(matcher, pattern, len, &regex);
	free(regex.pattern);
	return rc;
}

int regex_list_add_pattern(struct regex_matcher *matcher, char *pattern)
{
	int rc;
	regex_t *preg;
	size_t len;
	/* we only match the host, so remove useless stuff */
	const char remove_end[] = "([/?].*)?/";
	const char remove_end2[] = "([/?].*)/";

	len = strlen(pattern);
	if(len > sizeof(remove_end)) {
		if(strncmp(&pattern[len - sizeof(remove_end)+1], remove_end, sizeof(remove_end)-1) == 0) {
			len -= sizeof(remove_end) - 1;
			pattern[len++]='/';
		}
		if(strncmp(&pattern[len - sizeof(remove_end2)+1], remove_end2, sizeof(remove_end2)-1) == 0) {
			len -= sizeof(remove_end2) - 1;
			pattern[len++]='/';
		}
	}
	pattern[len] = '\0';

	preg = new_preg(matcher);
	if(!preg)
		return CL_EMEM;

	rc = cli_regex2suffix(pattern, preg, add_pattern_suffix, (void*)matcher);
	if(rc) {
		cli_regfree(preg);
	}

	return rc;
}

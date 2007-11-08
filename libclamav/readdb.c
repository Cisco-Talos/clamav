/*
 *  Copyright (C) 2002 - 2007 Tomasz Kojm <tkojm@clamav.net>
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

#ifdef _MSC_VER
#include <winsock.h> /* for Sleep() */
#endif

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifndef C_WINDOWS
#include <dirent.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#ifdef	HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <fcntl.h>

#include "clamav.h"
#include "cvd.h"
#ifdef	HAVE_STRINGS_H
#include <strings.h>
#endif
#include "matcher-ac.h"
#include "matcher-bm.h"
#include "matcher.h"
#include "others.h"
#include "str.h"
#include "dconf.h"
#include "lockdb.h"
#include "readdb.h"

#include "phishcheck.h"
#include "phish_whitelist.h"
#include "phish_domaincheck_db.h"
#include "regex_list.h"

#if defined(HAVE_READDIR_R_3) || defined(HAVE_READDIR_R_2)
#include <limits.h>
#include <stddef.h>
#endif

#ifdef CL_THREAD_SAFE
#  include <pthread.h>
static pthread_mutex_t cli_ref_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

/* Prototypes for old public functions just to shut up some gcc warnings;
 * to be removed in 1.0
 */
int cl_loaddb(const char *filename, struct cl_engine **engine, unsigned int *signo);
int cl_loaddbdir(const char *dirname, struct cl_engine **engine, unsigned int *signo);


int cli_parse_add(struct cli_matcher *root, const char *virname, const char *hexsig, unsigned short type, const char *offset, unsigned short target)
{
	struct cli_bm_patt *bm_new;
	char *pt, *hexcpy, *start, *n;
	int ret, virlen, asterisk = 0;
	unsigned int i, j, len, parts = 0;
	int mindist = 0, maxdist = 0, error = 0;


    if(strchr(hexsig, '{')) {

	root->ac_partsigs++;

	if(!(hexcpy = cli_strdup(hexsig)))
	    return CL_EMEM;

	len = strlen(hexsig);
	for(i = 0; i < len; i++)
	    if(hexsig[i] == '{' || hexsig[i] == '*')
		parts++;

	if(parts)
	    parts++;

	start = pt = hexcpy;
	for(i = 1; i <= parts; i++) {

	    if(i != parts) {
		for(j = 0; j < strlen(start); j++) {
		    if(start[j] == '{') {
			asterisk = 0;
			pt = start + j;
			break;
		    }
		    if(start[j] == '*') {
			asterisk = 1;
			pt = start + j;
			break;
		    }
		}
		*pt++ = 0;
	    }

	    if((ret = cli_ac_addsig(root, virname, start, root->ac_partsigs, parts, i, type, mindist, maxdist, offset, target))) {
		cli_errmsg("cli_parse_add(): Problem adding signature (1).\n");
		error = 1;
		break;
	    }

	    if(i == parts)
		break;

	    mindist = maxdist = 0;

	    if(asterisk) {
		start = pt;
		continue;
	    }

	    if(!(start = strchr(pt, '}'))) {
		error = 1;
		break;
	    }
	    *start++ = 0;

	    if(!pt) {
		error = 1;
		break;
	    }

	    if(!strchr(pt, '-')) {
		if((mindist = maxdist = atoi(pt)) < 0) {
		    error = 1;
		    break;
		}
	    } else {
		if((n = cli_strtok(pt, 0, "-"))) {
		    if((mindist = atoi(n)) < 0) {
			error = 1;
			free(n);
			break;
		    }
		    free(n);
		}

		if((n = cli_strtok(pt, 1, "-"))) {
		    if((maxdist = atoi(n)) < 0) {
			error = 1;
			free(n);
			break;
		    }
		    free(n);
		}
	    }
	}

	free(hexcpy);
	if(error)
	    return CL_EMALFDB;

    } else if(strchr(hexsig, '*')) {
	root->ac_partsigs++;

	len = strlen(hexsig);
	for(i = 0; i < len; i++)
	    if(hexsig[i] == '*')
		parts++;

	if(parts)
	    parts++;

	for(i = 1; i <= parts; i++) {
	    if((pt = cli_strtok(hexsig, i - 1, "*")) == NULL) {
		cli_errmsg("Can't extract part %d of partial signature.\n", i);
		return CL_EMALFDB;
	    }

	    if((ret = cli_ac_addsig(root, virname, pt, root->ac_partsigs, parts, i, type, 0, 0, offset, target))) {
		cli_errmsg("cli_parse_add(): Problem adding signature (2).\n");
		free(pt);
		return ret;
	    }

	    free(pt);
	}

    } else if(root->ac_only || strpbrk(hexsig, "?(") || type) {
	if((ret = cli_ac_addsig(root, virname, hexsig, 0, 0, 0, type, 0, 0, offset, target))) {
	    cli_errmsg("cli_parse_add(): Problem adding signature (3).\n");
	    return ret;
	}

    } else {
	bm_new = (struct cli_bm_patt *) cli_calloc(1, sizeof(struct cli_bm_patt));
	if(!bm_new)
	    return CL_EMEM;

	if(!(bm_new->pattern = (unsigned char *) cli_hex2str(hexsig))) {
	    free(bm_new);
	    return CL_EMALFDB;
	}

	bm_new->length = strlen(hexsig) / 2;

	if((pt = strstr(virname, "(Clam)")))
	    virlen = strlen(virname) - strlen(pt) - 1;
	else
	    virlen = strlen(virname);

	if(virlen <= 0) {
	    free(bm_new->pattern);
	    free(bm_new);
	    return CL_EMALFDB;
	}

	if((bm_new->virname = cli_calloc(virlen + 1, sizeof(char))) == NULL) {
	    free(bm_new->pattern);
	    free(bm_new);
	    return CL_EMEM;
	}

	strncpy(bm_new->virname, virname, virlen);

	if(offset) {
	    bm_new->offset = cli_strdup(offset);
	    if(!bm_new->offset) {
		free(bm_new->pattern);
		free(bm_new->virname);
		free(bm_new);
		return CL_EMEM;
	    }
	}

	bm_new->target = target;

	if(bm_new->length > root->maxpatlen)
	    root->maxpatlen = bm_new->length;

	if((ret = cli_bm_addpatt(root, bm_new))) {
	    cli_errmsg("cli_parse_add(): Problem adding signature (4).\n");
	    free(bm_new->pattern);
	    free(bm_new->virname);
	    free(bm_new);
	    return ret;
	}
    }

    return CL_SUCCESS;
}

int cli_initengine(struct cl_engine **engine, unsigned int options)
{
	int ret;


    if(!*engine) {
#ifdef CL_EXPERIMENTAL
	cli_dbgmsg("Initializing the engine ("VERSION"-exp)\n");
#else
	cli_dbgmsg("Initializing the engine ("VERSION")\n");
#endif

	*engine = (struct cl_engine *) cli_calloc(1, sizeof(struct cl_engine));
	if(!*engine) {
	    cli_errmsg("Can't allocate memory for the engine structure!\n");
	    return CL_EMEM;
	}

	(*engine)->refcount = 1;

	(*engine)->root = cli_calloc(CL_TARGET_TABLE_SIZE, sizeof(struct cli_matcher *));
	if(!(*engine)->root) {
	    /* no need to free previously allocated memory here */
	    cli_errmsg("Can't allocate memory for roots!\n");
	    return CL_EMEM;
	}

	(*engine)->dconf = cli_dconf_init();
	if(!(*engine)->dconf) {
	    cli_errmsg("Can't initialize dynamic configuration\n");
	    return CL_EMEM;
	}
    }

    if((options & CL_DB_PHISHING_URLS) && (((struct cli_dconf*) (*engine)->dconf)->phishing & PHISHING_CONF_ENGINE))
	if((ret = phishing_init(*engine)))
	    return ret;

    return CL_SUCCESS;
}

static int cli_initroots(struct cl_engine *engine, unsigned int options)
{
	int i, ret;
	struct cli_matcher *root;


    for(i = 0; i < CL_TARGET_TABLE_SIZE; i++) {
	if(!engine->root[i]) {
	    cli_dbgmsg("Initializing engine->root[%d]\n", i);
	    root = engine->root[i] = (struct cli_matcher *) cli_calloc(1, sizeof(struct cli_matcher));
	    if(!root) {
		cli_errmsg("cli_initroots: Can't allocate memory for cli_matcher\n");
		return CL_EMEM;
	    }

	    if(options & CL_DB_ACONLY) {
		cli_dbgmsg("cli_initroots: Only using AC pattern matcher.\n");
		root->ac_only = 1;
	    }

	    cli_dbgmsg("Initialising AC pattern matcher of root[%d]\n", i);
	    if((ret = cli_ac_init(root, cli_ac_mindepth, cli_ac_maxdepth))) {
		/* no need to free previously allocated memory here */
		cli_errmsg("cli_initroots: Can't initialise AC pattern matcher\n");
		return ret;
	    }

	    if(!root->ac_only) {
		cli_dbgmsg("cli_initroots: Initializing BM tables of root[%d]\n", i);
		if((ret = cli_bm_init(root))) {
		    cli_errmsg("cli_initroots: Can't initialise BM pattern matcher\n");
		    return ret;
		}
	    }
	}
    }

    return CL_SUCCESS;
}

static int cli_loaddb(FILE *fd, struct cl_engine **engine, unsigned int *signo, unsigned int options)
{
	char buffer[FILEBUFF], *pt, *start;
	int line = 0, ret = 0;
	struct cli_matcher *root;


    if((ret = cli_initengine(engine, options))) {
	cl_free(*engine);
	return ret;
    }

    if((ret = cli_initroots(*engine, options))) {
	cl_free(*engine);
	return ret;
    }

    root = (*engine)->root[0];

    while(fgets(buffer, FILEBUFF, fd)) {
	line++;
	cli_chomp(buffer);

	pt = strchr(buffer, '=');
	if(!pt) {
	    cli_errmsg("Malformed pattern line %d\n", line);
	    ret = CL_EMALFDB;
	    break;
	}

	start = buffer;
	*pt++ = 0;

	if(*pt == '=') continue;

	if((ret = cli_parse_add(root, start, pt, 0, NULL, 0))) {
	    cli_errmsg("Problem parsing signature at line %d\n", line);
	    ret = CL_EMALFDB;
	    break;
	}
    }

    if(!line) {
	cli_errmsg("Empty database file\n");
	cl_free(*engine);
	return CL_EMALFDB;
    }

    if(ret) {
	cli_errmsg("Problem parsing database at line %d\n", line);
	cl_free(*engine);
	return ret;
    }

    if(signo)
	*signo += line;

    return CL_SUCCESS;
}

static int cli_loadwdb(FILE *fd, struct cl_engine **engine, unsigned int options)
{
	int ret = 0;


    if((ret = cli_initengine(engine, options))) {
	cl_free(*engine);
	return ret;
    }

    if(!(((struct cli_dconf *) (*engine)->dconf)->phishing & PHISHING_CONF_ENGINE))
	return CL_SUCCESS;

    if(!(*engine)->whitelist_matcher) {
	if((ret = init_whitelist(*engine))) {
	    phishing_done(*engine);
	    cl_free(*engine);
	    return ret;
	}
    }

    if((ret = load_regex_matcher((*engine)->whitelist_matcher, fd, options, 1))) {
	phishing_done(*engine);
	cl_free(*engine);
	return ret;
    }

    return CL_SUCCESS;
}

static int cli_loadpdb(FILE *fd, struct cl_engine **engine, unsigned int options)
{
	int ret = 0;


    if((ret = cli_initengine(engine, options))) {
	cl_free(*engine);
	return ret;
    }

    if(!(((struct cli_dconf *) (*engine)->dconf)->phishing & PHISHING_CONF_ENGINE))
	return CL_SUCCESS;

    if(!(*engine)->domainlist_matcher) {
	if((ret = init_domainlist(*engine))) {
	    phishing_done(*engine);
	    cl_free(*engine);
	    return ret;
	}
    }

    if((ret = load_regex_matcher((*engine)->domainlist_matcher, fd, options, 0))) {
	phishing_done(*engine);
	cl_free(*engine);
	return ret;
    }

    return CL_SUCCESS;
}

#define NDB_TOKENS 6
static int cli_loadndb(FILE *fd, struct cl_engine **engine, unsigned int *signo, unsigned short sdb, unsigned int options)
{
	const char *tokens[NDB_TOKENS];
	char buffer[FILEBUFF];
	const char *sig, *virname, *offset, *pt;
	struct cli_matcher *root;
	int line = 0, sigs = 0, ret = 0;
	unsigned short target;
	unsigned int phish = options & CL_DB_PHISHING;


    if((ret = cli_initengine(engine, options))) {
	cl_free(*engine);
	return ret;
    }

    if((ret = cli_initroots(*engine, options))) {
	cl_free(*engine);
	return ret;
    }

    while(fgets(buffer, FILEBUFF, fd)) {
	line++;

	if(!strncmp(buffer, "Exploit.JPEG.Comment", 20)) /* temporary */
	    continue;

	if(!phish)
	    if(!strncmp(buffer, "HTML.Phishing", 13) || !strncmp(buffer, "Email.Phishing", 14))
		continue;

	sigs++;
	cli_chomp(buffer);

	cli_strtokenize(buffer, ':', NDB_TOKENS, tokens);

	if(!(virname = tokens[0])) {
	    ret = CL_EMALFDB;
	    break;
	}

	if((pt = tokens[4])) { /* min version */
	    if(!isdigit(*pt)) {
		ret = CL_EMALFDB;
		break;
	    }

	    if((unsigned int) atoi(pt) > cl_retflevel()) {
		cli_dbgmsg("Signature for %s not loaded (required f-level: %d)\n", virname, atoi(pt));
		sigs--;
		continue;
	    }


	    if((pt = tokens[5])) { /* max version */
		if(!isdigit(*pt)) {
		    ret = CL_EMALFDB;
		    break;
		}

		if((unsigned int) atoi(pt) < cl_retflevel()) {
		    sigs--;
		    continue;
		}

	    }
	}

	if(!(pt = tokens[1]) || !isdigit(*pt)) {
	    ret = CL_EMALFDB;
	    break;
	}
	target = (unsigned short) atoi(pt);

	if(target >= CL_TARGET_TABLE_SIZE) {
	    cli_dbgmsg("Not supported target type in signature for %s\n", virname);
	    sigs--;
	    continue;
	}

	root = (*engine)->root[target];

	if(!(offset = tokens[2])) {
	    ret = CL_EMALFDB;
	    break;
	} else if(!strcmp(offset, "*")) {
	    offset = NULL;
	}

	if(!(sig = tokens[3])) {
	    ret = CL_EMALFDB;
	    break;
	}

	if((ret = cli_parse_add(root, virname, sig, 0, offset, target))) {
	    cli_errmsg("Problem parsing signature at line %d\n", line);
	    ret = CL_EMALFDB;
	    break;
	}

    }

    if(!line) {
	cli_errmsg("Empty database file\n");
	cl_free(*engine);
	return CL_EMALFDB;
    }

    if(ret) {
	cli_errmsg("Problem parsing database at line %d\n", line);
	cl_free(*engine);
	return ret;
    }

    if(signo)
	*signo += sigs;

    if(sdb && sigs && !(*engine)->sdb) {
	(*engine)->sdb = 1;
	cli_dbgmsg("*** Self protection mechanism activated.\n");
    }

    return CL_SUCCESS;
}

static int scomp(const void *a, const void *b)
{
    return *(const uint32_t *)a - *(const uint32_t *)b;
}

#define MD5_HDB	    0
#define MD5_MDB	    1
#define MD5_FP	    2
static int cli_loadmd5(FILE *fd, struct cl_engine **engine, unsigned int *signo, uint8_t mode, unsigned int options)
{
	char buffer[FILEBUFF], *pt;
	int ret = CL_SUCCESS;
	uint8_t size_field = 1, md5_field = 0, found;
	uint32_t line = 0, i;
	struct cli_md5_node *new;
	struct cli_bm_patt *bm_new;
	struct cli_matcher *md5_sect = NULL;


    if((ret = cli_initengine(engine, options))) {
	cl_free(*engine);
	return ret;
    }

    if(mode == MD5_MDB) {
	size_field = 0;
	md5_field = 1;
    }

    while(fgets(buffer, FILEBUFF, fd)) {
	line++;
	cli_chomp(buffer);

	new = (struct cli_md5_node *) cli_calloc(1, sizeof(struct cli_md5_node));
	if(!new) {
	    ret = CL_EMEM;
	    break;
	}

	if(mode == MD5_FP) /* fp */
	    new->fp = 1;

	if(!(pt = cli_strtok(buffer, md5_field, ":"))) {
	    free(new);
	    ret = CL_EMALFDB;
	    break;
	}

	if(!(new->md5 = (unsigned char *) cli_hex2str(pt))) {
	    cli_errmsg("cli_loadmd5: Malformed MD5 string at line %u\n", line);
	    free(pt);
	    free(new);
	    ret = CL_EMALFDB;
	    break;
	}
	free(pt);

	if(!(pt = cli_strtok(buffer, size_field, ":"))) {
	    free(new->md5);
	    free(new);
	    ret = CL_EMALFDB;
	    break;
	}
	new->size = atoi(pt);
	free(pt);

	if(!(new->virname = cli_strtok(buffer, 2, ":"))) {
	    free(new->md5);
	    free(new);
	    ret = CL_EMALFDB;
	    break;
	}

	if(mode == MD5_MDB) { /* section MD5 */
	    if(!(*engine)->md5_sect) {
		(*engine)->md5_sect = (struct cli_matcher *) cli_calloc(sizeof(struct cli_matcher), 1);
		if(!(*engine)->md5_sect) {
		    free(new->virname);
		    free(new->md5);
		    free(new);
		    ret = CL_EMEM;
		    break;
		}
		if((ret = cli_bm_init((*engine)->md5_sect))) {
		    cli_errmsg("cli_loadmd5: Can't initialise BM pattern matcher\n");
		    free(new->virname);
		    free(new->md5);
		    free(new);
		    break;
		}
	    }
	    md5_sect = (*engine)->md5_sect;

	    bm_new = (struct cli_bm_patt *) cli_calloc(1, sizeof(struct cli_bm_patt));
	    if(!bm_new) {
		cli_errmsg("cli_loadmd5: Can't allocate memory for bm_new\n");
		free(new->virname);
		free(new->md5);
		free(new);
		ret = CL_EMEM;
		break;
	    }

	    bm_new->pattern = new->md5;
	    bm_new->length = 16;
	    bm_new->virname = new->virname;

	    found = 0;
	    for(i = 0; i < md5_sect->soff_len; i++) {
		if(md5_sect->soff[i] == new->size) {
		    found = 1;
		    break;
		}
	    }

	    if(!found) {
		md5_sect->soff_len++;
		md5_sect->soff = (uint32_t *) cli_realloc2(md5_sect->soff, md5_sect->soff_len * sizeof(uint32_t));
		if(!md5_sect->soff) {
		    cli_errmsg("cli_loadmd5: Can't realloc md5_sect->soff\n");
		    free(bm_new->pattern);
		    free(bm_new->virname);
		    free(bm_new);
		    free(new);
		    ret = CL_EMEM;
		    break;
		}
		md5_sect->soff[md5_sect->soff_len - 1] = new->size;
	    }

	    free(new);

	    if((ret = cli_bm_addpatt(md5_sect, bm_new))) {
		cli_errmsg("cli_loadmd5: Error adding BM pattern\n");
		free(bm_new->pattern);
		free(bm_new->virname);
		free(bm_new);
		break;
	    }

	} else {
	    if(!(*engine)->md5_hlist) {
		cli_dbgmsg("cli_loadmd5: Initializing MD5 list structure\n");
		(*engine)->md5_hlist = cli_calloc(256, sizeof(struct cli_md5_node *));
		if(!(*engine)->md5_hlist) {
		    free(new->virname);
		    free(new->md5);
		    free(new);
		    ret = CL_EMEM;
		    break;
		}
	    }

	    new->next = (*engine)->md5_hlist[new->md5[0] & 0xff];
	    (*engine)->md5_hlist[new->md5[0] & 0xff] = new;
	}
    }

    if(!line) {
	cli_errmsg("cli_loadmd5: Empty database file\n");
	cl_free(*engine);
	return CL_EMALFDB;
    }

    if(ret) {
	cli_errmsg("cli_loadmd5: Problem parsing database at line %u\n", line);
	cl_free(*engine);
	return ret;
    }

    if(signo)
	*signo += line;

    if(md5_sect)
	qsort(md5_sect->soff, md5_sect->soff_len, sizeof(uint32_t), scomp);

    return CL_SUCCESS;
}

static int cli_loadmd(FILE *fd, struct cl_engine **engine, unsigned int *signo, int type, unsigned int options)
{
	char buffer[FILEBUFF], *pt;
	int line = 0, comments = 0, ret = 0, crc32;
	struct cli_meta_node *new;


    if((ret = cli_initengine(engine, options))) {
	cl_free(*engine);
	return ret;
    }

    while(fgets(buffer, FILEBUFF, fd)) {
	line++;
	if(buffer[0] == '#') {
	    comments++;
	    continue;
	}

	cli_chomp(buffer);

	new = (struct cli_meta_node *) cli_calloc(1, sizeof(struct cli_meta_node));
	if(!new) {
	    ret = CL_EMEM;
	    break;
	}

	if(!(new->virname = cli_strtok(buffer, 0, ":"))) {
	    free(new);
	    ret = CL_EMALFDB;
	    break;
	}

	if(!(pt = cli_strtok(buffer, 1, ":"))) {
	    free(new->virname);
	    free(new);
	    ret = CL_EMALFDB;
	    break;
	} else {
	    new->encrypted = atoi(pt);
	    free(pt);
	}

	if(!(new->filename = cli_strtok(buffer, 2, ":"))) {
	    free(new->virname);
	    free(new);
	    ret = CL_EMALFDB;
	    break;
	} else {
	    if(!strcmp(new->filename, "*")) {
		free(new->filename);
		new->filename = NULL;
	    }
	}

	if(!(pt = cli_strtok(buffer, 3, ":"))) {
	    free(new->filename);
	    free(new->virname);
	    free(new);
	    ret = CL_EMALFDB;
	    break;
	} else {
	    if(!strcmp(pt, "*"))
		new->size = -1;
	    else
		new->size = atoi(pt);
	    free(pt);
	}

	if(!(pt = cli_strtok(buffer, 4, ":"))) {
	    free(new->filename);
	    free(new->virname);
	    free(new);
	    ret = CL_EMALFDB;
	    break;
	} else {
	    if(!strcmp(pt, "*"))
		new->csize = -1;
	    else
		new->csize = atoi(pt);
	    free(pt);
	}

	if(!(pt = cli_strtok(buffer, 5, ":"))) {
	    free(new->filename);
	    free(new->virname);
	    free(new);
	    ret = CL_EMALFDB;
	    break;
	} else {
	    if(!strcmp(pt, "*")) {
		new->crc32 = 0;
	    } else {
		crc32 = cli_hex2num(pt);
		if(crc32 == -1) {
		    ret = CL_EMALFDB;
		    break;
		}
		new->crc32 = (unsigned int) crc32;
	    }
	    free(pt);
	}

	if(!(pt = cli_strtok(buffer, 6, ":"))) {
	    free(new->filename);
	    free(new->virname);
	    free(new);
	    ret = CL_EMALFDB;
	    break;
	} else {
	    if(!strcmp(pt, "*"))
		new->method = -1;
	    else
		new->method = atoi(pt);
	    free(pt);
	}

	if(!(pt = cli_strtok(buffer, 7, ":"))) {
	    free(new->filename);
	    free(new->virname);
	    free(new);
	    ret = CL_EMALFDB;
	    break;
	} else {
	    if(!strcmp(pt, "*"))
		new->fileno = 0;
	    else
		new->fileno = atoi(pt);
	    free(pt);
	}

	if(!(pt = cli_strtok(buffer, 8, ":"))) {
	    free(new->filename);
	    free(new->virname);
	    free(new);
	    ret = CL_EMALFDB;
	    break;
	} else {
	    if(!strcmp(pt, "*"))
		new->maxdepth = 0;
	    else
		new->maxdepth = atoi(pt);
	    free(pt);
	}

	if(type == 1) {
	    new->next = (*engine)->zip_mlist;
	    (*engine)->zip_mlist = new;
	} else {
	    new->next = (*engine)->rar_mlist;
	    (*engine)->rar_mlist = new;
	}
    }

    if(!line) {
	cli_errmsg("Empty database file\n");
	cl_free(*engine);
	return CL_EMALFDB;
    }

    if(ret) {
	cli_errmsg("Problem parsing database at line %d\n", line);
	cl_free(*engine);
	return ret;
    }

    if(signo)
	*signo += (line - comments);

    return CL_SUCCESS;
}

static int cli_loaddbdir(const char *dirname, struct cl_engine **engine, unsigned int *signo, unsigned int options);

static int cli_load(const char *filename, struct cl_engine **engine, unsigned int *signo, unsigned int options)
{
	FILE *fd;
	int ret = CL_SUCCESS;
	uint8_t skipped = 0;


    if((fd = fopen(filename, "rb")) == NULL) {
	cli_errmsg("cli_load(): Can't open file %s\n", filename);
	return CL_EOPEN;
    }

    if(cli_strbcasestr(filename, ".db")) {
	ret = cli_loaddb(fd, engine, signo, options);

    } else if(cli_strbcasestr(filename, ".cvd")) {
	    int warn = 0;

	if(strstr(filename, "daily.cvd"))
	    warn = 1;

	ret = cli_cvdload(fd, engine, signo, warn, options);

    } else if(cli_strbcasestr(filename, ".hdb")) {
	ret = cli_loadmd5(fd, engine, signo, MD5_HDB, options);

    } else if(cli_strbcasestr(filename, ".hdu")) {
	if(options & CL_DB_PUA)
	    ret = cli_loadmd5(fd, engine, signo, MD5_HDB, options);
	else
	    skipped = 1;

    } else if(cli_strbcasestr(filename, ".fp")) {
	ret = cli_loadmd5(fd, engine, signo, MD5_FP, options);

    } else if(cli_strbcasestr(filename, ".mdb")) {
	ret = cli_loadmd5(fd, engine, signo, MD5_MDB, options);

    } else if(cli_strbcasestr(filename, ".mdu")) {
	if(options & CL_DB_PUA)
	    ret = cli_loadmd5(fd, engine, signo, MD5_MDB, options);
	else
	    skipped = 1;

    } else if(cli_strbcasestr(filename, ".ndb")) {
	ret = cli_loadndb(fd, engine, signo, 0, options);

    } else if(cli_strbcasestr(filename, ".ndu")) {
	if(!(options & CL_DB_PUA))
	    skipped = 1;
	else
	    ret = cli_loadndb(fd, engine, signo, 0, options);

    } else if(cli_strbcasestr(filename, ".sdb")) {
	ret = cli_loadndb(fd, engine, signo, 1, options);

    } else if(cli_strbcasestr(filename, ".zmd")) {
	ret = cli_loadmd(fd, engine, signo, 1, options);

    } else if(cli_strbcasestr(filename, ".rmd")) {
	ret = cli_loadmd(fd, engine, signo, 2, options);

    } else if(cli_strbcasestr(filename, ".cfg")) {
	ret = cli_dconf_load(fd, engine, options);

    } else if(cli_strbcasestr(filename, ".wdb")) {
	if(options & CL_DB_PHISHING_URLS)
	    ret = cli_loadwdb(fd, engine, options);
	else
	    skipped = 1;
    } else if(cli_strbcasestr(filename, ".pdb")) {
	if(options & CL_DB_PHISHING_URLS)
	    ret = cli_loadpdb(fd, engine, options);
	else
	    skipped = 1;
    } else {
	cli_dbgmsg("cli_load: unknown extension - assuming old database format\n");
	ret = cli_loaddb(fd, engine, signo, options);
    }

    if(ret) {
	cli_errmsg("Can't load %s: %s\n", filename, cl_strerror(ret));
    } else  {
	if(skipped)
	    cli_dbgmsg("%s skipped\n", filename);
	else
	    cli_dbgmsg("%s loaded\n", filename);
    }

    fclose(fd);
    return ret;
}

int cl_loaddb(const char *filename, struct cl_engine **engine, unsigned int *signo) {
    return cli_load(filename, engine, signo, CL_DB_STDOPT);
}

#define CLI_DBEXT(ext)				\
    (						\
	cli_strbcasestr(ext, ".db")    ||	\
	cli_strbcasestr(ext, ".db2")   ||	\
	cli_strbcasestr(ext, ".db3")   ||	\
	cli_strbcasestr(ext, ".hdb")   ||	\
	cli_strbcasestr(ext, ".hdu")   ||	\
	cli_strbcasestr(ext, ".fp")    ||	\
	cli_strbcasestr(ext, ".mdb")   ||	\
	cli_strbcasestr(ext, ".mdu")   ||	\
	cli_strbcasestr(ext, ".ndb")   ||	\
	cli_strbcasestr(ext, ".ndu")   ||	\
	cli_strbcasestr(ext, ".sdb")   ||	\
	cli_strbcasestr(ext, ".zmd")   ||	\
	cli_strbcasestr(ext, ".rmd")   ||	\
	cli_strbcasestr(ext, ".pdb")   ||	\
	cli_strbcasestr(ext, ".wdb")   ||	\
	cli_strbcasestr(ext, ".inc")   ||	\
	cli_strbcasestr(ext, ".cvd")		\
    )

static int cli_loaddbdir_l(const char *dirname, struct cl_engine **engine, unsigned int *signo, unsigned int options)
{
	DIR *dd;
	struct dirent *dent;
#if defined(HAVE_READDIR_R_3) || defined(HAVE_READDIR_R_2)
	union {
	    struct dirent d;
	    char b[offsetof(struct dirent, d_name) + NAME_MAX + 1];
	} result;
#endif
	struct stat sb;
	char *dbfile;
	int ret = CL_ESUPPORT;


    cli_dbgmsg("Loading databases from %s\n", dirname);

    /* check for and load daily.cfg */
    dbfile = (char *) cli_malloc(strlen(dirname) + 11);
    if(!dbfile)
	return CL_EMEM;
    sprintf(dbfile, "%s/daily.cfg", dirname);
    if(stat(dbfile, &sb) != -1) {
	if((ret = cli_load(dbfile, engine, signo, options))) {
	    free(dbfile);
	    return ret;
	}
    }
    free(dbfile);

    if((dd = opendir(dirname)) == NULL) {
        cli_errmsg("cli_loaddbdir(): Can't open directory %s\n", dirname);
        return CL_EOPEN;
    }

#ifdef HAVE_READDIR_R_3
    while(!readdir_r(dd, &result.d, &dent) && dent) {
#elif defined(HAVE_READDIR_R_2)
    while((dent = (struct dirent *) readdir_r(dd, &result.d))) {
#else
    while((dent = readdir(dd))) {
#endif
#if	(!defined(C_INTERIX)) && (!defined(C_WINDOWS)) && (!defined(C_CYGWIN))
	if(dent->d_ino)
#endif
	{
	    if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..") && CLI_DBEXT(dent->d_name)) {

		dbfile = (char *) cli_malloc(strlen(dent->d_name) + strlen(dirname) + 2);

		if(!dbfile) {
		    cli_dbgmsg("cli_loaddbdir(): dbfile == NULL\n");
		    closedir(dd);
		    return CL_EMEM;
		}
		sprintf(dbfile, "%s/%s", dirname, dent->d_name);

		if(cli_strbcasestr(dbfile, ".inc"))
		    ret = cli_loaddbdir(dbfile, engine, signo, options);
		else
		    ret = cli_load(dbfile, engine, signo, options);

		if(ret) {
		    cli_dbgmsg("cli_loaddbdir(): error loading database %s\n", dbfile);
		    free(dbfile);
		    closedir(dd);
		    return ret;
		}
		free(dbfile);
	    }
	}
    }

    closedir(dd);
    if(ret == CL_ESUPPORT)
	cli_errmsg("cli_loaddb(): No supported database files found in %s\n", dirname);

    return ret;
}

static int cli_loaddbdir(const char *dirname, struct cl_engine **engine, unsigned int *signo, unsigned int options)
{
	int ret, try = 0, lock;


    cli_dbgmsg("cli_loaddbdir: Acquiring dbdir lock\n");
    while((lock = cli_readlockdb(dirname, 0)) == CL_ELOCKDB) {
#ifdef C_WINDOWS
	Sleep(5);
#else
	sleep(5);
#endif
	if(try++ > 24) {
	    cli_errmsg("cl_load(): Unable to lock database directory: %s\n", dirname);
	    return CL_ELOCKDB;
	}
    }

    ret = cli_loaddbdir_l(dirname, engine, signo, options);
    if(lock == CL_SUCCESS)
	cli_unlockdb(dirname);

    return ret;
}

int cl_loaddbdir(const char *dirname, struct cl_engine **engine, unsigned int *signo) {
    return cli_loaddbdir(dirname, engine, signo, CL_DB_STDOPT);
}

int cl_load(const char *path, struct cl_engine **engine, unsigned int *signo, unsigned int options)
{
	struct stat sb;
	int ret;


    if(stat(path, &sb) == -1) {
        cli_errmsg("cl_loaddbdir(): Can't get status of %s\n", path);
        return CL_EIO;
    }

    if((ret = cli_initengine(engine, options))) {
	cl_free(*engine);
	return ret;
    }

    (*engine)->dboptions = options;

    switch(sb.st_mode & S_IFMT) {
	case S_IFREG: 
	    ret = cli_load(path, engine, signo, options);
	    break;

	case S_IFDIR:
	    ret = cli_loaddbdir(path, engine, signo, options);
	    break;

	default:
	    cli_errmsg("cl_load(%s): Not supported database file type\n", path);
	    return CL_EOPEN;
    }

    return ret;
}

const char *cl_retdbdir(void)
{
    return DATADIR;
}

int cl_statinidir(const char *dirname, struct cl_stat *dbstat)
{
	DIR *dd;
	const struct dirent *dent;
#if defined(HAVE_READDIR_R_3) || defined(HAVE_READDIR_R_2)
	union {
	    struct dirent d;
	    char b[offsetof(struct dirent, d_name) + NAME_MAX + 1];
	} result;
#endif
        char *fname;


    if(dbstat) {
	dbstat->entries = 0;
	dbstat->stattab = NULL;
	dbstat->statdname = NULL;
	dbstat->dir = cli_strdup(dirname);
    } else {
        cli_errmsg("cl_statdbdir(): Null argument passed.\n");
	return CL_ENULLARG;
    }

    if((dd = opendir(dirname)) == NULL) {
        cli_errmsg("cl_statdbdir(): Can't open directory %s\n", dirname);
	cl_statfree(dbstat);
        return CL_EOPEN;
    }

    cli_dbgmsg("Stat()ing files in %s\n", dirname);

#ifdef HAVE_READDIR_R_3
    while(!readdir_r(dd, &result.d, &dent) && dent) {
#elif defined(HAVE_READDIR_R_2)
    while((dent = (struct dirent *) readdir_r(dd, &result.d))) {
#else
    while((dent = readdir(dd))) {
#endif
#if	(!defined(C_INTERIX)) && (!defined(C_WINDOWS)) && (!defined(C_CYGWIN))
	if(dent->d_ino)
#endif
	{
	    if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..") && CLI_DBEXT(dent->d_name)) {
		dbstat->entries++;
		dbstat->stattab = (struct stat *) cli_realloc2(dbstat->stattab, dbstat->entries * sizeof(struct stat));
		if(!dbstat->stattab) {
		    cl_statfree(dbstat);
		    closedir(dd);
		    return CL_EMEM;
		}

#if defined(C_INTERIX) || defined(C_OS2)
		dbstat->statdname = (char **) cli_realloc2(dbstat->statdname, dbstat->entries * sizeof(char *));
		if(!dbstat->statdname) {
		    cl_statfree(dbstat);
		    closedir(dd);
		    return CL_EMEM;
		}
#endif

                fname = cli_malloc(strlen(dirname) + strlen(dent->d_name) + 32);
		if(!fname) {
		    cl_statfree(dbstat);
		    closedir(dd);
		    return CL_EMEM;
		}

		if(cli_strbcasestr(dent->d_name, ".inc")) {
		    sprintf(fname, "%s/%s/%s.info", dirname, dent->d_name, strstr(dent->d_name, "daily") ? "daily" : "main");
		} else {
		    sprintf(fname, "%s/%s", dirname, dent->d_name);
		}
#if defined(C_INTERIX) || defined(C_OS2)
		dbstat->statdname[dbstat->entries - 1] = (char *) cli_malloc(strlen(dent->d_name) + 1);
		if(!dbstat->statdname[dbstat->entries - 1]) {
		    cl_statfree(dbstat);
		    closedir(dd);
		    return CL_EMEM;
		}

		strcpy(dbstat->statdname[dbstat->entries - 1], dent->d_name);
#endif
		stat(fname, &dbstat->stattab[dbstat->entries - 1]);
		free(fname);
	    }
	}
    }

    closedir(dd);
    return CL_SUCCESS;
}

int cl_statchkdir(const struct cl_stat *dbstat)
{
	DIR *dd;
	struct dirent *dent;
#if defined(HAVE_READDIR_R_3) || defined(HAVE_READDIR_R_2)
	union {
	    struct dirent d;
	    char b[offsetof(struct dirent, d_name) + NAME_MAX + 1];
	} result;
#endif
	struct stat sb;
	unsigned int i, found;
	char *fname;


    if(!dbstat || !dbstat->dir) {
        cli_errmsg("cl_statdbdir(): Null argument passed.\n");
	return CL_ENULLARG;
    }

    if((dd = opendir(dbstat->dir)) == NULL) {
        cli_errmsg("cl_statdbdir(): Can't open directory %s\n", dbstat->dir);
        return CL_EOPEN;
    }

    cli_dbgmsg("Stat()ing files in %s\n", dbstat->dir);

#ifdef HAVE_READDIR_R_3
    while(!readdir_r(dd, &result.d, &dent) && dent) {
#elif defined(HAVE_READDIR_R_2)
    while((dent = (struct dirent *) readdir_r(dd, &result.d))) {
#else
    while((dent = readdir(dd))) {
#endif
#if	(!defined(C_INTERIX)) && (!defined(C_WINDOWS)) && (!defined(C_CYGWIN))
	if(dent->d_ino)
#endif
	{
	    if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..") && CLI_DBEXT(dent->d_name)) {
                fname = cli_malloc(strlen(dbstat->dir) + strlen(dent->d_name) + 32);
		if(!fname) {
		    closedir(dd);
		    return CL_EMEM;
		}

		if(cli_strbcasestr(dent->d_name, ".inc")) {
		    sprintf(fname, "%s/%s/%s.info", dbstat->dir, dent->d_name, strstr(dent->d_name, "daily") ? "daily" : "main");
		} else {
		    sprintf(fname, "%s/%s", dbstat->dir, dent->d_name);
		}
		stat(fname, &sb);
		free(fname);

		found = 0;
		for(i = 0; i < dbstat->entries; i++)
#if defined(C_INTERIX) || defined(C_OS2)
		    if(!strcmp(dbstat->statdname[i], dent->d_name)) {
#else
		    if(dbstat->stattab[i].st_ino == sb.st_ino) {
#endif
			found = 1;
			if(dbstat->stattab[i].st_mtime != sb.st_mtime) {
			    closedir(dd);
			    return 1;
			}
		    }

		if(!found) {
		    closedir(dd);
		    return 1;
		}
	    }
	}
    }

    closedir(dd);
    return CL_SUCCESS;
}

int cl_statfree(struct cl_stat *dbstat)
{

    if(dbstat) {

#if defined(C_INTERIX) || defined(C_OS2)
	    int i;

	if(dbstat->statdname) {
	    for(i = 0; i < dbstat->entries; i++) {
		if(dbstat->statdname[i])
		    free(dbstat->statdname[i]);
		dbstat->statdname[i] = NULL;
	    }
	    free(dbstat->statdname);
	    dbstat->statdname = NULL;
	}
#endif

	if(dbstat->stattab) {
	    free(dbstat->stattab);
	    dbstat->stattab = NULL;
	}
	dbstat->entries = 0;

	if(dbstat->dir) {
	    free(dbstat->dir);
	    dbstat->dir = NULL;
	}
    } else {
        cli_errmsg("cl_statfree(): Null argument passed\n");
	return CL_ENULLARG;
    }

    return CL_SUCCESS;
}

void cl_free(struct cl_engine *engine)
{
	int i;
	struct cli_md5_node *md5pt, *md5h;
	struct cli_meta_node *metapt, *metah;
	struct cli_matcher *root;


    if(!engine) {
	cli_errmsg("cl_free: engine == NULL\n");
	return;
    }

#ifdef CL_THREAD_SAFE
    pthread_mutex_lock(&cli_ref_mutex);
#endif

    engine->refcount--;
    if(engine->refcount) {
#ifdef CL_THREAD_SAFE
	pthread_mutex_unlock(&cli_ref_mutex);
#endif
	return;
    }

#ifdef CL_THREAD_SAFE
    pthread_mutex_unlock(&cli_ref_mutex);
#endif

    if(engine->root) {
	for(i = 0; i < CL_TARGET_TABLE_SIZE; i++) {
	    if((root = engine->root[i])) {
		if(!root->ac_only)
		    cli_bm_free(root);
		cli_ac_free(root);
		free(root);
	    }
	}
	free(engine->root);
    }

    if(engine->md5_hlist) {
	for(i = 0; i < 256; i++) {
	    md5pt = engine->md5_hlist[i];
	    while(md5pt) {
		md5h = md5pt;
		md5pt = md5pt->next;
		free(md5h->md5);
		free(md5h->virname);
		free(md5h);
	    }
	}
	free(engine->md5_hlist);
    }

    if((root = engine->md5_sect)) {
	cli_bm_free(root);
	free(root->soff);
	free(root);
    }

    metapt = engine->zip_mlist;
    while(metapt) {
	metah = metapt;
	metapt = metapt->next;
	free(metah->virname);
	if(metah->filename)
	    free(metah->filename);
	free(metah);
    }

    metapt = engine->rar_mlist;
    while(metapt) {
	metah = metapt;
	metapt = metapt->next;
	free(metah->virname);
	if(metah->filename)
	    free(metah->filename);
	free(metah);
    }

    if(((struct cli_dconf *) engine->dconf)->phishing & PHISHING_CONF_ENGINE)
	phishing_done(engine);

    if(engine->dconf)
	free(engine->dconf);

    cli_freelocks();
    free(engine);
}

int cl_build(struct cl_engine *engine)
{
	int i, ret;
	struct cli_matcher *root;


    if((ret = cli_addtypesigs(engine)))
	return ret;

    for(i = 0; i < CL_TARGET_TABLE_SIZE; i++)
	if((root = engine->root[i]))
	    cli_ac_buildtrie(root);
    /* FIXME: check return values of cli_ac_buildtree */

    cli_dconf_print(engine->dconf);

    return CL_SUCCESS;
}

struct cl_engine *cl_dup(struct cl_engine *engine)
{
    if(!engine) {
	cli_errmsg("cl_dup: engine == NULL\n");
	return NULL;
    }

#ifdef CL_THREAD_SAFE
    pthread_mutex_lock(&cli_ref_mutex);
#endif

    engine->refcount++;

#ifdef CL_THREAD_SAFE
    pthread_mutex_unlock(&cli_ref_mutex);
#endif

    return engine;
}

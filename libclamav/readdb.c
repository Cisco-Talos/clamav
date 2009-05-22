/*
 *  Copyright (C) 2007-2008 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm
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
#include <zlib.h>

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
#include "filetypes.h"
#include "filetypes_int.h"
#include "readdb.h"
#include "cltypes.h"
#include "default.h"

#include "phishcheck.h"
#include "phish_whitelist.h"
#include "phish_domaincheck_db.h"
#include "regex_list.h"
#include "hashtab.h"

#if defined(HAVE_READDIR_R_3) || defined(HAVE_READDIR_R_2)
#include <limits.h>
#include <stddef.h>
#endif

#include "mpool.h"

#ifdef CL_THREAD_SAFE
#  include <pthread.h>
static pthread_mutex_t cli_ref_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

struct cli_ignsig {
    char *dbname, *signame;
    unsigned int line;
    struct cli_ignsig *next;
};

struct cli_ignored {
    struct hashset hs;
    struct cli_ignsig *list;
};

char *cli_virname(char *virname, unsigned int official)
{
	char *newname, *pt;


    if(!virname)
	return NULL;

    if((pt = strstr(virname, " (Clam)")))
	*pt='\0';

    if(!virname[0]) {
	cli_errmsg("cli_virname: Empty virus name\n");
	return NULL;
    }

    if(official)
        return cli_strdup(virname);

    newname = (char *) cli_malloc(strlen(virname) + 11 + 1);
    if(!newname) {
      cli_errmsg("cli_virname: Can't allocate memory for newname\n");
      return NULL;
    }
    sprintf(newname, "%s.UNOFFICIAL", virname);
    return newname;
}

int cli_parse_add(struct cli_matcher *root, const char *virname, const char *hexsig, uint16_t rtype, uint16_t type, const char *offset, uint8_t target, const uint32_t *lsigid, unsigned int options)
{
	struct cli_bm_patt *bm_new;
	char *pt, *hexcpy, *start, *n;
	int ret, asterisk = 0;
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

	    if((ret = cli_ac_addsig(root, virname, start, root->ac_partsigs, parts, i, rtype, type, mindist, maxdist, offset, lsigid, options))) {
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
		if(!cli_isnumber(pt) || (mindist = maxdist = atoi(pt)) < 0) {
		    error = 1;
		    break;
		}
	    } else {
		if((n = cli_strtok(pt, 0, "-"))) {
		    if(!cli_isnumber(n) || (mindist = atoi(n)) < 0) {
			error = 1;
			free(n);
			break;
		    }
		    free(n);
		}

		if((n = cli_strtok(pt, 1, "-"))) {
		    if(!cli_isnumber(n) || (maxdist = atoi(n)) < 0) {
			error = 1;
			free(n);
			break;
		    }
		    free(n);
		}

		if((n = cli_strtok(pt, 2, "-"))) { /* strict check */
		    error = 1;
		    free(n);
		    break;
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

	    if((ret = cli_ac_addsig(root, virname, pt, root->ac_partsigs, parts, i, rtype, type, 0, 0, offset, lsigid, options))) {
		cli_errmsg("cli_parse_add(): Problem adding signature (2).\n");
		free(pt);
		return ret;
	    }

	    free(pt);
	}

    } else if(root->ac_only || strpbrk(hexsig, "?(") || type || lsigid) {
	if((ret = cli_ac_addsig(root, virname, hexsig, 0, 0, 0, rtype, type, 0, 0, offset, lsigid, options))) {
	    cli_errmsg("cli_parse_add(): Problem adding signature (3).\n");
	    return ret;
	}

    } else {
	bm_new = (struct cli_bm_patt *) mpool_calloc(root->mempool, 1, sizeof(struct cli_bm_patt));
	if(!bm_new)
	    return CL_EMEM;
        bm_new->pattern = (unsigned char *) cli_mpool_hex2str(root->mempool, hexsig);
	if(!bm_new->pattern) {
	    mpool_free(root->mempool, bm_new);
	    return CL_EMALFDB;
	}
	bm_new->length = strlen(hexsig) / 2;

	bm_new->virname = cli_mpool_virname(root->mempool, (char *) virname, options & CL_DB_OFFICIAL);
	if(!bm_new->virname) {
	    mpool_free(root->mempool, bm_new->pattern);
	    mpool_free(root->mempool, bm_new);
	    return CL_EMEM;
	}

	if(offset) {
	    bm_new->offset = cli_mpool_strdup(root->mempool, offset);
	    if(!bm_new->offset) {
	        mpool_free(root->mempool, bm_new->pattern);
		mpool_free(root->mempool, bm_new->virname);
		mpool_free(root->mempool, bm_new);
		return CL_EMEM;
	    }
	}

	bm_new->target = target;

	if(bm_new->length > root->maxpatlen)
	    root->maxpatlen = bm_new->length;

	if((ret = cli_bm_addpatt(root, bm_new))) {
	    cli_errmsg("cli_parse_add(): Problem adding signature (4).\n");
	    mpool_free(root->mempool, bm_new->pattern);
	    mpool_free(root->mempool, bm_new->virname);
	    mpool_free(root->mempool, bm_new);
	    return ret;
	}
    }

    return CL_SUCCESS;
}

static int cli_initroots(struct cl_engine *engine, unsigned int options)
{
	int i, ret;
	struct cli_matcher *root;


    for(i = 0; i < CLI_MTARGETS; i++) {
	if(!engine->root[i]) {
	    cli_dbgmsg("Initializing engine->root[%d]\n", i);
	    root = engine->root[i] = (struct cli_matcher *) mpool_calloc(engine->mempool, 1, sizeof(struct cli_matcher));
#ifdef USE_MPOOL
	    root->mempool = engine->mempool;
#endif
	    if(!root) {
		cli_errmsg("cli_initroots: Can't allocate memory for cli_matcher\n");
		return CL_EMEM;
	    }

	    if(cli_mtargets[i].ac_only || engine->ac_only)
		root->ac_only = 1;

	    cli_dbgmsg("Initialising AC pattern matcher of root[%d]\n", i);
	    if((ret = cli_ac_init(root, engine->ac_mindepth, engine->ac_maxdepth))) {
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

char *cli_dbgets(char *buff, unsigned int size, FILE *fs, struct cli_dbio *dbio)
{
    if(fs) {
	return fgets(buff, size, fs);

    } else {
	    char *pt;
	    unsigned int bs;

	if(!dbio->size)
	    return NULL;

	bs = dbio->size < size ? dbio->size + 1 : size;
	if(dbio->gzs)
	    pt = gzgets(dbio->gzs, buff, bs);
	else
	    pt = fgets(buff, bs, dbio->fs);

	dbio->size -= strlen(buff);
	if(!pt)
	    cli_errmsg("cli_dbgets: Preliminary end of data\n");
	return pt;
    }
}

static int cli_chkign(const struct cli_ignored *ignored, const char *dbname, unsigned int line, const char *signame)
{
	struct cli_ignsig *pt;

    if(!ignored || !dbname || !signame)
	return 0;

    if(hashset_contains(&ignored->hs, line)) {
	pt = ignored->list;
	while(pt) {
	    if(pt->line == line && !strcmp(pt->dbname, dbname) && !strcmp(pt->signame, signame)) {
		cli_dbgmsg("Skipping signature %s @ %s:%u\n", signame, dbname, line);
		return 1;
	    }
	    pt = pt->next;
	}
    }

    return 0;
}

static int cli_chkpua(const char *signame, const char *pua_cats, unsigned int options)
{
	char cat[32], *pt;
	const char *sig;
	int ret;

    if(strncmp(signame, "PUA.", 4)) {
	cli_dbgmsg("Skipping signature %s - no PUA prefix\n", signame);
	return 1;
    }
    sig = signame + 3;
    if(!(pt = strchr(sig + 1, '.'))) {
	cli_dbgmsg("Skipping signature %s - bad syntax\n", signame);
	return 1;
    }

    if((unsigned int) (pt - sig + 2) > sizeof(cat)) {
	cli_dbgmsg("Skipping signature %s - too long category name\n", signame);
	return 1;
    }

    strncpy(cat, sig, pt - signame + 1);
    cat[pt - sig + 1] = 0;
    pt = strstr(pua_cats, cat);

    if(options & CL_DB_PUA_INCLUDE)
	ret = pt ? 0 : 1;
    else
	ret = pt ? 1 : 0;

    if(ret)
	cli_dbgmsg("Skipping PUA signature %s - excluded category\n", signame);

    return ret;
}

static int cli_loaddb(FILE *fs, struct cl_engine *engine, unsigned int *signo, unsigned int options, struct cli_dbio *dbio, const char *dbname)
{
	char buffer[FILEBUFF], *pt, *start;
	unsigned int line = 0, sigs = 0;
	int ret = 0;
	struct cli_matcher *root;


    if((ret = cli_initroots(engine, options)))
	return ret;

    root = engine->root[0];

    while(cli_dbgets(buffer, FILEBUFF, fs, dbio)) {
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

	if(engine->ignored && cli_chkign(engine->ignored, dbname, line, start))
	    continue;

	if(*pt == '=') continue;

	if((ret = cli_parse_add(root, start, pt, 0, 0, NULL, 0, NULL, options))) {
	    ret = CL_EMALFDB;
	    break;
	}
	sigs++;
    }

    if(!line) {
	cli_errmsg("Empty database file\n");
	return CL_EMALFDB;
    }

    if(ret) {
	cli_errmsg("Problem parsing database at line %d\n", line);
	return ret;
    }

    if(signo)
	*signo += sigs;

    return CL_SUCCESS;
}

static int cli_loadwdb(FILE *fs, struct cl_engine *engine, unsigned int options, struct cli_dbio *dbio)
{
	int ret = 0;


    if(!(engine->dconf->phishing & PHISHING_CONF_ENGINE))
	return CL_SUCCESS;

    if(!engine->whitelist_matcher) {
	if((ret = init_whitelist(engine))) {
	    return ret;
	}
    }

    if((ret = load_regex_matcher(engine->whitelist_matcher, fs, NULL, options, 1, dbio))) {
	return ret;
    }

    return CL_SUCCESS;
}

static int cli_loadpdb(FILE *fs, struct cl_engine *engine, unsigned int *signo, unsigned int options, struct cli_dbio *dbio)
{
	int ret = 0;


    if(!(engine->dconf->phishing & PHISHING_CONF_ENGINE))
	return CL_SUCCESS;

    if(!engine->domainlist_matcher) {
	if((ret = init_domainlist(engine))) {
	    return ret;
	}
    }

    if((ret = load_regex_matcher(engine->domainlist_matcher, fs, signo, options, 0, dbio))) {
	return ret;
    }

    return CL_SUCCESS;
}

static int cli_checkoffset(const char *offset, unsigned int type)
{
	unsigned int foo;
	const char *pt = offset;

    if(isdigit(*offset)) {
	while(*pt++)
	    if(!strchr("0123456789,", *pt))
		return 1;
	return 0;
    }

    if(!strncmp(offset, "EOF-", 4))
	return 0;

    if((type == 1 || type == 6) && (!strncmp(offset, "EP+", 3) || !strncmp(offset, "EP-", 3) || (sscanf(offset, "SL+%u", &foo) == 1) || (sscanf(offset, "S%u+%u", &foo, &foo) == 2)))
	return 0;

    return 1;
}

#define NDB_TOKENS 6
static int cli_loadndb(FILE *fs, struct cl_engine *engine, unsigned int *signo, unsigned short sdb, unsigned int options, struct cli_dbio *dbio, const char *dbname)
{
	const char *tokens[NDB_TOKENS + 1];
	char buffer[FILEBUFF];
	const char *sig, *virname, *offset, *pt;
	struct cli_matcher *root;
	int line = 0, sigs = 0, ret = 0, tokens_count;
	unsigned short target;
	unsigned int phish = options & CL_DB_PHISHING;


    if((ret = cli_initroots(engine, options)))
	return ret;

    while(cli_dbgets(buffer, FILEBUFF, fs, dbio)) {
	line++;

	if(!strncmp(buffer, "Exploit.JPEG.Comment", 20)) /* temporary */
	    continue;

	if(!phish)
	    if(!strncmp(buffer, "HTML.Phishing", 13) || !strncmp(buffer, "Email.Phishing", 14))
		continue;

	cli_chomp(buffer);

	tokens_count = cli_strtokenize(buffer, ':', NDB_TOKENS + 1, tokens);
	/* FIXME: re-enable after fixing invalid sig @ main.ndb:53467 */
	if(tokens_count < 4 /*|| tokens_count > 6*/) {
	    ret = CL_EMALFDB;
	    break;
	}

	virname = tokens[0];

	if(engine->pua_cats && (options & CL_DB_PUA_MODE) && (options & (CL_DB_PUA_INCLUDE | CL_DB_PUA_EXCLUDE)))
	    if(cli_chkpua(virname, engine->pua_cats, options))
		continue;

	if(engine->ignored && cli_chkign(engine->ignored, dbname, line, virname))
	    continue;

	if(tokens_count > 4) { /* min version */
	    pt = tokens[4];
	    if(!isdigit(*pt)) {
		ret = CL_EMALFDB;
		break;
	    }

	    if((unsigned int) atoi(pt) > cl_retflevel()) {
		cli_dbgmsg("Signature for %s not loaded (required f-level: %d)\n", virname, atoi(pt));
		continue;
	    }

	    if(tokens_count == 6) { /* max version */
		pt = tokens[5];
		if(!isdigit(*pt)) {
		    ret = CL_EMALFDB;
		    break;
		}

		if((unsigned int) atoi(pt) < cl_retflevel()) {
		    continue;
		}
	    }
	}

	if(!(pt = tokens[1]) || !isdigit(*pt)) {
	    ret = CL_EMALFDB;
	    break;
	}
	target = (unsigned short) atoi(pt);

	if(target >= CLI_MTARGETS) {
	    cli_dbgmsg("Not supported target type in signature for %s\n", virname);
	    continue;
	}

	root = engine->root[target];

	offset = tokens[2];
	if(!strcmp(offset, "*"))
	    offset = NULL;

	if(offset && cli_checkoffset(offset, target)) {
	    cli_errmsg("Incorrect offset '%s' for signature type-%u\n", offset, target);
	    ret = CL_EMALFDB;
	    break;
	}

	sig = tokens[3];

	if((ret = cli_parse_add(root, virname, sig, 0, 0, offset, target, NULL, options))) {
	    ret = CL_EMALFDB;
	    break;
	}
	sigs++;
    }

    if(!line) {
	cli_errmsg("Empty database file\n");
	return CL_EMALFDB;
    }

    if(ret) {
	cli_errmsg("Problem parsing database at line %d\n", line);
	return ret;
    }

    if(signo)
	*signo += sigs;

    if(sdb && sigs && !engine->sdb) {
	engine->sdb = 1;
	cli_dbgmsg("*** Self protection mechanism activated.\n");
    }

    return CL_SUCCESS;
}

struct lsig_attrib {
    const char *name;
    unsigned int type;
    void **pt;
};

/* TODO: rework this */
static int lsigattribs(char *attribs, struct cli_lsig_tdb *tdb)
{
	struct lsig_attrib attrtab[] = {
#define ATTRIB_TOKENS	2
	    { "Target",	    CLI_TDB_UINT,	(void **) &tdb->target	    },
	    { "Engine",	    CLI_TDB_RANGE,	(void **) &tdb->engine	    },
/*
	    { "NoS",	    CLI_TDB_RANGE,	(void **) &tdb->nos	    },
	    { "EP",	    CLI_TDB_RANGE,	(void **) &tdb->ep	    },
	    { "SectOff",    CLI_TDB_RANGE2,	(void **) &tdb->sectoff	    },
	    { "SectRVA",    CLI_TDB_RANGE2,	(void **) &tdb->sectrva	    },
	    { "SectVSZ",    CLI_TDB_RANGE2,	(void **) &tdb->sectvsz	    },
	    { "SectRAW",    CLI_TDB_RANGE2,	(void **) &tdb->sectraw	    },
	    { "SectRSZ",    CLI_TDB_RANGE2,	(void **) &tdb->sectrsz	    },
	    { "SectURVA",   CLI_TDB_RANGE2,	(void **) &tdb->secturva    },
	    { "SectUVSZ",   CLI_TDB_RANGE2,	(void **) &tdb->sectuvsz    },
	    { "SectURAW",   CLI_TDB_RANGE2,	(void **) &tdb->secturaw    },
	    { "SectURSZ",   CLI_TDB_RANGE2,	(void **) &tdb->sectursz    },
*/
	    { NULL,	    0,			NULL,			    }
	};
	struct lsig_attrib *apt;
	char *tokens[ATTRIB_TOKENS], *pt, *pt2;
	unsigned int v1, v2, v3, i, j, tokens_count;
	uint32_t cnt, off[ATTRIB_TOKENS];


    tokens_count = cli_strtokenize(attribs, ',', ATTRIB_TOKENS, (const char **) tokens);

    for(i = 0; i < tokens_count; i++) {
	if(!(pt = strchr(tokens[i], ':'))) {
	    cli_errmsg("lsigattribs: Incorrect format of attribute '%s'\n", tokens[i]);
	    return -1;
	}
	*pt++ = 0;

	apt = NULL;
	for(j = 0; attrtab[j].name; j++) {
	    if(!strcmp(attrtab[j].name, tokens[i])) {
		apt = &attrtab[j];
		break;
	    }
	}

	if(!apt) {
	    cli_dbgmsg("lsigattribs: Unknown attribute name '%s'\n", tokens[i]);
	    continue;
	}

	switch(apt->type) {
	    case CLI_TDB_UINT:
		off[i] = cnt = tdb->cnt[CLI_TDB_UINT]++;
		tdb->val = (uint32_t *) mpool_realloc2(tdb->mempool, tdb->val, tdb->cnt[CLI_TDB_UINT] * sizeof(uint32_t));
		if(!tdb->val) {
		    tdb->cnt[CLI_TDB_UINT] = 0;
		    return -1;
		}
		tdb->val[cnt] = atoi(pt);
		break;

	    case CLI_TDB_RANGE:
		if(!(pt2 = strchr(pt, '-'))) {
		    cli_errmsg("lsigattribs: Incorrect parameters in '%s'\n", tokens[i]);
		    return -1;
		}
		*pt2++ = 0;
		off[i] = cnt = tdb->cnt[CLI_TDB_RANGE];
		tdb->cnt[CLI_TDB_RANGE] += 2;
		tdb->range = (uint32_t *) mpool_realloc2(tdb->mempool, tdb->range, tdb->cnt[CLI_TDB_RANGE] * sizeof(uint32_t));
		if(!tdb->range) {
		    tdb->cnt[CLI_TDB_RANGE] = 0;
		    return -1;
		}
		tdb->range[cnt] = atoi(pt);
		tdb->range[cnt + 1] = atoi(pt2);
		break;

	    case CLI_TDB_RANGE2:
		if(!strchr(pt, '-') || !strchr(pt, '.')) {
		    cli_errmsg("lsigattribs: Incorrect parameters in '%s'\n", tokens[i]);
		    return -1;
		}
		off[i] = cnt = tdb->cnt[CLI_TDB_RANGE];
		tdb->cnt[CLI_TDB_RANGE] += 3;
		tdb->range = (uint32_t *) mpool_realloc2(tdb->mempool, tdb->range, tdb->cnt[CLI_TDB_RANGE] * sizeof(uint32_t));
		if(!tdb->range) {
		    tdb->cnt[CLI_TDB_RANGE] = 0;
		    return -1;
		}
		if(sscanf(pt, "%u.%u-%u", &v1, &v2, &v3) != 3) {
		    cli_errmsg("lsigattribs: Can't parse parameters in '%s'\n", tokens[i]);
		    return -1;
		}
		tdb->range[cnt] = (uint32_t) v1;
		tdb->range[cnt + 1] = (uint32_t) v2;
		tdb->range[cnt + 2] = (uint32_t) v3;
		break;

	    case CLI_TDB_STR:
		off[i] = cnt = tdb->cnt[CLI_TDB_STR];
		tdb->cnt[CLI_TDB_STR] += strlen(pt) + 1;
		tdb->str = (char *) mpool_realloc2(tdb->mempool, tdb->str, tdb->cnt[CLI_TDB_STR] * sizeof(char));
		if(!tdb->str) {
		    cli_errmsg("lsigattribs: Can't allocate memory for tdb->str\n");
		    return -1;
		}
		memcpy(&tdb->str[cnt], pt, strlen(pt));
		tdb->str[tdb->cnt[CLI_TDB_STR] - 1] = 0;
		break;
	}
    }

    if(!i) {
	cli_errmsg("lsigattribs: Empty TDB\n");
	return -1;
    }

    for(i = 0; i < tokens_count; i++) {
	for(j = 0; attrtab[j].name; j++) {
	    if(!strcmp(attrtab[j].name, tokens[i])) {
		apt = &attrtab[j];
		break;
	    }
	}
	if(!apt)
	    continue;
	switch(apt->type) {
	    case CLI_TDB_UINT:
		*apt->pt = (uint32_t *) &tdb->val[off[i]];
		break;

	    case CLI_TDB_RANGE:
	    case CLI_TDB_RANGE2:
		*apt->pt = (uint32_t *) &tdb->range[off[i]];
		break;

	    case CLI_TDB_STR:
		*apt->pt = (char *) &tdb->str[off[i]];
		break;
	}
    }

    return 0;
}

#define FREE_TDB(x) do {		\
  if(x.cnt[CLI_TDB_UINT])		\
    mpool_free(x.mempool, x.val);		\
  if(x.cnt[CLI_TDB_RANGE])		\
    mpool_free(x.mempool, x.range);	\
  if(x.cnt[CLI_TDB_STR])		\
    mpool_free(x.mempool, x.str);		\
  } while(0);

#define LDB_TOKENS 67
static int cli_loadldb(FILE *fs, struct cl_engine *engine, unsigned int *signo, unsigned int options, struct cli_dbio *dbio, const char *dbname)
{
	char *tokens[LDB_TOKENS];
	char buffer[CLI_DEFAULT_LSIG_BUFSIZE + 1], *pt;
	const char *sig, *virname, *offset, *logic;
	struct cli_matcher *root;
	unsigned int line = 0, sigs = 0;
	unsigned short target = 0;
	struct cli_ac_lsig **newtable, *lsig;
	uint32_t lsigid[2];
	int ret = CL_SUCCESS, i, subsigs, tokens_count;
	struct cli_lsig_tdb tdb;


    if((ret = cli_initroots(engine, options)))
	return ret;

    while(cli_dbgets(buffer, sizeof(buffer), fs, dbio)) {
	line++;
	sigs++;
	cli_chomp(buffer);

	tokens_count = cli_strtokenize(buffer, ';', LDB_TOKENS, (const char **) tokens);
	if(tokens_count < 4) {
	    ret = CL_EMALFDB;
	    break;
	}

	virname = tokens[0];
	logic = tokens[2];

	if(engine->pua_cats && (options & CL_DB_PUA_MODE) && (options & (CL_DB_PUA_INCLUDE | CL_DB_PUA_EXCLUDE)))
	    if(cli_chkpua(virname, engine->pua_cats, options))
		continue;

	if(engine->ignored && cli_chkign(engine->ignored, dbname, line, virname))
	    continue;

	subsigs = cli_ac_chklsig(logic, logic + strlen(logic), NULL, NULL, NULL, 1);
	if(subsigs == -1) {
	    ret = CL_EMALFDB;
	    break;
	}
	subsigs++;

	if(subsigs > 64) {
	    cli_errmsg("cli_loadldb: Broken logical expression or too many subsignatures\n");
	    ret = CL_EMALFDB;
	    break;
	}

	/* TDB */
	memset(&tdb, 0, sizeof(tdb));
#ifdef USE_MPOOL
	tdb.mempool = engine->mempool;
#endif

	if(lsigattribs(tokens[1], &tdb) == -1) {
	    FREE_TDB(tdb);
	    ret = CL_EMALFDB;
	    break;
	}

	if(tdb.engine) {
	    if(tdb.engine[0] > cl_retflevel()) {
		cli_dbgmsg("cli_loadldb: Signature for %s not loaded (required f-level: %u)\n", virname, tdb.engine[0]);
		FREE_TDB(tdb);
		sigs--;
		continue;
	    } else if(tdb.engine[1] < cl_retflevel()) {
		FREE_TDB(tdb);
		sigs--;
		continue;
	    }
	}

	if(!tdb.target) {
	    cli_errmsg("cli_loadldb: No target specified in TDB\n");
	    FREE_TDB(tdb);
	    ret = CL_EMALFDB;
	    break;
	} else if(tdb.target[0] >= CLI_MTARGETS) {
	    cli_dbgmsg("cli_loadldb: Not supported target type in logical signature for %s\n", virname);
	    FREE_TDB(tdb);
	    sigs--;
	    continue;
	}

	root = engine->root[tdb.target[0]];

	lsig = (struct cli_ac_lsig *) mpool_calloc(engine->mempool, 1, sizeof(struct cli_ac_lsig));
	if(!lsig) {
	    cli_errmsg("cli_loadldb: Can't allocate memory for lsig\n");
	    FREE_TDB(tdb);
	    ret = CL_EMEM;
	    break;
	}

	lsig->logic = cli_mpool_strdup(engine->mempool, logic);
	if(!lsig->logic) {
	    cli_errmsg("cli_loadldb: Can't allocate memory for lsig->logic\n");
	    FREE_TDB(tdb);
	    ret = CL_EMEM;
	    mpool_free(engine->mempool, lsig);
	    break;
	}

	lsigid[0] = lsig->id = root->ac_lsigs;
	memcpy(&lsig->tdb, &tdb, sizeof(tdb));

	root->ac_lsigs++;
	newtable = (struct cli_ac_lsig **) mpool_realloc(engine->mempool, root->ac_lsigtable, root->ac_lsigs * sizeof(struct cli_ac_lsig *));
	if(!newtable) {
	    root->ac_lsigs--;
	    cli_errmsg("cli_loadldb: Can't realloc root->ac_lsigtable\n");
	    FREE_TDB(tdb);
	    mpool_free(engine->mempool, lsig);
	    ret = CL_EMEM;
	    break;
	}
	newtable[root->ac_lsigs - 1] = lsig;
	root->ac_lsigtable = newtable;

	for(i = 0; i < subsigs; i++) {
	    if(i >= tokens_count) {
		cli_errmsg("cli_loadldb: Missing subsignature id %u\n", i);
		ret = CL_EMALFDB;
		break;
	    }
	    lsigid[1] = i;
	    sig = tokens[3 + i];

	    if((pt = strchr(tokens[3 + i], ':'))) {
		*pt = 0;
		sig = ++pt;
		offset = tokens[3 + i];
		if(!strcmp(offset, "*"))
		    offset = NULL;
	    } else {
		offset = NULL;
		sig = tokens[3 + i];
	    }

	    if(offset && cli_checkoffset(offset, tdb.target[0])) {
		cli_errmsg("Incorrect offset '%s' in subsignature id %u for signature type-%u\n", offset, i, tdb.target[0]);
		ret = CL_EMALFDB;
		break;
	    }

	    if((ret = cli_parse_add(root, virname, sig, 0, 0, offset, target, lsigid, options))) {
		ret = CL_EMALFDB;
		break;
	    }
	}
	if(ret)
	    break;
    }

    if(!line) {
	cli_errmsg("Empty database file\n");
	return CL_EMALFDB;
    }

    if(ret) {
	cli_errmsg("Problem parsing database at line %u\n", line);
	return ret;
    }

    if(signo)
	*signo += sigs;

    return CL_SUCCESS;
}

#define FTM_TOKENS 8
static int cli_loadftm(FILE *fs, struct cl_engine *engine, unsigned int options, unsigned int internal, struct cli_dbio *dbio)
{
	const char *tokens[FTM_TOKENS + 1], *pt;
	char buffer[FILEBUFF];
	unsigned int line = 0, sigs = 0, tokens_count;
	struct cli_ftype *new;
	cli_file_t rtype, type;
	int ret;


    if((ret = cli_initroots(engine, options)))
	return ret;

    while(1) {
	if(internal) {
	    if(!ftypes_int[line])
		break;
	    strncpy(buffer, ftypes_int[line], sizeof(buffer));
	    buffer[sizeof(buffer)-1]='\0';
	} else {
	    if(!cli_dbgets(buffer, FILEBUFF, fs, dbio))
		break;
	    cli_chomp(buffer);
	}
	line++;
	tokens_count = cli_strtokenize(buffer, ':', FTM_TOKENS + 1, tokens);

	if(tokens_count < 6 || tokens_count > 8) {
	    ret = CL_EMALFDB;
	    break;
	}

	if(tokens_count > 6) { /* min version */
	    pt = tokens[6];
	    if(!cli_isnumber(pt)) {
		ret = CL_EMALFDB;
		break;
	    }
	    if((unsigned int) atoi(pt) > cl_retflevel()) {
		cli_dbgmsg("cli_loadftm: File type signature for %s not loaded (required f-level: %u)\n", tokens[3], atoi(pt));
		continue;
	    }
	    if(tokens_count == 8) { /* max version */
		pt = tokens[7];
		if(!cli_isnumber(pt)) {
		    ret = CL_EMALFDB;
		    break;
		}
		if((unsigned int) atoi(pt) < cl_retflevel())
		    continue;
	    }
	}

	rtype = cli_ftcode(tokens[4]);
	type = cli_ftcode(tokens[5]);
	if(rtype == CL_TYPE_ERROR || type == CL_TYPE_ERROR) {
	    ret = CL_EMALFDB;
	    break;
	}

	if(atoi(tokens[0]) == 1) { /* A-C */
	    if((ret = cli_parse_add(engine->root[0], tokens[3], tokens[2], rtype, type, strcmp(tokens[1], "*") ? tokens[1] : NULL, 0, NULL, options)))
		break;

	} else if(atoi(tokens[0]) == 0) { /* memcmp() */
	    new = (struct cli_ftype *) mpool_malloc(engine->mempool, sizeof(struct cli_ftype));
	    if(!new) {
		ret = CL_EMEM;
		break;
	    }
	    new->type = type;
	    new->offset = atoi(tokens[1]);
	    new->magic = (unsigned char *) cli_mpool_hex2str(engine->mempool, tokens[2]);
	    if(!new->magic) {
		cli_errmsg("cli_loadftm: Can't decode the hex string\n");
		ret = CL_EMALFDB;
		mpool_free(engine->mempool, new);
		break;
	    }
	    new->length = strlen(tokens[2]) / 2;
	    new->tname = cli_mpool_strdup(engine->mempool, tokens[3]);
	    if(!new->tname) {
		mpool_free(engine->mempool, new->magic);
		mpool_free(engine->mempool, new);
		ret = CL_EMEM;
		break;
	    }
	    new->next = engine->ftypes;
	    engine->ftypes = new;

	} else {
	    cli_dbgmsg("cli_loadftm: Unsupported mode %u\n", atoi(tokens[0]));
	    continue;
	}
	sigs++;
    }

    if(ret) {
	cli_errmsg("Problem parsing %s filetype database at line %u\n", internal ? "built-in" : "external", line);
	return ret;
    }

    if(!sigs) {
	cli_errmsg("Empty %s filetype database\n", internal ? "built-in" : "external");
	return CL_EMALFDB;
    }

    cli_dbgmsg("Loaded %u filetype definitions\n", sigs);
    return CL_SUCCESS;
}

#define IGN_TOKENS 3
static int cli_loadign(FILE *fs, struct cl_engine *engine, unsigned int options, struct cli_dbio *dbio)
{
	const char *tokens[IGN_TOKENS + 1];
	char buffer[FILEBUFF];
	unsigned int line = 0, tokens_count;
	struct cli_ignsig *new;
	int ret = CL_SUCCESS;


    if(!engine->ignored) {
	engine->ignored = (struct cli_ignored *) cli_calloc(sizeof(struct cli_ignored), 1);
	if(!engine->ignored || hashset_init(&engine->ignored->hs, 64, 50))
	    return CL_EMEM;
    }

    while(cli_dbgets(buffer, FILEBUFF, fs, dbio)) {
	line++;
	cli_chomp(buffer);
	tokens_count = cli_strtokenize(buffer, ':', IGN_TOKENS + 1, tokens);
	if(tokens_count != IGN_TOKENS) {
	    ret = CL_EMALFDB;
	    break;
	}

	new = (struct cli_ignsig *) mpool_calloc(engine->mempool, 1, sizeof(struct cli_ignsig));
	if(!new) {
	    ret = CL_EMEM;
	    break;
	}

	new->dbname = cli_mpool_strdup(engine->mempool, tokens[0]);

	if(!new->dbname) {
	    mpool_free(engine->mempool, new);
	    ret = CL_EMALFDB;
	    break;
	}

	new->line = atoi(tokens[1]);

	if((ret = hashset_addkey(&engine->ignored->hs, new->line)))
	    break;

	new->signame = cli_mpool_strdup(engine->mempool, tokens[2]);
	if(!new->signame) {
	    mpool_free(engine->mempool, new->dbname);
	    mpool_free(engine->mempool, new);
	    ret = CL_EMALFDB;
	    break;
	}

	new->next = engine->ignored->list;
	engine->ignored->list = new;
    }

    if(ret) {
	cli_errmsg("cli_loadign: Problem parsing database at line %u\n", line);
	return ret;
    }

    return CL_SUCCESS;
}

static void cli_freeign(struct cl_engine *engine)
{
	struct cli_ignsig *pt;
	struct cli_ignored *ignored;

    if((ignored = engine->ignored)) {
	while(ignored->list) {
	    pt = ignored->list;
	    ignored->list = ignored->list->next;
	    mpool_free(engine->mempool, pt->dbname);
	    mpool_free(engine->mempool, pt->signame);
	    mpool_free(engine->mempool,pt);
	}
	hashset_destroy(&ignored->hs);
	free(engine->ignored);
	engine->ignored = NULL;
    }
}

static int scomp(const void *a, const void *b)
{
    return *(const uint32_t *)a - *(const uint32_t *)b;
}

#define MD5_HDB	    0
#define MD5_MDB	    1
#define MD5_FP	    2

static int cli_md5db_init(struct cl_engine *engine, unsigned int mode)
{
	struct cli_matcher *bm = NULL;
	int ret;


    if(mode == MD5_HDB) {
	bm = engine->md5_hdb = (struct cli_matcher *) mpool_calloc(engine->mempool, sizeof(struct cli_matcher), 1);
    } else if(mode == MD5_MDB) {
	bm = engine->md5_mdb = (struct cli_matcher *) mpool_calloc(engine->mempool, sizeof(struct cli_matcher), 1);
    } else {
	bm = engine->md5_fp = (struct cli_matcher *) mpool_calloc(engine->mempool, sizeof(struct cli_matcher), 1);
    }

    if(!bm)
	return CL_EMEM;
#ifdef USE_MPOOL
    bm->mempool = engine->mempool;
#endif
    if((ret = cli_bm_init(bm))) {
	cli_errmsg("cli_md5db_init: Failed to initialize B-M\n");
	return ret;
    }

    return CL_SUCCESS;
}

#define MD5_DB			    \
    if(mode == MD5_HDB)		    \
	db = engine->md5_hdb;    \
    else if(mode == MD5_MDB)	    \
	db = engine->md5_mdb;    \
    else			    \
	db = engine->md5_fp;

#define MD5_TOKENS 3
static int cli_loadmd5(FILE *fs, struct cl_engine *engine, unsigned int *signo, unsigned int mode, unsigned int options, struct cli_dbio *dbio, const char *dbname)
{
	const char *tokens[MD5_TOKENS + 1];
	char buffer[FILEBUFF];
	const char *pt;
	int ret = CL_SUCCESS;
	unsigned int size_field = 1, md5_field = 0, line = 0, sigs = 0, tokens_count;
	uint32_t size;
	struct cli_bm_patt *new;
	struct cli_matcher *db = NULL;


    if(mode == MD5_MDB) {
	size_field = 0;
	md5_field = 1;
    }

    while(cli_dbgets(buffer, FILEBUFF, fs, dbio)) {
	line++;
	cli_chomp(buffer);
	tokens_count = cli_strtokenize(buffer, ':', MD5_TOKENS + 1, tokens);
	if(tokens_count != MD5_TOKENS) {
	    ret = CL_EMALFDB;
	    break;
	}

	pt = tokens[2]; /* virname */
	if(engine->pua_cats && (options & CL_DB_PUA_MODE) && (options & (CL_DB_PUA_INCLUDE | CL_DB_PUA_EXCLUDE)))
	    if(cli_chkpua(pt, engine->pua_cats, options))
		continue;

	if(engine->ignored && cli_chkign(engine->ignored, dbname, line, pt))
	    continue;

	new = (struct cli_bm_patt *) mpool_calloc(engine->mempool, 1, sizeof(struct cli_bm_patt));
	if(!new) {
	    ret = CL_EMEM;
	    break;
	}

	pt = tokens[md5_field]; /* md5 */
	if(strlen(pt) != 32 || !(new->pattern = (unsigned char *) cli_mpool_hex2str(engine->mempool, pt))) {
	    cli_errmsg("cli_loadmd5: Malformed MD5 string at line %u\n", line);
	    mpool_free(engine->mempool, new);
	    ret = CL_EMALFDB;
	    break;
	}
	new->length = 16;

	size = atoi(tokens[size_field]);

	new->virname = cli_mpool_virname(engine->mempool, (char *) tokens[2], options & CL_DB_OFFICIAL);
	if(!new->virname) {
	    mpool_free(engine->mempool, new->pattern);
	    mpool_free(engine->mempool, new);
	    ret = CL_EMALFDB;
	    break;
	}

	MD5_DB;
	if(!db && (ret = cli_md5db_init(engine, mode))) {
	    mpool_free(engine->mempool, new->pattern);
	    mpool_free(engine->mempool, new->virname);
	    mpool_free(engine->mempool, new);
	    break;
	} else {
	    MD5_DB;
	}

	if((ret = cli_bm_addpatt(db, new))) {
	    cli_errmsg("cli_loadmd5: Error adding BM pattern\n");
	    mpool_free(engine->mempool, new->pattern);
	    mpool_free(engine->mempool, new->virname);
	    mpool_free(engine->mempool, new);
	    break;
	}

	if(mode == MD5_MDB) { /* section MD5 */
	    if(!db->md5_sizes_hs.capacity) {
		    hashset_init(&db->md5_sizes_hs, 65536, 80);
	    }
	    hashset_addkey(&db->md5_sizes_hs, size);
	}

	sigs++;
    }

    if(!line) {
	cli_errmsg("cli_loadmd5: Empty database file\n");
	return CL_EMALFDB;
    }

    if(ret) {
	cli_errmsg("cli_loadmd5: Problem parsing database at line %u\n", line);
	return ret;
    }

    if(signo)
	*signo += sigs;

    return CL_SUCCESS;
}

#define MD_TOKENS 9
static int cli_loadmd(FILE *fs, struct cl_engine *engine, unsigned int *signo, int type, unsigned int options, struct cli_dbio *dbio, const char *dbname)
{
	const char *tokens[MD_TOKENS + 1];
	char buffer[FILEBUFF];
	unsigned int line = 0, sigs = 0, tokens_count;
	int ret = CL_SUCCESS, crc;
	struct cli_meta_node *new;


    while(cli_dbgets(buffer, FILEBUFF, fs, dbio)) {
	line++;
	if(buffer[0] == '#')
	    continue;

	cli_chomp(buffer);
	tokens_count = cli_strtokenize(buffer, ':', MD_TOKENS + 1, tokens);
	if(tokens_count != MD_TOKENS) {
	    ret = CL_EMALFDB;
	    break;
	}

	new = (struct cli_meta_node *) mpool_calloc(engine->mempool, 1, sizeof(struct cli_meta_node));
	if(!new) {
	    ret = CL_EMEM;
	    break;
	}

	new->virname = cli_mpool_virname(engine->mempool, (char *)tokens[0], options & CL_DB_OFFICIAL);
	if(!new->virname) {
	    mpool_free(engine->mempool, new);
	    ret = CL_EMEM;
	    break;
	}

	if(engine->ignored && cli_chkign(engine->ignored, dbname, line, new->virname)) {
	    mpool_free(engine->mempool, new->virname);
	    mpool_free(engine->mempool, new);
	    continue;
	}

	new->encrypted = atoi(tokens[1]);
	new->filename = cli_mpool_strdup(engine->mempool, tokens[2]);
	if(!new->filename) {
	    mpool_free(engine->mempool, new->virname);
	    mpool_free(engine->mempool, new);
	    ret = CL_EMALFDB;
	    break;
	} else {
	    if(!strcmp(new->filename, "*")) {
	        mpool_free(engine->mempool, new->filename);
		new->filename = NULL;
	    }
	}

	if(!strcmp(tokens[3], "*"))
	    new->size = -1;
	else
	    new->size = atoi(tokens[3]);

	if(!strcmp(tokens[4], "*"))
	    new->csize = -1;
	else
	    new->csize = atoi(tokens[4]);

	if(!strcmp(tokens[5], "*")) {
	    new->crc32 = 0;
	} else {
	    crc = cli_hex2num(tokens[5]);
	    if(crc == -1) {
	        ret = CL_EMALFDB;
		break;
	    }
	    new->crc32 = (unsigned int) crc;
	}

	if(!strcmp(tokens[6], "*"))
	    new->method = -1;
	else
	    new->method = atoi(tokens[6]);

	if(!strcmp(tokens[7], "*"))
	    new->fileno = 0;
	else
	    new->fileno = atoi(tokens[7]);

	if(!strcmp(tokens[8], "*"))
	    new->maxdepth = 0;
	else
	    new->maxdepth = atoi(tokens[8]);

	if(type == 1) {
	    new->next = engine->zip_mlist;
	    engine->zip_mlist = new;
	} else {
	    new->next = engine->rar_mlist;
	    engine->rar_mlist = new;
	}

	sigs++;
    }

    if(!line) {
	cli_errmsg("Empty database file\n");
	return CL_EMALFDB;
    }

    if(ret) {
	cli_errmsg("Problem parsing database at line %d\n", line);
	return ret;
    }

    if(signo)
	*signo += sigs;

    return CL_SUCCESS;
}

static int cli_loaddbdir(const char *dirname, struct cl_engine *engine, unsigned int *signo, unsigned int options);

int cli_load(const char *filename, struct cl_engine *engine, unsigned int *signo, unsigned int options, struct cli_dbio *dbio)
{
	FILE *fs = NULL;
	int ret = CL_SUCCESS;
	uint8_t skipped = 0;
	const char *dbname;


    if(!dbio && (fs = fopen(filename, "rb")) == NULL) {
	cli_errmsg("cli_load(): Can't open file %s\n", filename);
	return CL_EOPEN;
    }

/*
#ifdef C_WINDOWS
    if((dbname = strrchr(filename, '\\')))
#else
*/
    if((dbname = strrchr(filename, '/')))
/*#endif */
	dbname++;
    else
	dbname = filename;

    if(cli_strbcasestr(dbname, ".db")) {
	ret = cli_loaddb(fs, engine, signo, options, dbio, dbname);

    } else if(cli_strbcasestr(dbname, ".cvd")) {
	ret = cli_cvdload(fs, engine, signo, !strcmp(dbname, "daily.cvd"), options, 0);

    } else if(cli_strbcasestr(dbname, ".cld")) {
	ret = cli_cvdload(fs, engine, signo, !strcmp(dbname, "daily.cld"), options | CL_DB_CVDNOTMP, 1);

    } else if(cli_strbcasestr(dbname, ".hdb")) {
	ret = cli_loadmd5(fs, engine, signo, MD5_HDB, options, dbio, dbname);

    } else if(cli_strbcasestr(dbname, ".hdu")) {
	if(options & CL_DB_PUA)
	    ret = cli_loadmd5(fs, engine, signo, MD5_HDB, options | CL_DB_PUA_MODE, dbio, dbname);
	else
	    skipped = 1;

    } else if(cli_strbcasestr(dbname, ".fp")) {
	ret = cli_loadmd5(fs, engine, signo, MD5_FP, options, dbio, dbname);

    } else if(cli_strbcasestr(dbname, ".mdb")) {
	ret = cli_loadmd5(fs, engine, signo, MD5_MDB, options, dbio, dbname);

    } else if(cli_strbcasestr(dbname, ".mdu")) {
	if(options & CL_DB_PUA)
	    ret = cli_loadmd5(fs, engine, signo, MD5_MDB, options | CL_DB_PUA_MODE, dbio, dbname);
	else
	    skipped = 1;

    } else if(cli_strbcasestr(dbname, ".ndb")) {
	ret = cli_loadndb(fs, engine, signo, 0, options, dbio, dbname);

    } else if(cli_strbcasestr(dbname, ".ndu")) {
	if(!(options & CL_DB_PUA))
	    skipped = 1;
	else
	    ret = cli_loadndb(fs, engine, signo, 0, options | CL_DB_PUA_MODE, dbio, dbname);

    } else if(cli_strbcasestr(filename, ".ldb")) {
       ret = cli_loadldb(fs, engine, signo, options, dbio, dbname);

    } else if(cli_strbcasestr(filename, ".ldu")) {
	if(options & CL_DB_PUA)
	    ret = cli_loadldb(fs, engine, signo, options | CL_DB_PUA_MODE, dbio, dbname);
	else
	    skipped = 1;

    } else if(cli_strbcasestr(dbname, ".sdb")) {
	ret = cli_loadndb(fs, engine, signo, 1, options, dbio, dbname);

    } else if(cli_strbcasestr(dbname, ".zmd")) {
	ret = cli_loadmd(fs, engine, signo, 1, options, dbio, dbname);

    } else if(cli_strbcasestr(dbname, ".rmd")) {
	ret = cli_loadmd(fs, engine, signo, 2, options, dbio, dbname);

    } else if(cli_strbcasestr(dbname, ".cfg")) {
	ret = cli_dconf_load(fs, engine, options, dbio);

    } else if(cli_strbcasestr(dbname, ".wdb")) {
	if(options & CL_DB_PHISHING_URLS) {
	    ret = cli_loadwdb(fs, engine, options, dbio);
	} else
	    skipped = 1;
    } else if(cli_strbcasestr(dbname, ".pdb") || cli_strbcasestr(dbname, ".gdb")) {
	if(options & CL_DB_PHISHING_URLS) {
	    ret = cli_loadpdb(fs, engine, signo, options, dbio);
	} else
	    skipped = 1;
    } else if(cli_strbcasestr(dbname, ".ftm")) {
	ret = cli_loadftm(fs, engine, options, 0, dbio);

    } else if(cli_strbcasestr(dbname, ".ign")) {
	ret = cli_loadign(fs, engine, options, dbio);

    } else {
	cli_dbgmsg("cli_load: unknown extension - assuming old database format\n");
	ret = cli_loaddb(fs, engine, signo, options, dbio, dbname);
    }

    if(ret) {
	cli_errmsg("Can't load %s: %s\n", filename, cl_strerror(ret));
    } else  {
	if(skipped)
	    cli_dbgmsg("%s skipped\n", filename);
	else
	    cli_dbgmsg("%s loaded\n", filename);
    }

    if(fs)
	fclose(fs);

    return ret;
}

static int cli_loaddbdir(const char *dirname, struct cl_engine *engine, unsigned int *signo, unsigned int options)
{
	DIR *dd;
	struct dirent *dent;
#if defined(HAVE_READDIR_R_3) || defined(HAVE_READDIR_R_2)
	union {
	    struct dirent d;
	    char b[offsetof(struct dirent, d_name) + NAME_MAX + 1];
	} result;
#endif
	char *dbfile;
	int ret = CL_EOPEN;


    cli_dbgmsg("Loading databases from %s\n", dirname);
    dbfile = (char *) cli_malloc(strlen(dirname) + 20);
    if(!dbfile)
	return CL_EMEM;

    /* try to load local.ign and daily.cvd/daily.ign first */
    sprintf(dbfile, "%s/local.ign", dirname);
    if(!access(dbfile, R_OK) && (ret = cli_load(dbfile, engine, signo, options, NULL))) {
	free(dbfile);
	return ret;
    }

    sprintf(dbfile, "%s/daily.cld", dirname);
    if(access(dbfile, R_OK))
	sprintf(dbfile, "%s/daily.cvd", dirname);
    if(!access(dbfile, R_OK) && (ret = cli_load(dbfile, engine, signo, options, NULL))) {
	free(dbfile);
	return ret;
    }

    sprintf(dbfile, "%s/daily.ign", dirname);
    if(!access(dbfile, R_OK) && (ret = cli_load(dbfile, engine, signo, options, NULL))) {
	free(dbfile);
	return ret;
    }

    /* try to load local.gdb next */
    sprintf(dbfile, "%s/local.gdb", dirname);
    if(!access(dbfile, R_OK) && (ret = cli_load(dbfile, engine, signo, options, NULL))) {
	free(dbfile);
	return ret;
    }

    /* check for and load daily.cfg */
    sprintf(dbfile, "%s/daily.cfg", dirname);
    if(!access(dbfile, R_OK) && (ret = cli_load(dbfile, engine, signo, options, NULL))) {
	free(dbfile);
	return ret;
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
#if	(!defined(C_INTERIX)) && (!defined(C_WINDOWS))
	if(dent->d_ino)
#endif
	{
	    if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..") && strcmp(dent->d_name, "daily.cvd") && strcmp(dent->d_name, "daily.cld") && strcmp(dent->d_name, "daily.ign") && strcmp(dent->d_name, "daily.cfg") && strcmp(dent->d_name, "local.ign") && CLI_DBEXT(dent->d_name)) {

		dbfile = (char *) cli_malloc(strlen(dent->d_name) + strlen(dirname) + 2);

		if(!dbfile) {
		    cli_dbgmsg("cli_loaddbdir(): dbfile == NULL\n");
		    closedir(dd);
		    return CL_EMEM;
		}
		sprintf(dbfile, "%s/%s", dirname, dent->d_name);
		ret = cli_load(dbfile, engine, signo, options, NULL);

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
    if(ret == CL_EOPEN)
	cli_errmsg("cli_loaddb(): No supported database files found in %s\n", dirname);

    return ret;
}

int cl_load(const char *path, struct cl_engine *engine, unsigned int *signo, unsigned int dboptions)
{
	struct stat sb;
	int ret;

    if(!engine) {
	cli_errmsg("cl_load: engine == NULL\n");
	return CL_ENULLARG;
    }

    if(engine->dboptions & CL_DB_COMPILED) {
	cli_errmsg("cl_load(): can't load new databases when engine is already compiled\n");
	return CL_EARG;
    }

    if(stat(path, &sb) == -1) {
        cli_errmsg("cl_load(): Can't get status of %s\n", path);
        return CL_ESTAT;
    }

    if((dboptions & CL_DB_PHISHING_URLS) && !engine->phishcheck && (engine->dconf->phishing & PHISHING_CONF_ENGINE))
	if((ret = phishing_init(engine)))
	    return ret;

    engine->dboptions |= dboptions;

    switch(sb.st_mode & S_IFMT) {
	case S_IFREG: 
	    ret = cli_load(path, engine, signo, dboptions, NULL);
	    break;

	case S_IFDIR:
	    ret = cli_loaddbdir(path, engine, signo, dboptions);
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
#if	(!defined(C_INTERIX)) && (!defined(C_WINDOWS))
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
		sprintf(fname, "%s/%s", dirname, dent->d_name);
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
#if	(!defined(C_INTERIX)) && (!defined(C_WINDOWS))
	if(dent->d_ino)
#endif
	{
	    if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..") && CLI_DBEXT(dent->d_name)) {
                fname = cli_malloc(strlen(dbstat->dir) + strlen(dent->d_name) + 32);
		if(!fname) {
		    closedir(dd);
		    return CL_EMEM;
		}

		sprintf(fname, "%s/%s", dbstat->dir, dent->d_name);
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

int cl_engine_free(struct cl_engine *engine)
{
	unsigned int i, j;
	struct cli_meta_node *metapt, *metah;
	struct cli_matcher *root;


    if(!engine) {
	cli_errmsg("cl_free: engine == NULL\n");
	return CL_ENULLARG;
    }

#ifdef CL_THREAD_SAFE
    pthread_mutex_lock(&cli_ref_mutex);
#endif

    if(engine->refcount)
	engine->refcount--;

    if(engine->refcount) {
#ifdef CL_THREAD_SAFE
	pthread_mutex_unlock(&cli_ref_mutex);
#endif
	return CL_SUCCESS;
    }

#ifdef CL_THREAD_SAFE
    pthread_mutex_unlock(&cli_ref_mutex);
#endif
    if(engine->root) {
	for(i = 0; i < CLI_MTARGETS; i++) {
	    if((root = engine->root[i])) {
		if(!root->ac_only)
		    cli_bm_free(root);
		cli_ac_free(root);
		if(root->ac_lsigtable) {
		    for(j = 0; j < root->ac_lsigs; j++) {
			mpool_free(engine->mempool, root->ac_lsigtable[j]->logic);
			FREE_TDB(root->ac_lsigtable[j]->tdb);
			mpool_free(engine->mempool, root->ac_lsigtable[j]);
		    }
		    mpool_free(engine->mempool, root->ac_lsigtable);
		}
		mpool_free(engine->mempool, root);
	    }
	}
	mpool_free(engine->mempool, engine->root);
    }

    if((root = engine->md5_hdb)) {
	cli_bm_free(root);
	mpool_free(engine->mempool, root);
    }

    if((root = engine->md5_mdb)) {
	cli_bm_free(root);
	mpool_free(engine->mempool, root->soff);
	if(root->md5_sizes_hs.capacity) {
		hashset_destroy(&root->md5_sizes_hs);
	}
	mpool_free(engine->mempool, root);
    }

    if((root = engine->md5_fp)) {
	cli_bm_free(root);
	mpool_free(engine->mempool, root);
    }

    metapt = engine->zip_mlist;
    while(metapt) {
	metah = metapt;
	metapt = metapt->next;
	mpool_free(engine->mempool, metah->virname);
	if(metah->filename)
	    mpool_free(engine->mempool, metah->filename);
	mpool_free(engine->mempool, metah);
    }

    metapt = engine->rar_mlist;
    while(metapt) {
	metah = metapt;
	metapt = metapt->next;
	mpool_free(engine->mempool, metah->virname);
	if(metah->filename)
	    mpool_free(engine->mempool, metah->filename);
	mpool_free(engine->mempool, metah);
    }

    if(engine->dconf->phishing & PHISHING_CONF_ENGINE)
	phishing_done(engine);
    if(engine->dconf)
	mpool_free(engine->mempool, engine->dconf);

    if(engine->pua_cats)
	mpool_free(engine->mempool, engine->pua_cats);

    if(engine->tmpdir)
	mpool_free(engine->mempool, engine->tmpdir);

    cli_ftfree(engine);
    cli_freeign(engine);
#ifdef USE_MPOOL
    if(engine->mempool) mpool_destroy(engine->mempool);
#endif
    free(engine);
    return CL_SUCCESS;
}

static void cli_md5db_build(struct cli_matcher* root)
{
	if(root && root->md5_sizes_hs.capacity) {
		/* TODO: use hashset directly, instead of the array when matching*/
		cli_dbgmsg("Converting hashset to array: %u entries\n", root->md5_sizes_hs.count);

#ifdef USE_MPOOL
		{
		uint32_t *mpoolht;
		unsigned int mpoolhtsz = root->md5_sizes_hs.count * sizeof(*mpoolht);
		root->soff = mpool_malloc(root->mempool, mpoolhtsz);
		root->soff_len = hashset_toarray(&root->md5_sizes_hs, &mpoolht);
		memcpy(root->soff, mpoolht, mpoolhtsz);
		free(mpoolht);
		}
#else
		root->soff_len = hashset_toarray(&root->md5_sizes_hs, &root->soff);
#endif
		hashset_destroy(&root->md5_sizes_hs);
		qsort(root->soff, root->soff_len, sizeof(uint32_t), scomp);
	}
}

int cl_engine_compile(struct cl_engine *engine)
{
	unsigned int i;
	int ret;
	struct cli_matcher *root;


    if(!engine)
	return CL_ENULLARG;

    if(!engine->ftypes)
	if((ret = cli_loadftm(NULL, engine, 0, 1, NULL)))
	    return ret;

    for(i = 0; i < CLI_MTARGETS; i++) {
	if((root = engine->root[i])) {
	    if((ret = cli_ac_buildtrie(root)))
		return ret;
	    cli_dbgmsg("matcher[%u]: %s: AC sigs: %u BM sigs: %u %s\n", i, cli_mtargets[i].name, root->ac_patterns, root->bm_patterns, root->ac_only ? "(ac_only mode)" : "");
	}
    }

    if((ret = cli_build_regex_list(engine->whitelist_matcher))) {
	    return ret;
    }
    if((ret = cli_build_regex_list(engine->domainlist_matcher))) {
	    return ret;
    }
    cli_md5db_build(engine->md5_mdb);
    cli_freeign(engine);
    cli_dconf_print(engine->dconf);
    mpool_flush(engine->mempool);

    engine->dboptions |= CL_DB_COMPILED;
    return CL_SUCCESS;
}

int cl_engine_addref(struct cl_engine *engine)
{
    if(!engine) {
	cli_errmsg("cl_engine_addref: engine == NULL\n");
	return CL_ENULLARG;
    }

#ifdef CL_THREAD_SAFE
    pthread_mutex_lock(&cli_ref_mutex);
#endif

    engine->refcount++;

#ifdef CL_THREAD_SAFE
    pthread_mutex_unlock(&cli_ref_mutex);
#endif

    return CL_SUCCESS;
}

/*
 *  Copyright (C) 2007-2014 Cisco Systems, Inc.
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
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef	HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <fcntl.h>
#include <zlib.h>
#include <errno.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "libclamav/crypto.h"

#include "clamav.h"
#include "cvd.h"
#ifdef	HAVE_STRINGS_H
#include <strings.h>
#endif
#include "matcher-ac.h"
#include "matcher-bm.h"
#include "matcher-hash.h"
#include "matcher.h"
#include "others.h"
#include "str.h"
#include "dconf.h"
#include "filetypes.h"
#include "filetypes_int.h"
#include "readdb.h"
#include "cltypes.h"
#include "default.h"
#include "dsig.h"
#include "asn1.h"

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
#include "bytecode.h"
#include "bytecode_api.h"
#include "bytecode_priv.h"
#include "cache.h"
#include "openioc.h"
#ifdef CL_THREAD_SAFE
#  include <pthread.h>
static pthread_mutex_t cli_ref_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

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
	char *pt, *hexcpy, *start, *n, l, r;
	const char *wild;
	int ret, asterisk = 0, range;
	unsigned int i, j, hexlen, parts = 0;
	int mindist = 0, maxdist = 0, error = 0;


    hexlen = strlen(hexsig);
    if (hexsig[0] == '$') {
	/* macro */
	unsigned smin, smax, tid;
	struct cli_ac_patt *patt;
	if (hexsig[hexlen-1] != '$') {
	    cli_errmsg("cli_parseadd(): missing terminator $\n");
	    return CL_EMALFDB;
	}
	if (!lsigid) {
	    cli_errmsg("cli_parseadd(): macro signatures only valid inside logical signatures\n");
	    return CL_EMALFDB;
	}
	if (sscanf(hexsig,"${%u-%u}%u$",
		   &smin, &smax, &tid)  != 3) {
	    cli_errmsg("cli_parseadd(): invalid macro signature format\n");
	    return CL_EMALFDB;
	}
	if (tid >= 32) {
	    cli_errmsg("cli_parseadd(): only 32 macro groups are supported\n");
	    return CL_EMALFDB;
	}
	patt = mpool_calloc(root->mempool, 1, sizeof(*patt));
	if (!patt)
	    return CL_EMEM;
	/* this is not a pattern that will be matched by AC itself, rather it is a
	 * pattern checked by the lsig code */
	patt->ch_mindist[0] = smin;
	patt->ch_maxdist[0] = smax;
	patt->sigid = tid;
	patt->length = root->ac_mindepth;
	/* dummy */
	patt->pattern = mpool_calloc(root->mempool, patt->length, sizeof(*patt->pattern));
	if (!patt->pattern) {
	    free(patt);
	    return CL_EMEM;
	}
	if ((ret = cli_ac_addpatt(root, patt))) {
	    mpool_free(root->mempool, patt->pattern);
	    free(patt);
	    return ret;
	}
	return CL_SUCCESS;
    }
    if((wild = strchr(hexsig, '{'))) {
	if(sscanf(wild, "%c%u%c", &l, &range, &r) == 3 && l == '{' && r == '}' && range > 0 && range < 128) {
	    hexcpy = cli_calloc(hexlen + 2 * range, sizeof(char));
	    if(!hexcpy)
		return CL_EMEM;
	    strncpy(hexcpy, hexsig, wild - hexsig);
	    for(i = 0; i < (unsigned int) range; i++)
		strcat(hexcpy, "??");
	    if(!(wild = strchr(wild, '}'))) {
		cli_errmsg("cli_parse_add(): Problem adding signature: missing bracket\n");
		free(hexcpy);
		return CL_EMALFDB;
	    }
	    strcat(hexcpy, ++wild);
	    ret = cli_parse_add(root, virname, hexcpy, rtype, type, offset, target, lsigid, options);
	    free(hexcpy);
	    return ret;
	}

	root->ac_partsigs++;

	if(!(hexcpy = cli_strdup(hexsig)))
	    return CL_EMEM;

	for(i = 0; i < hexlen; i++)
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
	if(error) {
	    cli_errmsg("cli_parseadd(): Problem adding signature (1b).\n");
	    return CL_EMALFDB;
	}

    } else if(strchr(hexsig, '*')) {
	root->ac_partsigs++;

	for(i = 0; i < hexlen; i++)
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

    } else if(root->ac_only || type || lsigid || strpbrk(hexsig, "?([") || (root->bm_offmode && (!strcmp(offset, "*") || strchr(offset, ','))) || strstr(offset, "VI") || strchr(offset, '$')) {
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
	bm_new->length = hexlen / 2;

	bm_new->virname = cli_mpool_virname(root->mempool, virname, options & CL_DB_OFFICIAL);
	if(!bm_new->virname) {
	    mpool_free(root->mempool, bm_new->pattern);
	    mpool_free(root->mempool, bm_new);
	    return CL_EMEM;
	}

	if(bm_new->length > root->maxpatlen) {
	    root->maxpatlen = bm_new->length;
	}

	if((ret = cli_bm_addpatt(root, bm_new, offset))) {
	    cli_errmsg("cli_parse_add(): Problem adding signature (4).\n");
	    mpool_free(root->mempool, bm_new->pattern);
	    mpool_free(root->mempool, bm_new->virname);
	    mpool_free(root->mempool, bm_new);
	    return ret;
	}
    }

    return CL_SUCCESS;
}

int cli_initroots(struct cl_engine *engine, unsigned int options)
{
	int i, ret;
	struct cli_matcher *root;


    for(i = 0; i < CLI_MTARGETS; i++) {
	if(!engine->root[i]) {
	    cli_dbgmsg("Initializing engine->root[%d]\n", i);
	    root = engine->root[i] = (struct cli_matcher *) mpool_calloc(engine->mempool, 1, sizeof(struct cli_matcher));
	    if(!root) {
		cli_errmsg("cli_initroots: Can't allocate memory for cli_matcher\n");
		return CL_EMEM;
	    }
#ifdef USE_MPOOL
	    root->mempool = engine->mempool;
#endif
	    root->type = i;
	    if(cli_mtargets[i].ac_only || engine->ac_only)
		root->ac_only = 1;

	    cli_dbgmsg("Initialising AC pattern matcher of root[%d]\n", i);
	    if((ret = cli_ac_init(root, engine->ac_mindepth, engine->ac_maxdepth, engine->dconf->other&OTHER_CONF_PREFILTERING))) {
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
    engine->root[1]->bm_offmode = 1; /* BM offset mode for PE files */
    return CL_SUCCESS;
}

char *cli_dbgets(char *buff, unsigned int size, FILE *fs, struct cli_dbio *dbio)
{
    if(fs)
	return fgets(buff, size, fs);

    if(dbio->usebuf) {
	    int bread;
	    char *nl;

	while(1) {
	    if(!dbio->bufpt) {
		if(!dbio->size)
		    return NULL;

		if(dbio->gzs) {
		    bread = gzread(dbio->gzs, dbio->readpt, dbio->readsize);
		    if(bread == -1) {
			cli_errmsg("cli_dbgets: gzread() failed\n");
			return NULL;
		    }
		} else {
		    bread = fread(dbio->readpt, 1, dbio->readsize, dbio->fs);
		    if(!bread && ferror(dbio->fs)) {
			cli_errmsg("cli_dbgets: fread() failed\n");
			return NULL;
		    }
		}
		if(!bread)
		    return NULL;
		dbio->readpt[bread] = 0;
		dbio->bufpt = dbio->buf;
		dbio->size -= bread;
		dbio->bread += bread;
        if (dbio->hashctx)
            cl_update_hash(dbio->hashctx, dbio->readpt, bread);
	    }
	    if(dbio->chkonly && dbio->bufpt) {
		dbio->bufpt = NULL;
		dbio->readsize = dbio->size < dbio->bufsize ? dbio->size : dbio->bufsize - 1;
		continue;
	    }
	    nl = strchr(dbio->bufpt, '\n');
	    if(nl) {
		if(nl - dbio->bufpt >= size) {
		    cli_errmsg("cli_dbgets: Line too long for provided buffer\n");
		    return NULL;
		}
		strncpy(buff, dbio->bufpt, nl - dbio->bufpt);
		buff[nl - dbio->bufpt] = 0;
		if(nl < dbio->buf + dbio->bufsize) {
		    dbio->bufpt = ++nl;
		} else {
		    dbio->bufpt = NULL;
		    dbio->readpt = dbio->buf;
		    dbio->readsize = dbio->size < dbio->bufsize ? dbio->size : dbio->bufsize - 1;
		}
		return buff;
	    } else {
		    unsigned int remain = dbio->buf + dbio->bufsize - 1 - dbio->bufpt;

		if(dbio->bufpt == dbio->buf) {
		    cli_errmsg("cli_dbgets: Invalid data or internal buffer too small\n");
		    return NULL;
		}
		memmove(dbio->buf, dbio->bufpt, remain);
		dbio->readpt = dbio->buf + remain;
		dbio->readsize = dbio->bufsize - remain;
		dbio->readsize = dbio->size < dbio->bufsize - remain ? dbio->size : dbio->bufsize - remain - 1;
		dbio->bufpt = NULL;
	    }
	}
    } else { /* use gzgets/fgets */
	    char *pt;
	    unsigned int bs;

	if(!dbio->size)
	    return NULL;

	bs = dbio->size < size ? dbio->size + 1 : size;
	if(dbio->gzs)
	    pt = gzgets(dbio->gzs, buff, bs);
	else
	    pt = fgets(buff, bs, dbio->fs);

	if(!pt) {
	    cli_errmsg("cli_dbgets: Preliminary end of data\n");
	    return pt;
	}
	bs = strlen(buff);
	dbio->size -= bs;
	dbio->bread += bs;
    if (dbio->hashctx)
        cl_update_hash(dbio->hashctx, buff, bs);
	return pt;
    }
}

static int cli_chkign(const struct cli_matcher *ignored, const char *signame, const char *entry)
{
    const char *md5_expected = NULL;
    unsigned char digest[16];

    if(!ignored || !signame || !entry)
        return 0;

    if(cli_bm_scanbuff((const unsigned char *) signame, strlen(signame), &md5_expected, NULL, ignored, 0, NULL, NULL,NULL) == CL_VIRUS) {
        if(md5_expected) {
            cl_hash_data("md5", entry, strlen(entry), digest, NULL);
            if(memcmp(digest, (const unsigned char *) md5_expected, 16))
                return 0;
        }

        cli_dbgmsg("Ignoring signature %s\n", signame);
        return 1;
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
	char buffer[FILEBUFF], *buffer_cpy = NULL, *pt, *start;
	unsigned int line = 0, sigs = 0;
	int ret = 0;
	struct cli_matcher *root;


    if((ret = cli_initroots(engine, options)))
	return ret;

    root = engine->root[0];

    if(engine->ignored)
	if(!(buffer_cpy = cli_malloc(FILEBUFF))) {
        cli_errmsg("cli_loaddb: Can't allocate memory for buffer_cpy\n");
	    return CL_EMEM;
    }

    while(cli_dbgets(buffer, FILEBUFF, fs, dbio)) {
	line++;
	if(buffer[0] == '#')
	    continue;
	cli_chomp(buffer);
	if(engine->ignored)
	    strcpy(buffer_cpy, buffer);

	pt = strchr(buffer, '=');
	if(!pt) {
	    cli_errmsg("Malformed pattern line %d\n", line);
	    ret = CL_EMALFDB;
	    break;
	}

	start = buffer;
	*pt++ = 0;

	if(engine->ignored && cli_chkign(engine->ignored, start, buffer_cpy))
	    continue;

	if(engine->cb_sigload && engine->cb_sigload("db", start, ~options & CL_DB_OFFICIAL, engine->cb_sigload_ctx)) {
	    cli_dbgmsg("cli_loaddb: skipping %s due to callback\n", start);
	    continue;
	}

	if(*pt == '=') continue;

	if((ret = cli_parse_add(root, start, pt, 0, 0, "*", 0, NULL, options))) {
	    cli_dbgmsg("cli_loaddb: cli_parse_add failed on line %d\n", line);
	    ret = CL_EMALFDB;
	    break;
	}
	sigs++;
    }

    if(engine->ignored)
	free(buffer_cpy);

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

#define ICO_TOKENS 4
static int cli_loadidb(FILE *fs, struct cl_engine *engine, unsigned int *signo, unsigned int options, struct cli_dbio *dbio)
{
        const char *tokens[ICO_TOKENS + 1];
	char buffer[FILEBUFF], *buffer_cpy = NULL;
	uint8_t *hash;
	int ret = CL_SUCCESS;
	unsigned int line = 0, sigs = 0, tokens_count, i, size, enginesize;
	struct icomtr *metric;
	struct icon_matcher *matcher;


    if(!(matcher = (struct icon_matcher *)mpool_calloc(engine->mempool, sizeof(*matcher),1))) 
	return CL_EMEM;
    
    if(engine->ignored)
	if(!(buffer_cpy = cli_malloc(FILEBUFF))) {
        cli_errmsg("cli_loadidb: Can't allocate memory for buffer_cpy\n");
	    mpool_free(engine->mempool, matcher);
	    return CL_EMEM;
	}

    while(cli_dbgets(buffer, FILEBUFF, fs, dbio)) {
	line++;
	if(buffer[0] == '#')
	    continue;

	cli_chomp(buffer);
	if(engine->ignored)
	    strcpy(buffer_cpy, buffer);

	tokens_count = cli_strtokenize(buffer, ':', ICO_TOKENS + 1, tokens);
	if(tokens_count != ICO_TOKENS) {
	    cli_errmsg("cli_loadidb: Malformed hash at line %u (wrong token count)\n", line);
	    ret = CL_EMALFDB;
	    break;
	}

	if(strlen(tokens[3]) != 124) {
	    cli_errmsg("cli_loadidb: Malformed hash at line %u (wrong length)\n", line);
	    ret = CL_EMALFDB;
	    break;
	}

	if(engine->ignored && cli_chkign(engine->ignored, tokens[0], buffer_cpy))
	    continue;

	if(engine->cb_sigload && engine->cb_sigload("idb", tokens[0], ~options & CL_DB_OFFICIAL, engine->cb_sigload_ctx)) {
	    cli_dbgmsg("cli_loadidb: skipping %s due to callback\n", tokens[0]);
	    continue;
	}

	hash = (uint8_t *)tokens[3];
	if(cli_hexnibbles((char *)hash, 124)) {
	    cli_errmsg("cli_loadidb: Malformed hash at line %u (bad chars)\n", line);
	    ret = CL_EMALFDB;
	    break;
	}
	size = (hash[0] << 4) + hash[1];
	if(size != 32 && size != 24 && size != 16) {
	    cli_errmsg("cli_loadidb: Malformed hash at line %u (bad size)\n", line);
	    ret = CL_EMALFDB;
	    break;
	}
	enginesize = (size >> 3) - 2;
	hash+=2;

	metric = (struct icomtr *)mpool_realloc(engine->mempool, matcher->icons[enginesize], sizeof(struct icomtr) * (matcher->icon_counts[enginesize] + 1));
	if(!metric) {
	    ret = CL_EMEM;
	    break;
	}

	matcher->icons[enginesize] = metric;
	metric += matcher->icon_counts[enginesize];
	matcher->icon_counts[enginesize]++;

	for(i=0; i<3; i++) {
	    if((metric->color_avg[i] = (hash[0] << 8) | (hash[1] << 4) | hash[2]) > 4072)
		break;
	    if((metric->color_x[i] = (hash[3] << 4) | hash[4]) > size - size / 8)
		break;
	    if((metric->color_y[i] = (hash[5] << 4) | hash[6]) > size - size / 8)
		break;
	    hash += 7;
	}
	if(i!=3) {
	    cli_errmsg("cli_loadidb: Malformed hash at line %u (bad color data)\n", line);
	    ret = CL_EMALFDB;
	    break;
	}

	for(i=0; i<3; i++) {
	    if((metric->gray_avg[i] = (hash[0] << 8) | (hash[1] << 4) | hash[2]) > 4072)
		break;
	    if((metric->gray_x[i] = (hash[3] << 4) | hash[4]) > size - size / 8)
		break;
	    if((metric->gray_y[i] = (hash[5] << 4) | hash[6]) > size - size / 8)
		break;
	    hash += 7;
	}
	if(i!=3) {
	    cli_errmsg("cli_loadidb: Malformed hash at line %u (bad gray data)\n", line);
	    ret = CL_EMALFDB;
	    break;
	}

	for(i=0; i<3; i++) {
	    metric->bright_avg[i] = (hash[0] << 4) | hash[1];
	    if((metric->bright_x[i] = (hash[2] << 4) | hash[3]) > size - size / 8)
		break;
	    if((metric->bright_y[i] = (hash[4] << 4) | hash[5]) > size - size / 8)
		break;
	    hash += 6;
	}
	if(i!=3) {
	    cli_errmsg("cli_loadidb: Malformed hash at line %u (bad bright data)\n", line);
	    ret = CL_EMALFDB;
	    break;
	}

	for(i=0; i<3; i++) {
	    metric->dark_avg[i] = (hash[0] << 4) | hash[1];
	    if((metric->dark_x[i] = (hash[2] << 4) | hash[3]) > size - size / 8)
		break;
	    if((metric->dark_y[i] = (hash[4] << 4) | hash[5]) > size - size / 8)
		break;
	    hash += 6;
	}
	if(i!=3) {
	    cli_errmsg("cli_loadidb: Malformed hash at line %u (bad dark data)\n", line);
	    ret = CL_EMALFDB;
	    break;
	}

	for(i=0; i<3; i++) {
	    metric->edge_avg[i] = (hash[0] << 4) | hash[1];
	    if((metric->edge_x[i] = (hash[2] << 4) | hash[3]) > size - size / 8)
		break;
	    if((metric->edge_y[i] = (hash[4] << 4) | hash[5]) > size - size / 8)
		break;
	    hash += 6;
	}
	if(i!=3) {
	    cli_errmsg("cli_loadidb: Malformed hash at line %u (bad edge data)\n", line);
	    ret = CL_EMALFDB;
	    break;
	}

	for(i=0; i<3; i++) {
	    metric->noedge_avg[i] = (hash[0] << 4) | hash[1];
	    if((metric->noedge_x[i] = (hash[2] << 4) | hash[3]) > size - size / 8)
		break;
	    if((metric->noedge_y[i] = (hash[4] << 4) | hash[5]) > size - size / 8)
		break;
	    hash += 6;
	}
	if(i!=3) {
	    cli_errmsg("cli_loadidb: Malformed hash at line %u (bad noedge data)\n", line);
	    ret = CL_EMALFDB;
	    break;
	}

	metric->rsum = (hash[0] << 4) | hash[1];
	metric->gsum = (hash[2] << 4) | hash[3];
	metric->bsum = (hash[4] << 4) | hash[5];
	metric->ccount = (hash[6] << 4) | hash[7];
	if(metric->rsum + metric->gsum + metric->bsum > 103 || metric->ccount > 100) {
	    cli_errmsg("cli_loadidb: Malformed hash at line %u (bad spread data)\n", line);
	    ret = CL_EMALFDB;
	    break;
	}

	if(!(metric->name = cli_mpool_strdup(engine->mempool, tokens[0]))) {
	    ret = CL_EMEM;
	    break;
	}

	for(i=0; i<matcher->group_counts[0]; i++) {
	    if(!strcmp(tokens[1], matcher->group_names[0][i]))
		break;
	}
	if(i==matcher->group_counts[0]) {
	    if(!(matcher->group_names[0] = mpool_realloc(engine->mempool, matcher->group_names[0], sizeof(char *) * (i + 1))) ||
	       !(matcher->group_names[0][i] = cli_mpool_strdup(engine->mempool, tokens[1]))) {
		ret = CL_EMEM;
		break;
	    }
	    matcher->group_counts[0]++;
	}
	metric->group[0] = i;

	for(i=0; i<matcher->group_counts[1]; i++) {
	    if(!strcmp(tokens[2], matcher->group_names[1][i]))
		break;
	}
	if(i==matcher->group_counts[1]) {
	    if(!(matcher->group_names[1] = mpool_realloc(engine->mempool, matcher->group_names[1], sizeof(char *) * (i + 1))) ||
	       !(matcher->group_names[1][i] = cli_mpool_strdup(engine->mempool, tokens[2]))) {
		ret = CL_EMEM;
		break;
	    }
	    matcher->group_counts[1]++;
	}
	metric->group[1] = i;

	if(matcher->group_counts[0] > 256 || matcher->group_counts[1] > 256) {
	    cli_errmsg("cli_loadidb: too many icon groups!\n");
	    ret = CL_EMALFDB;
	    break;
	}

	sigs++;
    }
    if(engine->ignored)
	free(buffer_cpy);

    if(!line) {
	cli_errmsg("cli_loadidb: Empty database file\n");
	return CL_EMALFDB;
    }

    if(ret) {
	cli_errmsg("cli_loadidb: Problem parsing database at line %u\n", line);
	return ret;
    }

    if(signo)
	*signo += sigs;

    engine->iconcheck = matcher;
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

    if((ret = load_regex_matcher(engine, engine->whitelist_matcher, fs, NULL, options, 1, dbio, engine->dconf->other&OTHER_CONF_PREFILTERING))) {
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

    if((ret = load_regex_matcher(engine, engine->domainlist_matcher, fs, signo, options, 0, dbio, engine->dconf->other&OTHER_CONF_PREFILTERING))) {
	return ret;
    }

    return CL_SUCCESS;
}

#define NDB_TOKENS 6
static int cli_loadndb(FILE *fs, struct cl_engine *engine, unsigned int *signo, unsigned short sdb, unsigned int options, struct cli_dbio *dbio, const char *dbname)
{
	const char *tokens[NDB_TOKENS + 1];
	char buffer[FILEBUFF], *buffer_cpy = NULL;
	const char *sig, *virname, *offset, *pt;
	struct cli_matcher *root;
	int line = 0, sigs = 0, ret = 0, tokens_count;
	unsigned short target;
	unsigned int phish = options & CL_DB_PHISHING;


    if((ret = cli_initroots(engine, options)))
	return ret;

    if(engine->ignored)
	if(!(buffer_cpy = cli_malloc(FILEBUFF))) {
        cli_errmsg("cli_loadndb: Can't allocate memory for buffer_cpy\n");
	    return CL_EMEM;
    }

    while(cli_dbgets(buffer, FILEBUFF, fs, dbio)) {
	line++;
	if(buffer[0] == '#')
	    continue;

	if(!phish)
	    if(!strncmp(buffer, "HTML.Phishing", 13) || !strncmp(buffer, "Email.Phishing", 14))
		continue;

	cli_chomp(buffer);
	if(engine->ignored)
	    strcpy(buffer_cpy, buffer);

	tokens_count = cli_strtokenize(buffer, ':', NDB_TOKENS + 1, tokens);
	if(tokens_count < 4 || tokens_count > 6) {
	    ret = CL_EMALFDB;
	    break;
	}

	virname = tokens[0];

	if(engine->pua_cats && (options & CL_DB_PUA_MODE) && (options & (CL_DB_PUA_INCLUDE | CL_DB_PUA_EXCLUDE)))
	    if(cli_chkpua(virname, engine->pua_cats, options))
		continue;

	if(engine->ignored && cli_chkign(engine->ignored, virname, buffer_cpy))
	    continue;

	if(!sdb && engine->cb_sigload && engine->cb_sigload("ndb", virname, ~options & CL_DB_OFFICIAL, engine->cb_sigload_ctx)) {
	    cli_dbgmsg("cli_loadndb: skipping %s due to callback\n", virname);
	    continue;
	}

	if(tokens_count > 4) { /* min version */
	    pt = tokens[4];

	    if(!cli_isnumber(pt)) {
		ret = CL_EMALFDB;
		break;
	    }

	    if((unsigned int) atoi(pt) > cl_retflevel()) {
		cli_dbgmsg("Signature for %s not loaded (required f-level: %d)\n", virname, atoi(pt));
		continue;
	    }

	    if(tokens_count == 6) { /* max version */
		pt = tokens[5];
		if(!cli_isnumber(pt)) {
		    ret = CL_EMALFDB;
		    break;
		}

		if((unsigned int) atoi(pt) < cl_retflevel()) {
		    continue;
		}
	    }
	}

	if(!(pt = tokens[1]) || (strcmp(pt, "*") && !cli_isnumber(pt))) {
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
	sig = tokens[3];

	if((ret = cli_parse_add(root, virname, sig, 0, 0, offset, target, NULL, options))) {
	    ret = CL_EMALFDB;
	    break;
	}
	sigs++;
    }
    if(engine->ignored)
	free(buffer_cpy);

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
#define ATTRIB_TOKENS	9
	    { "Target",		    CLI_TDB_UINT,	(void **) &tdb->target	    },
	    { "Engine",		    CLI_TDB_RANGE,	(void **) &tdb->engine	    },

	    { "FileSize",	    CLI_TDB_RANGE,	(void **) &tdb->filesize    },
	    { "EntryPoint",	    CLI_TDB_RANGE,	(void **) &tdb->ep	    },
	    { "NumberOfSections",   CLI_TDB_RANGE,	(void **) &tdb->nos	    },

	    { "IconGroup1",	    CLI_TDB_STR,	(void **) &tdb->icongrp1    },
	    { "IconGroup2",	    CLI_TDB_STR,	(void **) &tdb->icongrp2    },

	    { "Container",	    CLI_TDB_FTYPE,	(void **) &tdb->container   },
	    { "HandlerType",	    CLI_TDB_FTYPE,	(void **) &tdb->handlertype },
/*
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
	unsigned int v1, v2, v3, i, j, tokens_count, have_newext = 0;
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
	    return 1;
	}

	if(!strcmp(apt->name, "Engine")) {
	    if(i) {
		cli_errmsg("lsigattribs: For backward compatibility the Engine attribute must be on the first position\n");
		return -1;
	    }
	} else if(strcmp(apt->name, "Target"))
	    have_newext = 1;

	switch(apt->type) {
	    case CLI_TDB_UINT:
		if(!cli_isnumber(pt)) {
		    cli_errmsg("lsigattribs: Invalid argument for %s\n", tokens[i]);
		    return -1;
		}
		off[i] = cnt = tdb->cnt[CLI_TDB_UINT]++;
		tdb->val = (uint32_t *) mpool_realloc2(tdb->mempool, tdb->val, tdb->cnt[CLI_TDB_UINT] * sizeof(uint32_t));
		if(!tdb->val) {
		    tdb->cnt[CLI_TDB_UINT] = 0;
		    return -1;
		}
		tdb->val[cnt] = atoi(pt);
		break;

	    case CLI_TDB_FTYPE:
		if((v1 = cli_ftcode(pt)) == CL_TYPE_ERROR) {
		    cli_dbgmsg("lsigattribs: Unknown file type in %s\n", tokens[i]);
		    return 1; /* skip */
		}
		off[i] = cnt = tdb->cnt[CLI_TDB_UINT]++;
		tdb->val = (uint32_t *) mpool_realloc2(tdb->mempool, tdb->val, tdb->cnt[CLI_TDB_UINT] * sizeof(uint32_t));
		if(!tdb->val) {
		    tdb->cnt[CLI_TDB_UINT] = 0;
		    return -1;
		}
		tdb->val[cnt] = v1;
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
		if(!cli_isnumber(pt) || !cli_isnumber(pt2)) {
		    cli_errmsg("lsigattribs: Invalid argument for %s\n", tokens[i]);
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

	    default:
		/* All known TDB types handled above, skip unknown */
		cli_dbgmsg("lsigattribs: Unknown attribute type '%u'\n", apt->type);
		return 1; /* +1 = skip */
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
	    case CLI_TDB_FTYPE:
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

    if(have_newext && (!tdb->engine || tdb->engine[0] < 51)) {
	cli_errmsg("lsigattribs: For backward compatibility all signatures using new attributes must have the Engine attribute present and set to min_level of at least 51 (0.96)\n");
	return -1;
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
  if(x.macro_ptids)\
    mpool_free(x.mempool, x.macro_ptids);\
  } while(0);

/*     0         1        2      3        4        5    ... (max 66)
 * VirusName:Attributes:Logic:SubSig1[:SubSig2[:SubSig3 ... ]]
 * NOTE: Maximum of 64 subsignatures (last would be token 66)
 */
#define LDB_TOKENS 67
static int load_oneldb(char *buffer, int chkpua, struct cl_engine *engine, unsigned int options, const char *dbname, unsigned int line, unsigned int *sigs, unsigned bc_idx, const char *buffer_cpy, int *skip)
{
    const char *sig, *virname, *offset, *logic;
    struct cli_ac_lsig **newtable, *lsig;
    char *tokens[LDB_TOKENS+1], *pt;
    int i, subsigs, tokens_count;
    unsigned short target = 0;
    struct cli_matcher *root;
    struct cli_lsig_tdb tdb;
    uint32_t lsigid[2];
    int ret;

    tokens_count = cli_strtokenize(buffer, ';', LDB_TOKENS + 1, (const char **) tokens);
    if(tokens_count < 4) {
	return CL_EMALFDB;
    }
    virname = tokens[0];
    logic = tokens[2];

    if (chkpua && cli_chkpua(virname, engine->pua_cats, options))
	    return CL_SUCCESS;

    if (engine->ignored && cli_chkign(engine->ignored, virname, buffer_cpy ? buffer_cpy : virname)) {
	if(skip)
	    *skip = 1;
	return CL_SUCCESS;
    }

    if(engine->cb_sigload && engine->cb_sigload("ldb", virname, ~options & CL_DB_OFFICIAL, engine->cb_sigload_ctx)) {
	cli_dbgmsg("cli_loadldb: skipping %s due to callback\n", virname);
	(*sigs)--;
	return CL_SUCCESS;
    }

    subsigs = cli_ac_chklsig(logic, logic + strlen(logic), NULL, NULL, NULL, 1);
    if(subsigs == -1) {
	return CL_EMALFDB;
    }
    subsigs++;
    if(subsigs > 64) {
	cli_errmsg("cli_loadldb: Broken logical expression or too many subsignatures\n");
	return CL_EMALFDB;
    }
    if (!line) {
	/* This is a logical signature from the bytecode, we need all
	 * subsignatures, even if not referenced from the logical expression */
	if (subsigs > tokens_count-3) {
	    cli_errmsg("load_oneldb: Too many subsignatures: %u (max %u)\n",
		       subsigs, tokens_count-3);
	    return CL_EMALFDB;
	}
	subsigs = tokens_count-3;
    } else if(subsigs != tokens_count - 3) {
	cli_errmsg("cli_loadldb: The number of subsignatures (== %u) doesn't match the IDs in the logical expression (== %u)\n", tokens_count - 3, subsigs);
	return CL_EMALFDB;
    }

    /* TDB */
    memset(&tdb, 0, sizeof(tdb));
#ifdef USE_MPOOL
    tdb.mempool = engine->mempool;
#endif
    if((ret = lsigattribs(tokens[1], &tdb))) {
	FREE_TDB(tdb);
	if(ret == 1) {
	    cli_dbgmsg("cli_loadldb: Not supported attribute(s) in logical signature for %s, skipping\n", virname);
	    (*sigs)--;
	    return CL_SUCCESS;
	}
	return CL_EMALFDB;
    }

    if(tdb.engine) {
	if(tdb.engine[0] > cl_retflevel()) {
	    cli_dbgmsg("cli_loadldb: Signature for %s not loaded (required f-level: %u)\n", virname, tdb.engine[0]);
	    FREE_TDB(tdb);
	    (*sigs)--;
	    return CL_SUCCESS;
	} else if(tdb.engine[1] < cl_retflevel()) {
	    FREE_TDB(tdb);
	    (*sigs)--;
	    return CL_SUCCESS;
	}
    }

    if(!tdb.target) {
	cli_errmsg("cli_loadldb: No target specified in TDB\n");
	FREE_TDB(tdb);
	return CL_EMALFDB;
    } else if(tdb.target[0] >= CLI_MTARGETS) {
	cli_dbgmsg("cli_loadldb: Not supported target type in logical signature for %s, skipping\n", virname);
	FREE_TDB(tdb);
	(*sigs)--;
	return CL_SUCCESS;
    }

    if((tdb.icongrp1 || tdb.icongrp2) && tdb.target[0] != 1) {
	cli_errmsg("cli_loadldb: IconGroup is only supported in PE (target 1) signatures\n");
	FREE_TDB(tdb);
	return CL_EMALFDB;
    }

    if((tdb.ep || tdb.nos) && tdb.target[0] != 1 && tdb.target[0] != 6 && tdb.target[0] != 9) {
	cli_errmsg("cli_loadldb: EntryPoint/NumberOfSections is only supported in PE/ELF/Mach-O signatures\n");
	FREE_TDB(tdb);
	return CL_EMALFDB;
    }

    root = engine->root[tdb.target[0]];

    lsig = (struct cli_ac_lsig *) mpool_calloc(engine->mempool, 1, sizeof(struct cli_ac_lsig));
    if(!lsig) {
	cli_errmsg("cli_loadldb: Can't allocate memory for lsig\n");
	FREE_TDB(tdb);
	return CL_EMEM;
    }

    lsig->logic = cli_mpool_strdup(engine->mempool, logic);
    if(!lsig->logic) {
	cli_errmsg("cli_loadldb: Can't allocate memory for lsig->logic\n");
	FREE_TDB(tdb);
	mpool_free(engine->mempool, lsig);
	return CL_EMEM;
    }

    lsigid[0] = lsig->id = root->ac_lsigs;

    root->ac_lsigs++;
    newtable = (struct cli_ac_lsig **) mpool_realloc(engine->mempool, root->ac_lsigtable, root->ac_lsigs * sizeof(struct cli_ac_lsig *));
    if(!newtable) {
	root->ac_lsigs--;
	cli_errmsg("cli_loadldb: Can't realloc root->ac_lsigtable\n");
	FREE_TDB(tdb);
	mpool_free(engine->mempool, lsig);
	return CL_EMEM;
    }
    /* 0 marks no bc, we can't use a pointer to bc, since that is
     * realloced/moved during load */
    lsig->bc_idx = bc_idx;
    newtable[root->ac_lsigs - 1] = lsig;
    root->ac_lsigtable = newtable;
    tdb.subsigs = subsigs;

    for(i = 0; i < subsigs; i++) {
	lsigid[1] = i;
	sig = tokens[3 + i];

	if((pt = strchr(tokens[3 + i], ':'))) {
	    *pt = 0;
	    sig = ++pt;
	    offset = tokens[3 + i];
	} else {
	    offset = "*";
	    sig = tokens[3 + i];
	}

	if((ret = cli_parse_add(root, virname, sig, 0, 0, offset, target, lsigid, options)))
	    return ret;
	if(sig[0] == '$' && i) {
	    /* allow mapping from lsig back to pattern for macros */
	    if (!tdb.macro_ptids)
		tdb.macro_ptids = mpool_calloc(root->mempool, subsigs, sizeof(*tdb.macro_ptids));
	    if (!tdb.macro_ptids)
		return CL_EMEM;
	    tdb.macro_ptids[i-1] = root->ac_patterns-1;
	}
    }
    memcpy(&lsig->tdb, &tdb, sizeof(tdb));
    return CL_SUCCESS;
}

static int cli_loadldb(FILE *fs, struct cl_engine *engine, unsigned int *signo, unsigned int options, struct cli_dbio *dbio, const char *dbname)
{
	char buffer[CLI_DEFAULT_LSIG_BUFSIZE + 1], *buffer_cpy = NULL;
	unsigned int line = 0, sigs = 0;
	int ret;


    if((ret = cli_initroots(engine, options)))
	return ret;

    if(engine->ignored)
	if(!(buffer_cpy = cli_malloc(sizeof(buffer)))) {
        cli_errmsg("cli_loadldb: Can't allocate memory for buffer_cpy\n");
	    return CL_EMEM;
    }
    while(cli_dbgets(buffer, sizeof(buffer), fs, dbio)) {
	line++;
	if(buffer[0] == '#')
	    continue;
	sigs++;
	cli_chomp(buffer);

	if(engine->ignored)
	    strcpy(buffer_cpy, buffer);
	ret = load_oneldb(buffer,
			  engine->pua_cats && (options & CL_DB_PUA_MODE) && (options & (CL_DB_PUA_INCLUDE | CL_DB_PUA_EXCLUDE)),
			  engine, options, dbname, line, &sigs, 0, buffer_cpy, NULL);
	if (ret)
	    break;
    }
    if(engine->ignored)
	free(buffer_cpy);

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

static int cli_loadcbc(FILE *fs, struct cl_engine *engine, unsigned int *signo, unsigned int options, struct cli_dbio *dbio, const char *dbname)
{
    char buf[4096];
    int rc, skip = 0;
    struct cli_all_bc *bcs = &engine->bcs;
    struct cli_bc *bc;
    unsigned sigs = 0;
    unsigned security_trust = 0;
    unsigned i;


    /* TODO: virusname have a common prefix, and whitelist by that */
    if((rc = cli_initroots(engine, options)))
	return rc;

    if(!(engine->dconf->bytecode & BYTECODE_ENGINE_MASK)) {
	return CL_SUCCESS;
    }

    if(engine->cb_sigload && engine->cb_sigload("cbc", dbname, ~options & CL_DB_OFFICIAL, engine->cb_sigload_ctx)) {
	cli_dbgmsg("cli_loadcbc: skipping %s due to callback\n", dbname);
	return CL_SUCCESS;
    }

    if (!(options & CL_DB_BYTECODE_UNSIGNED) && !(options & CL_DB_SIGNED)) {
	cli_warnmsg("Only loading signed bytecode, skipping load of unsigned bytecode!\n");
	cli_warnmsg("Turn on BytecodeUnsigned/--bytecode-unsigned to enable loading of unsigned bytecode\n");
	return CL_SUCCESS;
    }

    bcs->all_bcs = cli_realloc2(bcs->all_bcs, sizeof(*bcs->all_bcs)*(bcs->count+1));
    if (!bcs->all_bcs) {
	cli_errmsg("cli_loadcbc: Can't allocate memory for bytecode entry\n");
	return CL_EMEM;
    }
    bcs->count++;
    bc = &bcs->all_bcs[bcs->count-1];

    switch (engine->bytecode_security) {
	case CL_BYTECODE_TRUST_SIGNED:
	    security_trust = !!(options & CL_DB_SIGNED);
	    break;
	default:
	    security_trust = 0;
    }

    rc = cli_bytecode_load(bc, fs, dbio, security_trust, options&CL_DB_BYTECODE_STATS);
    /* read remainder of DB, needed because cvd.c checks that we read the entire
     * file */
    while (cli_dbgets(buf, sizeof(buf), fs, dbio)) {}

    if (rc != CL_SUCCESS) {
	cli_bytecode_destroy(bc);
	cli_errmsg("Unable to load %s bytecode: %s\n", dbname, cl_strerror(rc));
	return rc;
    }
    if (bc->state == bc_skip) {
	cli_bytecode_destroy(bc);
	bcs->count--;
	return CL_SUCCESS;
    }
    bc->id = bcs->count;/* must set after _load, since load zeroes */
    if (engine->bytecode_mode == CL_BYTECODE_MODE_TEST)
	cli_infomsg(NULL, "bytecode %u -> %s\n", bc->id, dbname);
    if (bc->kind == BC_LOGICAL || bc->lsig) {
        unsigned oldsigs = sigs;
	if (!bc->lsig) {
	    cli_errmsg("Bytecode %s has logical kind, but missing logical signature!\n", dbname);
	    return CL_EMALFDB;
	}
	cli_dbgmsg("Bytecode %s(%u) has logical signature: %s\n", dbname, bc->id, bc->lsig);
	rc = load_oneldb(bc->lsig, 0, engine, options, dbname, 0, &sigs, bcs->count, NULL, &skip);
	if (rc != CL_SUCCESS) {
	    cli_errmsg("Problem parsing logical signature %s for bytecode %s: %s\n",
		       bc->lsig, dbname, cl_strerror(rc));
	    return rc;
	}
	if (skip) {
	    cli_bytecode_destroy(bc);
	    bcs->count--;
	    return CL_SUCCESS;
	}
        if (sigs != oldsigs) {
          /* compiler ensures Engine field in lsig matches the one in bytecode,
           * so this should never happen. */
          cli_errmsg("Bytecode logical signature skipped, but bytecode itself not?");
          return CL_EMALFDB;
        }
    }
    sigs++;
    if (bc->kind != BC_LOGICAL) {
	if (bc->lsig) {
	    /* runlsig will only flip a status bit, not report a match,
	     * when the hooks are executed we only execute the hook if its
	     * status bit is on */
	    bc->hook_lsig_id = ++engine->hook_lsig_ids;
	}
	if (bc->kind >= _BC_START_HOOKS && bc->kind < _BC_LAST_HOOK) {
	    unsigned hook = bc->kind - _BC_START_HOOKS;
	    unsigned cnt = ++engine->hooks_cnt[hook];
	    engine->hooks[hook] = cli_realloc2(engine->hooks[hook],
					       sizeof(*engine->hooks[0])*cnt);
	    if (!engine->hooks[hook]) {
		cli_errmsg("Out of memory allocating memory for hook %u", hook);
		return CL_EMEM;
	    }
	    engine->hooks[hook][cnt-1] = bcs->count-1;
	} else switch (bc->kind) {
	    case BC_STARTUP:
		for (i=0;i<bcs->count-1;i++)
		    if (bcs->all_bcs[i].kind == BC_STARTUP) {
			struct cli_bc *bc0 = &bcs->all_bcs[i];
			cli_errmsg("Can only load 1 BC_STARTUP bytecode, attempted to load 2nd!\n");
			cli_warnmsg("Previous BC_STARTUP: %d %d by %s\n",
				    bc0->id, (uint32_t)bc0->metadata.timestamp,
				    bc0->metadata.sigmaker ? bc0->metadata.sigmaker : "N/A");
			cli_warnmsg("Conflicting BC_STARTUP: %d %d by %s\n",
				    bc->id, (uint32_t)bc->metadata.timestamp,
				    bc->metadata.sigmaker ? bc->metadata.sigmaker : "N/A");
			return CL_EMALFDB;
		    }
		break;
	    default:
		cli_errmsg("Bytecode: unhandled bytecode kind %u\n", bc->kind);
		return CL_EMALFDB;
	}
    }
    if (signo)
	*signo += sigs;
    return CL_SUCCESS;
}

/*     0       1      2     3        4            5          6      7
 * MagicType:Offset:HexSig:Name:RequiredType:DetectedType[:MinFL[:MaxFL]]
 */
#define FTM_TOKENS 8
static int cli_loadftm(FILE *fs, struct cl_engine *engine, unsigned int options, unsigned int internal, struct cli_dbio *dbio)
{
	const char *tokens[FTM_TOKENS + 1], *pt;
	char buffer[FILEBUFF];
	unsigned int line = 0, sigs = 0, tokens_count;
	struct cli_ftype *new;
	cli_file_t rtype, type;
	int ret;
	int magictype;

    if((ret = cli_initroots(engine, options)))
	return ret;

    while(1) {
	if(internal) {
	    options |= CL_DB_OFFICIAL;
	    if(!ftypes_int[line])
		break;
	    strncpy(buffer, ftypes_int[line], sizeof(buffer));
	    buffer[sizeof(buffer)-1]='\0';
	} else {
	    if(!cli_dbgets(buffer, FILEBUFF, fs, dbio))
		break;
	    if(buffer[0] == '#')
		continue;
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

	if(!cli_isnumber(tokens[0])) {
	    cli_errmsg("cli_loadftm: Invalid value for the first field\n");
	    ret = CL_EMALFDB;
	    break;
	}

        magictype = atoi(tokens[0]);
	if(magictype == 1) { /* A-C */
	    if((ret = cli_parse_add(engine->root[0], tokens[3], tokens[2], rtype, type, tokens[1], 0, NULL, options)))
		break;

	} else if ((magictype == 0) || (magictype == 4)) { /* memcmp() */
	    if(!cli_isnumber(tokens[1])) {
		cli_errmsg("cli_loadftm: Invalid offset\n");
		ret = CL_EMALFDB;
		break;
	    }
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
            /* files => ftypes, partitions => ptypes */
	    if(magictype == 4) {
		new->next = engine->ptypes;
		engine->ptypes = new;
	    }
	    else {
		new->next = engine->ftypes;
		engine->ftypes = new;
            }
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

#define INFO_NSTR "11088894983048545473659556106627194923928941791795047620591658697413581043322715912172496806525381055880964520618400224333320534660299233983755341740679502866829909679955734391392668378361221524205396631090105151641270857277080310734320951653700508941717419168723942507890702904702707587451621691050754307850383399865346487203798464178537392211402786481359824461197231102895415093770394216666324484593935762408468516826633192140826667923494822045805347809932848454845886971706424360558667862775876072059437703365380209101697738577515476935085469455279994113145977994084618328482151013142393373316337519977244732747977"
#define INFO_ESTR "100002049"
#define INFO_TOKENS 3
static int cli_loadinfo(FILE *fs, struct cl_engine *engine, unsigned int options, struct cli_dbio *dbio)
{
	const char *tokens[INFO_TOKENS + 1];
	char buffer[FILEBUFF];
	unsigned int line = 0, tokens_count, len;
	unsigned char hash[32];
        struct cli_dbinfo *last = NULL, *new;
	int ret = CL_SUCCESS, dsig = 0;
    void *ctx;


    if(!dbio) {
	cli_errmsg("cli_loadinfo: .info files can only be loaded from within database container files\n");
	return CL_EMALFDB;
    }

    ctx = cl_hash_init("sha256");
    if (!(ctx))
        return CL_EMALFDB;

    while(cli_dbgets(buffer, FILEBUFF, fs, dbio)) {
	line++;
	if(!(options & CL_DB_UNSIGNED) && !strncmp(buffer, "DSIG:", 5)) {
	    dsig = 1;
	    cl_finish_hash(ctx, hash);
	    if(cli_versig2(hash, buffer + 5, INFO_NSTR, INFO_ESTR) != CL_SUCCESS) {
		cli_errmsg("cli_loadinfo: Incorrect digital signature\n");
		ret = CL_EMALFDB;
	    }
	    break;
	}
	len = strlen(buffer);
    if (!len) {
        buffer[len] = '\n';
        buffer[len+1] = 0;
    } else {
        if(dbio->usebuf && buffer[len - 1] != '\n' && len + 1 < FILEBUFF) {
            /* cli_dbgets in buffered mode strips \n */
            buffer[len] = '\n';
            buffer[len + 1] = 0;
        }
    }
	cl_update_hash(ctx, buffer, strlen(buffer));
	cli_chomp(buffer);
	if(!strncmp("ClamAV-VDB:", buffer, 11)) {
	    if(engine->dbinfo) { /* shouldn't be initialized at this point */
		cli_errmsg("cli_loadinfo: engine->dbinfo already initialized\n");
		ret = CL_EMALFDB;
		break;
	    }
	    last = engine->dbinfo = (struct cli_dbinfo *) mpool_calloc(engine->mempool, 1, sizeof(struct cli_bm_patt));
	    if(!engine->dbinfo) {
		ret = CL_EMEM;
		break;
	    }
	    engine->dbinfo->cvd = cl_cvdparse(buffer);
	    if(!engine->dbinfo->cvd) {
		cli_errmsg("cli_loadinfo: Can't parse header entry\n");
		ret = CL_EMALFDB;
		break;
	    }
	    continue;
	}

	if(!last) {
	    cli_errmsg("cli_loadinfo: Incorrect file format\n");
	    ret = CL_EMALFDB;
	    break;
	}
	tokens_count = cli_strtokenize(buffer, ':', INFO_TOKENS + 1, tokens);
	if(tokens_count != INFO_TOKENS) {
	    ret = CL_EMALFDB;
	    break;
	}
        new = (struct cli_dbinfo *) mpool_calloc(engine->mempool, 1, sizeof(struct cli_dbinfo));
	if(!new) {
	    ret = CL_EMEM;
	    break;
	}
	new->name = cli_mpool_strdup(engine->mempool, tokens[0]);
	if(!new->name) {
	    mpool_free(engine->mempool, new);
	    ret = CL_EMEM;
	    break;
	}

	if(!cli_isnumber(tokens[1])) {
	    cli_errmsg("cli_loadinfo: Invalid value in the size field\n");
	    mpool_free(engine->mempool, new->name);
	    mpool_free(engine->mempool, new);
	    ret = CL_EMALFDB;
	    break;
	}
	new->size = atoi(tokens[1]);

	if(strlen(tokens[2]) != 64 || !(new->hash = cli_mpool_hex2str(engine->mempool, tokens[2]))) {
	    cli_errmsg("cli_loadinfo: Malformed SHA256 string at line %u\n", line);
	    mpool_free(engine->mempool, new->name);
	    mpool_free(engine->mempool, new);
	    ret = CL_EMALFDB;
	    break;
	}
	last->next = new;
	last = new;
    }

    if(!(options & CL_DB_UNSIGNED) && !dsig) {
	cli_errmsg("cli_loadinfo: Digital signature not found\n");
	return CL_EMALFDB;
    }

    if(ret) {
	cli_errmsg("cli_loadinfo: Problem parsing database at line %u\n", line);
	return ret;
    }

    return CL_SUCCESS;
}

#define IGN_MAX_TOKENS   3
static int cli_loadign(FILE *fs, struct cl_engine *engine, unsigned int options, struct cli_dbio *dbio)
{
	const char *tokens[IGN_MAX_TOKENS + 1], *signame, *hash = NULL;
	char buffer[FILEBUFF];
	unsigned int line = 0, tokens_count, len;
        struct cli_bm_patt *new;
	int ret = CL_SUCCESS;

    if(!engine->ignored) {
	engine->ignored = (struct cli_matcher *) mpool_calloc(engine->mempool, 1, sizeof(struct cli_matcher));
	if(!engine->ignored)
	    return CL_EMEM;
#ifdef USE_MPOOL
	engine->ignored->mempool = engine->mempool;
#endif
	if((ret = cli_bm_init(engine->ignored))) {
	    cli_errmsg("cli_loadign: Can't initialise AC pattern matcher\n");
	    return ret;
	}
    }

    while(cli_dbgets(buffer, FILEBUFF, fs, dbio)) {
	line++;
	if(buffer[0] == '#')
	    continue;
	cli_chomp(buffer);

	tokens_count = cli_strtokenize(buffer, ':', IGN_MAX_TOKENS + 1, tokens);
	if(tokens_count > IGN_MAX_TOKENS) {
	    ret = CL_EMALFDB;
	    break;
	}

	if(tokens_count == 1) {
	    signame = buffer;
	} else if(tokens_count == 2) {
	    signame = tokens[0];
	    hash = tokens[1];
	} else { /* old mode */
	    signame = tokens[2];
	}
	if(!(len = strlen(signame))) {
	    cli_errmsg("cli_loadign: No signature name provided\n");
	    ret = CL_EMALFDB;
	    break;
	}

        new = (struct cli_bm_patt *) mpool_calloc(engine->mempool, 1, sizeof(struct cli_bm_patt));
	if(!new) {
	    ret = CL_EMEM;
	    break;
	}
	new->pattern = (unsigned char *) cli_mpool_strdup(engine->mempool, signame);
	if(!new->pattern) {
	    mpool_free(engine->mempool, new);
	    ret = CL_EMEM;
	    break;
	}
	if(hash) {
	    if(strlen(hash) != 32 || !(new->virname = (char *) cli_mpool_hex2str(engine->mempool, hash))) {
		cli_errmsg("cli_loadign: Malformed MD5 string at line %u\n", line);
		mpool_free(engine->mempool, new->pattern);
		mpool_free(engine->mempool, new);
		ret = CL_EMALFDB;
		break;
	    }
	}
	new->length = len;
	new->boundary |= BM_BOUNDARY_EOL;

        if((ret = cli_bm_addpatt(engine->ignored, new, "0"))) {
	    if(hash)
		mpool_free(engine->mempool, new->virname);
	    mpool_free(engine->mempool, new->pattern);
	    mpool_free(engine->mempool, new);
	    break;
	}
    }

    if(ret) {
	cli_errmsg("cli_loadign: Problem parsing database at line %u\n", line);
	return ret;
    }

    return CL_SUCCESS;
}

#define MD5_HDB	    0
#define MD5_MDB	    1
#define MD5_FP	    2

#define MD5_TOKENS 5
static int cli_loadhash(FILE *fs, struct cl_engine *engine, unsigned int *signo, unsigned int mode, unsigned int options, struct cli_dbio *dbio, const char *dbname)
{
    const char *tokens[MD5_TOKENS + 1];
    char buffer[FILEBUFF], *buffer_cpy = NULL;
    const char *pt, *virname;
    int ret = CL_SUCCESS;
    unsigned int size_field = 1, md5_field = 0, line = 0, sigs = 0, tokens_count;
    unsigned int req_fl = 0; 
    struct cli_matcher *db;
    unsigned long size;


    if(mode == MD5_MDB) {
	size_field = 0;
	md5_field = 1;
	db = engine->hm_mdb;
    } else if(mode == MD5_HDB)
	db = engine->hm_hdb;
    else
	db = engine->hm_fp;

    if(!db) {
	if(!(db = mpool_calloc(engine->mempool, 1, sizeof(*db))))
	    return CL_EMEM;
#ifdef USE_MPOOL
	db->mempool = engine->mempool;
#endif
	if(mode == MD5_HDB)
	    engine->hm_hdb = db;
	else if(mode == MD5_MDB)
	    engine->hm_mdb = db;
	else
	    engine->hm_fp = db;
    }

    if(engine->ignored)
	if(!(buffer_cpy = cli_malloc(FILEBUFF))) {
        cli_errmsg("cli_loadhash: Can't allocate memory for buffer_cpy\n");
	    return CL_EMEM;
    }

    while(cli_dbgets(buffer, FILEBUFF, fs, dbio)) {
	line++;
	if(buffer[0] == '#')
	    continue;
	cli_chomp(buffer);
	if(engine->ignored)
	    strcpy(buffer_cpy, buffer);

	tokens_count = cli_strtokenize(buffer, ':', MD5_TOKENS + 1, tokens);
	if(tokens_count < 3) {
	    ret = CL_EMALFDB;
	    break;
	}
	if(tokens_count > MD5_TOKENS - 2) {
	    req_fl = atoi(tokens[MD5_TOKENS - 2]);

	    if(tokens_count > MD5_TOKENS) {
		ret = CL_EMALFDB;
		break;
	    }

	    if(cl_retflevel() < req_fl)
		continue;
	    if(tokens_count == MD5_TOKENS) {
		int max_fl = atoi(tokens[MD5_TOKENS - 1]);
		if(cl_retflevel() > max_fl)
		    continue;
	    }
	}

	if((mode == MD5_MDB) || strcmp(tokens[size_field],"*")) {
	    size = strtoul(tokens[size_field], (char **)&pt, 10);
	    if(*pt || !size || size >= 0xffffffff) {
		cli_errmsg("cli_loadhash: Invalid value for the size field\n");
		ret = CL_EMALFDB;
		break;
	    }
	}
	else {
	    size = 0;
	    if((tokens_count < MD5_TOKENS - 1) || (req_fl < 73)) {
		cli_errmsg("cli_loadhash: Minimum FLEVEL field must be at least 73 for wildcard size hash signatures."
			" For reference, running FLEVEL is %d\n", cl_retflevel());
		ret = CL_EMALFDB;
		break;
	    }
	}

	pt = tokens[2]; /* virname */
	if(engine->pua_cats && (options & CL_DB_PUA_MODE) && (options & (CL_DB_PUA_INCLUDE | CL_DB_PUA_EXCLUDE)))
	    if(cli_chkpua(pt, engine->pua_cats, options))
		continue;

	if(engine->ignored && cli_chkign(engine->ignored, pt, buffer_cpy))
	    continue;

	if(engine->cb_sigload) {
	    const char *dot = strchr(dbname, '.');
	    if(!dot)
		dot = dbname;
	    else
		dot++;
	    if(engine->cb_sigload(dot, pt, ~options & CL_DB_OFFICIAL, engine->cb_sigload_ctx)) {
		cli_dbgmsg("cli_loadhash: skipping %s (%s) due to callback\n", pt, dot);
	        continue;
	    }
	}

	virname = cli_mpool_virname(engine->mempool, pt, options & CL_DB_OFFICIAL);
	if(!virname) {
	    ret = CL_EMALFDB;
	    break;
	}

	if((ret = hm_addhash_str(db, tokens[md5_field], size, virname))) {
	    cli_errmsg("cli_loadhash: Malformed hash string at line %u\n", line);
	    mpool_free(engine->mempool, (void *)virname);
	    break;
	}

	sigs++;
    }
    if(engine->ignored)
	free(buffer_cpy);

    if(!line) {
	cli_errmsg("cli_loadhash: Empty database file\n");
	return CL_EMALFDB;
    }

    if(ret) {
	cli_errmsg("cli_loadhash: Problem parsing database at line %u\n", line);
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
	char buffer[FILEBUFF], *buffer_cpy = NULL;
	unsigned int line = 0, sigs = 0, tokens_count;
	int ret = CL_SUCCESS;
	struct cli_cdb *new;


    if(engine->ignored)
	if(!(buffer_cpy = cli_malloc(FILEBUFF))) {
        cli_errmsg("cli_loadmd: Can't allocate memory for buffer_cpy\n");
	    return CL_EMEM;
    }

    while(cli_dbgets(buffer, FILEBUFF, fs, dbio)) {
	line++;
	if(buffer[0] == '#')
	    continue;

	cli_chomp(buffer);
	if(engine->ignored)
	    strcpy(buffer_cpy, buffer);

	tokens_count = cli_strtokenize(buffer, ':', MD_TOKENS + 1, tokens);
	if(tokens_count != MD_TOKENS) {
	    ret = CL_EMALFDB;
	    break;
	}

	if(strcmp(tokens[1], "*") && !cli_isnumber(tokens[1])) {
	    cli_errmsg("cli_loadmd: Invalid value for the 'encrypted' field\n");
	    ret = CL_EMALFDB;
	    break;
	}
	if(strcmp(tokens[3], "*") && !cli_isnumber(tokens[3])) {
	    cli_errmsg("cli_loadmd: Invalid value for the 'original size' field\n");
	    ret = CL_EMALFDB;
	    break;
	}
	if(strcmp(tokens[4], "*") && !cli_isnumber(tokens[4])) {
	    cli_errmsg("cli_loadmd: Invalid value for the 'compressed size' field\n");
	    ret = CL_EMALFDB;
	    break;
	}
	if(strcmp(tokens[6], "*") && !cli_isnumber(tokens[6])) {
	    cli_errmsg("cli_loadmd: Invalid value for the 'compression method' field\n");
	    ret = CL_EMALFDB;
	    break;
	}
	if(strcmp(tokens[7], "*") && !cli_isnumber(tokens[7])) {
	    cli_errmsg("cli_loadmd: Invalid value for the 'file number' field\n");
	    ret = CL_EMALFDB;
	    break;
	}
	if(strcmp(tokens[8], "*") && !cli_isnumber(tokens[8])) {
	    cli_errmsg("cli_loadmd: Invalid value for the 'max depth' field\n");
	    ret = CL_EMALFDB;
	    break;
	}

	new = (struct cli_cdb *) mpool_calloc(engine->mempool, 1, sizeof(struct cli_cdb));
	if(!new) {
	    ret = CL_EMEM;
	    break;
	}

	new->virname = cli_mpool_virname(engine->mempool, tokens[0], options & CL_DB_OFFICIAL);
	if(!new->virname) {
	    mpool_free(engine->mempool, new);
	    ret = CL_EMEM;
	    break;
	}
	new->ctype = (type == 1) ? CL_TYPE_ZIP : CL_TYPE_RAR;

	if(engine->ignored && cli_chkign(engine->ignored, new->virname, buffer/*_cpy*/)) {
	    mpool_free(engine->mempool, new->virname);
	    mpool_free(engine->mempool, new);
	    continue;
	}

	if(engine->cb_sigload && engine->cb_sigload("md", new->virname, ~options & CL_DB_OFFICIAL, engine->cb_sigload_ctx)) {
	    cli_dbgmsg("cli_loadmd: skipping %s due to callback\n", new->virname);
	    mpool_free(engine->mempool, new->virname);
	    mpool_free(engine->mempool, new);
	    continue;
	}

	new->encrypted = strcmp(tokens[1], "*") ? atoi(tokens[1]) : 2;

	if(strcmp(tokens[2], "*") && cli_regcomp(&new->name, tokens[2], REG_EXTENDED | REG_NOSUB)) {
	    cli_errmsg("cli_loadmd: Can't compile regular expression %s in signature for %s\n", tokens[2], tokens[0]);
	    mpool_free(engine->mempool, new->virname);
	    mpool_free(engine->mempool, new);
	    ret = CL_EMEM;
	    break;
	}
	new->csize[0] = new->csize[1] = CLI_OFF_ANY;

	if(!strcmp(tokens[3], "*"))
	    new->fsizer[0] = new->fsizer[1] = CLI_OFF_ANY;
	else
	    new->fsizer[0] = new->fsizer[1] = atoi(tokens[3]);

	if(!strcmp(tokens[4], "*"))
	    new->fsizec[0] = new->fsizec[1] = CLI_OFF_ANY;
	else
	    new->fsizec[0] = new->fsizec[1] = atoi(tokens[4]);

	if(strcmp(tokens[5], "*")) {
	    new->res1 = cli_hex2num(tokens[5]);
	    if(new->res1 == -1) {
		mpool_free(engine->mempool, new->virname);
		mpool_free(engine->mempool, new);
		if(new->name.re_magic)
		    cli_regfree(&new->name);
	        ret = CL_EMALFDB;
		break;
	    }
	}

	/* tokens[6] - not used */

	new->filepos[0] = new->filepos[1] = strcmp(tokens[7], "*") ? atoi(tokens[7]) : (int) CLI_OFF_ANY;

	/* tokens[8] - not used */

	new->next = engine->cdb;
	engine->cdb = new;
	sigs++;
    }
    if(engine->ignored)
	free(buffer_cpy);

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

/*    0		 1		2		3	         4	       5	      6	      7	      8   9    10     11
 * VirusName:ContainerType:ContainerSize:FileNameREGEX:FileSizeInContainer:FileSizeReal:IsEncrypted:FilePos:Res1:Res2[:MinFL[:MaxFL]]
 */

#define CDB_TOKENS 12
static int cli_loadcdb(FILE *fs, struct cl_engine *engine, unsigned int *signo, unsigned int options, struct cli_dbio *dbio)
{
	const char *tokens[CDB_TOKENS + 1];
	char buffer[FILEBUFF], *buffer_cpy = NULL;
	unsigned int line = 0, sigs = 0, tokens_count, n0, n1;
	int ret = CL_SUCCESS;
	struct cli_cdb *new;


    if(engine->ignored)
	if(!(buffer_cpy = cli_malloc(FILEBUFF))) {
        cli_errmsg("cli_loadcdb: Can't allocate memory for buffer_cpy\n");
	    return CL_EMEM;
    }

    while(cli_dbgets(buffer, FILEBUFF, fs, dbio)) {
	line++;
	if(buffer[0] == '#')
	    continue;

	cli_chomp(buffer);
	if(engine->ignored)
	    strcpy(buffer_cpy, buffer);

	tokens_count = cli_strtokenize(buffer, ':', CDB_TOKENS + 1, tokens);
	if(tokens_count > CDB_TOKENS || tokens_count < CDB_TOKENS - 2) {
	    ret = CL_EMALFDB;
	    break;
	}

	if(tokens_count > 10) { /* min version */
	    if(!cli_isnumber(tokens[10])) {
		ret = CL_EMALFDB;
		break;
	    }
	    if((unsigned int) atoi(tokens[10]) > cl_retflevel()) {
		cli_dbgmsg("cli_loadcdb: Container signature for %s not loaded (required f-level: %u)\n", tokens[0], atoi(tokens[10]));
		continue;
	    }
	    if(tokens_count == CDB_TOKENS) { /* max version */
		if(!cli_isnumber(tokens[11])) {
		    ret = CL_EMALFDB;
		    break;
		}
		if((unsigned int) atoi(tokens[11]) < cl_retflevel())
		    continue;
	    }
	}

	new = (struct cli_cdb *) mpool_calloc(engine->mempool, 1, sizeof(struct cli_cdb));
	if(!new) {
	    ret = CL_EMEM;
	    break;
	}

	new->virname = cli_mpool_virname(engine->mempool, tokens[0], options & CL_DB_OFFICIAL);
	if(!new->virname) {
	    mpool_free(engine->mempool, new);
	    ret = CL_EMEM;
	    break;
	}

	if(engine->ignored && cli_chkign(engine->ignored, new->virname, buffer/*_cpy*/)) {
	    mpool_free(engine->mempool, new->virname);
	    mpool_free(engine->mempool, new);
	    continue;
	}

	if(engine->cb_sigload && engine->cb_sigload("cdb", new->virname, ~options & CL_DB_OFFICIAL, engine->cb_sigload_ctx)) {
	    cli_dbgmsg("cli_loadcdb: skipping %s due to callback\n", new->virname);
	    mpool_free(engine->mempool, new->virname);
	    mpool_free(engine->mempool, new);
	    continue;
	}

	if(!strcmp(tokens[1], "*")) {
	    new->ctype = CL_TYPE_ANY;
	} else if((new->ctype = cli_ftcode(tokens[1])) == CL_TYPE_ERROR) {
	    cli_dbgmsg("cli_loadcdb: Unknown container type %s in signature for %s, skipping\n", tokens[1], tokens[0]);
	    mpool_free(engine->mempool, new->virname);
	    mpool_free(engine->mempool, new);
	    continue;
	}

	if(strcmp(tokens[3], "*") && cli_regcomp(&new->name, tokens[3], REG_EXTENDED | REG_NOSUB)) {
	    cli_errmsg("cli_loadcdb: Can't compile regular expression %s in signature for %s\n", tokens[3], tokens[0]);
	    mpool_free(engine->mempool, new->virname);
	    mpool_free(engine->mempool, new);
	    ret = CL_EMEM;
	    break;
	}

#define CDBRANGE(token_str, dest)					    \
	if(strcmp(token_str, "*")) {					    \
	    if(strchr(token_str, '-')) {				    \
		if(sscanf(token_str, "%u-%u", &n0, &n1) != 2) {		    \
		    ret = CL_EMALFDB;					    \
		} else {						    \
		    dest[0] = n0;					    \
		    dest[1] = n1;					    \
		}							    \
	    } else {							    \
		if(!cli_isnumber(token_str))				    \
		    ret = CL_EMALFDB;					    \
		else							    \
		    dest[0] = dest[1] = atoi(token_str);		    \
	    }								    \
	    if(ret != CL_SUCCESS) {					    \
		cli_errmsg("cli_loadcdb: Invalid value %s in signature for %s\n",\
		    token_str, tokens[0]);				    \
		if(new->name.re_magic)					    \
		    cli_regfree(&new->name);				    \
		mpool_free(engine->mempool, new->virname);		    \
		mpool_free(engine->mempool, new);			    \
		ret = CL_EMEM;						    \
		break;							    \
	    }								    \
	} else {							    \
	    dest[0] = dest[1] = CLI_OFF_ANY;				    \
	}

	CDBRANGE(tokens[2], new->csize);
	CDBRANGE(tokens[4], new->fsizec);
	CDBRANGE(tokens[5], new->fsizer);
	CDBRANGE(tokens[7], new->filepos);

	if(!strcmp(tokens[6], "*")) {
	    new->encrypted = 2;
	} else {
	    if(strcmp(tokens[6], "0") && strcmp(tokens[6], "1")) {
		cli_errmsg("cli_loadcdb: Invalid encryption flag value in signature for %s\n", tokens[0]);
		if(new->name.re_magic)
		    cli_regfree(&new->name);
		mpool_free(engine->mempool, new->virname);
		mpool_free(engine->mempool, new);
		ret = CL_EMEM;
		break;
	    }
	    new->encrypted = *tokens[6] - 0x30;
	}

	if(strcmp(tokens[9], "*")) {
	    new->res2 = cli_mpool_strdup(engine->mempool, tokens[9]);
	    if(!new->res2) {
		cli_errmsg("cli_loadcdb: Can't allocate memory for res2 in signature for %s\n", tokens[0]);
		if(new->name.re_magic)
		    cli_regfree(&new->name);
		mpool_free(engine->mempool, new->virname);
		mpool_free(engine->mempool, new);
		ret = CL_EMEM;
		break;
	    }
	}

	new->next = engine->cdb;
	engine->cdb = new;
	sigs++;
    }
    if(engine->ignored)
	free(buffer_cpy);

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

/* 
 * name;trusted;subject;serial;pubkey;exp;codesign;timesign;certsign;notbefore;comment[;minFL[;maxFL]]
 * Name and comment are ignored. They're just for the end user.
 * Exponent is ignored for now and hardcoded to \x01\x00\x01.
 */
#define CRT_TOKENS 13
static int cli_loadcrt(FILE *fs, struct cl_engine *engine, struct cli_dbio *dbio) {
    char buffer[FILEBUFF];
    char *tokens[CRT_TOKENS+1];
    size_t line=0, tokens_count, i, j;
    cli_crt ca;
    int ret=CL_SUCCESS;
    char *subject=NULL, *pubkey=NULL, *exponent=NULL, *serial=NULL;
    const uint8_t exp[] = "\x01\x00\x01";
    char c;

    cli_crt_init(&ca);
    memset(ca.issuer, 0xca, sizeof(ca.issuer));

    while (cli_dbgets(buffer, FILEBUFF, fs, dbio)) {
        line++;

        if (buffer[0] == '#')
            continue;

        cli_chomp(buffer);
        if (!strlen(buffer))
            continue;

        tokens_count = cli_strtokenize(buffer, ';', CRT_TOKENS + 1, (const char **)tokens);
        if (tokens_count > CRT_TOKENS || tokens_count < CRT_TOKENS - 2) {
            cli_errmsg("cli_loadcrt: line %u: Invalid number of tokens: %u\n", (unsigned int)line, (unsigned int)tokens_count);
            ret = CL_EMALFDB;
            goto end;
        }

        if (tokens_count > CRT_TOKENS - 2) {
            if (!cli_isnumber(tokens[CRT_TOKENS-1])) {
                cli_errmsg("cli_loadcrt: line %u: Invalid minimum feature level\n", (unsigned int)line);
                ret = CL_EMALFDB;
                goto end;
            }
            if ((unsigned int)atoi(tokens[CRT_TOKENS-1]) > cl_retflevel()) {
                cli_dbgmsg("cli_loadcrt: Cert %s not loaded (required f-level: %u)\n", tokens[0], cl_retflevel());
                continue;
            }

            if (tokens_count == CRT_TOKENS) {
                if (!cli_isnumber(tokens[CRT_TOKENS])) {
                    cli_errmsg("cli_loadcrt: line %u: Invalid maximum feature level\n", (unsigned int)line);
                    ret = CL_EMALFDB;
                    goto end;
                }

                if ((unsigned int)atoi(tokens[CRT_TOKENS]) < cl_retflevel()) {
                    cli_dbgmsg("cli_ladcrt: Cert %s not loaded (maximum f-level: %s)\n", tokens[0], tokens[CRT_TOKENS]);
                    continue;
                }
            }
        }

        switch (tokens[1][0]) {
            case '1':
                ca.isBlacklisted = 0;
                break;
            case '0':
                ca.isBlacklisted = 1;
                break;
            default:
                cli_errmsg("cli_loadcrt: line %u: Invalid trust specification. Expected 0 or 1\n", (unsigned int)line);
                ret = CL_EMALFDB;
                goto end;
        }

        subject = cli_hex2str(tokens[2]);
        if (strlen(tokens[3])) {
            serial = cli_hex2str(tokens[3]);
            if (!serial) {
                cli_errmsg("cli_loadcrt: line %u: Cannot convert serial to binary string\n", (unsigned int)line);
                ret = CL_EMALFDB;
                goto end;
            }
            memcpy(ca.serial, serial, sizeof(ca.serial));
            free(serial);
        } else {
            memset(ca.serial, 0xca, sizeof(ca.serial));
        }
        pubkey = cli_hex2str(tokens[4]);
        cli_dbgmsg("cli_loadcrt: subject: %s\n", tokens[2]);
        cli_dbgmsg("cli_loadcrt: public key: %s\n", tokens[4]);

        if (!subject) {
            cli_errmsg("cli_loadcrt: line %u: Cannot convert subject to binary string\n", (unsigned int)line);
            ret = CL_EMALFDB;
            goto end;
        }
        if (!pubkey) {
            cli_errmsg("cli_loadcrt: line %u: Cannot convert public key to binary string\n", (unsigned int)line);
            ret = CL_EMALFDB;
            goto end;
        }

        memcpy(ca.subject, subject, sizeof(ca.subject));
        if (mp_read_unsigned_bin(&(ca.n), pubkey, strlen(tokens[4])/2) || mp_read_unsigned_bin(&(ca.e), exp, sizeof(exp)-1)) {
            cli_errmsg("cli_loadcrt: line %u: Cannot convert exponent to binary data\n", (unsigned int)line);
            ret = CL_EMALFDB;
            goto end;
        }

        switch (tokens[6][0]) {
            case '1':
                ca.codeSign = 1;
                break;
            case '0':
                ca.codeSign = 0;
                break;
            default:
                cli_errmsg("cli_loadcrt: line %u: Invalid code sign specification. Expected 0 or 1\n", (unsigned int)line);
                ret = CL_EMALFDB;
                goto end;
        }

        switch (tokens[7][0]) {
            case '1':
                ca.timeSign = 1;
                break;
            case '0':
                ca.timeSign = 0;
                break;
            default:
                cli_errmsg("cli_loadcrt: line %u: Invalid time sign specification. Expected 0 or 1\n", (unsigned int)line);
                ret = CL_EMALFDB;
                goto end;
        }

        switch (tokens[8][0]) {
            case '1':
                ca.certSign = 1;
                break;
            case '0':
                ca.certSign = 0;
                break;
            default:
                cli_errmsg("cli_loadcrt: line %u: Invalid cert sign specification. Expected 0 or 1\n", (unsigned int)line);
                ret = CL_EMALFDB;
                goto end;
        }

        if (strlen(tokens[0]))
            ca.name = tokens[0];
        else
            ca.name = NULL;

        if (strlen(tokens[9]))
            ca.not_before = atoi(tokens[8]);
        ca.not_after = (-1U)>>1;

        ca.hashtype = CLI_SHA1RSA;
        crtmgr_add(&(engine->cmgr), &ca);
        free(subject);
        free(pubkey);
        subject = pubkey = NULL;
    }

end:
    if (subject)
        free(subject);
    if (pubkey)
        free(pubkey);

    cli_dbgmsg("Number of certs: %d\n", engine->cmgr.items);
    cli_crt_clear(&ca);
    return ret;
}

static int cli_loadmscat(FILE *fs, const char *dbname, struct cl_engine *engine, unsigned int options, struct cli_dbio *dbio) {
    fmap_t *map;

    if(!(map = fmap(fileno(fs), 0, 0))) {
	cli_dbgmsg("Can't map cat: %s\n", dbname);
	return 0;
    }

    if(asn1_load_mscat(map, engine))
	cli_dbgmsg("Failed to load certificates from cat: %s\n", dbname);
    funmap(map);
    return 0;
}

static int cli_loadopenioc(FILE *fs, const char *dbname, struct cl_engine *engine, unsigned int options)
{
    int rc;
    rc = openioc_parse(dbname, fileno(fs), engine, options);
    if (rc != CL_SUCCESS)
        return CL_EMALFDB;
    return rc;
}

static int cli_loaddbdir(const char *dirname, struct cl_engine *engine, unsigned int *signo, unsigned int options);

int cli_load(const char *filename, struct cl_engine *engine, unsigned int *signo, unsigned int options, struct cli_dbio *dbio)
{
	FILE *fs = NULL;
	int ret = CL_SUCCESS;
	uint8_t skipped = 0;
	const char *dbname;
	char buff[FILEBUFF];


    if(dbio && dbio->chkonly) {
	while(cli_dbgets(buff, FILEBUFF, NULL, dbio));
	return CL_SUCCESS;
    }

    if(!dbio && (fs = fopen(filename, "rb")) == NULL) {
	if(options & CL_DB_DIRECTORY) { /* bb#1624 */
	    if(access(filename, R_OK)) {
		if(errno == ENOENT) {
		    cli_dbgmsg("Detected race condition, ignoring old file %s\n", filename);
		    return CL_SUCCESS;
		}
	    }
	}
	cli_errmsg("cli_load(): Can't open file %s\n", filename);
	return CL_EOPEN;
    }

    if((dbname = strrchr(filename, *PATHSEP)))
	dbname++;
    else
	dbname = filename;

    if(cli_strbcasestr(dbname, ".db")) {
	ret = cli_loaddb(fs, engine, signo, options, dbio, dbname);

    } else if(cli_strbcasestr(dbname, ".cvd")) {
	ret = cli_cvdload(fs, engine, signo, options, 0, filename, 0);

    } else if(cli_strbcasestr(dbname, ".cld")) {
	ret = cli_cvdload(fs, engine, signo, options, 1, filename, 0);

    } else if(cli_strbcasestr(dbname, ".cud")) {
	ret = cli_cvdload(fs, engine, signo, options, 2, filename, 0);

    } else if (cli_strbcasestr(dbname, ".crb")) {
        ret = cli_loadcrt(fs, engine, dbio);

    } else if(cli_strbcasestr(dbname, ".hdb") || cli_strbcasestr(dbname, ".hsb")) {
	ret = cli_loadhash(fs, engine, signo, MD5_HDB, options, dbio, dbname);
    } else if(cli_strbcasestr(dbname, ".hdu") || cli_strbcasestr(dbname, ".hsu")) {
	if(options & CL_DB_PUA)
	    ret = cli_loadhash(fs, engine, signo, MD5_HDB, options | CL_DB_PUA_MODE, dbio, dbname);
	else
	    skipped = 1;

    } else if(cli_strbcasestr(dbname, ".fp") || cli_strbcasestr(dbname, ".sfp")) {
	ret = cli_loadhash(fs, engine, signo, MD5_FP, options, dbio, dbname);
    } else if(cli_strbcasestr(dbname, ".mdb") || cli_strbcasestr(dbname, ".msb")) {
	ret = cli_loadhash(fs, engine, signo, MD5_MDB, options, dbio, dbname);

    } else if(cli_strbcasestr(dbname, ".mdu") || cli_strbcasestr(dbname, ".msu")) {
	if(options & CL_DB_PUA)
	    ret = cli_loadhash(fs, engine, signo, MD5_MDB, options | CL_DB_PUA_MODE, dbio, dbname);
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
    } else if(cli_strbcasestr(filename, ".cbc")) {
	if(options & CL_DB_BYTECODE)
	    ret = cli_loadcbc(fs, engine, signo, options, dbio, dbname);
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

    } else if(cli_strbcasestr(dbname, ".info")) {
	ret = cli_loadinfo(fs, engine, options, dbio);

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

    } else if(cli_strbcasestr(dbname, ".ign") || cli_strbcasestr(dbname, ".ign2")) {
	ret = cli_loadign(fs, engine, options, dbio);

    } else if(cli_strbcasestr(dbname, ".idb")) {
    	ret = cli_loadidb(fs, engine, signo, options, dbio);

    } else if(cli_strbcasestr(dbname, ".cdb")) {
    	ret = cli_loadcdb(fs, engine, signo, options, dbio);
    } else if(cli_strbcasestr(dbname, ".cat")) {
	ret = cli_loadmscat(fs, dbname, engine, options, dbio);
    } else if(cli_strbcasestr(dbname, ".ioc")) {
	ret = cli_loadopenioc(fs, dbname, engine, options);
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
	int ret = CL_EOPEN, have_cld, ends_with_sep = 0;
	size_t dirname_len;
	struct cl_cvd *daily_cld, *daily_cvd;


    cli_dbgmsg("Loading databases from %s\n", dirname);

    if((dd = opendir(dirname)) == NULL) {
        cli_errmsg("cli_loaddbdir(): Can't open directory %s\n", dirname);
        return CL_EOPEN;
    }

    dirname_len = strlen(dirname);
    if(dirname_len >= strlen(PATHSEP)) {
        if(strcmp(dirname + dirname_len - strlen(PATHSEP), PATHSEP) == 0) {
            cli_dbgmsg("cli_loaddbdir(): dirname ends with separator\n");
            ends_with_sep = 1;
        }
    }

    /* first round - load .ign and .ign2 files */
#ifdef HAVE_READDIR_R_3
    while(!readdir_r(dd, &result.d, &dent) && dent) {
#elif defined(HAVE_READDIR_R_2)
    while((dent = (struct dirent *) readdir_r(dd, &result.d))) {
#else
    while((dent = readdir(dd))) {
#endif
	if(dent->d_ino)
	{
	    if(cli_strbcasestr(dent->d_name, ".ign") || cli_strbcasestr(dent->d_name, ".ign2")) {
		dbfile = (char *) cli_malloc(strlen(dent->d_name) + dirname_len + 2);
		if(!dbfile) {
		    cli_errmsg("cli_loaddbdir(): dbfile == NULL\n");
		    closedir(dd);
		    return CL_EMEM;
		}
		if(ends_with_sep)
		    sprintf(dbfile, "%s%s", dirname, dent->d_name);
		else
                    sprintf(dbfile, "%s"PATHSEP"%s", dirname, dent->d_name);
		ret = cli_load(dbfile, engine, signo, options, NULL);
		if(ret) {
		    cli_errmsg("cli_loaddbdir(): error loading database %s\n", dbfile);
		    free(dbfile);
		    closedir(dd);
		    return ret;
		}
		free(dbfile);
	    }
	}
    }

    /* the daily db must be loaded before main */
    dbfile = (char *) cli_malloc(dirname_len + 20);
    if(!dbfile) {
	closedir(dd);
    cli_errmsg("cli_loaddbdir: Can't allocate memory for dbfile\n");
	return CL_EMEM;
    }

    if(ends_with_sep)
        sprintf(dbfile, "%sdaily.cld", dirname);
    else
        sprintf(dbfile, "%s"PATHSEP"daily.cld", dirname);
    have_cld = !access(dbfile, R_OK);
    if(have_cld) {
	daily_cld = cl_cvdhead(dbfile);
	if(!daily_cld) {
	    cli_errmsg("cli_loaddbdir(): error parsing header of %s\n", dbfile);
	    free(dbfile);
	    closedir(dd);
	    return CL_EMALFDB;
	}
    }
    if(ends_with_sep)
        sprintf(dbfile, "%sdaily.cvd", dirname);
    else
        sprintf(dbfile, "%s"PATHSEP"daily.cvd", dirname);
    if(!access(dbfile, R_OK)) {
	if(have_cld) {
	    daily_cvd = cl_cvdhead(dbfile);
	    if(!daily_cvd) {
		cli_errmsg("cli_loaddbdir(): error parsing header of %s\n", dbfile);
		free(dbfile);
		cl_cvdfree(daily_cld);
		closedir(dd);
		return CL_EMALFDB;
	    }
	    if(daily_cld->version > daily_cvd->version) {
		if(ends_with_sep)
                    sprintf(dbfile, "%sdaily.cld", dirname);
		else
                    sprintf(dbfile, "%s"PATHSEP"daily.cld", dirname);
	    }
	    cl_cvdfree(daily_cvd);
	}
    } else {
	if(ends_with_sep)
	    sprintf(dbfile, "%sdaily.cld", dirname);
	else
	    sprintf(dbfile, "%s"PATHSEP"daily.cld", dirname);
    }
    if(have_cld)
	cl_cvdfree(daily_cld);

    if(!access(dbfile, R_OK) && (ret = cli_load(dbfile, engine, signo, options, NULL))) {
	free(dbfile);
	closedir(dd);
	return ret;
    }

    /* try to load local.gdb next */
    if(ends_with_sep)
        sprintf(dbfile, "%slocal.gdb", dirname);
    else
        sprintf(dbfile, "%s"PATHSEP"local.gdb", dirname);
    if(!access(dbfile, R_OK) && (ret = cli_load(dbfile, engine, signo, options, NULL))) {
	free(dbfile);
	closedir(dd);
	return ret;
    }

    /* check for and load daily.cfg */
    if(ends_with_sep)
        sprintf(dbfile, "%sdaily.cfg", dirname);
    else
        sprintf(dbfile, "%s"PATHSEP"daily.cfg", dirname);
    if(!access(dbfile, R_OK) && (ret = cli_load(dbfile, engine, signo, options, NULL))) {
	free(dbfile);
	closedir(dd);
	return ret;
    }
    free(dbfile);

    /* second round - load everything else */
    rewinddir(dd);
#ifdef HAVE_READDIR_R_3
    while(!readdir_r(dd, &result.d, &dent) && dent) {
#elif defined(HAVE_READDIR_R_2)
    while((dent = (struct dirent *) readdir_r(dd, &result.d))) {
#else
    while((dent = readdir(dd))) {
#endif
	if(dent->d_ino)
	{
	    if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..") && strcmp(dent->d_name, "daily.cvd") && strcmp(dent->d_name, "daily.cld") && strcmp(dent->d_name, "daily.cfg") && CLI_DBEXT(dent->d_name)) {
		if((options & CL_DB_OFFICIAL_ONLY) && !strstr(dirname, "clamav-") && !cli_strbcasestr(dent->d_name, ".cld") && !cli_strbcasestr(dent->d_name, ".cvd")) {
		    cli_dbgmsg("Skipping unofficial database %s\n", dent->d_name);
		    continue;
		}

		dbfile = (char *) cli_malloc(strlen(dent->d_name) + dirname_len + 2);
		if(!dbfile) {
		    cli_errmsg("cli_loaddbdir(): dbfile == NULL\n");
		    closedir(dd);
		    return CL_EMEM;
		}
                if(ends_with_sep)
		    sprintf(dbfile, "%s%s", dirname, dent->d_name);
                else
		    sprintf(dbfile, "%s"PATHSEP"%s", dirname, dent->d_name);
		ret = cli_load(dbfile, engine, signo, options, NULL);
		if(ret) {
		    cli_errmsg("cli_loaddbdir(): error loading database %s\n", dbfile);
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
	cli_errmsg("cli_loaddbdir(): No supported database files found in %s\n", dirname);

    return ret;
}

int cl_load(const char *path, struct cl_engine *engine, unsigned int *signo, unsigned int dboptions)
{
	STATBUF sb;
	int ret;

    if(!engine) {
	cli_errmsg("cl_load: engine == NULL\n");
	return CL_ENULLARG;
    }

    if(engine->dboptions & CL_DB_COMPILED) {
	cli_errmsg("cl_load(): can't load new databases when engine is already compiled\n");
	return CL_EARG;
    }

    if(CLAMSTAT(path, &sb) == -1) {
        switch (errno) {
#if defined(EACCES)
            case EACCES:
                cli_errmsg("cl_load(): Access denied for path: %s\n", path);
                break;
#endif
#if defined(ENOENT)
            case ENOENT:
                cli_errmsg("cl_load(): No such file or directory: %s\n", path);
                break;
#endif
#if defined(ELOOP)
            case ELOOP:
                cli_errmsg("cl_load(): Too many symbolic links encountered in path: %s\n", path);
                break;
#endif
#if defined(EOVERFLOW)
            case EOVERFLOW:
                cli_errmsg("cl_load(): File size is too large to be recognized. Path: %s\n", path);
                break;
#endif
#if defined(EIO)
            case EIO:
                cli_errmsg("cl_load(): An I/O error occurred while reading from path: %s\n", path);
                break;
#endif
            default:
                cli_errmsg("cl_load: Can't get status of: %s\n", path);
                break;
        }
        return CL_ESTAT;
    }

    if((dboptions & CL_DB_PHISHING_URLS) && !engine->phishcheck && (engine->dconf->phishing & PHISHING_CONF_ENGINE))
	if((ret = phishing_init(engine)))
	    return ret;

    if((dboptions & CL_DB_BYTECODE) && !engine->bcs.inited) {
	if((ret = cli_bytecode_init(&engine->bcs)))
	    return ret;
    } else {
	cli_dbgmsg("Bytecode engine disabled\n");
    }

    if(cli_cache_init(engine))
	return CL_EMEM;

    engine->dboptions |= dboptions;

    switch(sb.st_mode & S_IFMT) {
	case S_IFREG:
	    ret = cli_load(path, engine, signo, dboptions, NULL);
	    break;

	case S_IFDIR:
	    ret = cli_loaddbdir(path, engine, signo, dboptions | CL_DB_DIRECTORY);
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
	struct dirent *dent;
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
	if(dent->d_ino)
	{
	    if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..") && CLI_DBEXT(dent->d_name)) {
		dbstat->entries++;
		dbstat->stattab = (STATBUF *) cli_realloc2(dbstat->stattab, dbstat->entries * sizeof(STATBUF));
		if(!dbstat->stattab) {
		    cl_statfree(dbstat);
		    closedir(dd);
		    return CL_EMEM;
		}

#ifdef _WIN32
		dbstat->statdname = (char **) cli_realloc2(dbstat->statdname, dbstat->entries * sizeof(char *));
		if(!dbstat->statdname) {
            cli_errmsg("cl_statinidir: Can't allocate memory for dbstat->statdname\n");
		    cl_statfree(dbstat);
		    closedir(dd);
		    return CL_EMEM;
		}
#endif

                fname = cli_malloc(strlen(dirname) + strlen(dent->d_name) + 32);
		if(!fname) {
            cli_errmsg("cl_statinidir: Cant' allocate memory for fname\n");
		    cl_statfree(dbstat);
		    closedir(dd);
		    return CL_EMEM;
		}
		sprintf(fname, "%s"PATHSEP"%s", dirname, dent->d_name);
#ifdef _WIN32
		dbstat->statdname[dbstat->entries - 1] = (char *) cli_malloc(strlen(dent->d_name) + 1);
		if(!dbstat->statdname[dbstat->entries - 1]) {
            cli_errmsg("cli_statinidir: Can't allocate memory for dbstat->statdname\n");
		    cl_statfree(dbstat);
		    closedir(dd);
		    return CL_EMEM;
		}

		strcpy(dbstat->statdname[dbstat->entries - 1], dent->d_name);
#endif
		CLAMSTAT(fname, &dbstat->stattab[dbstat->entries - 1]);
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
	STATBUF sb;
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
	if(dent->d_ino)
	{
	    if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..") && CLI_DBEXT(dent->d_name)) {
                fname = cli_malloc(strlen(dbstat->dir) + strlen(dent->d_name) + 32);
		if(!fname) {
            cli_errmsg("cl_statchkdir: can't allocate memory for fname\n");
		    closedir(dd);
		    return CL_EMEM;
		}

		sprintf(fname, "%s"PATHSEP"%s", dbstat->dir, dent->d_name);
		CLAMSTAT(fname, &sb);
		free(fname);

		found = 0;
		for(i = 0; i < dbstat->entries; i++)
#ifdef _WIN32
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

#ifdef _WIN32
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

    if (engine->cb_stats_submit)
        engine->cb_stats_submit(engine, engine->stats_data);

#ifdef CL_THREAD_SAFE
    if (engine->stats_data) {
        cli_intel_t *intel = (cli_intel_t *)(engine->stats_data);

        pthread_mutex_destroy(&(intel->mutex));
    }

    pthread_mutex_unlock(&cli_ref_mutex);
#endif
    if (engine->stats_data)
        free(engine->stats_data);

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

    if((root = engine->hm_hdb)) {
	hm_free(root);
	mpool_free(engine->mempool, root);
    }

    if((root = engine->hm_mdb)) {
	hm_free(root);
	mpool_free(engine->mempool, root);
    }

    if((root = engine->hm_fp)) {
	hm_free(root);
	mpool_free(engine->mempool, root);
    }

    crtmgr_free(&engine->cmgr);

    while(engine->cdb) {
	struct cli_cdb *pt = engine->cdb;
	engine->cdb = pt->next;
	if(pt->name.re_magic)
	    cli_regfree(&pt->name);
	mpool_free(engine->mempool, pt->res2);
	mpool_free(engine->mempool, pt->virname);
	mpool_free(engine->mempool, pt);
    }

    while(engine->dbinfo) {
	struct cli_dbinfo *pt = engine->dbinfo;
	engine->dbinfo = pt->next;
	mpool_free(engine->mempool, pt->name);
	mpool_free(engine->mempool, pt->hash);
	if(pt->cvd)
	    cl_cvdfree(pt->cvd);
	mpool_free(engine->mempool, pt);
    }

    if(engine->dconf) {
        if(engine->dconf->bytecode & BYTECODE_ENGINE_MASK) {
            if (engine->bcs.all_bcs)
                for(i=0;i<engine->bcs.count;i++)
                    cli_bytecode_destroy(&engine->bcs.all_bcs[i]);
            cli_bytecode_done(&engine->bcs);
            free(engine->bcs.all_bcs);
            for (i=0;i<_BC_LAST_HOOK - _BC_START_HOOKS;i++) {
                free (engine->hooks[i]);
            }
        }

        if(engine->dconf->phishing & PHISHING_CONF_ENGINE)
            phishing_done(engine);

        mpool_free(engine->mempool, engine->dconf);
    }

    if(engine->pua_cats)
	mpool_free(engine->mempool, engine->pua_cats);

    if(engine->iconcheck) {
	struct icon_matcher *iconcheck = engine->iconcheck;
	for(i=0; i<3; i++) {
	    if(iconcheck->icons[i]) {
		for (j=0;j<iconcheck->icon_counts[i];j++) {
		    struct icomtr* metric = iconcheck->icons[i];
		    mpool_free(engine->mempool, metric[j].name);
		}
		mpool_free(engine->mempool, iconcheck->icons[i]);
	    }
	}
	if(iconcheck->group_names[0]) {
	    for(i=0; i<iconcheck->group_counts[0]; i++)
		mpool_free(engine->mempool, iconcheck->group_names[0][i]);
	    mpool_free(engine->mempool, iconcheck->group_names[0]);
	}
	if(iconcheck->group_names[1]) {
	    for(i=0; i<iconcheck->group_counts[1]; i++)
		mpool_free(engine->mempool, iconcheck->group_names[1][i]);
	    mpool_free(engine->mempool, iconcheck->group_names[1]);
	}
	mpool_free(engine->mempool, iconcheck);
    }	

    if(engine->tmpdir)
	mpool_free(engine->mempool, engine->tmpdir);

    if(engine->cache)
	cli_cache_destroy(engine);

    cli_ftfree(engine);
    if(engine->ignored) {
	cli_bm_free(engine->ignored);
	mpool_free(engine->mempool, engine->ignored);
    }

#ifdef USE_MPOOL
    if(engine->mempool) mpool_destroy(engine->mempool);
#endif
    free(engine);
    return CL_SUCCESS;
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
	    cli_dbgmsg("Matcher[%u]: %s: AC sigs: %u (reloff: %u, absoff: %u) BM sigs: %u (reloff: %u, absoff: %u) maxpatlen %u %s\n", i, cli_mtargets[i].name, root->ac_patterns, root->ac_reloff_num, root->ac_absoff_num, root->bm_patterns, root->bm_reloff_num, root->bm_absoff_num, root->maxpatlen, root->ac_only ? "(ac_only mode)" : "");
	}
    }
    if(engine->hm_hdb)
	hm_flush(engine->hm_hdb);

    if(engine->hm_mdb)
	hm_flush(engine->hm_mdb);

    if(engine->hm_fp)
	hm_flush(engine->hm_fp);

    if((ret = cli_build_regex_list(engine->whitelist_matcher))) {
	    return ret;
    }
    if((ret = cli_build_regex_list(engine->domainlist_matcher))) {
	    return ret;
    }
    if(engine->ignored) {
	cli_bm_free(engine->ignored);
	mpool_free(engine->mempool, engine->ignored);
	engine->ignored = NULL;
    }
    cli_dconf_print(engine->dconf);
    mpool_flush(engine->mempool);

    /* Compile bytecode */
    if((ret = cli_bytecode_prepare2(engine, &engine->bcs, engine->dconf->bytecode))) {
	cli_errmsg("Unable to compile/load bytecode: %s\n", cl_strerror(ret));
	return ret;
    }

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

static int countentries(const char *dbname, unsigned int *sigs)
{
	char buffer[CLI_DEFAULT_LSIG_BUFSIZE + 1];
	FILE *fs;
	unsigned int entry = 0;

    fs = fopen(dbname, "r");
    if(!fs) {
	cli_errmsg("countentries: Can't open file %s\n", dbname);
	return CL_EOPEN;
    }
    while(fgets(buffer, sizeof(buffer), fs)) {
	if(buffer[0] == '#')
	    continue;
	entry++;
    }
    fclose(fs);
    *sigs += entry;
    return CL_SUCCESS;
}

static int countsigs(const char *dbname, unsigned int options, unsigned int *sigs)
{
    if((cli_strbcasestr(dbname, ".cvd") || cli_strbcasestr(dbname, ".cld"))) {
	if(options & CL_COUNTSIGS_OFFICIAL) {
		struct cl_cvd *cvd = cl_cvdhead(dbname);
	    if(!cvd) {
		cli_errmsg("countsigs: Can't parse %s\n", dbname);
		return CL_ECVD;
	    }
	    *sigs += cvd->sigs;
	    cl_cvdfree(cvd);
	}
    } else if(cli_strbcasestr(dbname, ".cbc")) {
	if(options & CL_COUNTSIGS_UNOFFICIAL)
	    (*sigs)++;

    } else if(cli_strbcasestr(dbname, ".wdb") || cli_strbcasestr(dbname, ".fp") || cli_strbcasestr(dbname, ".ftm") || cli_strbcasestr(dbname, ".cfg") || cli_strbcasestr(dbname, ".cat")) {
	/* ignore */

    } else if((options & CL_COUNTSIGS_UNOFFICIAL) && CLI_DBEXT(dbname)) {
	return countentries(dbname, sigs);
    }

    return CL_SUCCESS;
}

int cl_countsigs(const char *path, unsigned int countoptions, unsigned int *sigs)
{
	STATBUF sb;
	char fname[1024];
	struct dirent *dent;
#if defined(HAVE_READDIR_R_3) || defined(HAVE_READDIR_R_2)
	union {
	    struct dirent d;
	    char b[offsetof(struct dirent, d_name) + NAME_MAX + 1];
	} result;
#endif
	DIR *dd;
	int ret;

    if(!sigs)
	return CL_ENULLARG;

    if(CLAMSTAT(path, &sb) == -1) {
	cli_errmsg("cl_countsigs: Can't stat %s\n", path);
	return CL_ESTAT;
    }

    if((sb.st_mode & S_IFMT) == S_IFREG) {
	return countsigs(path, countoptions, sigs);

    } else if((sb.st_mode & S_IFMT) == S_IFDIR) {
	if((dd = opendir(path)) == NULL) {
	    cli_errmsg("cl_countsigs: Can't open directory %s\n", path);
	    return CL_EOPEN;
	}
#ifdef HAVE_READDIR_R_3
	while(!readdir_r(dd, &result.d, &dent) && dent) {
#elif defined(HAVE_READDIR_R_2)
	while((dent = (struct dirent *) readdir_r(dd, &result.d))) {
#else
	while((dent = readdir(dd))) {
#endif
	    if(dent->d_ino) {
		if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..") && CLI_DBEXT(dent->d_name)) {
		    snprintf(fname, sizeof(fname), "%s"PATHSEP"%s", path, dent->d_name);
		    fname[sizeof(fname) - 1] = 0;
		    ret = countsigs(fname, countoptions, sigs);
		    if(ret != CL_SUCCESS) {
			closedir(dd);
			return ret;
		    }
		}
	    }
	}
	closedir(dd);
    } else {
	cli_errmsg("cl_countsigs: Unsupported file type\n");
	return CL_EARG;
    }

    return CL_SUCCESS;
}

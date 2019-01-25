/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *  Copyright (C) 2002-2007 Tomasz Kojm <tkojm@clamav.net>
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
#include <stdint.h>
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

#include "clamav.h"
#include "cvd.h"
#ifdef	HAVE_STRINGS_H
#include <strings.h>
#endif
#include "matcher-ac.h"
#include "matcher-bm.h"
#include "matcher-pcre.h"
#include "matcher-byte-comp.h"
#include "matcher-hash.h"
#include "matcher.h"
#include "others.h"
#include "str.h"
#include "dconf.h"
#include "filetypes.h"
#include "filetypes_int.h"
#include "readdb.h"
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

#ifdef HAVE_YARA
#include "yara_clam.h"
#include "yara_compiler.h"
#include "yara_grammar.h"
#include "yara_lexer.h"
#endif


#define MAX_LDB_SUBSIGS 64

char *cli_virname(const char *virname, unsigned int official)
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

int cli_sigopts_handler(struct cli_matcher *root, const char *virname, const char *hexsig, uint8_t sigopts, uint16_t rtype, uint16_t type, const char *offset, uint8_t target, const uint32_t *lsigid, unsigned int options)
{
    char *hexcpy, *start, *end, *mid;
    unsigned int i;
    int ret = CL_SUCCESS;

    /*
     * cyclic loops with cli_parse_add are impossible now as cli_parse_add 
     * no longer calls cli_sigopts_handler; leaving here for safety
     */
    if (sigopts & ACPATT_OPTION_ONCE) {
        cli_errmsg("cli_sigopts_handler: invalidly called multiple times!\n");
        return CL_EPARSE;
    }

    hexcpy = cli_strdup(hexsig);
    if (!hexcpy)
        return CL_EMEM;

    sigopts |= ACPATT_OPTION_ONCE;

    /* REGEX testing and sigopt handling */
    start = strchr(hexcpy, '/');
    end = strrchr(hexcpy, '/');

    if (start != end) {
        /* FULLWORD regex sigopt handling */
        if (sigopts & ACPATT_OPTION_FULLWORD) {
            size_t ovrlen = strlen(hexcpy)+21;
            char *hexovr = cli_calloc(ovrlen, sizeof(char));
            if (!hexovr) {
                free(hexcpy);
                return CL_EMEM;
            }

            *start++ = '\0';
            *end++ = '\0';

            snprintf(hexovr, ovrlen, "%s/([\\W_]|\\A)%s([\\W_]|\\Z)/%s", hexcpy, start, end);

            free(hexcpy);
            hexcpy = hexovr;
        }
        /* NOCASE sigopt is passed onto the regex-opt handler */
        if (sigopts & ACPATT_OPTION_NOCASE) {
            size_t ovrlen = strlen(hexcpy)+2;
            char *hexovr = cli_calloc(ovrlen, sizeof(char));
            if (!hexovr) {
                free(hexcpy);
                return CL_EMEM;
            }

            snprintf(hexovr, ovrlen, "%si", hexcpy);

            free(hexcpy);
            hexcpy = hexovr;
        }
        /* WIDE sigopt is unsupported */
        if (sigopts & ACPATT_OPTION_WIDE) {
            cli_errmsg("cli_parse_add: wide modifier [w] is not supported for regex subsigs\n");
            free(hexcpy);
            return CL_EMALFDB;
        }

        ret = cli_parse_add(root, virname, hexcpy, sigopts, rtype, type, offset, target, lsigid, options);
        free(hexcpy);
        return ret;
    }

    /* BCOMP sigopt handling */
    start = strchr(hexcpy, '#');
    end = strrchr(hexcpy, '#');
    mid = strchr(hexcpy, '(');

    if (start != end && mid && (*(++mid) == '#' ||  !strncmp(mid, ">>", 2) ||
                                    !strncmp(mid, "<<", 2) || !strncmp(mid, "0#", 2))) {
        /* TODO byte compare currently does not have support for sigopts, pass through */
        ret = cli_parse_add(root, virname, hexcpy, sigopts, rtype, type, offset, target, lsigid, options);
        free(hexcpy);
        return ret;
    }

    /* NORMAL HEXSIG sigopt handling */
    /* FULLWORD sigopt handling - only happens once */
    if (sigopts & ACPATT_OPTION_FULLWORD) {
        char *rechar;
        size_t ovrlen = strlen(hexcpy)+7;
        char *hexovr = cli_calloc(ovrlen, sizeof(char));
        if (!hexovr) {
            free(hexcpy);
            return CL_EMEM;
        }

        snprintf(hexovr, ovrlen, "(W)%s(W)", hexcpy);

        /* change the '[' and ']' to '{' and '}' since there are now two bytes */
        rechar = hexovr;
        while ((rechar = strchr(rechar, '['))) { //TEST TODO
            *rechar = '{';

            if (!(rechar = strchr(rechar, ']'))) {
                cli_errmsg("cli_parse_add: unmatched '[' in signature %s\n", virname);
                free(hexcpy);
                free(hexovr);
                return CL_EMALFDB;
            }
            *rechar = '}';
        }

        free(hexcpy);
        hexcpy = hexovr;
    }

    /* WIDE sigopt handling - only happens once (after fullword)
     * TODO - consider handling in cli_ac_addpatt? (two pattern possibility)
     */
    if (sigopts & ACPATT_OPTION_WIDE) {
        size_t ovrlen = 2*strlen(hexcpy)+1;
        char *hexovr = cli_calloc(ovrlen, sizeof(char));
        if (!hexovr) {
            free(hexcpy);
            return CL_EMEM;
        }

        /* clamav-specific wildcards need to be handled here! */
        for (i = 0; i < strlen(hexcpy); ++i) {
           size_t len = strlen(hexovr);

            if (hexcpy[i] == '*' || hexcpy[i] == '|' || hexcpy[i] == ')') {
                hexovr[len] = hexcpy[i];
            } else if (hexcpy[i] == '[') {
                /* change the '[' and ']' to '{' and '}' since there are now two bytes */
                hexovr[len++] = '{';
                ++i;
                while (i < strlen(hexcpy) && hexcpy[i] != ']')
                    hexovr[len++] = hexcpy[i++];

                hexovr[len] = '}';
            } else if (hexcpy[i] == '{') {
                while (i < strlen(hexcpy) && hexcpy[i] != '}')
                    hexovr[len++] = hexcpy[i++];

                hexovr[len] = '}';
            } else if (hexcpy[i] == '!' || hexcpy[i] == '(') {
                if (hexcpy[i] == '!')
                    hexovr[len++] = hexcpy[i++];

                /* copies '(' */
                hexovr[len] = hexcpy[i];

                if (hexcpy[i+1] == 'B' || hexcpy[i+1] == 'L' || hexcpy[i+1] == 'W') {
                    ++len; ++i;
                    hexovr[len++] = hexcpy[i++];
                    if (hexcpy[i] != ')') {
                        free(hexcpy);
                        free(hexovr);
                        return CL_EMALFDB;
                    }
                    hexovr[len] = hexcpy[i];
                }
            } else {
                //snprintf(hexovr+len, ovrlen-len, "%02x%c%c", 0, hexcpy[i], hexcpy[i+1]);
                snprintf(hexovr+len, ovrlen-len, "%c%c%02x", hexcpy[i], hexcpy[i+1], 0);
                ++i;
            }
        }

        /* NOCASE sigopt is handled in cli_ac_addsig */
        ret = cli_parse_add(root, virname, hexovr, sigopts, rtype, type, offset, target, lsigid, options);
        free(hexovr);
        if (ret != CL_SUCCESS || !(sigopts & ACPATT_OPTION_ASCII)) {
            free(hexcpy);
            return ret;
        } else {
            /* disable wide sigopt for ascii variant */
            sigopts &= ~ACPATT_OPTION_WIDE;
        }
    }

    /* ASCII sigopt; NOCASE sigopt is handled in cli_ac_addsig */
    ret = cli_parse_add(root, virname, hexcpy, sigopts, rtype, type, offset, target, lsigid, options);
    free(hexcpy);
    return ret;
}

#define PCRE_TOKENS 4
int cli_parse_add(struct cli_matcher *root, const char *virname, const char *hexsig, uint8_t sigopts, uint16_t rtype, uint16_t type, const char *offset, uint8_t target, const uint32_t *lsigid, unsigned int options)
{
    struct cli_bm_patt *bm_new;
    char *pt, *hexcpy, *start = NULL, *mid = NULL, *end = NULL, *n, l, r;
    const char *wild;
    int ret, asterisk = 0, range;
    unsigned int i, j, hexlen, nest, parts = 0;
    int mindist = 0, maxdist = 0, error = 0;

    hexlen = strlen(hexsig);
    if (hexsig[0] == '$') {
        /* macro */
        unsigned int smin, smax, tid;
        struct cli_ac_patt *patt;

        if (hexsig[hexlen-1] != '$') {
            cli_errmsg("cli_parseadd(): missing terminator $\n");
            return CL_EMALFDB;
        }

        if (!lsigid) {
            cli_errmsg("cli_parseadd(): macro signatures only valid inside logical signatures\n");
            return CL_EMALFDB;
        }

        if (sscanf(hexsig,"${%u-%u}%u$", &smin, &smax, &tid)  != 3) {
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
        patt->length[0] = root->ac_mindepth;

        /* dummy */
        patt->pattern = mpool_calloc(root->mempool, patt->length[0], sizeof(*patt->pattern));
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
    /* expected format => ^offset:trigger/regex/[cflags]$ */
    if (strchr(hexsig, '/')) {
        char *start, *end;
        const char *trigger, *pattern, *cflags;

        /* get copied */
        hexcpy = cli_strdup(hexsig);
        if(!hexcpy)
            return CL_EMEM;

        /* get delimiters-ed */
        start = strchr(hexcpy, '/');
        end = strrchr(hexcpy, '/');

        /* get pcre-ed */
        if (start == end) {
            cli_errmsg("cli_parseadd(): PCRE subsig mismatched '/' delimiter\n");
            free(hexcpy);
            return CL_EMALFDB;
        }
#if HAVE_PCRE
        /* get checked */
        if (hexsig[0] == '/') {
            cli_errmsg("cli_parseadd(): PCRE subsig must contain logical trigger\n");
            free(hexcpy);
            return CL_EMALFDB;
        }

        /* get NULL-ed */
        *start = '\0';
        *end = '\0';

        /* get tokens-ed */
        trigger = hexcpy;
        pattern = start+1;
        cflags = end+1;
        if (*cflags == '\0') /* get compat-ed */
            cflags = NULL;

        /* normal trigger, get added */
        ret = cli_pcre_addpatt(root, virname, trigger, pattern, cflags, offset, lsigid, options);
        free(hexcpy);
        return ret;
#else
        free(hexcpy);
        cli_errmsg("cli_parseadd(): cannot parse PCRE subsig without PCRE support\n");
        return CL_EPARSE;
#endif
    }
    else if((wild = strchr(hexsig, '{'))) {
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
            ret = cli_parse_add(root, virname, hexcpy, sigopts, rtype, type, offset, target, lsigid, options);
            free(hexcpy);

            return ret;
        }

        root->ac_partsigs++;

        if(!(hexcpy = cli_strdup(hexsig)))
            return CL_EMEM;

        nest = 0;
        for(i = 0; i < hexlen; i++) {
            if(hexsig[i] == '(')
                nest++;
            else if(hexsig[i] == ')')
                nest--;
            else if(hexsig[i] == '{') {
                if (nest) {
                    cli_errmsg("cli_parse_add(): Alternative match contains unsupported ranged wildcard\n");
                    free(hexcpy);
                    return CL_EMALFDB;
                }
                parts++;
            } else if(hexsig[i] == '*') {
                if (nest) {
                    cli_errmsg("cli_parse_add(): Alternative match cannot contain unbounded wildcards\n");
                    free(hexcpy);
                    return CL_EMALFDB;
                }
                parts++;
            }
        }

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

            if((ret = cli_ac_addsig(root, virname, start, sigopts, root->ac_partsigs, parts, i, rtype, type, mindist, maxdist, offset, lsigid, options))) {
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

        nest = 0;
        for(i = 0; i < hexlen; i++) {
            if(hexsig[i] == '(')
                nest++;
            else if(hexsig[i] == ')')
                nest--;
            else if(hexsig[i] == '*') {
                if (nest) {
                    cli_errmsg("cli_parse_add(): Alternative match cannot contain unbounded wildcards\n");
                    return CL_EMALFDB;
                }
                parts++;
            }
        }

        if(parts)
            parts++;

        for(i = 1; i <= parts; i++) {
            if((pt = cli_strtok(hexsig, i - 1, "*")) == NULL) {
                cli_errmsg("cli_parse_add():Can't extract part %d of partial signature.\n", i);
                return CL_EMALFDB;
            }

            if((ret = cli_ac_addsig(root, virname, pt, sigopts, root->ac_partsigs, parts, i, rtype, type, 0, 0, offset, lsigid, options))) {
                cli_errmsg("cli_parse_add(): Problem adding signature (2).\n");
                free(pt);
                return ret;
            }

            free(pt);
        }
    } else if((start = strchr(hexsig, '(')) && (mid = strchr(hexsig, '#')) && (end = strrchr(hexsig, '#')) && mid != end) {

        /* format seems to match byte_compare */
        if ( ret = cli_bcomp_addpatt(root, virname, hexsig, lsigid, options) ) {
            cli_errmsg("cli_parse_add(): Problem adding signature (2b).\n");
            return ret;
        }

    } else if(root->ac_only || type || lsigid || sigopts || strpbrk(hexsig, "?([") || (root->bm_offmode && (!strcmp(offset, "*") || strchr(offset, ','))) || strstr(offset, "VI") || strchr(offset, '$')) {
        if((ret = cli_ac_addsig(root, virname, hexsig, sigopts, 0, 0, 0, rtype, type, 0, 0, offset, lsigid, options))) {
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

        if(bm_new->length > root->maxpatlen)
            root->maxpatlen = bm_new->length;

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

    UNUSEDPARAM(options);

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

	    cli_dbgmsg("Initializing AC pattern matcher of root[%d]\n", i);
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

static char *cli_signorm(const char *signame)
{
    char *new_signame = NULL;
    size_t pad = 0;
    size_t nsz;

    if (!signame)
        return NULL;

    nsz = strlen(signame);

    if (nsz > 3 && signame[nsz-1] == '}') {
        char *pt = strstr(signame, ".{");
        if (pt)         /* strip the ".{ }" clause at the end of signame */
            nsz = pt - signame;
        else
            return NULL;
    } else if (nsz > 11) {
        if (!strncmp(signame+nsz-11, ".UNOFFICIAL", 11))
            nsz -= 11;
        else
            return NULL;
    } else if (nsz > 2)
        return NULL;
    
    if (nsz < 3) {
        pad = 3 - nsz;
        nsz = 3;
    }

    new_signame = malloc(nsz + 1);
    if (!new_signame) 
        return NULL;

    memcpy(new_signame, signame, nsz-pad);
    new_signame[nsz] = '\0';

    while (pad > 0)
        new_signame[nsz-pad--] = '\x20';

    return new_signame;
}

static int cli_chkign(const struct cli_matcher *ignored, const char *signame, const char *entry)
{

    const char *md5_expected = NULL;
    char *norm_signame;
    unsigned char digest[16];
    int ret = 0;

    if(!ignored || !signame || !entry)
        return 0;

    norm_signame = cli_signorm(signame);
    if (norm_signame != NULL)
	signame = norm_signame;

    if(cli_bm_scanbuff((const unsigned char *) signame, strlen(signame), &md5_expected, NULL, ignored, 0, NULL, NULL,NULL) == CL_VIRUS)
        do {
            if(md5_expected) {
                cl_hash_data("md5", entry, strlen(entry), digest, NULL);
                if(memcmp(digest, (const unsigned char *) md5_expected, 16))
                    break;
            }
            
            cli_dbgmsg("Ignoring signature %s\n", signame);
            ret = 1;
        } while (0);

    if (norm_signame)
	free(norm_signame);
    return ret;
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

    UNUSEDPARAM(dbname);

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

	if((ret = cli_parse_add(root, start, pt, 0, 0, 0, "*", 0, NULL, options))) {
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

    UNUSEDPARAM(dbname);

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

	if((ret = cli_parse_add(root, virname, sig, 0, 0, 0, offset, target, NULL, options))) {
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
#define ATTRIB_TOKENS   10
#define EXPR_TOKEN_MAX  16
        { "Target",         CLI_TDB_UINT,   (void **) &tdb->target      },
        { "Engine",         CLI_TDB_RANGE,  (void **) &tdb->engine      },

        { "FileSize",       CLI_TDB_RANGE,  (void **) &tdb->filesize    },
        { "EntryPoint",     CLI_TDB_RANGE,  (void **) &tdb->ep      },
        { "NumberOfSections",   CLI_TDB_RANGE,  (void **) &tdb->nos     },

        { "IconGroup1",     CLI_TDB_STR,    (void **) &tdb->icongrp1    },
        { "IconGroup2",     CLI_TDB_STR,    (void **) &tdb->icongrp2    },

        { "Container",      CLI_TDB_FTYPE,  (void **) &tdb->container   },
        { "HandlerType",        CLI_TDB_FTYPE,  (void **) &tdb->handlertype },
        { "Intermediates",  CLI_TDB_FTYPE_EXPR, (void **) &tdb->intermediates },
/*
        { "SectOff",    CLI_TDB_RANGE2, (void **) &tdb->sectoff     },
        { "SectRVA",    CLI_TDB_RANGE2, (void **) &tdb->sectrva     },
        { "SectVSZ",    CLI_TDB_RANGE2, (void **) &tdb->sectvsz     },
        { "SectRAW",    CLI_TDB_RANGE2, (void **) &tdb->sectraw     },
        { "SectRSZ",    CLI_TDB_RANGE2, (void **) &tdb->sectrsz     },
        { "SectURVA",   CLI_TDB_RANGE2, (void **) &tdb->secturva    },
        { "SectUVSZ",   CLI_TDB_RANGE2, (void **) &tdb->sectuvsz    },
        { "SectURAW",   CLI_TDB_RANGE2, (void **) &tdb->secturaw    },
        { "SectURSZ",   CLI_TDB_RANGE2, (void **) &tdb->sectursz    },
*/
        { NULL,     0,          NULL,               }
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
        } else if(strcmp(apt->name, "Target")) {
            have_newext = 1;
        }

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
                cli_dbgmsg("lsigattribs: Unknown file type '%s' in %s\n", pt, tokens[i]);
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

        case CLI_TDB_FTYPE_EXPR:
            {
                char *ftypes[EXPR_TOKEN_MAX];
                unsigned int ftypes_count;

                off[i] = cnt = tdb->cnt[CLI_TDB_UINT];
                ftypes_count = cli_strtokenize(pt, '>', EXPR_TOKEN_MAX, (const char **) ftypes);
                if(!ftypes_count) {
                    cli_dbgmsg("lsigattribs: No intermediate container tokens found.");
                    return 1;
                }
                tdb->cnt[CLI_TDB_UINT] += (ftypes_count + 1);
                tdb->val = (uint32_t *) mpool_realloc2(tdb->mempool, tdb->val, tdb->cnt[CLI_TDB_UINT] * sizeof(uint32_t));
                if(!tdb->val) {
                    tdb->cnt[CLI_TDB_UINT] = 0;
                    return -1;
                }

                tdb->val[cnt++] = ftypes_count;
                for(j = 0; j < ftypes_count; j++) {
                    if((v1 = cli_ftcode(ftypes[j])) == CL_TYPE_ERROR) {
                        cli_dbgmsg("lsigattribs: Unknown file type '%s' in %s\n", ftypes[j], tokens[i]);
                        return 1; /* skip */
                    }
                    tdb->val[cnt++] = v1;
                }
            }
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
        case CLI_TDB_FTYPE_EXPR:
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

#define FREE_TDB_P(x) do {		\
  if(x->cnt[CLI_TDB_UINT])		\
    mpool_free(x->mempool, x->val);		\
  if(x->cnt[CLI_TDB_RANGE])		\
    mpool_free(x->mempool, x->range);	\
  if(x->cnt[CLI_TDB_STR])		\
    mpool_free(x->mempool, x->str);		\
  if(x->macro_ptids)\
    mpool_free(x->mempool, x->macro_ptids);\
  } while(0);

static inline int init_tdb(struct cli_lsig_tdb *tdb, struct cl_engine *engine, char *target, const char *virname)
{
    int ret;

#ifdef USE_MPOOL
    tdb->mempool = engine->mempool;
#endif
    if((ret = lsigattribs(target, tdb))) {
        FREE_TDB_P(tdb);
        if(ret == 1) {
            cli_dbgmsg("init_tdb: Not supported attribute(s) in signature for %s, skipping\n", virname);
            return CL_BREAK;
        }
        return CL_EMALFDB;
    }

    if(tdb->engine) {
        if(tdb->engine[0] > cl_retflevel()) {
            FREE_TDB_P(tdb);
            cli_dbgmsg("init_tdb: Signature for %s not loaded (required f-level: %u)\n", virname, tdb->engine[0]);
            return CL_BREAK;
        } else if(tdb->engine[1] < cl_retflevel()) {
            FREE_TDB_P(tdb);
            return CL_BREAK;
        }
    }

    if(!tdb->target) {
        FREE_TDB_P(tdb);
        cli_errmsg("init_tdb: No target specified in TDB\n");
        return CL_EMALFDB;
    } else if(tdb->target[0] >= CLI_MTARGETS) {
        FREE_TDB_P(tdb);
        cli_dbgmsg("init_tdb: Not supported target type in signature for %s, skipping\n", virname);
        return CL_BREAK;
    }

    if((tdb->icongrp1 || tdb->icongrp2) && tdb->target[0] != 1) {
        FREE_TDB_P(tdb);
        cli_errmsg("init_tdb: IconGroup is only supported in PE (target 1) signatures\n");
        return CL_EMALFDB;
    }

    if((tdb->ep || tdb->nos) && tdb->target[0] != 1 && tdb->target[0] != 6 && tdb->target[0] != 9) {
        FREE_TDB_P(tdb);
        cli_errmsg("init_tdb: EntryPoint/NumberOfSections is only supported in PE/ELF/Mach-O signatures\n");
        return CL_EMALFDB;
    }

    return CL_SUCCESS;
}

/*     0         1        2      3        4        5    ... (max 66)
 * VirusName;Attributes;Logic;SubSig1[;SubSig2[;SubSig3 ... ]]
 * NOTE: Maximum of 64(see MAX_LDB_SUBSIGS) subsignatures (last would be token 66)
 */
#define LDB_TOKENS 67
#define SUB_TOKENS 4
static int load_oneldb(char *buffer, int chkpua, struct cl_engine *engine, unsigned int options, const char *dbname, unsigned int line, unsigned int *sigs, unsigned bc_idx, const char *buffer_cpy, int *skip)
{
    const char *sig, *virname, *offset, *logic, *sigopts;
    struct cli_ac_lsig **newtable, *lsig;
    char *tokens[LDB_TOKENS+1], *subtokens[SUB_TOKENS+1];
    int i, j, subsigs, tokens_count, subtokens_count;
    unsigned short target = 0;
    struct cli_matcher *root;
    struct cli_lsig_tdb tdb;
    uint32_t lsigid[2];
    uint8_t subsig_opts;
    int ret;

    UNUSEDPARAM(dbname);

    tokens_count = cli_ldbtokenize(buffer, ';', LDB_TOKENS + 1, (const char **) tokens, 2);
    if(tokens_count < 4) {
        cli_errmsg("Invalid or unsupported ldb signature format\n");
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
        cli_errmsg("Invalid or unsupported ldb logic\n");
        return CL_EMALFDB;
    }
    subsigs++;

#if !HAVE_PCRE
    /* Regex Usage and Support Check */
    for (i = 0; i < subsigs; ++i) {
        char *slash = strchr(tokens[i+3], '/');
        if (slash && strchr(slash+1, '/')) {
            cli_warnmsg("cli_loadldb: logical signature for %s uses PCREs but support is disabled, skipping\n", virname);
            (*sigs)--;
            return CL_SUCCESS;
        }
    }
#endif

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

    /* enforce MAX_LDB_SUBSIGS(currently 64) subsig cap */
    if(subsigs > MAX_LDB_SUBSIGS) {
        cli_errmsg("cli_loadldb: Broken logical expression or too many subsignatures\n");
        return CL_EMALFDB;
    }

    /* TDB */
    memset(&tdb, 0, sizeof(tdb));
    if ((ret = init_tdb(&tdb, engine, tokens[1], virname)) != CL_SUCCESS) {
        (*sigs)--;
        if (ret == CL_BREAK)
            return CL_SUCCESS;
        return ret;
    }

    root = engine->root[tdb.target[0]];

    lsig = (struct cli_ac_lsig *) mpool_calloc(engine->mempool, 1, sizeof(struct cli_ac_lsig));
    if(!lsig) {
        cli_errmsg("cli_loadldb: Can't allocate memory for lsig\n");
        FREE_TDB(tdb);
        return CL_EMEM;
    }

    lsig->type = CLI_LSIG_NORMAL;
    lsig->u.logic = cli_mpool_strdup(engine->mempool, logic);
    if(!lsig->u.logic) {
        cli_errmsg("cli_loadldb: Can't allocate memory for lsig->logic\n");
        FREE_TDB(tdb);
        mpool_free(engine->mempool, lsig);
        return CL_EMEM;
    }

    lsigid[0] = lsig->id = root->ac_lsigs;

    if (bc_idx)
        root->linked_bcs++;
    root->ac_lsigs++;
    newtable = (struct cli_ac_lsig **) mpool_realloc(engine->mempool, root->ac_lsigtable, root->ac_lsigs * sizeof(struct cli_ac_lsig *));
    if(!newtable) {
        if (bc_idx)
            root->linked_bcs--;
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
        offset = "*";

        sigopts = NULL;
        subsig_opts = 0;

        subtokens_count = cli_ldbtokenize(tokens[3 + i], ':', SUB_TOKENS + 1, (const char **) subtokens, 0);
	    if(!subtokens_count) {
            cli_errmsg("Invalid or unsupported ldb subsignature format\n");
            return CL_EMALFDB;
        }

	    if((subtokens_count % 2) == 0)
            offset = subtokens[0];

	    if(subtokens_count == 3)
            sigopts = subtokens[2];
        else if(subtokens_count == 4)
            sigopts = subtokens[3];

        if(sigopts) { /* signature modifiers */
            for(j = 0; j < (int)strlen(sigopts); j++)
                switch(sigopts[j]) {
                case 'i':
                    subsig_opts |= ACPATT_OPTION_NOCASE;
                    break;
                case 'f':
                    subsig_opts |= ACPATT_OPTION_FULLWORD;
                    break;
                case 'w':
                    subsig_opts |= ACPATT_OPTION_WIDE;
                    break;
                case 'a':
                    subsig_opts |= ACPATT_OPTION_ASCII;
                    break;
                default:
                    cli_errmsg("cli_loadldb: Signature for %s uses invalid option: %02x\n", virname, sigopts[j]);
                    return CL_EMALFDB;
                }
        }

        sig = (subtokens_count % 2) ? subtokens[0] : subtokens[1];

        if(subsig_opts)
            ret = cli_sigopts_handler(root, virname, sig, subsig_opts, 0, 0, offset, target, lsigid, options);
        else
            ret = cli_parse_add(root, virname, sig, 0, 0, 0, offset, target, lsigid, options);

        if(ret)
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

    if(engine->ignored) {
        if(!(buffer_cpy = cli_malloc(sizeof(buffer)))) {
            cli_errmsg("cli_loadldb: Can't allocate memory for buffer_cpy\n");
            return CL_EMEM;
        }
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
	    if((ret = cli_parse_add(engine->root[0], tokens[3], tokens[2], 0, rtype, type, tokens[1], 0, NULL, options)))
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
	    new->length = (uint16_t)strlen(tokens[2]) / 2;
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
	char hash[32];
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
	    if(cli_versig2((unsigned char*)hash, buffer + 5, INFO_NSTR, INFO_ESTR) != CL_SUCCESS) {
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

    UNUSEDPARAM(options);

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
        if (len < 3) {
            int pad = 3 - len;
            /* patch-up for Boyer-Moore minimum length of 3: pad with spaces */ 
            if (signame != buffer) {
                strncpy (buffer, signame, len);
                signame = buffer;
            }
            buffer[3] = '\0';
            while (pad > 0)
                buffer[3-pad--] = '\x20';
            len = 3;
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
	    if(strlen(hash) != 32 || !(new->virname = cli_mpool_hex2str(engine->mempool, hash))) {
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
#define MD5_IMP	    3

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
    else if(mode == MD5_IMP)
	db = engine->hm_imp;
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
	else if(mode == MD5_IMP)
	    engine->hm_imp = db;
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
		if(cl_retflevel() > (unsigned int)max_fl)
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

    UNUSEDPARAM(dbname);

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

	new->filepos[0] = new->filepos[1] = strcmp(tokens[7], "*") ? (unsigned int) atoi(tokens[7]) : (unsigned int) CLI_OFF_ANY;

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
	    cli_errmsg("cli_loadcdb: Unknown container type %s in signature for %s, skipping\n", tokens[1], tokens[0]);
            ret = CL_EMALFDB;
	    mpool_free(engine->mempool, new->virname);
	    mpool_free(engine->mempool, new);
	    break;
	}

	if(strcmp(tokens[3], "*") && cli_regcomp(&new->name, tokens[3], REG_EXTENDED | REG_NOSUB)) {
	    cli_errmsg("cli_loadcdb: Can't compile regular expression %s in signature for %s\n", tokens[3], tokens[0]);
	    mpool_free(engine->mempool, new->virname);
	    mpool_free(engine->mempool, new);
	    ret = CL_EMEM;
	    break;
	}

    #define CDBRANGE(token_str, dest)                                             \
        if (strcmp(token_str, "*"))                                               \
        {                                                                         \
            if (strchr(token_str, '-'))                                           \
            {                                                                     \
                if (sscanf(token_str, "%u-%u", &n0, &n1) != 2)                    \
                {                                                                 \
                    ret = CL_EMALFDB;                                             \
                }                                                                 \
                else                                                              \
                {                                                                 \
                    dest[0] = n0;                                                 \
                    dest[1] = n1;                                                 \
                }                                                                 \
            }                                                                     \
            else                                                                  \
            {                                                                     \
                if (!cli_isnumber(token_str))                                     \
                    ret = CL_EMALFDB;                                             \
                else                                                              \
                    dest[0] = dest[1] = (unsigned int)atoi(token_str);            \
            }                                                                     \
            if (ret != CL_SUCCESS)                                                \
            {                                                                     \
                cli_errmsg("cli_loadcdb: Invalid value %s in signature for %s\n", \
                        token_str, tokens[0]);                                    \
                if (new->name.re_magic)                                           \
                    cli_regfree(&new->name);                                      \
                mpool_free(engine->mempool, new->virname);                        \
                mpool_free(engine->mempool, new);                                 \
                ret = CL_EMEM;                                                    \
                break;                                                            \
            }                                                                     \
        }                                                                         \
        else                                                                      \
        {                                                                         \
            dest[0] = dest[1] = CLI_OFF_ANY;                                      \
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
    size_t line=0, tokens_count;
    cli_crt ca;
    int ret=CL_SUCCESS;
    char *subject=NULL, *pubkey=NULL, *serial=NULL;
    const uint8_t exp[] = "\x01\x00\x01";

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
        if (mp_read_unsigned_bin(&(ca.n), (const unsigned char *)pubkey, strlen(tokens[4])/2) || mp_read_unsigned_bin(&(ca.e), exp, sizeof(exp)-1)) {
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

    UNUSEDPARAM(options);
    UNUSEDPARAM(dbio);

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

#ifdef HAVE_YARA
#define YARA_DEBUG 1
#if (YARA_DEBUG == 2)
#define cli_yaramsg(...) cli_errmsg(__VA_ARGS__)
#elif (YARA_DEBUG == 1)
#define cli_yaramsg(...) cli_dbgmsg(__VA_ARGS__)
#else
#define cli_yaramsg(...) 
#endif

static char *parse_yara_hex_string(YR_STRING *string, int *ret);

static char *parse_yara_hex_string(YR_STRING *string, int *ret)
{
    char *res, *str, *ovr;
    size_t slen, reslen=0, i, j;

    if (!(string) || !(string->string)) {
        if (ret) *ret = CL_ENULLARG;
        return NULL;
    }

    if (!STRING_IS_HEX(string)) {
        if (ret) *ret = CL_EARG;
        return NULL;
    }

    str = (char *)(string->string);

    if ((slen = string->length) == 0) {
        if (ret) *ret = CL_EARG;
        return NULL;
    }

    str = strchr(str, '{')+1;

    for (i=0; i < slen-1; i++) {
        switch (str[i]) {
        case ' ':
        case '\t':
        case '\r':
        case '\n':
        case '}': /* end of hex string */
            break;
        default:
            reslen++;
            break;
        }
    }

    reslen++;
    res = cli_calloc(reslen, 1);
    if (!(res)) {
        if (ret) *ret = CL_EMEM;
        return NULL;
    }

    for (i=0, j=0; i < slen-1 && j < reslen; i++) {
        switch (str[i]) {
        case ' ':
        case '\t':
        case '\r':
        case '\n':
        case '}':
            break;
        case '[':
            /* unbounded range check */
            if ((i+2 < slen-1) && (str[i+1] == '-') && (str[i+2] == ']')) {
                res[j++] = '*';
                i += 2;
            } else {
                res[j++] = '{';
            }
            break;
        case ']':
            res[j++] = '}';
            break;
        default:
            res[j++] = str[i];
            break;
        }
    }

/* FIXME: removing this code because anchored bytes are not sufficiently 
   general for the purposes of yara rule to ClamAV sig conversions.
   1. ClamAV imposes a maximum value for the upper range limit of 32:
      #define AC_CH_MAXDIST 32
      Values larger cause an error in matcher-ac.c
   2. If the upper range values is not present, ClamAV sets the missing
      range value to be equal to the lower range value. This changes the
      semantic of yara jumps.
*/
#ifdef YARA_ANCHOR_SUPPORT
    /* backward anchor overwrite, 2 (hex chars in one byte) */
    if ((ovr = strchr(res, '{')) && ((ovr - res) == 2)) {
        *ovr = '[';
        if ((ovr = strchr(ovr, '}')))
            *ovr = ']';
        else {
            free(res);
            if (ret) *ret = CL_EMALFDB;
            return NULL;
        }
    }
    /* forward anchor overwrite, 2 (hex chars in one byte) +1 (NULL char) */
    if ((ovr = strrchr(res, '}')) && ((res+j - ovr) == 3)) {
        *ovr = ']';
        if ((ovr = strrchr(res, '{')))
            *ovr = '[';
        else {
            free(res);
            if (ret) *ret = CL_EMALFDB;
            return NULL;
        }
    }
#else
    if (((ovr = strchr(res, '{')) && ((ovr - res) == 2)) ||
        ((ovr = strrchr(res, '}')) && ((res+j - ovr) == 3))) {
        cli_errmsg("parse_yara_hex_string: Single byte subpatterns unsupported in ClamAV\n");
        free(res);
        if (ret != NULL)
            *ret = CL_EMALFDB;
        return NULL;
    }
#endif

    if (ret)
        *ret = CL_SUCCESS;
    return res;
}

struct cli_ytable_entry {
    char *offset;
    char *hexstr;
    uint8_t sigopts;
};

struct cli_ytable {
    struct cli_ytable_entry **table;
    int32_t tbl_cnt;
};

static int32_t ytable_lookup(const char *hexsig)
{
    (void) hexsig;
    /* TODO - WRITE ME! */
    return -1;
}

static int ytable_add_attrib(struct cli_ytable *ytable, const char *hexsig, const char *value, int type)
{
    int32_t lookup;

    if (!ytable || !value)
        return CL_ENULLARG;

    if (!hexsig)
        lookup = ytable->tbl_cnt-1; /* assuming to attach to current string */
    else
        lookup = ytable_lookup(hexsig);

    if (lookup < 0) {
        cli_yaramsg("ytable_add_attrib: hexsig cannot be found\n");
        return CL_EARG;
    }

    if (type) {
        /* add to sigopts */
        switch (*value) {
        case 'i':
            ytable->table[lookup]->sigopts |= ACPATT_OPTION_NOCASE;
            break;
        case 'f':
            ytable->table[lookup]->sigopts |= ACPATT_OPTION_FULLWORD;
            break;
        case 'w':
            ytable->table[lookup]->sigopts |= ACPATT_OPTION_WIDE;
            break;
        case 'a':
            ytable->table[lookup]->sigopts |= ACPATT_OPTION_ASCII;
            break;
        default:
            cli_yaramsg("ytable_add_attrib: invalid sigopt %02x\n", *value);
            return CL_EARG;
        }
    }
    else {
        /* overwrite the previous offset */
        if (ytable->table[lookup]->offset)
            free(ytable->table[lookup]->offset);

        ytable->table[lookup]->offset = cli_strdup(value);

        if (!ytable->table[lookup]->offset) {
            cli_yaramsg("ytable_add_attrib: ran out of memory for offset\n");
            return CL_EMEM;
        }
    }

    return CL_SUCCESS;
}

/* function is dumb - TODO - rewrite using hashtable */
static int ytable_add_string(struct cli_ytable *ytable, const char *hexsig)
{
    struct cli_ytable_entry *new;
    struct cli_ytable_entry **newtable;
    int ret;

    if (!ytable || !hexsig)
        return CL_ENULLARG;

    new = cli_calloc(1, sizeof(struct cli_ytable_entry));
    if (!new) {
        cli_yaramsg("ytable_add_string: out of memory for new ytable entry\n");
        return CL_EMEM;
    }

    new->hexstr = cli_strdup(hexsig);
    if (!new->hexstr) {
        cli_yaramsg("ytable_add_string: out of memory for hexsig copy\n");
        free(new);
        return CL_EMEM;
    }

    ytable->tbl_cnt++;
    newtable = cli_realloc(ytable->table, ytable->tbl_cnt * sizeof(struct cli_ytable_entry *));
    if (!newtable) {
        cli_yaramsg("ytable_add_string: failed to reallocate new ytable table\n");
        free(new->hexstr);
        free(new);
        ytable->tbl_cnt--;
        return CL_EMEM;
    }

    newtable[ytable->tbl_cnt-1] = new;
    ytable->table = newtable;

    if ((ret = ytable_add_attrib(ytable, NULL, "*", 0)) != CL_SUCCESS) {
        cli_yaramsg("ytable_add_string: failed to add default offset\n");
        free(new->hexstr);
        free(new);
        ytable->tbl_cnt--;
        return ret;
    }

    return CL_SUCCESS;
}

static void ytable_delete(struct cli_ytable *ytable)
{
    int32_t i;
    if (!ytable)
        return;

    if (ytable->table) {
        for (i = 0; i < ytable->tbl_cnt; ++i) {
            free(ytable->table[i]->offset);
            free(ytable->table[i]->hexstr);
            free(ytable->table[i]);
        }
        free(ytable->table);
    }
}

/* should only operate on HEX STRINGS */
static int yara_hexstr_verify(YR_STRING *string, const char *hexstr, uint32_t *lsigid, struct cl_engine *engine, unsigned int options)
{
    int ret = CL_SUCCESS;

    /* Quick Check 1: NULL String */
    if (!hexstr || !string) {
        cli_warnmsg("load_oneyara[verify]: string is empty\n");
        return CL_ENULLARG;
    }

    /* Quick Check 2: String Too Short */
    if (strlen(hexstr)/2 < CLI_DEFAULT_AC_MINDEPTH) {
        cli_warnmsg("load_oneyara[verify]: string is too short: %s\n", string->identifier);
        return CL_EMALFDB;
    }

    /* Long Check: Attempt to load hexstr */
    if((ret = cli_sigopts_handler(engine->test_root, "test-hex", hexstr, 0, 0, 0, "*", 0, lsigid, options)) != CL_SUCCESS) {
        if (ret == CL_EMALFDB) {
            cli_warnmsg("load_oneyara[verify]: recovered from database loading error\n");
            /* TODO: if necessary, reset testing matcher if error occurs */
            cli_warnmsg("load_oneyara[verify]: string failed test insertion: %s\n", string->identifier);
        }
        return ret;
    }

    return CL_SUCCESS;
}

static unsigned int yara_total, yara_loaded, yara_malform, yara_empty, yara_complex;
#define YARATARGET0 "Target:0"
#define YARATARGET1 "Target:1"
#define EPSTR "EP+0:"

/* yara has no apparent cap on the number of strings; TODO - should we have one? */
/* function base off load_oneldb */
static int load_oneyara(YR_RULE *rule, int chkpua, struct cl_engine *engine, unsigned int options, unsigned int *sigs)
{
    YR_STRING *string;
    struct cli_ytable ytable;
    size_t i;
    int str_error = 0, ret = CL_SUCCESS;
    struct cli_lsig_tdb tdb;
    uint32_t lsigid[2];
    struct cli_matcher *root;
    struct cli_ac_lsig **newtable, *lsig, *tsig = NULL;
    unsigned short target = 0;
    char *logic = NULL, *target_str = NULL;
    char *newident = NULL;
    /* size_t lsize; */         // only used in commented out code
    /* char *exp_op = "|"; */   // only used in commented out code

    cli_yaramsg("load_oneyara: attempting to load %s\n", rule->identifier);

    if (!rule) {
        cli_errmsg("load_oneyara: empty rule passed as argument\n");
        return CL_ENULLARG;
    }

    /* PUA and IGN checks */
    if (chkpua && cli_chkpua(rule->identifier, engine->pua_cats, options))
        return CL_SUCCESS;

    if (engine->ignored && cli_chkign(engine->ignored, rule->identifier, rule->identifier)) {
        return CL_SUCCESS;
    }

    newident = cli_malloc(strlen(rule->identifier) + 5 + 1);
    if(!newident) {
        cli_errmsg("cli_loadyara(): newident == NULL\n");
        return CL_EMEM;
    }

    snprintf(newident, strlen(rule->identifier) + 5 + 1, "YARA.%s", rule->identifier);

    if(engine->cb_sigload && engine->cb_sigload("yara", newident, ~options & CL_DB_OFFICIAL, engine->cb_sigload_ctx)) {
        cli_dbgmsg("cli_loadyara: skipping %s due to callback\n", newident);
        free(newident);
        (*sigs)--;
        return CL_SUCCESS;
    }

    memset(&ytable, 0, sizeof(ytable));

    /*** rule specific checks ***/
#ifdef YARA_FINISHED
    if (RULE_IS_PRIVATE(rule)) {
        cli_warnmsg("load_oneyara: private modifier for yara rule is unsupported\n");
        cli_yaramsg("RULE_IS_PRIVATE                yes\n");
    }
    if (RULE_IS_GLOBAL(rule)) {
        cli_warnmsg("load_oneyara: global modifier for yara rule is unsupported\n");
        cli_yaramsg("RULE_IS_GLOBAL                 yes\n");
    }
    if ((rule->g_flags) & RULE_GFLAGS_REQUIRE_FILE) {
        cli_warnmsg("load_oneyara: RULE_GFLAGS_REQUIRE_FILE for yara rule is unsupported\n");
        cli_yaramsg("RULE_GFLAGS_REQUIRE_FILE       yes\n");
    }


    if (RULE_IS_NULL(rule) || ((rule->g_flags) & RULE_GFLAGS_REQUIRE_EXECUTABLE)) {

        cli_warnmsg("load_oneyara: skipping %s due to unsupported rule gflags\n", newident);

        cli_yaramsg("RULE_IS_NULL                   %s\n", RULE_IS_NULL(rule) ? "yes" : "no");
        cli_yaramsg("RULE_GFLAGS_REQUIRE_EXECUTABLE %s\n", ((rule->g_flags) & RULE_GFLAGS_REQUIRE_EXECUTABLE) ? "yes" : "no");

        free(newident);
        (*sigs)--;
        return CL_SUCCESS;
    }
#else
    /*
    cli_warnmsg("load_oneyara: yara support is incomplete, rule flags are ignored\n");

    if (RULE_IS_PRIVATE(rule))
        cli_yaramsg("RULE_IS_PRIVATE                yes\n");
    if (RULE_IS_GLOBAL(rule))
        cli_yaramsg("RULE_IS_GLOBAL                 yes\n");
    if (RULE_IS_NULL(rule))
        cli_yaramsg("RULE_IS_NULL                   yes\n");
    if ((rule->g_flags) & RULE_GFLAGS_REQUIRE_FILE)
        cli_yaramsg("RULE_GFLAGS_REQUIRE_FILE       yes\n");
    if ((rule->g_flags) & RULE_GFLAGS_REQUIRE_EXECUTABLE)
        cli_yaramsg("RULE_GFLAGS_REQUIRE_EXECUTABLE yes\n");
    */
#endif

    if(engine->cb_sigload && engine->cb_sigload("yara", newident, ~options & CL_DB_OFFICIAL, engine->cb_sigload_ctx)) {
        cli_dbgmsg("load_oneyara: skipping %s due to callback\n", newident);
        (*sigs)--;
        free(newident);
        return CL_SUCCESS;
    }

    /*** verification step - can clamav load it?       ***/
    /*** initial population pass for the strings table ***/
    STAILQ_FOREACH(string, &rule->strings, link) {
        char *substr = NULL;

        /* string type handler */
        if (STRING_IS_NULL(string)) {
            cli_warnmsg("load_oneyara: skipping NULL string %s\n", newident);
            //str_error++; /* kill the insertion? */
            continue;
#ifdef YARA_FINISHED
        } else if (STRING_IS_LITERAL(string)) {
            /* TODO - handle literal strings, short-circuits other string type handling */
            cli_yaramsg("load_oneyara: literal string: [%.*s] => [%s]\n", string->length, string->string, substr);
#else
        } else if (STRING_IS_LITERAL(string)) {
            cli_errmsg("load_oneyara: literal strings are unsupported, reorganize existing code\n");
#endif
        } else if (STRING_IS_HEX(string)) {
            substr = parse_yara_hex_string(string, &ret);
            if (ret != CL_SUCCESS) {
                cli_errmsg("load_oneyara: error in parsing yara hex string\n");
                str_error++;
                break;
            }

            /* handle lack of hexstr support here in order to suppress */
            /* initialize testing matcher */
            if (!engine->test_root) {
                engine->test_root = (struct cli_matcher *) mpool_calloc(engine->mempool, 1, sizeof(struct cli_matcher));
                if (!engine->test_root) {
                    cli_errmsg("load_oneyara[verify]: cannot allocate memory for test cli_matcher\n");
                    return CL_EMEM;
                }
#ifdef USE_MPOOL
                engine->test_root->mempool = engine->mempool;
#endif
                if((ret = cli_ac_init(engine->test_root, engine->ac_mindepth, engine->ac_maxdepth, engine->dconf->other&OTHER_CONF_PREFILTERING))) {
                    cli_errmsg("load_oneyara: cannot initialize test ac root\n");
                    return ret;
                }
            }

            /* generate a test lsig if one does not exist */
            if (!tsig) {
                /*** populating lsig ***/
                tsig = (struct cli_ac_lsig *) mpool_calloc(engine->mempool, 1, sizeof(struct cli_ac_lsig));
                if(!tsig) {
                    cli_errmsg("load_oneyara: cannot allocate memory for test lsig\n");
                    return CL_EMEM;
                }

                root = engine->test_root;

                tsig->type = CLI_YARA_NORMAL;
                lsigid[0] = tsig->id = root->ac_lsigs;

                root->ac_lsigs++;
                newtable = (struct cli_ac_lsig **) mpool_realloc(engine->mempool, root->ac_lsigtable, root->ac_lsigs * sizeof(struct cli_ac_lsig *));
                if(!newtable) {
                    root->ac_lsigs--;
                    cli_errmsg("load_oneyara: cannot allocate test root->ac_lsigtable\n");
                    mpool_free(engine->mempool, tsig);
                    return CL_EMEM;
                }

                newtable[root->ac_lsigs - 1] = tsig;
                root->ac_lsigtable = newtable;
            }

            /* attempt to insert hexsig */
            lsigid[1] = 0;
            ret = yara_hexstr_verify(string, substr, lsigid, engine, options);
            if (ret != CL_SUCCESS) {
                str_error++;
                free(substr);
                break;
            }

            cli_yaramsg("load_oneyara: hex string: [%.*s] => [%s]\n", string->length, string->string, substr);

            ytable_add_string(&ytable, substr);
            free(substr);
        } else if (STRING_IS_REGEXP(string)) {
            /* TODO - rewrite to NOT use PCRE_BYPASS */
#if HAVE_PCRE
            size_t length = strlen(PCRE_BYPASS) + string->length + 3;

            substr = cli_calloc(length, sizeof(char));
            if (!substr) {
                cli_errmsg("load_oneyara: cannot allocate memory for converted regex string\n");
                str_error++;
                ret = CL_EMEM;
                break;
            }

            snprintf(substr, length, "%s/%.*s/", PCRE_BYPASS, string->length, string->string);

            cli_yaramsg("load_oneyara: regex string: [%.*s] => [%s]\n", string->length, string->string, substr);

            ytable_add_string(&ytable, substr);
            free(substr);
#else
            cli_warnmsg("cli_loadyara: %s uses PCREs but support is disabled\n", newident);
            str_error++;
            ret = CL_SUCCESS;
            break;
#endif
        } else {
            /* TODO - extract the string length to handle NULL hex-escaped characters
             * For now, we'll just use the strlen we get which crudely finds the length
             */
            size_t length = string->length;
            size_t totsize = 2*length+1;

            if (length < CLI_DEFAULT_AC_MINDEPTH) {
                cli_warnmsg("load_oneyara: string is too short %s\n", newident);
                str_error++;
                continue;
            }

            substr = cli_calloc(totsize, sizeof(char));
            if (!substr) {
                cli_errmsg("load_oneyara: cannot allocate memory for converted generic string\n");
                str_error++;
                ret = CL_EMEM;
                break;
            }

            for (i=0; i < length; ++i) {
                size_t len = strlen(substr);
                snprintf(substr+len, totsize-len, "%02x", string->string[i]);
            }

            cli_yaramsg("load_oneyara: generic string: [%.*s] => [%s]\n", string->length, string->string, substr);

            ytable_add_string(&ytable, substr);
            free(substr);
        }


        /* modifier handler */
        if (STRING_IS_NO_CASE(string)) {
            cli_yaramsg("STRING_IS_NO_CASE         %s\n", STRING_IS_SINGLE_MATCH(string) ? "yes" : "no");
            if ((ret = ytable_add_attrib(&ytable, NULL, "i", 1)) != CL_SUCCESS) {
                cli_warnmsg("load_oneyara: failed to add 'nocase' sigopt\n");
                str_error++;
                break;
            }
        }
        if (STRING_IS_ASCII(string)) {
            cli_yaramsg("STRING_IS_ASCII           %s\n", STRING_IS_SINGLE_MATCH(string) ? "yes" : "no");
            if ((ret = ytable_add_attrib(&ytable, NULL, "a", 1)) != CL_SUCCESS) {
                cli_warnmsg("load_oneyara: failed to add 'ascii' sigopt\n");
                str_error++;
                break;
            }
        }
        if (STRING_IS_WIDE(string)) {
            cli_yaramsg("STRING_IS_WIDE            %s\n", STRING_IS_SINGLE_MATCH(string) ? "yes" : "no");
            /* handle lack of 'wide' support for regex here in order to suppress */
            if (STRING_IS_REGEXP(string)) {
                cli_warnmsg("load_oneyara[verify]: wide modifier [w] is not supported for regex subsigs\n");
                str_error++;
                break;
            }
            if ((ret = ytable_add_attrib(&ytable, NULL, "w", 1)) != CL_SUCCESS) {
                cli_warnmsg("load_oneyara: failed to add 'wide' sigopt\n");
                str_error++;
                break;
            }
        }
        if (STRING_IS_FULL_WORD(string)) {
            cli_yaramsg("STRING_IS_FULL_WORD       %s\n", STRING_IS_SINGLE_MATCH(string) ? "yes" : "no");
            if ((ret = ytable_add_attrib(&ytable, NULL, "f", 1)) != CL_SUCCESS) {
                cli_warnmsg("load_oneyara: failed to add 'fullword' sigopt\n");
                str_error++;
                break;
            }
        }

#ifdef YARA_FINISHED
        /* special modifier handler */
        if (STRING_IS_ANONYMOUS(string))
            cli_yaramsg("STRING_IS_ANONYMOUS       %s\n", STRING_IS_SINGLE_MATCH(string) ? "yes" : "no");

        /* unsupported(?) modifier handler */
        if (STRING_IS_SINGLE_MATCH(string))
            cli_yaramsg("STRING_IS_SINGLE_MATCH    %s\n", STRING_IS_SINGLE_MATCH(string) ? "yes" : "no");

        if (STRING_IS_REFERENCED(string) || STRING_IS_FAST_HEX_REGEXP(string) || STRING_IS_CHAIN_PART(string) ||
            STRING_IS_CHAIN_TAIL(string) || STRING_FITS_IN_ATOM(string)) {

            cli_warnmsg("load_oneyara: skipping unsupported string %s\n", newident);

            cli_yaramsg("STRING_IS_REFERENCED      %s\n", STRING_IS_REFERENCED(string) ? "yes" : "no");
            cli_yaramsg("STRING_IS_FAST_HEX_REGEXP %s\n", STRING_IS_FAST_HEX_REGEXP(string) ? "yes" : "no");
            cli_yaramsg("STRING_IS_CHAIN_PART      %s\n", STRING_IS_CHAIN_PART(string) ? "yes" : "no");
            cli_yaramsg("STRING_IS_CHAIN_TAIL      %s\n", STRING_IS_CHAIN_TAIL(string) ? "yes" : "no");
            cli_yaramsg("STRING_FITS_IN_ATOM       %s\n", STRING_FITS_IN_ATOM(string) ? "yes" : "no");

            str_error++;
            continue;
        }
#else
        /*
        cli_warnmsg("load_oneyara: yara support is incomplete, rule flags are ignored\n");
        if (STRING_IS_ANONYMOUS(string))
            cli_yaramsg("STRING_IS_ANONYMOUS       yes\n");
        if (STRING_IS_SINGLE_MATCH(string))
            cli_yaramsg("STRING_IS_SINGLE_MATCH    yes\n");
        if (STRING_IS_REFERENCED(string))
            cli_yaramsg("STRING_IS_REFERENCED      yes\n");
        if (STRING_IS_FAST_HEX_REGEXP(string))
            cli_yaramsg("STRING_IS_FAST_HEX_REGEXP yes\n");
        if (STRING_IS_CHAIN_PART(string))
            cli_yaramsg("STRING_IS_CHAIN_PART      yes\n");
        if (STRING_IS_CHAIN_TAIL(string))
            cli_yaramsg("STRING_IS_CHAIN_TAIL      yes\n");
        if (STRING_FITS_IN_ATOM(string))
            cli_yaramsg("STRING_FITS_IN_ATOM       yes\n");
        */
#endif
        string->subsig_id = ytable.tbl_cnt-1;
    }

    if (str_error > 0) {
        cli_warnmsg("load_oneyara: clamav cannot support %d input strings, skipping %s\n", str_error, newident);
        yara_malform++;
        ytable_delete(&ytable);
        free(newident);
        (*sigs)--;
        return ret;
    } else if (ytable.tbl_cnt == 0) {
        cli_warnmsg("load_oneyara: yara rule contains no supported strings, skipping %s\n", newident);
        yara_malform++;
        ytable_delete(&ytable);
        free(newident);
        (*sigs)--;
        return CL_SUCCESS; /* TODO - kill signature instead? */
    } else if (ytable.tbl_cnt > MAX_LDB_SUBSIGS) {
        cli_warnmsg("load_oneyara: yara rule contains too many subsigs (%d, max: %d), skipping %s\n", ytable.tbl_cnt, MAX_LDB_SUBSIGS, newident);
        yara_malform++;
        ytable_delete(&ytable);
        free(newident);
        (*sigs)--;
        return CL_SUCCESS;
    }

    /*** conditional verification step (ex. do we define too many strings versus used?)  ***/
    /*** additional string table population (ex. offsets), second translation table pass ***/
#if 0
    if (rule->cl_flags & RULE_ALL ||  rule->cl_flags & RULE_ANY) {
        lsize = 3*ytable.tbl_cnt;
        logic = cli_calloc(lsize, sizeof(char));
        if (!logic) {
            cli_errmsg("load_oneyara: cannot allocate memory for logic statement\n");
            ytable_delete(&ytable);
            return CL_EMEM;
        }
        
        if (rule->cl_flags & RULE_ALL && rule->cl_flags & RULE_THEM)
            exp_op = "&";
        else {
            exp_op = "|";
            if ((!(rule->cl_flags & RULE_ANY && rule->cl_flags & RULE_THEM) && ytable.tbl_cnt > 1) &&
                !(rule->cl_flags & RULE_EP && ytable.tbl_cnt == 1))
                yara_complex++;
        }
        
        for (i=0; i<ytable.tbl_cnt; i++) {
            size_t len=strlen(logic);
            snprintf(logic+len, lsize-len, "%u%s", i, (i+1 == ytable.tbl_cnt) ? "" : exp_op);
        }    
        
        /*** END CONDITIONAL HANDLING ***/
    }

    /* TDB */
    if (rule->cl_flags & RULE_EP && ytable.tbl_cnt == 1)
        target_str = cli_strdup(YARATARGET1);
    else
#endif
        target_str = cli_strdup(YARATARGET0);

    memset(&tdb, 0, sizeof(tdb));
    if ((ret = init_tdb(&tdb, engine, target_str, newident)) != CL_SUCCESS) {
        ytable_delete(&ytable);
        free(logic);
        free(target_str);
        free(newident);
        (*sigs)--;
        if (ret == CL_BREAK)
            return CL_SUCCESS;
        return ret;
    }
    free(target_str);

    /*** populating lsig ***/
    root = engine->root[tdb.target[0]];

    lsig = (struct cli_ac_lsig *) mpool_calloc(engine->mempool, 1, sizeof(struct cli_ac_lsig));
    if(!lsig) {
        cli_errmsg("load_oneyara: Can't allocate memory for lsig\n");
        FREE_TDB(tdb);
        ytable_delete(&ytable);
        free(logic);
        free(newident);
        return CL_EMEM;
    }

    if (logic) {
        cli_yaramsg("normal lsig triggered yara: %s\n", logic);

        lsig->type = CLI_LSIG_NORMAL;
        lsig->u.logic = cli_mpool_strdup(engine->mempool, logic);
        free(logic);
        if(!lsig->u.logic) {
            cli_errmsg("load_oneyara: Can't allocate memory for lsig->logic\n");
            FREE_TDB(tdb);
            ytable_delete(&ytable);
            mpool_free(engine->mempool, lsig);
            free(newident);
            return CL_EMEM;
        }
    } else {
        if (NULL != (lsig->u.code_start = rule->code_start)) {
            lsig->type = (rule->cl_flags & RULE_OFFSETS) ? CLI_YARA_OFFSET : CLI_YARA_NORMAL;
            if (RULE_IS_PRIVATE(rule))
                lsig->flag |= CLI_LSIG_FLAG_PRIVATE;
        } else {
            cli_errmsg("load_oneyara: code start is NULL\n");
            FREE_TDB(tdb);
            ytable_delete(&ytable);
            mpool_free(engine->mempool, lsig);
            free(newident);
            return CL_EMEM;
        }
    }


    lsigid[0] = lsig->id = root->ac_lsigs;

    root->ac_lsigs++;
    newtable = (struct cli_ac_lsig **) mpool_realloc(engine->mempool, root->ac_lsigtable, root->ac_lsigs * sizeof(struct cli_ac_lsig *));
    if(!newtable) {
        root->ac_lsigs--;
        cli_errmsg("cli_loadldb: Can't realloc root->ac_lsigtable\n");
        FREE_TDB(tdb);
        ytable_delete(&ytable);
        mpool_free(engine->mempool, lsig);
        free(newident);
        return CL_EMEM;
    }

    newtable[root->ac_lsigs - 1] = lsig;
    root->ac_lsigtable = newtable;
    tdb.subsigs = ytable.tbl_cnt;

    /*** loading step - put things into the AC trie ***/
    for (i = 0; i < (size_t)ytable.tbl_cnt; ++i) {
        lsigid[1] = i;

        cli_yaramsg("%zu: [%s] [%s] [%s%s%s%s]\n", i, ytable.table[i]->hexstr, ytable.table[i]->offset,
                    (ytable.table[i]->sigopts & ACPATT_OPTION_NOCASE) ? "i" : "",
                    (ytable.table[i]->sigopts & ACPATT_OPTION_FULLWORD) ? "f" : "",
                    (ytable.table[i]->sigopts & ACPATT_OPTION_WIDE) ? "w" : "",
                    (ytable.table[i]->sigopts & ACPATT_OPTION_ASCII) ? "a" : "");

        if((ret = cli_sigopts_handler(root, newident, ytable.table[i]->hexstr, ytable.table[i]->sigopts, 0, 0, ytable.table[i]->offset, target, lsigid, options)) != CL_SUCCESS) {
            root->ac_lsigs--;
            FREE_TDB(tdb);
            ytable_delete(&ytable);
            mpool_free(engine->mempool, lsig);

            yara_malform++;
            free(newident);
            return ret;
        }
    }

    memcpy(&lsig->tdb, &tdb, sizeof(tdb));
    ytable_delete(&ytable);

    rule->lsigid = root->ac_lsigs - 1;
    yara_loaded++;
    cli_yaramsg("load_oneyara: successfully loaded %s\n", newident);
    free(newident);
    return CL_SUCCESS;
}

struct _yara_global {
    YR_ARENA      * the_arena;
    YR_HASH_TABLE * rules_table;
    YR_HASH_TABLE * objects_table;
    YR_HASH_TABLE * db_table;
};

int cli_yara_init(struct cl_engine * engine)
{
    /* Initialize YARA */
    engine->yara_global = cli_calloc(1, sizeof(struct _yara_global));
    if (NULL == engine->yara_global) {
        cli_errmsg("cli_yara_init: failed to create YARA global\n");
        return CL_EMEM;
    }
    if (ERROR_SUCCESS != yr_arena_create(1024, 0, &engine->yara_global->the_arena)) {
        cli_errmsg("cli_yara_init: failed to create the YARA arena\n");
        free(engine->yara_global);
        engine->yara_global = NULL;
        return CL_EMEM;
    }
    if (ERROR_SUCCESS != yr_hash_table_create(10007, &engine->yara_global->rules_table)) {
        cli_errmsg("cli_yara_init: failed to create the YARA rules table\n");
        yr_arena_destroy(engine->yara_global->the_arena);
        engine->yara_global->the_arena = NULL;
        free(engine->yara_global);
        engine->yara_global = NULL;
        return CL_EMEM;
    }
    if (ERROR_SUCCESS != yr_hash_table_create(10007, &engine->yara_global->objects_table)) {
        cli_errmsg("cli_yara_init: failed to create the YARA objects table\n");
        yr_hash_table_destroy(engine->yara_global->rules_table, NULL);
        yr_arena_destroy(engine->yara_global->the_arena);
        engine->yara_global->rules_table = NULL;
        engine->yara_global->the_arena = NULL; 
        free(engine->yara_global);
        engine->yara_global = NULL;
        engine->yara_global = NULL;
        return CL_EMEM;
    }
    if (ERROR_SUCCESS != yr_hash_table_create(10007, &engine->yara_global->db_table)) {
        cli_errmsg("cli_yara_init: failed to create the YARA objects table\n");
        yr_hash_table_destroy(engine->yara_global->objects_table, NULL);
        yr_hash_table_destroy(engine->yara_global->rules_table, NULL);
        yr_arena_destroy(engine->yara_global->the_arena);
        engine->yara_global->objects_table = NULL;
        engine->yara_global->rules_table = NULL;
        engine->yara_global->the_arena = NULL; 
        free(engine->yara_global);
        engine->yara_global = NULL;
        return CL_EMEM;
    }
    return CL_SUCCESS;
}

void cli_yara_free(struct cl_engine * engine)
{
    if (engine->yara_global != NULL) {
        if (engine->yara_global->db_table != NULL) {
            yr_hash_table_destroy(engine->yara_global->db_table, NULL);
            engine->yara_global->db_table = NULL;
        }
        if (engine->yara_global->rules_table != NULL) {
            yr_hash_table_destroy(engine->yara_global->rules_table, NULL);
            engine->yara_global->rules_table = NULL;
        }
        if (engine->yara_global->objects_table != NULL) {
            yr_hash_table_destroy(engine->yara_global->objects_table, NULL);
            engine->yara_global->objects_table = NULL;
        }    
        if (engine->yara_global->the_arena != NULL) {
            yr_arena_destroy(engine->yara_global->the_arena);
            engine->yara_global->the_arena = NULL;
        }
        free(engine->yara_global);
        engine->yara_global = NULL;
    }        
}

//TODO - pua? dbio?
static int cli_loadyara(FILE *fs, struct cl_engine *engine, unsigned int *signo, unsigned int options, struct cli_dbio *dbio, const char *filename)
{
    YR_COMPILER compiler;
    YR_NAMESPACE ns;
    YR_RULE *rule;
    unsigned int sigs = 0, rules = 0, rule_errors = 0;
    int rc;

    UNUSEDPARAM(dbio);

    if((rc = cli_initroots(engine, options)))
        return rc;

    memset(&compiler, 0, sizeof(YR_COMPILER));

    compiler.last_result = ERROR_SUCCESS;
    STAILQ_INIT(&compiler.rule_q);
    STAILQ_INIT(&compiler.current_rule_string_q);

    rc = yr_arena_create(65536, 0, &compiler.sz_arena);
    if (rc == ERROR_SUCCESS)
        rc = yr_arena_create(65536, 0, &compiler.rules_arena);
    if (rc == ERROR_SUCCESS)
        rc = yr_arena_create(65536, 0, &compiler.code_arena);
    if (rc == ERROR_SUCCESS)
        rc = yr_arena_create(65536, 0, &compiler.strings_arena);
    if (rc == ERROR_SUCCESS)
        rc = yr_arena_create(65536, 0, &compiler.metas_arena);
    if (rc != ERROR_SUCCESS)
        return CL_EMEM;
    compiler.loop_for_of_mem_offset = -1;
    ns.name = "default";
    compiler.current_namespace = &ns;
    compiler.the_arena = engine->yara_global->the_arena;
    compiler.rules_table = engine->yara_global->rules_table;
    compiler.objects_table = engine->yara_global->objects_table;
    compiler.allow_includes = 1;
    _yr_compiler_push_file_name(&compiler, filename);

    rc = yr_lex_parse_rules_file(fs, &compiler);
    if (rc > 0) { /* rc = number of errors */
        /* TODO - handle the various errors? */
#ifdef YARA_FINISHED
        cli_errmsg("cli_loadyara: failed to parse rules file %s, error count %i\n", filename, rc);
        if (compiler.sz_arena != NULL)
            yr_arena_destroy(compiler.sz_arena);
        if (compiler.rules_arena != NULL)
            yr_arena_destroy(compiler.rules_arena);
        if (compiler.code_arena != NULL)
            yr_arena_destroy(compiler.code_arena);
        if (compiler.strings_arena != NULL)
            yr_arena_destroy(compiler.strings_arena);
        if (compiler.metas_arena != NULL)
            yr_arena_destroy(compiler.metas_arena);
        _yr_compiler_pop_file_name(&compiler);
        return CL_EMALFDB;
#else
        if (compiler.last_result == ERROR_INSUFICIENT_MEMORY)
            return CL_EMEM;
        rule_errors = rc;
        rc = CL_SUCCESS;
#endif
    }

    while (!STAILQ_EMPTY(&compiler.rule_q)) {
        rule = STAILQ_FIRST(&compiler.rule_q);
        STAILQ_REMOVE(&compiler.rule_q, rule, _yc_rule, link);

        rules++;
        sigs++; /* can be decremented by load_oneyara */

        rc = load_oneyara(rule,
                          engine->pua_cats && (options & CL_DB_PUA_MODE) && (options & (CL_DB_PUA_INCLUDE | CL_DB_PUA_EXCLUDE)),
                          engine, options, &sigs);
        if (rc != CL_SUCCESS) {
            cli_warnmsg("cli_loadyara: problem parsing yara file %s, yara rule %s\n", filename, rule->identifier);
            continue;
        }
    }

    if (0 != rule_errors)
        cli_warnmsg("cli_loadyara: failed to parse or load %u yara rules from file %s, successfully loaded %u rules.\n", rule_errors+rules-sigs, filename, sigs);

    yr_arena_append(engine->yara_global->the_arena, compiler.sz_arena);
    yr_arena_append(engine->yara_global->the_arena, compiler.rules_arena);
    yr_arena_append(engine->yara_global->the_arena, compiler.strings_arena);
    yr_arena_destroy(compiler.code_arena);
    yr_arena_destroy(compiler.metas_arena);
    _yr_compiler_pop_file_name(&compiler);

    if(rc)
        return rc;

#ifdef YARA_FINISHED
    if(!rules) {
        cli_errmsg("cli_loadyara: empty database file\n");
        return CL_EMALFDB;
    }
#else
    if(!rules) {
        cli_warnmsg("cli_loadyara: empty database file\n");
        yara_empty++;
    }
#endif

    /* globals */
    yara_total += rules;

    if(signo)
        *signo += sigs;

    cli_yaramsg("cli_loadyara: loaded %u of %u yara signatures from %s\n", sigs, rules, filename);

    return CL_SUCCESS;
}
#endif

/*      0            1           2          3
 * PasswordName;Attributes;PWStorageType;Password
 */
#define PWDB_TOKENS 4
static int cli_loadpwdb(FILE *fs, struct cl_engine *engine, unsigned int options, unsigned int internal, struct cli_dbio *dbio)
{
    const char *tokens[PWDB_TOKENS + 1], *passname;
    char *attribs;
    char buffer[FILEBUFF];
    unsigned int line = 0, skip = 0, pwcnt = 0, tokens_count;
    struct cli_pwdb *new;
    cl_pwdb_t container;
    struct cli_lsig_tdb tdb;
    int ret = CL_SUCCESS, pwstype;

    while(1) {
        if(internal){
            options |= CL_DB_OFFICIAL;
            /* TODO - read default passwords */
            return CL_SUCCESS;
        } else {
            if(!cli_dbgets(buffer, FILEBUFF, fs, dbio))
                break;
            if(buffer[0] == '#')
                continue;
            cli_chomp(buffer);
        }
        line++;
        tokens_count = cli_strtokenize(buffer, ';', PWDB_TOKENS, tokens);

        if(tokens_count != PWDB_TOKENS) {
            ret = CL_EMALFDB;
            break;
        }

        passname = tokens[0];

        /* check if password is ignored, note that name is not stored */
        if (engine->ignored && cli_chkign(engine->ignored, passname, passname)) {
            skip++;
            continue;
        }

        if(engine->cb_sigload && engine->cb_sigload("pwdb", passname, ~options & CL_DB_OFFICIAL, engine->cb_sigload_ctx)) {
            cli_dbgmsg("cli_loadpwdb: skipping %s due to callback\n", passname);
            skip++;
            continue;
        }

        /* append target type 0 to tdb string if needed */
        if ((tokens[1][0] == '\0') || (strstr(tokens[1], "Target:") != NULL)) {
            attribs = cli_strdup(tokens[1]);
            if(!attribs) {
                cli_errmsg("cli_loadpwdb: Can't allocate memory for attributes\n");
                ret = CL_EMEM;
                break;
            }
        } else {
            size_t attlen = strlen(tokens[1]) + 10;
            attribs = cli_calloc(attlen, sizeof(char));
            if(!attribs) {
                cli_errmsg("cli_loadpwdb: Can't allocate memory for attributes\n");
                ret = CL_EMEM;
                break;
            }
            snprintf(attribs, attlen, "%s,Target:0", tokens[1]);
        }

        /* use the tdb to track filetypes and check flevels */
        memset(&tdb, 0, sizeof(tdb));
        ret = init_tdb(&tdb, engine, attribs, passname);
        free(attribs);
        if(ret != CL_SUCCESS) {
            skip++;
            if (ret == CL_BREAK)
                continue;
            else
                break;
        }

        /* check container type */
        if (!tdb.container) {
            container = CLI_PWDB_ANY;
        } else {
            switch (*(tdb.container)) {
            case CL_TYPE_ANY:
                container = CLI_PWDB_ANY;
                break;
            case CL_TYPE_ZIP:
                container = CLI_PWDB_ZIP;
                break;
            case CL_TYPE_RAR:
                container = CLI_PWDB_RAR;
                break;
            default:
                cli_errmsg("cli_loadpwdb: Invalid container specified to .pwdb signature\n");
                return CL_EMALFDB;
            }
        }
        FREE_TDB(tdb);

        /* check the PWStorageType */
        if(!cli_isnumber(tokens[2])) {
            cli_errmsg("cli_loadpwdb: Invalid value for PWStorageType (third entry)\n");
            ret = CL_EMALFDB;
            break;
        }

        pwstype = atoi(tokens[2]);
        if((pwstype == 0) || (pwstype == 1)) {
            new = (struct cli_pwdb *) mpool_calloc(engine->mempool, 1, sizeof(struct cli_pwdb));
            if(!new) {
                ret = CL_EMEM;
                break;
            }

            /* copy passwd name */
            new->name = cli_mpool_strdup(engine->mempool, tokens[0]);
            if (!new->name) {
                ret = CL_EMEM;
                mpool_free(engine->mempool, new);
                break;
            }

            if(pwstype == 0) { /* cleartext */
                new->passwd = cli_mpool_strdup(engine->mempool, tokens[3]);
                new->length = (uint16_t)strlen(tokens[3]);
            } else { /* 1 => hex-encoded */
                new->passwd = cli_mpool_hex2str(engine->mempool, tokens[3]);
                new->length = (uint16_t)strlen(tokens[3]) / 2;
            }
            if(!new->passwd) {
                cli_errmsg("cli_loadpwdb: Can't decode or add new password entry\n");
                if(pwstype == 0)
                    ret = CL_EMEM;
                else
                    ret = CL_EMALFDB;
                mpool_free(engine->mempool, new->name);
                mpool_free(engine->mempool, new);
                break;
            }

            /* add to the engine list, sorted by target type */
	    new->next = engine->pwdbs[container];
	    engine->pwdbs[container] = new;
        } else {
            cli_dbgmsg("cli_loadpwdb: Unsupported PWStorageType %u\n", pwstype);
            continue;
        }

        pwcnt++;
    }

    /* error reporting */
    if(ret) {
        cli_errmsg("Problem processing %s password database at line %u\n", internal ? "built-in" : "external", line);
        return ret;
    }

    if(!pwcnt) {
        cli_errmsg("Empty %s password database\n", internal ? "built-in" : "external");
        return CL_EMALFDB;
    }

    cli_dbgmsg("Loaded %u (%u skipped) password entries\n", pwcnt, skip);
    return CL_SUCCESS;
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

#ifdef HAVE_YARA
    if(options & CL_DB_YARA_ONLY) {
        if(cli_strbcasestr(dbname, ".yar") || cli_strbcasestr(dbname, ".yara"))
	    ret = cli_loadyara(fs, engine, signo, options, dbio, filename);
	else
	    skipped = 1;
    } else
#endif
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
    } else if(cli_strbcasestr(dbname, ".imp")) {
	ret = cli_loadhash(fs, engine, signo, MD5_IMP, options, dbio, dbname);

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
#ifdef HAVE_YARA
    } else if(cli_strbcasestr(dbname, ".yar") || cli_strbcasestr(dbname, ".yara")) {
	if(!(options & CL_DB_YARA_EXCLUDE))
	    ret = cli_loadyara(fs, engine, signo, options, dbio, filename);
	else
	    skipped = 1;
#endif
    } else if(cli_strbcasestr(dbname, ".pwdb")) {
        ret = cli_loadpwdb(fs, engine, options, 0, dbio);
    } else {
	cli_warnmsg("cli_load: unknown extension - skipping %s\n", filename);
	skipped = 1;
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

#ifdef YARA_PROTO
    if (yara_total) {
        cli_yaramsg("$$$$$$$$$$$$ YARA $$$$$$$$$$$$\n");
        cli_yaramsg("\tTotal Rules: %u\n", yara_total);
        cli_yaramsg("\tRules Loaded: %u\n", yara_loaded);
        cli_yaramsg("\tComplex Conditions: %u\n", yara_complex);
        cli_yaramsg("\tMalformed/Unsupported Rules: %u\n", yara_malform);
        cli_yaramsg("\tEmpty Rules: %u\n", yara_empty);
        cli_yaramsg("$$$$$$$$$$$$ YARA $$$$$$$$$$$$\n");
    }
#endif
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

void cli_pwdb_list_free(struct cl_engine *engine, struct cli_pwdb *pwdb)
{
    struct cli_pwdb *thiz, *that;

    thiz = pwdb;
    while (thiz) {
	that = thiz->next;

	mpool_free(engine->mempool, thiz->name);
	mpool_free(engine->mempool, thiz->passwd);
	mpool_free(engine->mempool, thiz);

	thiz = that;
    }
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
			if (root->ac_lsigtable[j]->type == CLI_LSIG_NORMAL)
			    mpool_free(engine->mempool, root->ac_lsigtable[j]->u.logic);
			FREE_TDB(root->ac_lsigtable[j]->tdb);
			mpool_free(engine->mempool, root->ac_lsigtable[j]);
		    }
		    mpool_free(engine->mempool, root->ac_lsigtable);
		}
#if HAVE_PCRE
                cli_pcre_freetable(root);
#endif /* HAVE_PCRE */
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

    if(engine->pwdbs) {
        for(i = 0; i < CLI_PWDB_COUNT; i++)
            if(engine->pwdbs[i])
                cli_pwdb_list_free(engine, engine->pwdbs[i]);
	mpool_free(engine->mempool, engine->pwdbs);
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
    if(engine->test_root) {
	root = engine->test_root;
	if(!root->ac_only)
	    cli_bm_free(root);
	cli_ac_free(root);
	if(root->ac_lsigtable) {
	    for(i = 0; i < root->ac_lsigs; i++) {
		if (root->ac_lsigtable[i]->type == CLI_LSIG_NORMAL)
		    mpool_free(engine->mempool, root->ac_lsigtable[i]->u.logic);
		FREE_TDB(root->ac_lsigtable[i]->tdb);
		mpool_free(engine->mempool, root->ac_lsigtable[i]);
	    }
	    mpool_free(engine->mempool, root->ac_lsigtable);
	}
#if HAVE_PCRE
	cli_pcre_freetable(root);
#endif /* HAVE_PCRE */
	mpool_free(engine->mempool, root);
    }

#ifdef USE_MPOOL
    if(engine->mempool) mpool_destroy(engine->mempool);
#endif

#ifdef HAVE_YARA
    cli_yara_free(engine);
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
#ifdef HAVE_YARA
    /* Free YARA hash tables - only needed for parse and load */
    if (engine->yara_global != NULL) {
        if (engine->yara_global->rules_table)
            yr_hash_table_destroy(engine->yara_global->rules_table, NULL);
        if (engine->yara_global->objects_table)
            yr_hash_table_destroy(engine->yara_global->objects_table, NULL);
        engine->yara_global->rules_table = engine->yara_global->objects_table = NULL;
    }
#endif

    if(!engine->ftypes)
	if((ret = cli_loadftm(NULL, engine, 0, 1, NULL)))
	    return ret;

    /* handle default passwords */
    if(!engine->pwdbs[0] && !engine->pwdbs[1] && !engine->pwdbs[2])
	if((ret = cli_loadpwdb(NULL, engine, 0, 1, NULL)))
	    return ret;

    for(i = 0; i < CLI_MTARGETS; i++) {
	if((root = engine->root[i])) {
	    if((ret = cli_ac_buildtrie(root)))
		return ret;
#if HAVE_PCRE
            if((ret = cli_pcre_build(root, engine->pcre_match_limit, engine->pcre_recmatch_limit, engine->dconf)))
                return ret;

	    cli_dbgmsg("Matcher[%u]: %s: AC sigs: %u (reloff: %u, absoff: %u) BM sigs: %u (reloff: %u, absoff: %u) PCREs: %u (reloff: %u, absoff: %u) maxpatlen %u %s\n", i, cli_mtargets[i].name, root->ac_patterns, root->ac_reloff_num, root->ac_absoff_num, root->bm_patterns, root->bm_reloff_num, root->bm_absoff_num, root->pcre_metas, root->pcre_reloff_num, root->pcre_absoff_num, root->maxpatlen, root->ac_only ? "(ac_only mode)" : "");
#else
	    cli_dbgmsg("Matcher[%u]: %s: AC sigs: %u (reloff: %u, absoff: %u) BM sigs: %u (reloff: %u, absoff: %u) maxpatlen %u PCREs: 0 (disabled) %s\n", i, cli_mtargets[i].name, root->ac_patterns, root->ac_reloff_num, root->ac_absoff_num, root->bm_patterns, root->bm_reloff_num, root->bm_absoff_num, root->maxpatlen, root->ac_only ? "(ac_only mode)" : "");
#endif
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
    if(engine->test_root) {
	root = engine->test_root;
	if(!root->ac_only)
	    cli_bm_free(root);
	cli_ac_free(root);
	if(root->ac_lsigtable) {
	    for(i = 0; i < root->ac_lsigs; i++) {
		if (root->ac_lsigtable[i]->type == CLI_LSIG_NORMAL)
		    mpool_free(engine->mempool, root->ac_lsigtable[i]->u.logic);
		FREE_TDB(root->ac_lsigtable[i]->tdb);
		mpool_free(engine->mempool, root->ac_lsigtable[i]);
	    }
	    mpool_free(engine->mempool, root->ac_lsigtable);
	}
#if HAVE_PCRE
	cli_pcre_freetable(root);
#endif /* HAVE_PCRE */
	mpool_free(engine->mempool, root);
	engine->test_root = NULL;
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

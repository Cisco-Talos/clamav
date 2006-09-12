/*
 *  Copyright (C) 2002 - 2006 Tomasz Kojm <tkojm@clamav.net>
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
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <fcntl.h>

#include "clamav.h"
#include "cvd.h"
#include "strings.h"
#include "matcher-ac.h"
#include "matcher-bm.h"
#include "others.h"
#include "str.h"
#include "defaults.h"

#ifdef CL_EXPERIMENTAL
/*
#include "phish_whitelist.h"
#include "phish_domaincheck_db.h"
*/
#endif


#if defined(HAVE_READDIR_R_3) || defined(HAVE_READDIR_R_2)
#include <limits.h>
#include <stddef.h>
#endif

/* Maximum filenames under various systems - njh */
#ifndef	NAME_MAX	/* e.g. Linux */
# ifdef	MAXNAMELEN	/* e.g. Solaris */
#   define	NAME_MAX	MAXNAMELEN
# else
#   ifdef	FILENAME_MAX	/* e.g. SCO */
#     define	NAME_MAX	FILENAME_MAX
#   else
#     define	NAME_MAX	256
#   endif
# endif
#endif

#ifdef CL_THREAD_SAFE
#  include <pthread.h>
static pthread_mutex_t cli_ref_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

#ifdef HAVE_HWACCEL
#include <sn_sigscan/sn_sigscan.h>
#endif


/* TODO: clean up the code */

static int cli_ac_addsig(struct cli_matcher *root, const char *virname, const char *hexsig, int sigid, int parts, int partno, unsigned short type, unsigned int mindist, unsigned int maxdist, char *offset, unsigned short target)
{
	struct cli_ac_patt *new;
	char *pt, *hex;
	int virlen, ret, error = 0;
	unsigned int i, j, wprefix = 0;

#define FREE_ALT			\
    if(new->alt) {			\
	free(new->altn);		\
	for(i = 0; i < new->alt; i++)	\
	    free(new->altc[i]);		\
	free(new->altc);		\
	free(hex);			\
    }

    if((new = (struct cli_ac_patt *) cli_calloc(1, sizeof(struct cli_ac_patt))) == NULL)
	return CL_EMEM;

    new->type = type;
    new->sigid = sigid;
    new->parts = parts;
    new->partno = partno;
    new->mindist = mindist;
    new->maxdist = maxdist;
    new->target = target;
    new->offset = offset;

    if(strchr(hexsig, '(')) {
	    char *hexcpy, *hexnew, *start, *h, *c;

	if(!(hexcpy = strdup(hexsig))) {
	    free(new);
	    return CL_EMEM;
	}

	if(!(hexnew = (char *) cli_calloc(strlen(hexsig) + 1, 1))) {
	    free(hexcpy);
	    free(new);
	    return CL_EMEM;
	}

	start = pt = hexcpy;
	while((pt = strchr(start, '('))) {
	    *pt++ = 0;

	    if(!start) {
		error = 1;
		break;
	    }

	    strcat(hexnew, start);
	    strcat(hexnew, "@@");

	    if(!(start = strchr(pt, ')'))) {
		error = 1;
		break;
	    }
	    *start++ = 0;

	    new->alt++;
	    new->altn = (unsigned short int *) cli_realloc(new->altn, new->alt * sizeof(unsigned short int));
	    new->altn[new->alt - 1] = 0;
	    new->altc = (char **) cli_realloc(new->altc, new->alt * sizeof(char *));
	    new->altc[new->alt - 1] = NULL;

	    for(i = 0; i < strlen(pt); i++)
		if(pt[i] == '|')
		    new->altn[new->alt - 1]++;

	    if(!new->altn[new->alt - 1]) {
		error = 1;
		break;
	    } else
		new->altn[new->alt - 1]++;

	    if(!(new->altc[new->alt - 1] = (char *) cli_calloc(new->altn[new->alt - 1], 1))) {
		error = 1;
		break;
	    }

	    for(i = 0; i < new->altn[new->alt - 1]; i++) {
		if((h = cli_strtok(pt, i, "|")) == NULL) {
		    error = 1;
		    break;
		}

		if((c = cli_hex2str(h)) == NULL) {
		    free(h);
		    error = 1;
		    break;
		}

		new->altc[new->alt - 1][i] = *c;
		free(c);
		free(h);
	    }

	    if(error)
		break;
	}

	if(start)
	    strcat(hexnew, start);

	hex = hexnew;
	free(hexcpy);

	if(error) {
	    FREE_ALT;
	    free(new);
	    return CL_EMALFDB;
	}

    } else
	hex = (char *) hexsig;

    if((new->pattern = cli_hex2si(hex)) == NULL) {
	FREE_ALT;
	free(new);
	return CL_EMALFDB;
    }

    new->length = strlen(hex) / 2;

    for(i = 0; i < AC_DEFAULT_DEPTH; i++) {
	if(new->pattern[i] == CLI_IGN || new->pattern[i] == CLI_ALT) {
	    wprefix = 1;
	    break;
	}
    }

    if(wprefix) {
	for(; i < new->length - AC_DEFAULT_DEPTH + 1; i++) {
	    wprefix = 0;
	    for(j = i; j < i + AC_DEFAULT_DEPTH; j++) {
		if(new->pattern[j] == CLI_IGN || new->pattern[j] == CLI_ALT) {
		    wprefix = 1;
		    break;
		}
	    }
	    if(!wprefix)
		break;
	}

	if(wprefix) {
	    FREE_ALT;
	    free(new->pattern);
	    free(new);
	    return CL_EMALFDB;
	}

	new->prefix = new->pattern;
	new->prefix_length = i;
	new->pattern = &new->prefix[i];
	new->length -= i;

	for(i = 0; i < new->prefix_length; i++)
	    if(new->prefix[i] == CLI_ALT)
		new->alt_pattern++;
    }

    if(new->length > root->maxpatlen)
	root->maxpatlen = new->length;

    if((pt = strstr(virname, "(Clam)")))
	virlen = strlen(virname) - strlen(pt) - 1;
    else
	virlen = strlen(virname);

    if(virlen <= 0) {
	if(new->prefix)
	    free(new->prefix);
	else
	    free(new->pattern);
	FREE_ALT;
	free(new);
	return CL_EMALFDB;
    }

    if((new->virname = cli_calloc(virlen + 1, sizeof(char))) == NULL) {
	if(new->prefix)
	    free(new->prefix);
	else
	    free(new->pattern);
	FREE_ALT;
	free(new);
	return CL_EMEM;
    }

    strncpy(new->virname, virname, virlen);

    if((ret = cli_ac_addpatt(root, new))) {
	if(new->prefix)
	    free(new->prefix);
	else
	    free(new->pattern);
	free(new->virname);
	FREE_ALT;
	free(new);
	return ret;
    }

    if(new->alt)
	free(hex);

    return CL_SUCCESS;
}

int cli_parse_add(struct cli_matcher *root, const char *virname, const char *hexsig, unsigned short type, char *offset, unsigned short target)
{
	struct cli_bm_patt *bm_new;
	char *pt, *hexcpy, *start, *n;
	int ret, virlen, asterisk = 0;
	unsigned int i, j, len, parts = 0;
	int mindist = 0, maxdist = 0, error = 0;


    if(strchr(hexsig, '{')) {

	root->ac_partsigs++;

	if(!(hexcpy = strdup(hexsig)))
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

	if(!(bm_new->pattern = cli_hex2str(hexsig))) {
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

	bm_new->offset = offset;
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

static int cli_initengine(struct cl_engine **engine, unsigned int options)
{

    if(!*engine) {
	cli_dbgmsg("Initializing the engine structure\n");

	*engine = (struct cl_engine *) cli_calloc(1, sizeof(struct cl_engine));
	if(!*engine) {
	    cli_errmsg("Can't allocate memory for the engine structure!\n");
	    return CL_EMEM;
	}

	(*engine)->refcount = 1;

	(*engine)->root = (struct cli_matcher **) cli_calloc(CL_TARGET_TABLE_SIZE, sizeof(struct cli_matcher *));
	if(!(*engine)->root) {
	    /* no need to free previously allocated memory here */
	    cli_errmsg("Can't allocate memory for roots!\n");
	    return CL_EMEM;
	}
    }

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
		cli_errmsg("Can't initialise AC pattern matcher\n");
		return CL_EMEM;
	    }

	    if(options & CL_DB_ACONLY) {
		cli_dbgmsg("Only using AC pattern matcher.\n");
		root->ac_only = 1;
	    }

	    cli_dbgmsg("Initialising AC pattern matcher of root[%d]\n", i);
	    root->ac_root =  (struct cli_ac_node *) cli_calloc(1, sizeof(struct cli_ac_node));
	    if(!root->ac_root) {
		/* no need to free previously allocated memory here */
		cli_errmsg("Can't initialise AC pattern matcher\n");
		return CL_EMEM;
	    }

	    if(!root->ac_only) {
		cli_dbgmsg("Initializing BM tables of root[%d]\n", i);
		if((ret = cli_bm_init(root))) {
		    cli_errmsg("Can't initialise BM pattern matcher\n");
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

static int cli_loadndb(FILE *fd, struct cl_engine **engine, unsigned int *signo, unsigned short sdb, unsigned int options)
{
	char buffer[FILEBUFF], *sig, *virname, *offset, *pt;
	struct cli_matcher *root;
	int line = 0, sigs = 0, ret = 0;
	unsigned short target;
	unsigned int nophish = options & CL_DB_NOPHISHING;


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

	if(nophish)
	    if(!strncmp(buffer, "HTML.Phishing", 13) || !strncmp(buffer, "Email.Phishing", 14))
		continue;

	sigs++;
	cli_chomp(buffer);

	if(!(virname = cli_strtok(buffer, 0, ":"))) {
	    ret = CL_EMALFDB;
	    break;
	}

	if((pt = cli_strtok(buffer, 4, ":"))) { /* min version */
	    if(!isdigit(*pt)) {
		free(virname);
		free(pt);
		ret = CL_EMALFDB;
		break;
	    }

	    if(atoi(pt) > cl_retflevel()) {
		cli_dbgmsg("Signature for %s requires new ClamAV version. Please update!\n", virname);
		sigs--;
		free(virname);
		free(pt);
		continue;
	    }

	    free(pt);

	    if((pt = cli_strtok(buffer, 5, ":"))) { /* max version */
		if(!isdigit(*pt)) {
		    free(virname);
		    free(pt);
		    ret = CL_EMALFDB;
		    break;
		}

		if(atoi(pt) < cl_retflevel()) {
		    sigs--;
		    free(virname);
		    free(pt);
		    continue;
		}

		free(pt);
	    }
	}

	if(!(pt = cli_strtok(buffer, 1, ":")) || !isdigit(*pt)) {
	    free(virname);
	    if(pt)
		free(pt);
	    ret = CL_EMALFDB;
	    break;
	}
	target = (unsigned short) atoi(pt);
	free(pt);

	if(target >= CL_TARGET_TABLE_SIZE) {
	    cli_dbgmsg("Not supported target type in signature for %s\n", virname);
	    sigs--;
	    free(virname);
	    free(pt);
	    continue;
	}

	root = (*engine)->root[target];

	if(!(offset = cli_strtok(buffer, 2, ":"))) {
	    free(virname);
	    ret = CL_EMALFDB;
	    break;
	} else if(!strcmp(offset, "*")) {
	    free(offset);
	    offset = NULL;
	}

	if(!(sig = cli_strtok(buffer, 3, ":"))) {
	    free(virname);
	    free(offset);
	    ret = CL_EMALFDB;
	    break;
	}

	if((ret = cli_parse_add(root, virname, sig, 0, offset, target))) {
	    cli_errmsg("Problem parsing signature at line %d\n", line);
	    free(virname);
	    free(offset);
	    free(sig);
	    ret = CL_EMALFDB;
	    break;
	}

	free(virname);
	free(sig);
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

static int cli_loadhdb(FILE *fd, struct cl_engine **engine, unsigned int *signo, unsigned short fp, unsigned int options)
{
	char buffer[FILEBUFF], *pt;
	int line = 0, ret = 0;
	struct cli_md5_node *new;


    if((ret = cli_initengine(engine, options))) {
	cl_free(*engine);
	return ret;
    }

    while(fgets(buffer, FILEBUFF, fd)) {
	line++;
	cli_chomp(buffer);

	new = (struct cli_md5_node *) cli_calloc(1, sizeof(struct cli_md5_node));
	if(!new) {
	    ret = CL_EMEM;
	    break;
	}

	new->fp = fp;

	if(!(pt = cli_strtok(buffer, 0, ":"))) {
	    free(new);
	    ret = CL_EMALFDB;
	    break;
	}

	if(!(new->md5 = (unsigned char *) cli_hex2str(pt))) {
	    cli_errmsg("Malformed MD5 string at line %d\n", line);
	    free(pt);
	    free(new);
	    ret = CL_EMALFDB;
	    break;
	}
	free(pt);

	if(!(pt = cli_strtok(buffer, 1, ":"))) {
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

	new->viralias = cli_strtok(buffer, 3, ":"); /* aliases are optional */

	if(!(*engine)->md5_hlist) {
	    cli_dbgmsg("Initializing md5 list structure\n");
	    (*engine)->md5_hlist = (struct cli_md5_node **) cli_calloc(256, sizeof(struct cli_md5_node *));
	    if(!(*engine)->md5_hlist) {
		ret = CL_EMEM;
		break;
	    }
	}

	new->next = (*engine)->md5_hlist[new->md5[0] & 0xff];
	(*engine)->md5_hlist[new->md5[0] & 0xff] = new;
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

#ifdef HAVE_HWACCEL
static int cli_loadhw(const char *filename, struct cl_engine **engine, unsigned int *signo, unsigned int options)
{
	int ret = 0;


    if((ret = cli_initengine(engine, options))) {
	cl_free(*engine);
	return ret;
    }

    if((ret = sn_sigscan_initdb(&(*engine)->hwdb)) < 0) {
	cli_errmsg("hwaccel: error initializing the matcher: %d\n", ret);
	cl_free(*engine);
	return CL_EHWINIT;
    }

    (*engine)->hwaccel = 1;

    if((ret = sn_sigscan_loaddb((*engine)->hwdb, filename, 0, signo)) < 0) {
	cli_errmsg("hwaccel: can't load hardware database: %d\n", ret);
	cl_free(*engine);
	return CL_EHWLOAD;
    }

    return CL_SUCCESS;
}
#endif /* HAVE_HWACCEL */

static int cli_loaddbdir(const char *dirname, struct cl_engine **engine, unsigned int *signo, unsigned int options);

static int cli_load(const char *filename, struct cl_engine **engine, unsigned int *signo, unsigned int options)
{
	FILE *fd;
	int ret = CL_SUCCESS;
	uint8_t skipped = 0;


    if(cli_strbcasestr(filename, ".inc"))
	return cli_loaddbdir(filename, engine, signo, options);

    if((fd = fopen(filename, "rb")) == NULL) {
	cli_errmsg("cli_load(): Can't open file %s\n", filename);
	return CL_EOPEN;
    }

    if(cli_strbcasestr(filename, ".db")) {
	if(options & CL_DB_HWACCEL)
	    skipped = 1;
	else
	    ret = cli_loaddb(fd, engine, signo, options);

    } else if(cli_strbcasestr(filename, ".cvd")) {
	    int warn = 0;

	if(strstr(filename, "daily.cvd"))
	    warn = 1;

	ret = cli_cvdload(fd, engine, signo, warn, options);

    } else if(cli_strbcasestr(filename, ".hdb")) {
	ret = cli_loadhdb(fd, engine, signo, 0, options);

    } else if(cli_strbcasestr(filename, ".fp")) {
	ret = cli_loadhdb(fd, engine, signo, 1, options);

    } else if(cli_strbcasestr(filename, ".ndb")) {
	if(options & CL_DB_HWACCEL)
	    skipped = 1;
	else
	    ret = cli_loadndb(fd, engine, signo, 0, options);

    } else if(cli_strbcasestr(filename, ".sdb")) {
	/* FIXME: Add support in hwaccel mode */
	if(options & CL_DB_HWACCEL)
	    skipped = 1;
	else
	    ret = cli_loadndb(fd, engine, signo, 1, options);

    } else if(cli_strbcasestr(filename, ".zmd")) {
	ret = cli_loadmd(fd, engine, signo, 1, options);

    } else if(cli_strbcasestr(filename, ".rmd")) {
	ret = cli_loadmd(fd, engine, signo, 2, options);

    } else if(cli_strbcasestr(filename, ".hw")) {
#ifdef HAVE_HWACCEL
	if(options & CL_DB_HWACCEL)
	    ret = cli_loadhw(filename, engine, signo, options);
	else
#endif
	    skipped = 1;
#ifdef CL_EXPERIMENTAL
/*
    } else if(cli_strbcasestr(filename, ".wdb")) {
	if(!(options & CL_SCAN_NOPHISHING))
	    ret = cli_loadwdb(fd, options);
	else
	    skipped = 1;
    } else if(cli_strbcasestr(filename, ".pdb")) {
	if(!(options & CL_SCAN_NOPHISHING))
	    ret = cli_loadpdb(fd, options);
	else
	    skipped = 1;
*/
#endif
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
    return cli_load(filename, engine, signo, 0);
}

static int cli_loaddbdir(const char *dirname, struct cl_engine **engine, unsigned int *signo, unsigned int options)
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
	int ret;


    if((dd = opendir(dirname)) == NULL) {
        cli_errmsg("cli_loaddbdir(): Can't open directory %s\n", dirname);
        return CL_EOPEN;
    }

    cli_dbgmsg("Loading databases from %s\n", dirname);

#ifdef HAVE_READDIR_R_3
    while(!readdir_r(dd, &result.d, &dent) && dent) {
#elif defined(HAVE_READDIR_R_2)
    while((dent = (struct dirent *) readdir_r(dd, &result.d))) {
#else
    while((dent = readdir(dd))) {
#endif
#ifndef C_INTERIX
	if(dent->d_ino)
#endif
	{
	    if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..") &&
	    (cli_strbcasestr(dent->d_name, ".db")   ||
	     cli_strbcasestr(dent->d_name, ".db2")  ||
	     cli_strbcasestr(dent->d_name, ".db3")  ||
	     cli_strbcasestr(dent->d_name, ".hdb")  ||
	     cli_strbcasestr(dent->d_name, ".fp")   ||
	     cli_strbcasestr(dent->d_name, ".ndb")  ||
	     cli_strbcasestr(dent->d_name, ".sdb")  ||
	     cli_strbcasestr(dent->d_name, ".zmd")  ||
	     cli_strbcasestr(dent->d_name, ".rmd")  ||
#ifdef CL_EXPERIMENTAL
/*
	     cli_strbcasestr(dent->d_name, ".pdb")  ||
	     cli_strbcasestr(dent->d_name, ".wdb")  ||
*/
#endif
	     cli_strbcasestr(dent->d_name, ".hw")  ||
	     cli_strbcasestr(dent->d_name, ".inc")  ||
	     cli_strbcasestr(dent->d_name, ".cvd"))) {

		dbfile = (char *) cli_calloc(strlen(dent->d_name) + strlen(dirname) + 2, sizeof(char));

		if(!dbfile) {
		    cli_dbgmsg("cli_loaddbdir(): dbfile == NULL\n");
		    closedir(dd);
		    return CL_EMEM;
		}
		sprintf(dbfile, "%s/%s", dirname, dent->d_name);
		if((ret = cli_load(dbfile, engine, signo, options))) {
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
    return CL_SUCCESS;
}

int cl_loaddbdir(const char *dirname, struct cl_engine **engine, unsigned int *signo) {
    return cli_loaddbdir(dirname, engine, signo, 0);
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

    switch(sb.st_mode & S_IFMT) {
	case S_IFREG: 
	    return cli_load(path, engine, signo, options);

	case S_IFDIR:
	    return cli_loaddbdir(path, engine, signo, options);

	default:
	    cli_errmsg("cl_load(): Not supported database file type\n");
	    return CL_EOPEN;
    }
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
	dbstat->no = 0;
	dbstat->stattab = NULL;
	dbstat->statdname = NULL;
	dbstat->dir = strdup(dirname);
    } else {
        cli_errmsg("cl_statdbdir(): Null argument passed.\n");
	return CL_ENULLARG;
    }

    if((dd = opendir(dirname)) == NULL) {
        cli_errmsg("cl_statdbdir(): Can't open directory %s\n", dirname);
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
#ifndef C_INTERIX
	if(dent->d_ino)
#endif
	{
	    if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..") &&
	    (cli_strbcasestr(dent->d_name, ".db")  ||
	    cli_strbcasestr(dent->d_name, ".db2")  || 
	    cli_strbcasestr(dent->d_name, ".db3")  || 
	    cli_strbcasestr(dent->d_name, ".hdb")  || 
	    cli_strbcasestr(dent->d_name, ".fp")   || 
	    cli_strbcasestr(dent->d_name, ".ndb")  || 
	    cli_strbcasestr(dent->d_name, ".sdb")  || 
	    cli_strbcasestr(dent->d_name, ".zmd")  || 
	    cli_strbcasestr(dent->d_name, ".rmd")  || 
#ifdef CL_EXPERIMENTAL
/*
	    cli_strbcasestr(dent->d_name, ".pdb")  ||
	    cli_strbcasestr(dent->d_name, ".wdb")  ||
*/
#endif
	    cli_strbcasestr(dent->d_name, ".hw")   ||
	    cli_strbcasestr(dent->d_name, ".inc")   ||
	    cli_strbcasestr(dent->d_name, ".cvd"))) {

		dbstat->no++;
		dbstat->stattab = (struct stat *) realloc(dbstat->stattab, dbstat->no * sizeof(struct stat));
#if defined(C_INTERIX) || defined(C_OS2)
		dbstat->statdname = (char **) realloc(dbstat->statdname, dbstat->no * sizeof(char *));
#endif

                fname = cli_calloc(strlen(dirname) + strlen(dent->d_name) + 2, sizeof(char));
		sprintf(fname, "%s/%s", dirname, dent->d_name);
#if defined(C_INTERIX) || defined(C_OS2)
		dbstat->statdname[dbstat->no - 1] = (char *) cli_calloc(strlen(dent->d_name) + 1, sizeof(char));
		strcpy(dbstat->statdname[dbstat->no - 1], dent->d_name);
#endif
		stat(fname, &dbstat->stattab[dbstat->no - 1]);
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
	int i, found;
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
#ifndef C_INTERIX
	if(dent->d_ino)
#endif
	{
	    if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..") &&
	    (cli_strbcasestr(dent->d_name, ".db")  ||
	    cli_strbcasestr(dent->d_name, ".db2")  || 
	    cli_strbcasestr(dent->d_name, ".db3")  || 
	    cli_strbcasestr(dent->d_name, ".hdb")  || 
	    cli_strbcasestr(dent->d_name, ".fp")   || 
	    cli_strbcasestr(dent->d_name, ".ndb")  || 
	    cli_strbcasestr(dent->d_name, ".sdb")  || 
	    cli_strbcasestr(dent->d_name, ".zmd")  || 
	    cli_strbcasestr(dent->d_name, ".rmd")  || 
#ifdef CL_EXPERIMENTAL
/*
	    cli_strbcasestr(dent->d_name, ".pdb")  ||
	    cli_strbcasestr(dent->d_name, ".wdb")  ||
*/
#endif
	    cli_strbcasestr(dent->d_name, ".hw")   ||
	    cli_strbcasestr(dent->d_name, ".inc")   ||
	    cli_strbcasestr(dent->d_name, ".cvd"))) {

                fname = cli_calloc(strlen(dbstat->dir) + strlen(dent->d_name) + 2, sizeof(char));
		sprintf(fname, "%s/%s", dbstat->dir, dent->d_name);
		stat(fname, &sb);
		free(fname);

		found = 0;
		for(i = 0; i < dbstat->no; i++)
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

	for(i = 0;i < dbstat->no; i++) {
	    free(dbstat->statdname[i]);
	    dbstat->statdname[i] = NULL;
	}
	free(dbstat->statdname);
	dbstat->statdname = NULL;
#endif

	free(dbstat->stattab);
	dbstat->stattab = NULL;
	dbstat->no = 0;
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
#ifdef HAVE_HWACCEL
	int ret;
#endif


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

#ifdef HAVE_HWACCEL
    if(engine->hwaccel) {
	if((ret = sn_sigscan_closedb(engine->hwdb)) < 0) {
	    cli_errmsg("cl_free: can't close hardware database: %d\n", ret);
	}
    }
#endif

    for(i = 0; i < CL_TARGET_TABLE_SIZE; i++) {
	if((root = engine->root[i])) {
	    cli_ac_free(root);
	    if(!engine->root[i]->ac_only)
		cli_bm_free(root);
	    free(root);
	}
    }

    free(engine->root);
    if(engine->md5_hlist) {
	for(i = 0; i < 256; i++) {
	    md5pt = engine->md5_hlist[i];
	    while(md5pt) {
		md5h = md5pt;
		md5pt = md5pt->next;
		free(md5h->md5);
		free(md5h->virname);
		if(md5h->viralias)
		    free(md5h->viralias);
		free(md5h);
	    }
	}
	free(engine->md5_hlist);
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

/*
 *  Copyright (C) 2002 - 2005 Tomasz Kojm <tkojm@clamav.net>
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
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

/* TODO: clean up the code */

static int cli_ac_addsig(struct cl_node *root, const char *virname, const char *hexsig, int sigid, int parts, int partno, unsigned short type, unsigned int mindist, unsigned int maxdist, char *offset, unsigned short target)
{
	struct cli_ac_patt *new;
	char *pt, *hex;
	int virlen, ret, error = 0;
	unsigned int i;


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
	    new->altn = (unsigned short int *) realloc(new->altn, new->alt * sizeof(unsigned short int));
	    new->altn[new->alt - 1] = 0;
	    new->altc = (char **) realloc(new->altc, new->alt * sizeof(char *));
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
	    free(hexnew);
	    if(new->alt) {
		free(new->altn);
		for(i = 0; i < new->alt; i++)
		    if(new->altc[i])
			free(new->altc[i]);
		free(new->altc);
	    }
	    free(new);
	    return CL_EMALFDB;
	}

    } else
	hex = (char *) hexsig;


    new->length = strlen(hex) / 2;

    if(new->length > root->maxpatlen)
	root->maxpatlen = new->length;

    if((new->pattern = cli_hex2si(hex)) == NULL) {
	if(new->alt) {
	    free(new->altn);
	    for(i = 0; i < new->alt; i++)
		free(new->altc[i]);
	    free(new->altc);
	    free(hex);
	}
	free(new);
	return CL_EMALFDB;
    }

    if((pt = strstr(virname, "(Clam)")))
	virlen = strlen(virname) - strlen(pt) - 1;
    else
	virlen = strlen(virname);

    if(virlen <= 0) {
	free(new->pattern);
	if(new->alt) {
	    free(new->altn);
	    for(i = 0; i < new->alt; i++)
		free(new->altc[i]);
	    free(new->altc);
	    free(hex);
	}
	free(new);
	return CL_EMALFDB;
    }

    if((new->virname = cli_calloc(virlen + 1, sizeof(char))) == NULL) {
	free(new->pattern);
	if(new->alt) {
	    free(new->altn);
	    for(i = 0; i < new->alt; i++)
		free(new->altc[i]);
	    free(new->altc);
	    free(hex);
	}
	free(new);
	return CL_EMEM;
    }

    strncpy(new->virname, virname, virlen);

    if((ret = cli_ac_addpatt(root, new))) {
	free(new->pattern);
	free(new->virname);
	if(new->alt) {
	    free(new->altn);
	    for(i = 0; i < new->alt; i++)
		free(new->altc[i]);
	    free(new->altc);
	    free(hex);
	}
	free(new);
	return ret;
    }

    if(new->alt)
	free(hex);

    return 0;
}

int cli_parse_add(struct cl_node *root, const char *virname, const char *hexsig, unsigned short type, char *offset, unsigned short target)
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
		cli_errmsg("Can't extract part %d of partial signature.\n", i + 1);
		return CL_EMALFDB;
	    }

	    if((ret = cli_ac_addsig(root, virname, pt, root->ac_partsigs, parts, i, type, 0, 0, offset, target))) {
		cli_errmsg("cli_parse_add(): Problem adding signature (2).\n");
		free(pt);
		return ret;
	    }

	    free(pt);
	}

    } else if(strpbrk(hexsig, "?(") || type) {
	if((ret = cli_ac_addsig(root, virname, hexsig, 0, 0, 0, type, 0, 0, offset, target))) {
	    cli_errmsg("cli_parse_add(): Problem adding signature (3).\n");
	    return ret;
	}

    } else {
	bm_new = (struct cli_bm_patt *) calloc(1, sizeof(struct cli_bm_patt));
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

    return 0;
}

static int cli_loaddb(FILE *fd, struct cl_node **root, unsigned int *signo)
{
	char buffer[FILEBUFF], *pt, *start;
	int line = 0, ret = 0;


    if(!*root) {
	cli_dbgmsg("Initializing main node\n");
	*root = (struct cl_node *) cli_calloc(1, sizeof(struct cl_node));
	if(!*root)
	    return CL_EMEM;
	(*root)->refcount = 1;
    }

    if(!(*root)->ac_root) {
	cli_dbgmsg("Initializing trie\n");
	(*root)->ac_root =  (struct cli_ac_node *) cli_calloc(1, sizeof(struct cli_ac_node));
	if(!(*root)->ac_root) {
	    free(*root);
	    cli_errmsg("Can't initialise AC pattern matcher\n");
	    return CL_EMEM;
	}
    }

    if(!(*root)->bm_shift) {
	cli_dbgmsg("Initializing BM tables\n");
	if((ret = cli_bm_init(*root))) {
	    cli_errmsg("Can't initialise BM pattern matcher\n");
	    return ret;
	}
    }

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

	if((ret = cli_parse_add(*root, start, pt, 0, NULL, 0))) {
	    cli_errmsg("Problem parsing signature at line %d\n", line);
	    ret = CL_EMALFDB;
	    break;
	}
    }

    if(!line) {
	cli_errmsg("Empty database file\n");
	cl_free(*root);
	return CL_EMALFDB;
    }

    if(ret) {
	cli_errmsg("Problem parsing database at line %d\n", line);
	cl_free(*root);
	return ret;
    }

    if(signo)
	*signo += line;

    return 0;
}

static int cli_loadndb(FILE *fd, struct cl_node **root, unsigned int *signo, unsigned short sdb)
{
	char buffer[FILEBUFF], *sig, *virname, *offset, *pt;
	int line = 0, sigs = 0, ret = 0;
	unsigned short target;


    if(!*root) {
	cli_dbgmsg("Initializing main node\n");
	*root = (struct cl_node *) cli_calloc(1, sizeof(struct cl_node));
	if(!*root)
	    return CL_EMEM;
	(*root)->refcount = 1;
    }

    if(!(*root)->ac_root) {
	cli_dbgmsg("Initializing trie\n");
	(*root)->ac_root =  (struct cli_ac_node *) cli_calloc(1, sizeof(struct cli_ac_node));
	if(!(*root)->ac_root) {
	    free(*root);
	    cli_errmsg("Can't initialise AC pattern matcher\n");
	    return CL_EMEM;
	}
    }

    if(!(*root)->bm_shift) {
	cli_dbgmsg("Initializing BM tables\n");
	if((ret = cli_bm_init(*root))) {
	    cli_errmsg("Can't initialise BM pattern matcher\n");
	    return ret;
	}
    }

    while(fgets(buffer, FILEBUFF, fd)) {
	line++;

	if(!strncmp(buffer, "Exploit.JPEG.Comment", 20)) /* temporary */
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
		cli_warnmsg("Signature for %s requires new ClamAV version. Please update!\n", virname);
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

	if((ret = cli_parse_add(*root, virname, sig, 0, offset, target))) {
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
	cl_free(*root);
	return CL_EMALFDB;
    }

    if(ret) {
	cli_errmsg("Problem parsing database at line %d\n", line);
	cl_free(*root);
	return ret;
    }

    if(signo)
	*signo += sigs;

    if(sdb && sigs && !(*root)->sdb) {
	(*root)->sdb = 1;
	cli_dbgmsg("*** Self protection mechanism activated.\n");
    }

    return 0;
}

static int cli_loadhdb(FILE *fd, struct cl_node **root, unsigned int *signo, unsigned short fp)
{
	char buffer[FILEBUFF], *pt;
	int line = 0, ret = 0;
	struct cli_md5_node *new;


    if(!*root) {
	cli_dbgmsg("Initializing main node\n");
	*root = (struct cl_node *) cli_calloc(1, sizeof(struct cl_node));
	if(!*root)
	    return CL_EMEM;
	(*root)->refcount = 1;
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

	if(!(*root)->md5_hlist) {
	    cli_dbgmsg("Initializing md5 list structure\n");
	    (*root)->md5_hlist = (struct cli_md5_node **) cli_calloc(256, sizeof(struct cli_md5_node *));
	    if(!(*root)->md5_hlist) {
		ret = CL_EMEM;
		break;
	    }
	}

	new->next = (*root)->md5_hlist[new->md5[0] & 0xff];
	(*root)->md5_hlist[new->md5[0] & 0xff] = new;
    }

    if(!line) {
	cli_errmsg("Empty database file\n");
	cl_free(*root);
	return CL_EMALFDB;
    }

    if(ret) {
	cli_errmsg("Problem parsing database at line %d\n", line);
	cl_free(*root);
	return ret;
    }

    if(signo)
	*signo += line;

    return 0;
}

static int cli_loadmd(FILE *fd, struct cl_node **root, unsigned int *signo, int type)
{
	char buffer[FILEBUFF], *pt;
	int line = 0, comments = 0, ret = 0;
	struct cli_meta_node *new;


    if(!*root) {
	cli_dbgmsg("Initializing main node\n");
	*root = (struct cl_node *) cli_calloc(1, sizeof(struct cl_node));
	if(!*root)
	    return CL_EMEM;
	(*root)->refcount = 1;
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
		new->crc32 = cli_hex2num(pt);
		if(new->crc32 == -1) {
		    ret = CL_EMALFDB;
		    break;
		}
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
	    new->next = (*root)->zip_mlist;
	    (*root)->zip_mlist = new;
	} else {
	    new->next = (*root)->rar_mlist;
	    (*root)->rar_mlist = new;
	}
    }

    if(!line) {
	cli_errmsg("Empty database file\n");
	cl_free(*root);
	return CL_EMALFDB;
    }

    if(ret) {
	cli_errmsg("Problem parsing database at line %d\n", line);
	cl_free(*root);
	return ret;
    }

    if(signo)
	*signo += (line - comments);

    return 0;
}

int cl_loaddb(const char *filename, struct cl_node **root, unsigned int *signo)
{
	FILE *fd;
	int ret;


    if((fd = fopen(filename, "rb")) == NULL) {
	cli_errmsg("cl_loaddb(): Can't open file %s\n", filename);
	return CL_EOPEN;
    }

    cli_dbgmsg("Loading %s\n", filename);

    if(cli_strbcasestr(filename, ".db")  || cli_strbcasestr(filename, ".db2") || cli_strbcasestr(filename, ".db3")) {
	ret = cli_loaddb(fd, root, signo);

    } else if(cli_strbcasestr(filename, ".cvd")) {
	    int warn = 0;

	if(strstr(filename, "daily.cvd"))
	    warn = 1;

	ret = cli_cvdload(fd, root, signo, warn);

    } else if(cli_strbcasestr(filename, ".hdb")) {
	ret = cli_loadhdb(fd, root, signo, 0);

    } else if(cli_strbcasestr(filename, ".fp")) {
	ret = cli_loadhdb(fd, root, signo, 1);

    } else if(cli_strbcasestr(filename, ".ndb")) {
	ret = cli_loadndb(fd, root, signo, 0);

    } else if(cli_strbcasestr(filename, ".sdb")) {
	ret = cli_loadndb(fd, root, signo, 1);

    } else if(cli_strbcasestr(filename, ".zmd")) {
	ret = cli_loadmd(fd, root, signo, 1);

    } else if(cli_strbcasestr(filename, ".rmd")) {
	ret = cli_loadmd(fd, root, signo, 2);

    } else {
	cli_dbgmsg("cl_loaddb: unknown extension - assuming old database format\n");
	ret = cli_loaddb(fd, root, signo);
    }

    if(ret)
	cli_errmsg("Can't load %s: %s\n", filename, cl_strerror(ret));

    fclose(fd);
    return ret;
}

int cl_loaddbdir(const char *dirname, struct cl_node **root, unsigned int *signo)
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
        cli_errmsg("cl_loaddbdir(): Can't open directory %s\n", dirname);
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
	     cli_strbcasestr(dent->d_name, ".cvd"))) {

		dbfile = (char *) cli_calloc(strlen(dent->d_name) + strlen(dirname) + 2, sizeof(char));

		if(!dbfile) {
		    cli_dbgmsg("cl_loaddbdir(): dbfile == NULL\n");
		    closedir(dd);
		    return CL_EMEM;
		}
		sprintf(dbfile, "%s/%s", dirname, dent->d_name);
		if((ret = cl_loaddb(dbfile, root, signo))) {
		    cli_dbgmsg("cl_loaddbdir(): error loading database %s\n", dbfile);
		    free(dbfile);
		    closedir(dd);
		    return ret;
		}
		free(dbfile);
	    }
	}
    }

    closedir(dd);
    return 0;
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
	    cli_strbcasestr(dent->d_name, ".fp")  || 
	    cli_strbcasestr(dent->d_name, ".ndb")  || 
	    cli_strbcasestr(dent->d_name, ".sdb")  || 
	    cli_strbcasestr(dent->d_name, ".zmd")  || 
	    cli_strbcasestr(dent->d_name, ".rmd")  || 
	    cli_strbcasestr(dent->d_name, ".cvd"))) {

		dbstat->no++;
		dbstat->stattab = (struct stat *) realloc(dbstat->stattab, dbstat->no * sizeof(struct stat));
#if defined(C_INTERIX) || defined(C_OS2)
		dbstat->statdname = (char **) realloc(dbstat->statdname, dbstat->no * sizeof(char *));
#endif

                fname = cli_calloc(strlen(dirname) + strlen(dent->d_name) + 2, sizeof(char));
		sprintf(fname, "%s/%s", dirname, dent->d_name);
#if defined(C_INTERIX) || defined(C_OS2)
		dbstat->statdname[dbstat->no - 1] = (char *) calloc(strlen(dent->d_name) + 1, sizeof(char));
		strcpy(dbstat->statdname[dbstat->no - 1], dent->d_name);
#endif
		stat(fname, &dbstat->stattab[dbstat->no - 1]);
		free(fname);
	    }
	}
    }

    closedir(dd);
    return 0;
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
	    cli_strbcasestr(dent->d_name, ".fp")  || 
	    cli_strbcasestr(dent->d_name, ".ndb")  || 
	    cli_strbcasestr(dent->d_name, ".sdb")  || 
	    cli_strbcasestr(dent->d_name, ".zmd")  || 
	    cli_strbcasestr(dent->d_name, ".rmd")  || 
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
    return 0;
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

    return 0;
}

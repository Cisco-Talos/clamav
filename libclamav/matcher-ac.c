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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "clamav.h"
#include "others.h"
#include "matcher.h"
#include "matcher-ac.h"
#include "filetypes.h"
#include "cltypes.h"
#include "str.h"

uint8_t cli_ac_mindepth = AC_DEFAULT_MIN_DEPTH;
uint8_t cli_ac_maxdepth = AC_DEFAULT_MAX_DEPTH;

int cli_ac_addpatt(struct cli_matcher *root, struct cli_ac_patt *pattern)
{
	struct cli_ac_node *pt, *next, **newtable;
	struct cli_ac_patt *ph;
	struct cli_ac_alt *a1, *a2;
	uint8_t i, match;
	uint16_t len = MIN(root->ac_maxdepth, pattern->length);


    for(i = 0; i < len; i++) {
	if(pattern->pattern[i] & CLI_MATCH_WILDCARD) {
	    len = i;
	    break;
	}
    }

    if(len < root->ac_mindepth)
	return CL_EPATSHORT;

    pt = root->ac_root;

    for(i = 0; i < len; i++) {
	if(!pt->trans) {
	    pt->trans = (struct cli_ac_node **) cli_calloc(256, sizeof(struct cli_ac_node *));
	    if(!pt->trans) {
		cli_errmsg("cli_ac_addpatt: Can't allocate memory for pt->trans\n");
		return CL_EMEM;
	    }
	}

	next = pt->trans[(unsigned char) (pattern->pattern[i] & 0xff)]; 

	if(!next) {
	    next = (struct cli_ac_node *) cli_calloc(1, sizeof(struct cli_ac_node));
	    if(!next) {
		cli_errmsg("cli_ac_addpatt: Can't allocate memory for AC node\n");
		return CL_EMEM;
	    }

	    if(i != len - 1) {
		next->trans = (struct cli_ac_node **) cli_calloc(256, sizeof(struct cli_ac_node *));
		if(!next->trans) {
		    cli_errmsg("cli_ac_addpatt: Can't allocate memory for next->trans\n");
		    free(next);
		    return CL_EMEM;
		}
	    } else {
		next->leaf = 1;
	    }

	    root->ac_nodes++;
	    newtable = (struct cli_ac_node **) cli_realloc(root->ac_nodetable, root->ac_nodes * sizeof(struct cli_ac_node *));
	    if(!newtable) {
		root->ac_nodes--;
		cli_errmsg("cli_ac_addpatt: Can't realloc ac_nodetable\n");
		if(next->trans)
		    free(next->trans);
		free(next);
		return CL_EMEM;
	    }
	    newtable[root->ac_nodes - 1] = next;
	    root->ac_nodetable = newtable;

	    pt->trans[(unsigned char) (pattern->pattern[i] & 0xff)] = next;
	    pt->leaf = 0;
	}

	pt = next;
    }

    root->ac_patterns++;
    root->ac_pattable = (struct cli_ac_patt **) cli_realloc2(root->ac_pattable, root->ac_patterns * sizeof(struct cli_ac_patt *));
    if(!root->ac_pattable) {
	cli_errmsg("cli_ac_addpatt: Can't realloc ac_pattable\n");
	return CL_EMEM;
    }
    root->ac_pattable[root->ac_patterns - 1] = pattern;

    pt->final = 1;
    pattern->depth = i;

    ph = pt->list;
    while(ph) {
	if((ph->length == pattern->length) && (ph->prefix_length == pattern->prefix_length)) {
	    if(!memcmp(ph->pattern, pattern->pattern, ph->length * sizeof(uint16_t)) && !memcmp(ph->prefix, pattern->prefix, ph->prefix_length * sizeof(uint16_t))) {
		if(!ph->alt && !pattern->alt) {
		    match = 1;
		} else if(ph->alt == pattern->alt) {
		    match = 1;
		    for(i = 0; i < ph->alt; i++) {
			a1 = ph->alttable[i];
			a2 = pattern->alttable[i];

			if(a1->num != a2->num) {
			    match = 0;
			    break;
			}
			if(a1->chmode != a2->chmode) {
			    match = 0;
			    break;
			} else if(a1->chmode) {
			    if(memcmp(a1->str, a2->str, a1->num)) {
				match = 0;
				break;
			    }
			} else {
			    while(a1 && a2) {
				if((a1->len != a2->len) || memcmp(a1->str, a2->str, a1->len))
				    break;
				a1 = a1->next;
				a2 = a2->next;
			    }
			    if(a1 || a2) {
				match = 0;
				break;
			    }
			}
		    }
		} else {
		    match = 0;
		}

		if(match) {
		    pattern->next_same = ph->next_same;
		    ph->next_same = pattern;
		    return CL_SUCCESS;
		}
	    }
	}
	ph = ph->next;
    }

    pattern->next = pt->list;
    pt->list = pattern;

    return CL_SUCCESS;
}

struct bfs_list {
    struct cli_ac_node *node;
    struct bfs_list *next;
};

static int bfs_enqueue(struct bfs_list **bfs, struct bfs_list **last, struct cli_ac_node *n)
{
	struct bfs_list *new;


    new = (struct bfs_list *) cli_malloc(sizeof(struct bfs_list));
    if(!new) {
	cli_errmsg("bfs_enqueue: Can't allocate memory for bfs_list\n");
	return CL_EMEM;
    }
    new->next = NULL;
    new->node = n;

    if(*last) {
	(*last)->next = new;
	*last = new;
    } else {
	*bfs = *last = new;
    }

    return CL_SUCCESS;
}

static struct cli_ac_node *bfs_dequeue(struct bfs_list **bfs, struct bfs_list **last)
{
	struct bfs_list *lpt;
	struct cli_ac_node *pt;


    if(!(lpt = *bfs)) {
	return NULL;
    } else {
	*bfs = (*bfs)->next;
	pt = lpt->node;
	if(lpt == *last)
	    *last = NULL;
	free(lpt);
	return pt;
    }
}

static int ac_maketrans(struct cli_matcher *root)
{
	struct bfs_list *bfs = NULL, *bfs_last = NULL;
	struct cli_ac_node *ac_root = root->ac_root, *child, *node, *fail;
	struct cli_ac_patt *patt;
	int i, ret;


    for(i = 0; i < 256; i++) {
	node = ac_root->trans[i];
	if(!node) {
	    ac_root->trans[i] = ac_root;
	} else {
	    node->fail = ac_root;
	    if((ret = bfs_enqueue(&bfs, &bfs_last, node)))
		return ret;
	}
    }

    while((node = bfs_dequeue(&bfs, &bfs_last))) {
	if(node->leaf)
	    continue;

	for(i = 0; i < 256; i++) {
	    child = node->trans[i];
	    if(child) {
		fail = node->fail;
		while(fail->leaf || !fail->trans[i])
		    fail = fail->fail;

		child->fail = fail->trans[i];

		if(child->list) {
		    patt = child->list;
		    while(patt->next)
			patt = patt->next;

		    patt->next = child->fail->list;
		} else {
		    child->list = child->fail->list;
		}

		if(child->list)
		    child->final = 1;

		if((ret = bfs_enqueue(&bfs, &bfs_last, child)) != 0)
		    return ret;
	    }
	}
    }

    return CL_SUCCESS;
}

int cli_ac_buildtrie(struct cli_matcher *root)
{
    if(!root)
	return CL_EMALFDB;

    if(!root->ac_root) {
	cli_dbgmsg("cli_ac_buildtrie: AC pattern matcher is not initialised\n");
	return CL_SUCCESS;
    }

    return ac_maketrans(root);
}

int cli_ac_init(struct cli_matcher *root, uint8_t mindepth, uint8_t maxdepth)
{

    root->ac_root = (struct cli_ac_node *) cli_calloc(1, sizeof(struct cli_ac_node));
    if(!root->ac_root) {
	cli_errmsg("cli_ac_init: Can't allocate memory for ac_root\n");
	return CL_EMEM;
    }

    root->ac_root->trans = (struct cli_ac_node **) cli_calloc(256, sizeof(struct cli_ac_node *));
    if(!root->ac_root->trans) {
	cli_errmsg("cli_ac_init: Can't allocate memory for ac_root->trans\n");
	free(root->ac_root);
	return CL_EMEM;
    }

    root->ac_mindepth = mindepth;
    root->ac_maxdepth = maxdepth;

    return CL_SUCCESS;
}

static void ac_free_alt(struct cli_ac_patt *p)
{
	uint16_t i;
	struct cli_ac_alt *a1, *a2;


    if(!p->alt)
	return;

    for(i = 0; i < p->alt; i++) {
	a1 = p->alttable[i];
	while(a1) {
	    a2 = a1;
	    a1 = a1->next;
	    if(a2->str)
		free(a2->str);
	    free(a2);
	}
    }
    free(p->alttable);
}

void cli_ac_free(struct cli_matcher *root)
{
	uint32_t i;
	struct cli_ac_patt *patt;


    for(i = 0; i < root->ac_patterns; i++) {
	patt = root->ac_pattable[i];

	if(patt->prefix)
	    free(patt->prefix);
	else
	    free(patt->pattern);
	free(patt->virname);
	if(patt->offset)
	    free(patt->offset);
	if(patt->alt)
	    ac_free_alt(patt);
	free(patt);
    }
    if(root->ac_pattable)
	free(root->ac_pattable);

    for(i = 0; i < root->ac_nodes; i++) {
	if(!root->ac_nodetable[i]->leaf)
	    free(root->ac_nodetable[i]->trans);
	free(root->ac_nodetable[i]);
    }

    if(root->ac_nodetable)
	free(root->ac_nodetable);

    if(root->ac_root) {
	free(root->ac_root->trans);
	free(root->ac_root);
    }
}

/* 
 * FIXME: the current support for string alternatives uses a brute-force
 *        approach and doesn't perform any kind of verification and
 *        backtracking. This may easily lead to false negatives, eg. when
 *        an alternative contains strings of different lengths and 
 *        more than one of them can match at the current position.
 */

#define AC_MATCH_CHAR(p,b)						\
    switch(wc = p & CLI_MATCH_WILDCARD) {				\
	case CLI_MATCH_CHAR:						\
	    if((unsigned char) p != b)					\
		return 0;						\
	    break;							\
									\
	case CLI_MATCH_IGNORE:						\
	    break;							\
									\
	case CLI_MATCH_ALTERNATIVE:					\
	    found = 0;							\
	    alt = pattern->alttable[altcnt];				\
	    if(alt->chmode) {						\
		for(j = 0; j < alt->num; j++) {				\
		    if(alt->str[j] == b) {				\
			found = 1;					\
			break;						\
		    }							\
		}							\
	    } else {							\
		while(alt) {						\
		    if(bp + alt->len <= length) {			\
			if(!memcmp(&buffer[bp], alt->str, alt->len)) {	\
			    found = 1;					\
			    bp += alt->len - 1;				\
			    break;					\
			}						\
		    }							\
		    alt = alt->next;					\
		}							\
	    }								\
	    if(!found)							\
		return 0;						\
	    altcnt++;							\
	    break;							\
									\
	case CLI_MATCH_NIBBLE_HIGH:					\
	    if((unsigned char) (p & 0x00f0) != (b & 0xf0))		\
		return 0;						\
	    break;							\
									\
	case CLI_MATCH_NIBBLE_LOW:					\
	    if((unsigned char) (p & 0x000f) != (b & 0x0f))		\
		return 0;						\
	    break;							\
									\
	default:							\
	    cli_errmsg("ac_findmatch: Unknown wildcard 0x%x\n", wc);	\
	    return 0;							\
    }

inline static int ac_findmatch(const unsigned char *buffer, uint32_t offset, uint32_t length, const struct cli_ac_patt *pattern, uint32_t *end)
{
	uint32_t bp;
	uint16_t wc, i, j, altcnt = pattern->alt_pattern;
	uint8_t found;
	struct cli_ac_alt *alt;


    if((offset + pattern->length > length) || (pattern->prefix_length > offset))
	return 0;

    bp = offset + pattern->depth;

    for(i = pattern->depth; i < pattern->length && bp < length; i++) {
	AC_MATCH_CHAR(pattern->pattern[i],buffer[bp]);
	bp++;
    }
    *end = bp;

    if(pattern->prefix) {
	altcnt = 0;
	bp = offset - pattern->prefix_length;

	for(i = 0; i < pattern->prefix_length; i++) {
	    AC_MATCH_CHAR(pattern->prefix[i],buffer[bp]);
	    bp++;
	}
    }

    return 1;
}

int cli_ac_initdata(struct cli_ac_data *data, uint32_t partsigs, uint8_t tracklen)
{

    if(!data) {
	cli_errmsg("cli_ac_init: data == NULL\n");
	return CL_ENULLARG;
    }

    data->partsigs = partsigs;

    if(!partsigs)
	return CL_SUCCESS;

    data->offmatrix = (int32_t ***) cli_calloc(partsigs, sizeof(int32_t **));
    if(!data->offmatrix) {
	cli_errmsg("cli_ac_init: Can't allocate memory for data->offmatrix\n");
	return CL_EMEM;
    }

    return CL_SUCCESS;
}

void cli_ac_freedata(struct cli_ac_data *data)
{
	uint32_t i;


    if(data && data->partsigs) {
	for(i = 0; i < data->partsigs; i++) {
	    if(data->offmatrix[i]) {
		free(data->offmatrix[i][0]);
		free(data->offmatrix[i]);
	    }
	}
	free(data->offmatrix);
    }
}

inline static int ac_addtype(struct cli_matched_type **list, cli_file_t type, off_t offset)
{
	struct cli_matched_type *tnode, *tnode_last;


    if(*list && (*list)->cnt >= MAX_EMBEDDED_OBJ)
	return CL_SUCCESS;

    if(!(tnode = cli_calloc(1, sizeof(struct cli_matched_type)))) {
	cli_errmsg("cli_ac_addtype: Can't allocate memory for new type node\n");
	return CL_EMEM;
    }

    tnode->type = type;
    tnode->offset = offset;

    tnode_last = *list;
    while(tnode_last && tnode_last->next)
	tnode_last = tnode_last->next;

    if(tnode_last)
	tnode_last->next = tnode;
    else
	*list = tnode;

    (*list)->cnt++;
    return CL_SUCCESS;
}

int cli_ac_scanbuff(const unsigned char *buffer, uint32_t length, const char **virname, const struct cli_matcher *root, struct cli_ac_data *mdata, uint8_t otfrec, uint32_t offset, cli_file_t ftype, int fd, struct cli_matched_type **ftoffset)
{
	struct cli_ac_node *current;
	struct cli_ac_patt *patt, *pt;
        uint32_t i, bp, realoff, matchend;
	uint16_t j;
	int32_t **offmatrix;
	uint8_t found;
	struct cli_target_info info;
	int type = CL_CLEAN;


    if(!root->ac_root)
	return CL_CLEAN;

    if(!mdata) {
	cli_errmsg("cli_ac_scanbuff: mdata == NULL\n");
	return CL_ENULLARG;
    }

    memset(&info, 0, sizeof(info));
    current = root->ac_root;

    for(i = 0; i < length; i++)  {

	while(current->leaf || !current->trans[buffer[i]])
	    current = current->fail;

	current = current->trans[buffer[i]];

	if(current->final) {
	    patt = current->list;
	    while(patt) {
		bp = i + 1 - patt->depth;
		if(ac_findmatch(buffer, bp, length, patt, &matchend)) {
		    pt = patt;
		    while(pt) {
			realoff = offset + bp - pt->prefix_length;

			if((pt->offset || pt->target) && (!pt->sigid || pt->partno == 1)) {
			    if((fd == -1 && !ftype) || !cli_validatesig(ftype, pt->offset, realoff, &info, fd, pt->virname)) {
				pt = pt->next_same;
				continue;
			    }
			}

			if(pt->sigid) { /* it's a partial signature */

			    if(pt->partno != 1 && (!mdata->offmatrix[pt->sigid - 1] || !mdata->offmatrix[pt->sigid - 1][pt->partno - 2][0])) {
				pt = pt->next_same;
				continue;
			    }

			    if(!mdata->offmatrix[pt->sigid - 1]) {
				mdata->offmatrix[pt->sigid - 1] = cli_malloc(pt->parts * sizeof(int32_t *));
				if(!mdata->offmatrix[pt->sigid - 1]) {
				    cli_errmsg("cli_ac_scanbuff: Can't allocate memory for mdata->offmatrix[%u]\n", pt->sigid - 1);
				    return CL_EMEM;
				}

				mdata->offmatrix[pt->sigid - 1][0] = cli_malloc(pt->parts * (AC_DEFAULT_TRACKLEN + 1) * sizeof(int32_t));
				if(!mdata->offmatrix[pt->sigid - 1][0]) {
				    cli_errmsg("cli_ac_scanbuff: Can't allocate memory for mdata->offmatrix[%u][0]\n", pt->sigid - 1);
				    free(mdata->offmatrix[pt->sigid - 1]);
				    mdata->offmatrix[pt->sigid - 1] = NULL;
				    return CL_EMEM;
				}
				memset(mdata->offmatrix[pt->sigid - 1][0], -1, pt->parts * (AC_DEFAULT_TRACKLEN + 1) * sizeof(int32_t));
				mdata->offmatrix[pt->sigid - 1][0][0] = 0;
				for(j = 1; j < pt->parts; j++) {
				    mdata->offmatrix[pt->sigid - 1][j] = mdata->offmatrix[pt->sigid - 1][0] + j * (AC_DEFAULT_TRACKLEN + 1);
				    mdata->offmatrix[pt->sigid - 1][j][0] = 0;
				}
			    }
			    offmatrix = mdata->offmatrix[pt->sigid - 1];

			    if(pt->partno != 1) {
				found = 0;
				for(j = 1; j <= AC_DEFAULT_TRACKLEN && offmatrix[pt->partno - 2][j] != -1; j++) {
				    found = 1;
				    if(pt->maxdist)
					if(realoff - offmatrix[pt->partno - 2][j] > pt->maxdist)
					    found = 0;

				    if(found && pt->mindist)
					if(realoff - offmatrix[pt->partno - 2][j] < pt->mindist)
					    found = 0;

				    if(found)
					break;
				}
			    }

			    if(pt->partno == 1 || (found && (pt->partno != pt->parts))) {
				offmatrix[pt->partno - 1][0] %= AC_DEFAULT_TRACKLEN;
				offmatrix[pt->partno - 1][0]++;
				offmatrix[pt->partno - 1][offmatrix[pt->partno - 1][0]] = offset + matchend;

				if(pt->partno == 1) /* save realoff for the first part */
				    offmatrix[pt->parts - 1][offmatrix[pt->partno - 1][0]] = realoff;
			    } else if(found && pt->partno == pt->parts) {
				if(pt->type) {
				    if(otfrec) {
					if(pt->type > type || pt->type >= CL_TYPE_SFX || pt->type == CL_TYPE_MSEXE) {
					    cli_dbgmsg("Matched signature for file type %s\n", pt->virname);
					    type = pt->type;
					    if(ftoffset && (!*ftoffset || (*ftoffset)->cnt < MAX_EMBEDDED_OBJ) && ((ftype == CL_TYPE_MSEXE && type >= CL_TYPE_SFX) || ((ftype == CL_TYPE_MSEXE || ftype == CL_TYPE_ZIP) && type == CL_TYPE_MSEXE)))  {
						/* FIXME: we don't know which offset of the first part is the correct one */
						for(j = 1; j <= AC_DEFAULT_TRACKLEN && offmatrix[0][j] != -1; j++) {
						    if(ac_addtype(ftoffset, type, offmatrix[pt->parts - 1][j])) {
							if(info.exeinfo.section)
							    free(info.exeinfo.section);
							return CL_EMEM;
						    }
						}
					    }

					    memset(offmatrix[0], -1, pt->parts * (AC_DEFAULT_TRACKLEN + 1) * sizeof(int32_t));
					    for(j = 0; j < pt->parts; j++)
						offmatrix[j][0] = 0;
					}
				    }

				} else { /* !pt->type */
				    if(virname)
					*virname = pt->virname;

				    if(info.exeinfo.section)
					free(info.exeinfo.section);

				    return CL_VIRUS;
				}
			    }

			} else { /* old type signature */
			    if(pt->type) {
				if(otfrec) {
				    if(pt->type > type || pt->type >= CL_TYPE_SFX || pt->type == CL_TYPE_MSEXE) {
					cli_dbgmsg("Matched signature for file type %s at %u\n", pt->virname, realoff);
					type = pt->type;
					if(ftoffset && (!*ftoffset || (*ftoffset)->cnt < MAX_EMBEDDED_OBJ) && ((ftype == CL_TYPE_MSEXE && type >= CL_TYPE_SFX) || ((ftype == CL_TYPE_MSEXE || ftype == CL_TYPE_ZIP) && type == CL_TYPE_MSEXE)))  {

					    if(ac_addtype(ftoffset, type, realoff)) {
						if(info.exeinfo.section)
						    free(info.exeinfo.section);
						return CL_EMEM;
					    }
					}
				    }
				}
			    } else {
				if(virname)
				    *virname = pt->virname;

				if(info.exeinfo.section)
				    free(info.exeinfo.section);
				return CL_VIRUS;
			    }
			}
			pt = pt->next_same;
		    }
		}
		patt = patt->next;
	    }
	}
    }

    if(info.exeinfo.section)
	free(info.exeinfo.section);

    return otfrec ? type : CL_CLEAN;
}

/* FIXME: clean up the code */
int cli_ac_addsig(struct cli_matcher *root, const char *virname, const char *hexsig, uint32_t sigid, uint16_t parts, uint16_t partno, uint16_t type, uint32_t mindist, uint32_t maxdist, const char *offset, uint8_t target)
{
	struct cli_ac_patt *new;
	char *pt, *hex = NULL;
	uint16_t i, j, ppos = 0, pend;
	uint8_t wprefix = 0, zprefix = 1, namelen, plen = 0;
	struct cli_ac_alt *newalt, *altpt, **newtable;
	int ret, error = CL_SUCCESS;


    if(strlen(hexsig) / 2 < root->ac_mindepth)
	return CL_EPATSHORT;

    if((new = (struct cli_ac_patt *) cli_calloc(1, sizeof(struct cli_ac_patt))) == NULL)
	return CL_EMEM;

    new->type = type;
    new->sigid = sigid;
    new->parts = parts;
    new->partno = partno;
    new->mindist = mindist;
    new->maxdist = maxdist;
    new->target = target;

    if(strchr(hexsig, '(')) {
	    char *hexcpy, *hexnew, *start, *h, *c;

	if(!(hexcpy = cli_strdup(hexsig))) {
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
		error = CL_EMALFDB;
		break;
	    }

	    strcat(hexnew, start);
	    strcat(hexnew, "()");

	    if(!(start = strchr(pt, ')'))) {
		error = CL_EMALFDB;
		break;
	    }
	    *start++ = 0;

	    newalt = (struct cli_ac_alt *) cli_calloc(1, sizeof(struct cli_ac_alt));
	    if(!newalt) {
		cli_errmsg("cli_ac_addsig: Can't allocate newalt\n");
		error = CL_EMEM;
		break;
	    }

	    new->alt++;
	    newtable = (struct cli_ac_alt **) cli_realloc(new->alttable, new->alt * sizeof(struct cli_ac_alt *));
	    if(!newtable) {
		new->alt--;
		free(newalt);
		cli_errmsg("cli_ac_addsig: Can't realloc new->alttable\n");
		error = CL_EMEM;
		break;
	    }
	    newtable[new->alt - 1] = newalt;
	    new->alttable = newtable;

	    for(i = 0; i < strlen(pt); i++)
		if(pt[i] == '|')
		    newalt->num++;

            if(!newalt->num) {
                error = CL_EMALFDB;
                break;
            } else
                newalt->num++;

	    if(3 * newalt->num - 1 == (uint16_t) strlen(pt)) {
		newalt->chmode = 1;
		newalt->str = (unsigned char *) cli_malloc(newalt->num);
		if(!newalt->str) {
		    cli_errmsg("cli_ac_addsig: Can't allocate newalt->str\n");
		    error = CL_EMEM;
		    break;
		}
	    }

	    for(i = 0; i < newalt->num; i++) {
		if(!(h = cli_strtok(pt, i, "|"))) {
		    error = CL_EMALFDB;
		    break;
		}

		if(!(c = cli_hex2str(h))) {
		    free(h);
		    error = CL_EMALFDB;
		    break;
		}

		if(newalt->chmode) {
		    newalt->str[i] = *c;
		    free(c);
		} else {
		    if(i) {
			altpt = newalt;
			while(altpt->next)
			    altpt = altpt->next;

			altpt->next = (struct cli_ac_alt *) cli_calloc(1, sizeof(struct cli_ac_alt));
			if(!altpt->next) {
			    cli_errmsg("cli_ac_addsig: Can't allocate altpt->next\n");
			    error = CL_EMEM;
			    free(c);
			    free(h);
			    break;
			}

			altpt->next->str = (unsigned char *) c;
			altpt->next->len = strlen(h) / 2;
		    } else {
			newalt->str = (unsigned char *) c;
			newalt->len = strlen(h) / 2;
		    }
		}

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
	    if(new->alt) {
		free(hex);
		ac_free_alt(new);
	    }
	    free(new);
	    return error;
	}
    }

    if((new->pattern = cli_hex2ui(new->alt ? hex : hexsig)) == NULL) {
	if(new->alt) {
	    free(hex);
	    ac_free_alt(new);
	}
	free(new);
	return CL_EMALFDB;
    }
    new->length = strlen(new->alt ? hex : hexsig) / 2;
    if(new->alt)
	free(hex);

    for(i = 0; i < root->ac_maxdepth && i < new->length; i++) {
	if(new->pattern[i] & CLI_MATCH_WILDCARD) {
	    wprefix = 1;
	    break;
	}
	if(zprefix && new->pattern[i])
	    zprefix = 0;
    }

    if(wprefix || zprefix) {
	pend = new->length - root->ac_mindepth + 1;
	for(i = 0; i < pend; i++) {
	    for(j = i; j < i + root->ac_maxdepth && j < new->length; j++) {
		if(new->pattern[j] & CLI_MATCH_WILDCARD) {
		    break;
		} else {
		    if(j - i + 1 >= plen) {
			plen = j - i + 1;
			ppos = i;
		    }
		}
		if(plen >= root->ac_maxdepth && (new->pattern[ppos] || new->pattern[ppos + 1]))
		    break;
	    }
	    if(plen >= root->ac_maxdepth && (new->pattern[ppos] || new->pattern[ppos + 1]))
		break;
	}

	if(plen < root->ac_mindepth) {
	    cli_errmsg("cli_ac_addsig: Can't find a static subpattern of length %u\n", root->ac_mindepth);
	    ac_free_alt(new);
	    free(new->pattern);
	    free(new);
	    return CL_EMALFDB;
	}

	new->prefix = new->pattern;
	new->prefix_length = ppos;
	new->pattern = &new->prefix[ppos];
	new->length -= ppos;

	for(i = 0; i < new->prefix_length; i++)
	    if((new->prefix[i] & CLI_MATCH_WILDCARD) == CLI_MATCH_ALTERNATIVE)
		new->alt_pattern++;
    }

    if(new->length > root->maxpatlen)
	root->maxpatlen = new->length;

    if((pt = strstr(virname, " (Clam)")))
	namelen = strlen(virname) - strlen(pt);
    else
	namelen = strlen(virname);

    if(!namelen) {
	cli_errmsg("cli_ac_addsig: No virus name\n");
	if(new->prefix)
	    free(new->prefix);
	else
	    free(new->pattern);
	ac_free_alt(new);
	free(new);
	return CL_EMALFDB;
    }

    if((new->virname = cli_calloc(namelen + 1, sizeof(char))) == NULL) {
	if(new->prefix)
	    free(new->prefix);
	else
	    free(new->pattern);
	ac_free_alt(new);
	free(new);
	return CL_EMEM;
    }
    strncpy(new->virname, virname, namelen);

    if(offset) {
	new->offset = cli_strdup(offset);
	if(!new->offset) {
	    if(new->prefix)
		free(new->prefix);
	    else
		free(new->pattern);
	    ac_free_alt(new);
	    free(new->virname);
	    free(new);
	    return CL_EMEM;
	}
    }

    if((ret = cli_ac_addpatt(root, new))) {
	if(new->prefix)
	    free(new->prefix);
	else
	    free(new->pattern);
	free(new->virname);
	ac_free_alt(new);
	if(new->offset)
	    free(new->offset);
	free(new);
	return ret;
    }

    return CL_SUCCESS;
}

void cli_ac_setdepth(uint8_t mindepth, uint8_t maxdepth)
{
    cli_ac_mindepth = mindepth;
    cli_ac_maxdepth = maxdepth;
}

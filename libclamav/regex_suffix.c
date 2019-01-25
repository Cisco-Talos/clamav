/*
 *  Parse a regular expression, and extract a static suffix.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "clamav.h"
#include "others.h"
#include "jsparse/textbuf.h"
#include "regex_suffix.h"
#define MODULE "regex_suffix: "


enum node_type {
	root=0,
	concat,
	alternate, /* | */
	optional,/* ?, * */
	leaf, /* a character */
	leaf_class /* character class */
	/* (x)+ is transformed into (x)*(x) */
};

struct node {
	enum node_type type; /* must be first field */
	struct node *parent;
	union {
		struct {
			struct node* left;
			struct node* right;
		} children;
		uint8_t*    leaf_class_bitmap;
		uint8_t     leaf_char;
	} u;
};

/* --- Prototypes --*/
static int build_suffixtree_descend(struct node *n, struct text_buffer *buf, suffix_callback cb, void *cbdata, struct regex_list *regex);
/* -----------------*/

static uint8_t dot_bitmap[32] = {
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
};

static struct node* make_node(enum node_type type, struct node *left, struct node *right)
{
	struct node *n;
	if(type == concat) {
		if(left == NULL)
			return right;
		if(right == NULL)
			return left;
	}
	n = cli_malloc(sizeof(*n));
	if(!n) {
        cli_errmsg("make_node: Unable to allocate memory for new node\n");
		return NULL;
    }
	n->type = type;
	n->parent = NULL;
	n->u.children.left = left;
	n->u.children.right = right;
	if(left)
		left->parent = n;
	if(right)
		right->parent = n;
	return n;
}

static struct node *dup_node(struct node *p)
{
	struct node *node_left, *node_right;
	struct node *d;

	if(!p)
		return NULL;
	d = cli_malloc(sizeof(*d));
	if(!d) {
        cli_errmsg("dup_node: Unable to allocate memory for duplicate node\n");
		return NULL;
    }
	d->type = p->type;
	d->parent = NULL;
	switch(p->type) {
		case leaf:
			d->u.leaf_char = p->u.leaf_char;
			break;
		case leaf_class:
			d->u.leaf_class_bitmap = cli_malloc(32);
			if(!d->u.leaf_class_bitmap) {
                cli_errmsg("make_node: Unable to allocate memory for leaf class\n");
				free(d);
				return NULL;
			}
			memcpy(d->u.leaf_class_bitmap, p->u.leaf_class_bitmap, 32);
			break;
		default:
			node_left = dup_node(p->u.children.left);
			node_right = dup_node(p->u.children.right);
			d->u.children.left = node_left;
			d->u.children.right = node_right;
			if(node_left)
				node_left->parent = d;
			if(node_right)
				node_right->parent = d;
			break;
	}
	return d;
}

static struct node *make_charclass(uint8_t *bitmap)
{
	struct node *v = cli_malloc(sizeof(*v));
	if(!v) {
        cli_errmsg("make_charclass: Unable to allocate memory for character class\n");
		return NULL;
    }
	v->type = leaf_class;
	v->parent = NULL;
	v->u.leaf_class_bitmap = bitmap;
	return v;
}

static struct node *make_leaf(char c)
{
	struct node *v = cli_malloc(sizeof(*v));
	if(!v)
		return NULL;
	v->type = leaf;
	v->parent = NULL;
	v->u.leaf_char = c;
	return v;
}

static void destroy_tree(struct node *n)
{
	if(!n)
		return;
	switch(n->type) {
		case concat:
		case alternate:
		case optional:
			destroy_tree(n->u.children.left);
			destroy_tree(n->u.children.right);
			break;
		case leaf_class:
			if(n->u.leaf_class_bitmap != dot_bitmap)
			  free(n->u.leaf_class_bitmap);
			break;
		case root:
		case leaf:
			break;
	}
	free(n);
}

static uint8_t* parse_char_class(const char *pat, size_t *pos)
{
	unsigned char range_start=0;
	int hasprev = 0;
	uint8_t* bitmap = cli_malloc(32);
	if(!bitmap) {
        cli_errmsg("parse_char_class: Unable to allocate memory for bitmap\n");
		return NULL;
    }
	if (pat[*pos]=='^') {
		memset(bitmap,0xFF,32);/*match chars not in brackets*/
		++*pos;
	}
	else
		memset(bitmap,0x00,32);
	do {
		/* literal ] can be first character, so test for it at the end of the loop, for example: []] */
		if (pat[*pos]=='-' && hasprev) {
			/* it is a range*/
			unsigned char range_end;
			unsigned int c;
			assert(range_start);
			++*pos;
			if (pat[*pos]=='[')
				if (pat[*pos+1]=='.') {
					/* collating sequence not handled */
					free(bitmap);
					/* we are parsing the regex for a
					 * filter, be conservative and
					 * tell the filter that anything could
					 * match here */
					while(pat[*pos] != ']') ++*pos;
					++*pos;
					while(pat[*pos] != ']') ++*pos;
					return dot_bitmap;
				}
				else
					range_end = pat[*pos];
			else
				range_end = pat[*pos];
			for(c=range_start+1;c<=range_end;c++)
				bitmap[c>>3] ^= 1<<(c&0x7);
			hasprev = 0;
		}
		else if (pat[*pos]=='[' && pat[*pos]==':') {
			/* char class */
			free(bitmap);
			while(pat[*pos] != ']') ++*pos;
			++*pos;
			while(pat[*pos] != ']') ++*pos;
			return dot_bitmap;
		} else {
			bitmap[pat[*pos]>>3] ^= 1<<(pat[*pos]&0x7);
			range_start = pat[*pos];
			++*pos;
			hasprev = 1;
		}
	} while(pat[*pos]!=']');
	return bitmap;
}

static struct node* parse_regex(const char *p, size_t *last)
{
	struct node *v = NULL;
	struct node *right;
	struct node *tmp;

	while(p[*last] != '$' && p[*last] != '\0') {
		switch(p[*last]) {
			case '|':
				++*last;
				right = parse_regex(p, last);
				v = make_node(alternate, v, right);
				if(!v)
					return NULL;
				break;
			case '*':
			case '?':
				v = make_node(optional, v, NULL);
				if(!v)
					return NULL;
				++*last;
				break;
			case '+':
				/* (x)* */
				tmp = make_node(optional, v, NULL);
				if(!tmp)
					return NULL;
				/* (x) */
				right = dup_node(v);
				if(!right)
					return NULL;
				/* (x)*(x) => (x)+ */
				v = make_node(concat, tmp, right);
				if(!v)
					return NULL;
				++*last;
				break;
			case '(':
				++*last;
				right = parse_regex(p, last);
				if(!right)
					return NULL;
				++*last;
				v = make_node(concat, v, right);
				break;
			case ')':
				return v;
			case '.':
				right = make_charclass(dot_bitmap);
				if(!right)
					return NULL;
				v = make_node(concat, v, right);
				if(!v)
					return NULL;
				++*last;
				break;
			case '[':
				++*last;
				right = make_charclass( parse_char_class(p, last) );
				if(!right)
					return NULL;
				v = make_node(concat, v, right);
				if(!v)
					return NULL;
				++*last;
				break;
			case '\\':
				/* next char is escaped, advance pointer
				 * and let fall-through handle it */
				++*last;
			default:
				right = make_leaf(p[*last]);
				v = make_node(concat, v, right);
				if(!v)
					return NULL;
				++*last;
				break;
		}
	}
	return v;
}

#define BITMAP_HASSET(b, i) (b[i>>3] & (1<<(i&7)))

static int build_suffixtree_ascend(struct node *n, struct text_buffer *buf, struct node *prev, suffix_callback cb, void *cbdata, struct regex_list *regex)
{
	size_t i, cnt;
	while(n) {
		struct node *q = n;
		switch(n->type) {
			case root:
				textbuffer_putc(buf, '\0');
				if(cb(cbdata, buf->data, buf->pos-1, regex) < 0)
					return CL_EMEM;
				return 0;
			case leaf:
				textbuffer_putc(buf, n->u.leaf_char);
				n = n->parent;
				break;
			case leaf_class:
				cnt = 0;
				for(i=0;i<255;i++)
					if (BITMAP_HASSET(n->u.leaf_class_bitmap, i))
						cnt++;
				if (cnt > 16) {
					textbuffer_putc(buf, '\0');
					if(cb(cbdata, buf->data, buf->pos-1, regex) < 0)
						return CL_EMEM;
					return 0;
				}
				/* handle small classes by expanding */
				for(i=0;i<255;i++) {
					if(BITMAP_HASSET(n->u.leaf_class_bitmap, i)) {
						size_t pos;
						pos = buf->pos;
						textbuffer_putc(buf, (char)i);
						if(build_suffixtree_ascend(n->parent, buf, n, cb, cbdata, regex) < 0)
							return CL_EMEM;
						buf->pos = pos;
					}
				}
				return 0;
			case concat:
				if(prev != n->u.children.left) {
					if(build_suffixtree_descend(n->u.children.left, buf, cb, cbdata, regex) < 0)
						return CL_EMEM;
					/* we're done here, descend will call
					 * ascend if needed */
					return 0;
				} else {
					n = n->parent;
				}
				break;
			case alternate:
				n = n->parent;
				break;
			case optional:
				textbuffer_putc(buf, '\0');
				if(cb(cbdata, buf->data, buf->pos-1, regex) < 0)
					return CL_EMEM;
				return 0;
		}
		prev = q;
	}
	return 0;
}

static int build_suffixtree_descend(struct node *n, struct text_buffer *buf, suffix_callback cb, void *cbdata, struct regex_list *regex)
{
	size_t pos;
	while(n && n->type == concat) {
		n = n->u.children.right;
	}
	if(!n)
		return 0;
	/* find out end of the regular expression,
	 * if it ends with a static pattern */
	switch(n->type) {
		case alternate:
			/* save pos as restart point */
			pos = buf->pos;
			if(build_suffixtree_descend(n->u.children.left, buf, cb, cbdata, regex) < 0)
				return CL_EMEM;
			buf->pos = pos;
			if(build_suffixtree_descend(n->u.children.right, buf, cb, cbdata, regex) < 0)
				return CL_EMEM;
			buf->pos = pos;
			break;
		case optional:
			textbuffer_putc(buf, '\0');
			if(cb(cbdata, buf->data, buf->pos-1, regex) < 0)
				return CL_EMEM;
			return 0;
		case leaf:
		case leaf_class:
			if(build_suffixtree_ascend(n, buf, NULL, cb, cbdata, regex) < 0)
			        return CL_EMEM;
			return 0;
		default:
			break;
	}
	return 0;
}

int cli_regex2suffix(const char *pattern, regex_t *preg, suffix_callback cb, void *cbdata)
{
	struct regex_list regex;
	struct text_buffer buf;
	struct node root_node;
	struct node *n;
	size_t last = 0;
	int rc;

	assert(pattern);

	regex.preg = preg;
	rc = cli_regcomp(regex.preg, pattern, REG_EXTENDED);
	if(rc) {
		size_t buflen = cli_regerror(rc, regex.preg, NULL, 0);
		char *errbuf = cli_malloc(buflen);
		if(errbuf) {
			cli_regerror(rc, regex.preg, errbuf, buflen);
			cli_errmsg(MODULE "Error compiling regular expression %s: %s\n", pattern, errbuf);
			free(errbuf);
		} else {
			cli_errmsg(MODULE "Error compiling regular expression: %s\n", pattern);
		}
		return rc;
	}
	regex.nxt = NULL;
	regex.pattern = cli_strdup(pattern);

	n = parse_regex(pattern, &last);
	if(!n)
		return REG_ESPACE;
	memset(&buf, 0, sizeof(buf));
	memset(&root_node, 0, sizeof(buf));
	n->parent = &root_node;

	rc = build_suffixtree_descend(n, &buf, cb, cbdata, &regex);
	free(regex.pattern);
	free(buf.data);
	destroy_tree(n);
	return rc;
}



/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Nigel Horne
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
 * $Log: text.c,v $
 * Revision 1.25  2007/02/12 20:46:09  njh
 * Various tidy
 *
 * Revision 1.24  2006/09/13 20:53:50  njh
 * Added debug
 *
 * Revision 1.23  2006/07/14 12:13:08  njh
 * Typo
 *
 * Revision 1.22  2006/07/01 21:03:36  njh
 * Better use of destroy mode
 *
 * Revision 1.21  2006/07/01 16:17:35  njh
 * Added destroy flag
 *
 * Revision 1.20  2006/07/01 03:47:50  njh
 * Don't loop if binhex runs out of memory
 *
 * Revision 1.19  2006/05/19 11:02:12  njh
 * Just include mbox.h
 *
 * Revision 1.18  2006/05/04 10:37:03  nigelhorne
 * Speed up scanning of clean files
 *
 * Revision 1.17  2006/05/03 09:36:40  nigelhorne
 * Pass full ctx into the mbox code
 *
 * Revision 1.16  2006/04/09 19:59:28  kojm
 * update GPL headers with new address for FSF
 *
 * Revision 1.15  2005/03/10 08:50:49  nigelhorne
 * Tidy
 *
 * Revision 1.14  2005/01/19 05:31:55  nigelhorne
 * Added textIterate
 *
 * Revision 1.13  2004/12/08 19:03:41  nigelhorne
 * Fix compilation error on Solaris
 *
 * Revision 1.12  2004/12/04 16:03:55  nigelhorne
 * Text/plain now handled as no encoding
 *
 * Revision 1.11  2004/11/27 21:54:26  nigelhorne
 * Tidy
 *
 * Revision 1.10  2004/08/22 10:34:24  nigelhorne
 * Use fileblob
 *
 * Revision 1.9  2004/08/21 11:57:57  nigelhorne
 * Use line.[ch]
 *
 * Revision 1.8  2004/07/20 14:35:29  nigelhorne
 * Some MYDOOM.I were getting through
 *
 * Revision 1.7  2004/06/22 04:08:02  nigelhorne
 * Optimise empty lines
 *
 * Revision 1.6  2004/05/05 09:37:52  nigelhorne
 * Removed textClean - not needed in clamAV
 *
 * Revision 1.5  2004/03/25 22:40:46  nigelhorne
 * Removed even more calls to realloc and some duplicated code
 *
 * Revision 1.4  2004/02/26 13:26:34  nigelhorne
 * Handle spaces at the end of uuencoded lines
 *
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdlib.h>
#ifdef	C_DARWIN
#include <sys/types.h>
#include <sys/malloc.h>
#else
#ifdef HAVE_MALLOC_H /* tk: FreeBSD-CURRENT doesn't support malloc.h */
#ifndef	C_BSD	/* BSD now uses stdlib.h */
#include <malloc.h>
#endif
#endif
#endif
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <stdio.h>

#include "clamav.h"
#include "others.h"

#include "mbox.h"

static	text	*textCopy(const text *t_head);
static	text	*textAdd(text *t_head, const text *t);
static	void	addToFileblob(const line_t *line, void *arg);
static	void	getLength(const line_t *line, void *arg);
static	void	addToBlob(const line_t *line, void *arg);
static	void	*textIterate(text *t_text, void (*cb)(const line_t *line, void *arg), void *arg, int destroy);

void
textDestroy(text *t_head)
{
	while(t_head) {
		text *t_next = t_head->t_next;
		if(t_head->t_line) {
			lineUnlink(t_head->t_line);
			t_head->t_line = NULL;
		}
		free(t_head);
		t_head = t_next;
	}
}

/* Clone the current object */
static text *
textCopy(const text *t_head)
{
	text *first = NULL, *last = NULL;

	while(t_head) {
		if(first == NULL)
			last = first = (text *)cli_malloc(sizeof(text));
		else {
			last->t_next = (text *)cli_malloc(sizeof(text));
			last = last->t_next;
		}

		if(last == NULL) {
			cli_errmsg("textCopy: Unable to allocate memory to clone object\n");
			if(first)
				textDestroy(first);
			return NULL;
		}

		last->t_next = NULL;

		if(t_head->t_line)
			last->t_line = lineLink(t_head->t_line);
		else
			last->t_line = NULL;

		t_head = t_head->t_next;
	}

	if(first)
		last->t_next = NULL;

	return first;
}

/* Add a copy of a text to the end of the current object */
static text *
textAdd(text *t_head, const text *t)
{
	text *ret;
	int count;

	if(t_head == NULL) {
		if(t == NULL) {
			cli_errmsg("textAdd fails sanity check\n");
			return NULL;
		}
		return textCopy(t);
	}

	if(t == NULL)
		return t_head;

	ret = t_head;

	count = 0;
	while(t_head->t_next) {
		count++;
		t_head = t_head->t_next;
	}

	cli_dbgmsg("textAdd: count = %d\n", count);

	while(t) {
		t_head->t_next = (text *)cli_malloc(sizeof(text));
		t_head = t_head->t_next;

		assert(t_head != NULL);

		if(t->t_line)
			t_head->t_line = lineLink(t->t_line);
		else
			t_head->t_line = NULL;

		t = t->t_next;
	}

	t_head->t_next = NULL;

	return ret;
}

/*
 * Add a message's content to the end of the current object
 */
text *
textAddMessage(text *aText, message *aMessage)
{
	assert(aMessage != NULL);

	if(messageGetEncoding(aMessage) == NOENCODING)
		return textAdd(aText, messageGetBody(aMessage));
	else {
		text *anotherText = messageToText(aMessage);

		if(aText) {
			text *newHead = textMove(aText, anotherText);
			free(anotherText);
			return newHead;
		}
		return anotherText;
	}
}

/*
 * Put the contents of the given text at the end of the current object.
 * The given text emptied; it can be used again if needed, though be warned that
 * it will have an empty line at the start.
 */
text *
textMove(text *t_head, text *t)
{
	text *ret;

	if(t_head == NULL) {
		if(t == NULL) {
			cli_errmsg("textMove fails sanity check\n");
			return NULL;
		}
		t_head = (text *)cli_malloc(sizeof(text));
		if(t_head == NULL) {
            cli_errmsg("textMove: Unable to allocate memory for head\n");
			return NULL;
        }
		t_head->t_line = t->t_line;
		t_head->t_next = t->t_next;
		t->t_line = NULL;
		t->t_next = NULL;
		return t_head;
	}

	if(t == NULL)
		return t_head;

	ret = t_head;

	while(t_head->t_next)
		t_head = t_head->t_next;

	/*
	 * Move the first line manually so that the caller is left clean but
	 * empty, the rest is moved by a simple pointer reassignment
	 */
	t_head->t_next = (text *)cli_malloc(sizeof(text));
	if(t_head->t_next == NULL) {
        cli_errmsg("textMove: Unable to allocate memory for head->next\n");
		return NULL;
    }
	t_head = t_head->t_next;

	assert(t_head != NULL);

	if(t->t_line) {
		t_head->t_line = t->t_line;
		t->t_line = NULL;
	} else
		t_head->t_line = NULL;

	t_head->t_next = t->t_next;
	t->t_next = NULL;

	return ret;
}

/*
 * Transfer the contents of the text into a blob
 * The caller must free the returned blob if b is NULL
 */
blob *
textToBlob(text *t, blob *b, int destroy)
{
	size_t s;
	blob *bin;

	if(t == NULL)
		return NULL;

	s = 0;

	(void)textIterate(t, getLength, &s, 0);

	if(s == 0)
		return b;

	/*
	 * copy b. If b is NULL and an error occurs we know we need to free
	 *	before returning
	 */
	bin = b;
	if(b == NULL) {
		b = blobCreate();

		if(b == NULL)
			return NULL;
	}

	if(blobGrow(b, s) != CL_SUCCESS) {
		cli_warnmsg("Couldn't grow the blob: we may be low on memory\n");
#if	0
		if(!destroy) {
			if(bin == NULL)
				blobDestroy(b);
			return NULL;
		}
		/*
		 * We may be able to recover enough memory as we destroy to
		 * create the blob
		 */
#else
		if(bin == NULL)
			blobDestroy(b);
		return NULL;
#endif
	}

	(void)textIterate(t, addToBlob, b, destroy);

	if(destroy && t->t_next) {
		textDestroy(t->t_next);
		t->t_next = NULL;
	}

	blobClose(b);

	return b;
}

fileblob *
textToFileblob(text *t, fileblob *fb, int destroy)
{
	assert(fb != NULL);
	assert(t != NULL);

	if(fb == NULL) {
		cli_dbgmsg("textToFileBlob, destroy = %d\n", destroy);
		fb = fileblobCreate();

		if(fb == NULL)
			return NULL;
	} else {
		cli_dbgmsg("textToFileBlob to %s, destroy = %d\n",
			fileblobGetFilename(fb), destroy);

		fb->ctx = NULL;	/* no need to scan */
	}

	fb = textIterate(t, addToFileblob, fb, destroy);
	if(destroy && t->t_next) {
		textDestroy(t->t_next);
		t->t_next = NULL;
	}
	return fb;
}

static void
getLength(const line_t *line, void *arg)
{
	size_t *length = (size_t *)arg;

	if(line)
		*length += strlen(lineGetData(line)) + 1;
	else
		(*length)++;
}

static void
addToBlob(const line_t *line, void *arg)
{
	blob *b = (blob *)arg;

	if(line) {
		const char *l = lineGetData(line);

		blobAddData(b, (const unsigned char *)l, strlen(l));
	}
	blobAddData(b, (const unsigned char *)"\n", 1);
}

static void
addToFileblob(const line_t *line, void *arg)
{
	fileblob *fb = (fileblob *)arg;

	if(line) {
		const char *l = lineGetData(line);

		fileblobAddData(fb, (const unsigned char *)l, strlen(l));
	}
	fileblobAddData(fb, (const unsigned char *)"\n", 1);
}

static void *
textIterate(text *t_text, void (*cb)(const line_t *item, void *arg), void *arg, int destroy)
{
	/*
	 * Have two loops rather than one, so that we're not checking the
	 * value of "destroy" lots and lots of times
	 */
#if	0
	while(t_text) {
		(*cb)(t_text->t_line, arg);

		if(destroy && t_text->t_line) {
			lineUnlink(t_text->t_line);
			t_text->t_line = NULL;
		}

		t_text = t_text->t_next;
	}
#else
	if(destroy)
		while(t_text) {
			(*cb)(t_text->t_line, arg);

			if(t_text->t_line) {
				lineUnlink(t_text->t_line);
				t_text->t_line = NULL;
			}

			t_text = t_text->t_next;
		}
	else
		while(t_text) {
			(*cb)(t_text->t_line, arg);

			t_text = t_text->t_next;
		}
#endif
	return arg;
}

/*
 *  Copyright (C) 2002 Nigel Horne <njh@bandsman.co.uk>
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
 *
 * $Log: text.c,v $
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

static	char	const	rcsid[] = "$Id: text.c,v 1.15 2005/03/10 08:50:49 nigelhorne Exp $";

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifndef	CL_DEBUG
#define	NDEBUG	/* map CLAMAV debug onto standard */
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

#include "line.h"
#include "mbox.h"
#include "blob.h"
#include "text.h"
#include "others.h"

static	text	*textCopy(const text *t_head);
static	void	addToFileblob(const line_t *line, void *arg);
static	void	getLength(const line_t *line, void *arg);
static	void	addToBlob(const line_t *line, void *arg);
static	void	*textIterate(const text *t_text, void (*cb)(const line_t *line, void *arg), void *arg);

void
textDestroy(text *t_head)
{
	while(t_head) {
		text *t_next = t_head->t_next;
		if(t_head->t_line)
			(void)lineUnlink(t_head->t_line);
		free(t_head);
		t_head = t_next;
	}
}

/*
 * Remove trailing spaces from the lines and trailing blank lines
 * This could be used to remove trailing blank lines, empty lines etc.,
 *	but it probably isn't worth the time taken given that it won't reclaim
 *	much memory
 */
text *
textClean(text *t_head)
{
	return t_head;
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
			if(first)
				textDestroy(first);
			return NULL;
		}

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
text *
textAdd(text *t_head, const text *t)
{
	text *ret;
	int count;

	if(t_head == NULL)
		return textCopy(t);

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
			aText = textAdd(aText, anotherText);
			textDestroy(anotherText);
			return aText;
		}
		return anotherText;
	}
}

/*
 * Transfer the contents of the text into a blob
 * The caller must free the returned blob if b is NULL
 */
blob *
textToBlob(const text *t, blob *b)
{
	size_t s;

	if(t == NULL)
		return NULL;

	s = 0;

	(void)textIterate(t, getLength, &s);

	if(s == 0)
		return b;

	if(b == NULL) {
		b = blobCreate();

		if(b == NULL)
			return NULL;
	}

	blobGrow(b, s);

	(void)textIterate(t, addToBlob, b);

	blobClose(b);

	return b;
}

fileblob *
textToFileblob(const text *t, fileblob *fb)
{
	assert(fb != NULL);
	assert(t != NULL);

	if(fb == NULL) {
		fb = fileblobCreate();

		if(fb == NULL)
			return NULL;
	}

	return textIterate(t, addToFileblob, fb);
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

		blobAddData(b, (unsigned char *)l, strlen(l));
	}
	blobAddData(b, (unsigned char *)"\n", 1);
}

static void
addToFileblob(const line_t *line, void *arg)
{
	fileblob *fb = (fileblob *)arg;

	if(line) {
		const char *l = lineGetData(line);

		fileblobAddData(fb, (unsigned char *)l, strlen(l));
	}
	fileblobAddData(fb, (unsigned char *)"\n", 1);
}

static void *
textIterate(const text *t_text, void (*cb)(const line_t *item, void *arg), void *arg)
{
	while(t_text) {
		(*cb)(t_text->t_line, arg);
		t_text = t_text->t_next;
	}
	return arg;
}

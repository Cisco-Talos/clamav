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
 */

#include <stdlib.h>
#if	C_DARWIN
#include <sys/types.h>
#include <sys/malloc.h>
#else
#ifdef HAVE_MALLOC_H /* tk: FreeBSD-CURRENT doesn't support malloc.h */
#include <malloc.h>
#endif
#endif
#include <string.h>
#include <ctype.h>
#include <assert.h>

#include "mbox.h"
#include "blob.h"
#include "text.h"
#include "others.h"

void
textDestroy(text *t_head)
{
	text *t_next;

	while(t_head) {
		t_next = t_head->t_next;
		free(t_head->t_text);
		free(t_head);
		t_head = t_next;
	}
}

/*
 * Remove trailing spaces from the lines and trailing blank lines
 */
text *
textClean(text *t_head)
{
	text *t_lastnonempty = NULL, *t_ret;

	while(t_head) {
		char *line = t_head->t_text;
		const size_t len = strlen(line);

		if(len > 0) {
			int last = len;

			while((--last >= 0) && isspace(line[last]))
				;

			if(++last > 0) {
				t_lastnonempty = t_head;
				if(last < len) {
					line[last] = '\0';
					t_head->t_text = realloc(line, ++last);
				}
			} else {
				t_head->t_text = realloc(line, 1);
				t_head->t_text[0] = '\0';
			}
		}
		t_head = t_head->t_next;
	}

	if(t_lastnonempty == NULL)
		return(NULL);	/* empty message I presume */

	t_ret = t_lastnonempty;
	t_lastnonempty = t_lastnonempty->t_next;

	while(t_lastnonempty) {
		text *t_next = t_lastnonempty->t_next;

		assert(strlen(t_lastnonempty->t_text) == 0);

		free(t_lastnonempty->t_text);
		free(t_lastnonempty);

		t_lastnonempty = t_next;
	}

	t_ret->t_next = NULL;

	return t_ret;
}

/* Clone the current object */
text *
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

		assert(last != NULL);

		last->t_text = strdup(t_head->t_text);

		assert(last->t_text != NULL);

		t_head = t_head->t_next;
	}

	if(first)
		last->t_next = NULL;

	return first;
}

/* Add a message to the end of the current object */
text *
textAdd(text *t_head, const text *t)
{
	text *ret;

	if(t_head == NULL)
		return textCopy(t);

	if(t == NULL)
		return t_head;

	ret = t_head;

	while(t_head->t_next)
		t_head = t_head->t_next;

	while(t) {
		t_head->t_next = (text *)cli_malloc(sizeof(text));
		t_head = t_head->t_next;

		assert(t_head != NULL);

		t_head->t_text = strdup(t->t_text);

		assert(t_head->t_text != NULL);

		t = t->t_next;
	}

	t_head->t_next = NULL;

	return ret;
}

/*
 * Add a message's content to the end of the current object
 */
text *
textAddMessage(text *aText, const message *aMessage)
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

/*
 *  Copyright (C) 2004 Trog <trog@clamav.net>
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
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "others.h"

#define FALSE (0)
#define TRUE (1)

/* Normalize an HTML buffer using the following rules:
	o Remove multiple contiguous spaces
	o Remove spaces around '<' and '>' in tags
	o Remove spaces around '=' in tags
	o Replace single quote with double quote in tags
	o Convert to lowercase
	o Convert all white space to a space character
*/

unsigned char *html_normalize(unsigned char *in_buff, off_t in_size)
{
	unsigned char *out_buff;
	off_t out_size=0, i;
	int had_space=FALSE, tag_depth=0, in_quote=FALSE;

	out_buff = (unsigned char *) cli_malloc(in_size+1);
	if (!out_buff) {
		cli_dbgmsg("html_normalize(): malloc failed\n");
		return NULL;
	}

	for (i=0 ; i < in_size ; i++) {
		if (in_buff[i] == '<') {
			out_buff[out_size++] = '<';
			tag_depth++;
			if (tag_depth == 1) {
				had_space=TRUE; /* consume spaces */
			}
		} else if ((in_buff[i] == '=') && (tag_depth == 1)) {
			/* Remove preceeding spaces */
			while ((out_size > 0) &&
				(out_buff[out_size-1] == ' ')) {
				out_size--;
			}
			out_buff[out_size++] = '=';
			had_space=TRUE;
		} else if (isspace(in_buff[i])) {
			if (!had_space) {
				out_buff[out_size++] = ' ';
				had_space=TRUE;
			}
		} else if (in_buff[i] == '>') {
			/* Remove preceeding spaces */
			if (tag_depth == 1) {
				while ((out_size > 0) &&
					(out_buff[out_size-1] == ' ')) {
					out_size--;
				}
			}
			out_buff[out_size++] = '>';
			tag_depth--;	
		} else if ((in_buff[i] == '\'') && (tag_depth==1)) {
			/* Convert single quotes to double quotes */
			if (in_quote || out_buff[out_size-1] == '=') {
				out_buff[out_size++] = '\"';
				in_quote = !in_quote;
			} else {
				out_buff[out_size++] = '\'';
			}
		} else {
			out_buff[out_size++] = tolower(in_buff[i]);
			had_space=FALSE;
		}
	}
	out_buff[out_size] = '\0';
	return out_buff;
}

/* Remove HTML style comments from buffer */
unsigned char *remove_html_comments(unsigned char *line)
{
	unsigned char *newline, *newcurrent;
	int in_comment=FALSE;
	
	if (!line) {
		return NULL;
	}
	
	newcurrent = newline = (unsigned char *) cli_malloc(strlen(line) + 1);
	if (!newline) {
		return NULL;
	}
	
	while(line) {
		if (!(in_comment)) {
			while (*line && *line != '<') {
				*newcurrent = *line;
				newcurrent++;
				line++;
			}
			if (! *line) {
				break;
			}
			if (!line[1]) {
				*newcurrent = *line;
				newcurrent++;
				line++;
				continue;
			}
			if (line[1] == '!') {
				in_comment = TRUE;
				line += 1;
			} else {
				*newcurrent = *line;
				newcurrent++;
				line++;
			}
		} else {
			while (*line && *line != '>') {
				line++;
			}
			if (! *line) {
				break;
			}
			in_comment = FALSE;
			line++;
		}
	}
	*newcurrent = '\0';
	return newline;
}

/* Decode an HTML escape character into it's character value */
unsigned int decode_html_char_ref(unsigned char *cref,
                                    unsigned char *dest)
{

	unsigned int hex=FALSE, value=0, count=0;
	
	if (!cref[0] || !cref[1]) {
		return 0;
	}
	
	if (((*cref == 'x') || (*cref == 'X')) && isxdigit(cref[1])) {
		hex=TRUE;
		cref++;
		count++;
	}
	
	while (isdigit(*cref) || (hex && isxdigit(*cref))) {
		if (hex) {
			value *= 16;
		} else {
			value *= 10;
		}
		if (isdigit(*cref)) {
			value += (*cref - '0');
		} else {
			value += (tolower(*cref) - 'a' + 10);
		}
		cref++;
		count++;
	}
	if (*cref == ';') {
		cref++;
		count++;
	}
	
	*dest = value;
	
	return count;
}

/* Remove HTML character escape sequences from buffer */
unsigned char *remove_html_char_ref(unsigned char *line)
{
	unsigned char *newline, *newcurrent;
	unsigned char *linepos, count;
	
	if (!line) {
		return NULL;
	}
	
	newcurrent = newline = (unsigned char *) cli_malloc(strlen(line) + 1);
	if (!newline) {
		return NULL;
	}
	while (line) {
		linepos = strchr(line, '&');
		if (!linepos) {
			strcpy(newcurrent, line);
			return newline;
		}
		strncpy(newcurrent, line, linepos-line);
		newcurrent += linepos-line;

		if (!linepos[1] || !linepos[2]) {
			*newcurrent = '&';
			newcurrent++;
			line = linepos+1;
			continue;
		}
		switch (linepos[1]) {
		case '#':
			count = decode_html_char_ref(linepos+2,
					newcurrent);
			if (count > 0) {
				newcurrent++;
				linepos += count+2;
			} else {
				*newcurrent = '&';
				newcurrent++;
				linepos++;
			}
			break;
		/* TODO: character entities, &amp; etc. */
		default:
			*newcurrent = '&';
			newcurrent++;
			linepos++;
		}
		line = linepos;
	}
	*newcurrent = '\0';
	return newline;
}

int char2hex(unsigned char c)
{
	if ((c-'0') <= 9) {
		return (c-'0');
	} else if ((c-'A') <= 5) {
		return (c-'A'+10);
	}
	return (c-'a'+10);
}

char *quoted_decode(unsigned char *line, off_t in_size)
{
	unsigned char *newline, *newcurrent, *line_end;
	
	newcurrent = newline = (unsigned char *) cli_malloc(in_size + 1);
	if (!newline) {
		return NULL;
	}
	
	line_end = line+in_size;
	while (line <= line_end) {
		while ((line < line_end) && *line != '=') {
			*newcurrent = *line;
			line++;
			newcurrent++;
		}
		if ((line < line_end) && isspace(line[1])) {
			line++;
			while ((line < line_end) && isspace(*line)) {
				line++;
			}
			continue;
		}
		if ((line+2) <= line_end) {
			if (isxdigit(line[1]) && isxdigit(line[2])) {
				*newcurrent = 	(char2hex(line[1]) * 16) +
						char2hex(line[2]);
				newcurrent++;
				line += 3;
				continue;
			}
		}
		line++;	
	}
	*newcurrent = '\0';
	return newline;
}

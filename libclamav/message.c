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

#ifndef	CL_DEBUG
/*#define	NDEBUG	/* map CLAMAV debug onto standard */
#endif

#ifdef CL_THREAD_SAFE
#define	_REENTRANT	/* for Solaris 2.8 */
#endif

#if	C_DARWIN
#include <sys/types.h>
#include <sys/malloc.h>
#else
#ifdef HAVE_MALLOC_H /* tk: FreeBSD-CURRENT doesn't support malloc.h */
#include <malloc.h>
#endif
#endif
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <assert.h>
#include <ctype.h>
#include <stdio.h>

#include "mbox.h"
#include "blob.h"
#include "text.h"
#include "strrcpy.h"
#include "others.h"

#if	defined(NO_STRTOK_R) || !defined(CL_THREAD_SAFE)
#undef strtok_r
#undef __strtok_r
#define strtok_r(a,b,c)	strtok(a,b)
#endif

/* required for AIX and Tru64 */
#ifdef TRUE
#undef TRUE
#endif
#ifdef FALSE
#undef FALSE
#endif

typedef enum    { FALSE = 0, TRUE = 1 } bool;

static	const	text	*uuencodeBegin(const message *m);
static	unsigned char	*decodeLine(const message *m, const char *line, unsigned char *ptr);
static unsigned char *decode(const char *in, unsigned char *out, unsigned char (*decoder)(char), bool isFast);
static	unsigned	char	hex(char c);
static	unsigned	char	base64(char c);
static	unsigned	char	uudecode(char c);
static	const	char	*messageGetArgument(const message *m, int arg);

/*
 * These maps are ordered in decreasing likelyhood of their appearance
 * in an e-mail
 */
static	const	struct	encoding_map {
	const	char	*string;
	encoding_type	type;
} encoding_map[] = {
	{	"7bit",			NOENCODING	},
	{	"quoted-printable",	QUOTEDPRINTABLE	},	/* rfc1522 */
	{	"base64",		BASE64		},
	{	"8bit",			EIGHTBIT	},
	{	"x-uuencode",		UUENCODE	},
	{	"binary",		BINARY		},
	{	NULL,			0		}
};

static	struct	mime_map {
	const	char	*string;
	mime_type	type;
} mime_map[] = {
	{	"text",			TEXT		},
	{	"multipart",		MULTIPART	},
	{	"application",		APPLICATION	},
	{	"audio",		AUDIO		},
	{	"image",		IMAGE		},
	{	"message",		MESSAGE		},
	{	"video",		VIDEO		},
	{	NULL,			0		}
};

message *
messageCreate(void)
{
	message *m = (message *)cli_calloc(1, sizeof(message));

	m->mimeType = NOMIME;

	return m;
}

void
messageDestroy(message *m)
{
	messageReset(m);

	free(m);
}

void
messageReset(message *m)
{
	int i;

	assert(m != NULL);

	if(m->mimeSubtype)
		free(m->mimeSubtype);

	if(m->mimeDispositionType)
		free(m->mimeDispositionType);

	if(m->mimeArguments) {
		for(i = 0; i < m->numberOfArguments; i++)
			free(m->mimeArguments[i]);
		free(m->mimeArguments);
	}

	if(m->body_first)
		textDestroy(m->body_first);

	memset(m, '\0', sizeof(message));
	m->mimeType = NOMIME;
}

void
messageSetMimeType(message *mess, const char *type)
{
	const struct mime_map *m;

	assert(mess != NULL);
	assert(type != NULL);

	mess->mimeType = NOMIME;

	cli_dbgmsg("messageSetMimeType: '%s'\n", type);

	/* Ignore leading spaces */
	while(isspace(*type))
		if(*type++ == '\0')
			return;

	for(m = mime_map; m->string; m++)
		if(strcasecmp(type, m->string) == 0) {
			mess->mimeType = m->type;
			break;
		}

	if(mess->mimeType == NOMIME) {
		if(strncasecmp(type, "x-", 2) == 0)
			mess->mimeType = MEXTENSION;
		else {
			/*
			 * Based on a suggestion by James Stevens
			 *	<James@kyzo.com>
			 * Force scanning of strange messages
			 */
			cli_warnmsg("Unknown MIME type: `%s' - set to Application\n", type);
			mess->mimeType = APPLICATION;
		}
	}
}

mime_type
messageGetMimeType(const message *m)
{
	return(m->mimeType);
}

void
messageSetMimeSubtype(message *m, const char *subtype)
{
	assert(m != NULL);
	assert(subtype != NULL);

	if(m->mimeSubtype)
		free(m->mimeSubtype);

	m->mimeSubtype = strdup(subtype);
}

const char *
messageGetMimeSubtype(const message *m)
{
	return((m->mimeSubtype) ? m->mimeSubtype : "");
}

void
messageSetDispositionType(message *m, const char *disptype)
{
	assert(m != NULL);
	assert(disptype != NULL);

	m->mimeDispositionType = strdup(disptype);
}

const char *
messageGetDispositionType(const message *m)
{
	return((m->mimeDispositionType) ? m->mimeDispositionType : "");
}

/*
 * TODO:
 *	Arguments are held on a per message basis, they should be held on
 * a per section basis. Otherwise what happens if two sections have two
 * different values for charset? Probably doesn't matter for the use this
 * code will be given, but will need fixing if this code is used elsewhere
 */
void
messageAddArgument(message *m, const char *arg)
{
	int offset;

	assert(m != NULL);

	if(arg == NULL)
		return;	/* Note: this is not an error condition */

	while(isspace(*arg))
		arg++;

	if(*arg == '\0')
		/* Empty argument? Probably a broken mail client... */
		return;

	cli_dbgmsg("Add argument '%s'\n", arg);

	for(offset = 0; offset < m->numberOfArguments; offset++)
		if(m->mimeArguments[offset] == NULL)
			break;
		else if(strcasecmp(arg, m->mimeArguments[offset]) == 0)
			return;	/* already in there */

	if(offset == m->numberOfArguments) {
		m->numberOfArguments++;
		m->mimeArguments = (char **)realloc(m->mimeArguments, m->numberOfArguments * sizeof(char *));
	}

	m->mimeArguments[offset] = strdup(arg);
}

/*
 * Add in all the arguments.
 * Cope with:
 *	name="foo bar.doc"
 *	charset=foo name=bar
 */
void
messageAddArguments(message *m, const char *s)
{
	const char *string = s;

	cli_dbgmsg("Add arguments '%s'\n", string);

	assert(string != NULL);

	while(*string) {
		const char *key, *cptr;
		char *data, *field;

		if(isspace(*string) || (*string == ';')) {
			string++;
			continue;
		}

		key = string;
		data = strchr(string, '=');

		/*
		 * Some spam breaks RFC1521 by using ':' instead of '='
		 * e.g.:
		 *	Content-Type: text/html; charset:ISO-8859-1
		 * should be:
		 *	Content-type: text/html; charset=ISO-8859-1
		 *
		 * We give up with lines that are completely broken because
		 * we don't have ESP and don't know what was meant to be there.
		 * It's unlikely to really be a problem.
		 */
		if(data == NULL)
			data = strchr(string, ':');

		if(data == NULL) {
			/*
			 * Completely broken, give up
			 */
			cli_warnmsg("Can't parse non RFC1521 header \"%s\"\n",
				s);
			return;
		}

		string = data;

		string++;

		/*
		 * Handle white space to the right of the equals sign
		 */
		while(isspace(*string) && (*string != '\0'))
			string++;

		cptr = string++;

		if(*cptr == '"') {
			char *ptr;

			/*
			 * The field is in quotes, so look for the
			 * closing quotes
			 */
			key = strdup(key);
			ptr = strchr(key, '=');
			if(ptr == NULL)
				ptr = strchr(key, ':');
			*ptr = '\0';

			cptr++;

			string = strchr(cptr, '"');
			if((string == NULL) || (strlen(key) == 0)) {
				cli_warnmsg("Can't parse header \"%s\"\n", s);
				free((char *)key);
				return;
			}

			string++;

			data = strdup(cptr);

			ptr = strchr(data, '"');
			if(ptr == NULL) {
				/*
				 * Weird e-mail header such as:
				 * Content-Type: application/octet-stream; name="
				 * "
				 * Content-Transfer-Encoding: base64
				 * Content-Disposition: attachment; filename="
				 * "
				 *
				 * TODO: the file should still be saved and
				 * virus checked
				 */
				cli_warnmsg("Can't parse header \"%s\"\n", s);
				free(data);
				free((char *)key);
				return;
			}

			*ptr = '\0';

			field = cli_malloc(strlen(key) + strlen(data) + 2);
			sprintf(field, "%s=%s", key, data);

			free((char *)key);
			free(data);
		} else {
			size_t len;
			/*
			 * The field is not in quotes, so look for the closing
			 * white space
			 */
			while((*string != '\0') && !isspace(*string))
				string++;

			assert(*cptr != '\0');

			len = (size_t)string - (size_t)key + 1;
			field = cli_malloc(len);

			memcpy(field, key, len - 1);
			field[len - 1] = '\0';
		}
		messageAddArgument(m, field);
		free(field);
	}
}

static const char *
messageGetArgument(const message *m, int arg)
{
	assert(m != NULL);
	assert(arg >= 0);
	assert(arg < m->numberOfArguments);

	return((m->mimeArguments[arg]) ? m->mimeArguments[arg] : "");
}

/*
 * Find a MIME variable from the header and return a COPY to the value of that
 * variable. The caller must free the copy
 */
const char *
messageFindArgument(const message *m, const char *variable)
{
	int i;

	assert(m != NULL);
	assert(variable != NULL);

	for(i = 0; i < m->numberOfArguments; i++) {
		const char *ptr;
		size_t len;

		ptr = messageGetArgument(m, i);
		if((ptr == NULL) || (*ptr == '\0'))
			return(NULL);
		len = strlen(variable);
#ifdef	CL_DEBUG
		cli_dbgmsg("messageFindArgument: compare %d bytes of %s with %s\n",
			len, variable, ptr);
#endif
		if(strncasecmp(ptr, variable, len) == 0) {
			ptr = &ptr[len];
			while(isspace(*ptr))
				ptr++;
			if(*ptr != '=') {
				cli_warnmsg("messageFindArgument: no '=' sign found in MIME header\n");
				return NULL;
			}
			if((*++ptr == '"') && (strchr(&ptr[1], '"') != NULL)) {
				/* Remove any quote characters */
				char *ret = strdup(++ptr);

				ret[strlen(ret) - 1] = '\0';
				return(ret);
			}
			return(strdup(ptr));
		}
	}
	return(NULL);
}

void
messageSetEncoding(message *m, const char *enctype)
{
	const struct encoding_map *e;
	assert(m != NULL);
	assert(enctype != NULL);

	m->encodingType = EEXTENSION;

	for(e = encoding_map; e->string; e++)
		if(strcasecmp(enctype, e->string) == 0) {
			m->encodingType = e->type;
			return;
		}

	cli_warnmsg("Unknown encoding type \"%s\"\n", enctype);
}

encoding_type
messageGetEncoding(const message *m)
{
	assert(m != NULL);
	return(m->encodingType);
}

/*
 * Line should not be terminated by a \n
 */
void
messageAddLine(message *m, const char *line)
{
	assert(m != NULL);

	if(m->body_first == NULL)
		m->body_last = m->body_first = (text *)cli_malloc(sizeof(text));
	else {
		m->body_last->t_next = (text *)cli_malloc(sizeof(text));
		m->body_last = m->body_last->t_next;
	}

	assert(m->body_last != NULL);

	m->body_last->t_next = NULL;

	m->body_last->t_text = strdup((line) ? line : "");

	assert(m->body_last->t_text != NULL);
	assert(m->body_first != NULL);
}

const text *
messageGetBody(const message *m)
{
	assert(m != NULL);
	return(m->body_first);
}

/*
 * Clean up the message by removing trailing spaces and blank lines
 */
void
messageClean(message *m)
{
	text *newEnd = textClean(m->body_first);

	if(newEnd)
		m->body_last = newEnd;
}

/*
 * Decode and transfer the contents of the message into a blob
 */
blob *
messageToBlob(const message *m)
{
	blob *b;
	const text *t_line = NULL;
	const char *filename;

	assert(m != NULL);

	b = blobCreate();

	assert(b != NULL);

	/*
	 * Find the filename to decode
	 */
	if(messageGetEncoding(m) == UUENCODE) {
		char *copy;
#ifdef CL_THREAD_SAFE
		char *strptr;
#endif

		t_line = uuencodeBegin(m);

		if(t_line == NULL) {
			/*cli_warnmsg("UUENCODED attachment is missing begin statement\n");*/
			blobDestroy(b);
			return NULL;
		}

		copy = strdup(t_line->t_text);
		(void)strtok_r(copy, " ", &strptr);
		(void)strtok_r(NULL, " ", &strptr);
		filename = strtok_r(NULL, "\r\n", &strptr);

		if(filename == NULL) {
			cli_dbgmsg("UUencoded attachment sent with no filename\n");
			blobDestroy(b);
			free(copy);
			return NULL;
		}

		cli_dbgmsg("Set uuencode filename to \"%s\"\n", filename);

		blobSetFilename(b, filename);
		free(copy);
		t_line = t_line->t_next;
	} else {
		/*
		 * Discard attachments with no filename
		 */
		filename = messageFindArgument(m, "filename");
		if(filename == NULL) {
			filename = messageFindArgument(m, "name");

			if(filename == NULL) {
				cli_dbgmsg("Attachment sent with no filename\n");
				blobDestroy(b);
				return NULL;
			}
		}

		blobSetFilename(b, filename);

		free((char *)filename);
		t_line = messageGetBody(m);
	}

	/*
	 * t_line should now point to the first (encoded) line of the message
	 */
	if(t_line == NULL) {
		cli_warnmsg("Empty attachment not saved\n");
		blobDestroy(b);
		return NULL;
	}

	if(messageGetEncoding(m) == NOENCODING)
		/*
		 * Fast copy
		 */
		do {
			blobAddData(b, (unsigned char *)t_line->t_text, strlen(t_line->t_text));
			blobAddData(b, (unsigned char *)"\n", 1);
		} while((t_line = t_line->t_next) != NULL);
	else
		do {
			unsigned char data[1024];
			unsigned char *uptr;
			const char *line = t_line->t_text;

			if(messageGetEncoding(m) == UUENCODE)
				if(strcasecmp(line, "end") == 0)
					break;

			uptr = decodeLine(m, line, data);

			if(uptr == NULL)
				break;

			assert(uptr <= &data[sizeof(data)]);

			blobAddData(b, data, (size_t)(uptr - data));
			/*
			 * According to RFC1521, '=' is used to pad out
			 * the last byte and should be used as evidence
			 * of the end of the data. Some mail clients
			 * annoyingly then put plain text after the '='
			 * bytes. Sigh
			 */
			if(messageGetEncoding(m) == BASE64)
				if(strchr(line, '='))
					break;

		} while((t_line = t_line->t_next) != NULL);
	return b;
}

/*
 * Decode and transfer the contents of the message into a text area
 */
text *
messageToText(const message *m)
{
	text *first = NULL, *last = NULL;
	const text *t_line;

	assert(m != NULL);

	if(messageGetEncoding(m) == NOENCODING)
		/*
		 * Fast copy
		 */
		for(t_line = messageGetBody(m); t_line; t_line = t_line->t_next) {
			const char *line;

			if(first == NULL)
				first = last = cli_malloc(sizeof(text));
			else {
				last->t_next = cli_malloc(sizeof(text));
				last = last->t_next;
			}

			assert(last != NULL);

			line = t_line->t_text;

			last->t_text = cli_malloc(strlen(line) + 2);

			assert(last->t_text != NULL);

			sprintf(last->t_text, "%s\n", line);
		}
	else {
		if(messageGetEncoding(m) == UUENCODE) {
			t_line = uuencodeBegin(m);

			if(t_line == NULL) {
				/*cli_warnmsg("UUENCODED attachment is missing begin statement\n");*/
				return NULL;
			}
			t_line = t_line->t_next;
		} else
			t_line = messageGetBody(m);

		for(; t_line; t_line = t_line->t_next) {
			unsigned char data[1024];
			unsigned char *uptr;
			const char *line = t_line->t_text;

			if(messageGetEncoding(m) == UUENCODE)
				if(strcasecmp(line, "end") == 0)
					break;

			uptr = decodeLine(m, line, data);

			if(uptr == NULL)
				break;

			assert(uptr <= &data[sizeof(data)]);

			if(first == NULL)
				first = last = cli_malloc(sizeof(text));
			else {
				last->t_next = cli_malloc(sizeof(text));
				last = last->t_next;
			}
			assert(last != NULL);

			last->t_text = strdup((char *)data);
			assert(last->t_text != NULL);

			if(messageGetEncoding(m) == BASE64)
				if(strchr(line, '='))
					break;
		}
	}

	if(last)
		last->t_next = NULL;

	return first;
}

static const text *
uuencodeBegin(const message *m)
{
	const text *t_line;

	/*
	 * Scan to find the UUENCODED message (if any)
	 *
	 * Fix based on an idea by Magnus Jonsson
	 * <Magnus.Jonsson@umdac.umu.se>, to allow for blank
	 * lines before the begin. Should not happen, but some
	 * e-mail clients are rather broken...
	 */
	for(t_line = messageGetBody(m); t_line; t_line = t_line->t_next) {
		const char *line = t_line->t_text;

		if((strncasecmp(line, "begin ", 6) == 0) &&
		   (isdigit(line[6])) &&
		   (isdigit(line[7])) &&
		   (isdigit(line[8])) &&
		   (line[9] == ' '))
			return t_line;
	}
	return NULL;
}

/*
 * Decode a line and add it to a buffer, return the end of the buffer
 * to help appending callers. There is no new line at the end of "line"
 */
static unsigned char *
decodeLine(const message *m, const char *line, unsigned char *ptr)
{
	int len;
	char *p2;
	char *copy;

	assert(m != NULL);
	assert(line != NULL);
	assert(ptr != NULL);

	switch(messageGetEncoding(m)) {
		case NOENCODING:
		case EIGHTBIT:
		default:	/* unknown encoding type - try our best */
			ptr = (unsigned char *)strrcpy((char *)ptr, line);
			/* Put the new line back in */
			return (unsigned char *)strrcpy((char *)ptr, "\n");

		case QUOTEDPRINTABLE:
			while(*line) {
				if(*line == '=') {
					unsigned char byte;

					if((*++line == '\0') || (*line == '\n'))
						/* soft line break */
						break;

					byte = hex(*line);

					if((*++line == '\0') || (*line == '\n')) {
						/*
						 * broken e-mail, not
						 * adhering to RFC1522
						 */
						*ptr++ = byte;
						break;
					}

					byte <<= 4;
					byte += hex(*line);
					*ptr++ = byte;
				} else if((*ptr != '\n') && (*ptr != '\r')) /* hard line break */
					*ptr++ = *line;
				line++;
			}
			break;

		case BASE64:
			/*
			 * RFC1521 sets the maximum length to 76 bytes
			 * but many e-mail clients ignore that
			 */
			copy = strdup(line);
			p2 = strchr(copy, '=');
			if(p2)
				*p2 = '\0';
			/*
			 * Klez doesn't always put "=" on the last line
			 */
			/*ptr = decode(line, ptr, base64, p2 == NULL);*/
			ptr = decode(copy, ptr, base64, 0);

			free(copy);
			break;

		case UUENCODE:
			assert(*line != '\0');

			if(strncasecmp(line, "begin ", 6) == 0)
				break;
			if(strcasecmp(line, "end") == 0)
				break;

			assert(strlen(line) <= 62);
			if((line[0] & 0x3F) == ' ')
				break;

			len = *line++ - ' ';

			assert((len >= 0) && (len <= 63));

			ptr = decode(line, ptr, uudecode, (len & 3) == 0);
			break;

		case BINARY:
			/*
			 * TODO: find out what this is, encoded as binary??
			 */
			break;
	}

	*ptr = '\0';
	return ptr;
}

static unsigned char *
decode(const char *in, unsigned char *out, unsigned char (*decoder)(char), bool isFast)
{
	unsigned char b1, b2, b3, b4;
	int nbytes;

	if(isFast)
		/* Fast decoding if not last line */
		while(*in) {
			b1 = (*decoder)(*in++);
			b2 = (*decoder)(*in++);
			b3 = (*decoder)(*in++);
			b4 = (*decoder)(*in++);
			*out++ = (b1 << 2) | ((b2 >> 4) & 0x3);
			*out++ = (b2 << 4) | ((b3 >> 2) & 0xF);
			*out++ = (b3 << 6) | (b4 & 0x3F);
		}
	else
		/* Slower decoding for last line */
		while(*in) {
			b1 = (*decoder)(*in++);
			if(*in == '\0') {
				b2 = '\0';
				nbytes = 1;
			} else {
				assert(*in != '\0');

				b2 = (*decoder)(*in++);
				if(*in == '\0') {
					b3 = '\0';
					nbytes = 2;
				} else {
					assert(*in != '\0');

					b3 = (*decoder)(*in++);

					if(*in == '\0') {
						b4 = '\0';
						nbytes = 3;
					} else {
						assert(*in != '\0');

						b4 = (*decoder)(*in++);
						nbytes = 4;
					}
				}
			}

			switch(nbytes) {
				case 3:
					b4 = '\0';
					/* fall through */
				case 4:
					*out++ = (b1 << 2) | ((b2 >> 4) & 0x3);
					*out++ = (b2 << 4) | ((b3 >> 2) & 0xF);
					*out++ = (b3 << 6) | (b4 & 0x3F);
					break;
				case 2:
					*out++ = (b1 << 2) | ((b2 >> 4) & 0x3);
					*out++ = b2 << 4;
					break;
				case 1:
					*out++ = b1 << 2;
					break;
				default:
					assert(0);
			}
			if(nbytes != 4)
				break;
		}
	return out;
}

static unsigned char
hex(char c)
{
	if(isdigit(c))
		return c - '0';
	if((c >= 'A') && (c <= 'F'))
		return c - 'A' + 10;

	/*
	 * Some mails (notably some spam) break RFC1522 by failing to encode
	 * the '=' character
	 */
	return '=';
}

static unsigned char
base64(char c)
{
	if(isupper(c))
		return c - 'A';
	if(islower(c))
		return c - 'a' + 26;
	if(isdigit(c))
		return c - '0' + 52;
	if(c == '+')
		return 62;

	if(c != '/')
		cli_warnmsg("Illegal character <%c> in base64 encoding\n", c);

	return 63;
}

static unsigned char
uudecode(char c)
{
	return(c - ' ');
}

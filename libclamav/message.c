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
 * Change History:
 * $Log: message.c,v $
 * Revision 1.52  2004/04/05 12:04:56  nigelhorne
 * Scan attachments with no filename
 *
 * Revision 1.51  2004/04/01 15:32:34  nigelhorne
 * Graceful exit if messageAddLine fails in strdup
 *
 * Revision 1.50  2004/03/31 17:00:20  nigelhorne
 * Code tidy up free memory earlier
 *
 * Revision 1.49  2004/03/29 09:22:03  nigelhorne
 * Tidy up code and reduce shuffling of data
 *
 * Revision 1.48  2004/03/25 22:40:46  nigelhorne
 * Removed even more calls to realloc and some duplicated code
 *
 * Revision 1.47  2004/03/21 17:19:49  nigelhorne
 * Handle bounce messages with no headers
 *
 * Revision 1.46  2004/03/21 09:41:27  nigelhorne
 * Faster scanning for non MIME messages
 *
 * Revision 1.45  2004/03/20 19:26:48  nigelhorne
 * Second attempt to handle all bounces
 *
 * Revision 1.44  2004/03/20 17:39:23  nigelhorne
 * First attempt to handle all bounces
 *
 * Revision 1.43  2004/03/20 13:23:44  nigelhorne
 * More bounces handled
 *
 * Revision 1.42  2004/03/19 17:38:11  nigelhorne
 * Handle binary encoding as though it had no encoding
 *
 * Revision 1.41  2004/03/19 08:08:38  nigelhorne
 * Handle '8 bit' encoding as well as the RFC '8bit'
 *
 * Revision 1.40  2004/03/18 21:51:41  nigelhorne
 * If a message only contains a single RFC822 message that has no encoding don't save for scanning
 *
 * Revision 1.39  2004/03/18 14:05:25  nigelhorne
 * Added bounce and handle text/plain encoding messages
 *
 * Revision 1.38  2004/03/17 19:47:32  nigelhorne
 * Handle spaces in disposition type
 *
 * Revision 1.37  2004/03/10 05:35:03  nigelhorne
 * Implemented a couple of small speed improvements
 *
 * Revision 1.36  2004/03/07 15:11:48  nigelhorne
 * Fixed minor typo in bounce message
 *
 * Revision 1.35  2004/03/07 12:32:01  nigelhorne
 * Added new bounce message
 *
 * Revision 1.34  2004/02/20 17:04:43  nigelhorne
 * Added new bounce delimeter
 *
 * Revision 1.33  2004/02/18 10:07:40  nigelhorne
 * Find some Yaha
 *
 * Revision 1.32  2004/02/17 20:43:50  nigelhorne
 * Added bounce message
 *
 * Revision 1.31  2004/02/17 09:53:56  nigelhorne
 * Added bounce message
 *
 * Revision 1.30  2004/02/13 14:23:56  nigelhorne
 * Add a new bounce delimeter
 *
 * Revision 1.29  2004/02/10 17:01:30  nigelhorne
 * Recognise a new type of bounce message
 *
 * Revision 1.28  2004/02/07 23:13:55  nigelhorne
 * Handle content-type: text/
 *
 * Revision 1.27  2004/02/06 13:46:08  kojm
 * Support for clamav-config.h
 *
 * Revision 1.26  2004/02/06 13:10:34  nigelhorne
 * Now integrates with winzip
 *
 * Revision 1.25  2004/02/05 11:23:07  nigelhorne
 * Bounce messages are now table driven
 *
 * Revision 1.24  2004/02/04 13:29:16  nigelhorne
 * Handle blobAddData of more than 128K
 *
 * Revision 1.23  2004/02/03 23:04:09  nigelhorne
 * Disabled binhex code
 *
 * Revision 1.22  2004/02/03 22:54:59  nigelhorne
 * Catch another example of Worm.Dumaru.Y
 *
 * Revision 1.21  2004/02/03 14:35:37  nigelhorne
 * Fixed an infinite loop on binhex
 *
 * Revision 1.20  2004/02/02 17:10:04  nigelhorne
 * Scan a rare form of bounce message
 *
 * Revision 1.19  2004/02/02 15:52:09  nigelhorne
 * Remove handling of 8bit binhex files for now
 *
 * Revision 1.18  2004/02/02 15:30:54  nigelhorne
 * Remove handling of 8bit binhex files for now
 *
 * Revision 1.17  2004/02/02 14:01:58  nigelhorne
 * Carefully crafted binhex messages could have caused a crash
 *
 * Revision 1.16  2004/01/28 10:15:24  nigelhorne
 * Added support to scan some bounce messages
 *
 * Revision 1.15  2004/01/14 10:08:45  nigelhorne
 * blobGetData now allows contents to be changed - tuttut
 *
 * Revision 1.14  2004/01/10 13:01:19  nigelhorne
 * Added BinHex compression support
 *
 * Revision 1.13  2004/01/09 18:01:03  nigelhorne
 * Started BinHex work
 *
 * Revision 1.12  2003/12/05 09:34:00  nigelhorne
 * Use cli_tok instead of strtok - replaced now by cli_strtok
 *
 * Revision 1.11  2003/11/17 07:57:12  nigelhorne
 * Prevent buffer overflow in broken uuencoded files
 *
 * Revision 1.10  2003/11/05 07:03:51  nigelhorne
 * Handle broken content-disposition
 *
 * Revision 1.9  2003/10/01 09:28:23  nigelhorne
 * Handle content-type header going over to a new line
 *
 * Revision 1.8  2003/09/28 10:07:08  nigelhorne
 * uuencodebegin() no longer static
 *
 */
static	char	const	rcsid[] = "$Id: message.c,v 1.52 2004/04/05 12:04:56 nigelhorne Exp $";

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifndef	CL_DEBUG
/*#define	NDEBUG	/* map CLAMAV debug onto standard */
#endif

#ifdef CL_THREAD_SAFE
#ifndef	_REENTRANT
#define	_REENTRANT	/* for Solaris 2.8 */
#endif
#endif

#if	C_DARWIN
#include <sys/types.h>
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
#include "str.h"
#include "scanners.h"

/* required for AIX and Tru64 */
#ifdef TRUE
#undef TRUE
#endif
#ifdef FALSE
#undef FALSE
#endif

typedef enum { FALSE = 0, TRUE = 1 } bool;

static	unsigned char	*decodeLine(const message *m, const char *line, unsigned char *buf, size_t buflen);
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
	{	"text/plain",		NOENCODING	},
	{	"quoted-printable",	QUOTEDPRINTABLE	},	/* rfc1522 */
	{	"base64",		BASE64		},
	{	"8bit",			EIGHTBIT	},
	{	"8 bit",		EIGHTBIT	},	/* incorrect */
	{	"x-uuencode",		UUENCODE	},
	{	"binary",		BINARY		},
	{	NULL,			NOENCODING	}
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
	{	NULL,			TEXT		}
};

message *
messageCreate(void)
{
	message *m = (message *)cli_calloc(1, sizeof(message));

	m->mimeType = NOMIME;
	m->encodingType = NOENCODING;

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
	m->encodingType = NOENCODING;
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

	if(subtype == NULL) {
		/*
		 * Handle broken content-type lines, e.g.
		 *	Content-Type: text/
		 */
		cli_dbgmsg("Empty content subtype\n");
		subtype = "";
	}

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

	/*
	 * It's broken for there to be an entry such as "Content-Disposition:"
	 * However some spam and viruses are rather broken, it's a sign
	 * that something is wrong if we get that - maybe we should force a
	 * scan of this part
	 */
	if(disptype) {
		while(isspace((int)*disptype))
			disptype++;
		if(*disptype)
			m->mimeDispositionType = strdup(disptype);
	}
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

	/*
	 * These are the only arguments we're interested in.
	 * Do 'fgrep messageFindArgument *.c' if you don't believe me!
	 * It's probably not good doing this since each time a new
	 * messageFindArgument is added I need to remember to look here,
	 * but it can save a lot of memory...
	 */
	if((strncasecmp(arg, "name", 4) != 0) &&
	   (strncasecmp(arg, "filename", 8) != 0) &&
	   (strncasecmp(arg, "boundary", 8) != 0) &&
	   (strncasecmp(arg, "type", 4) != 0)) {
		cli_dbgmsg("Discarding unwanted argument '%s'\n", arg);
		return;
	}

	cli_dbgmsg("Add argument '%s'\n", arg);

	for(offset = 0; offset < m->numberOfArguments; offset++)
		if(m->mimeArguments[offset] == NULL)
			break;
		else if(strcasecmp(arg, m->mimeArguments[offset]) == 0)
			return;	/* already in there */

	if(offset == m->numberOfArguments) {
		m->numberOfArguments++;
		m->mimeArguments = (char **)cli_realloc(m->mimeArguments, m->numberOfArguments * sizeof(char *));
	}

	m->mimeArguments[offset] = strdup(arg);

	/*
	 * This is terribly broken from an RFC point of view but is useful
	 * for catching viruses which have a filename but no type of
	 * mime. By pretending defaulting to an application rather than
	 * to nomime we can ensure they're saved and scanned
	 */
	if((strncasecmp(arg, "filename=", 9) == 0) || (strncasecmp(arg, "name=", 5) == 0))
		if(messageGetMimeType(m) == NOMIME) {
			cli_dbgmsg("Force mime encoding to application\n");
			messageSetMimeType(m, "application");
		}
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

			if(*cptr == '\0') {
				cli_warnmsg("Ignoring empty field in \"%s\"\n", s);
				return;
			}

			/*
			 * The field is not in quotes, so look for the closing
			 * white space
			 */
			while((*string != '\0') && !isspace(*string))
				string++;

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
				char *p;

				ret[strlen(ret) - 1] = '\0';
				/*
				 * Thomas Lamy <Thomas.Lamy@in-online.net>:
				 * fix un-quoting of boundary strings from
				 * header, occurs if boundary was given as
				 *	'boundary="_Test_";'
				 *
				 * At least two quotes in string, assume
				 * quoted argument
				 * end string at next quote
				 */
				if((p = strchr(ret, '"')) != NULL)
					*p = '\0';
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

	while((*enctype == '\t') || (*enctype == ' '))
		enctype++;

	for(e = encoding_map; e->string; e++)
		if(strcasecmp(enctype, e->string) == 0) {
			m->encodingType = e->type;
			cli_dbgmsg("Encoding type is \"%s\"\n", enctype);
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
 * Add the given line to the current message
 * If needed a copy of the given line is taken which the caller must free
 * Line should not be terminated by a \n
 */
int
messageAddLine(message *m, const char *line, int takeCopy)
{
	static const char encoding[] = "Content-Transfer-Encoding";
	static const char binhex[] = "(This file must be converted with BinHex 4.0)";
	assert(m != NULL);

	if(m->body_first == NULL)
		m->body_last = m->body_first = (text *)cli_malloc(sizeof(text));
	else {
		m->body_last->t_next = (text *)cli_malloc(sizeof(text));
		m->body_last = m->body_last->t_next;
	}

	if(m->body_last == NULL)
		return -1;

	m->body_last->t_next = NULL;

	if(takeCopy) {
		m->body_last->t_text = strdup((line) ? line : "");
		if(m->body_last->t_text == NULL) {
			cli_errmsg("messageAddLine: out of memory\n");
			return -1;
		}
		assert(m->body_last->t_text != NULL);
	} else {
		assert(line != NULL);
		m->body_last->t_text = (char *)line;
	}

	assert(m->body_first != NULL);

	/*
	 * See if this line marks the start of a non MIME inclusion that
	 * will need to be scanned
	 */
	if(line) {
		if((m->encoding == NULL) &&
		   (strncasecmp(line, encoding, sizeof(encoding) - 1) == 0) &&
		   (strstr(line, "7bit") == NULL))
			m->encoding = m->body_last;
		else if((m->bounce == NULL) &&
			(cli_filetype(line, strlen(line)) == CL_MAILFILE))
				m->bounce = m->body_last;
		else if((m->binhex == NULL) &&
			(strncasecmp(line, binhex, sizeof(binhex) - 1) == 0))
				m->binhex = m->body_last;
		else if((m->uuencode == NULL) &&
			((strncasecmp(line, "begin ", 6) == 0) &&
			(isdigit(line[6])) &&
			(isdigit(line[7])) &&
			(isdigit(line[8])) &&
			(line[9] == ' ')))
				m->uuencode = m->body_last;
	}
	return 1;
}

/*
 * Returns a pointer to the body of the message. Note that it does NOT return
 * a copy of the data
 */
const text *
messageGetBody(const message *m)
{
	assert(m != NULL);
	return m->body_first;
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
 * The caller must free the returned blob
 */
blob *
messageToBlob(message *m)
{
	blob *b;
	const text *t_line = NULL;
	char *filename;

	assert(m != NULL);

	b = blobCreate();

	if(b == NULL)
		return NULL;

	/*
	 * Find the filename to decode
	 */
	if(messageGetEncoding(m) == UUENCODE) {
		t_line = uuencodeBegin(m);

		if(t_line == NULL) {
			/*cli_warnmsg("UUENCODED attachment is missing begin statement\n");*/
			blobDestroy(b);
			return NULL;
		}

		filename = cli_strtok(t_line->t_text, 2, " ");

		if(filename == NULL) {
			cli_dbgmsg("UUencoded attachment sent with no filename\n");
			blobDestroy(b);
			return NULL;
		}
		cli_chomp(filename);

		cli_dbgmsg("Set uuencode filename to \"%s\"\n", filename);

		blobSetFilename(b, filename);
		t_line = t_line->t_next;
	} else if((t_line = binhexBegin(m)) != NULL) {
		unsigned char byte;
		unsigned long len, l, newlen = 0L;
		char *filename;
		unsigned char *ptr, *data;
		int bytenumber;
		blob *tmp = blobCreate();

		/*
		 * Table look up by Thomas Lamy <Thomas.Lamy@in-online.net>
		 * HQX conversion table - illegal chars are 0xff
		 */
		const unsigned char hqxtbl[] = {
			     /*   00   01   02   03   04   05   06   07   08   09   0a   0b   0c   0d   0e   0f */
		/* 00-0f */	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
		/* 10-1f */	0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
		/* 20-2f */	0xff,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0xff,0xff,
		/* 30-3f */	0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0xff,0x14,0x15,0xff,0xff,0xff,0xff,0xff,0xff,
		/* 40-4f */	0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,0x21,0x22,0x23,0x24,0xff,
		/* 50-5f */	0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0xff,0x2c,0x2d,0x2e,0x2f,0xff,0xff,0xff,0xff,
		/* 60-6f */	0x30,0x31,0x32,0x33,0x34,0x35,0x36,0xff,0x37,0x38,0x39,0x3a,0x3b,0x3c,0xff,0xff,
		/* 70-7f */	0x3d,0x3e,0x3f,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
		};

		/*
		 * Decode BinHex4. First create a temporary blob which contains
		 * the encoded message. Then decode that blob to the target
		 * blob, free the temporary blob and return the target one
		 *
		 * See RFC1741
		 */
		while((t_line = t_line->t_next) != NULL)
			blobAddData(tmp, (unsigned char *)t_line->t_text, strlen(t_line->t_text));

		data = blobGetData(tmp);

		if(data == NULL) {
			cli_warnmsg("Couldn't locate the binhex message that was claimed to be there\n");
			blobDestroy(tmp);
			blobDestroy(b);
			return NULL;
		}
		if(data[0] != ':') {
			/*
			 * TODO: Need an example of this before I can be
			 * sure it works
			 * Possibly data[0] = '#'
			 */
			cli_warnmsg("8 bit binhex code is not yet supported\n");
			blobDestroy(tmp);
			blobDestroy(b);
			return NULL;
		}

		len = blobGetDataSize(tmp);

		/*
		 * FIXME: this is dirty code, modification of the contents
		 * of a member of the blob object should be done through blob.c
		 *
		 * Convert 7 bit data into 8 bit
		 */
		cli_dbgmsg("decode HQX7 message (%lu bytes)\n", len);

		ptr = cli_malloc(len);
		memcpy(ptr, data, len);
		bytenumber = 0;

		/*
		 * ptr now contains the encoded (7bit) data - len bytes long
		 * data will contain the unencoded (8bit) data
		 */
		for(l = 1; l < len; l++) {
			unsigned char c = ptr[l];

			if(c == ':')
				break;

			if((c == '\n') || (c == '\r'))
				continue;

			if((c < 0x20) || (c > 0x7f) || (hqxtbl[c] == 0xff)) {
				cli_warnmsg("Invalid HQX7 character '%c' (0x%02x)\n", c, c);
				break;
			}
			c = hqxtbl[c];
			assert(c <= 63);

			/*
			 * These masks probably aren't needed, but
			 * they're here to verify the code is correct
			 */
			switch(bytenumber) {
				case 0:
					data[newlen] = (c << 2) & 0xFC;
					bytenumber = 1;
					break;
				case 1:
					data[newlen++] |= (c >> 4) & 0x3;
					data[newlen] = (c << 4) & 0xF0;
					bytenumber = 2;
					break;
				case 2:
					data[newlen++] |= (c >> 2) & 0xF;
					data[newlen] = (c << 6) & 0xC0;
					bytenumber = 3;
					break;
				case 3:
					data[newlen++] |= c & 0x3F;
					bytenumber = 0;
					break;
			}
		}

		cli_dbgmsg("decoded HQX7 message (now %lu bytes)\n", newlen);

		/*
		 * Throw away the old encoded (7bit) data
		 * data now points to the encoded (8bit) data - newlen bytes
		 *
		 * The data array may contain repetitive characters
		 */
		free(ptr);

		/*
		 * Uncompress repetitive characters
		 */
		if(memchr(data, 0x90, newlen)) {
			blob *u = blobCreate();	/* uncompressed data */

			/*
			 * Includes compression
			 */
			for(l = 0L; l < newlen; l++) {
				unsigned char c = data[l];

				/*
				 * TODO: handle the case where the first byte
				 * is 0x90
				 */
				blobAddData(u, &c, 1);

				if((l < (newlen - 1L)) && (data[l + 1] == 0x90)) {
					int count;

					l += 2;
					count = data[l];
#ifdef	CL_DEBUG
					cli_dbgmsg("uncompress HQX7 at 0x%06x: %d repetitive bytes\n", l, count);
#endif

					if(count == 0) {
						c = 0x90;
						blobAddData(u, &c, 1);
					} else {
						blobGrow(u, count);
						while(--count > 0)
							blobAddData(u, &c, 1);
					}
				}
			}
			blobDestroy(tmp);
			tmp = u;
			data = blobGetData(tmp);
			len = blobGetDataSize(tmp);
			cli_dbgmsg("Uncompressed %lu bytes to %lu\n", newlen, len);
		} else {
			len = newlen;
			cli_dbgmsg("HQX7 message (%lu bytes) is not compressed\n",
				len);
		}

		/*
		 * The blob tmp now contains the uncompressed data
		 * of len bytes, i.e. the repetitive bytes have been removed
		 */

		/*
		 * Parse the header
		 *
		 * TODO: set filename argument in message as well
		 */
		byte = data[0];
		filename = cli_malloc(byte + 1);
		memcpy(filename, &data[1], byte);
		filename[byte] = '\0';
		blobSetFilename(b, filename);
		ptr = cli_malloc(strlen(filename) + 6);
		sprintf(ptr, "name=%s", filename);
		messageAddArgument(m, ptr);
		free(ptr);

		/*
		 * skip over length, filename, version, type, creator and flags
		 */
		byte = 1 + byte + 1 + 4 + 4 + 2;

		/*
		 * Set len to be the data fork length
		 */
		len = ((data[byte] << 24) & 0xFF000000) |
		      ((data[byte + 1] << 16) & 0xFF0000) |
		      ((data[byte + 2] << 8) & 0xFF00) |
		      (data[byte + 3] & 0xFF);

		cli_dbgmsg("Filename = '%s', data fork length = %lu bytes\n",
			filename, len);

		free((char *)filename);

		/*
		 * Skip over data fork length, resource fork length and CRC
		 */
		byte += 10;

		blobAddData(b, &data[byte], len);

		blobDestroy(tmp);

		return b;
	} else {
		/*
		 * Discard attachments with no filename
		 */
		filename = (char *)messageFindArgument(m, "filename");
		if(filename == NULL) {
			filename = (char *)messageFindArgument(m, "name");

			if(filename == NULL) {
				cli_dbgmsg("Attachment sent with no filename\n");
				messageAddArgument(m, "name=attachment");
				filename = strdup("attachment");
			}
		}

		blobSetFilename(b, filename);

		t_line = messageGetBody(m);
	}
	free((char *)filename);

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
		return textToBlob(t_line, b);

	do {
		unsigned char data[1024];
		unsigned char *uptr;
		const char *line = t_line->t_text;

		if(messageGetEncoding(m) == UUENCODE)
			if(strcasecmp(line, "end") == 0)
				break;

		uptr = decodeLine(m, line, data, sizeof(data));

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
		/*if(messageGetEncoding(m) == BASE64)
			if(strchr(line, '='))
				break;*/

	} while((t_line = t_line->t_next) != NULL);

	return b;
}

/*
 * Decode and transfer the contents of the message into a text area
 * The caller must free the returned text
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
			if(first == NULL)
				first = last = cli_malloc(sizeof(text));
			else {
				last->t_next = cli_malloc(sizeof(text));
				last = last->t_next;
			}

			if((last == NULL) ||
			   ((last->t_text = strdup(t_line->t_text)) == NULL)) {
				textDestroy(first);
				return NULL;
			}
		}
	else {
		if(messageGetEncoding(m) == UUENCODE) {
			t_line = uuencodeBegin(m);

			if(t_line == NULL) {
				/*cli_warnmsg("UUENCODED attachment is missing begin statement\n");*/
				return NULL;
			}
			t_line = t_line->t_next;
		} else {
			if(binhexBegin(m))
				cli_warnmsg("Binhex messages not supported yet (2).\n");
			t_line = messageGetBody(m);
		}

		for(; t_line; t_line = t_line->t_next) {
			unsigned char data[1024];
			unsigned char *uptr;
			const char *line = t_line->t_text;

			if(messageGetEncoding(m) == UUENCODE)
				if(strcasecmp(line, "end") == 0)
					break;

			uptr = decodeLine(m, line, data, sizeof(data));

			if(uptr == NULL)
				break;

			assert(uptr <= &data[sizeof(data)]);

			if(first == NULL)
				first = last = cli_malloc(sizeof(text));
			else {
				last->t_next = cli_malloc(sizeof(text));
				last = last->t_next;
			}

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

/*
 * Scan to find the UUENCODED message (if any)
 */
#if	0
const text *
uuencodeBegin(const message *m)
{
	const text *t_line;

	/*
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
#else
const text *
uuencodeBegin(const message *m)
{
	return m->uuencode;
}
#endif

/*
 * Scan to find the BINHEX message (if any)
 */
#if	0
const text *
binhexBegin(const message *m)
{
	const text *t_line;

	for(t_line = messageGetBody(m); t_line; t_line = t_line->t_next)
		if(strcasecmp(t_line->t_text, "(This file must be converted with BinHex 4.0)") == 0)
			return t_line;

	return NULL;
}
#else
const text *
binhexBegin(const message *m)
{
	return m->binhex;
}
#endif

/*
 * Scan to find a bounce message. There is no standard for these, not
 * even a convention, so don't expect this to be foolproof
 */
#if	0
const text *
bounceBegin(const message *m)
{
	const text *t_line;

	for(t_line = messageGetBody(m); t_line; t_line = t_line->t_next)
		if(cli_filetype(t_line->t_text, strlen(t_line->t_text)) == CL_MAILFILE)
			return t_line;

	return NULL;
}
#else
const text *
bounceBegin(const message *m)
{
	return m->bounce;
}
#endif

/*
 * If a message doesn't not contain another message which could be harmful
 * it is deemed to be safe.
 *
 * TODO: ensure nothing can get through this
 *
 * TODO: check to see if we need to
 * find anything else, perhaps anything
 * from the RFC821 table?
 */
#if	0
int
messageIsAllText(const message *m)
{
	const text *t;

	for(t = messageGetBody(m); t; t = t->t_next)
		if(strncasecmp(t->t_text,
			"Content-Transfer-Encoding",
			strlen("Content-Transfer-Encoding")) == 0)
				return 0;

	return 1;
}
#else
const text *
encodingLine(const message *m)
{
	return m->encoding;
}
#endif

/*
 * Decode a line and add it to a buffer, return the end of the buffer
 * to help appending callers. There is no new line at the end of "line"
 *
 * len is sizeof(ptr)
 */
static unsigned char *
decodeLine(const message *m, const char *line, unsigned char *buf, size_t buflen)
{
	size_t len;
	bool softbreak;
	char *p2;
	char *copy;

	assert(m != NULL);
	assert(line != NULL);
	assert(buf != NULL);

	switch(messageGetEncoding(m)) {
		case BINARY:
			/*
			 * TODO: find out what this is, encoded as binary??
			 */
			/* fall through */
		case NOENCODING:
		case EIGHTBIT:
		default:	/* unknown encoding type - try our best */
			buf = (unsigned char *)strrcpy((char *)buf, line);
			/* Put the new line back in */
			return (unsigned char *)strrcpy((char *)buf, "\n");

		case QUOTEDPRINTABLE:
			softbreak = FALSE;
			while(*line) {
				if(*line == '=') {
					unsigned char byte;

					if((*++line == '\0') || (*line == '\n')) {
						softbreak = TRUE;
						/* soft line break */
						break;
					}

					byte = hex(*line);

					if((*++line == '\0') || (*line == '\n')) {
						/*
						 * broken e-mail, not
						 * adhering to RFC1522
						 */
						*buf++ = byte;
						break;
					}

					byte <<= 4;
					byte += hex(*line);
					*buf++ = byte;
				} else
					*buf++ = *line;
				line++;
			}
			if(!softbreak)
				/* Put the new line back in */
				*buf++ = '\n';
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
			/*buf = decode(line, buf, base64, p2 == NULL);*/
			buf = decode(copy, buf, base64, FALSE);

			free(copy);
			break;

		case UUENCODE:
			if(*line == '\0')	/* empty line */
				break;
			if(strncasecmp(line, "begin ", 6) == 0)
				break;
			if(strcasecmp(line, "end") == 0)
				break;

			if((line[0] & 0x3F) == ' ')
				break;

			len = *line++ - ' ';

			if(len > buflen)
				/*
				 * In practice this should never occur since
				 * the maximum length of a uuencoded line is
				 * 62 characters
				 */
				cli_warnmsg("uudecode: buffer overflow stopped, attempting to ignore but decoding may fail");
			else
				buf = decode(line, buf, uudecode, (len & 3) == 0);
			break;
	}

	*buf = '\0';
	return buf;
}

/*
 * Returns one byte after the end of the decoded data in "out"
 */
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
		cli_dbgmsg("Illegal character <%c> in base64 encoding\n", c);

	return 63;
}

static unsigned char
uudecode(char c)
{
	return(c - ' ');
}

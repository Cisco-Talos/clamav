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
 * Revision 1.76  2004/09/03 15:59:00  nigelhorne
 * Handle boundary= "foo"
 *
 * Revision 1.75  2004/08/23 13:15:16  nigelhorne
 * messageClearMarkers
 *
 * Revision 1.74  2004/08/22 15:08:59  nigelhorne
 * messageExport
 *
 * Revision 1.73  2004/08/22 10:34:24  nigelhorne
 * Use fileblob
 *
 * Revision 1.72  2004/08/21 11:57:57  nigelhorne
 * Use line.[ch]
 *
 * Revision 1.71  2004/08/13 09:28:16  nigelhorne
 * Remove incorrect comment style
 *
 * Revision 1.70  2004/08/08 19:13:15  nigelhorne
 * Better handling of bounces
 *
 * Revision 1.69  2004/08/04 18:59:19  nigelhorne
 * Tidy up multipart handling
 *
 * Revision 1.68  2004/07/30 11:50:39  nigelhorne
 * Code tidy
 *
 * Revision 1.67  2004/07/26 08:31:04  nigelhorne
 * Fix embedded multi parts
 *
 * Revision 1.66  2004/07/20 15:17:44  nigelhorne
 * Remove overlapping strcpy
 *
 * Revision 1.65  2004/07/20 14:35:29  nigelhorne
 * Some MYDOOM.I were getting through
 *
 * Revision 1.64  2004/07/02 23:00:57  kojm
 * new method of file type detection; HTML normalisation
 *
 * Revision 1.63  2004/06/26 13:16:25  nigelhorne
 * Added newline to end of warning message
 *
 * Revision 1.62  2004/06/24 21:37:26  nigelhorne
 * Handle uuencoded files created with buggy software
 *
 * Revision 1.61  2004/06/22 04:08:02  nigelhorne
 * Optimise empty lines
 *
 * Revision 1.60  2004/06/16 08:07:39  nigelhorne
 * Added thread safety
 *
 * Revision 1.59  2004/06/02 10:11:09  nigelhorne
 * Corrupted binHex could crash on non Linux systems
 *
 * Revision 1.58  2004/06/01 09:07:19  nigelhorne
 * Corrupted binHex could crash on non Linux systems
 *
 * Revision 1.57  2004/05/27 16:52:47  nigelhorne
 * Short binhex data could confuse things
 *
 * Revision 1.56  2004/05/19 10:02:25  nigelhorne
 * Default encoding for attachments set to base64
 *
 * Revision 1.55  2004/05/10 11:24:18  nigelhorne
 * Handle bounce message false positives
 *
 * Revision 1.54  2004/05/06 18:01:25  nigelhorne
 * Force attachments marked as RFC822 messages to be scanned
 *
 * Revision 1.53  2004/04/29 08:59:24  nigelhorne
 * Tidied up SetDispositionType
 *
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
static	char	const	rcsid[] = "$Id: message.c,v 1.76 2004/09/03 15:59:00 nigelhorne Exp $";

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

#ifdef	CL_THREAD_SAFE
#include <pthread.h>
#endif

#include "line.h"
#include "mbox.h"
#include "table.h"
#include "blob.h"
#include "text.h"
#include "strrcpy.h"
#include "others.h"
#include "str.h"
#include "filetypes.h"

/* required for AIX and Tru64 */
#ifdef TRUE
#undef TRUE
#endif
#ifdef FALSE
#undef FALSE
#endif

typedef enum { FALSE = 0, TRUE = 1 } bool;

static	void	messageIsEncoding(message *m);
static	const	text	*binhexBegin(const message *m);
static	unsigned char	*decodeLine(message *m, const char *line, unsigned char *buf, size_t buflen);
static unsigned char *decode(message *m, const char *in, unsigned char *out, unsigned char (*decoder)(char), bool isFast);
static	void	squeeze(char *s);
static	unsigned	char	hex(char c);
static	unsigned	char	base64(char c);
static	unsigned	char	uudecode(char c);
static	const	char	*messageGetArgument(const message *m, int arg);
static	void	*messageExport(message *m, const char *dir, void *(*create)(void), void (*destroy)(void *), void (*setFilename)(void *, const char *, const char *), void (*addData)(void *, const unsigned char *, size_t), void *(*exportText)(const text *, void *));
static	int	usefulArg(const char *arg);

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
	{	"base64",		BASE64		},	/* rfc2045 */
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

	if(m) {
		m->mimeType = NOMIME;
		m->encodingType = NOENCODING;
	}

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

	assert(m->base64chars == 0);

	memset(m, '\0', sizeof(message));
	m->mimeType = NOMIME;
	m->encodingType = NOENCODING;
}

void
messageSetMimeType(message *mess, const char *type)
{
#ifdef	CL_THREAD_SAFE
	static pthread_mutex_t mime_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif
	static table_t *mime_table;
	int typeval;

	assert(mess != NULL);
	assert(type != NULL);

	mess->mimeType = NOMIME;

	cli_dbgmsg("messageSetMimeType: '%s'\n", type);

	/* Ignore leading spaces */
	while(isspace(*type))
		if(*type++ == '\0')
			return;

#ifdef	CL_THREAD_SAFE
	pthread_mutex_lock(&mime_mutex);
#endif
	if(mime_table == NULL) {
		const struct mime_map *m;

		mime_table = tableCreate();
		if(mime_table == NULL) {
#ifdef	CL_THREAD_SAFE
			pthread_mutex_unlock(&mime_mutex);
#endif
			return;
		}

		for(m = mime_map; m->string; m++)
			if(!tableInsert(mime_table, m->string, m->type)) {
				tableDestroy(mime_table);
				mime_table = NULL;
#ifdef	CL_THREAD_SAFE
				pthread_mutex_unlock(&mime_mutex);
#endif
				return;
			}
	}
#ifdef	CL_THREAD_SAFE
	pthread_mutex_unlock(&mime_mutex);
#endif

	typeval = tableFind(mime_table, type);

	mess->mimeType = (mime_type)((typeval == -1) ? (int)NOMIME : typeval);

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

	if(m->mimeDispositionType)
		free(m->mimeDispositionType);
	if(disptype == NULL) {
		m->mimeDispositionType = NULL;
		return;
	}

	/*
	 * It's broken for there to be an entry such as "Content-Disposition:"
	 * However some spam and viruses are rather broken, it's a sign
	 * that something is wrong if we get that - maybe we should force a
	 * scan of this part
	 */
	while(*disptype && isspace((int)*disptype))
		disptype++;
	if(*disptype) {
		m->mimeDispositionType = strdup(disptype);
		if(m->mimeDispositionType)
			strstrip(m->mimeDispositionType);
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

	if(!usefulArg(arg))
		return;

	cli_dbgmsg("Add argument '%s'\n", arg);

	for(offset = 0; offset < m->numberOfArguments; offset++)
		if(m->mimeArguments[offset] == NULL)
			break;
		else if(strcasecmp(arg, m->mimeArguments[offset]) == 0)
			return;	/* already in there */

	if(offset == m->numberOfArguments) {
		char **ptr;

		m->numberOfArguments++;
		ptr = (char **)cli_realloc(m->mimeArguments, m->numberOfArguments * sizeof(char *));
		if(ptr == NULL) {
			m->numberOfArguments--;
			return;
		}
		m->mimeArguments = ptr;
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
			cli_dbgmsg("Can't parse header \"%s\"\n", s);
			return;
		}

		string = data;

		string++;

		/*
		 * Handle white space to the right of the equals sign
		 * This breaks RFC1521 which has:
		 *	parameter := attribute "=" value
		 *	attribute := token   ; case-insensitive
		 *	token  :=  1*<any (ASCII) CHAR except SPACE, CTLs,
		 *		or tspecials>
		 * But too many MUAs ignore this
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
				if(usefulArg(key))
					cli_warnmsg("Can't parse header (1) \"%s\"\n", s);
				free((char *)key);
				return;
			}

			string++;

			if(!usefulArg(key)) {
				free((char *)key);
				continue;
			}

			data = strdup(cptr);

			ptr = (data) ? strchr(data, '"') : NULL;
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
				cli_warnmsg("Can't parse header (2) \"%s\"\n", s);
				if(data)
					free(data);
				free((char *)key);
				return;
			}

			*ptr = '\0';

			field = cli_realloc((char *)key, strlen(key) + strlen(data) + 2);
			if(field) {
				strcat(field, "=");
				strcat(field, data);
			} else
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

			if(field) {
				memcpy(field, key, len - 1);
				field[len - 1] = '\0';
			}
		}
		if(field) {
			messageAddArgument(m, field);
			free(field);
		}
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
	size_t len;

	assert(m != NULL);
	assert(variable != NULL);

	len = strlen(variable);

	for(i = 0; i < m->numberOfArguments; i++) {
		const char *ptr;

		ptr = messageGetArgument(m, i);
		if((ptr == NULL) || (*ptr == '\0'))
			continue;
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

				if(ret == NULL)
					return NULL;

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
				return ret;
			}
			return strdup(ptr);
		}
	}
	return NULL;
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

int
messageAddLine(message *m, line_t *line)
{
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

	if(line && lineGetData(line)) {
		m->body_last->t_line = lineLink(line);

		messageIsEncoding(m);
	} else
		m->body_last->t_line = NULL;

	return 1;
}

/*
 * Add the given line to the end of the given message
 * If needed a copy of the given line is taken which the caller must free
 * Line must not be terminated by a \n
 */
int
messageAddStr(message *m, const char *data)
{
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

	if(data && *data) {
		m->body_last->t_line = lineCreate(data);

		if(m->body_last->t_line == NULL) {
			cli_errmsg("messageAddStr: out of memory\n");
			return -1;
		}
		/* cli_chomp(m->body_last->t_text); */

		messageIsEncoding(m);
	} else
		m->body_last->t_line = NULL;

	return 1;
}

/*
 * Add the given line to the start of the given message
 * A copy of the given line is taken which the caller must free
 * Line must not be terminated by a \n
 */
int
messageAddStrAtTop(message *m, const char *data)
{
	text *oldfirst;

	assert(m != NULL);

	if(m->body_first == NULL)
		return messageAddLine(m, lineCreate(data));

	oldfirst = m->body_first;
	m->body_first = (text *)cli_malloc(sizeof(text));
	if(m->body_first == NULL) {
		m->body_first = oldfirst;
		return -1;
	}

	m->body_first->t_next = oldfirst;
	m->body_first->t_line = lineCreate((data) ? data : "");

	if(m->body_first->t_line == NULL) {
		cli_errmsg("messageAddStrAtTop: out of memory\n");
		return -1;
	}
	return 1;
}

/*
 * See if the last line marks the start of a non MIME inclusion that
 * will need to be scanned
 */
static void
messageIsEncoding(message *m)
{
	static const char encoding[] = "Content-Transfer-Encoding";
	static const char binhex[] = "(This file must be converted with BinHex 4.0)";
	const char *line = lineGetData(m->body_last->t_line);

	if((m->encoding == NULL) &&
	   (strncasecmp(line, encoding, sizeof(encoding) - 1) == 0) &&
	   (strstr(line, "7bit") == NULL))
		m->encoding = m->body_last;
	else if(/*(m->bounce == NULL) &&*/
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
 * Export a message using the given export routines
 */
static void *
messageExport(message *m, const char *dir, void *(*create)(void), void (*destroy)(void *), void (*setFilename)(void *, const char *, const char *), void (*addData)(void *, const unsigned char *, size_t), void *(*exportText)(const text *, void *))
{
	void *ret;
	const text *t_line;
	char *filename;

	assert(m != NULL);

	ret = (*create)();

	if(ret == NULL)
		return NULL;

	/*
	 * Find the filename to decode
	 */
	if(messageGetEncoding(m) == UUENCODE) {
		t_line = uuencodeBegin(m);

		if(t_line == NULL) {
			/*cli_warnmsg("UUENCODED attachment is missing begin statement\n");*/
			(*destroy)(ret);
			return NULL;
		}

		filename = cli_strtok(lineGetData(t_line->t_line), 2, " ");

		if(filename == NULL) {
			cli_dbgmsg("UUencoded attachment sent with no filename\n");
			(*destroy)(ret);
			return NULL;
		}
		cli_chomp(filename);

		cli_dbgmsg("Set uuencode filename to \"%s\"\n", filename);

		(*setFilename)(ret, dir, filename);
		t_line = t_line->t_next;
	} else if((t_line = binhexBegin(m)) != NULL) {
		unsigned char byte;
		unsigned long len, l, newlen = 0L;
		unsigned char *uptr, *data;
		char *ptr;
		int bytenumber;
		blob *tmp;

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

		tmp = blobCreate();

		if(tmp == NULL) {
			(*destroy)(ret);
			return NULL;
		}

		/*
		 * Decode BinHex4. First create a temporary blob which contains
		 * the encoded message. Then decode that blob to the target
		 * blob, free the temporary blob and return the target one
		 *
		 * See RFC1741
		 */
		while((t_line = t_line->t_next) != NULL)
			if(t_line->t_line) {
				const char *d = lineGetData(t_line->t_line);
				blobAddData(tmp, (unsigned char *)d, strlen(d));
			}

		data = blobGetData(tmp);

		if(data == NULL) {
			cli_warnmsg("Couldn't locate the binhex message that was claimed to be there\n");
			blobDestroy(tmp);
			(*destroy)(ret);
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
			(*destroy)(ret);
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

		uptr = cli_malloc(len);
		if(uptr == NULL) {
			blobDestroy(tmp);
			(*destroy)(ret);
			return NULL;
		}
		memcpy(uptr, data, len);
		bytenumber = 0;

		/*
		 * uptr now contains the encoded (7bit) data - len bytes long
		 * data will contain the unencoded (8bit) data
		 */
		for(l = 1; l < len; l++) {
			unsigned char c = uptr[l];

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
		free(uptr);

		/*
		 * Uncompress repetitive characters
		 */
		if(memchr(data, 0x90, newlen)) {
			blob *u = blobCreate();	/* uncompressed data */

			if(u == NULL) {
				(*destroy)(ret);
				blobDestroy(tmp);
				return NULL;
			}
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
		if(len == 0) {
			cli_warnmsg("Discarding empty binHex attachment\n");
			(*destroy)(ret);
			blobDestroy(tmp);
			return NULL;
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
		if(byte >= len) {
			(*destroy)(ret);
			blobDestroy(tmp);
			return NULL;
		}
		filename = cli_malloc(byte + 1);
		if(filename == NULL) {
			(*destroy)(ret);
			blobDestroy(tmp);
			return NULL;
		}
		memcpy(filename, &data[1], byte);
		filename[byte] = '\0';
		(*setFilename)(ret, dir, filename);
		/*ptr = cli_malloc(strlen(filename) + 6);*/
		ptr = cli_malloc(byte + 6);
		if(ptr) {
			sprintf(ptr, "name=%s", filename);
			messageAddArgument(m, ptr);
			free(ptr);
		}

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

		l = blobGetDataSize(tmp) - byte;

		if(l < len) {
			cli_warnmsg("Corrupt BinHex file, claims it is %lu bytes long in a message of %lu bytes\n",
				len, l);
			len = l;
		}
		(*addData)(ret, &data[byte], len);

		blobDestroy(tmp);

		return ret;
	} else {
		filename = (char *)messageFindArgument(m, "filename");
		if(filename == NULL) {
			filename = (char *)messageFindArgument(m, "name");

			if(filename == NULL) {
				cli_dbgmsg("Attachment sent with no filename\n");
				messageAddArgument(m, "name=attachment");
				filename = strdup("attachment");
			} else if(messageGetEncoding(m) == NOENCODING)
				/*
				 * Some virus attachments don't say how they've
				 * been encoded. We assume base64
				 */
				messageSetEncoding(m, "base64");
		}

		(*setFilename)(ret, dir, filename);

		t_line = messageGetBody(m);
	}
	free((char *)filename);

	/*
	 * t_line should now point to the first (encoded) line of the message
	 */
	if(t_line == NULL) {
		cli_warnmsg("Empty attachment not saved\n");
		(*destroy)(ret);
		return NULL;
	}

	if(messageGetEncoding(m) == NOENCODING)
		/*
		 * Fast copy
		 */
		return exportText(t_line, ret);

	do {
		unsigned char data[1024];
		unsigned char *uptr;
		const char *line = lineGetData(t_line->t_line);

		if(messageGetEncoding(m) == UUENCODE) {
			/*
			 * There should be no blank lines in uuencoded files...
			 */
			if(line == NULL)
				continue;
			if(strcasecmp(line, "end") == 0)
				break;
		}

		uptr = decodeLine(m, line, data, sizeof(data));

		if(uptr == NULL)
			break;

		assert(uptr <= &data[sizeof(data)]);

		if(uptr != data)
			(*addData)(ret, data, (size_t)(uptr - data));

		/*
		 * According to RFC1521, '=' is used to pad out
		 * the last byte and should be used as evidence
		 * of the end of the data. Some mail clients
		 * annoyingly then put plain text after the '='
		 * byte and viruses exploit this bug. Sigh
		 */
		/*if(messageGetEncoding(m) == BASE64)
			if(strchr(line, '='))
				break;*/

	} while((t_line = t_line->t_next) != NULL);

	/* Verify we have nothing left to flush out */
	if(m->base64chars) {
		unsigned char data[4];
		unsigned char *ptr;

		ptr = decode(m, NULL, data, base64, FALSE);
		if(ptr)
			(*addData)(ret, data, (size_t)(ptr - data));
		m->base64chars = 0;
	}

	return ret;
}

/*
 * Decode and transfer the contents of the message into a fileblob
 * The caller must free the returned fileblob
 */
fileblob *
messageToFileblob(message *m, const char *dir)
{
	cli_dbgmsg("messageToFileblob\n");
	return messageExport(m, dir, fileblobCreate, fileblobDestroy, fileblobSetFilename, fileblobAddData, textToFileblob);
}

/*
 * Decode and transfer the contents of the message into a blob
 * The caller must free the returned blob
 */
blob *
messageToBlob(message *m)
{
	return messageExport(m, NULL, blobCreate, blobDestroy, blobSetFilename, blobAddData, textToBlob);
}

/*
 * Decode and transfer the contents of the message into a text area
 * The caller must free the returned text
 */
text *
messageToText(message *m)
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

			if(last == NULL) {
				if(first)
					textDestroy(first);
				return NULL;
			}
			last->t_line = lineLink(t_line->t_line);
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
				cli_warnmsg("Binhex messages not supported yet.\n");
			t_line = messageGetBody(m);
		}

		for(; t_line; t_line = t_line->t_next) {
			unsigned char data[1024];
			unsigned char *uptr;
			const char *line = lineGetData(t_line->t_line);

			if(messageGetEncoding(m) == BASE64) {
				/*
				 * ignore blanks - breaks RFC which is
				 * probably the point!
				 */
				if(line == NULL)
					continue;
			} else if(messageGetEncoding(m) == UUENCODE)
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

			if(last == NULL)
				break;

			last->t_line = ((data[0] != '\n') && data[0]) ? lineCreate((char *)data) : NULL;

			if(line && messageGetEncoding(m) == BASE64)
				if(strchr(line, '='))
					break;
		}
		if(m->base64chars) {
			unsigned char data[4];

			memset(data, '\0', sizeof(data));
			if(decode(m, NULL, data, base64, FALSE)) {
				if(first == NULL)
					first = last = cli_malloc(sizeof(text));
				else {
					last->t_next = cli_malloc(sizeof(text));
					last = last->t_next;
				}

				if(last != NULL)
					last->t_line = data[0] ? lineCreate((char *)data) : NULL;
			}
			m->base64chars = 0;
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
static const text *
binhexBegin(const message *m)
{
	const text *t_line;

	for(t_line = messageGetBody(m); t_line; t_line = t_line->t_next)
		if(strcasecmp(t_line->t_text, "(This file must be converted with BinHex 4.0)") == 0)
			return t_line;

	return NULL;
}
#else
static const text *
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

void
messageClearMarkers(message *m)
{
	m->encoding = m->bounce = m->uuencode = m->binhex = NULL;
}

/*
 * Decode a line and add it to a buffer, return the end of the buffer
 * to help appending callers. There is no new line at the end of "line"
 *
 * len is sizeof(ptr)
 */
static unsigned char *
decodeLine(message *m, const char *line, unsigned char *buf, size_t buflen)
{
	size_t len;
	bool softbreak;
	char *p2;
	char *copy;

	assert(m != NULL);
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
			if(line == NULL) {	/* empty line */
				*buf++ = '\n';
				break;
			}
			buf = (unsigned char *)strrcpy((char *)buf, line);
			/* Put the new line back in */
			return (unsigned char *)strrcpy((char *)buf, "\n");

		case QUOTEDPRINTABLE:
			if(line == NULL) {	/* empty line */
				*buf++ = '\n';
				break;
			}

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
			if(line == NULL)
				break;
			/*
			 * RFC1521 sets the maximum length to 76 bytes
			 * but many e-mail clients ignore that
			 */
			copy = strdup(line);
			if(copy == NULL)
				break;

			squeeze(copy);

			p2 = strchr(copy, '=');
			if(p2)
				*p2 = '\0';

			/*
			 * Klez doesn't always put "=" on the last line
			 */
			buf = decode(m, copy, buf, base64, (p2 == NULL) && ((strlen(copy) & 3) == 0));
			if(p2)
				/* flush the read ahead bytes */
				buf = decode(m, NULL, buf, base64, FALSE);

			/*buf = decode(m, copy, buf, base64, FALSE);*/

			free(copy);
			break;

		case UUENCODE:
			if((line == NULL) || (*line == '\0'))	/* empty line */
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
				cli_warnmsg("uudecode: buffer overflow stopped, attempting to ignore but decoding may fail\n");
			else
				buf = decode(m, line, buf, uudecode, (len & 3) == 0);
			break;
	}

	*buf = '\0';
	return buf;
}

/*
 * Remove the spaces from the middle of a string. Spaces shouldn't appear
 * mid string in base64 files, but some broken mail clients ignore such
 * errors rather than discarding the mail, and virus writers exploit this bug
 */
static void
squeeze(char *s)
{
	while((s = strchr(s, ' ')) != NULL) {
		/*strcpy(s, &s[1]);*/	/* overlapping strcpy */

		char *p1;

		for(p1 = s; p1[0] != '\0'; p1++)
			p1[0] = p1[1];
	}
}

/*
 * Returns one byte after the end of the decoded data in "out"
 *
 * Update m->base64chars with the last few bytes of data that we haven't
 * decoded. After the last line is found, decode will be called with in = NULL
 * to flush these out
 */
static unsigned char *
decode(message *m, const char *in, unsigned char *out, unsigned char (*decoder)(char), bool isFast)
{
	unsigned char b1, b2, b3, b4;
	unsigned char cb1, cb2, cb3;	/* carried over from last line */

	/*cli_dbgmsg("decode %s (len %d ifFast %d base64chars %d)\n", in,
		in ? strlen(in) : 0,
		isFast, m->base64chars);*/

	cb1 = cb2 = cb3 = '\0';

	switch(m->base64chars) {
		case 3:
			cb3 = m->base64_3;
			/* FALLTHROUGH */
		case 2:
			cb2 = m->base64_2;
			/* FALLTHROUGH */
		case 1:
			cb1 = m->base64_1;
			isFast = FALSE;
			break;
		default:
			assert(m->base64chars <= 3);
	}

	if(isFast)
		/* Fast decoding if not last line */
		while(*in) {
			b1 = (*decoder)(*in++);
			b2 = (*decoder)(*in++);
			b3 = (*decoder)(*in++);
			/*
			 * Put this line here to help on some compilers which
			 * can make use of some architecure's ability to
			 * multiprocess when different variables can be
			 * updated at the same time - here b3 is used in
			 * one line, b1/b2 in the next and b4 in the next after
			 * that, b3 and b4 rely on in but b1/b2 don't
			 */
			*out++ = (b1 << 2) | ((b2 >> 4) & 0x3);
			b4 = (*decoder)(*in++);
			*out++ = (b2 << 4) | ((b3 >> 2) & 0xF);
			*out++ = (b3 << 6) | (b4 & 0x3F);
		}
	else {
		if(in == NULL) {	/* flush */
			int nbytes = m->base64chars;

			if(nbytes == 0)
				return out;

			m->base64chars--;
			b1 = cb1;

			if(m->base64chars) {
				m->base64chars--;
				b2 = cb2;

				if(m->base64chars) {
					m->base64chars--;
					b3 = cb3;
					assert(m->base64chars == 0);
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

		} else while(*in) {
			int nbytes;

			if(m->base64chars) {
				m->base64chars--;
				b1 = cb1;
			} else
				b1 = (*decoder)(*in++);

			if(*in == '\0') {
				b2 = '\0';
				nbytes = 1;
			} else {
				if(m->base64chars) {
					m->base64chars--;
					b2 = cb2;
				} else
					b2 = (*decoder)(*in++);

				if(*in == '\0') {
					b3 = '\0';
					nbytes = 2;
				} else {
					if(m->base64chars) {
						m->base64chars--;
						b3 = cb3;
					} else
						b3 = (*decoder)(*in++);

					if(*in == '\0') {
						b4 = '\0';
						nbytes = 3;
					} else {
						b4 = (*decoder)(*in++);
						nbytes = 4;
					}
				}
			}

			switch(nbytes) {
				case 3:
					m->base64_3 = b3;
				case 2:
					m->base64_2 = b2;
				case 1:
					m->base64_1 = b1;
					break;
				case 4:
					*out++ = (b1 << 2) | ((b2 >> 4) & 0x3);
					*out++ = (b2 << 4) | ((b3 >> 2) & 0xF);
					*out++ = (b3 << 6) | (b4 & 0x3F);
					break;
				default:
					assert(0);
			}
			if(nbytes != 4) {
				m->base64chars = nbytes;
				break;
			}
		}
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

/*
 * These are the only arguments we're interested in.
 * Do 'fgrep messageFindArgument *.c' if you don't believe me!
 * It's probably not good doing this since each time a new
 * messageFindArgument is added I need to remember to look here,
 * but it can save a lot of memory...
 */
static int
usefulArg(const char *arg)
{
	if((strncasecmp(arg, "name", 4) != 0) &&
	   (strncasecmp(arg, "filename", 8) != 0) &&
	   (strncasecmp(arg, "boundary", 8) != 0) &&
	   (strncasecmp(arg, "type", 4) != 0)) {
		cli_dbgmsg("Discarding unwanted argument '%s'\n", arg);
		return 0;
	}
	return 1;
}

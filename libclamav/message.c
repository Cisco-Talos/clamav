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
 * Revision 1.109  2004/11/07 16:39:00  nigelhorne
 * Handle para 4 of RFC2231
 *
 * Revision 1.108  2004/10/31 09:28:27  nigelhorne
 * Improve the handling of blank filenames
 *
 * Revision 1.107  2004/10/24 03:51:48  nigelhorne
 * Change encoding guess from warn to debug
 *
 * Revision 1.106  2004/10/22 17:18:13  nigelhorne
 * Handle encoding type us-ascii - should be none
 *
 * Revision 1.105  2004/10/22 15:53:45  nigelhorne
 * Fuzzy logic match for unknown encoding types
 *
 * Revision 1.104  2004/10/19 13:53:55  nigelhorne
 * Don't add trailing NUL bytes
 *
 * Revision 1.103  2004/10/17 09:29:21  nigelhorne
 * Advise to report broken emails
 *
 * Revision 1.102  2004/10/16 20:53:28  nigelhorne
 * Tidy up
 *
 * Revision 1.101  2004/10/16 13:53:52  nigelhorne
 * Handle '8 bit' and plain/text
 *
 * Revision 1.100  2004/10/14 17:45:55  nigelhorne
 * Try to reclaim some memory if it becomes low when decoding
 *
 * Revision 1.99  2004/10/12 10:40:48  nigelhorne
 * Remove shadow declaration of isblank
 *
 * Revision 1.98  2004/10/11 10:56:17  nigelhorne
 * Reimplement squeeze ads sanisiseBase64
 *
 * Revision 1.97  2004/10/06 17:21:46  nigelhorne
 * Code tidy
 *
 * Revision 1.96  2004/10/05 15:46:18  nigelhorne
 * First draft of code to handle RFC1341
 *
 * Revision 1.95  2004/10/05 10:58:00  nigelhorne
 * Table driven base64 decoding
 *
 * Revision 1.94  2004/10/04 12:18:08  nigelhorne
 * Better warning message about PGP attachments not being scanned
 *
 * Revision 1.93  2004/10/01 13:49:22  nigelhorne
 * Minor code tidy
 *
 * Revision 1.92  2004/09/30 08:58:56  nigelhorne
 * Remove empty lines
 *
 * Revision 1.91  2004/09/28 18:39:48  nigelhorne
 * Don't copy if the decoded == the encoded
 *
 * Revision 1.90  2004/09/22 16:24:22  nigelhorne
 * Fix error return
 *
 * Revision 1.89  2004/09/22 16:19:13  nigelhorne
 * Fix error return
 *
 * Revision 1.88  2004/09/21 14:55:26  nigelhorne
 * Handle blank lines in text/plain messages
 *
 * Revision 1.87  2004/09/20 12:44:03  nigelhorne
 * Fix parsing error on mime arguments
 *
 * Revision 1.86  2004/09/18 14:59:26  nigelhorne
 * Code tidy
 *
 * Revision 1.85  2004/09/17 13:47:19  nigelhorne
 * Handle yEnc attachments
 *
 * Revision 1.84  2004/09/17 09:48:53  nigelhorne
 * Handle attempts to hide mime type
 *
 * Revision 1.83  2004/09/16 15:56:45  nigelhorne
 * Handle double colons
 *
 * Revision 1.82  2004/09/16 14:23:57  nigelhorne
 * Handle quotes around mime type
 *
 * Revision 1.81  2004/09/16 12:59:36  nigelhorne
 * Handle = and space as header separaters
 *
 * Revision 1.80  2004/09/16 11:35:08  nigelhorne
 * Minor code tidy
 *
 * Revision 1.79  2004/09/16 10:05:59  nigelhorne
 * Use default decoders
 *
 * Revision 1.78  2004/09/15 18:08:23  nigelhorne
 * Handle multiple encoding types
 *
 * Revision 1.77  2004/09/13 16:44:01  kojm
 * minor cleanup
 *
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
static	char	const	rcsid[] = "$Id: message.c,v 1.109 2004/11/07 16:39:00 nigelhorne Exp $";

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifndef	CL_DEBUG
#define	NDEBUG	/* map CLAMAV debug onto standard */
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
static	unsigned char	*decodeLine(message *m, encoding_type enctype, const char *line, unsigned char *buf, size_t buflen);
static unsigned char *decode(message *m, const char *in, unsigned char *out, unsigned char (*decoder)(char), bool isFast);
static	void	sanitiseBase64(char *s);
static	unsigned	char	hex(char c);
static	unsigned	char	base64(char c);
static	unsigned	char	uudecode(char c);
static	const	char	*messageGetArgument(const message *m, int arg);
static	void	*messageExport(message *m, const char *dir, void *(*create)(void), void (*destroy)(void *), void (*setFilename)(void *, const char *, const char *), void (*addData)(void *, const unsigned char *, size_t), void *(*exportText)(const text *, void *));
static	int	usefulArg(const char *arg);
static	void	messageDedup(message *m);
static	char	*rfc2231(const char *in);
static	int	simil(const char *str1, const char *str2);

/*
 * These maps are ordered in decreasing likelyhood of their appearance
 * in an e-mail. Probably these should be in a table...
 */
static	const	struct	encoding_map {
	const	char	*string;
	encoding_type	type;
} encoding_map[] = {	/* rfc1521 */
	{	"7bit",			NOENCODING	},
	{	"text/plain",		NOENCODING	},
	{	"quoted-printable",	QUOTEDPRINTABLE	},	/* rfc1522 */
	{	"base64",		BASE64		},	/* rfc2045 */
	{	"8bit",			EIGHTBIT	},
	{	"binary",		BINARY		},
	{	"x-uuencode",		UUENCODE	},
	{	"x-yencode",		YENCODE		},
	{	"us-ascii",		NOENCODING	},	/* incorrect */
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

#define	USE_TABLE	/* table driven base64 decoder */

#ifdef	USE_TABLE
static const unsigned char base64Table[256] = {
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,62,255,255,255,63,
	52,53,54,55,56,57,58,59,60,61,255,255,255,0,255,255,
	255,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,
	15,16,17,18,19,20,21,22,23,24,25,255,255,255,255,255,
	255,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
	41,42,43,44,45,46,47,48,49,50,51,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
	255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255
};
#endif

message *
messageCreate(void)
{
	message *m = (message *)cli_calloc(1, sizeof(message));

	if(m)
		m->mimeType = NOMIME;

	return m;
}

void
messageDestroy(message *m)
{
	assert(m != NULL);

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

	if(m->encodingTypes) {
		assert(m->numberOfEncTypes > 0);
		free(m->encodingTypes);
	}

	memset(m, '\0', sizeof(message));
	m->mimeType = NOMIME;
}

/*
 * Handle the Content-Type header. The syntax is in RFC1341.
 * Return success (1) or failure (0). Failure only happens when it's an
 * unknown type and we've already received a known type, or we've received an
 * empty type. If we receive an unknown type by itself we default to application
 */
int
messageSetMimeType(message *mess, const char *type)
{
#ifdef	CL_THREAD_SAFE
	static pthread_mutex_t mime_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif
	static table_t *mime_table;
	int typeval;

	assert(mess != NULL);
	assert(type != NULL);

	cli_dbgmsg("messageSetMimeType: '%s'\n", type);

	/* Ignore leading spaces */
	while(!isalpha(*type))
		if(*type++ == '\0')
			return 0;

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
			return 0;
		}

		for(m = mime_map; m->string; m++)
			if(!tableInsert(mime_table, m->string, m->type)) {
				tableDestroy(mime_table);
				mime_table = NULL;
#ifdef	CL_THREAD_SAFE
				pthread_mutex_unlock(&mime_mutex);
#endif
				return 0;
			}
	}
#ifdef	CL_THREAD_SAFE
	pthread_mutex_unlock(&mime_mutex);
#endif

	typeval = tableFind(mime_table, type);

	if(typeval != -1) {
		mess->mimeType = typeval;
		return 1;
	} else if(mess->mimeType == NOMIME) {
		if(strncasecmp(type, "x-", 2) == 0)
			mess->mimeType = MEXTENSION;
		else {
			/*
			 * Based on a suggestion by James Stevens
			 *	<James@kyzo.com>
			 * Force scanning of strange messages
			 */
			if(strcasecmp(type, "plain") == 0) {
				cli_dbgmsg("Incorrect MIME type: `plain', set to Text\n", type);
				mess->mimeType = TEXT;
			} else {
				/*
				 * Don't handle broken e-mail probably sending
				 *	Content-Type: plain/text
				 * instead of
				 *	Content-Type: text/plain
				 * as an attachment
				 */
				cli_warnmsg("Unknown MIME type: `%s', set to Application - report to bugs@clamav.net\n", type);
				mess->mimeType = APPLICATION;
			}
		}
		return 1;
	}
	return 0;
}

mime_type
messageGetMimeType(const message *m)
{
	assert(m != NULL);

	return m->mimeType;
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
	return (m->mimeSubtype) ? m->mimeSubtype : "";
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
	return (m->mimeDispositionType) ? m->mimeDispositionType : "";
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

	m->mimeArguments[offset] = rfc2231(arg);

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

			if(key == NULL)
				return;

			ptr = strchr(key, '=');
			if(ptr == NULL)
				ptr = strchr(key, ':');
			*ptr = '\0';

			cptr++;

			string = strchr(cptr, '"');

			if((string == NULL) || (strlen(key) == 0)) {
				if(usefulArg(key))
					cli_warnmsg("Can't parse header (1) \"%s\" - report to bugs@clamav.net\n", s);
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

	return (m->mimeArguments[arg]) ? m->mimeArguments[arg] : "";
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
	int i = 0;
	char *type;
	assert(m != NULL);
	assert(enctype != NULL);

	/*m->encodingType = EEXTENSION;*/

	while((*enctype == '\t') || (*enctype == ' '))
		enctype++;

	if(strcasecmp(enctype, "8 bit") == 0) {
		cli_dbgmsg("Broken content-transfer-encoding: '8 bit' changed to '8bit'\n");
		enctype = "8bit";
	}

	/*
	 * Iterate through
	 *	Content-Transfer-Encoding: base64 binary
	 * cli_strtok's fieldno counts from 0
	 */
	i = 0;
	while((type = cli_strtok(enctype, i++, " \t")) != NULL) {
		int highestSimil = 0;
		const char *closest = NULL;

		for(e = encoding_map; e->string; e++)
			if(strcasecmp(type, e->string) == 0) {
				int j;
				encoding_type *et;

				for(j = 0; j < m->numberOfEncTypes; j++) {
					if(m->encodingTypes[j] == e->type) {
						cli_dbgmsg("Ignoring duplicate encoding mechanism\n");
						break;
					}
				}

				et = (encoding_type *)cli_realloc(m->encodingTypes, (m->numberOfEncTypes + 1) * sizeof(encoding_type));
				if(et == NULL)
					break;

				m->encodingTypes = et;
				m->encodingTypes[m->numberOfEncTypes++] = e->type;

				cli_dbgmsg("Encoding type %d is \"%s\"\n", m->numberOfEncTypes, type);
				break;

			} else {
				const int sim = simil(type, e->string);

				if(sim > highestSimil) {
					closest = e->string;
					highestSimil = sim;
				}
			}

		if(e->string == NULL) {
			/*
			 * 50% is arbitary. For example 7bi will match as
			 * 66% certain to be 7bit
			 */
			if(closest && (highestSimil >= 50)) {
				cli_dbgmsg("Unknown encoding type \"%s\" - guessing as %s (%u%% certainty)\n",
					type, closest, highestSimil);
				messageSetEncoding(m, closest);
			} else {
				cli_warnmsg("Unknown encoding type \"%s\" - report to bugs@clamav.net\n", type);
				/*
				 * Err on the side of safety, enable all
				 * decoding modules
				 */
				messageSetEncoding(m, "base64");
				messageSetEncoding(m, "quoted-printable");
			}
		}

		free(type);
	}
}

encoding_type
messageGetEncoding(const message *m)
{
	assert(m != NULL);

	if(m->numberOfEncTypes == 0)
		return NOENCODING;
	return m->encodingTypes[0];
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
	line_t *repeat = NULL;

	assert(m != NULL);

	if(data) {
		int iswhite = 1;
		const char *p;

		for(p = data; *p != '\0'; p++)
			if(!isspace(*p)) {
				iswhite = 0;
				break;
			}
		if(iswhite) {
			/*cli_dbgmsg("messageAddStr: empty line: '%s'\n", data);*/
			data = NULL;
		}
	}

	if(m->body_first == NULL)
		m->body_last = m->body_first = (text *)cli_malloc(sizeof(text));
	else {
		assert(m->body_last != NULL);
		m->body_last->t_next = (text *)cli_malloc(sizeof(text));
		if(m->body_last->t_next == NULL) {
			messageDedup(m);
			m->body_last->t_next = (text *)cli_malloc(sizeof(text));
			if(m->body_last->t_next == NULL) {
				cli_errmsg("messageAddStr: out of memory\n");
				return -1;
			}
		}

		if(data && m->body_last->t_line && (strcmp(data, lineGetData(m->body_last->t_line)) == 0))
			repeat = m->body_last->t_line;
		m->body_last = m->body_last->t_next;
	}

	if(m->body_last == NULL) {
		cli_errmsg("messageAddStr: out of memory\n");
		return -1;
	}

	m->body_last->t_next = NULL;

	if(data && *data) {
		if(repeat)
			m->body_last->t_line = lineLink(repeat);
		else
			m->body_last->t_line = lineCreate(data);

		if((m->body_last->t_line == NULL) && (repeat == NULL)) {
			messageDedup(m);
			m->body_last->t_line = lineCreate(data);

			if(m->body_last->t_line == NULL) {
				cli_errmsg("messageAddStr: out of memory\n");
				return -1;
			}
		}
		/* cli_chomp(m->body_last->t_text); */

		if(repeat == NULL)
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
		(cli_filetype(line, strlen(line)) == CL_TYPE_MAIL))
			m->bounce = m->body_last;
	else if((m->uuencode == NULL) &&
		((strncasecmp(line, "begin ", 6) == 0) &&
		(isdigit(line[6])) &&
		(isdigit(line[7])) &&
		(isdigit(line[8])) &&
		(line[9] == ' ')))
			m->uuencode = m->body_last;
	else if((m->binhex == NULL) &&
		(strncasecmp(line, binhex, sizeof(binhex) - 1) == 0))
			m->binhex = m->body_last;
	else if((m->yenc == NULL) && (strncmp(line, "=ybegin line=", 13) == 0))
		m->yenc = m->body_last;
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
	int i;

	assert(m != NULL);

	if(messageGetBody(m) == NULL)
		return NULL;

	ret = (*create)();

	if(ret == NULL)
		return NULL;

	if((t_line = binhexBegin(m)) != NULL) {
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

		m->binhex = NULL;
	}

	if(m->numberOfEncTypes == 0) {
		/*
		 * Fast copy
		 */
		filename = (char *)messageFindArgument(m, "filename");
		if(filename == NULL) {
			filename = (char *)messageFindArgument(m, "name");

			if(filename == NULL) {
				cli_dbgmsg("Attachment sent with no filename\n");
				messageAddArgument(m, "name=attachment");
			} else
				/*
				 * Some virus attachments don't say how they've
				 * been encoded. We assume base64
				 */
				messageSetEncoding(m, "base64");
		}

		(*setFilename)(ret, dir, (filename && *filename) ? filename : "attachment");

		if(filename)
			free((char *)filename);

		if(m->numberOfEncTypes == 0) {
			if(uuencodeBegin(m))
				messageSetEncoding(m, "x-uuencode");
			else
				return exportText(messageGetBody(m), ret);
		}
	}

	for(i = 0; i < m->numberOfEncTypes; i++) {
		encoding_type enctype = m->encodingTypes[i];
		size_t size;

		/*
		 * Find the filename to decode
		 */
		if((enctype == UUENCODE) || ((i == 0) && uuencodeBegin(m))) {
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
			enctype = UUENCODE;
		} else if((enctype == YENCODE) || ((i == 0) && yEncBegin(m))) {
			/*
			 * TODO: handle multipart yEnc encoded files
			 */
			t_line = yEncBegin(m);
			filename = (char *)lineGetData(t_line->t_line);

			if((filename = strstr(filename, " name=")) != NULL) {
				filename = strdup(&filename[6]);
				if(filename) {
					cli_chomp(filename);
					strstrip(filename);
					cli_dbgmsg("Set yEnc filename to \"%s\"\n", filename);
				}
			}

			(*setFilename)(ret, dir, (filename && *filename) ? filename : "attachment");
			if(filename) {
				free((char *)filename);
				filename = NULL;
			}
			t_line = t_line->t_next;
			enctype = YENCODE;
		} else {
			filename = (char *)messageFindArgument(m, "filename");
			if(filename == NULL) {
				filename = (char *)messageFindArgument(m, "name");

				if(filename == NULL) {
					cli_dbgmsg("Attachment sent with no filename\n");
					messageAddArgument(m, "name=attachment");
				} else if(enctype == NOENCODING)
					/*
					 * Some virus attachments don't say how they've
					 * been encoded. We assume base64
					 */
					messageSetEncoding(m, "base64");
			}

			(*setFilename)(ret, dir, (filename && *filename) ? filename : "attachment");

			t_line = messageGetBody(m);
		}
		if(filename)
			free((char *)filename);

		/*
		 * t_line should now point to the first (encoded) line of the message
		 */
		if(t_line == NULL) {
			cli_warnmsg("Empty attachment not saved\n");
			(*destroy)(ret);
			return NULL;
		}

		if(enctype == NOENCODING) {
			/*
			 * Fast copy
			 */
			(void)exportText(t_line, ret);
			continue;
		}

		size = 0;
		do {
			unsigned char data[1024];
			unsigned char *uptr;
			const char *line = lineGetData(t_line->t_line);

			if(enctype == UUENCODE) {
				/*
				 * There should be no blank lines in uuencoded files...
				 */
				if(line == NULL)
					continue;
				if(strcasecmp(line, "end") == 0)
					break;
			} else if(enctype == YENCODE) {
				if(line == NULL)
					continue;
				if(strncmp(line, "=yend ", 6) == 0)
					break;
			}

			uptr = decodeLine(m, enctype, line, data, sizeof(data));

			if(uptr == NULL)
				break;

			assert(uptr <= &data[sizeof(data)]);

			if(uptr != data) {
				(*addData)(ret, data, (size_t)(uptr - data));
				size += (size_t)(uptr - data);
			}

			/*
			 * According to RFC1521, '=' is used to pad out
			 * the last byte and should be used as evidence
			 * of the end of the data. Some mail clients
			 * annoyingly then put plain text after the '='
			 * byte and viruses exploit this bug. Sigh
			 */
			/*if(enctype == BASE64)
				if(strchr(line, '='))
					break;*/

		} while((t_line = t_line->t_next) != NULL);

		cli_dbgmsg("Exported %u bytes\n", size);
	}

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
	return messageExport(m, dir, (void *)fileblobCreate, (void *)fileblobDestroy, (void *)fileblobSetFilename, (void *)fileblobAddData, (void *)textToFileblob);
}

/*
 * Decode and transfer the contents of the message into a blob
 * The caller must free the returned blob
 */
blob *
messageToBlob(message *m)
{
	return messageExport(m, NULL, (void *)blobCreate, (void *)blobDestroy, (void *)blobSetFilename, (void *)blobAddData, (void *)textToBlob);
}

/*
 * Decode and transfer the contents of the message into a text area
 * The caller must free the returned text
 */
text *
messageToText(message *m)
{
	int i;
	text *first = NULL, *last = NULL;
	const text *t_line;

	assert(m != NULL);

	if(m->numberOfEncTypes == 0) {
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
			if(t_line->t_line)
				last->t_line = lineLink(t_line->t_line);
			else
				last->t_line = NULL;	/* empty line */
		}
		if(last)
			last->t_next = NULL;

		return first;
	}
	/*
	 * Scan over the data a number of times once for each claimed encoding
	 * type
	 */
	for(i = 0; i < m->numberOfEncTypes; i++) {
		const encoding_type enctype = m->encodingTypes[i];

		cli_dbgmsg("messageToText: export transfer method %d = %d\n",
			i, enctype);
		if(enctype == NOENCODING) {
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
				if(t_line->t_line)
					last->t_line = lineLink(t_line->t_line);
				else
					last->t_line = NULL;	/* empty line */
			}
			continue;
		}
		if(enctype == UUENCODE) {
			t_line = uuencodeBegin(m);

			if(t_line == NULL) {
				/*cli_warnmsg("UUENCODED attachment is missing begin statement\n");*/
				if(first)
					textDestroy(first);
				return NULL;
			}
			t_line = t_line->t_next;
		} else if(enctype == YENCODE) {
			t_line = yEncBegin(m);

			if(t_line == NULL) {
				/*cli_warnmsg("YENCODED attachment is missing begin statement\n");*/
				if(first)
					textDestroy(first);
				return NULL;
			}
			t_line = t_line->t_next;
		} else {
			if((i == 0) && binhexBegin(m))
				cli_warnmsg("Binhex messages not supported yet.\n");
			t_line = messageGetBody(m);
		}

		for(; t_line; t_line = t_line->t_next) {
			unsigned char data[1024];
			unsigned char *uptr;
			const char *line = lineGetData(t_line->t_line);

			if(enctype == BASE64) {
				/*
				 * ignore blanks - breaks RFC which is
				 * probably the point!
				 */
				if(line == NULL)
					continue;
			} else if(enctype == UUENCODE)
				if(strcasecmp(line, "end") == 0)
					break;

			uptr = decodeLine(m, enctype, line, data, sizeof(data));

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

			/*
			 * If the decoded line is the same as the encoded
			 * there's no need to take a copy, just link it.
			 * Note that the comparison is done without the
			 * trailing newline that the decoding routine may have
			 * added - that's why there's a strncmp rather than a
			 * strcmp - that'd be bad for MIME decoders, but is OK
			 * for AV software
			 */
			if((data[0] == '\n') || (data[0] == '\0'))
				last->t_line = NULL;
			else if(line && (strncmp(data, line, strlen(line)) == 0)) {
				cli_dbgmsg("messageToText: decoded line is the same(%s)\n", data);
				last->t_line = lineLink(t_line->t_line);
			} else
				last->t_line = lineCreate((char *)data);

			if(line && enctype == BASE64)
				if(strchr(line, '='))
					break;
		}
		if(m->base64chars) {
			unsigned char data[4];

			memset(data, '\0', sizeof(data));
			if(decode(m, NULL, data, base64, FALSE) && data[0]) {
				if(first == NULL)
					first = last = cli_malloc(sizeof(text));
				else {
					last->t_next = cli_malloc(sizeof(text));
					last = last->t_next;
				}

				if(last != NULL)
					last->t_line = lineCreate((char *)data);
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

const text *
yEncBegin(const message *m)
{
	return m->yenc;
}

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
		if(cli_filetype(t_line->t_text, strlen(t_line->t_text)) == CL_TYPE_MAIL)
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
decodeLine(message *m, encoding_type et, const char *line, unsigned char *buf, size_t buflen)
{
	size_t len;
	bool softbreak;
	char *p2;
	char *copy;

	assert(m != NULL);
	assert(buf != NULL);

	switch(et) {
		case BINARY:
			/*
			 * TODO: find out what this is, encoded as binary??
			 */
			/* fall through */
		case NOENCODING:
		case EIGHTBIT:
		default:	/* unknown encoding type - try our best */
			if(line)	/* empty line? */
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

			p2 = strchr(copy, '=');
			if(p2)
				*p2 = '\0';

			sanitiseBase64(copy);

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
		case YENCODE:
			if((line == NULL) || (*line == '\0'))	/* empty line */
				break;
			if(strncmp(line, "=yend ", 6) == 0)
				break;

			while(*line)
				if(*line == '=') {
					if(*++line == '\0')
						break;
					*buf++ = ((*line++ - 64) & 255);
				} else
					*buf++ = ((*line++ - 42) & 255);
			break;
	}

	*buf = '\0';
	return buf;
}

/*
 * Remove the non base64 characters such as spaces from a string. Spaces
 * shouldn't appear mid string in base64 files, but some broken mail clients
 * ignore such errors rather than discarding the mail, and virus writers
 * exploit this bug
 */
static void
sanitiseBase64(char *s)
{
#ifdef	USE_TABLE
	for(; *s; s++)
		if(base64Table[(int)*s] == 255) {
			char *p1;

			for(p1 = s; p1[0] != '\0'; p1++)
				p1[0] = p1[1];
		}
#else
	for(; *s; s++) {
		char *p1;
		char c = *s;

		if(isupper(c))
			continue;
		if(isdigit(c))
			continue;
		if(c == '+')
			continue;
		if(c == '/')
			continue;
		if(islower(c))
			continue;

		for(p1 = s; p1[0] != '\0'; p1++)
			p1[0] = p1[1];
	}
#endif
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
			int nbytes;

			if(m->base64chars == 0)
				return out;

			cli_dbgmsg("base64chars = %d (%c %c %c)\n", m->base64chars,
				cb1 ? cb1 : '@',
				cb2 ? cb2 : '@',
				cb3 ? cb3 : '@');

			m->base64chars--;
			b1 = cb1;
			nbytes = 1;

			if(m->base64chars) {
				m->base64chars--;
				b2 = cb2;

				if(m->base64chars) {
					nbytes++;
					m->base64chars--;
					b3 = cb3;
					if(b3)
						nbytes++;
				} else if(b2)
					nbytes++;
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

#ifdef	USE_TABLE
static unsigned char
base64(char c)
{
	const unsigned char ret = base64Table[(int)c];

	if(ret == 255) {
		cli_dbgmsg("Illegal character <%c> in base64 encoding\n", c);
		return 63;
	}
	return ret;
}
#else
static unsigned char
base64(char c)
{
	if(isupper(c))
		return c - 'A';
	if(isdigit(c))
		return c - '0' + 52;
	if(c == '+')
		return 62;
	if(islower(c))	/* call last, most base64 is upper case */
		return c - 'a' + 26;

	if(c != '/')
		cli_dbgmsg("Illegal character <%c> in base64 encoding\n", c);

	return 63;
}
#endif

static unsigned char
uudecode(char c)
{
	return c - ' ';
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
	   (strncasecmp(arg, "protocol", 8) != 0) &&
	   (strncasecmp(arg, "id", 2) != 0) &&
	   (strncasecmp(arg, "number", 6) != 0) &&
	   (strncasecmp(arg, "total", 5) != 0) &&
	   (strncasecmp(arg, "type", 4) != 0)) {
		cli_dbgmsg("Discarding unwanted argument '%s'\n", arg);
		return 0;
	}
	return 1;
}

/*
 * We've run out of memory. Try to recover some by
 * deduping the message
 */
static void
messageDedup(message *m)
{
	const text *t1;
	size_t saved = 0;

	t1 = m->dedupedThisFar ? m->dedupedThisFar : m->body_first;

	for(t1 = m->body_first; t1; t1 = t1->t_next) {
		const char *d1;
		text *t2;
		line_t *l1;
		unsigned int r1;

		if(saved >= 100*1000)
			break;	/* that's enough */
		l1 = t1->t_line;
		if(l1 == NULL)
			continue;
		d1 = lineGetData(l1);
		if(strlen(d1) < 8)
			continue;	/* wouldn't recover many bytes */
		r1 = (unsigned int)lineGetRefCount(l1);
		if(r1 == 255)
			continue;
		/*
		 * We don't want to foul up any pointers
		 */
		if(t1 == m->encoding)
			continue;
		if(t1 == m->bounce)
			continue;
		if(t1 == m->uuencode)
			continue;
		if(t1 == m->binhex)
			continue;
		if(t1 == m->yenc)
			continue;

		for(t2 = t1->t_next; t2; t2 = t2->t_next) {
			const char *d2;
			line_t *l2 = t2->t_line;

			if(l2 == NULL)
				continue;
			if((r1 + (unsigned int)lineGetRefCount(l2)) > 255)
				continue;
			d2 = lineGetData(l2);
			if(d1 == d2)
				/* already linked */
				continue;
			if(strcmp(d1, d2) == 0) {
				if(lineUnlink(l2) == NULL)
					saved += strlen(d1);
				t2->t_line = lineLink(l1);
				if(t2->t_line == NULL) {
					cli_errmsg("messageDedup: out of memory\n");
					return;
				}
			}
		}
	}
	m->dedupedThisFar = t1;
}

/*
 * Handle RFC2231 encoding. Returns a malloc'd buffer that the caller must
 * free, or NULL on error.
 *
 * TODO: Currently only handles paragraph 4 of RFC2231 e.g.
 *	 protocol*=ansi-x3.4-1968''application%2Fpgp-signature;
 */
static char *
rfc2231(const char *in)
{
	char *out;
	char *ptr;
	char *ret;
	enum { LANGUAGE, CHARSET, CONTENTS } field = LANGUAGE;

	ptr = strstr(in, "*=");

	if(ptr == NULL)	/* quick return */
		return strdup(in);

	cli_dbgmsg("rfc2231 '%s'\n", in);

	ret = cli_malloc(strlen(in) + 1);

	if(ret == NULL)
		return NULL;

	for(out = ret; in != ptr; in++)
		*out++ = *in;

	*out++ = '=';

	/*
	 * We don't do anything with the language and character set, just skip
	 * over them!
	 */
	while(*in) {
		switch(field) {
			case LANGUAGE:
				if(*in == '\'')
					field = CHARSET;
				break;
			case CHARSET:
				if(*in == '\'')
					field = CONTENTS;
				break;
			case CONTENTS:
				if(*in == '%') {
					unsigned char byte;

					if((*++in == '\0') || (*in == '\n'))
						break;

					byte = hex(*in);

					if((*++in == '\0') || (*in == '\n')) {
						*out++ = byte;
						break;
					}

					byte <<= 4;
					byte += hex(*in);
					*out++ = byte;
				} else
					*out++ = *in;
		}
		in++;
	}

	if(field != CONTENTS) {
		cli_warnmsg("Invalid RFC2231 header: '%s'\n", in);
		free(ret);
		return strdup("");
	}
				
	*out = '\0';

	cli_dbgmsg("rfc2231 returns '%s'\n", ret);

	return ret;
}

/*
 * common/simil:
 *	From Computing Magazine 20/8/92
 * Returns %ge number from 0 to 100 - how similar are 2 strings?
 * 100 for exact match, < for error
 */
struct	pstr_list {	/* internal stack */
	char	*d1;
	struct	pstr_list	*next;
};

#define	OUT_OF_MEMORY	(-2)
#define	FAILURE	(-3)
#define	SUCCESS	(-4)
#define	ARRAY_OVERFLOW	(-5)
typedef	struct	pstr_list	ELEMENT1;
typedef	ELEMENT1		*LINK1;

static	int	push(LINK1 *top, const char *string);
static	int	pop(LINK1 *top, char *buffer);
static	unsigned	int	compare(char *ls1, char **rs1, char *ls2, char **rs2);

#define	MAX_PATTERN_SIZ	40	/* maximum string lengths */

static int
simil(const char *str1, const char *str2)
{
	LINK1 top = NULL;
	unsigned int score = 0;
	unsigned int common, total, len1;
	unsigned int len2;
	char ls1[MAX_PATTERN_SIZ], ls2[MAX_PATTERN_SIZ];
	char *rs1 = NULL, *rs2 = NULL;
	char *s1, *s2;

	if(strcasecmp(str1, str2) == 0)
		return 100;

	if((s1 = strdup(str1)) == NULL)
		return OUT_OF_MEMORY;
	if((s2 = strdup(str2)) == NULL) {
		free(s1);
		return OUT_OF_MEMORY;
	}

	if(((total = strstrip(s1)) > MAX_PATTERN_SIZ - 1) || ((len2 = strstrip(s2)) > MAX_PATTERN_SIZ - 1)) {
		free(s1);
		free(s2);
		return ARRAY_OVERFLOW;
	}

	total += len2;

	if((push(&top, s1) == OUT_OF_MEMORY) ||
	   (push(&top, s2) == OUT_OF_MEMORY)) {
		free(s1);
		free(s2);
		return OUT_OF_MEMORY;
	}

	while(pop(&top, ls2) == SUCCESS) {
		pop(&top, ls1);
		common = compare(ls1, &rs1, ls2, &rs2);
		if(common > 0) {
			score += common;
			len1 = strlen(ls1);
			len2 = strlen(ls2);

			if((len1 > 1 && len2 >= 1) || (len2 > 1 && len1 >= 1))
				if((push(&top, ls1) == OUT_OF_MEMORY) || (push(&top, ls2) == OUT_OF_MEMORY)) {
					free(s1);
					free(s2);
					return OUT_OF_MEMORY;
				}
			len1 = strlen(rs1);
			len2 = strlen(rs2);

			if((len1 > 1 && len2 >= 1) || (len2 > 1 && len1 >= 1))
				if((push(&top, rs1) == OUT_OF_MEMORY) || (push(&top, rs2) == OUT_OF_MEMORY)) {
					free(s1);
					free(s2);
					return OUT_OF_MEMORY;
				}
		}
	}
	free(s1);
	free(s2);
	return (total > 0) ? ((score * 200) / total) : 0;
}

static unsigned int
compare(char *ls1, char **rs1, char *ls2, char **rs2)
{
	unsigned int common, diff, maxchars = 0;
	bool some_similarity = FALSE;
	char *s1, *s2;
	char *maxs1 = NULL, *maxs2 = NULL, *maxe1 = NULL, *maxe2 = NULL;
	char *cs1, *cs2, *start1, *end1, *end2;

	end1 = ls1 + strlen(ls1);
	end2 = ls2 + strlen(ls2);
	start1 = ls1;

	for(;;) {
		s1 = start1;
		s2 = ls2;

		if(s1 < end1) {
			while(s1 < end1 && s2 < end2) {
				if(tolower(*s1) == tolower(*s2)) {
					some_similarity = TRUE;
					cs1 = s1;
					cs2 = s2;
					common = 0;
					do
						if(s1 == end1 || s2 == end2)
							break;
						else {
							s1++;
							s2++;
							common++;
						}
					while(tolower(*s1) == tolower(*s2));

					if(common > maxchars) {
						diff = common - maxchars;
						maxchars = common;
						maxs1 = cs1;
						maxs2 = cs2;
						maxe1 = s1;
						maxe2 = s2;
						end1 -= diff;
						end2 -= diff;
					} else
						s1 -= common;
				} else
					s2++;
			}
			start1++;
		} else
			break;
	}
	if(some_similarity) {
		*maxs1 = '\0';
		*maxs2 = '\0';
		*rs1 = maxe1;
		*rs2 = maxe2;
	}
	return maxchars;
}

static int
push(LINK1 *top, const char *string)
{
	LINK1 element;

	if((element = (LINK1)cli_malloc(sizeof(ELEMENT1))) == NULL)
		return OUT_OF_MEMORY;
	if((element->d1 = strdup(string)) == NULL)
		return OUT_OF_MEMORY;
	element->next = *top;
	*top = element;

	return SUCCESS;
}

static int
pop(LINK1 *top, char *buffer)
{
	LINK1 t1;

	if((t1 = *top) != NULL) {
		(void)strcpy(buffer, t1->d1);
		*top = t1->next;
		free(t1->d1);
		free((char *)t1);
		return SUCCESS;
	}
	return FAILURE;
}

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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <clamav.h>

#include "table.h"
#include "mbox.h"
#include "blob.h"
#include "text.h"
#include "message.h"
#include "others.h"
#include "defaults.h"

/* FIXME: implement HAVE_STRTOK_R */
#ifndef CL_THREAD_SAFE
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

static	int	insert(message *mainMessage, blob **blobsIn, int nBlobs, text *textIn, const char *dir, table_t *rfc821Table, table_t *subtypeTable);
static	int	boundaryStart(const char *line, const char *boundary);
static	int	endOfMessage(const char *line, const char *boundary);
static	int	initialiseTables(table_t **rfc821Table, table_t **subtypeTable);
static	int	getTextPart(message *const messages[], size_t size);
static	size_t	strip(char *buf, int len);
static	size_t	strstrip(char *s);
static	bool	continuationMarker(const char *line);
static	int	parseMimeHeader(message *m, const char *cmd, const table_t *rfc821Table, const char *arg);
static	bool	saveFile(const blob *b, const char *dir);

/* Maximum number of attachements that we accept */
#define	MAX_ATTACHMENTS	10

/* Maximum line length according to RFC821 */
#define	LINE_LENGTH	1000

/* Hashcodes for our hash tables */
#define	CONTENT_TYPE			1
#define	CONTENT_TRANSFER_ENCODING	2
#define	CONTENT_DISPOSITION		3

/* Mime sub types */
#define	PLAIN		1
#define	ENRICHED	2
#define	HTML		3
#define	RICHTEXT	4
#define	MIXED		5
#define	ALTERNATIVE	6
#define	DIGEST		7
#define	SIGNED		8
#define	PARALLEL	9
#define	RELATED		10	/* RFC2387 */
#define	REPORT		11	/* RFC1892 */

static	const	struct tableinit {
	const	char	*key;
	int	value;
} rfc821headers[] = {
	{	"Content-Type:",		CONTENT_TYPE		},
	{	"Content-Transfer-Encoding:",	CONTENT_TRANSFER_ENCODING	},
	{	"Content-Disposition:",		CONTENT_DISPOSITION	},
	{	NULL,				0			}
}, mimeSubtypes[] = {
		/* subtypes of Text */
	{	"plain",	PLAIN		},
	{	"enriched",	ENRICHED	},
	{	"html",		HTML		},
	{	"richtext",	RICHTEXT	},
		/* subtypes of Multipart */
	{	"mixed",	MIXED		},
	{	"alternative",	ALTERNATIVE	},
	{	"digest",	DIGEST		},
	{	"signed",	SIGNED		},
	{	"parallel",	PARALLEL	},
	{	"related",	RELATED		},
	{	"report",	REPORT		},
	{	NULL,		0		}
};

/*
 * TODO: when signal handling is added, need to remove temp files when a
 * signal is received
 * TODO: add option to scan in memory not via temp files, perhaps with a
 * named pipe or memory mapped file?
 * TODO: if debug is enabled, catch a segfault and dump the current e-mail
 * in it's entirety, then call abort()
 * TODO: parse .msg format files
 */
int
cl_mbox(const char *dir, int desc)
{
	int retcode, i;
	bool isMbox;	/*
			 * is it a UNIX style mbox with more than one
			 * mail message, or just a single mail message?
			 */
	message *m;
	table_t	*rfc821Table, *subtypeTable;
	FILE *fd;
	char buffer[LINE_LENGTH];
#ifdef CL_THREAD_SAFE
	char *strptr;
#endif

	cli_dbgmsg("in mbox()\n");

	i = dup(desc);
	if((fd = fdopen(i, "rb")) == NULL) {
		cli_errmsg("Can't open descriptor %d\n", desc);
		close(i);
		return -1;
	}
	if(fgets(buffer, sizeof(buffer), fd) == NULL) {
		/* empty message */
		fclose(fd);
		return 0;
	}
	m = messageCreate();
	assert(m != NULL);

	if(initialiseTables(&rfc821Table, &subtypeTable) < 0) {
		messageDestroy(m);
		fclose(fd);
		return -1;
	}

	isMbox = (strncmp(buffer, "From ", 5) == 0);

	if(isMbox) {
		/*
		 * Have been asked to check a UNIX style mbox file, which
		 * may contain more than one e-mail message to decode
		 */
		bool inHeader = FALSE;
		bool inMimeHeader = FALSE;
		bool lastLineWasEmpty = TRUE;
		bool first = TRUE;

		do {
			/*cli_dbgmsg("read: %s", buffer);*/

			/*
			 * Handle this where we're mid point through this stuff
			 *	Content-Type: multipart/alternative;
			 *		boundary="----foo"
			 */
			if(inHeader && ((buffer[0] == '\t') || (buffer[0] == ' ')))
				inMimeHeader = TRUE;
			if(inMimeHeader) {
				const char *ptr;

				assert(!first);

				if(!continuationMarker(buffer))
					inMimeHeader = FALSE;	 /* no more args */

				/*
				 * Add all the arguments on the line
				 */
				for(ptr = strtok_r(buffer, ";\r\n", &strptr); ptr; ptr = strtok_r(NULL, ":\r\n", &strptr))
					messageAddArgument(m, ptr);

			} else if((!inHeader) && lastLineWasEmpty && (strncmp(buffer, "From ", 5) == 0)) {
				/*
				 * New message, save the previous message, if any
				 */
				if(!first) {
					/*
					 * End of the current message, add it and look
					 * for the start of the next one
					 */
					messageClean(m);
					if(messageGetBody(m))
						if(!insert(m,  NULL, 0, NULL, dir, rfc821Table, subtypeTable))
							break;
					/*
					 * Starting a new message, throw away all the
					 * information about the old one
					 */
					messageReset(m);
				} else
					first = FALSE;

				lastLineWasEmpty = inHeader = TRUE;
				cli_dbgmsg("Finished processing message\n");
			} else if(inHeader) {

				cli_dbgmsg("Deal with header %s", buffer);

				/*
				 * A blank line signifies the end of the header and
				 * the start of the text
				 */
				if((strstrip(buffer) == 0) || (buffer[0] == '\n') || (buffer[0] == '\r')) {
					cli_dbgmsg("End of header information\n");
					inHeader = FALSE;
				} else {
					const bool isLastLine = !continuationMarker(buffer);
					const char *cmd = strtok_r(buffer, " \t", &strptr);

					if (cmd && *cmd) {
						const char *arg = strtok_r(NULL, "\r\n", &strptr);

						if(arg)
							if(parseMimeHeader(m, cmd, rfc821Table, arg) == CONTENT_TYPE)
								inMimeHeader = !isLastLine;
					}
				}
			} else {
				assert(!first);

				/*cli_dbgmsg("adding line %s", buffer);*/

				lastLineWasEmpty = ((buffer[0] == '\n') || (buffer[0] == '\r'));
				/*
				 * Add this line to the end of the linked list
				 * of lines. This isn't needed when using
				 * .forward since the rest of the file *must*
				 * be the text so a single fread() should
				 * suffice. Still, it does no harm and is more
				 * flexible this way
				 *
				 * Note that the terminating newline is not
				 * added
				 */
				messageAddLine(m, strtok_r(buffer, "\r\n", &strptr));
			}
		} while(fgets(buffer, sizeof(buffer), fd) != NULL);
	} else {
		/* !isMbox => single mail message */
		bool inHeader = TRUE;
		bool inMimeHeader = FALSE;

		do {
			/*
			 * State machine:
			 *	inMimeHeader	= handling mime commands over
			 *				more than one line
			 *	inHeader	= handling e-mail header
			 *	otherwise	= handling e-mail body
			 */
			/*
			 * Section B.2 of RFC822 says TAB or SPACE means
			 * a continuation of the previous entry
			 */
			if(inHeader && ((buffer[0] == '\t') || (buffer[0] == ' ')))
				inMimeHeader = TRUE;
			if(inMimeHeader) {
				const char *ptr;

				assert(inHeader);

				if(!continuationMarker(buffer))
					inMimeHeader = FALSE;	 /* no more args */

				/*
				 * Add all the arguments on the line
				 */
				for(ptr = strtok_r(buffer, ";\r\n", &strptr); ptr; ptr = strtok_r(NULL, ":\r\n", &strptr))
					messageAddArgument(m, ptr);
			} else if(inHeader) {

				cli_dbgmsg("Deal with header %s", buffer);

				/*
				 * A blank line signifies the end of the header and
				 * the start of the text
				 */
				if((strstrip(buffer) == 0) || (buffer[0] == '\n') || (buffer[0] == '\r')) {
					cli_dbgmsg("End of header information\n");
					inHeader = FALSE;
				} else {
					const bool isLastLine = !continuationMarker(buffer);
					const char *cmd = strtok_r(buffer, " \t", &strptr);

					if (cmd && *cmd) {
						const char *arg = strtok_r(NULL, "\r\n", &strptr);

						if(arg)
							if(parseMimeHeader(m, cmd, rfc821Table, arg) == CONTENT_TYPE)
								inMimeHeader = !isLastLine;
					}
				}
			} else {
				/*cli_dbgmsg("adding line %s", buffer);*/

				messageAddLine(m, strtok_r(buffer, "\r\n", &strptr));
			}
		} while(fgets(buffer, sizeof(buffer), fd) != NULL);
	}

	fclose(fd);

	retcode = 0;

	/*
	 * Write out the last entry in the mailbox
	 */
	messageClean(m);
	if(messageGetBody(m))
		if(!insert(m, NULL, 0, NULL, dir, rfc821Table, subtypeTable))
			retcode = -1;

	/*
	 * Tidy up and quit
	 */
	messageDestroy(m);

	tableDestroy(rfc821Table);
	tableDestroy(subtypeTable);

	cli_dbgmsg("cli_mbox returning %d\n", retcode);

	return retcode;
}

/*
 * This is a recursive routine.
 *
 * mainMessage is the buffer to be parsed. First time of calling it'll be
 *	the whole message. Later it'll be parts of a multipart message
 * textIn is the plain text message being built up so far
 * blobsIn contains the array of attachments found so far
 *
 * Returns:
 *	0 for fail
 *	1 for success, attachements saved
 *	2 for success, attachements not saved
 */
static int	/* success or fail */
insert(message *mainMessage, blob **blobsIn, int nBlobs, text *textIn, const char *dir, table_t *rfc821Table, table_t *subtypeTable)
{
	char *ptr;
	message *messages[MAXALTERNATIVE];
	int inhead, inMimeHead, i, rc, htmltextPart, multiparts = 0;
	text *aText;
	blob *blobList[MAX_ATTACHMENTS], **blobs;
	const char *cptr;

	cli_dbgmsg("in insert(nBlobs = %d)\n", nBlobs);

	/* Pre-assertions */
	if(nBlobs >= MAX_ATTACHMENTS) {
		cli_warnmsg("Not all attachments will be scanned\n");
		return 2;
	}

	aText = textIn;
	blobs = blobsIn;

	/* Anything left to be parsed? */
	if(mainMessage && (messageGetBody(mainMessage) != NULL)) {
		int numberOfAttachments = 0;
		mime_type mimeType;
		const char *mimeSubtype;
		const text *t_line;
		bool isAlternative;
		const char *boundary;
		message *aMessage;
#ifdef CL_THREAD_SAFE
		char *strptr;
#endif

		cli_dbgmsg("Parsing mail file\n");

		mimeType = messageGetMimeType(mainMessage);
		mimeSubtype = messageGetMimeSubtype(mainMessage);

		if((mimeType == TEXT) && (tableFind(subtypeTable, mimeSubtype) == PLAIN)) {
			/*
			 * This is effectively no encoding, notice that we
			 * don't check that charset is us-ascii
			 */
			cli_dbgmsg("assume no encoding\n");
			mimeType = NOMIME;
		}

		cli_dbgmsg("mimeType = %d\n", mimeType);

		switch(mimeType) {
		case NOMIME:
			aText = textAddMessage(aText, mainMessage);
			break;
		case TEXT:
			if(tableFind(subtypeTable, mimeSubtype) == PLAIN)
				aText = textCopy(messageGetBody(mainMessage));
			break;
		case MULTIPART:

			assert(mimeSubtype[0] != '\0');

			boundary = messageFindArgument(mainMessage, "boundary");

			if(boundary == NULL) {
				cli_warnmsg("Multipart MIME message contains no boundaries\n");
				return 2;	/* Broken e-mail message */
			}


			/*
			 * Get to the start of the first message
			 */
			for(t_line = messageGetBody(mainMessage); t_line; t_line = t_line->t_next) {
				if(boundaryStart(t_line->t_text, boundary)) {
					break;
				}
			}

			if(t_line == NULL) {
				cli_warnmsg("Multipart MIME message contains no parts\n");
				free((char *) boundary);	/* this was strdup()'d *TL*/
				return 2;	/* Nothing to do */
			}
			/*
			 * Build up a table of all of the parts of this
			 * multipart message. Remember, each part may itself
			 * be a multipart message.
			 */
			inhead = 1;
			inMimeHead = 0;

			for(multiparts = 0; t_line && (multiparts < MAXALTERNATIVE); multiparts++) {
				aMessage = messages[multiparts] = messageCreate();

				cli_dbgmsg("Now read in part %d\n", multiparts);

				/* tk: shut up parentheses warning */
				while((t_line = t_line->t_next)) {
					const char *line = t_line->t_text;

					/*cli_dbgmsg("inMimeHead %d inhead %d boundary %s line %s\n",
						inMimeHead, inhead, boundary, line);*/

					if(inMimeHead) {
						while(isspace((int)*line))
							line++;

						if(*line == '\0') {
							inhead = inMimeHead = 0;
							continue;
						}
						cli_dbgmsg("About to add mime Argument '%s'\n",
							line);
						/*
						 * This may cause a trailing ';'
						 * to be added if this test
						 * fails - TODO: verify this
						 */
						inMimeHead = continuationMarker(line);
						messageAddArgument(aMessage, line);
					} else if(inhead) {
						char *copy, *arg;

						if(strlen(line) == 0) {
							inhead = 0;
							continue;
						}
						/*
						 * Some clients are broken and
						 * put white space after the ;
						 */
						inMimeHead = continuationMarker(line);
						copy = strdup(line);
						ptr = strtok_r(copy, " \t", &strptr);

						switch(tableFind(rfc821Table, ptr)) {
						case CONTENT_TYPE:
							cli_dbgmsg("insert content-type: parse line '%s'\n", line);
							arg = strtok_r(NULL, "\r\n", &strptr);
							if((arg == NULL) || (strchr(arg, '/') == NULL)) {
								cli_warnmsg("Invalid content-type '%s' received, no subtype specified, assuming text/plain; charset=us-ascii\n", arg);
								messageSetMimeType(aMessage, "text");
								messageSetMimeSubtype(aMessage, "plain");
							} else {
								messageSetMimeType(aMessage, strtok_r(arg, "/", &strptr));
								messageSetMimeSubtype(aMessage, strtok_r(NULL, ";", &strptr));
								ptr = strtok_r(NULL, "\r\n", &strptr);
								if(ptr)
									messageAddArguments(aMessage, ptr);
							}
							break;
						case CONTENT_TRANSFER_ENCODING:
							messageSetEncoding(aMessage, strtok_r(NULL, "", &strptr));
							break;
						case CONTENT_DISPOSITION:
							messageSetDispositionType(aMessage, strtok_r(NULL, ";", &strptr));
							messageAddArgument(aMessage, strtok_r(NULL, "", &strptr));
							break;
						}
						free(copy);
					} else if(boundaryStart(line, boundary)) {
						inhead = 1;
						break;
					} else if(endOfMessage(line, boundary)) {
						/*
						 * Some viruses put information
						 * *after* the end of message,
						 * which presumably some broken
						 * mail clients find, so we
						 * can't assume that this
						 * is the end of the message
						 */
						/* t_line = NULL;*/
						break;
					} else
						messageAddLine(aMessage, line);
				}
				messageClean(aMessage);
			}

			free((char *)boundary);

			if(multiparts == 0)
				return 2;	/* Nothing to do */

			cli_dbgmsg("The message has %d parts\n", multiparts);
			cli_dbgmsg("Find out the multipart type(%s)\n", mimeSubtype);

			switch(tableFind(subtypeTable, mimeSubtype)) {
			case RELATED:
				/*
				 * Look for the text bit
				 */
				aMessage = NULL;
				assert(multiparts > 0);

				htmltextPart = getTextPart(messages, multiparts);

				if(htmltextPart >= 0)
					aText = textAddMessage(aText, messages[htmltextPart]);
				else
					/*
					 * There isn't a text bit. If there's a
					 * multipart bit, it'll probably be in
					 * there somewhere
					 */
					for(i = 0; i < multiparts; i++)
						if(messageGetMimeType(messages[i]) == MULTIPART) {
							aMessage = messages[i];
							htmltextPart = i;
							break;
						}

				assert(htmltextPart != -1);

				rc = insert(aMessage, blobs, nBlobs, aText, dir, rfc821Table, subtypeTable);
				blobArrayDestroy(blobs, nBlobs);
				blobs = NULL;
				nBlobs = 0;

				/*
				 * Fixed based on an idea from Stephen White <stephen@earth.li>
				 * The message is confused about the difference
				 * between alternative and related. Badtrans.B
				 * suffers from this problem.
				 *
				 * Fall through in this case:
				 * Content-Type: multipart/related;
				 *	type="multipart/alternative"
				 */
				cptr = messageFindArgument(mainMessage, "type");
				if(cptr == NULL)
					break;
				isAlternative = (bool)(strcasecmp(cptr, "multipart/alternative") == 0);
				free((char *)cptr);
				if(!isAlternative)
					break;
			case ALTERNATIVE:
				cli_dbgmsg("Multipart alternative handler\n");

				htmltextPart = getTextPart(messages, multiparts);

				if(htmltextPart == -1)
					htmltextPart = 0;

				aMessage = messages[htmltextPart];
				aText = textAddMessage(aText, aMessage);

				rc = insert(NULL, blobs, nBlobs, aText, dir, rfc821Table, subtypeTable);
				if(rc == 1) {
					/*
					 * Alternative message has saved its
					 * attachments, ensure we don't do
					 * the same thing
					 */
					blobArrayDestroy(blobs, nBlobs);
					blobs = NULL;
					nBlobs = 0;
					rc = 2;
				}
				/*
				 * Fall through - some clients are broken and
				 * say alternative instead of mixed. The Klez
				 * virus is broken that way
				 */
			case REPORT:
				/*
				 * According to section 1 of RFC1892, the
				 * syntax of multipart/report is the same
				 * as multipart/mixed. There are some required
				 * parameters, but there's no need for us to
				 * verify that they exist
				 */
			case MIXED:
				/*
				 * Look for attachments
				 *
				 * Not all formats are supported. If an
				 * unsupported format turns out to be
				 * common enough to implement, it is a simple
				 * matter to add it
				 */
				if(aText)
					mainMessage = NULL;

#ifdef	CL_DEBUG
				cli_dbgmsg("Mixed message with %d parts\n", multiparts);
#endif
				for(i = 0; i < multiparts; i++) {
					bool addAttachment = FALSE;
					bool addToText = FALSE;
					const char *dtype;
					text *t;

					aMessage = messages[i];

					assert(aMessage != NULL);

					dtype = messageGetDispositionType(aMessage);
					cptr = messageGetMimeSubtype(aMessage);

#ifdef	CL_DEBUG
					cli_dbgmsg("Mixed message part %d is of type %d\n",
						i, messageGetMimeType(aMessage));
#endif

					switch(messageGetMimeType(aMessage)) {
					case APPLICATION:
#if	0
						/* strict checking... */
						if((strcasecmp(dtype, "attachment") == 0) ||
						   (strcasecmp(cptr, "x-msdownload") == 0) ||
						   (strcasecmp(cptr, "octet-stream") == 0) ||
						   (strcasecmp(dtype, "octet-stream") == 0))
							addAttachment = TRUE;
						else {
							cli_dbgmsg("Discarded mixed/application not sent as attachment\n");
							continue;
						}
#endif
						addAttachment = TRUE;

						break;
					case NOMIME:
						mainMessage = NULL;
						addToText = TRUE;
						if(messageGetBody(aMessage) == NULL)
							/*
							 * No plain text version
							 */
							messageAddLine(aMessage, "No plain text alternative");
						assert(messageGetBody(aMessage) != NULL);
						break;
					case TEXT:
						if(strcasecmp(dtype, "attachment") == 0)
							addAttachment = TRUE;
						else if((*dtype == '\0') || (strcasecmp(dtype, "inline") == 0)) {
							mainMessage = NULL;
							/*
							 * Strictly speaking
							 * a text/html part is
							 * not an attachment. We
							 * pretend it is so that
							 * we can decode and
							 * scan it
							 */
							if(strcasecmp(messageGetMimeSubtype(aMessage), "plain") == 0)
								addToText = TRUE;
							else {
								messageAddArgument(aMessage, "filename=textportion");
								addAttachment = TRUE;
							}
						} else {
							cli_dbgmsg("Text type %s is not supported", dtype);
							continue;
						}
						break;
					case MESSAGE:
						cli_dbgmsg("Found message inside multipart\n");
						rc = insert(aMessage, blobs, nBlobs, NULL, dir, rfc821Table, subtypeTable);
						continue;
					case MULTIPART:
						/*
						 * It's a multi part within a multi part
						 * Run the message parser on this bit, it won't
						 * be an attachment
						 *
						 */
						cli_dbgmsg("Found multipart inside multipart\n");
						t = messageToText(aMessage);
						rc = insert(aMessage, blobs, nBlobs, t, dir, rfc821Table, subtypeTable);
						textDestroy(t);

						mainMessage = aMessage;
						continue;
					case AUDIO:
					case IMAGE:
						/*
						 * TODO: it may be nice to
						 * have an option to throw
						 * away all images and sound
						 * files for ultra-secure sites
						 */
						addAttachment = TRUE;
						break;
					default:
						cli_dbgmsg("Only text and application attachments are supported, type = %d\n",
							messageGetMimeType(aMessage));
						continue;
					}

					/*
					 * It must be either text or
					 * an attachment. It can't be both
					 */
					assert(addToText || addAttachment);
					assert(!(addToText && addAttachment));

					if(addToText)
						aText = textAdd(aText, messageGetBody(aMessage));
					else if(addAttachment) {
						blob *aBlob = messageToBlob(aMessage);

						if(aBlob) {
							assert(blobGetFilename(aBlob) != NULL);
							/*if(blobGetDataSize(aBlob) > 0)*/
								blobList[numberOfAttachments++] = aBlob;
						}
					}
				}

				if(numberOfAttachments == 0) {
					/* No usable attachment was found */
					rc = insert(NULL, NULL, 0, aText, dir, rfc821Table, subtypeTable);
					break;
				}
				/*
				 * Store any existing attachments at the end of
				 * the list we've just built up
				 */
				for(i = 0; i < nBlobs; i++) {
#ifdef	CL_DEBUG
					assert(blobs[i]->magic == BLOB);
#endif
					blobList[numberOfAttachments++] = blobs[i];
				}

				rc = insert(mainMessage, blobList, numberOfAttachments, aText, dir, rfc821Table, subtypeTable);
				break;
			case DIGEST:
			case SIGNED:
			case PARALLEL:
				/*
				 * If we're here it could be because we have a
				 * multipart/mixed message, consisting of a
				 * message followed by an attachment. That
				 * message itself is a multipart/alternative
				 * message and we need to dig out the plain
				 * text part of that alternative
				 */
				htmltextPart = getTextPart(messages, multiparts);
				if(htmltextPart == -1)
					htmltextPart = 0;

				rc = insert(messages[htmltextPart], blobs, nBlobs, aText, dir, rfc821Table, subtypeTable);
				blobArrayDestroy(blobs, nBlobs);
				blobs = NULL;
				nBlobs = 0;
				break;
			default:
				/*
				 * According to section 7.2.6 of RFC1521,
				 * unrecognised multiparts should be treated as
				 * multipart/mixed. I don't do this yet so
				 * that I can see what comes along...
				 */
				cli_warnmsg("Unsupported multipart format `%s'\n", mimeSubtype);
				rc = 0;
			}

			for(i = 0; i < multiparts; i++)
				messageDestroy(messages[i]);

			if(blobs && (blobsIn == NULL))
				puts("arraydestroy");

			if(aText && (textIn == NULL))
				textDestroy(aText);

			return rc;

		case MESSAGE:
			/*
			 * Check for forbidden encodings
			 */
			switch(messageGetEncoding(mainMessage)) {
				case NOENCODING:
				case EIGHTBIT:
				case BINARY:
					break;
				default:
					cli_warnmsg("MIME type 'message' cannot be decoded\n");
					break;
			}
			if((strcasecmp(mimeSubtype, "rfc822") == 0) ||
			   (strcasecmp(mimeSubtype, "delivery-status") == 0)) {
				/*
				 * TODO: Tidy this up, it's just a duplicate
				 * of the cl_mbox code....
				 */
				text *msgText = messageToText(mainMessage);
				text *t = msgText;
				bool inHeader = TRUE;
				bool inMimeHeader = FALSE;
				message *m;

				assert(t != NULL);

				m = messageCreate();
				assert(m != NULL);

				cli_dbgmsg("Decode rfc822");

				/*
				 * Since by using the forward facility, the program is spawned each
				 * time a mail comes in this loop, which looks at each new item in
				 * the mailbox, probably isn't needed. It's in here incase the forward
				 * mechanism is dropped, and it doesn't really add too much
				 */
				do {
					char *buffer = strdup(t->t_text);

					/*
					 * Handle this where we're mid point through this stuff
					 *	Content-Type: multipart/alternative;
					 *		boundary="----foo"
					 */
					if(inMimeHeader) {
						const char *ptr;

						/*
						 * Some clients are broken and put white space after
						 * the ;
						 */
						if(!continuationMarker(buffer))
							inMimeHeader = FALSE;	 /* no more args */

						/*
						 * Add all the arguments on the line
						 */
						for(ptr = strtok_r(buffer, ";\r\n", &strptr); ptr; ptr = strtok_r(NULL, ":\r\n", &strptr))
							messageAddArgument(m, ptr);

					} else if(inHeader) {
						/*
						 * A blank line signifies the end of the header and
						 * the start of the text
						 */
						strstrip(buffer);

						if((buffer[0] == '\n') || (buffer[0] == '\r'))
							inHeader = 0;
						else {
							const bool isLastLine = !continuationMarker(buffer);
							const char *cmd = strtok_r(buffer, " \t", &strptr);

							if (cmd && *cmd) {
								const char *arg = strtok_r(NULL, "\r\n", &strptr);

								if(arg)
									if(parseMimeHeader(m, cmd, rfc821Table, arg) == CONTENT_TYPE)
										inMimeHeader = !isLastLine;
							}
						}
					} else {
						messageAddLine(m, strtok_r(buffer, "\r\n", &strptr));
					}
					free(buffer);
				} while((t = t->t_next) != NULL);


				textDestroy(msgText);
				messageClean(m);
				if(messageGetBody(m))
					rc = insert(m, NULL, 0, NULL, dir, rfc821Table, subtypeTable);

				messageDestroy(m);

				cli_dbgmsg("End of rfc822\n");
				break;
			} else if(strcasecmp(mimeSubtype, "partial") == 0) {
				/* TODO */
				cli_warnmsg("Content-type message/partial not yet supported");
			} else if(strcasecmp(mimeSubtype, "external-body") == 0) {
				/*
				 * I don't believe that we should be going
				 * around the Internet looking for referenced
				 * files...
				 */
				cli_warnmsg("Attempt to send Content-type message/external-body trapped");
			} else {
				cli_warnmsg("Unsupported message format `%s'\n", mimeSubtype);
			}

			return 0;

		case APPLICATION:
			cptr = messageGetMimeSubtype(mainMessage);

			if((strcasecmp(cptr, "octet-stream") == 0) ||
			   (strcasecmp(cptr, "x-msdownload") == 0)) {
				blob *aBlob = messageToBlob(mainMessage);

				if(aBlob) {
					cli_dbgmsg("Saving main message as attachment %d\n", nBlobs);
					assert(blobGetFilename(aBlob) != NULL);
					/*
					 * It's likely that we won't have built
					 * a set of attachments
					 */
					if(blobs == NULL)
						blobs = blobList;
					for(i = 0; i < nBlobs; i++)
						if(blobs[i] == NULL)
							break;
					blobs[i] = aBlob;
					if(i == nBlobs) {
						nBlobs++;
						assert(nBlobs < MAX_ATTACHMENTS);
					}
				}
			} else
				cli_warnmsg("Discarded application not sent as attachment\n");
			break;

		case AUDIO:
		case VIDEO:
		case IMAGE:
			break;

		default:
			cli_warnmsg("Message received with unknown mime encoding");
			break;
		}
	}

#ifdef	CL_DEBUG
	cli_dbgmsg("%d attachments found\n", nBlobs);
#endif

	if(nBlobs == 0) {
		blob *b;

		/*
		 * No attachments - scan the text portions, often files
		 * are hidden in HTML code
		 */

#ifdef	CL_DEBUG
		cli_dbgmsg("%d multiparts found\n", multiparts);
#endif
		for(i = 0; i < multiparts; i++) {
			b = messageToBlob(messages[i]);

			assert(b != NULL);

#ifdef	CL_DEBUG
			cli_dbgmsg("Saving multipart %d, encoded with scheme %d\n",
				i, messageGetEncoding(messages[i]));
#endif

			(void)saveFile(b, dir);

			blobDestroy(b);
		}

		if(mainMessage) {
			/*
			 * Look for uu-encoded main file
			 */
			const text *t_line;

			for(t_line = messageGetBody(mainMessage); t_line; t_line = t_line->t_next) {
				const char *line = t_line->t_text;

				if((strncasecmp(line, "begin ", 6) == 0) &&
				   (isdigit(line[6])) &&
				   (isdigit(line[7])) &&
				   (isdigit(line[8])) &&
				   (line[9] == ' '))
					break;
			}

			if(t_line != NULL) {
				/*
				 * Main part contains uuencoded section
				 */
				messageSetEncoding(mainMessage,	"x-uuencode");

				if((b = messageToBlob(mainMessage)) != NULL) {
					if((cptr = blobGetFilename(b)) != NULL) {
						cli_dbgmsg("Found uuencoded message %s\n", cptr);

						(void)saveFile(b, dir);
					}
					blobDestroy(b);
				}
			} else {
				messageAddArgument(mainMessage, "filename=textportion");
				if((b = messageToBlob(mainMessage)) != NULL) {
					/*
					 * Save main part to scan that
					 */
					cli_dbgmsg("Saving main message, encoded with scheme %d\n",
						messageGetEncoding(mainMessage));

					(void)saveFile(b, dir);

					blobDestroy(b);
				}
			}
		}
	} else {
		short attachmentNumber;

		for(attachmentNumber = 0; attachmentNumber < nBlobs; attachmentNumber++) {
			blob *b = blobs[attachmentNumber];

			if(b) {
				if(!saveFile(b, dir))
					break;
				blobDestroy(b);
				blobs[attachmentNumber] = NULL;
			}
		}
	}

	if(aText && (textIn == NULL))
		textDestroy(aText);

	/* Already done */
	if(blobs && (blobsIn == NULL))
		blobArrayDestroy(blobs, nBlobs);

	cli_dbgmsg("insert() returning 1\n");

	return 1;
}

/*
 * Is the current line the start of a new section?
 *
 * New sections start with --boundary
 */
static int
boundaryStart(const char *line, const char *boundary)
{
	/*
	 * Gibe.B3 is broken it has:
	 *	boundary="---- =_NextPart_000_01C31177.9DC7C000"
	 * but it's boundaries look like
	 *	------ =_NextPart_000_01C31177.9DC7C000
	 * notice the extra '-'
	 */
	if(strstr(line, boundary) != NULL) {
		cli_dbgmsg("found %s in %s\n", boundary, line);
		return 1;
	}
	if(*line++ != '-')
		return 0;
	if(*line++ != '-')
		return 0;
	return strcasecmp(line, boundary) == 0;
}

/*
 * Is the current line the end?
 *
 * The message ends with with --boundary--
 */
static int
endOfMessage(const char *line, const char *boundary)
{
	size_t len;

	if(*line++ != '-')
		return 0;
	if(*line++ != '-')
		return 0;
	len = strlen(boundary);
	if(strncasecmp(line, boundary, len) != 0)
		return 0;
	if(strlen(line) != (len + 2))
		return 0;
	line = &line[len];
	if(*line++ != '-')
		return 0;
	return *line == '-';
}

/*
 * Initialise the various lookup tables
 */
static int
initialiseTables(table_t **rfc821Table, table_t **subtypeTable)
{
	const struct tableinit *tableinit;

	/*
	 * Initialise the various look up tables
	 */
	*rfc821Table = tableCreate();
	assert(*rfc821Table != NULL);

	for(tableinit = rfc821headers; tableinit->key; tableinit++)
		if(tableInsert(*rfc821Table, tableinit->key, tableinit->value) < 0)
			return -1;

	*subtypeTable = tableCreate();
	assert(*subtypeTable != NULL);

	for(tableinit = mimeSubtypes; tableinit->key; tableinit++)
		if(tableInsert(*subtypeTable, tableinit->key, tableinit->value) < 0) {
			tableDestroy(*rfc821Table);
			return -1;
		}

	return 0;
}

/*
 * If there's a HTML text version use that, otherwise
 * use the first text part, otherwise just use the
 * first one around. HTML text is most likely to include
 * a scripting worm
 *
 * If we can't find one, return -1
 */
static int
getTextPart(message *const messages[], size_t size)
{
	size_t i;

	for(i = 0; i < size; i++) {
		assert(messages[i] != NULL);
		if((messageGetMimeType(messages[i]) == TEXT) &&
		   (strcasecmp(messageGetMimeSubtype(messages[i]), "html") == 0))
			return (int)i;
	}
	for(i = 0; i < size; i++)
		if(messageGetMimeType(messages[i]) == TEXT)
			return (int)i;

	return -1;
}

/*
 * strip -
 *	Remove the trailing spaces from a buffer
 * Returns it's new length (a la strlen)
 *
 * len must be int not size_t because of the >= 0 test, it is sizeof(buf)
 *	not strlen(buf)
 */
static size_t
strip(char *buf, int len)
{
	register char *ptr;
	register size_t i;

	if((buf == NULL) || (len <= 0))
		return(0);

	i = strlen(buf);
	if(len > (int)(i + 1))
		return(i);

	ptr = &buf[--len];

#if	defined(UNIX) || defined(C_LINUX) || defined(C_DARWIN)	/* watch - it may be in shared text area */
	do
		if(*ptr)
			*ptr = '\0';
	while((--len >= 0) && !isgraph(*--ptr) && (*ptr != '\n') && (*ptr != '\r'));
#else	/* more characters can be displayed on DOS */
	do
#ifndef	REAL_MODE_DOS
		if(*ptr)	/* C8.0 puts into a text area */
#endif
			*ptr = '\0';
	while((--len >= 0) && ((*--ptr == '\0') || (isspace((int)*ptr))));
#endif
	return((size_t)(len + 1));
}

/*
 * strstrip:
 *	Strip a given string
 */
static size_t
strstrip(char *s)
{
	if(s == (char *)NULL)
		return(0);
	return(strip(s, strlen(s) + 1));
}

/*
 * When parsing a MIME header see if this spans more than one line. A
 * semi-colon at the end of the line indicates that the MIME information
 * is continued on the next line.
 *
 * Some clients are broken and put white space after the ;
 */
static bool
continuationMarker(const char *line)
{
	const char *ptr;

	assert(line != NULL);

#ifdef	CL_DEBUG
	cli_dbgmsg("continuationMarker(%s)\n", line);
#endif

	if(strlen(line) == 0)
		return FALSE;

	ptr = strchr(line, '\0');

	assert(ptr != NULL);

	while(ptr > line)
		switch(*--ptr) {
			case '\n':
			case '\r':
			case ' ':
			case '\t':
				continue;
			case ';':
				return TRUE;
			default:
				return FALSE;
		}

	return FALSE;
}

static int
parseMimeHeader(message *m, const char *cmd, const table_t *rfc821Table, const char *arg)
{
	int type = tableFind(rfc821Table, cmd);
#ifdef CL_THREAD_SAFE
	char *strptr;
#endif
	char *copy = strdup(arg);
	char *ptr = copy;

	cli_dbgmsg("parseMimeHeader: cmd='%s', arg='%s'\n", cmd, arg);

	switch(type) {
		case CONTENT_TYPE:
			/*
			 * Fix for non RFC1521 compliant mailers
			 * that send content-type: Text instead
			 * of content-type: Text/Plain, or
			 * just simply "Content-Type:"
			 */
			if(copy == NULL)
				  cli_warnmsg("Empty content-type received, no subtype specified, assuming text/plain; charset=us-ascii\n");
			else if(strchr(copy, '/') == NULL)
				  cli_warnmsg("Invalid content-type '%s' received, no subtype specified, assuming text/plain; charset=us-ascii\n", copy);
			else {
				char *s;
				/*
				 * Some clients are broken and
				 * put white space after the ;
				 */
				strstrip(copy);
				messageSetMimeType(m, strtok_r(copy, "/", &strptr));

				/*
				 * Stephen White <stephen@earth.li>
				 * Some clients put space after
				 * the mime type but before
				 * the ;
				 */
				s = strtok_r(NULL, ";", &strptr);
				strstrip(s);
				messageSetMimeSubtype(m, s);

				/*
				 * Add in all the arguments.
				 */
				while((copy = strtok_r(NULL, "\r\n \t", &strptr)))
					messageAddArgument(m, copy);
			}
			break;
		case CONTENT_TRANSFER_ENCODING:
			messageSetEncoding(m, copy);
			break;
		case CONTENT_DISPOSITION:
			messageSetDispositionType(m, strtok_r(copy, ";", &strptr));
			messageAddArgument(m, strtok_r(NULL, "\r\n", &strptr));
	}
	free(ptr);

	return type;
}

static bool
saveFile(const blob *b, const char *dir)
{
	unsigned long nbytes = blobGetDataSize(b);
	int fd;
	const char *cptr, *suffix;
#ifdef	NAME_MAX	/* e.g. Linux */
	char filename[NAME_MAX + 1];
#else
#ifdef	MAXNAMELEN	/* e.g. Solaris */
	char filename[MAXNAMELEN + 1];
#endif
#endif

	assert(dir != NULL);

	if(nbytes == 0)
		return TRUE;

	cptr = blobGetFilename(b);

	if(cptr == NULL) {
		cptr = "unknown";
		suffix = "";
	} else {
		/*
		 * Some programs are broken and use an idea of a ".suffix"
		 * to determine the file type rather than looking up the
		 * magic number. CPM has a lot to answer for...
		 * FIXME: the suffix now appears twice in the filename...
		 */
		suffix = strrchr(cptr, '.');
		if(suffix == NULL)
			suffix = "";
	}
	cli_dbgmsg("Saving attachment in %s/%s\n", dir, cptr);

	/*
	 * Allow for very long filenames. We have to truncate them to fit
	 */
	snprintf(filename, sizeof(filename) - 7, "%s/%s", dir, cptr);
	strcat(filename, "XXXXXX");

	/*
	 * TODO: add a HAS_MKSTEMP property
	 */
#if	defined(C_LINUX) || defined(C_BSD) || defined(HAVE_MKSTEMP)
	fd = mkstemp(filename);
#else
	(void)mktemp(filename);
	fd = open(filename, O_WRONLY|O_CREAT|O_EXCL|O_TRUNC, 0600);
#endif

	if(fd < 0) {
		cli_errmsg("%s: %s\n", filename, strerror(errno));
		return FALSE;
	}

	/*
	 * Add the suffix back to the end of the filename. Tut-tut, filenames
	 * should be independant of their usage on UNIX type systems.
	 */
	if(strlen(suffix) > 1) {
		char *stub = strdup(filename);

		strcat(filename, suffix);
		link(stub, filename);
		unlink(stub);
		free(stub);
	}

	write(fd, blobGetData(b), (size_t)nbytes);
	cli_dbgmsg("Attachment saved as %s (%lu bytes long)\n",
		filename, nbytes);

	return (close(fd) >= 0);
}

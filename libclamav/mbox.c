/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Nigel Horne
 * 
 *  Acknowledgements: Some ideas came from Stephen White <stephen@earth.li>,
 *                    Michael Dankov <misha@btrc.ru>, Gianluigi Tiesi <sherpya@netfarm.it>,
 *                    Everton da Silva Marques, Thomas Lamy <Thomas.Lamy@in-online.net>,
 *                    James Stevens <James@kyzo.com>
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

#ifdef CL_THREAD_SAFE
#ifndef	_REENTRANT
#define	_REENTRANT	/* for Solaris 2.8 */
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#ifdef	HAVE_STRINGS_H
#include <strings.h>
#endif
#ifdef	HAVE_STRING_H
#include <string.h>
#endif
#include <ctype.h>
#include <time.h>
#include <fcntl.h>
#ifdef	HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <dirent.h>
#include <limits.h>
#include <signal.h>

#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif

#if defined(HAVE_READDIR_R_3) || defined(HAVE_READDIR_R_2)
#include <stddef.h>
#endif

#ifdef	CL_THREAD_SAFE
#include <pthread.h>
#endif

#include "clamav.h"
#include "others.h"
#include "str.h"
#include "filetypes.h"
#include "mbox.h"
#include "dconf.h"
#include "fmap.h"
#include "json_api.h"
#include "msxml_parser.h"

#if HAVE_LIBXML2
#include <libxml/xmlversion.h>
#include <libxml/HTMLtree.h>
#include <libxml/HTMLparser.h>
#include <libxml/xmlreader.h>
#endif

#define DCONF_PHISHING mctx->ctx->dconf->phishing

#ifdef	CL_DEBUG

#if	defined(C_LINUX)
#include <features.h>
#endif

#if __GLIBC__ == 2 && __GLIBC_MINOR__ >= 1
#define HAVE_BACKTRACE
#endif
#endif

#ifdef HAVE_BACKTRACE
#include <execinfo.h>
#include <syslog.h>

static	void	sigsegv(int sig);
static	void	print_trace(int use_syslog);

/*#define	SAVE_TMP */	/* Save the file being worked on in tmp */
#endif

#if	defined(NO_STRTOK_R) || !defined(CL_THREAD_SAFE)
#undef strtok_r
#undef __strtok_r
#define strtok_r(a,b,c)	strtok(a,b)
#endif

#ifdef	HAVE_STDBOOL_H
#ifdef	C_BEOS
#include "SupportDefs.h"
#else
#include <stdbool.h>
#endif
#else
#ifdef	FALSE
typedef	unsigned	char	bool;
#else
typedef enum	{ FALSE = 0, TRUE = 1 } bool;
#endif
#endif

typedef	enum {
	FAIL,
	OK,
	OK_ATTACHMENTS_NOT_SAVED,
	VIRUS,
	MAXREC,
	MAXFILES
} mbox_status;

#ifndef isblank
#define isblank(c)	(((c) == ' ') || ((c) == '\t'))
#endif

#define	SAVE_TO_DISC	/* multipart/message are saved in a temporary file */

#include "htmlnorm.h"

#include "phishcheck.h"

#ifndef	_WIN32
#include <sys/time.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#if !defined(C_BEOS) && !defined(C_INTERIX)
#include <net/if.h>
#include <arpa/inet.h>
#endif
#endif

#include <fcntl.h>

/*
 * Use CL_SCAN_MAIL_PARTIAL_MESSAGE to handle messages covered by section 7.3.2 of RFC1341.
 *	This is experimental code so it is up to YOU to (1) ensure it's secure
 * (2) periodically trim the directory of old files
 *
 * If you use the load balancing feature of clamav-milter to run clamd on
 * more than one machine you must make sure that .../partial is on a shared
 * network filesystem
 */
/*#define	NEW_WORLD*/

/*#define	SCAN_UNENCODED_BOUNCES	*//*
					 * Slows things down a lot and only catches unencoded copies
					 * of EICAR within bounces, which don't matter
					 */

typedef	struct	mbox_ctx {
	const	char	*dir;
	const	table_t	*rfc821Table;
	const	table_t	*subtypeTable;
	cli_ctx	*ctx;
	unsigned	int	files;	/* number of files extracted */
#if HAVE_JSON
	json_object *wrkobj;
#endif
} mbox_ctx;

/* if supported by the system, use the optimized
 * version of getc, that doesn't do locking,
 * and is possibly implemented entirely as a macro */
#if defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200112L
#define GETC(fp) getc_unlocked(fp)
#define LOCKFILE(fp) flockfile(fp)
#define UNLOCKFILE(fp) funlockfile(fp)
#else
#define GETC(fp) getc(fp)
#define LOCKFILE(fp)
#define UNLOCKFILE(fp)
#endif

static	int	cli_parse_mbox(const char *dir, cli_ctx *ctx);
static	message	*parseEmailFile(fmap_t *map, size_t *at, const table_t *rfc821Table, const char *firstLine, const char *dir);
static	message	*parseEmailHeaders(message *m, const table_t *rfc821Table);
static	int	parseEmailHeader(message *m, const char *line, const table_t *rfc821Table);
static	int	parseMHTMLComment(const char *comment, cli_ctx *ctx, void *wrkjobj, void *cbdata);
static	mbox_status	parseRootMHTML(mbox_ctx *mctx, message *m, text *t);
static	mbox_status	parseEmailBody(message *messageIn, text *textIn, mbox_ctx *mctx, unsigned int recursion_level);
static	int	boundaryStart(const char *line, const char *boundary);
static	int	boundaryEnd(const char *line, const char *boundary);
static	int	initialiseTables(table_t **rfc821Table, table_t **subtypeTable);
static	int	getTextPart(message *const messages[], size_t size);
static	size_t	strip(char *buf, int len);
static	int	parseMimeHeader(message *m, const char *cmd, const table_t *rfc821Table, const char *arg);
static	int	saveTextPart(mbox_ctx *mctx, message *m, int destroy_text);
static	char	*rfc2047(const char *in);
static	char	*rfc822comments(const char *in, char *out);
static	int	rfc1341(message *m, const char *dir);
static	bool	usefulHeader(int commandNumber, const char *cmd);
static	char	*getline_from_mbox(char *buffer, size_t len, fmap_t *map, size_t *at);
static	bool	isBounceStart(mbox_ctx *mctx, const char *line);
static	bool	exportBinhexMessage(mbox_ctx *mctx, message *m);
static	int	exportBounceMessage(mbox_ctx *ctx, text *start);
static	const	char	*getMimeTypeStr(mime_type mimetype);
static	const	char	*getEncTypeStr(encoding_type enctype);
static	message	*do_multipart(message *mainMessage, message **messages, int i, mbox_status *rc, mbox_ctx *mctx, message *messageIn, text **tptr, unsigned int recursion_level);
static	int	count_quotes(const char *buf);
static	bool	next_is_folded_header(const text *t);
static	bool	newline_in_header(const char *line);

static	blob	*getHrefs(message *m, tag_arguments_t *hrefs);
static	void	hrefs_done(blob *b, tag_arguments_t *hrefs);
static	void	checkURLs(message *m, mbox_ctx *mctx, mbox_status *rc, int is_html);

/* Maximum line length according to RFC2821 */
#define	RFC2821LENGTH	1000

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
#define	ALTERNATIVE	6	/* RFC1521*/
#define	DIGEST		7
#define	SIGNED		8
#define	PARALLEL	9
#define	RELATED		10	/* RFC2387 */
#define	REPORT		11	/* RFC1892 */
#define	APPLEDOUBLE	12	/* Handling of this in only noddy for now */
#define	FAX		MIXED	/*
				 * RFC3458
				 * Drafts stated to treat is as mixed if it is
				 * not known.  This disappeared in the final
				 * version (except when talking about
				 * voice-message), but it is good enough for us
				 * since we do no validation of coversheet
				 * presence etc. (which also has disappeared
				 * in the final version)
				 */
#define	ENCRYPTED	13	/*
				 * e.g. RFC2015
				 * Content-Type: multipart/encrypted;
				 * boundary="nextPart1383049.XCRrrar2yq";
				 * protocol="application/pgp-encrypted"
				 */
#define	X_BFILE		RELATED	/*
				 * BeOS, expert two parts: the file and it's
				 * attributes. The attributes part comes as
				 *	Content-Type: application/x-be_attribute
				 *		name="foo"
				 * I can't find where it is defined, any
				 * pointers would be appreciated. For now
				 * we treat it as multipart/related
				 */
#define	KNOWBOT		14	/* Unknown and undocumented format? */

static	const	struct tableinit {
	const	char	*key;
	int	value;
} rfc821headers[] = {
	/* TODO: make these regular expressions */
	{	"Content-Type",			CONTENT_TYPE		},
	{	"Content-Transfer-Encoding",	CONTENT_TRANSFER_ENCODING	},
	{	"Content-Disposition",		CONTENT_DISPOSITION	},
	{	NULL,				0			}
}, mimeSubtypes[] = {	/* see RFC2045 */
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
	{	"appledouble",	APPLEDOUBLE	},
	{	"fax-message",	FAX		},
	{	"encrypted",	ENCRYPTED	},
	{	"x-bfile",	X_BFILE		},	/* BeOS */
	{	"knowbot",		KNOWBOT		},	/* ??? */
	{	"knowbot-metadata",	KNOWBOT		},	/* ??? */
	{	"knowbot-code",		KNOWBOT		},	/* ??? */
	{	"knowbot-state",	KNOWBOT		},	/* ??? */
	{	NULL,		0		}
}, mimeTypeStr[] = {
	{	"NOMIME", 	NOMIME		},
	{	"APPLICATION",	APPLICATION	},
	{	"AUDIO",	AUDIO		},
	{	"IMAGE",	IMAGE		},
	{	"MESSAGE",	MESSAGE		},
	{	"MULTIPART",	MULTIPART	},
	{	"TEXT",		TEXT		},
	{	"VIDEO",	VIDEO		},
	{	"MEXTENSION",	MEXTENSION	},
	{	NULL,		0		}
}, encTypeStr[] = {
	{	"NOENCODING", 	NOENCODING	},
	{	"QUOTEDPRINTABLE", 	QUOTEDPRINTABLE	},
	{	"BASE64", 	BASE64		},
	{	"EIGHTBIT", 	EIGHTBIT	},
	{	"BINARY", 	BINARY		},
	{	"UUENCODE", 	UUENCODE	},
	{	"YENCODE", 	YENCODE		},
	{	"EEXTENSION", 	EEXTENSION	},
	{	"BINHEX", 	BINHEX		},
	{	NULL,		0		}
};

#ifdef	CL_THREAD_SAFE
static	pthread_mutex_t	tables_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif
static	table_t *rfc821 = NULL;
static	table_t *subtype = NULL;

int
cli_mbox(const char *dir, cli_ctx *ctx)
{
	if(dir == NULL) {
		cli_dbgmsg("cli_mbox called with NULL dir\n");
		return CL_ENULLARG;
	}
	return cli_parse_mbox(dir, ctx);
}

/*
 * TODO: when signal handling is added, need to remove temp files when a
 *	signal is received
 * TODO: add option to scan in memory not via temp files, perhaps with a
 * named pipe or memory mapped file, though this won't work on big e-mails
 * containing many levels of encapsulated messages - it'd just take too much
 * RAM
 * TODO: parse .msg format files
 * TODO: fully handle AppleDouble format, see
 *	http://www.lazerware.com/formats/Specs/AppleSingle_AppleDouble.pdf
 * TODO: ensure parseEmailHeaders is always called before parseEmailBody
 * TODO: create parseEmail which calls parseEmailHeaders then parseEmailBody
 * TODO: Handle unexpected NUL bytes in header lines which stop strcmp()s:
 *	e.g. \0Content-Type: application/binary;
 */
static int
cli_parse_mbox(const char *dir, cli_ctx *ctx)
{
	int retcode;
	message *body;
	char buffer[RFC2821LENGTH + 1];
	mbox_ctx mctx;
	size_t at = 0;
	fmap_t *map = *ctx->fmap;

	cli_dbgmsg("in mbox()\n");

	if(!fmap_gets(map, buffer, &at, sizeof(buffer) - 1)) {
		/* empty message */
		return CL_CLEAN;
	}
#ifdef	CL_THREAD_SAFE
	pthread_mutex_lock(&tables_mutex);
#endif
	if(rfc821 == NULL) {
		assert(subtype == NULL);

		if(initialiseTables(&rfc821, &subtype) < 0) {
			rfc821 = NULL;
			subtype = NULL;
#ifdef	CL_THREAD_SAFE
			pthread_mutex_unlock(&tables_mutex);
#endif
			return CL_EMEM;
		}
	}
#ifdef	CL_THREAD_SAFE
	pthread_mutex_unlock(&tables_mutex);
#endif

	retcode = CL_SUCCESS;
	body = NULL;

	mctx.dir = dir;
	mctx.rfc821Table = rfc821;
	mctx.subtypeTable = subtype;
	mctx.ctx = ctx;
	mctx.files = 0;
#if HAVE_JSON
	mctx.wrkobj = ctx->wrkproperty;
#endif

	/*
	 * Is it a UNIX style mbox with more than one
	 * mail message, or just a single mail message?
	 *
	 * TODO: It would be better if we called cli_scandir here rather than
	 * in cli_scanmail. Then we could improve the way mailboxes with more
	 * than one message is handled, e.g. giving a better indication of
	 * which message within the mailbox is infected
	 */
	/*if((strncmp(buffer, "From ", 5) == 0) && isalnum(buffer[5])) {*/
	if(strncmp(buffer, "From ", 5) == 0) {
		/*
		 * Have been asked to check a UNIX style mbox file, which
		 * may contain more than one e-mail message to decode
		 *
		 * It would be far better for scanners.c to do this splitting
		 * and do this
		 *	FOR EACH mail in the mailbox
		 *	DO
		 *		pass this mail to cli_mbox --
		 *		scan this file
		 *		IF this file has a virus quit
		 *		THEN
		 *			return CL_VIRUS
		 *		FI
		 *	END
		 * This would remove a problem with this code that it can
		 * fill up the tmp directory before it starts scanning
		 */
		bool lastLineWasEmpty;
		int messagenumber;
		message *m = messageCreate();

		if(m == NULL)
			return CL_EMEM;

		lastLineWasEmpty = FALSE;
		messagenumber = 1;
		messageSetCTX(m, ctx);

		do {
			cli_chomp(buffer);
			/*if(lastLineWasEmpty && (strncmp(buffer, "From ", 5) == 0) && isalnum(buffer[5])) {*/
			if(lastLineWasEmpty && (strncmp(buffer, "From ", 5) == 0)) {
				cli_dbgmsg("Deal with message number %d\n", messagenumber++);
				/*
				 * End of a message in the mail box
				 */
				body = parseEmailHeaders(m, rfc821);
				if(body == NULL) {
					messageReset(m);
					continue;
				}
				messageSetCTX(body, ctx);
				messageDestroy(m);
				if(messageGetBody(body)) {
					mbox_status rc = parseEmailBody(body, NULL, &mctx, 0);
					if(rc == FAIL) {
						messageReset(body);
						m = body;
						continue;
					} else if(rc == VIRUS) {
						cli_dbgmsg("Message number %d is infected\n",
							messagenumber-1);
						retcode = CL_VIRUS;
						m = NULL;
						break;
					}
				}
				/*
				 * Starting a new message, throw away all the
				 * information about the old one. It would
				 * be best to be able to scan this message
				 * now, but cli_scanfile needs arguments
				 * that haven't been passed here so it can't be
				 * called
				 */
				m = body;
				messageReset(body);
				messageSetCTX(body, ctx);

				cli_dbgmsg("Finished processing message\n");
			} else
				lastLineWasEmpty = (bool)(buffer[0] == '\0');

			if(isuuencodebegin(buffer)) {
				/*
				 * Fast track visa to uudecode.
				 * TODO: binhex, yenc
				 */
			  if(uudecodeFile(m, buffer, dir, map, &at) < 0)
					if(messageAddStr(m, buffer) < 0)
						break;
			} else
				/* at this point, the \n has been removed */
				if(messageAddStr(m, buffer) < 0)
					break;
		} while(fmap_gets(map, buffer, &at, sizeof(buffer) - 1));

		if(retcode == CL_SUCCESS) {
			cli_dbgmsg("Extract attachments from email %d\n", messagenumber);
			body = parseEmailHeaders(m, rfc821);
		}
		if(m)
			messageDestroy(m);
	} else {
		/*
		 * It's a single message, parse the headers then the body
		 */
		if(strncmp(buffer, "P I ", 4) == 0)
			/*
			 * CommuniGate Pro format: ignore headers until
			 * blank line
			 */
			while(fmap_gets(map, buffer, &at, sizeof(buffer) - 1) &&
				(strchr("\r\n", buffer[0]) == NULL))
					;
		/* getline_from_mbox could be using unlocked_stdio(3),
		 * so lock file here */
		/*
		 * Ignore any blank lines at the top of the message
		 */
		while(strchr("\r\n", buffer[0]) &&
		      (getline_from_mbox(buffer, sizeof(buffer) - 1, map, &at) != NULL))
			;

		buffer[sizeof(buffer) - 1] = '\0';

		body = parseEmailFile(map, &at, rfc821, buffer, dir);
	}

	if(body) {
		/*
		 * Write out the last entry in the mailbox
		 */
		if((retcode == CL_SUCCESS) && messageGetBody(body)) {
			messageSetCTX(body, ctx);
			switch(parseEmailBody(body, NULL, &mctx, 0)) {
				case OK:
				case OK_ATTACHMENTS_NOT_SAVED:
					break;
				case FAIL:
					/*
					 * beware: cli_magic_scandesc(),
					 * changes this into CL_CLEAN, so only
					 * use it to inform the higher levels
					 * that we couldn't decode it because
					 * it isn't an mbox, not to signal
					 * decoding errors on what *is* a valid
					 * mbox
					 */
					retcode = CL_EFORMAT;
					break;
				case MAXREC:
					retcode = CL_EMAXREC;
					break;
				case MAXFILES:
					retcode = CL_EMAXFILES;
					break;
				case VIRUS:
					retcode = CL_VIRUS;
					break;
			}
		}

		if(body->isTruncated && retcode == CL_SUCCESS)
			retcode = CL_EMEM;
		/*
		 * Tidy up and quit
		 */
		messageDestroy(body);
	}
	
	if((retcode == CL_CLEAN) && ctx->found_possibly_unwanted &&
	   (*ctx->virname == NULL || SCAN_ALLMATCHES)) {
	    retcode = cli_append_virus(ctx, "Heuristics.Phishing.Email");
	    ctx->found_possibly_unwanted = 0;
	}

	cli_dbgmsg("cli_mbox returning %d\n", retcode);

	return retcode;
}

/*
 * Read in an email message from fin, parse it, and return the message
 *
 * FIXME: files full of new lines and nothing else are
 * handled ungracefully...
 */
static message *
parseEmailFile(fmap_t *map, size_t *at, const table_t *rfc821, const char *firstLine, const char *dir)
{
	bool inHeader = TRUE;
	bool bodyIsEmpty = TRUE;
	bool lastWasBlank = FALSE, lastBodyLineWasBlank = FALSE;
	message *ret;
	bool anyHeadersFound = FALSE;
	int commandNumber = -1;
	char *fullline = NULL, *boundary = NULL;
	size_t fulllinelength = 0;
	char buffer[RFC2821LENGTH + 1];

	cli_dbgmsg("parseEmailFile\n");

	ret = messageCreate();
	if(ret == NULL)
		return NULL;

	strncpy(buffer, firstLine, sizeof(buffer)-1);
	do {
		const char *line;

		(void)cli_chomp(buffer);

		if(buffer[0] == '\0')
			line = NULL;
		else
			line = buffer;

		/*
		 * Don't blank lines which are only spaces from headers,
		 * otherwise they'll be treated as the end of header marker
		 */
		if(lastWasBlank) {
			lastWasBlank = FALSE;
			if(boundaryStart(buffer, boundary)) {
				cli_dbgmsg("Found a header line with space that should be blank\n");
				inHeader = FALSE;
			}
		}
		if(inHeader) {
			cli_dbgmsg("parseEmailFile: check '%s' fullline %p\n",
				buffer, fullline);
			/*
			 * Ensure wide characters are handled where
			 * sizeof(char) > 1
			 */
			if(line && isspace(line[0] & 0xFF)) {
				char copy[sizeof(buffer)];

				strcpy(copy, buffer);
				strstrip(copy);
				if(copy[0] == '\0') {
					/*
					 * The header line contains only white
					 * space. This is not the end of the
					 * headers according to RFC2822, but
					 * some MUAs will handle it as though
					 * it were, and virus writers exploit
					 * this bug. We can't just break from
					 * the loop here since that would allow
					 * other exploits such as inserting a
					 * white space line before the
					 * content-type line. So we just have
					 * to make a best guess. Sigh.
					 */
					if(fullline) {
						if(parseEmailHeader(ret, fullline, rfc821) < 0)
							continue;

						free(fullline);
						fullline = NULL;
					}
					if(boundary ||
					   ((boundary = (char *)messageFindArgument(ret, "boundary")) != NULL)) {
						lastWasBlank = TRUE;
						continue;
					}
				}
			}
			if((line == NULL) && (fullline == NULL)) {	/* empty line */
				/*
				 * A blank line signifies the end of
				 * the header and the start of the text
				 */
				if(!anyHeadersFound)
					/* Ignore the junk at the top */
					continue;

				cli_dbgmsg("End of header information\n");
				inHeader = FALSE;
				bodyIsEmpty = TRUE;
			} else {
				char *ptr;
				const char *lookahead;

				if(fullline == NULL) {
					char cmd[RFC2821LENGTH + 1], out[RFC2821LENGTH + 1];

					/*
					 * Continuation of line we're ignoring?
					 */
					if(isblank(line[0]))
						continue;

					/*
					 * Is this a header we're interested in?
					 */
					if((strchr(line, ':') == NULL) ||
					   (cli_strtokbuf(line, 0, ":", cmd) == NULL)) {
						if(strncmp(line, "From ", 5) == 0)
							anyHeadersFound = TRUE;
						continue;
					}

					ptr = rfc822comments(cmd, out);
					commandNumber = tableFind(rfc821, ptr ? ptr : cmd);

					switch(commandNumber) {
						case CONTENT_TRANSFER_ENCODING:
						case CONTENT_DISPOSITION:
						case CONTENT_TYPE:
							anyHeadersFound = TRUE;
							break;
						default:
							if(!anyHeadersFound)
								anyHeadersFound = usefulHeader(commandNumber, cmd);
							continue;
					}
					fullline = cli_strdup(line);
					fulllinelength = strlen(line) + 1;
					if(!fullline) {
						if(ret)
							ret->isTruncated = TRUE;
						break;
					}
				} else if(line != NULL) {
					fulllinelength += strlen(line) + 1;
					ptr = cli_realloc(fullline, fulllinelength);
					if(ptr == NULL)
						continue;
					fullline = ptr;
					cli_strlcat(fullline, line, fulllinelength);
				}

				assert(fullline != NULL);

				if((lookahead = fmap_need_off_once(map, *at, 1))) {
					/*
					 * Section B.2 of RFC822 says TAB or
					 * SPACE means a continuation of the
					 * previous entry.
					 *
					 * Add all the arguments on the line
					 */
					if(isblank(*lookahead))
						continue;
				}

				/*
				 * Handle broken headers, where the next
				 * line isn't indented by whitespace
				 */
				if(fullline[strlen(fullline) - 1] == ';')
					/* Add arguments to this line */
					continue;

				if(line && (count_quotes(fullline) & 1))
					continue;

				ptr = rfc822comments(fullline, NULL);
				if(ptr) {
					free(fullline);
					fullline = ptr;
				}

				if(parseEmailHeader(ret, fullline, rfc821) < 0)
					continue;

				free(fullline);
				fullline = NULL;
			}
		} else if(line && isuuencodebegin(line)) {
			/*
			 * Fast track visa to uudecode.
			 * TODO: binhex, yenc
			 */
			bodyIsEmpty = FALSE;
			if(uudecodeFile(ret, line, dir, map, at) < 0)
				if(messageAddStr(ret, line) < 0)
					break;
		} else {
			if(line == NULL) {
				/*
				 * Although this would save time and RAM, some
				 * phish signatures have been built which need
				 * the blank lines
				 */
				if(lastBodyLineWasBlank &&
				  (messageGetMimeType(ret) != TEXT)) {
					cli_dbgmsg("Ignoring consecutive blank lines in the body\n");
					continue;
				}
				lastBodyLineWasBlank = TRUE;
			} else {
				if(bodyIsEmpty) {
					/*
					 * Broken message: new line in the
					 * middle of the headers, so the first
					 * line of the body is in fact
					 * the last lines of the header
					 */
					if(newline_in_header(line))
						continue;
					bodyIsEmpty = FALSE;
				}
				lastBodyLineWasBlank = FALSE;
			}

			if(messageAddStr(ret, line) < 0)
				break;
		}
	} while(getline_from_mbox(buffer, sizeof(buffer) - 1, map, at) != NULL);

	if(boundary)
		free(boundary);

	if(fullline) {
		if(*fullline) switch(commandNumber) {
			case CONTENT_TRANSFER_ENCODING:
			case CONTENT_DISPOSITION:
			case CONTENT_TYPE:
				cli_dbgmsg("parseEmailFile: Fullline unparsed '%s'\n", fullline);
		}
		free(fullline);
	}

	if(!anyHeadersFound) {
		/*
		 * False positive in believing we have an e-mail when we don't
		 */
		messageDestroy(ret);
		cli_dbgmsg("parseEmailFile: no headers found, assuming it isn't an email\n");
		return NULL;
	}

	cli_dbgmsg("parseEmailFile: return\n");

	return ret;
}

/*
 * The given message contains a raw e-mail.
 *
 * Returns the message's body with the correct arguments set, empties the
 * given message's contents (note that it isn't destroyed)
 *
 * TODO: remove the duplication with parseEmailFile
 */
static message *
parseEmailHeaders(message *m, const table_t *rfc821)
{
	bool inHeader = TRUE;
	bool bodyIsEmpty = TRUE;
	text *t;
	message *ret;
	bool anyHeadersFound = FALSE;
	int commandNumber = -1;
	char *fullline = NULL;
	size_t fulllinelength = 0;

	cli_dbgmsg("parseEmailHeaders\n");

	if(m == NULL)
		return NULL;

	ret = messageCreate();

	for(t = messageGetBody(m); t; t = t->t_next) {
		const char *line;

		if(t->t_line)
			line = lineGetData(t->t_line);
		else
			line = NULL;

		if(inHeader) {
			cli_dbgmsg("parseEmailHeaders: check '%s'\n",
				line ? line : "");
			if(line == NULL) {
				/*
				 * A blank line signifies the end of
				 * the header and the start of the text
				 */
				cli_dbgmsg("End of header information\n");
				if(!anyHeadersFound) {
					cli_dbgmsg("Nothing interesting in the header\n");
					break;
				}
				inHeader = FALSE;
				bodyIsEmpty = TRUE;
			} else {
				char *ptr;

				if(fullline == NULL) {
					char cmd[RFC2821LENGTH + 1];

					/*
					 * Continuation of line we're ignoring?
					 */
					if(isblank(line[0]))
						continue;

					/*
					 * Is this a header we're interested in?
					 */
					if((strchr(line, ':') == NULL) ||
					   (cli_strtokbuf(line, 0, ":", cmd) == NULL)) {
						if(strncmp(line, "From ", 5) == 0)
							anyHeadersFound = TRUE;
						continue;
					}

					ptr = rfc822comments(cmd, NULL);
					commandNumber = tableFind(rfc821, ptr ? ptr : cmd);
					if(ptr)
						free(ptr);

					switch(commandNumber) {
						case CONTENT_TRANSFER_ENCODING:
						case CONTENT_DISPOSITION:
						case CONTENT_TYPE:
							anyHeadersFound = TRUE;
							break;
						default:
							if(!anyHeadersFound)
								anyHeadersFound = usefulHeader(commandNumber, cmd);
							continue;
					}
					fullline = cli_strdup(line);
					fulllinelength = strlen(line) + 1;
				} else if(line) {
					fulllinelength += strlen(line) + 1;
					ptr = cli_realloc(fullline, fulllinelength);
					if(ptr == NULL)
						continue;
					fullline = ptr;
					cli_strlcat(fullline, line, fulllinelength);
				}
				assert(fullline != NULL);

				if(next_is_folded_header(t))
					/* Add arguments to this line */
					continue;

				lineUnlink(t->t_line);
				t->t_line = NULL;

				if(count_quotes(fullline) & 1)
					continue;

				ptr = rfc822comments(fullline, NULL);
				if(ptr) {
					free(fullline);
					fullline = ptr;
				}

				if(parseEmailHeader(ret, fullline, rfc821) < 0)
					continue;

				free(fullline);
				fullline = NULL;
			}
		} else {
			if(bodyIsEmpty) {
				if(line == NULL)
					/* throw away leading blank lines */
					continue;
				/*
				 * Broken message: new line in the
				 * middle of the headers, so the first
				 * line of the body is in fact
				 * the last lines of the header
				 */
				if(newline_in_header(line))
					continue;
				bodyIsEmpty = FALSE;
			}
			/*if(t->t_line && isuuencodebegin(t->t_line))
				puts("FIXME: add fast visa here");*/
			cli_dbgmsg("parseEmailHeaders: finished with headers, moving body\n");
			messageMoveText(ret, t, m);
			break;
		}
	}

	if(fullline) {
		if(*fullline) switch(commandNumber) {
			case CONTENT_TRANSFER_ENCODING:
			case CONTENT_DISPOSITION:
			case CONTENT_TYPE:
				cli_dbgmsg("parseEmailHeaders: Fullline unparsed '%s'\n", fullline);
		}
		free(fullline);
	}

	if(!anyHeadersFound) {
		/*
		 * False positive in believing we have an e-mail when we don't
		 */
		messageDestroy(ret);
		cli_dbgmsg("parseEmailHeaders: no headers found, assuming it isn't an email\n");
		return NULL;
	}

	cli_dbgmsg("parseEmailHeaders: return\n");

	return ret;
}

/*
 * Handle a header line of an email message
 */
static int
parseEmailHeader(message *m, const char *line, const table_t *rfc821)
{
	int ret;
#ifdef CL_THREAD_SAFE
	char *strptr;
#endif
	const char *separator;
	char *cmd, *copy, tokenseparator[2];

	cli_dbgmsg("parseEmailHeader '%s'\n", line);

	/*
	 * In RFC822 the separator between the key a value is a colon,
	 * e.g.	Content-Transfer-Encoding: base64
	 * However some MUA's are lapse about this and virus writers exploit
	 * this hole, so we need to check all known possibilities
	 */
	for(separator = ":= "; *separator; separator++)
		if(strchr(line, *separator) != NULL)
			break;

	if(*separator == '\0')
		return -1;

	copy = rfc2047(line);
	if(copy == NULL)
		/* an RFC checker would return -1 here */
		copy = cli_strdup(line);

	tokenseparator[0] = *separator;
	tokenseparator[1] = '\0';

	ret = -1;

#ifdef	CL_THREAD_SAFE
	cmd = strtok_r(copy, tokenseparator, &strptr);
#else
	cmd = strtok(copy, tokenseparator);
#endif

	if(cmd && (strstrip(cmd) > 0)) {
#ifdef	CL_THREAD_SAFE
		char *arg = strtok_r(NULL, "", &strptr);
#else
		char *arg = strtok(NULL, "");
#endif

		if(arg)
			/*
			 * Found a header such as
			 * Content-Type: multipart/mixed;
			 * set arg to be
			 * "multipart/mixed" and cmd to
			 * be "Content-Type"
			 */
			ret = parseMimeHeader(m, cmd, rfc821, arg);
	}
	free(copy);
	return ret;
}

#if HAVE_LIBXML2
static const struct key_entry mhtml_keys[] = {
	/* root html tags for microsoft office document */
	{	"html",			"RootHTML",		MSXML_JSON_ROOT | MSXML_JSON_ATTRIB	},

	{	"head",			"Head",			MSXML_JSON_WRKPTR | MSXML_COMMENT_CB	},
	{	"meta",			"Meta",			MSXML_JSON_WRKPTR | MSXML_JSON_MULTI | MSXML_JSON_ATTRIB	},
	{	"link",			"Link",			MSXML_JSON_WRKPTR | MSXML_JSON_MULTI | MSXML_JSON_ATTRIB	},
	{	"script",		"Script",		MSXML_JSON_WRKPTR | MSXML_JSON_MULTI | MSXML_JSON_VALUE		}
};
static size_t num_mhtml_keys = sizeof(mhtml_keys) / sizeof(struct key_entry);

static const struct key_entry mhtml_comment_keys[] = {
	/* embedded xml tags (comment) for microsoft office document */
	{	"o:documentproperties",	"DocumentProperties",	MSXML_JSON_ROOT | MSXML_JSON_ATTRIB	},
	{	"o:author",		"Author",		MSXML_JSON_WRKPTR | MSXML_JSON_VALUE	},
	{	"o:lastauthor",		"LastAuthor",		MSXML_JSON_WRKPTR | MSXML_JSON_VALUE	},
	{	"o:revision",		"Revision",		MSXML_JSON_WRKPTR | MSXML_JSON_VALUE	},
	{	"o:totaltime",		"TotalTime",		MSXML_JSON_WRKPTR | MSXML_JSON_VALUE	},
	{	"o:created",		"Created",		MSXML_JSON_WRKPTR | MSXML_JSON_VALUE	},
	{	"o:lastsaved",		"LastSaved",		MSXML_JSON_WRKPTR | MSXML_JSON_VALUE	},
	{	"o:pages",		"Pages",		MSXML_JSON_WRKPTR | MSXML_JSON_VALUE	},
	{	"o:words",		"Words",		MSXML_JSON_WRKPTR | MSXML_JSON_VALUE	},
	{	"o:characters",		"Characters",		MSXML_JSON_WRKPTR | MSXML_JSON_VALUE	},
	{	"o:company",		"Company",		MSXML_JSON_WRKPTR | MSXML_JSON_VALUE	},
	{	"o:lines",		"Lines",		MSXML_JSON_WRKPTR | MSXML_JSON_VALUE	},
	{	"o:paragraphs",		"Paragraphs",		MSXML_JSON_WRKPTR | MSXML_JSON_VALUE	},
	{	"o:characterswithspaces",	"CharactersWithSpaces",	MSXML_JSON_WRKPTR | MSXML_JSON_VALUE	},
	{	"o:version",		"Version",		MSXML_JSON_WRKPTR | MSXML_JSON_VALUE	},

	{	"o:officedocumentsettings",	"DocumentSettings",	MSXML_IGNORE_ELEM	},
	{	"w:worddocument",	"WordDocument",		MSXML_IGNORE_ELEM	},
	{	"w:latentstyles",	"LatentStyles",		MSXML_IGNORE_ELEM	}
};
static size_t num_mhtml_comment_keys = sizeof(mhtml_comment_keys) / sizeof(struct key_entry);
#endif

/*
 * The related multipart root HTML file comment parsing wrapper.
 *
 * Attempts to leverage msxml parser, cannot operate without LIBXML2.
 * This function is only used for Preclassification JSON.
 */
static int
parseMHTMLComment(const char *comment, cli_ctx *ctx, void *wrkjobj, void *cbdata)
{
#if HAVE_LIBXML2
	const char *xmlsrt, *xmlend;
	xmlTextReaderPtr reader;
#if HAVE_JSON
	json_object *thisjobj = (json_object *)wrkjobj;
#endif
	int ret = CL_SUCCESS;

	UNUSEDPARAM(cbdata);
	UNUSEDPARAM(wrkjobj);

	xmlend = comment;
	while ((xmlsrt = strstr(xmlend, "<xml>"))) {
		xmlend = strstr(xmlsrt, "</xml>");
		if (xmlend == NULL) {
			cli_dbgmsg("parseMHTMLComment: unbounded xml tag\n");
			break;
		}

		reader = xmlReaderForMemory(xmlsrt, xmlend-xmlsrt+6, "comment.xml", NULL, CLAMAV_MIN_XMLREADER_FLAGS);
		if (!reader) {
			cli_dbgmsg("parseMHTMLComment: cannot initialize xmlReader\n");

#if HAVE_JSON
                       if (ctx->wrkproperty != NULL)
                           ret = cli_json_parse_error(ctx->wrkproperty, "MHTML_ERROR_XML_READER_MEM");
#endif
			return ret; // libxml2 failed!
		}

		/* comment callback is not set to prevent recursion */
		/* TODO: should we separate the key dictionaries? */
		/* TODO: should we use the json object pointer? */
		ret = cli_msxml_parse_document(ctx, reader, mhtml_comment_keys, num_mhtml_comment_keys, MSXML_FLAG_JSON, NULL);

		xmlTextReaderClose(reader);
		xmlFreeTextReader(reader);
		if (ret != CL_SUCCESS)
			return ret;
	}
#else
	UNUSEDPARAM(comment);
	UNUSEDPARAM(ctx);
	UNUSEDPARAM(wrkjobj);
	UNUSEDPARAM(cbdata);

	cli_dbgmsg("in parseMHTMLComment\n");
	cli_dbgmsg("parseMHTMLComment: parsing html xml-comments requires libxml2!\n");
#endif
	return CL_SUCCESS;
}

/*
 * The related multipart root HTML file parsing wrapper.
 *
 * Attempts to leverage msxml parser, cannot operate without LIBXML2.
 * This function is only used for Preclassification JSON.
 */
static mbox_status
parseRootMHTML(mbox_ctx *mctx, message *m, text *t)
{
	cli_ctx *ctx = mctx->ctx;
#if HAVE_LIBXML2
#ifdef LIBXML_HTML_ENABLED
	struct msxml_ctx mxctx;
	blob *input = NULL;
	htmlDocPtr htmlDoc;
	xmlTextReaderPtr reader;
	int ret = CL_SUCCESS;
	mbox_status rc = OK;
#if HAVE_JSON
	json_object *rhtml;
#endif

	cli_dbgmsg("in parseRootMHTML\n");

	if (ctx == NULL)
		return OK;

	if (m == NULL && t == NULL)
		return OK;

	if (m != NULL)
		input = messageToBlob(m, 0);
	else /* t != NULL */
		input = textToBlob(t, NULL, 0);

	if (input == NULL)
		return OK;

	htmlDoc = htmlReadMemory((char*)input->data, input->len, "mhtml.html", NULL, CLAMAV_MIN_XMLREADER_FLAGS);
	if (htmlDoc == NULL) {
		cli_dbgmsg("parseRootMHTML: cannot initialize read html document\n");
#if HAVE_JSON
                if (ctx->wrkproperty != NULL)
                    ret = cli_json_parse_error(ctx->wrkproperty, "MHTML_ERROR_HTML_READ");
		if (ret != CL_SUCCESS)
			rc = FAIL;
#endif
		blobDestroy(input);
		return rc;
	}

#if HAVE_JSON
	if (mctx->wrkobj) {
		rhtml = cli_jsonobj(mctx->wrkobj, "RootHTML");
		if (rhtml != NULL) {
			/* MHTML-specific properties */
			cli_jsonstr(rhtml, "Encoding", (const char*)htmlGetMetaEncoding(htmlDoc));
			cli_jsonint(rhtml, "CompressMode", xmlGetDocCompressMode(htmlDoc));
		}
	}
#endif

	reader = xmlReaderWalker(htmlDoc);
	if (reader == NULL) {
		cli_dbgmsg("parseRootMHTML: cannot initialize xmlTextReader\n");
#if HAVE_JSON
                if (ctx->wrkproperty != NULL)
                    ret = cli_json_parse_error(ctx->wrkproperty, "MHTML_ERROR_XML_READER_IO");
		if (ret != CL_SUCCESS)
			rc = FAIL;
#endif
		blobDestroy(input);
		return rc;
	}

	memset(&mxctx, 0, sizeof(mxctx));
	/* no scanning callback set */
	mxctx.comment_cb = parseMHTMLComment;
	ret = cli_msxml_parse_document(ctx, reader, mhtml_keys, num_mhtml_keys, MSXML_FLAG_JSON | MSXML_FLAG_WALK, &mxctx);
	switch (ret) {
	case CL_SUCCESS:
	case CL_ETIMEOUT:
	case CL_BREAK:
		rc = OK;
		break;

	case CL_EMAXREC:
		rc = MAXREC;
		break;

	case CL_EMAXFILES:
		rc = MAXFILES;
		break;

	case CL_VIRUS:
		rc = VIRUS;
		break;

	default:
		rc = FAIL;
	}

	xmlTextReaderClose(reader);
	xmlFreeTextReader(reader);
	xmlFreeDoc(htmlDoc);
	blobDestroy(input);
	return rc;
#else  /* LIBXML_HTML_ENABLED */
	UNUSEDPARAM(m);
	UNUSEDPARAM(t);
	cli_dbgmsg("in parseRootMHTML\n");
	cli_dbgmsg("parseRootMHTML: parsing html documents disabled in libxml2!\n");
#endif /* LIBXML_HTML_ENABLED */
#else  /* HAVE_LIBXML2 */
	UNUSEDPARAM(m);
	UNUSEDPARAM(t);
	cli_dbgmsg("in parseRootMHTML\n");
	cli_dbgmsg("parseRootMHTML: parsing html documents requires libxml2!\n");

	return OK;
#endif /* HAVE_LIBXML2 */
}

/*
 * This is a recursive routine.
 *
 * This function parses the body of mainMessage and saves its attachments in dir
 *
 * mainMessage is the buffer to be parsed, it contains an e-mail's body, without
 * any headers. First time of calling it'll be
 * the whole message. Later it'll be parts of a multipart message
 * textIn is the plain text message being built up so far
 */
static mbox_status
parseEmailBody(message *messageIn, text *textIn, mbox_ctx *mctx, unsigned int recursion_level)
{
	mbox_status rc;
	text *aText = textIn;
	message *mainMessage = messageIn;
	fileblob *fb;
	bool infected = FALSE;
	const struct cl_engine *engine = mctx->ctx->engine;
	const int doPhishingScan = engine->dboptions&CL_DB_PHISHING_URLS && (DCONF_PHISHING & PHISHING_CONF_ENGINE);
#if HAVE_JSON
	json_object *saveobj = mctx->wrkobj;
#endif

	cli_dbgmsg("in parseEmailBody, %u files saved so far\n",
		mctx->files);

	/* FIXMELIMITS: this should be better integrated */
	if(engine->maxreclevel)
		/*
		 * This is approximate
		 */
		if(recursion_level > engine->maxreclevel) {

				cli_dbgmsg("parseEmailBody: hit maximum recursion level (%u)\n", recursion_level);
				return MAXREC;
			}
	if(engine->maxfiles && (mctx->files >= engine->maxfiles)) {
		/*
		 * FIXME: This is only approx - it may have already
		 * been exceeded
		 */
		cli_dbgmsg("parseEmailBody: number of files exceeded %u\n", engine->maxfiles);
		return MAXFILES;
	}

	rc = OK;

	/* Anything left to be parsed? */
	if(mainMessage && (messageGetBody(mainMessage) != NULL)) {
		mime_type mimeType;
		int subtype, inhead, htmltextPart, inMimeHead, i;
		const char *mimeSubtype;
		char *boundary;
		const text *t_line;
		/*bool isAlternative;*/
		message *aMessage;
		int multiparts = 0;
		message **messages = NULL;	/* parts of a multipart message */

		cli_dbgmsg("Parsing mail file\n");

		mimeType = messageGetMimeType(mainMessage);
		mimeSubtype = messageGetMimeSubtype(mainMessage);
#if HAVE_JSON
		if (mctx->wrkobj != NULL) {
			mctx->wrkobj = cli_jsonobj(mctx->wrkobj, "Body");
			cli_jsonstr(mctx->wrkobj, "MimeType", getMimeTypeStr(mimeType));
			cli_jsonstr(mctx->wrkobj, "MimeSubtype", mimeSubtype);
			cli_jsonstr(mctx->wrkobj, "EncodingType", getEncTypeStr(messageGetEncoding(mainMessage)));
			cli_jsonstr(mctx->wrkobj, "Disposition", messageGetDispositionType(mainMessage));
			cli_jsonstr(mctx->wrkobj, "Filename", messageHasFilename(mainMessage) ?
				    messageGetFilename(mainMessage): "(inline)");
		}
#endif

		/* pre-process */
		subtype = tableFind(mctx->subtypeTable, mimeSubtype);
		if((mimeType == TEXT) && (subtype == PLAIN)) {
			/*
			 * This is effectively no encoding, notice that we
			 * don't check that charset is us-ascii
			 */
			cli_dbgmsg("text/plain: Assume no attachments\n");
			mimeType = NOMIME;
			messageSetMimeSubtype(mainMessage, "");
		} else if((mimeType == MESSAGE) &&
			  (strcasecmp(mimeSubtype, "rfc822-headers") == 0)) {
			/*
			 * RFC1892/RFC3462: section 2 text/rfc822-headers
			 * incorrectly sent as message/rfc822-headers
			 *
			 * Parse as text/plain, i.e. no mime
			 */
			cli_dbgmsg("Changing message/rfc822-headers to text/rfc822-headers\n");
			mimeType = NOMIME;
			messageSetMimeSubtype(mainMessage, "");
		} else
			cli_dbgmsg("mimeType = %d\n", (int)mimeType);

		switch(mimeType) {
		case NOMIME:
			cli_dbgmsg("Not a mime encoded message\n");
			aText = textAddMessage(aText, mainMessage);

			if(!doPhishingScan)
				break;
			/*
			 * Fall through: some phishing mails claim they are
			 * text/plain, when they are in fact html
			 */
		case TEXT:
			/* text/plain has been preprocessed as no encoding */
			if(doPhishingScan) {
				/*
				 * It would be better to save and scan the
				 * file and only checkURLs if it's found to be
				 * clean
				 */
				checkURLs(mainMessage, mctx, &rc, (subtype == HTML));
				/*
				 * There might be html sent without subtype
				 * html too, so scan them for phishing
				 */
				if(rc == VIRUS)
					infected = TRUE;
			}
			break;
		case MULTIPART:
			cli_dbgmsg("Content-type 'multipart' handler\n");
			boundary = messageFindArgument(mainMessage, "boundary");

#if HAVE_JSON
                        if (mctx->wrkobj != NULL)
                            cli_jsonstr(mctx->wrkobj, "Boundary", boundary);
#endif

			if(boundary == NULL) {
				cli_dbgmsg("Multipart/%s MIME message contains no boundary header\n",
					mimeSubtype);
				/* Broken e-mail message */
				mimeType = NOMIME;
				/*
				 * The break means that we will still
				 * check if the file contains a uuencoded file
				 */
				break;
			}

			cli_chomp(boundary);

			/* Perhaps it should assume mixed? */
			if(mimeSubtype[0] == '\0') {
				cli_dbgmsg("Multipart has no subtype assuming alternative\n");
				mimeSubtype = "alternative";
				messageSetMimeSubtype(mainMessage, "alternative");
			}

			/*
			 * Get to the start of the first message
			 */
			t_line = messageGetBody(mainMessage);

			if(t_line == NULL) {
				cli_dbgmsg("Multipart MIME message has no body\n");
				free((char *)boundary);
				mimeType = NOMIME;
				break;
			}

			do
				if(t_line->t_line) {
					if(boundaryStart(lineGetData(t_line->t_line), boundary))
						break;
					/*
					 * Found a binhex file before
					 *	the first multipart
					 * TODO: check yEnc
					 */
					if(binhexBegin(mainMessage) == t_line) {
						if(exportBinhexMessage(mctx, mainMessage)) {
							/* virus found */
							rc = VIRUS;
							infected = TRUE;
							break;
						}
					} else if(t_line->t_next &&
						 (encodingLine(mainMessage) == t_line->t_next)) {
						/*
						 * We look for the next line
						 * since later on we'll skip
						 * over the important line when
						 * we think it's a blank line
						 * at the top of the message -
						 * which it would have been in
						 * an RFC compliant world
						 */
						cli_dbgmsg("Found MIME attachment before the first MIME section \"%s\"\n",
							lineGetData(t_line->t_next->t_line));
						if(messageGetEncoding(mainMessage) == NOENCODING)
							break;
					}
				}
			while((t_line = t_line->t_next) != NULL);

			if(t_line == NULL) {
				cli_dbgmsg("Multipart MIME message contains no boundary lines (%s)\n",
					boundary);
				free((char *)boundary);
				mimeType = NOMIME;
				/*
				 * The break means that we will still
				 * check if the file contains a yEnc/binhex file
				 */
				break;
			}
			/*
			 * Build up a table of all of the parts of this
			 * multipart message. Remember, each part may itself
			 * be a multipart message.
			 */
			inhead = 1;
			inMimeHead = 0;

			/*
			 * Re-read this variable in case mimeSubtype has changed
			 */
			subtype = tableFind(mctx->subtypeTable, mimeSubtype);

			/*
			 * Parse the mainMessage object and create an array
			 * of objects called messages, one for each of the
			 * multiparts that mainMessage contains.
			 *
			 * This looks like parseEmailHeaders() - maybe there's
			 * some duplication of code to be cleaned up
			 *
			 * We may need to create an array rather than just
			 * save each part as it is found because not all
			 * elements will need scanning, and we don't yet know
			 * which of those elements it will be, except in
			 * the case of mixed, when all parts need to be scanned.
			 */
			for(multiparts = 0; t_line && !infected; multiparts++) {
				int lines = 0;
				message **m;
				mbox_status old_rc;

				m = cli_realloc(messages, ((multiparts + 1) * sizeof(message *)));
				if(m == NULL)
					break;
				messages = m;

				aMessage = messages[multiparts] = messageCreate();
				if(aMessage == NULL) {
					multiparts--;
					/* if allocation failed the first time,
					 * there's no point in retrying, just
					 * break out */
					break;
				}
				messageSetCTX(aMessage, mctx->ctx);

				cli_dbgmsg("Now read in part %d\n", multiparts);

				/*
				 * Ignore blank lines. There shouldn't be ANY
				 * but some viruses insert them
				 */
				while((t_line = t_line->t_next) != NULL)
					if(t_line->t_line &&
					   /*(cli_chomp(t_line->t_text) > 0))*/
					   (strlen(lineGetData(t_line->t_line)) > 0))
						break;

				if(t_line == NULL) {
					cli_dbgmsg("Empty part\n");
					/*
					 * Remove this part unless there's
					 * a binhex portion somewhere in
					 * the complete message that we may
					 * throw away by mistake if the MIME
					 * encoding information is incorrect
					 */
					if(mainMessage &&
					   (binhexBegin(mainMessage) == NULL)) {
						messageDestroy(aMessage);
						--multiparts;
					}
					continue;
				}

				do {
					const char *line = lineGetData(t_line->t_line);

					/*cli_dbgmsg("multipart %d: inMimeHead %d inhead %d boundary '%s' line '%s' next '%s'\n",
						multiparts, inMimeHead, inhead, boundary, line,
						t_line->t_next && t_line->t_next->t_line ? lineGetData(t_line->t_next->t_line) : "(null)");*/

					if(inMimeHead) {	/* continuation line */
						if(line == NULL) {
							/*inhead =*/ inMimeHead = 0;
							continue;
						}
						/*
						 * Handle continuation lines
						 * because the previous line
						 * ended with a ; or this line
						 * starts with a white space
						 */
						cli_dbgmsg("Multipart %d: About to add mime Argument '%s'\n",
							multiparts, line);
						/*
						 * Handle the case when it
						 * isn't really a continuation
						 * line:
						 * Content-Type: application/octet-stream;
						 * Content-Transfer-Encoding: base64
						 */
						parseEmailHeader(aMessage, line, mctx->rfc821Table);

						while(isspace((int)*line))
							line++;

						if(*line == '\0') {
							inhead = inMimeHead = 0;
							continue;
						}
						inMimeHead = FALSE;
						messageAddArgument(aMessage, line);
					} else if(inhead) {	/* handling normal headers */
						/*int quotes;*/
						char *fullline, *ptr;

						if(line == NULL) {
							/*
							 * empty line, should the end of the headers,
							 * but some base64 decoders, e.g. uudeview, are broken
							 * and will handle this type of entry, decoding the
							 * base64 content...
							 * Content-Type: application/octet-stream; name=text.zip
							 * Content-Transfer-Encoding: base64
							 * Content-Disposition: attachment; filename="text.zip"
							 *
							 * Content-Disposition: attachment;
							 *	filename=text.zip
							 * Content-Type: application/octet-stream;
							 *	name=text.zip
							 * Content-Transfer-Encoding: base64
							 *
							 * UEsDBAoAAAAAAACgPjJ2RHw676gAAO+oAABEAAAAbWFpbF90ZXh0LWluZm8udHh0ICAgICAgICAg
							 */
							const text *next = t_line->t_next;

							if(next && next->t_line) {
								const char *data = lineGetData(next->t_line);

								if((messageGetEncoding(aMessage) == NOENCODING) &&
								   (messageGetMimeType(aMessage) == APPLICATION) &&
								   data && strstr(data, "base64")) {
									/*
									 * Handle this nightmare (note the blank
									 * line in the header and the incorrect
									 * content-transfer-encoding header)
									 *
									 * Content-Type: application/octet-stream; name="zipped_files.EXEX-Spanska: Yes
									 *
									 * r-Encoding: base64
									 * Content-Disposition: attachment; filename="zipped_files.EXE"
									 */
									messageSetEncoding(aMessage, "base64");
									cli_dbgmsg("Ignoring fake end of headers\n");
									continue;
								}
								if((strncmp(data, "Content", 7) == 0) ||
								   (strncmp(data, "filename=", 9) == 0)) {
									cli_dbgmsg("Ignoring fake end of headers\n");
									continue;
								}
							}
							cli_dbgmsg("Multipart %d: End of header information\n",
								multiparts);
							inhead = 0;
							continue;
						}
						if(isspace((int)*line)) {
							/*
							 * The first line is
							 * continuation line.
							 * This is tricky
							 * to handle, but
							 * all we can do is our
							 * best
							 */
							cli_dbgmsg("Part %d starts with a continuation line\n",
								multiparts);
							messageAddArgument(aMessage, line);
							/*
							 * Give it a default
							 * MIME type since
							 * that may be the
							 * missing line
							 *
							 * Choose application to
							 * force a save
							 */
							if(messageGetMimeType(aMessage) == NOMIME)
								messageSetMimeType(aMessage, "application");
							continue;
						}

						inMimeHead = FALSE;

						assert(strlen(line) <= RFC2821LENGTH);

						fullline = rfc822comments(line, NULL);
						if(fullline == NULL)
							fullline = cli_strdup(line);

						/*quotes = count_quotes(fullline);*/

						/*
						 * Fold next lines to the end of this
						 * if they start with a white space
						 * or if this line has an odd number of quotes:
						 * Content-Type: application/octet-stream; name="foo
						 * "
						 */
						while(t_line && next_is_folded_header(t_line)) {
							const char *data;
							size_t datasz;

							t_line = t_line->t_next;

							data = lineGetData(t_line->t_line);

							if(data[1] == '\0') {
								/*
								 * Broken message: the
								 * blank line at the end
								 * of the headers isn't blank -
								 * it contains a space
								 */
								cli_dbgmsg("Multipart %d: headers not terminated by blank line\n",
									multiparts);
								inhead = FALSE;
								break;
							}

							datasz = strlen(fullline) + strlen(data) + 1;
							ptr = cli_realloc(fullline, datasz);

							if(ptr == NULL)
								break;

							fullline = ptr;
							cli_strlcat(fullline, data, datasz);

							/*quotes = count_quotes(data);*/
						}

						cli_dbgmsg("Multipart %d: About to parse folded header '%s'\n",
							multiparts, fullline);

						parseEmailHeader(aMessage, fullline, mctx->rfc821Table);
						free(fullline);
					} else if(boundaryEnd(line, boundary)) {
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
					} else if(boundaryStart(line, boundary)) {
						inhead = 1;
						break;
					} else {
						if(messageAddLine(aMessage, t_line->t_line) < 0)
							break;
						lines++;
					}
				} while((t_line = t_line->t_next) != NULL);

				cli_dbgmsg("Part %d has %d lines, rc = %d\n",
					multiparts, lines, (int)rc);

				/*
				 * Only save in the array of messages if some
				 * decision will be taken on whether to scan.
				 * If all parts will be scanned then save to
				 * file straight away
				 */
				switch(subtype) {
					case MIXED:
					case ALTERNATIVE:
					case REPORT:
					case DIGEST:
					case APPLEDOUBLE:
					case KNOWBOT:
					case -1:
						old_rc = rc;
						mainMessage = do_multipart(mainMessage,
							messages, multiparts,
							&rc, mctx, messageIn,
							&aText, recursion_level);
						if((rc == OK_ATTACHMENTS_NOT_SAVED) && (old_rc == OK))
							rc = OK;
						if(messages[multiparts]) {
							messageDestroy(messages[multiparts]);
							messages[multiparts] = NULL;
						}
						--multiparts;
						if(rc == VIRUS)
							infected = TRUE;
						break;

					case RELATED:
					case ENCRYPTED:
					case SIGNED:
					case PARALLEL:
						/* all the subtypes that we handle
						 * (all from the switch(tableFind...) below)
						 * must be listed here */
						break;
					default:
						/* this is a subtype that we 
						 * don't handle anyway, 
						 * don't store */
						if(messages[multiparts]) {
							messageDestroy(messages[multiparts]);
							messages[multiparts] = NULL;
						}
						--multiparts;
				}
			}

			free((char *)boundary);

			/*
			 * Preprocess. Anything special to be done before
			 * we handle the multiparts?
			 */
			switch(subtype) {
				case KNOWBOT:
					/* TODO */
					cli_dbgmsg("multipart/knowbot parsed as multipart/mixed for now\n");
					mimeSubtype = "mixed";
					break;
				case -1:
					/*
					 * According to section 7.2.6 of
					 * RFC1521, unrecognized multiparts
					 * should be treated as multipart/mixed.
					 */
					cli_dbgmsg("Unsupported multipart format `%s', parsed as mixed\n", mimeSubtype);
					mimeSubtype = "mixed";
					break;
			}

			/*
			 * We've finished message we're parsing
			 */
			if(mainMessage && (mainMessage != messageIn)) {
				messageDestroy(mainMessage);
				mainMessage = NULL;
			}

			cli_dbgmsg("The message has %d parts\n", multiparts);

			if(infected || ((multiparts == 0) && (aText == NULL))) {
				if(messages) {
					for(i = 0; i < multiparts; i++)
						if(messages[i])
							messageDestroy(messages[i]);
					free(messages);
				}
				if(aText && (textIn == NULL))
					textDestroy(aText);

#if HAVE_JSON
				mctx->wrkobj = saveobj;
#endif
				/*
				 * Nothing to do
				 */
				switch(rc) {
					case VIRUS: return VIRUS;
					case MAXREC: return MAXREC;
					default: return OK_ATTACHMENTS_NOT_SAVED;
				}
			}

			cli_dbgmsg("Find out the multipart type (%s)\n", mimeSubtype);

			/*
			 * We now have all the parts of the multipart message
			 * in the messages array:
			 *	message *messages[multiparts]
			 * Let's decide what to do with them all
			 */
			switch(tableFind(mctx->subtypeTable, mimeSubtype)) {
			case RELATED:
				cli_dbgmsg("Multipart related handler\n");
				/*
				 * Have a look to see if there's HTML code
				 * which will need scanning
				 */
				aMessage = NULL;
				assert(multiparts > 0);

				htmltextPart = getTextPart(messages, multiparts);

				if(htmltextPart >= 0 && messages) {
					if(messageGetBody(messages[htmltextPart]))

						aText = textAddMessage(aText, messages[htmltextPart]);
				} else
					/*
					 * There isn't an HTML bit. If there's a
					 * multipart bit, it'll may be in there
					 * somewhere
					 */
					for(i = 0; i < multiparts; i++)
						if(messageGetMimeType(messages[i]) == MULTIPART) {
							aMessage = messages[i];
							htmltextPart = i;
							break;
						}

				if(htmltextPart == -1)
					cli_dbgmsg("No HTML code found to be scanned\n");
				else {
#if HAVE_JSON
					/* Send root HTML file for preclassification */
					if (mctx->ctx->wrkproperty)
						parseRootMHTML(mctx, aMessage, aText);
#endif
					rc = parseEmailBody(aMessage, aText, mctx, recursion_level + 1);
					if((rc == OK) && aMessage) {
						assert(aMessage == messages[htmltextPart]);
						messageDestroy(aMessage);
						messages[htmltextPart] = NULL;
					} else if(rc == VIRUS) {
						infected = TRUE;
						break;
					}
				}

				/*
				 * The message is confused about the difference
				 * between alternative and related. Badtrans.B
				 * suffers from this problem.
				 *
				 * Fall through in this case:
				 * Content-Type: multipart/related;
				 *	type="multipart/alternative"
				 */
			case DIGEST:
				/*
				 * According to section 5.1.5 RFC2046, the
				 * default mime type of multipart/digest parts
				 * is message/rfc822
				 *
				 * We consider them as alternative, wrong in
				 * the strictest sense since they aren't
				 * alternatives - all parts a valid - but it's
				 * OK for our needs since it means each part
				 * will be scanned
				 */
			case ALTERNATIVE:
				cli_dbgmsg("Multipart alternative handler\n");

				/*
				 * Fall through - some clients are broken and
				 * say alternative instead of mixed. The Klez
				 * virus is broken that way, and anyway we
				 * wish to scan all of the alternatives
				 */
			case REPORT:
				/*
				 * According to section 1 of RFC1892, the
				 * syntax of multipart/report is the same
				 * as multipart/mixed. There are some required
				 * parameters, but there's no need for us to
				 * verify that they exist
				 */
			case ENCRYPTED:
				/* MUAs without encryption plugins can display as multipart/mixed,
				 * just scan it*/
			case MIXED:
			case APPLEDOUBLE:	/* not really supported */
				/*
				 * Look for attachments
				 *
				 * Not all formats are supported. If an
				 * unsupported format turns out to be
				 * common enough to implement, it is a simple
				 * matter to add it
				 */
				if(aText) {
					if(mainMessage && (mainMessage != messageIn))
						messageDestroy(mainMessage);
					mainMessage = NULL;
				}

				cli_dbgmsg("Mixed message with %d parts\n", multiparts);
				for(i = 0; i < multiparts; i++) {
					mainMessage = do_multipart(mainMessage,
						messages, i, &rc, mctx,
						messageIn, &aText, recursion_level + 1);
					if(rc == VIRUS) {
						infected = TRUE;
						break;
					}
					if(rc == MAXREC)
						break;
					if (rc == OK_ATTACHMENTS_NOT_SAVED)
					    rc = OK;
				}

				/* rc = parseEmailBody(NULL, NULL, mctx, recursion_level + 1); */
				break;
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
				if(messages) {
					htmltextPart = getTextPart(messages, multiparts);
					if(htmltextPart == -1)
						htmltextPart = 0;
					rc = parseEmailBody(messages[htmltextPart], aText, mctx, recursion_level + 1);
				}
				break;
			default:
				assert(0);
			}

			if(mainMessage && (mainMessage != messageIn))
				messageDestroy(mainMessage);

			if(aText && (textIn == NULL)) {
				if((!infected) && (fb = fileblobCreate()) != NULL) {
					cli_dbgmsg("Save non mime and/or text/plain part\n");
					fileblobSetFilename(fb, mctx->dir, "textpart");
					/*fileblobAddData(fb, "Received: by clamd (textpart)\n", 30);*/
					fileblobSetCTX(fb, mctx->ctx);
					(void)textToFileblob(aText, fb, 1);

					fileblobDestroy(fb);
					mctx->files++;
				}
				textDestroy(aText);
			}

			for(i = 0; i < multiparts; i++)
				if(messages[i])
					messageDestroy(messages[i]);

			if(messages)
				free(messages);

#if HAVE_JSON
			mctx->wrkobj = saveobj;
#endif
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
					cli_dbgmsg("MIME type 'message' cannot be decoded\n");
					break;
			}
			rc = FAIL;
			if((strcasecmp(mimeSubtype, "rfc822") == 0) ||
			   (strcasecmp(mimeSubtype, "delivery-status") == 0)) {
				message *m = parseEmailHeaders(mainMessage, mctx->rfc821Table);
				if(m) {
					cli_dbgmsg("Decode rfc822\n");

					messageSetCTX(m, mctx->ctx);

					if(mainMessage && (mainMessage != messageIn)) {
						messageDestroy(mainMessage);
						mainMessage = NULL;
					} else
						messageReset(mainMessage);
					if(messageGetBody(m))
						rc = parseEmailBody(m, NULL, mctx, recursion_level + 1);

					messageDestroy(m);
				}
				break;
			} else if(strcasecmp(mimeSubtype, "disposition-notification") == 0) {
				/* RFC 2298 - handle like a normal email */
				rc = OK;
				break;
			} else if(strcasecmp(mimeSubtype, "partial") == 0) {
				if(mctx->ctx->options->mail & CL_SCAN_MAIL_PARTIAL_MESSAGE) {
					/* RFC1341 message split over many emails */
					if(rfc1341(mainMessage, mctx->dir) >= 0)
						rc = OK;
				} else {
					cli_warnmsg("Partial message received from MUA/MTA - message cannot be scanned\n");
				}
			} else if(strcasecmp(mimeSubtype, "external-body") == 0)
				/* TODO */
				cli_warnmsg("Attempt to send Content-type message/external-body trapped\n");
			else
				cli_warnmsg("Unsupported message format `%s' - if you believe this file contains a virus, submit it to www.clamav.net\n", mimeSubtype);


			if(mainMessage && (mainMessage != messageIn))
				messageDestroy(mainMessage);
			if(messages)
				free(messages);
#if HAVE_JSON
			mctx->wrkobj = saveobj;
#endif
			return rc;

		default:
			cli_dbgmsg("Message received with unknown mime encoding - assume application\n");
			/*
			 * Some Yahoo emails attach as
			 * Content-Type: X-unknown/unknown;
			 * instead of
			 * Content-Type: application/unknown;
			 * so let's try our best to salvage something
			 */
		case APPLICATION:
			/*cptr = messageGetMimeSubtype(mainMessage);

			if((strcasecmp(cptr, "octet-stream") == 0) ||
			   (strcasecmp(cptr, "x-msdownload") == 0)) {*/
			{
				fb = messageToFileblob(mainMessage, mctx->dir, 1);

				if(fb) {
					cli_dbgmsg("Saving main message as attachment\n");
					if(fileblobScanAndDestroy(fb) == CL_VIRUS)
						rc = VIRUS;
					mctx->files++;
					if(mainMessage != messageIn) {
						messageDestroy(mainMessage);
						mainMessage = NULL;
					} else
						messageReset(mainMessage);
				}
			} /*else
				cli_warnmsg("Discarded application not sent as attachment\n");*/
			break;

		case AUDIO:
		case VIDEO:
		case IMAGE:
			break;
		}

		if(messages) {
			/* "can't happen" */
			cli_warnmsg("messages != NULL\n");
			free(messages);
		}
	}

	if(aText && (textIn == NULL)) {
		/* Look for a bounce in the text (non mime encoded) portion */
		const text *t;
		/* isBounceStart() is expensive, reduce the number of calls */
		bool lookahead_definately_is_bounce = FALSE;

		for(t = aText; t && (rc != VIRUS); t = t->t_next) {
			const line_t *l = t->t_line;
			const text *lookahead, *topofbounce;
			const char *s;
			bool inheader;

			if(l == NULL) {
				/* assert(lookahead_definately_is_bounce == FALSE) */
				continue;
			}

			if(lookahead_definately_is_bounce)
				lookahead_definately_is_bounce = FALSE;
			else if(!isBounceStart(mctx, lineGetData(l)))
				continue;

			lookahead = t->t_next;
			if(lookahead) {
				if(isBounceStart(mctx, lineGetData(lookahead->t_line))) {
					lookahead_definately_is_bounce = TRUE;
					/* don't save worthless header lines */
					continue;
				}
			} else	/* don't save a single liner */
				break;

			/*
			 * We've found what looks like the start of a bounce
			 * message. Only bother saving if it really is a bounce
			 * message, this helps to speed up scanning of ping-pong
			 * messages that have lots of bounces within bounces in
			 * them
			 */
			for(; lookahead; lookahead = lookahead->t_next) {
				l = lookahead->t_line;

				if(l == NULL)
					break;
				s = lineGetData(l);
				if(strncasecmp(s, "Content-Type:", 13) == 0) {
					/*
					 * Don't bother with text/plain or
					 * text/html
					 */
					if(cli_strcasestr(s, "text/plain") != NULL)
						/*
						 * Don't bother to save the
						 * unuseful part, read past
						 * the headers then we'll go
						 * on to look for the next
						 * bounce message
						 */
						continue;
					if((!doPhishingScan) &&
					   (cli_strcasestr(s, "text/html") != NULL))
						continue;
					break;
				}
			}

			if(lookahead && (lookahead->t_line == NULL)) {
				cli_dbgmsg("Non mime part bounce message is not mime encoded, so it will not be scanned\n");
				t = lookahead;
				/* look for next bounce message */
				continue;
			}

			/*
			 * Prescan the bounce message to see if there's likely
			 * to be anything nasty.
			 * This algorithm is hand crafted and may be breakable
			 * so all submissions are welcome. It's best NOT to
			 * remove this however you may be tempted, because it
			 * significantly speeds up the scanning of multiple
			 * bounces (i.e. bounces within many bounces)
			 */
			for(; lookahead; lookahead = lookahead->t_next) {
				l = lookahead->t_line;

				if(l) {
					s = lineGetData(l);
					if((strncasecmp(s, "Content-Type:", 13) == 0) &&
					   (strstr(s, "multipart/") == NULL) &&
					   (strstr(s, "message/rfc822") == NULL) &&
					   (strstr(s, "text/plain") == NULL))
						break;
				}
			}
			if(lookahead == NULL) {
				cli_dbgmsg("cli_mbox: I believe it's plain text which must be clean\n");
				/* nothing here, move along please */
				break;
			}
			if((fb = fileblobCreate()) == NULL)
				break;
			cli_dbgmsg("Save non mime part bounce message\n");
			fileblobSetFilename(fb, mctx->dir, "bounce");
			fileblobAddData(fb, (const unsigned char *)"Received: by clamd (bounce)\n", 28);
			fileblobSetCTX(fb, mctx->ctx);

			inheader = TRUE;
			topofbounce = NULL;
			do {
				l = t->t_line;

				if(l == NULL) {
					if(inheader) {
						inheader = FALSE;
						topofbounce = t;
					}
				} else {
					s = lineGetData(l);
					fileblobAddData(fb, (const unsigned char *)s, strlen(s));
				}
				fileblobAddData(fb, (const unsigned char *)"\n", 1);
				lookahead = t->t_next;
				if(lookahead == NULL)
					break;
				t = lookahead;
				l = t->t_line;
				if((!inheader) && l) {
					s = lineGetData(l);
					if(isBounceStart(mctx, s)) {
						cli_dbgmsg("Found the start of another bounce candidate (%s)\n", s);
						lookahead_definately_is_bounce = TRUE;
						break;
					}
				}
			} while(!fileblobInfected(fb));

			if(fileblobScanAndDestroy(fb) == CL_VIRUS)
				rc = VIRUS;
			mctx->files++;

			if(topofbounce)
				t = topofbounce;
		}
		textDestroy(aText);
		aText = NULL;
	}

	/*
	 * No attachments - scan the text portions, often files
	 * are hidden in HTML code
	 */
	if(mainMessage && (rc != VIRUS)) {
		text *t_line;

		/*
		 * Look for uu-encoded main file
		 */
		if(mainMessage->body_first != NULL &&
			(encodingLine(mainMessage) != NULL) &&
			((t_line = bounceBegin(mainMessage)) != NULL))
			rc = (exportBounceMessage(mctx, t_line) == CL_VIRUS) ? VIRUS : OK;
		else {
			bool saveIt;

			if(messageGetMimeType(mainMessage) == MESSAGE)
				/*
				 * Quick peek, if the encapsulated
				 * message has no
				 * content encoding statement don't
				 * bother saving to scan, it's safe
				 */
				saveIt = (bool)(encodingLine(mainMessage) != NULL);
			else if(mainMessage->body_last != NULL && (t_line = encodingLine(mainMessage)) != NULL) {
				/*
				 * Some bounces include the message
				 * body without the headers.
				 * FIXME: Unfortunately this generates a
				 * lot of false positives that a bounce
				 * has been found when it hasn't.
				 */
				if((fb = fileblobCreate()) != NULL) {
					cli_dbgmsg("Found a bounce message with no header at '%s'\n",
						lineGetData(t_line->t_line));
					fileblobSetFilename(fb, mctx->dir, "bounce");
					fileblobAddData(fb,
						(const unsigned char *)"Received: by clamd (bounce)\n",
						28);

					fileblobSetCTX(fb, mctx->ctx);
					if(fileblobScanAndDestroy(textToFileblob(t_line, fb, 1)) == CL_VIRUS)
						rc = VIRUS;
					mctx->files++;
				}
				saveIt = FALSE;
			} else
				/*
				 * Save the entire text portion,
				 * since it it may be an HTML file with
				 * a JavaScript virus or a phish
				 */
				saveIt = TRUE;

			if(saveIt) {
				cli_dbgmsg("Saving text part to scan, rc = %d\n",
					(int)rc);
				if(saveTextPart(mctx, mainMessage, 1) == CL_VIRUS)
					rc = VIRUS;

				if(mainMessage != messageIn) {
					messageDestroy(mainMessage);
					mainMessage = NULL;
				} else
					messageReset(mainMessage);
			}
		}
	} /*else
		rc = OK_ATTACHMENTS_NOT_SAVED; */	/* nothing saved */

	if(mainMessage && (mainMessage != messageIn))
		messageDestroy(mainMessage);

	if((rc != FAIL) && infected)
		rc = VIRUS;

#if HAVE_JSON
	mctx->wrkobj = saveobj;
#endif

	cli_dbgmsg("parseEmailBody() returning %d\n", (int)rc);

	return rc;
}

/*
 * Is the current line the start of a new section?
 *
 * New sections start with --boundary
 */
static int
boundaryStart(const char *line, const char *boundary)
{
	const char *ptr;
	char *out;
	int rc;
	char buf[RFC2821LENGTH + 1];
    char *newline;

	if(line == NULL || *line == '\0')
		return 0;	/* empty line */
	if(boundary == NULL)
		return 0;

    newline = strdup(line);
    if (!(newline))
        newline = (char *)line;

    if (newline != line && strlen(line)) {
        char *p;
        /* Trim trailing spaces */
        p = newline + strlen(line) - 1;
        while (p >= newline && *p == ' ')
            *(p--) = '\0';
    }

    if (newline != line)
        cli_chomp(newline);

	/* cli_dbgmsg("boundaryStart: line = '%s' boundary = '%s'\n", line, boundary); */

	if((*newline != '-') && (*newline != '(')) {
        if (newline != line)
            free(newline);
		return 0;
    }

	if(strchr(newline, '-') == NULL) {
        if (newline != line)
            free(newline);
		return 0;
    }

	if(strlen(newline) <= sizeof(buf)) {
		out = NULL;
		ptr = rfc822comments(newline, buf);
	} else
		ptr = out = rfc822comments(newline, NULL);

	if(ptr == NULL)
		ptr = newline;

	if((*ptr++ != '-') || (*ptr == '\0')) {
		if(out)
			free(out);
        if (newline != line)
            free(newline);

		return 0;
	}

	/*
	 * Gibe.B3 is broken, it has:
	 *	boundary="---- =_NextPart_000_01C31177.9DC7C000"
	 * but it's boundaries look like
	 *	------ =_NextPart_000_01C31177.9DC7C000
	 * notice the one too few '-'.
	 * Presumably this is a deliberate exploitation of a bug in some mail
	 * clients.
	 *
	 * The trouble is that this creates a lot of false positives for
	 * boundary conditions, if we're too lax about matches. We do our level
	 * best to avoid these false positives. For example if we have
	 * boundary="1" we want to ensure that we don't break out of every line
	 * that has -1 in it instead of starting --1. This needs some more work.
	 *
	 * Look with and without RFC822 comments stripped, I've seen some
	 * samples where () are taken as comments in boundaries and some where
	 * they're not. Irrespective of whatever RFC2822 says, we need to find
	 * viruses in both types of mails.
	 */
	if((strstr(&ptr[1], boundary) != NULL) || (strstr(newline, boundary) != NULL)) {
		const char *k = ptr;

		/*
		 * We need to ensure that we don't match --11=-=-=11 when
		 * looking for --1=-=-=1 in well behaved headers, that's a
		 * false positive problem mentioned above
		 */
		rc = 0;
		do
			if(strcmp(++k, boundary) == 0) {
				rc = 1;
				break;
			}
		while(*k == '-');
		if(rc == 0) {
			k = &line[1];
			do
				if(strcmp(++k, boundary) == 0) {
					rc = 1;
					break;
				}
			while(*k == '-');
		}
	} else if(*ptr++ != '-')
		rc = 0;
	else
		rc = (strcasecmp(ptr, boundary) == 0);

	if(out)
		free(out);

	if(rc == 1)
		cli_dbgmsg("boundaryStart: found %s in %s\n", boundary, line);

    if (newline != line)
        free(newline);

	return rc;
}

/*
 * Is the current line the end?
 *
 * The message ends with with --boundary--
 */
static int
boundaryEnd(const char *line, const char *boundary)
{
	size_t len;
    char *newline, *p, *p2;

	if(line == NULL || *line == '\0')
		return 0;

    p = newline = strdup(line);
    if (!(newline)) {
        p = (char *)line;
        newline = (char *)line;
    }

    if (newline != line && strlen(line)) {
        /* Trim trailing spaces */
        p2 = newline + strlen(line) - 1;
        while (p2 >= newline && *p2 == ' ')
            *(p2--) = '\0';
    }

	/* cli_dbgmsg("boundaryEnd: line = '%s' boundary = '%s'\n", newline, boundary); */

	if(*p++ != '-') {
        if (newline != line)
            free(newline);
		return 0;
    }

	if(*p++ != '-') {
        if (newline != line)
            free(newline);

		return 0;
    }

	len = strlen(boundary);
	if(strncasecmp(p, boundary, len) != 0) {
        if (newline != line)
            free(newline);

		return 0;
    }
	/*
	 * Use < rather than == because some broken mails have white
	 * space after the boundary
	 */
	if(strlen(p) < (len + 2)) {
        if (newline != line)
            free(newline);

		return 0;
    }

	p = &p[len];
	if(*p++ != '-') {
        if (newline != line)
            free(newline);

		return 0;
    }

	if(*p == '-') {
		/* cli_dbgmsg("boundaryEnd: found %s in %s\n", boundary, p); */
        if (newline != line)
            free(newline);

		return 1;
	}

    if (newline != line)
        free(newline);

	return 0;
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
		if(tableInsert(*rfc821Table, tableinit->key, tableinit->value) < 0) {
			tableDestroy(*rfc821Table);
			*rfc821Table = NULL;
			return -1;
		}

	*subtypeTable = tableCreate();
	assert(*subtypeTable != NULL);

	for(tableinit = mimeSubtypes; tableinit->key; tableinit++)
		if(tableInsert(*subtypeTable, tableinit->key, tableinit->value) < 0) {
			tableDestroy(*rfc821Table);
			tableDestroy(*subtypeTable);
			*rfc821Table = NULL;
			*subtypeTable = NULL;
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
	int textpart = -1;

	for(i = 0; i < size; i++)
		if(messages[i] && (messageGetMimeType(messages[i]) == TEXT)) {
			if(strcasecmp(messageGetMimeSubtype(messages[i]), "html") == 0)
				return (int)i;
			textpart = (int)i;
		}

	return textpart;
}

/*
 * strip -
 *	Remove the trailing spaces from a buffer. Don't call this directly,
 * always call strstrip() which is a wrapper to this routine to be used with
 * NUL terminated strings. This code looks a bit strange because of it's
 * heritage from code that worked on strings that weren't necessarily NUL
 * terminated.
 * TODO: rewrite for clamAV
 *
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
		return 0;

	i = strlen(buf);
	if(len > (int)(i + 1))
		return i;
	ptr = &buf[--len];

#if	defined(UNIX) || defined(C_LINUX) || defined(C_DARWIN)	/* watch - it may be in shared text area */
	do
		if(*ptr)
			*ptr = '\0';
	while((--len >= 0) && (!isgraph(*--ptr)) && (*ptr != '\n') && (*ptr != '\r'));
#else	/* more characters can be displayed on DOS */
	do
#ifndef	REAL_MODE_DOS
		if(*ptr)	/* C8.0 puts into a text area */
#endif
			*ptr = '\0';
	while((--len >= 0) && ((*--ptr == '\0') || isspace((int)(*ptr & 0xFF))));
#endif
	return((size_t)(len + 1));
}

/*
 * strstrip:
 *	Strip a given string
 */
size_t
strstrip(char *s)
{
	if(s == (char *)NULL)
		return(0);

	return(strip(s, strlen(s) + 1));
}

/*
 * Returns 0 for OK, -1 for error
 */
static int
parseMimeHeader(message *m, const char *cmd, const table_t *rfc821Table, const char *arg)
{
	char *copy, *p, *buf;
	const char *ptr;
	int commandNumber;

	cli_dbgmsg("parseMimeHeader: cmd='%s', arg='%s'\n", cmd, arg);

	copy = rfc822comments(cmd, NULL);
	if(copy) {
		commandNumber = tableFind(rfc821Table, copy);
		free(copy);
	} else
		commandNumber = tableFind(rfc821Table, cmd);

	copy = rfc822comments(arg, NULL);

	if(copy)
		ptr = copy;
	else
		ptr = arg;

	buf = NULL;

	switch(commandNumber) {
		case CONTENT_TYPE:
			/*
			 * Fix for non RFC1521 compliant mailers
			 * that send content-type: Text instead
			 * of content-type: Text/Plain, or
			 * just simply "Content-Type:"
			 */
			if(arg == NULL)
				/*
				 * According to section 4 of RFC1521:
				 * "Note also that a subtype specification is
				 * MANDATORY. There are no default subtypes"
				 *
				 * We have to break this and make an assumption
				 * for the subtype because virus writers and
				 * email client writers don't get it right
				 */
				 cli_dbgmsg("Empty content-type received, no subtype specified, assuming text/plain; charset=us-ascii\n");
			else if(strchr(ptr, '/') == NULL)
				/*
				 * Empty field, such as
				 *	Content-Type:
				 * which I believe is illegal according to
				 * RFC1521
				 */
				cli_dbgmsg("Invalid content-type '%s' received, no subtype specified, assuming text/plain; charset=us-ascii\n", ptr);
			else {
				int i;

				buf = cli_malloc(strlen(ptr) + 1);
				if(buf == NULL) {
                    cli_errmsg("parseMimeHeader: Unable to allocate memory for buf %llu\n", (long long unsigned)(strlen(ptr) + 1));
					if(copy)
						free(copy);
					return -1;
				}
				/*
				 * Some clients are broken and
				 * put white space after the ;
				 */
				if(*arg == '/') {
					cli_dbgmsg("Content-type '/' received, assuming application/octet-stream\n");
					messageSetMimeType(m, "application");
					messageSetMimeSubtype(m, "octet-stream");
				} else {
					/*
					 * The content type could be in quotes:
					 *	Content-Type: "multipart/mixed"
					 * FIXME: this is a hack in that ignores
					 *	the quotes, it doesn't handle
					 *	them properly
					 */
					while(isspace(*ptr))
						ptr++;
					if(ptr[0] == '\"')
						ptr++;

					if(ptr[0] != '/') {
						char *s;
#ifdef CL_THREAD_SAFE
						char *strptr = NULL;
#endif

						s = cli_strtokbuf(ptr, 0, ";", buf);
						/*
						 * Handle
						 * Content-Type: foo/bar multipart/mixed
						 * and
						 * Content-Type: multipart/mixed foo/bar
						 */
						if(s && *s) {
							char *buf2 = cli_strdup(buf);

							if(buf2 == NULL) {
								if(copy)
									free(copy);
								free(buf);
								return -1;
							}
							for(;;) {
#ifdef	CL_THREAD_SAFE
								int set = messageSetMimeType(m, strtok_r(s, "/", &strptr));
#else
								int set = messageSetMimeType(m, strtok(s, "/"));
#endif

#ifdef	CL_THREAD_SAFE
								s = strtok_r(NULL, ";", &strptr);
#else
								s = strtok(NULL, ";");
#endif
								if(s == NULL)
									break;
								if(set) {
									size_t len = strstrip(s) - 1;
									if(s[len] == '\"') {
										s[len] = '\0';
										len = strstrip(s);
									}
									if(len) {
										if(strchr(s, ' '))
											messageSetMimeSubtype(m,
												cli_strtokbuf(s, 0, " ", buf2));
										else
											messageSetMimeSubtype(m, s);
									}
								}

								while(*s && !isspace(*s))
									s++;
								if(*s++ == '\0')
									break;
								if(*s == '\0')
									break;
							}
							free(buf2);
						}
					}
				}

				/*
				 * Add in all rest of the the arguments.
				 * e.g. if the header is this:
				 * Content-Type:', arg='multipart/mixed; boundary=foo
				 * we find the boundary argument set it
				 */
				i = 1;
				while(cli_strtokbuf(ptr, i++, ";", buf) != NULL) {
					cli_dbgmsg("mimeArgs = '%s'\n", buf);

					messageAddArguments(m, buf);
				}
			}
			break;
		case CONTENT_TRANSFER_ENCODING:
			messageSetEncoding(m, ptr);
			break;
		case CONTENT_DISPOSITION:
			buf = cli_malloc(strlen(ptr) + 1);
			if(buf == NULL) {
                cli_errmsg("parseMimeHeader: Unable to allocate memory for buf %llu\n", (long long unsigned)(strlen(ptr) + 1));
				if(copy)
					free(copy);
				return -1;
			}
			p = cli_strtokbuf(ptr, 0, ";", buf);
			if(p && *p) {
				messageSetDispositionType(m, p);
				messageAddArgument(m, cli_strtokbuf(ptr, 1, ";", buf));
			}
			if(!messageHasFilename(m))
				/*
				 * Handle this type of header, without
				 * a filename (e.g. some Worm.Torvil.D)
				 *	Content-ID: <nRfkHdrKsAxRU>
				 * Content-Transfer-Encoding: base64
				 * Content-Disposition: attachment
				 */
				messageAddArgument(m, "filename=unknown");
	}
	if(copy)
		free(copy);
	if(buf)
		free(buf);

	return 0;
}

/*
 * Save the text portion of the message
 */
static int
saveTextPart(mbox_ctx *mctx, message *m, int destroy_text)
{
	fileblob *fb;

	messageAddArgument(m, "filename=textportion");
	if((fb = messageToFileblob(m, mctx->dir, destroy_text)) != NULL) {
		/*
		 * Save main part to scan that
		 */
		cli_dbgmsg("Saving main message\n");

		mctx->files++;
		return fileblobScanAndDestroy(fb);
	}
	return CL_ETMPFILE;
}

/*
 * Handle RFC822 comments in headers.
 * If out == NULL, return a buffer without the comments, the caller must free
 *	the returned buffer
 * Return NULL on error or if the input * has no comments.
 * See section 3.4.3 of RFC822
 * TODO: handle comments that go on to more than one line
 */
static char *
rfc822comments(const char *in, char *out)
{
	const char *iptr;
	char *optr;
	int backslash, inquote, commentlevel;

	if(in == NULL)
		return NULL;

	if(strchr(in, '(') == NULL)
		return NULL;

	assert(out != in);

	while(isspace(*in))
		in++;

	if(out == NULL) {
		out = cli_malloc(strlen(in) + 1);
		if(out == NULL) {
            cli_errmsg("rfc822comments: Unable to allocate memory for out %llu\n", (long long unsigned)(strlen(in) + 1));
			return NULL;
        }
	}

	backslash = commentlevel = inquote = 0;
	optr = out;

	cli_dbgmsg("rfc822comments: contains a comment\n");

	for(iptr = in; *iptr; iptr++)
		if(backslash) {
			if(commentlevel == 0)
				*optr++ = *iptr;
			backslash = 0;
		} else switch(*iptr) {
			case '\\':
				backslash = 1;
				break;
			case '\"':
				*optr++ = '\"';
				inquote = !inquote;
				break;
			case '(':
				if(inquote)
					*optr++ = '(';
				else
					commentlevel++;
				break;
			case ')':
				if(inquote)
					*optr++ = ')';
				else if(commentlevel > 0)
					commentlevel--;
				break;
			default:
				if(commentlevel == 0)
					*optr++ = *iptr;
		}

	if(backslash)	/* last character was a single backslash */
		*optr++ = '\\';
	*optr = '\0';

	/*strstrip(out);*/

	cli_dbgmsg("rfc822comments '%s'=>'%s'\n", in, out);

	return out;
}

/*
 * Handle RFC2047 encoding. Returns a malloc'd buffer that the caller must
 * free, or NULL on error
 */
static char *
rfc2047(const char *in)
{
	char *out, *pout;
	size_t len;

	if((strstr(in, "=?") == NULL) || (strstr(in, "?=") == NULL))
		return cli_strdup(in);

	cli_dbgmsg("rfc2047 '%s'\n", in);
	out = cli_malloc(strlen(in) + 1);

	if(out == NULL) {
        cli_errmsg("rfc2047: Unable to allocate memory for out %llu\n", (long long unsigned)(strlen(in) + 1));
		return NULL;
    }

	pout = out;

	/* For each RFC2047 string */
	while(*in) {
		char encoding, *ptr, *enctext;
		message *m;
		blob *b;

		/* Find next RFC2047 string */
		while(*in) {
			if((*in == '=') && (in[1] == '?')) {
				in += 2;
				break;
			}
			*pout++ = *in++;
		}
		/* Skip over charset, find encoding */
		while((*in != '?') && *in)
			in++;
		if(*in == '\0')
			break;
		encoding = *++in;
		encoding = (char)tolower(encoding);

		if((encoding != 'q') && (encoding != 'b')) {
			cli_warnmsg("Unsupported RFC2047 encoding type '%c' - if you believe this file contains a virus, submit it to www.clamav.net\n", encoding);
			free(out);
			out = NULL;
			break;
		}
		/* Skip to encoded text */
		if(*++in != '?')
			break;
		if(*++in == '\0')
			break;

		enctext = cli_strdup(in);
		if(enctext == NULL) {
			free(out);
			out = NULL;
			break;
		}
		in = strstr(in, "?=");
		if(in == NULL) {
			free(enctext);
			break;
		}
		in += 2;
		ptr = strstr(enctext, "?=");
		assert(ptr != NULL);
		*ptr = '\0';
		/*cli_dbgmsg("Need to decode '%s' with method '%c'\n", enctext, encoding);*/

		m = messageCreate();
		if(m == NULL)
			break;
		messageAddStr(m, enctext);
		free(enctext);
		switch(encoding) {
			case 'q':
				messageSetEncoding(m, "quoted-printable");
				break;
			case 'b':
				messageSetEncoding(m, "base64");
				break;
		}
		b = messageToBlob(m, 1);
                if (b == NULL) {
                    messageDestroy(m);
                    break;
                }
		len = blobGetDataSize(b);
		cli_dbgmsg("Decoded as '%*.*s'\n", (int)len, (int)len,
			(const char *)blobGetData(b));
		memcpy(pout, blobGetData(b), len);
		blobDestroy(b);
		messageDestroy(m);
		if(len > 0 && pout[len - 1] == '\n')
			pout += len - 1;
		else
			pout += len;

	}
	if(out == NULL)
		return NULL;

	*pout = '\0';

	cli_dbgmsg("rfc2047 returns '%s'\n", out);
	return out;
}

/*
 * Handle partial messages
 */
static int
rfc1341(message *m, const char *dir)
{
	char *arg, *id, *number, *total, *oldfilename;
	const char *tmpdir;
	int n;
	char pdir[NAME_MAX + 1];
	unsigned char md5_val[16];
	char *md5_hex;

	id = (char *)messageFindArgument(m, "id");
	if(id == NULL)
		return -1;

	tmpdir = cli_gettmpdir();

	snprintf(pdir, sizeof(pdir) - 1, "%s"PATHSEP"clamav-partial", tmpdir);

	if((mkdir(pdir, S_IRWXU) < 0) && (errno != EEXIST)) {
		cli_errmsg("Can't create the directory '%s'\n", pdir);
		free(id);
		return -1;
	} else if(errno == EEXIST) {
		STATBUF statb;

		if(CLAMSTAT(pdir, &statb) < 0) {
			char err[128];
			cli_errmsg("Partial directory %s: %s\n", pdir,
				cli_strerror(errno, err, sizeof(err)));
			free(id);
			return -1;
		}
		if(statb.st_mode & 077)
			cli_warnmsg("Insecure partial directory %s (mode 0%o)\n",
				pdir,
#ifdef	ACCESSPERMS
				(int)(statb.st_mode&ACCESSPERMS)
#else
				(int)(statb.st_mode & 0777)
#endif
			);
	}

	number = (char *)messageFindArgument(m, "number");
	if(number == NULL) {
		free(id);
		return -1;
	}

	oldfilename = messageGetFilename(m);

	arg = cli_malloc(10 + strlen(id) + strlen(number));
	if(arg) {
		sprintf(arg, "filename=%s%s", id, number);
		messageAddArgument(m, arg);
		free(arg);
	}

	if(oldfilename) {
		cli_dbgmsg("Must reset to %s\n", oldfilename);
		free(oldfilename);
	}

	n = atoi(number);
    cl_hash_data("md5", id, strlen(id), md5_val, NULL);
	md5_hex = cli_str2hex((const char*)md5_val, 16);

	if(!md5_hex) {
		free(id);
		free(number);
		return CL_EMEM;
	}

	if(messageSavePartial(m, pdir, md5_hex, n) < 0) {
		free(md5_hex);
		free(id);
		free(number);
		return -1;
	}

	total = (char *)messageFindArgument(m, "total");
	cli_dbgmsg("rfc1341: %s, %s of %s\n", id, number, (total) ? total : "?");
	if(total) {
		int t = atoi(total);
		DIR *dd = NULL;

		free(total);
		/*
		 * If it's the last one - reassemble it
		 * FIXME: this assumes that we receive the parts in order
		 */
		if((n == t) && ((dd = opendir(pdir)) != NULL)) {
			FILE *fout;
			char outname[NAME_MAX + 1];
			time_t now;

			sanitiseName(id);

			snprintf(outname, sizeof(outname) - 1, "%s"PATHSEP"%s", dir, id);

			cli_dbgmsg("outname: %s\n", outname);

			fout = fopen(outname, "wb");
			if(fout == NULL) {
				cli_errmsg("Can't open '%s' for writing", outname);
				free(id);
				free(number);
				free(md5_hex);
				closedir(dd);
				return -1;
			}

			time(&now);
			for(n = 1; n <= t; n++) {
				char filename[NAME_MAX + 1];
				struct dirent *dent;
#if defined(HAVE_READDIR_R_3) || defined(HAVE_READDIR_R_2)
				union {
					struct dirent d;
					char b[offsetof(struct dirent, d_name) + NAME_MAX + 1];
				} result;
#endif

				snprintf(filename, sizeof(filename), "_%s-%u", md5_hex, n);

#ifdef HAVE_READDIR_R_3
				while((readdir_r(dd, &result.d, &dent) == 0) && dent) {
#elif defined(HAVE_READDIR_R_2)
				while((dent = (struct dirent *)readdir_r(dd, &result.d))) {
#else	/*!HAVE_READDIR_R*/
				while((dent = readdir(dd))) {
#endif
					FILE *fin;
					char buffer[BUFSIZ], fullname[NAME_MAX + 1];
					int nblanks;
					STATBUF statb;
					const char *dentry_idpart;
                    int test_fd;

					if(dent->d_ino == 0)
						continue;

					if(!strcmp(".",dent->d_name) ||
							!strcmp("..", dent->d_name))
						continue;
					snprintf(fullname, sizeof(fullname) - 1,
						"%s"PATHSEP"%s", pdir, dent->d_name);
					dentry_idpart = strchr(dent->d_name, '_');

					if(!dentry_idpart ||
							strcmp(filename, dentry_idpart) != 0) {
						if(!m->ctx->engine->keeptmp)
							continue;

                        if ((test_fd = open(fullname, O_RDONLY)) < 0)
                            continue;

						if(FSTAT(test_fd, &statb) < 0) {
                            close(test_fd);
							continue;
                        }

						if(now - statb.st_mtime > (time_t)(7 * 24 * 3600)) {
							if (cli_unlink(fullname)) {
								cli_unlink(outname);
								fclose(fout);
								free(md5_hex);
								free(id);
								free(number);
								closedir(dd);
                                close(test_fd);
								return -1;
							}
						}

                        close(test_fd);
						continue;
					}

					fin = fopen(fullname, "rb");
					if(fin == NULL) {
						cli_errmsg("Can't open '%s' for reading", fullname);
						fclose(fout);
						cli_unlink(outname);
						free(md5_hex);
						free(id);
						free(number);
						closedir(dd);
						return -1;
					}
					nblanks = 0;
					while(fgets(buffer, sizeof(buffer) - 1, fin) != NULL)
						/*
						 * Ensure that trailing newlines
						 * aren't copied
						 */
						if(buffer[0] == '\n')
							nblanks++;
						else {
							if(nblanks)
								do {
									if (putc('\n', fout)==EOF) break;
								} while(--nblanks > 0);
							if (nblanks || fputs(buffer, fout)==EOF) {
								fclose(fin);
								fclose(fout);
								cli_unlink(outname);
								free(md5_hex);
								free(id);
								free(number);
								closedir(dd);
								return -1;
							}
						}
					fclose(fin);

					/* don't unlink if leave temps */
					if(!m->ctx->engine->keeptmp) {
						if(cli_unlink(fullname)) {
							fclose(fout);
							cli_unlink(outname);
							free(md5_hex);
							free(id);
							free(number);
							closedir(dd);
							return -1;
						}
					}
					break;
				}
				rewinddir(dd);
			}
			closedir(dd);
			fclose(fout);
		}
	}
	free(number);
	free(id);
	free(md5_hex);

	return 0;
}

static void
hrefs_done(blob *b, tag_arguments_t *hrefs)
{
	if(b)
		blobDestroy(b);
	html_tag_arg_free(hrefs);
}

/* extract URLs from static text */
static void extract_text_urls(const unsigned char *mem, size_t len, tag_arguments_t *hrefs)
{
    char url[1024];
    size_t off;
    for (off=0;off + 10 < len;off++) {
	/* check whether this is the start of a URL */
	int32_t proto = cli_readint32(mem + off);
	/* convert to lowercase */
	proto |= 0x20202020;
	/* 'http:', 'https:', or 'ftp:' in little-endian */
	if ((proto == 0x70747468 &&
	     (mem[off+4] == ':' || (mem[off+5] == 's' && mem[off+6] == ':')))
	    || proto == 0x3a707466) {
	    size_t url_len;
	    for (url_len=4; off + url_len < len && url_len < (sizeof(url)-1); url_len++) {
		unsigned char c = mem[off + url_len];
		/* smart compilers will compile this if into
		 * a single bt + jb instruction */
		if (c == ' ' || c == '\n' || c == '\t')
		    break;
	    }
	    memcpy(url, mem + off, url_len);
	    url[url_len] = '\0';
	    html_tag_arg_add(hrefs, "href", url);
	    off += url_len;
	}
    }
}

/*
 * This used to be part of checkURLs, split out, because phishingScan needs it
 * too, and phishingScan might be used in situations where checkURLs is
 * disabled (see ifdef)
 */
static blob *
getHrefs(message *m, tag_arguments_t *hrefs)
{
	unsigned char *mem;
	blob *b = messageToBlob(m, 0);
	size_t len;

	if(b == NULL)
		return NULL;

	len = blobGetDataSize(b);

	if(len == 0) {
		blobDestroy(b);
		return NULL;
	}

	/* TODO: make this size customisable */
	if(len > 100*1024) {
		cli_dbgmsg("Viruses pointed to by URLs not scanned in large message\n");
		blobDestroy(b);
		return NULL;
	}

	hrefs->count = 0;
	hrefs->tag = hrefs->value = NULL;
	hrefs->contents = NULL;

	cli_dbgmsg("getHrefs: calling html_normalise_mem\n");
	mem = blobGetData(b);
	if(!html_normalise_mem(mem, (off_t)len, NULL, hrefs,m->ctx->dconf)) {
		blobDestroy(b);
		return NULL;
	}
	cli_dbgmsg("getHrefs: html_normalise_mem returned\n");
	if (!hrefs->count && hrefs->scanContents) {
	    extract_text_urls(mem, len, hrefs);
	}

	/* TODO: Do we need to call remove_html_comments? */
	return b;
}

/*
 * validate URLs for phishes
 * followurls: see if URLs point to malware
 */
static void
checkURLs(message *mainMessage, mbox_ctx *mctx, mbox_status *rc, int is_html)
{
	blob *b;
	tag_arguments_t hrefs;

    UNUSEDPARAM(is_html);

	if(*rc == VIRUS)
		return;

	hrefs.scanContents = mctx->ctx->engine->dboptions&CL_DB_PHISHING_URLS && (DCONF_PHISHING & PHISHING_CONF_ENGINE);

	if(!hrefs.scanContents)
		/*
		 * Don't waste time extracting hrefs (parsing html), nobody
		 * will need it
		 */
		return;

	hrefs.count = 0;
	hrefs.tag = hrefs.value = NULL;
	hrefs.contents = NULL;

	b = getHrefs(mainMessage, &hrefs);
	if(b) {
		if(hrefs.scanContents) {
			if(phishingScan(mctx->ctx, &hrefs) == CL_VIRUS) {
				/*
				 * FIXME: message objects' contents are
				 *	encapsulated so we should not access
				 *	the members directly
				 */
				mainMessage->isInfected = TRUE;
				*rc = VIRUS;
				cli_dbgmsg("PH:Phishing found\n");
			}
		}
	}
	hrefs_done(b,&hrefs);
}

#ifdef HAVE_BACKTRACE
static void
sigsegv(int sig)
{
	signal(SIGSEGV, SIG_DFL);
	print_trace(1);
	exit(SIGSEGV);
}

static void
print_trace(int use_syslog)
{
	void *array[10];
	size_t size;
	char **strings;
	size_t i;
	pid_t pid = getpid();

	cli_errmsg("Segmentation fault, attempting to print backtrace\n");

	size = backtrace(array, 10);
	strings = backtrace_symbols(array, size);

	cli_errmsg("Backtrace of pid %d:\n", pid);
	if(use_syslog)
		syslog(LOG_ERR, "Backtrace of pid %d:", pid);

	for(i = 0; i < size; i++) {
		cli_errmsg("%s\n", strings[i]);
		if(use_syslog)
			syslog(LOG_ERR, "bt[%llu]: %s", (unsigned long long)i, strings[i]);
	}

#ifdef	SAVE_TMP
	cli_errmsg("The errant mail file has been saved\n");
#endif
	/* #else TODO: dump the current email */

	free(strings);
}
#endif

/* See also clamav-milter */
static bool
usefulHeader(int commandNumber, const char *cmd)
{
	switch(commandNumber) {
		case CONTENT_TRANSFER_ENCODING:
		case CONTENT_DISPOSITION:
		case CONTENT_TYPE:
			return TRUE;
		default:
			if(strcasecmp(cmd, "From") == 0)
				return TRUE;
			if(strcasecmp(cmd, "Received") == 0)
				return TRUE;
			if(strcasecmp(cmd, "De") == 0)
				return TRUE;
	}

	return FALSE;
}

/*
 * Like fgets but cope with end of line by "\n", "\r\n", "\n\r", "\r"
 */
static char *
getline_from_mbox(char *buffer, size_t buffer_len, fmap_t *map, size_t *at)
{
    const char *src, *cursrc;
    char *curbuf;
    size_t i;
    size_t input_len = MIN(map->len - *at, buffer_len + 1);
    src = cursrc = fmap_need_off_once(map, *at, input_len);

/*	we check for eof from the result of GETC()
 *	if(feof(fin)) 
		return NULL;*/
    if(!src) {
	cli_dbgmsg("getline_from_mbox: fmap need failed\n");
	return NULL;
    }
    if((buffer_len == 0) || (buffer == NULL)) {
	cli_errmsg("Invalid call to getline_from_mbox(). Refer to https://www.clamav.net/documents/installing-clamav\n");
	return NULL;
    }

    curbuf = buffer;
	
    for(i=0; i<buffer_len-1; i++) {
	char c;

	if(!input_len--) {
	    if(curbuf == buffer) {
		/* EOF on first char */
		return NULL;
	    }
	    break;
	}

	switch((c = *cursrc++)) {
	case '\0':
	    continue;
	case '\n':
	    *curbuf++ = '\n';
	    if(input_len && *cursrc == '\r') {
		i++;
		cursrc++;
	    }
	    break;
	case '\r':
	    *curbuf++ = '\r';
	    if(input_len && *cursrc == '\n') {
		i++;
		cursrc++;
	    }
	    break;
	default:
	    *curbuf++ = c;
	    continue;
	}
	break;
    }
    *at += cursrc - src;
    *curbuf = '\0';
    
    return buffer;
}

/*
 * Is this line a candidate for the start of a bounce message?
 */
static bool
isBounceStart(mbox_ctx *mctx, const char *line)
{
	size_t len;

	if(line == NULL)
		return FALSE;
	if(*line == '\0')
		return FALSE;
	/*if((strncmp(line, "From ", 5) == 0) && !isalnum(line[5]))
		return FALSE;
	if((strncmp(line, ">From ", 6) == 0) && !isalnum(line[6]))
		return FALSE;*/

	len = strlen(line);
	if((len < 6) || (len >= 72))
		return FALSE;

	if((memcmp(line, "From ", 5) == 0) ||
	   (memcmp(line, ">From ", 6) == 0)) {
		int numSpaces = 0, numDigits = 0;

		line += 4;

		do
			if(*line == ' ')
				numSpaces++;
			else if(isdigit((*line) & 0xFF))
				numDigits++;
		while(*++line != '\0');

		if(numSpaces < 6)
			return FALSE;
		if(numDigits < 11)
			return FALSE;
		return TRUE;
	}
	return (bool)(cli_filetype((const unsigned char *)line, len, mctx->ctx->engine) == CL_TYPE_MAIL);
}

/*
 * Extract a binhexEncoded message, return if it's found to be infected as we
 *	extract it
 */
static bool
exportBinhexMessage(mbox_ctx *mctx, message *m)
{
	bool infected = FALSE;
	fileblob *fb;

	if(messageGetEncoding(m) == NOENCODING)
		messageSetEncoding(m, "x-binhex");

	fb = messageToFileblob(m, mctx->dir, 0);

	if(fb) {
		cli_dbgmsg("Binhex file decoded to %s\n",
			fileblobGetFilename(fb));

		if(fileblobScanAndDestroy(fb) == CL_VIRUS)
			infected = TRUE;
		mctx->files++;
	} else
		cli_errmsg("Couldn't decode binhex file to %s\n", mctx->dir);

	return infected;
}

/*
 * Locate any bounce message and extract it. Return cl_status
 */
static int
exportBounceMessage(mbox_ctx *mctx, text *start)
{
	int rc = CL_CLEAN;
	text *t;
	fileblob *fb;

	/*
	 * Attempt to save the original (unbounced)
	 * message - clamscan will find that in the
	 * directory and call us again (with any luck)
	 * having found an e-mail message to handle.
	 *
	 * This finds a lot of false positives, the
	 * search that a content type is in the
	 * bounce (i.e. it's after the bounce header)
	 * helps a bit.
	 *
	 * messageAddLine
	 * optimization could help here, but needs
	 * careful thought, do it with line numbers
	 * would be best, since the current method in
	 * messageAddLine of checking encoding first
	 * must remain otherwise non bounce messages
	 * won't be scanned
	 */
	for(t = start; t; t = t->t_next) {
		const char *txt = lineGetData(t->t_line);
		char cmd[RFC2821LENGTH + 1];

		if(txt == NULL)
			continue;
		if(cli_strtokbuf(txt, 0, ":", cmd) == NULL)
			continue;

		switch(tableFind(mctx->rfc821Table, cmd)) {
			case CONTENT_TRANSFER_ENCODING:
				if((strstr(txt, "7bit") == NULL) &&
				   (strstr(txt, "8bit") == NULL))
					break;
				continue;
			case CONTENT_DISPOSITION:
				break;
			case CONTENT_TYPE:
				if(strstr(txt, "text/plain") != NULL)
					t = NULL;
				break;
			default:
				if(strcasecmp(cmd, "From") == 0)
					start = t;
				else if(strcasecmp(cmd, "Received") == 0)
					start = t;
				continue;
		}
		break;
	}
	if(t && ((fb = fileblobCreate()) != NULL)) {
		cli_dbgmsg("Found a bounce message\n");
		fileblobSetFilename(fb, mctx->dir, "bounce");
		fileblobSetCTX(fb, mctx->ctx);
		if(textToFileblob(start, fb, 1) == NULL) {
			cli_dbgmsg("Nothing new to save in the bounce message\n");
			fileblobDestroy(fb);
		} else
			rc = fileblobScanAndDestroy(fb);
		mctx->files++;
	} else
		cli_dbgmsg("Not found a bounce message\n");

	return rc;
}

/*
 * Get string representation of mimetype
 */
static	const	char	*getMimeTypeStr(mime_type mimetype)
{
	const struct tableinit *entry = mimeTypeStr;

	while (entry->key) {
		if (mimetype == entry->value)
			return entry->key;
		entry++;
	}
	return "UNKNOWN";
}

/*
 * Get string representation of encoding type
 */
static	const	char	*getEncTypeStr(encoding_type enctype)
{
	const struct tableinit *entry = encTypeStr;

	while (entry->key) {
		if (enctype == entry->value)
			return entry->key;
		entry++;
	}
	return "UNKNOWN";
}

/*
 * Handle the ith element of a number of multiparts, e.g. multipart/alternative
 */
static message *
do_multipart(message *mainMessage, message **messages, int i, mbox_status *rc, mbox_ctx *mctx, message *messageIn, text **tptr, unsigned int recursion_level)
{
	bool addToText = FALSE;
	const char *dtype;
#ifndef	SAVE_TO_DISC
	message *body;
#endif
	message *aMessage = messages[i];
	const int doPhishingScan = mctx->ctx->engine->dboptions&CL_DB_PHISHING_URLS && (DCONF_PHISHING&PHISHING_CONF_ENGINE);
#if HAVE_JSON
	const char *mtype = NULL;
	json_object *thisobj = NULL, *saveobj = mctx->wrkobj;

	if (mctx->wrkobj != NULL) {
		json_object *multiobj = cli_jsonarray(mctx->wrkobj, "Multipart");
		if (multiobj == NULL) {
			cli_errmsg("Cannot get multipart preclass array\n");
			*rc = -1;
			return mainMessage;
		}

		thisobj = messageGetJObj(aMessage);
		if (thisobj == NULL) {
			cli_errmsg("Cannot get message preclass object\n");
			*rc = -1;
			return mainMessage;
		}
		if (cli_json_addowner(multiobj, thisobj, NULL, -1) != CL_SUCCESS) {
			cli_errmsg("Cannot assign message preclass object to multipart preclass array\n");
			*rc = -1;
			return mainMessage;
		}
	}
#endif

	if(aMessage == NULL) {
#if HAVE_JSON
		if (thisobj != NULL)
			cli_jsonstr(thisobj, "MimeType", "NULL");
#endif
		return mainMessage;
	}

	if(*rc != OK)
		return mainMessage;

	cli_dbgmsg("Mixed message part %d is of type %d\n",
		i, messageGetMimeType(aMessage));

#if HAVE_JSON
	if (thisobj != NULL) {
		cli_jsonstr(thisobj, "MimeType", getMimeTypeStr(messageGetMimeType(aMessage)));
		cli_jsonstr(thisobj, "MimeSubtype", messageGetMimeSubtype(aMessage));
		cli_jsonstr(thisobj, "EncodingType", getEncTypeStr(messageGetEncoding(aMessage)));
		cli_jsonstr(thisobj, "Disposition", messageGetDispositionType(aMessage));
		cli_jsonstr(thisobj, "Filename", messageHasFilename(aMessage) ?
			    messageGetFilename(aMessage): "(inline)");
	}
#endif

	switch(messageGetMimeType(aMessage)) {
		case APPLICATION:
		case AUDIO:
		case IMAGE:
		case VIDEO:
			break;
		case NOMIME:
			cli_dbgmsg("No mime headers found in multipart part %d\n", i);
			if(mainMessage) {
				if(binhexBegin(aMessage)) {
					cli_dbgmsg("Found binhex message in multipart/mixed mainMessage\n");

					if(exportBinhexMessage(mctx, mainMessage))
						*rc = VIRUS;
				}
				if(mainMessage != messageIn)
					messageDestroy(mainMessage);
				mainMessage = NULL;
			} else if(aMessage) {
				if(binhexBegin(aMessage)) {
					cli_dbgmsg("Found binhex message in multipart/mixed non mime part\n");
					if(exportBinhexMessage(mctx, aMessage))
						*rc = VIRUS;
					assert(aMessage == messages[i]);
					messageReset(messages[i]);
				}
			}
			addToText = TRUE;
			if(messageGetBody(aMessage) == NULL)
				/*
				 * No plain text version
				 */
				cli_dbgmsg("No plain text alternative\n");
			break;
		case TEXT:
			dtype = messageGetDispositionType(aMessage);
			cli_dbgmsg("Mixed message text part disposition \"%s\"\n",
				dtype);
			if(strcasecmp(dtype, "attachment") == 0)
				break;
			if((*dtype == '\0') || (strcasecmp(dtype, "inline") == 0)) {
				const char *cptr;

				if(mainMessage && (mainMessage != messageIn))
					messageDestroy(mainMessage);
				mainMessage = NULL;
				cptr = messageGetMimeSubtype(aMessage);
				cli_dbgmsg("Mime subtype \"%s\"\n", cptr);
				if((tableFind(mctx->subtypeTable, cptr) == PLAIN) &&
				   (messageGetEncoding(aMessage) == NOENCODING)) {
					/*
					 * Strictly speaking, a text/plain part
					 * is not an attachment. We pretend it
					 * is so that we can decode and scan it
					 */
					if(!messageHasFilename(aMessage)) {
						cli_dbgmsg("Adding part to main message\n");
						addToText = TRUE;
					} else
						cli_dbgmsg("Treating inline as attachment\n");
				} else {
					const int is_html = (tableFind(mctx->subtypeTable, cptr) == HTML);
					if(doPhishingScan)
						checkURLs(aMessage, mctx, rc, is_html);
					messageAddArgument(aMessage,
						"filename=mixedtextportion");
				}
				break;
			}
			cli_dbgmsg("Text type %s is not supported\n", dtype);
			return mainMessage;
		case MESSAGE:
			/* Content-Type: message/rfc822 */
			cli_dbgmsg("Found message inside multipart (encoding type %d)\n",
				messageGetEncoding(aMessage));
#ifndef	SCAN_UNENCODED_BOUNCES
			switch(messageGetEncoding(aMessage)) {
				case NOENCODING:
				case EIGHTBIT:
				case BINARY:
					if(encodingLine(aMessage) == NULL) {
						/*
						 * This means that the message
						 * has no attachments
						 *
						 * The test for
						 * messageGetEncoding is needed
						 * since encodingLine won't have
						 * been set if the message
						 * itself has been encoded
						 */
						cli_dbgmsg("Unencoded multipart/message will not be scanned\n");
						assert(aMessage == messages[i]);
						messageDestroy(messages[i]);
						messages[i] = NULL;
						return mainMessage;
					}
					/* FALLTHROUGH */
				default:
					cli_dbgmsg("Encoded multipart/message will be scanned\n");
			}
#endif
#if	0
			messageAddStrAtTop(aMessage,
				"Received: by clamd (message/rfc822)");
#endif
#ifdef	SAVE_TO_DISC
			/*
			 * Save this embedded message
			 * to a temporary file
			 */
			if(saveTextPart(mctx, aMessage, 1) == CL_VIRUS)
				*rc = VIRUS;
			assert(aMessage == messages[i]);
			messageDestroy(messages[i]);
			messages[i] = NULL;
#else
			/*
			 * Scan in memory, faster but is open to DoS attacks
			 * when many nested levels are involved.
			 */
			body = parseEmailHeaders(aMessage, mctx->rfc821Table);

			/*
			 * We've finished with the
			 * original copy of the message,
			 * so throw that away and
			 * deal with the encapsulated
			 * message as a message.
			 * This can save a lot of memory
			 */
			assert(aMessage == messages[i]);
			messageDestroy(messages[i]);
			messages[i] = NULL;
#if HAVE_JSON
			mctx->wrkobj = thisobj;
#endif
			if(body) {
				messageSetCTX(body, mctx->ctx);
				*rc = parseEmailBody(body, NULL, mctx, recursion_level + 1);
				if((*rc == OK) && messageContainsVirus(body))
					*rc = VIRUS;
				messageDestroy(body);
			}
#if HAVE_JSON
			mctx->wrkobj = saveobj;
#endif
#endif
			return mainMessage;
		case MULTIPART:
			/*
			 * It's a multi part within a multi part
			 * Run the message parser on this bit, it won't
			 * be an attachment
			 */
			cli_dbgmsg("Found multipart inside multipart\n");
#if HAVE_JSON
			mctx->wrkobj = thisobj;
#endif
			if(aMessage) {
				/*
				 * The headers were parsed when reading in the
				 * whole multipart section
				 */
				*rc = parseEmailBody(aMessage, *tptr, mctx, recursion_level + 1);
				cli_dbgmsg("Finished recursion, rc = %d\n", (int)*rc);
				assert(aMessage == messages[i]);
				messageDestroy(messages[i]);
				messages[i] = NULL;
			} else {
				*rc = parseEmailBody(NULL, NULL, mctx, recursion_level + 1);
				if(mainMessage && (mainMessage != messageIn))
					messageDestroy(mainMessage);
				mainMessage = NULL;
			}
#if HAVE_JSON
			mctx->wrkobj = saveobj;
#endif
			return mainMessage;
		default:
			cli_dbgmsg("Only text and application attachments are fully supported, type = %d\n",
				messageGetMimeType(aMessage));
			/* fall through - we may be able to salvage something */
	}

	if(*rc != VIRUS) {
		fileblob *fb = messageToFileblob(aMessage, mctx->dir, 1);
#if HAVE_JSON
		json_object *arrobj;
		int arrlen = 0;

		if (thisobj != NULL) {
			/* attempt to determine container size - prevents incorrect type reporting */
			if (json_object_object_get_ex(mctx->ctx->wrkproperty, "ContainedObjects", &arrobj))
				arrlen = json_object_array_length(arrobj);
		}

#endif
		if(fb) {
			/* aMessage doesn't always have a ctx set */
			fileblobSetCTX(fb, mctx->ctx);
			if(fileblobScanAndDestroy(fb) == CL_VIRUS)
				*rc = VIRUS;
			if (!addToText)
				mctx->files++;
		}
#if HAVE_JSON
		if (thisobj != NULL) {
			json_object *entry = NULL;
			const char *dtype = NULL;

			/* attempt to acquire container type */
			if (json_object_object_get_ex(mctx->ctx->wrkproperty, "ContainedObjects", &arrobj))
				if (json_object_array_length(arrobj) > arrlen)
					entry = json_object_array_get_idx(arrobj, arrlen);
			if (entry) {
				json_object_object_get_ex(entry, "FileType", &entry);
				if (entry)
					dtype = json_object_get_string(entry);
			}
			cli_jsonint(thisobj, "ContainedObjectsIndex", arrlen);
			cli_jsonstr(thisobj, "ClamAVFileType", dtype ? dtype : "UNKNOWN");
		}
#endif
		if(messageContainsVirus(aMessage))
			*rc = VIRUS;
	}
	messageDestroy(aMessage);
	messages[i] = NULL;

	return mainMessage;
}

/*
 * Returns the number of quote characters in the given string
 */
static int
count_quotes(const char *buf)
{
	int quotes = 0;

	while(*buf)
		if(*buf++ == '\"')
			quotes++;

	return quotes;
}

/*
 * Will the next line be a folded header? See RFC2822 section 2.2.3
 */
static bool
next_is_folded_header(const text *t)
{
	const text *next = t->t_next;
	const char *data, *ptr;

	if(next == NULL)
		return FALSE;

	if(next->t_line == NULL)
		return FALSE;

	data = lineGetData(next->t_line);

	/*
	 * Section B.2 of RFC822 says TAB or SPACE means a continuation of the
	 * previous entry.
	 */
	if(isblank(data[0]))
		return TRUE;

	if(strchr(data, '=') == NULL)
		/*
		 * Avoid false positives with
		 *	Content-Type: text/html;
		 *	Content-Transfer-Encoding: quoted-printable
		 */
		return FALSE;

	/*
	 * Some are broken and don't fold headers lines
	 * correctly as per section 2.2.3 of RFC2822.
	 * Generally they miss the white space at
	 * the start of the fold line:
	 *	Content-Type: multipart/related;
	 *	type="multipart/alternative";
	 *	boundary="----=_NextPart_000_006A_01C6AC47.348CB550"
	 * should read:
	 *	Content-Type: multipart/related;
	 *	 type="multipart/alternative";
	 *	 boundary="----=_NextPart_000_006A_01C6AC47.348CB550"
	 * Since we're a virus checker not an RFC
	 * verifier we need to handle these
	 */
	data = lineGetData(t->t_line);

	ptr = strchr(data, '\0');

	while(--ptr > data)
		switch(*ptr) {
			case ';':
				return TRUE;
			case '\n':
			case ' ':
			case '\r':
			case '\t':
				continue;	/* white space at end of line */
			default:
				return FALSE;
		}
	return FALSE;
}

/*
 * This routine is called on the first line of the body of
 * an email to handle broken messages that have newlines
 * in the middle of its headers
 */
static bool
newline_in_header(const char *line)
{
	cli_dbgmsg("newline_in_header, check \"%s\"\n", line);

	if(strncmp(line, "Message-Id: ", 12) == 0)
		return TRUE;
	if(strncmp(line, "Date: ", 6) == 0)
		return TRUE;

	return FALSE;
}

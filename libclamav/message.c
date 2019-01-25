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
 * TODO: Optimise messageExport, decodeLine, messageIsEncoding
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifdef CL_THREAD_SAFE
#ifndef	_REENTRANT
#define	_REENTRANT	/* for Solaris 2.8 */
#endif
#endif

#ifdef	C_DARWIN
#include <sys/types.h>
#endif
#include <stdlib.h>
#include <string.h>
#ifdef	HAVE_STRINGS_H
#include <strings.h>
#endif
#include <assert.h>
#include <ctype.h>
#include <stdio.h>

#ifdef	CL_THREAD_SAFE
#include <pthread.h>
#endif

#include "others.h"
#include "str.h"
#include "filetypes.h"

#include "mbox.h"
#include "clamav.h"
#include "json_api.h"

#ifndef isblank
#define isblank(c)	(((c) == ' ') || ((c) == '\t'))
#endif

#define	RFC2045LENGTH	76	/* maximum number of characters on a line */

#ifdef	HAVE_STDBOOL_H
#include <stdbool.h>
#else
#ifdef	FALSE
typedef	unsigned	char	bool;
#else
typedef enum	{ FALSE = 0, TRUE = 1 } bool;
#endif
#endif

static	int	messageHasArgument(const message *m, const char *variable);
static	void	messageIsEncoding(message *m);
static unsigned char *decode(message *m, const char *in, unsigned char *out, unsigned char (*decoder)(char), bool isFast);
static	void	sanitiseBase64(char *s);
#ifdef	__GNUC__
static	unsigned	char	hex(char c)	__attribute__((const));
static	unsigned	char	base64(char c)	__attribute__((const));
static	unsigned	char	uudecode(char c)	__attribute__((const));
#else
static	unsigned	char	hex(char c);
static	unsigned	char	base64(char c);
static	unsigned	char	uudecode(char c);
#endif
static	const	char	*messageGetArgument(const message *m, int arg);
static	void	*messageExport(message *m, const char *dir, void *(*create)(void), void (*destroy)(void *), void (*setFilename)(void *, const char *, const char *), void (*addData)(void *, const unsigned char *, size_t), void *(*exportText)(text *, void *, int), void (*setCTX)(void *, cli_ctx *), int destroy_text);
static	int	usefulArg(const char *arg);
static	void	messageDedup(message *m);
static	char	*rfc2231(const char *in);
static	int	simil(const char *str1, const char *str2);

/*
 * These maps are ordered in decreasing likelihood of their appearance
 * in an e-mail. Probably these should be in a table...
 */
static	const	struct	encoding_map {
	const	char	*string;
	encoding_type	type;
} encoding_map[] = {	/* rfc2045 */
	{	"7bit",			NOENCODING	},
	{	"text/plain",		NOENCODING	},
	{	"quoted-printable",	QUOTEDPRINTABLE	},	/* rfc2045 */
	{	"base64",		BASE64		},	/* rfc2045 */
	{	"8bit",			EIGHTBIT	},
	{	"binary",		BINARY		},
	{	"x-uuencode",		UUENCODE	},	/* uuencode(5) */
	{	"x-yencode",		YENCODE		},
	{	"x-binhex",		BINHEX		},
	{	"us-ascii",		NOENCODING	},	/* incorrect */
	{	"x-uue",		UUENCODE	},	/* incorrect */
	{	"uuencode",		UUENCODE	},	/* incorrect */
	{	NULL,			NOENCODING	}
};

static	const	struct	mime_map {
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

/*
 * See RFC2045, section 6.8, table 1
 */
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

#if HAVE_JSON
	if(m->jobj)
		cli_json_delobj(m->jobj);
#endif

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
	const struct mime_map *m;
	int typeval;
	static table_t *mime_table;

	assert(mess != NULL);
	if(type == NULL) {
		cli_dbgmsg("Empty content-type field\n");
		return 0;
	}

	cli_dbgmsg("messageSetMimeType: '%s'\n", type);

	/* Ignore leading spaces */
	while(!isalpha(*type))
		if(*type++ == '\0')
			return 0;

#ifdef	CL_THREAD_SAFE
	pthread_mutex_lock(&mime_mutex);
#endif
	if(mime_table == NULL) {
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
		mess->mimeType = (mime_type)typeval;
		return 1;
	}
	if(mess->mimeType == NOMIME) {
		if(strncasecmp(type, "x-", 2) == 0)
			mess->mimeType = MEXTENSION;
		else {
			/*
			 * Force scanning of strange messages
			 */
			if(strcasecmp(type, "plain") == 0) {
				cli_dbgmsg("Incorrect MIME type: `plain', set to Text\n");
				mess->mimeType = TEXT;
			} else {
				/*
				 * Don't handle broken e-mail probably sending
				 *	Content-Type: plain/text
				 * instead of
				 *	Content-Type: text/plain
				 * as an attachment
				 */
				int highestSimil = 0, t = -1;
				const char *closest = NULL;

				for(m = mime_map; m->string; m++) {
					const int s = simil(m->string, type);

					if(s > highestSimil) {
						highestSimil = s;
						closest = m->string;
						t = m->type;
					}
				}
				if(highestSimil >= 50) {
					cli_dbgmsg("Unknown MIME type \"%s\" - guessing as %s (%d%% certainty)\n",
						type, closest,
						highestSimil);
					mess->mimeType = (mime_type)t;
				} else {
					cli_dbgmsg("Unknown MIME type: `%s', set to Application - if you believe this file contains a virus, submit it to www.clamav.net\n", type);
					mess->mimeType = APPLICATION;
				}
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

	m->mimeSubtype = cli_strdup(subtype);
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
		m->mimeDispositionType = cli_strdup(disptype);
		if(m->mimeDispositionType)
			strstrip(m->mimeDispositionType);
	} else
		m->mimeDispositionType = NULL;
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
	char *p;

	assert(m != NULL);

	if(arg == NULL)
		return;	/* Note: this is not an error condition */

	while(isspace(*arg))
		arg++;

	if(*arg == '\0')
		/* Empty argument? Probably a broken mail client... */
		return;

	cli_dbgmsg("messageAddArgument, arg='%s'\n", arg);

	if(!usefulArg(arg))
		return;

	for(offset = 0; offset < m->numberOfArguments; offset++)
		if(m->mimeArguments[offset] == NULL)
			break;
		else if(strcasecmp(arg, m->mimeArguments[offset]) == 0)
			return;	/* already in there */

	if(offset == m->numberOfArguments) {
		char **q;

		m->numberOfArguments++;
		q = (char **)cli_realloc(m->mimeArguments, m->numberOfArguments * sizeof(char *));
		if(q == NULL) {
			m->numberOfArguments--;
			return;
		}
		m->mimeArguments = q;
	}

	p = m->mimeArguments[offset] = rfc2231(arg);
	if(!p) {
		/* problem inside rfc2231() */
		cli_dbgmsg("messageAddArgument, error from rfc2231()\n");
		return;
	}

	if(strchr(p, '=') == NULL) {
		if(strncmp(p, "filename", 8) == 0) {
			/*
			 * FIXME: Bounce message handling is corrupting the in
			 * core copies of headers
			 */
                        if (strlen(p) > 8) {
                            cli_dbgmsg("Possible data corruption fixed\n");
                            p[8] = '=';
                        } else {
                            cli_dbgmsg("Possible data corruption not fixed\n");
                        }
		} else {
			if(*p)
				cli_dbgmsg("messageAddArgument, '%s' contains no '='\n", p);
			free(m->mimeArguments[offset]);
			m->mimeArguments[offset] = NULL;
			return;
		}
	}

	/*
	 * This is terribly broken from an RFC point of view but is useful
	 * for catching viruses which have a filename but no type of
	 * mime. By pretending defaulting to an application rather than
	 * to nomime we can ensure they're saved and scanned
	 */
	if((strncasecmp(p, "filename=", 9) == 0) || (strncasecmp(p, "name=", 5) == 0))
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
        size_t datasz=0;

		if(isspace(*string & 0xff) || (*string == ';')) {
			string++;
			continue;
		}

		key = string;

		data = strchr(string, '=');

		/*
		 * Some spam breaks RFC2045 by using ':' instead of '='
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

		string = &data[1];

		/*
		 * Handle white space to the right of the equals sign
		 * This breaks RFC2045 which has:
		 *	parameter := attribute "=" value
		 *	attribute := token   ; case-insensitive
		 *	token  :=  1*<any (ASCII) CHAR except SPACE, CTLs,
		 *		or tspecials>
		 * But too many MUAs ignore this
		 */
		while(isspace(*string) && (*string != '\0'))
			string++;

		cptr = string;

		if (*string)
			string++;

		if(*cptr == '"') {
			char *ptr, *kcopy;

			/*
			 * The field is in quotes, so look for the
			 * closing quotes
			 */
			kcopy = cli_strdup(key);

			if(kcopy == NULL)
				return;

			ptr = strchr(kcopy, '=');
			if(ptr == NULL) {
				ptr = strchr(kcopy, ':');
                if (ptr == NULL) {
                    cli_dbgmsg("Can't parse header \"%s\"\n", s);
                    free(kcopy);
                    return;
                }
            }

			*ptr = '\0';

			string = strchr(++cptr, '"');

			if(string == NULL) {
				cli_dbgmsg("Unbalanced quote character in \"%s\"\n", s);
				string = "";
			} else
				string++;

			if(!usefulArg(kcopy)) {
				free(kcopy);
				continue;
			}

			data = cli_strdup(cptr);

			if (!data) {
				cli_dbgmsg("Can't parse header \"%s\" - if you believe this file contains a missed virus, report it to bugs@clamav.net\n", s);
				free((char *)key);
				return;
				}

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
				 * Use the end of line as data.
				 */
				}
			else
				*ptr = '\0';

            datasz = strlen(kcopy) + strlen(data) + 2;
			field = cli_realloc(kcopy, strlen(kcopy) + strlen(data) + 2);
			if(field) {
                cli_strlcat(field, "=", datasz);
                cli_strlcat(field, data, datasz);
			} else {
				free(kcopy);
            }
			free(data);
		} else {
			size_t len;

			if(*cptr == '\0') {
				cli_dbgmsg("Ignoring empty field in \"%s\"\n", s);
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
char *
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
		cli_dbgmsg("messageFindArgument: compare %lu bytes of %s with %s\n",
			(unsigned long)len, variable, ptr);
#endif
		if(strncasecmp(ptr, variable, len) == 0) {
			ptr = &ptr[len];
			while(isspace(*ptr))
				ptr++;
			if(*ptr != '=') {
				cli_dbgmsg("messageFindArgument: no '=' sign found in MIME header '%s' (%s)\n", variable, messageGetArgument(m, i));
				return NULL;
			}
                        ptr++;
                        if((strlen(ptr) > 1) && (*ptr == '"') && (strchr(&ptr[1], '"') != NULL)) {
				/* Remove any quote characters */
				char *ret = cli_strdup(++ptr);
				char *p;

				if(ret == NULL)
					return NULL;

				/*
				 * fix un-quoting of boundary strings from
				 * header, occurs if boundary was given as
				 *	'boundary="_Test_";'
				 *
				 * At least two quotes in string, assume
				 * quoted argument
				 * end string at next quote
				 */
				if((p = strchr(ret, '"')) != NULL) {
					ret[strlen(ret) - 1] = '\0';
					*p = '\0';
				}
				return ret;
			}
			return cli_strdup(ptr);
		}
	}
	return NULL;
}

char *
messageGetFilename(const message *m)
{
	char *filename = (char *)messageFindArgument(m, "filename");

	if(filename)
		return filename;

	return (char *)messageFindArgument(m, "name");
}

/* Returns true or false */
static int
messageHasArgument(const message *m, const char *variable)
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
		cli_dbgmsg("messageHasArgument: compare %lu bytes of %s with %s\n",
			(unsigned long)len, variable, ptr);
#endif
		if(strncasecmp(ptr, variable, len) == 0) {
			ptr = &ptr[len];
			while(isspace(*ptr))
				ptr++;
			if(*ptr != '=') {
				cli_dbgmsg("messageHasArgument: no '=' sign found in MIME header '%s' (%s)\n", variable, messageGetArgument(m, i));
				return 0;
			}
			return 1;
		}
	}
	return 0;
}

int
messageHasFilename(const message *m)
{
	return messageHasArgument(m, "filename") || messageHasArgument(m, "file");
}

void
messageSetEncoding(message *m, const char *enctype)
{
	const struct encoding_map *e;
	int i;
	char *type;

	assert(m != NULL);
	assert(enctype != NULL);

	/*m->encodingType = EEXTENSION;*/

	while(isblank(*enctype))
		enctype++;

	cli_dbgmsg("messageSetEncoding: '%s'\n", enctype);

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

		for(e = encoding_map; e->string; e++) {
			int sim;
			const char lowertype = tolower(type[0]);

			if((lowertype != tolower(e->string[0])) && (lowertype != 'x'))
				/*
				 * simil is expensive, I'm yet to encounter only
				 * one example of a missent encoding when the
				 * first character was wrong, so lets assume no
				 * match to save the call.
				 *
				 * That example was quoted-printable sent as
				 * X-quoted-printable.
				 */
				continue;

			if(strcmp(e->string, "uuencode") == 0)
				/*
				 * No need to test here - fast track visa will have
				 * handled uuencoded files
				 */
				continue;

			sim = simil(type, e->string);

			if(sim == 100) {
				int j;
				encoding_type *et;

				for(j = 0; j < m->numberOfEncTypes; j++)
					if(m->encodingTypes[j] == e->type)
						break;

				if(j < m->numberOfEncTypes) {
					cli_dbgmsg("Ignoring duplicate encoding mechanism '%s'\n",
						type);
					break;
				}

				et = (encoding_type *)cli_realloc(m->encodingTypes, (m->numberOfEncTypes + 1) * sizeof(encoding_type));
				if(et == NULL)
					break;

				m->encodingTypes = et;
				m->encodingTypes[m->numberOfEncTypes++] = e->type;

				cli_dbgmsg("Encoding type %d is \"%s\"\n", m->numberOfEncTypes, type);
				break;
			} else if(sim > highestSimil) {
				closest = e->string;
				highestSimil = sim;
			}
		}

		if(e->string == NULL) {
			/*
			 * The stated encoding type is illegal, so we
			 * use a best guess of what it should be.
			 *
			 * 50% is arbitrary. For example 7bi will match as
			 * 66% certain to be 7bit
			 */
			if(highestSimil >= 50) {
				cli_dbgmsg("Unknown encoding type \"%s\" - guessing as %s (%u%% certainty)\n",
					type, closest, highestSimil);
				messageSetEncoding(m, closest);
			} else {
				cli_dbgmsg("Unknown encoding type \"%s\" - if you believe this file contains a virus, submit it to www.clamav.net\n", type);
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

	if(m->body_last == NULL) {
        cli_errmsg("messageAddLine: out of memory for m->body_last\n");
		return -1;
    }

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
		if(*data == '\0')
			data = NULL;
		else {
			/*
			 * If it's only white space, just store one space to
			 * save memory. You must store something since it may
			 * be a header line
			 */
			int iswhite = 1;
			const char *p;

			for(p = data; *p; p++)
				if(((*p) & 0x80) || !isspace(*p)) {
					iswhite = 0;
					break;
				}
			if(iswhite) {
				/*cli_dbgmsg("messageAddStr: empty line: '%s'\n", data);*/
				data = " ";
			}
		}
	}

	if(m->body_first == NULL)
		m->body_last = m->body_first = (text *)cli_malloc(sizeof(text));
	else {
		assert(m->body_last != NULL);
		if((data == NULL) && (m->body_last->t_line == NULL))
			/*
			 * Although this would save time and RAM, some
			 * phish signatures have been built which need the
			 * blank lines
			 */
			if(messageGetMimeType(m) != TEXT)
				/* don't save two blank lines in succession */
				return 1;

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
		else {
			m->body_last->t_line = lineCreate(data);

			if(m->body_last->t_line == NULL) {
				messageDedup(m);
				m->body_last->t_line = lineCreate(data);

				if(m->body_last->t_line == NULL) {
					cli_errmsg("messageAddStr: out of memory\n");
					return -1;
				}
			}
			/* cli_chomp(m->body_last->t_text); */
			messageIsEncoding(m);
		}
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
 * Put the contents of the given text at the end of the current object.
 * Can be used either to move a text object into a message, or to move a
 * message's text into another message only moving from a given offset.
 * The given text emptied; it can be used again if needed, though be warned that
 * it will have an empty line at the start.
 * Returns 0 for failure, 1 for success
 */
int
messageMoveText(message *m, text *t, message *old_message)
{
	int rc;

	if(m->body_first == NULL) {
		if(old_message) {
			text *u;
			/*
			 * t is within old_message which is about to be
			 * destroyed
			 */
			assert(old_message->body_first != NULL);

			m->body_first = t;
			for(u = old_message->body_first; u != t;) {
				text *next;

				if(u->t_line) {
					lineUnlink(u->t_line);
					u->t_line = NULL;
				}
				next = u->t_next;

				free(u);
				u = next;

				if(u == NULL) {
					cli_dbgmsg("messageMoveText sanity check: t not within old_message\n");
					return -1;
				}
			}
			assert(old_message->body_last->t_next == NULL);

			m->body_last = old_message->body_last;
			old_message->body_first = old_message->body_last = NULL;

			/* Do any pointers need to be reset? */
			if((old_message->bounce == NULL) &&
			   (old_message->encoding == NULL) &&
			   (old_message->binhex == NULL) &&
			   (old_message->yenc == NULL))
				return 0;

			m->body_last = m->body_first;
			rc = 0;
		} else {
			m->body_last = m->body_first = textMove(NULL, t);
			if(m->body_first == NULL)
				return -1;
			else
				rc = 0;
		}
	} else {
		m->body_last = textMove(m->body_last, t);
		if(m->body_last == NULL) {
			rc = -1;
			m->body_last = m->body_first;
		} else
			rc = 0;
	}

	while(m->body_last->t_next) {
		m->body_last = m->body_last->t_next;
		if(m->body_last->t_line)
			messageIsEncoding(m);
	}

	return rc;
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

	/*if(m->ctx == NULL)
		cli_dbgmsg("messageIsEncoding, ctx == NULL\n");*/

	if((m->encoding == NULL) &&
	   (strncasecmp(line, encoding, sizeof(encoding) - 1) == 0) &&
	   (strstr(line, "7bit") == NULL))
		m->encoding = m->body_last;
	else if((m->bounce == NULL) && m->ctx &&
		(strncasecmp(line, "Received: ", 10) == 0) &&
		(cli_filetype((const unsigned char *)line, strlen(line), m->ctx->engine) == CL_TYPE_MAIL))
			m->bounce = m->body_last;
		/* Not needed with fast track visa technology */
	/*else if((m->uuencode == NULL) && isuuencodebegin(line))
		m->uuencode = m->body_last;*/
	else if((m->binhex == NULL) &&
		strstr(line, "BinHex") &&
		(simil(line, binhex) > 90))
			/*
			 * Look for close matches for BinHex, but
			 * simil() is expensive so only do it if it's
			 * likely to be found
			 */
			m->binhex = m->body_last;
	else if((m->yenc == NULL) && (strncmp(line, "=ybegin line=", 13) == 0))
		m->yenc = m->body_last;
}

/*
 * Returns a pointer to the body of the message. Note that it does NOT return
 * a copy of the data
 */
text *
messageGetBody(message *m)
{
	assert(m != NULL);
	return m->body_first;
}

/*
 * Export a message using the given export routines
 *
 * TODO: It really should export into an array, one
 * for each encoding algorithm. However, what it does is it returns the
 * last item that was exported. That's sufficient for now.
 */
static void *
messageExport(message *m, const char *dir, void *(*create)(void), void (*destroy)(void *), void (*setFilename)(void *, const char *, const char *), void (*addData)(void *, const unsigned char *, size_t), void *(*exportText)(text *, void *, int), void(*setCTX)(void *, cli_ctx *), int destroy_text)
{
	void *ret;
	text *t_line;
	char *filename;
	int i;

	assert(m != NULL);

	if(messageGetBody(m) == NULL)
		return NULL;

	ret = (*create)();

	if(ret == NULL)
		return NULL;

	cli_dbgmsg("messageExport: numberOfEncTypes == %d\n", m->numberOfEncTypes);

	if(m->numberOfEncTypes == 0) {
		/*
		 * Fast copy
		 */
		cli_dbgmsg("messageExport: Entering fast copy mode\n");

#if	0
		filename = messageGetFilename(m);

		if(filename == NULL) {
			cli_dbgmsg("Unencoded attachment sent with no filename\n");
			messageAddArgument(m, "name=attachment");
		} else if((strcmp(filename, "textportion") != 0) && (strcmp(filename, "mixedtextportion") != 0))
			/*
			 * Some virus attachments don't say how they've
			 * been encoded. We assume base64
			 */
			messageSetEncoding(m, "base64");
#else
		filename = (char *)messageFindArgument(m, "filename");
		if(filename == NULL) {
			filename = (char *)messageFindArgument(m, "name");

			if(filename == NULL) {
				cli_dbgmsg("Unencoded attachment sent with no filename\n");
				messageAddArgument(m, "name=attachment");
			} else
				/*
				 * Some virus attachments don't say how they've
				 * been encoded. We assume base64.
				 * RFC says encoding should be 7-bit.
				 */
				messageSetEncoding(m, "7-bit");
		}
#endif

		(*setFilename)(ret, dir, (filename && *filename) ? filename : "attachment");

		if(filename)
			free((char *)filename);

		if(m->numberOfEncTypes == 0)
			return exportText(messageGetBody(m), ret, destroy_text);
	}

	if(setCTX && m->ctx)
		(*setCTX)(ret, m->ctx);

	for(i = 0; i < m->numberOfEncTypes; i++) {
		encoding_type enctype = m->encodingTypes[i];
		size_t size;

		if(i > 0) {
			void *newret;

			newret = (*create)();
			if(newret == NULL) {
				cli_dbgmsg("Not all decoding algorithms were run\n");
				return ret;
			}
			(*destroy)(ret);
			ret = newret;
		}
		cli_dbgmsg("messageExport: enctype %d is %d\n", i, (int)enctype);
		/*
		 * Find the filename to decode
		 */
		if(((enctype == YENCODE) || (i == 0)) && yEncBegin(m)) {
			const char *f;

			/*
			 * TODO: handle multipart yEnc encoded files
			 */
			t_line = yEncBegin(m);
			f = lineGetData(t_line->t_line);

			if((filename = strstr(f, " name=")) != NULL) {
				filename = cli_strdup(&filename[6]);
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
			m->yenc = NULL;
		} else {
			if(enctype == UUENCODE) {
				/*
				 * The body will have been stripped out by the
				 * fast track visa system. Treat as plain/text,
				 * which means we'll still scan for funnies
				 * outside of the uuencoded portion.
				 */
				cli_dbgmsg("messageExport: treat uuencode as text/plain\n");
				enctype = m->encodingTypes[i] = NOENCODING;
			}
			filename = messageGetFilename(m);

			if(filename == NULL) {
				cli_dbgmsg("Attachment sent with no filename\n");
				messageAddArgument(m, "name=attachment");
			} else if(enctype == NOENCODING)
				/*
				 * Some virus attachments don't say how
				 * they've been encoded. We assume
				 * base64.
				 *
				 * FIXME: don't do this if it's a fall
				 * through from uuencode
				 */
				messageSetEncoding(m, "base64");

			(*setFilename)(ret, dir, (filename && *filename) ? filename : "attachment");

			t_line = messageGetBody(m);
		}

		if(filename)
			free((char *)filename);

		/*
		 * t_line should now point to the first (encoded) line of the
		 * message
		 */
		if(t_line == NULL) {
			cli_dbgmsg("Empty attachment not saved\n");
			(*destroy)(ret);
			return NULL;
		}

		if(enctype == NOENCODING) {
			/*
			 * Fast copy
			 */
			if(i == m->numberOfEncTypes - 1) {
				/* last one */
				(void)exportText(t_line, ret, destroy_text);
				break;
			}
			(void)exportText(t_line, ret, 0);
			continue;
		}

		size = 0;
		do {
			unsigned char smallbuf[1024];
			unsigned char *uptr, *data;
			const char *line = lineGetData(t_line->t_line);
			unsigned char *bigbuf;
			size_t datasize;

			if(enctype == YENCODE) {
				if(line == NULL)
					continue;
				if(strncmp(line, "=yend ", 6) == 0)
					break;
			}

			/*
			 * Add two bytes for '\n' and '\0'
			 */
			datasize = (line) ? strlen(line) + 2 : 0;

			if(datasize >= sizeof(smallbuf))
				data = bigbuf = (unsigned char *)cli_malloc(datasize);
			else {
				bigbuf = NULL;
				data = smallbuf;
				datasize = sizeof(smallbuf);
			}

			uptr = decodeLine(m, enctype, line, data, datasize);
			if(uptr == NULL) {
				if(data == bigbuf)
					free(data);
				break;
			}

			if(uptr != data) {
				assert((size_t)(uptr - data) < datasize);
				(*addData)(ret, data, (size_t)(uptr - data));
				size += (size_t)(uptr - data);
			}

			if(data == bigbuf)
				free(data);

			/*
			 * According to RFC2045, '=' is used to pad out
			 * the last byte and should be used as evidence
			 * of the end of the data. Some mail clients
			 * annoyingly then put plain text after the '='
			 * byte and viruses exploit this bug. Sigh
			 */
			/*if(enctype == BASE64)
				if(strchr(line, '='))
					break;*/
			if(line && destroy_text && (i == m->numberOfEncTypes - 1)) {
				lineUnlink(t_line->t_line);
				t_line->t_line = NULL;
			}
		} while((t_line = t_line->t_next) != NULL);

		cli_dbgmsg("Exported %lu bytes using enctype %d\n",
			(unsigned long)size, (int)enctype);

		/* Verify we have nothing left to flush out */
		if(m->base64chars) {
			unsigned char data[4];
			unsigned char *ptr;

			ptr = base64Flush(m, data);
			if(ptr)
				(*addData)(ret, data, (size_t)(ptr - data));
		}
	}

	return ret;
}

unsigned char *
base64Flush(message *m, unsigned char *buf)
{
	cli_dbgmsg("%d trailing bytes to export\n", m->base64chars);

	if(m->base64chars) {
		unsigned char *ret = decode(m, NULL, buf, base64, FALSE);

		m->base64chars = 0;

		return ret;
	}
	return NULL;
}

int messageSavePartial(message *m, const char *dir, const char *md5id, unsigned part)
{
	char fullname[1024];
	fileblob *fb;
	unsigned long time_val;

	cli_dbgmsg("messageSavePartial\n");
	time_val  = time(NULL);
	snprintf(fullname, 1024, "%s"PATHSEP"clamav-partial-%lu_%s-%u", dir, time_val, md5id, part);

	fb = messageExport(m, fullname,
		(void *(*)(void))fileblobCreate,
		(void(*)(void *))fileblobDestroy,
		(void(*)(void *, const char *, const char *))fileblobPartialSet,
		(void(*)(void *, const unsigned char *, size_t))fileblobAddData,
		(void *(*)(text *, void *, int))textToFileblob,
		(void(*)(void *, cli_ctx *))fileblobSetCTX,
		0);
	if(!fb)
		return CL_EFORMAT;
	fileblobDestroy(fb);
	return CL_SUCCESS;
}

/*
 * Decode and transfer the contents of the message into a fileblob
 * The caller must free the returned fileblob
 */
fileblob *
messageToFileblob(message *m, const char *dir, int destroy)
{
	fileblob *fb;

	cli_dbgmsg("messageToFileblob\n");
	fb = messageExport(m, dir,
		(void *(*)(void))fileblobCreate,
		(void(*)(void *))fileblobDestroy,
		(void(*)(void *, const char *, const char *))fileblobSetFilename,
		(void(*)(void *, const unsigned char *, size_t))fileblobAddData,
		(void *(*)(text *, void *, int))textToFileblob,
		(void(*)(void *, cli_ctx *))fileblobSetCTX,
		destroy);
	if(destroy && m->body_first) {
		textDestroy(m->body_first);
		m->body_first = m->body_last = NULL;
	}
	return fb;
}

/*
 * Decode and transfer the contents of the message into a closed blob
 * The caller must free the returned blob
 */
blob *
messageToBlob(message *m, int destroy)
{
	blob *b;

	cli_dbgmsg("messageToBlob\n");

	b = messageExport(m, NULL,
		(void *(*)(void))blobCreate,
		(void(*)(void *))blobDestroy,
		(void(*)(void *, const char *, const char *))blobSetFilename,
		(void(*)(void *, const unsigned char *, size_t))blobAddData,
		(void *(*)(text *, void *, int))textToBlob,
		(void(*)(void *, cli_ctx *))NULL,
		destroy);

	if(destroy && m->body_first) {
		textDestroy(m->body_first);
		m->body_first = m->body_last = NULL;
	}
	return b;
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
			i, (int)enctype);

		switch(enctype) {
			case NOENCODING:
			case BINARY:
			case EIGHTBIT:
				/*
				 * Fast copy
				 */
				for(t_line = messageGetBody(m); t_line; t_line = t_line->t_next) {
					if(first == NULL)
						first = last = cli_malloc(sizeof(text));
					else if (last) {
						last->t_next = cli_malloc(sizeof(text));
						last = last->t_next;
					}

					if(last == NULL) {
						if(first) {
							textDestroy(first);
						}
						return NULL;
					}
					if(t_line->t_line)
						last->t_line = lineLink(t_line->t_line);
					else
						last->t_line = NULL;	/* empty line */
				}
				continue;
			case UUENCODE:
				cli_warnmsg("messageToText: Unexpected attempt to handle uuencoded file\n");
				if(first) {
					if(last)
						last->t_next = NULL;
					textDestroy(first);
				}
				return NULL;
			case YENCODE:
				t_line = yEncBegin(m);

				if(t_line == NULL) {
					/*cli_warnmsg("YENCODED attachment is missing begin statement\n");*/
					if(first) {
						if(last)
							last->t_next = NULL;
						textDestroy(first);
					}
					return NULL;
				}
				t_line = t_line->t_next;
			default:
				if((i == 0) && binhexBegin(m))
					cli_warnmsg("Binhex messages not supported yet.\n");
				t_line = messageGetBody(m);
		}

		for(; t_line; t_line = t_line->t_next) {
			unsigned char data[1024];
			unsigned char *uptr;
			const char *line = lineGetData(t_line->t_line);

			if(enctype == BASE64)
				/*
				 * ignore blanks - breaks RFC which is
				 * probably the point!
				 */
				if(line == NULL)
					continue;

			assert((line == NULL) || (strlen(line) <= sizeof(data)));

			uptr = decodeLine(m, enctype, line, data, sizeof(data));

			if(uptr == NULL)
				break;

			assert(uptr <= &data[sizeof(data)]);

			if(first == NULL)
				first = last = cli_malloc(sizeof(text));
			else if (last) {
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
			else if(line && (strncmp((const char *)data, line, strlen(line)) == 0)) {
#ifdef	CL_DEBUG
				cli_dbgmsg("messageToText: decoded line is the same(%s)\n", data);
#endif
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
				else if (last) {
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

text *
yEncBegin(message *m)
{
	return m->yenc;
}

/*
 * Scan to find the BINHEX message (if any)
 */
#if	0
const text *
binhexBegin(message *m)
{
	const text *t_line;

	for(t_line = messageGetBody(m); t_line; t_line = t_line->t_next)
		if(strcasecmp(t_line->t_text, "(This file must be converted with BinHex 4.0)") == 0)
			return t_line;

	return NULL;
}
#else
text *
binhexBegin(message *m)
{
	return m->binhex;
}
#endif

/*
 * Scan to find a bounce message. There is no standard for these, not
 * even a convention, so don't expect this to be foolproof
 */
#if	0
text *
bounceBegin(message *m)
{
	const text *t_line;

	for(t_line = messageGetBody(m); t_line; t_line = t_line->t_next)
		if(cli_filetype(t_line->t_text, strlen(t_line->t_text)) == CL_TYPE_MAIL)
			return t_line;

	return NULL;
}
#else
text *
bounceBegin(message *m)
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
text *
encodingLine(message *m)
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
unsigned char *
decodeLine(message *m, encoding_type et, const char *line, unsigned char *buf, size_t buflen)
{
	size_t len, reallen;
	bool softbreak;
	char *p2, *copy;
	char base64buf[RFC2045LENGTH + 1];

	/*cli_dbgmsg("decodeLine(et = %d buflen = %u)\n", (int)et, buflen);*/

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
				buf = (unsigned char *)cli_strrcpy((char *)buf, line);
			/* Put the new line back in */
			return (unsigned char *)cli_strrcpy((char *)buf, "\n");

		case QUOTEDPRINTABLE:
			if(line == NULL) {	/* empty line */
				*buf++ = '\n';
				break;
			}

			softbreak = FALSE;
			while(buflen && *line) {
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
						 * adhering to RFC2045
						 */
						*buf++ = byte;
						break;
					}

					/*
					 * Handle messages that use a broken
					 * quoted-printable encoding of
					 * href=\"http://, instead of =3D
					 */
					if(byte != '=')
						byte = (byte << 4) | hex(*line);
					else
						line -= 2;

					*buf++ = byte;
				} else
					*buf++ = *line;
				++line;
				--buflen;
			}
			if(!softbreak)
				/* Put the new line back in */
				*buf++ = '\n';
			break;

		case BASE64:
			if(line == NULL)
				break;
			/*
			 * RFC2045 sets the maximum length to 76 bytes
			 * but many e-mail clients ignore that
			 */
			if(strlen(line) < sizeof(base64buf)) {
				strcpy(base64buf, line);
				copy = base64buf;
			} else {
				copy = cli_strdup(line);
				if(copy == NULL)
					break;
			}

			p2 = strchr(copy, '=');
			if(p2)
				*p2 = '\0';

			sanitiseBase64(copy);

			/*
			 * Klez doesn't always put "=" on the last line
			 */
			buf = decode(m, copy, buf, base64, (p2 == NULL) && ((strlen(copy) & 3) == 0));

			if(copy != base64buf)
				free(copy);
			break;

		case UUENCODE:
			assert(m->base64chars == 0);

			if((line == NULL) || (*line == '\0'))	/* empty line */
				break;
			if(strcasecmp(line, "end") == 0)
				break;
			if(isuuencodebegin(line))
				break;

			if((line[0] & 0x3F) == ' ')
				break;

			/*
			 * reallen contains the number of bytes that were
			 *	encoded
			 */
			reallen = (size_t)uudecode(*line++);
			if(reallen <= 0)
				break;
			if(reallen > 62)
				break;
			len = strlen(line);

			if((len > buflen) || (reallen > len))
				/*
				 * In practice this should never occur since
				 * the maximum length of a uuencoded line is
				 * 62 characters
				 */
				cli_dbgmsg("uudecode: buffer overflow stopped, attempting to ignore but decoding may fail\n");
			else {
				(void)decode(m, line, buf, uudecode, (len & 3) == 0);
				buf = &buf[reallen];
			}
			m->base64chars = 0;	/* this happens with broken uuencoded files */
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
	cli_dbgmsg("sanitiseBase64 '%s'\n", s);
	while(*s)
		if(base64Table[(unsigned int)(*s & 0xFF)] == 255) {
			char *p1;

			for(p1 = s; p1[0] != '\0'; p1++)
				p1[0] = p1[1];
		} else
			s++;
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

	/*cli_dbgmsg("decode %s (len %d isFast %d base64chars %d)\n", in,
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
			 * can make use of some architecture's ability to
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
	else if(in == NULL) {	/* flush */
		int nbytes;

		if(m->base64chars == 0)
			return out;

		cli_dbgmsg("base64chars = %d (%c %c %c)\n", m->base64chars,
			isalnum(cb1) ? cb1 : '@',
			isalnum(cb2) ? cb2 : '@',
			isalnum(cb3) ? cb3 : '@');

		m->base64chars--;
		b1 = cb1;
		nbytes = 1;

		if(m->base64chars) {
			m->base64chars--;
			b2 = cb2;

			if(m->base64chars) {
				nbytes = 2;
				m->base64chars--;
				b3 = cb3;
				nbytes = 3;
			} else if(b2)
				nbytes = 2;
		}

		switch(nbytes) {
			case 3:
				b4 = '\0';
				/* fall through */
			case 4:
				*out++ = (b1 << 2) | ((b2 >> 4) & 0x3);
				*out++ = (b2 << 4) | ((b3 >> 2) & 0xF);
				if((nbytes == 4) || (b3&0x3))
					*out++ = (b3 << 6) | (b4 & 0x3F);
				break;
			case 2:
				*out++ = (b1 << 2) | ((b2 >> 4) & 0x3);
				if((b2 << 4) & 0xFF)
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
			case 4:
				*out++ = (b1 << 2) | ((b2 >> 4) & 0x3);
				*out++ = (b2 << 4) | ((b3 >> 2) & 0xF);
				*out++ = (b3 << 6) | (b4 & 0x3F);
				continue;
			case 3:
				m->base64_3 = b3;
			case 2:
				m->base64_2 = b2;
			case 1:
				m->base64_1 = b1;
				m->base64chars = nbytes;
				break;
			default:
				assert(0);
		}
		break;	/* nbytes != 4 => EOL */
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
	if((c >= 'a') && (c <= 'f'))
		return c - 'a' + 10;
	cli_dbgmsg("Illegal hex character '%c'\n", c);

	/*
	 * Some mails (notably some spam) break RFC2045 by failing to encode
	 * the '=' character
	 */
	return '=';
}

static unsigned char
base64(char c)
{
	const unsigned char ret = base64Table[(unsigned int)(c & 0xFF)];

	if(ret == 255) {
		/*cli_dbgmsg("Illegal character <%c> in base64 encoding\n", c);*/
		return 63;
	}
	return ret;
}

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

void
messageSetCTX(message *m, cli_ctx *ctx)
{
	m->ctx = ctx;
}

int
messageContainsVirus(const message *m)
{
	return m->isInfected ? TRUE : FALSE;
}

/*
 * We've run out of memory. Try to recover some by
 * deduping the message
 *
 * FIXME: this can take a long time. The real solution is for system admins
 *	to refrain from setting ulimits too low, then this routine won't be
 *	called
 */
static void
messageDedup(message *m)
{
	const text *t1;
	size_t saved = 0;

	cli_dbgmsg("messageDedup\n");

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
		if(t1 == m->binhex)
			continue;
		if(t1 == m->yenc)
			continue;

		for(t2 = t1->t_next; t2; t2 = t2->t_next) {
			const char *d2;
			line_t *l2 = t2->t_line;

			if(l2 == NULL)
				continue;
			d2 = lineGetData(l2);
			if(d1 == d2)
				/* already linked */
				continue;
			if(strcmp(d1, d2) == 0) {
				if(lineUnlink(l2) == NULL)
					saved += strlen(d1) + 1;
				t2->t_line = lineLink(l1);
				if(t2->t_line == NULL) {
					cli_errmsg("messageDedup: out of memory\n");
					return;
				}
				if(++r1 == 255)
					break;
			}
		}
	}

	cli_dbgmsg("messageDedup reclaimed %lu bytes\n", (unsigned long)saved);
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
	const char *ptr;
	char *ret, *out;
	enum { LANGUAGE, CHARSET, CONTENTS } field;

	if(strstr(in, "*0*=") != NULL) {
		char *p;

		/* Don't handle continuations, decode what we can */
		p = ret = cli_malloc(strlen(in) + 16);
		if(ret == NULL) {
            cli_errmsg("rfc2331: out of memory, unable to proceed\n");
			return NULL;
        }

		do {
			switch(*in) {
				default:
					*p++ = *in++;
					continue;
				case '*':
					do
						in++;
					while((*in != '*') && *in);
					if(*in) {
						in++;
						continue;
					}
					break;
				case '=':
					/*strcpy(p, in);*/
					strcpy(p, "=rfc2231failure");
                                        p += strlen ("=rfc2231failure");
					break;
			}
			break;
		} while(*in);
                *p = '\0';

		cli_dbgmsg("RFC2231 parameter continuations are not yet handled, returning \"%s\"\n",
			ret);
		return ret;
	}

	ptr = strstr(in, "*0=");
	if(ptr != NULL)
		/*
		 * Parameter continuation, with no continuation
		 * Thunderbird 1.5 (and possibly other versions) does this
		 */
		field = CONTENTS;
	else {
		ptr = strstr(in, "*=");
		field = LANGUAGE;
	}

	if(ptr == NULL) {	/* quick return */
		out = ret = cli_strdup(in);
		while(*out)
			*out++ &= 0x7F;
		return ret;
	}

	cli_dbgmsg("rfc2231 '%s'\n", in);

	ret = cli_malloc(strlen(in) + 1);

	if(ret == NULL) {
        cli_errmsg("rfc2331: out of memory for ret\n");
		return NULL;
    }

	/*
	 * memcpy(out, in, (ptr - in));
	 * out = &out[ptr - in];
	 * in = ptr;
	 */
	out = ret;
	while(in != ptr)
		*out++ = *in++;

	*out++ = '=';

	while(*ptr++ != '=')
		;

	/*
	 * We don't do anything with the language and character set, just skip
	 * over them!
	 */
	while(*ptr) {
		switch(field) {
			case LANGUAGE:
				if(*ptr == '\'')
					field = CHARSET;
				break;
			case CHARSET:
				if(*ptr == '\'')
					field = CONTENTS;
				break;
			case CONTENTS:
				if(*ptr == '%') {
					unsigned char byte;

					if((*++ptr == '\0') || (*ptr == '\n'))
						break;

					byte = hex(*ptr);

					if((*++ptr == '\0') || (*ptr == '\n')) {
						*out++ = byte;
						break;
					}

					byte <<= 4;
					byte += hex(*ptr);
					*out++ = byte;
				} else
					*out++ = *ptr;
		}
		if(*ptr++ == '\0')
			/*
			 * Incorrect message that has just one character after
			 * a '%'.
			 * FIXME: stash something in out that would, for example
			 *	treat %2 as %02, assuming field == CONTENTS
			 */
			break;
	}

	if(field != CONTENTS) {
		free(ret);
		cli_dbgmsg("Invalid RFC2231 header: '%s'\n", in);
		return cli_strdup("");
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

#define	MAX_PATTERN_SIZ	50	/* maximum string lengths */

static int
simil(const char *str1, const char *str2)
{
	LINK1 top = NULL;
	unsigned int score = 0;
	size_t common, total;
	size_t len1, len2;
	char *rs1 = NULL, *rs2 = NULL;
	char *s1, *s2;
	char ls1[MAX_PATTERN_SIZ], ls2[MAX_PATTERN_SIZ];

	if(strcasecmp(str1, str2) == 0)
		return 100;

	if((s1 = cli_strdup(str1)) == NULL)
		return OUT_OF_MEMORY;
	if((s2 = cli_strdup(str2)) == NULL) {
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
			score += (unsigned int)common;
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
	unsigned int common, maxchars = 0;
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
						unsigned int diff = common - maxchars;
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
	if((element->d1 = cli_strdup(string)) == NULL) {
		free (element);
		return OUT_OF_MEMORY;
	}
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

/*
 * Have we found a line that is a start of a uuencoded file (see uuencode(5))?
 */
int
isuuencodebegin(const char *line)
{
	if(line[0] != 'b')	/* quick check */
		return 0;

	if(strlen(line) < 10)
		return 0;

	return (strncasecmp(line, "begin ", 6) == 0) &&
		isdigit(line[6]) && isdigit(line[7]) &&
		isdigit(line[8]) && (line[9] == ' ');
}

#if HAVE_JSON
json_object *messageGetJObj(message *m)
{
	assert(m != NULL);

	if(m->jobj == NULL)
		m->jobj = cli_jsonobj(NULL, NULL);

	return m->jobj;
}
#endif

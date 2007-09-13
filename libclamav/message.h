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
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

#ifndef	_MESSAGE_H
#define	_MESSAGE_H

/* The contents could change, ONLY access in message.c */
typedef struct message {
	mime_type	mimeType;
	encoding_type	*encodingTypes;
	int	numberOfEncTypes;	/* size of encodingTypes */
	char	*mimeSubtype;
	int	numberOfArguments;	/* count of mimeArguments */
	char	**mimeArguments;
	char	*mimeDispositionType;	/* probably attachment */
	text	*body_first, *body_last;
	cli_ctx	*ctx;

	char	base64_1, base64_2, base64_3;
	int	base64chars;
	unsigned	int	isInfected : 1;

	/*
	 * Markers for the start of various non MIME messages that could
	 * be included within this message
	 */
	text	*bounce;	/* start of a bounced message */
	text	*binhex;	/* start of a binhex message */
	text	*yenc;		/* start of a yEnc message */
	text	*encoding;	/* is the non MIME message encoded? */
	const text	*dedupedThisFar;
} message;

message	*messageCreate(void);
void	messageDestroy(message *m);
void	messageReset(message *m);
int	messageSetMimeType(message *m, const char *type);
mime_type	messageGetMimeType(const message *m);
void	messageSetMimeSubtype(message *m, const char *subtype);
const	char	*messageGetMimeSubtype(const message *m);
void	messageSetDispositionType(message *m, const char *disptype);
const	char	*messageGetDispositionType(const message *m);
void	messageAddArgument(message *m, const char *arg);
void	messageAddArguments(message *m, const char *arg);
char	*messageFindArgument(const message *m, const char *variable);
char	*messageGetFilename(const message *m);
int	messageHasFilename(const message *m);
void	messageSetEncoding(message *m, const char *enctype);
encoding_type	messageGetEncoding(const message *m);
int	messageAddLine(message *m, line_t *line);
int	messageAddStr(message *m, const char *data);
int	messageAddStrAtTop(message *m, const char *data);
int	messageMoveText(message *m, text *t, message *old_message);
text	*messageGetBody(message *m);
unsigned	char	*base64Flush(message *m, unsigned char *buf);
fileblob	*messageToFileblob(message *m, const char *dir, int destroy);
blob	*messageToBlob(message *m, int destroy);
text	*messageToText(message *m);
text	*binhexBegin(message *m);
text	*yEncBegin(message *m);
text	*bounceBegin(message *m);
text	*encodingLine(message *m);
void	messageClearMarkers(message *m);
unsigned char	*decodeLine(message *m, encoding_type enctype, const char *line, unsigned char *buf, size_t buflen);
int	isuuencodebegin(const char *line);
void	messageSetCTX(message *m, cli_ctx *ctx);
int	messageContainsVirus(const message *m);

#endif	/*_MESSAGE_H*/

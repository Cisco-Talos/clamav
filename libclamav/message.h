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

#ifndef	_MESSAGE_H
#define	_MESSAGE_H

typedef struct message {
	mime_type	mimeType;
	encoding_type	*encodingTypes;
	int	numberOfEncTypes;	/* size of encodingTypes */
	char	*mimeSubtype;
	int	numberOfArguments;	/* count of mimeArguments */
	char	**mimeArguments;
	char	*mimeDispositionType;	/* probably attachment */
	text	*body_first, *body_last;

	char	base64_1, base64_2, base64_3;
	int	base64chars;
	/*
	 * Markers for the start of various non MIME messages that could
	 * be included within this message
	 */
	const text	*bounce;	/* start of a bounced message */
	const text	*binhex;	/* start of a binhex message */
	const text	*uuencode;	/* start of a uuencoded message */
	const text	*yenc;		/* start of a yEnc message */
	const text	*encoding;	/* is the non MIME message encoded? */
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
const	char	*messageFindArgument(const message *m, const char *variable);
void	messageSetEncoding(message *m, const char *enctype);
encoding_type	messageGetEncoding(const message *m);
int	messageAddLine(message *m, line_t *line);
int	messageAddStr(message *m, const char *data);
int	messageAddStrAtTop(message *m, const char *data);
const	text	*messageGetBody(const message *m);
void	messageClean(message *m);
fileblob	*messageToFileblob(message *m, const char *dir);
blob	*messageToBlob(message *m);
text	*messageToText(message *m);
const	text	*binhexBegin(const message *m);
const	text	*uuencodeBegin(const message *m);
const	text	*yEncBegin(const message *m);
const	text	*bounceBegin(const message *m);
const	text	*encodingLine(const message *m);
void	messageClearMarkers(message *m);
unsigned char	*decodeLine(message *m, encoding_type enctype, const char *line, unsigned char *buf, size_t buflen);
int	isuuencodebegin(const char *line);

#endif	/*_MESSAGE_H*/

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
 * $Log: message.h,v $
 * Revision 1.10  2004/04/05 12:04:56  nigelhorne
 * Scan attachments with no filename
 *
 * Revision 1.9  2004/04/01 15:32:34  nigelhorne
 * Graceful exit if messageAddLine fails in strdup
 *
 * Revision 1.8  2004/03/29 09:22:03  nigelhorne
 * Tidy up code and reduce shuffling of data
 *
 * Revision 1.7  2004/03/21 17:19:49  nigelhorne
 * Handle bounce messages with no headers
 *
 * Revision 1.6  2004/03/21 09:41:27  nigelhorne
 * Faster scanning for non MIME messages
 *
 * Revision 1.5  2004/01/28 10:15:24  nigelhorne
 * Added support to scan some bounce messages
 *
 * Revision 1.4  2004/01/14 18:02:55  nigelhorne
 * added definition of binhexBegin
 *
 */

#ifndef	_MESSAGE_H
#define	_MESSAGE_H

typedef struct message {
	mime_type	mimeType;
	encoding_type	encodingType;
	char	*mimeSubtype;
	int	numberOfArguments;	/* count of mimeArguments */
	char	**mimeArguments;
	char	*mimeDispositionType;	/* probably attachment */
	text	*body_first, *body_last;
	/*
	 * Markers for the start of various non MIME messages that could
	 * be included within this message
	 */
	text	*bounce;	/* start of a bounced message */
	text	*binhex;	/* start of a binhex message */
	text	*uuencode;	/* start of a uuencoded message */
	text	*encoding;	/* is the non MIME message encoded? */
} message;

message	*messageCreate(void);
void	messageDestroy(message *m);
void	messageReset(message *m);
void	messageSetMimeType(message *m, const char *type);
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
int	messageAddLine(message *m, const char *line, int takeCopy);
const	text	*messageGetBody(const message *m);
void	messageClean(message *m);
blob	*messageToBlob(message *m);
text	*messageToText(const message *m);
const	text	*uuencodeBegin(const message *m);
const	text	*binhexBegin(const message *m);
const	text	*bounceBegin(const message *m);
const	text	*encodingLine(const message *m);

#endif	/*_MESSAGE_H*/

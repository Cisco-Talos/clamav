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
 * Revision 1.24  2004/11/28 22:06:40  nigelhorne
 * Tidy space only headers code
 *
 * Revision 1.23  2004/11/28 21:05:50  nigelhorne
 * Handle headers with only spaces
 *
 * Revision 1.22  2004/11/22 15:18:51  nigelhorne
 * Performance work
 *
 * Revision 1.21  2004/10/16 17:24:15  nigelhorne
 * Handle colons in quotes in headers
 *
 * Revision 1.20  2004/10/14 17:45:55  nigelhorne
 * Try to reclaim some memory if it becomes low when decoding
 *
 * Revision 1.19  2004/09/17 13:47:19  nigelhorne
 * Handle yEnc attachments
 *
 * Revision 1.18  2004/09/17 09:48:53  nigelhorne
 * Handle attempts to hide mime type
 *
 * Revision 1.17  2004/09/15 18:08:23  nigelhorne
 * Handle multiple encoding types
 *
 * Revision 1.16  2004/08/23 13:15:16  nigelhorne
 * messageClearMarkers
 *
 * Revision 1.15  2004/08/22 15:08:59  nigelhorne
 * messageExport
 *
 * Revision 1.14  2004/08/22 10:34:24  nigelhorne
 * Use fileblob
 *
 * Revision 1.13  2004/08/21 11:57:57  nigelhorne
 * Use line.[ch]
 *
 * Revision 1.12  2004/07/20 14:35:29  nigelhorne
 * Some MYDOOM.I were getting through
 *
 * Revision 1.11  2004/05/06 18:01:25  nigelhorne
 * Force attachments marked as RFC822 messages to be scanned
 *
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

#endif	/*_MESSAGE_H*/

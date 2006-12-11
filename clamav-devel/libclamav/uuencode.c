/*
 *  Copyright (C) 2006 Nigel Horne <njh@bandsman.co.uk>
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
static	char	const	rcsid[] = "$Id: uuencode.c,v 1.8 2006/12/11 11:55:11 njh Exp $";

#include "clamav.h"

#if	HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdio.h>
#include <memory.h>
#include <sys/stat.h>
#ifdef	HAVE_STRINGS_H
#include <strings.h>
#endif
#include "others.h"
#include "str.h"

#ifdef	C_WINDOWS
#include <io.h>
#endif

#include "mbox.h"
#include "uuencode.h"

/* Maximum line length according to RFC821 */
#define	RFC2821LENGTH	1000

int
cli_uuencode(const char *dir, int desc)
{
	FILE *fin;
	int i;
	message *m;
	char buffer[RFC2821LENGTH + 1];

	i = dup(desc);
	if((fin = fdopen(i, "rb")) == NULL) {
		cli_errmsg("Can't open descriptor %d\n", desc);
		close(i);
		return CL_EOPEN;
	}
	if(fgets(buffer, sizeof(buffer) - 1, fin) == NULL) {
		/* empty message */
		fclose(fin);
		return CL_CLEAN;
	}
	if(!isuuencodebegin(buffer)) {
		fclose(fin);
		cli_errmsg("Message is not in uuencoded format\n");
		return CL_EFORMAT;
	}

	m = messageCreate();
	if(m == NULL) {
		fclose(fin);
		return CL_EMEM;
	}

	cli_dbgmsg("found uuencode file\n");

	if(uudecodeFile(m, buffer, dir, fin) < 0) {
		messageDestroy(m);
		fclose(fin);
		cli_errmsg("Message is not in uuencoded format\n");
		return CL_EFORMAT;
	}
	messageDestroy(m);

	fclose(fin);

	return CL_CLEAN;	/* a lie - but it gets things going */
}

/*
 * Save the uuencoded part of the file as it is read in since there's no need
 * to include it in the parse tree. Saves memory and parse time.
 * Return < 0 for failure
 */
int
uudecodeFile(message *m, const char *firstline, const char *dir, FILE *fin)
{
	fileblob *fb;
	char buffer[RFC2821LENGTH + 1];
	char *filename = cli_strtok(firstline, 2, " ");

	if(filename == NULL)
		return -1;

	fb = fileblobCreate();
	if(fb == NULL) {
		free(filename);
		return -1;
	}

	fileblobSetFilename(fb, dir, filename);
	cli_dbgmsg("uudecode %s\n", filename);
	free(filename);

	while(fgets(buffer, sizeof(buffer) - 1, fin) != NULL) {
		unsigned char data[1024];
		const unsigned char *uptr;
		size_t len;

		cli_chomp(buffer);
		if(strcasecmp(buffer, "end") == 0)
			break;
		if(buffer[0] == '\0')
			break;

		uptr = decodeLine(m, UUENCODE, buffer, data, sizeof(data));
		if(uptr == NULL)
			break;

		len = (size_t)(uptr - data);
		if((len > 62) || (len == 0))
			break;

		if(fileblobAddData(fb, data, len) < 0)
			break;
	}

	fileblobDestroy(fb);

	return 1;
}

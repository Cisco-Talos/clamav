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
 */

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

#include "mbox.h"
#include "uuencode.h"

/* Maximum line length according to RFC821 */
#define	RFC2821LENGTH	1000

int
cli_uuencode(const char *dir, fmap_t *map)
{
	message *m;
	char buffer[RFC2821LENGTH + 1];
	size_t at = 0;

	if(!fmap_gets(map, buffer, &at, sizeof(buffer) - 1)) {
		/* empty message */
		return CL_CLEAN;
	}
	if(!isuuencodebegin(buffer)) {
		cli_dbgmsg("Message is not in uuencoded format\n");
		return CL_EFORMAT;
	}

	m = messageCreate();
	if(m == NULL) {
		return CL_EMEM;
	}

	cli_dbgmsg("found uuencode file\n");

	if(uudecodeFile(m, buffer, dir, map, &at) < 0) {
		messageDestroy(m);
		cli_dbgmsg("Message is not in uuencoded format\n");
		return CL_EFORMAT;
	}
	messageDestroy(m);

	return CL_CLEAN;	/* a lie - but it gets things going */
}

/*
 * Save the uuencoded part of the file as it is read in since there's no need
 * to include it in the parse tree. Saves memory and parse time.
 * Return < 0 for failure
 */
int
uudecodeFile(message *m, const char *firstline, const char *dir, fmap_t *map, size_t *at)
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

	while(fmap_gets(map, buffer, at, sizeof(buffer) - 1)) {
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

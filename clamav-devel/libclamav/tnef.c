/*
 *  Copyright (C) 2005 Nigel Horne <njh@bandsman.co.uk>
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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

static	char	const	rcsid[] = "$Id: tnef.c,v 1.5 2005/03/25 18:30:18 nigelhorne Exp $";

#include <stdio.h>

#include "cltypes.h"
#include "clamav.h"
#include "others.h"
#include "tnef.h"

static	int	tnef_attachment(int desc);

/*
 * The algorithm will be based on kdepim/ktnef/lib/ktnefparser.cpp from
 * KDE, rewritten in C by NJH. The algorithm is released under the GPL and is
 *	Copyright (C) 2002 Michael Goffioul <kdeprint@swing.be>
 *
 * TODO: Use mmap on systems that support it
 */
#define	TNEF_SIGNATURE	0x223E9f78
#define	LVL_MESSAGE	0x01
#define	LVL_ATTACHMENT	0x02

#define	attMSGCLASS	0x8008
#define	attDATEMODIFIED	0x8020
#define	attTNEFVERSION	0x9006
#define	attOEMCODEPAGE	0x9007

int
cli_tnef(const char *dir, int desc)
{
	uint32_t i32;
	uint16_t i16;
	uint8_t i8;

	cli_warnmsg("TNEF not scanned yet - virus samples are welcome\n");

	lseek(desc, 0L, SEEK_SET);

	if(cli_readn(desc, &i32, sizeof(uint32_t)) != sizeof(uint32_t))
		return CL_EIO;

#ifdef	WORDS_BIGENDIAN
	if(i32 != TNEF_SIGNATURE)
		return CL_EFORMAT;
#else
	/* TODO */
#endif

	if(cli_readn(desc, &i16, sizeof(uint16_t)) != sizeof(uint16_t))
		return CL_EIO;

	for(;;) {
		int alldone = 0;

		switch(cli_readn(desc, &i8, sizeof(uint8_t))) {
			case -1:
				perror("read");
				return CL_EIO;
			case 0:
				alldone = 1;
				break;
			case sizeof(uint8_t):
				break;
			default:
				return CL_EIO;
		}
		if(alldone)
			break;
		switch(i8) {
			case LVL_MESSAGE:
				/*cli_dbgmsg("TNEF - found message\n");*/
				if(tnef_message(desc) != 0) {
					cli_errmsg("Error reading TNEF message\n");
					return CL_EFORMAT;
				}
				break;
			case LVL_ATTACHMENT:
				/*cli_dbgmsg("TNEF - found attachment\n");*/
				if(tnef_attachment(desc) != 0) {
					cli_errmsg("Error reading TNEF message\n");
					return CL_EFORMAT;
				}
				break;
			default:
				cli_errmsg("TNEF - unknown level %d\n", (int)i8);
				return CL_EFORMAT;
		}
	}

	return CL_CLEAN;
}

/*
 * TODO: Debug mode only apart from attBODY?
 */
static int
tnef_message(int desc)
{
	uint32_t i32, length;
	uint16_t i16, tag, type;
	off_t offset;
	char *string;

	if(cli_readn(desc, &i32, sizeof(uint32_t)) != sizeof(uint32_t))
		return -1;

	tag = i32 & 0xFFFF;
	type = (i32 & 0xFFFF0000) >> 16;

	if(cli_readn(desc, &i32, sizeof(uint32_t)) != sizeof(uint32_t))
		return -1;

	length = i32;

	/*cli_dbgmsg("message tag 0x%x, type 0x%x, length %u\n", tag, type, length);*/

	offset = lseek(desc, 0L, SEEK_CUR);

	/*
	 * a lot of this stuff should be only discovered in debug mode...
	 */
	switch(tag) {
		case attTNEFVERSION:
			/*assert(length == sizeof(uint32_t))*/
			if(cli_readn(desc, &i32, sizeof(uint32_t)) != sizeof(uint32_t))
				return -1;
			cli_dbgmsg("TNEF version %d\n", i32);
			break;
		case attOEMCODEPAGE:
			/*assert(length == sizeof(uint32_t))*/
			if(cli_readn(desc, &i32, sizeof(uint32_t)) != sizeof(uint32_t))
				return -1;
			cli_dbgmsg("TNEF codepage %d\n", i32);
			break;
		case attDATEMODIFIED:
			/* 14 bytes, long */
			break;
		case attMSGCLASS:
			string = cli_malloc(length + 1);
			if((unsigned int)cli_readn(desc, string, length) != length)
				return -1;
			string[length] = '\0';
			cli_dbgmsg("TNEF class %s\n", string);
			free(string);
			break;
		default:
			cli_errmsg("TNEF - unsupported tag 0x%x type 0x%d length %u\n", tag, type, length);
			break;
	}

	/*cli_dbgmsg("%lu %lu\n", offset + length, lseek(desc, 0L, SEEK_CUR));*/

	lseek(desc, offset + length, SEEK_SET);	/* shouldn't be needed */

	/* Checksum - TODO, verify */
	if(cli_readn(desc, &i16, sizeof(uint16_t)) != sizeof(uint16_t))
		return -1;

	return 0;
}

static int
tnef_attachment(int desc)
{
	return 0;
}

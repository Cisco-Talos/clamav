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

static	char	const	rcsid[] = "$Id: tnef.c,v 1.7 2005/03/25 21:58:01 nigelhorne Exp $";

#include <stdio.h>

#include "cltypes.h"
#include "clamav.h"
#include "others.h"
#include "tnef.h"
#include "blob.h"

static	int	tnef_message(int desc);
static	int	tnef_attachment(int desc, const char *dir, fileblob **fbref);

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
#define	attBODY		0x800c
#define	attATTACHDATA	0x800f	/* Attachment Data */
#define	attATTACHTITLE	0x8010	/* Attachment File Name */
#define	attDATEMODIFIED	0x8020
#define	attTNEFVERSION	0x9006
#define	attOEMCODEPAGE	0x9007

/* FIXME: use stdio */
/* FIXME: only works on little endian machines */
int
cli_tnef(const char *dir, int desc)
{
	uint32_t i32;
	uint16_t i16;
	uint8_t i8;
	fileblob *fb;
	int ret, alldone;

	lseek(desc, 0L, SEEK_SET);

	if(cli_readn(desc, &i32, sizeof(uint32_t)) != sizeof(uint32_t))
		return CL_EIO;

#if	WORDS_BIGENDIAN == 0
	/* little endian */
	if(i32 != TNEF_SIGNATURE)
		return CL_EFORMAT;
#else
	/* TODO */
#endif

	if(cli_readn(desc, &i16, sizeof(uint16_t)) != sizeof(uint16_t))
		return CL_EIO;

	fb = NULL;
	ret = CL_CLEAN;
	alldone = 0;

	do {
		switch(cli_readn(desc, &i8, sizeof(uint8_t))) {
			case -1:
				perror("read");
				ret = CL_EIO;
				alldone = 1;
				break;
			case 0:
				alldone = 1;
				break;
			case sizeof(uint8_t):
				break;
			default:
				ret = CL_EIO;
				alldone = 1;
				break;
		}
		if(alldone)
			break;
		switch(i8) {
			case LVL_MESSAGE:
				/*cli_dbgmsg("TNEF - found message\n");*/
				if(tnef_message(desc) != 0) {
					cli_errmsg("Error reading TNEF message\n");
					ret = CL_EFORMAT;
					alldone = 1;
				}
				break;
			case LVL_ATTACHMENT:
				/*cli_dbgmsg("TNEF - found attachment\n");*/
				if(tnef_attachment(desc, dir, &fb) != 0) {
					cli_errmsg("Error reading TNEF message\n");
					ret = CL_EFORMAT;
					alldone = 1;
				}
				break;
			case 0:
				break;
			default:
				cli_errmsg("TNEF - unknown level %d\n", (int)i8);
				ret = CL_EFORMAT;
				alldone = 1;
				break;
		}
	} while(!alldone);

	if(fb) {
		fileblobDestroy(fb);
		fb = NULL;
	}
	return CL_CLEAN;
}

static int
tnef_message(int desc)
{
	uint32_t i32, length;
	uint16_t i16, tag, type;
	off_t offset;
#if	CL_DEBUG
	char *string;
#endif

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
		case attBODY:
			cli_warnmsg("TNEF body not being scanned - report to bugs@clamav.net\n");
			break;
#if	CL_DEBUG
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
			cli_dbgmsg("TNEF - unsupported message tag 0x%x type 0x%d length %u\n", tag, type, length);
			break;
#endif
	}

	/*cli_dbgmsg("%lu %lu\n", offset + length, lseek(desc, 0L, SEEK_CUR));*/

	lseek(desc, offset + length, SEEK_SET);	/* shouldn't be needed */

	/* Checksum - TODO, verify */
	if(cli_readn(desc, &i16, sizeof(uint16_t)) != sizeof(uint16_t))
		return -1;

	return 0;
}

static int
tnef_attachment(int desc, const char *dir, fileblob **fbref)
{
	uint32_t i32, length, todo;
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

	switch(tag) {
		case attATTACHTITLE:
			if(*fbref != NULL)
				fileblobDestroy(*fbref);
			*fbref = fileblobCreate();

			if(*fbref == NULL)
				return -1;
			string = cli_malloc(length + 1);

			if((unsigned int)cli_readn(desc, string, length) != length)
				return -1;
			string[length] = '\0';
			cli_dbgmsg("TNEF filename %s\n", string);
			fileblobSetFilename(*fbref, dir, string);
			free(string);
			break;
		case attATTACHDATA:
			if(*fbref == NULL) {
				*fbref = fileblobCreate();

				if(*fbref == NULL)
					return -1;
			}
			/* FIXME: use stdio */
			todo = length;
			while(todo) {
				unsigned char *c;

				if(cli_readn(desc, &c, 1) != 1)
					break;
				fileblobAddData(*fbref, (const unsigned char *)&c, 1);
			}
			break;
		default:
			cli_dbgmsg("TNEF - unsupported attachment tag 0x%x type 0x%d length %u\n", tag, type, length);
			break;
	}

	/*cli_dbgmsg("%lu %lu\n", offset + length, lseek(desc, 0L, SEEK_CUR));*/

	lseek(desc, offset + length, SEEK_SET);	/* shouldn't be needed */

	/* Checksum - TODO, verify */
	if(cli_readn(desc, &i16, sizeof(uint16_t)) != sizeof(uint16_t))
		return -1;

	return 0;
}

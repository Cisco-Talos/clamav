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
 *
 * The algorithm is based on kdepim/ktnef/lib/ktnefparser.cpp from
 * KDE, rewritten in C by NJH. That algorithm is released under the GPL and is
 *	Copyright (C) 2002 Michael Goffioul <kdeprint@swing.be>
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

static	char	const	rcsid[] = "$Id: tnef.c,v 1.11 2005/03/26 10:35:53 nigelhorne Exp $";

#include <stdio.h>

#include "cltypes.h"
#include "clamav.h"
#include "others.h"
#include "tnef.h"
#if	CL_DEBUG
#include "mbox.h"
#endif
#include "blob.h"

static	int	tnef_message(FILE *fp);
static	int	tnef_attachment(FILE *fp, const char *dir, fileblob **fbref);

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

#if WORDS_BIGENDIAN == 0
#define host16(v)	(v)
#define host32(v)	(v)

#else

#if	defined(C_LINUX)
#include <byteswap.h>
#define	host16(v)	__bswap_16(v)
#define	host32(v)	__bswap_32(v)
#elif	defined(C_SOLARIS)
#include <sys/byteorder.h>
#define	host16(v)	BSWAP_16(v)
#define	host32(v)	BSWAP_32(v)
#else
#define	host16(v)	((v >> 8) | (v << 8))
#define	host32(v)	((v >> 24) | ((v & 0x00FF0000) >> 8) | \
				((v & 0x0000FF00) << 8) | (v << 24))
#endif

#endif

/* FIXME: only works on little endian machines */
int
cli_tnef(const char *dir, int desc)
{
	uint32_t i32;
	uint16_t i16;
	uint8_t i8;
	fileblob *fb;
	int i, ret, alldone;
	FILE *fp;

	lseek(desc, 0L, SEEK_SET);

	i = dup(desc);
	if((fp = fdopen(i, "rb")) == NULL) {
		cli_errmsg("Can't open descriptor %d\n", desc);
		close(i);
		return CL_EOPEN;
	}

	if(fread(&i32, sizeof(uint32_t), 1, fp) != 1) {
		fclose(fp);
		return CL_EIO;
	}
	if(host32(i32) != TNEF_SIGNATURE) {
		fclose(fp);
		return CL_EFORMAT;
	}

	if(fread(&i16, sizeof(uint16_t), 1, fp) != 1) {
		fclose(fp);
		return CL_EIO;
	}

	fb = NULL;
	ret = CL_CLEAN;
	alldone = 0;

	do {
		switch(fread(&i8, sizeof(uint8_t), 1, fp)) {
			case 0:
				if(ferror(fp)) {
					perror("read");
					ret = CL_EIO;
				}
				alldone = 1;
				break;
			case 1:
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
				if(tnef_message(fp) != 0) {
					cli_errmsg("Error reading TNEF message\n");
					ret = CL_EFORMAT;
					alldone = 1;
				}
				break;
			case LVL_ATTACHMENT:
				/*cli_dbgmsg("TNEF - found attachment\n");*/
				if(tnef_attachment(fp, dir, &fb) != 0) {
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
	fclose(fp);

	cli_dbgmsg("cli_tnef: returning 0\n");
	return CL_CLEAN;	/* we don't know if it's clean or not :-) */
}

static int
tnef_message(FILE *fp)
{
	uint32_t i32, length;
	uint16_t i16, tag, type;
	off_t offset;
#if	CL_DEBUG
	char *string;
#endif

	if(fread(&i32, sizeof(uint32_t), 1, fp) != 1)
		return -1;

	i32 = host32(i32);
	tag = i32 & 0xFFFF;
	type = (i32 & 0xFFFF0000) >> 16;

	if(fread(&i32, sizeof(uint32_t), 1, fp) != 1)
		return -1;
	length = host32(i32);

	cli_dbgmsg("message tag 0x%x, type 0x%x, length %u\n", tag, type, length);

	offset = ftell(fp);

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
			if(fread(&i32, sizeof(uint32_t), 1, fp) != 1)
				return -1;
			i32 = host32(i32);
			cli_dbgmsg("TNEF version %d\n", i32);
			break;
		case attOEMCODEPAGE:
			/* 8 bytes, but just print the first 4 */
			/*assert(length == sizeof(uint32_t))*/
			if(fread(&i32, sizeof(uint32_t), 1, fp) != 1)
				return -1;
			i32 = host32(i32);
			cli_dbgmsg("TNEF codepage %d\n", i32);
			break;
		case attDATEMODIFIED:
			/* 14 bytes, long */
			break;
		case attMSGCLASS:
			string = cli_malloc(length + 1);
			if(fread(string, 1, length, fp) != length)
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

	cli_dbgmsg("%lu %lu\n", (long)(offset + length), ftell(fp));

	fseek(fp, offset + length, SEEK_SET);

	/* Checksum - TODO, verify */
	if(fread(&i16, sizeof(uint16_t), 1, fp) != 1)
		return -1;

	return 0;
}

static int
tnef_attachment(FILE *fp, const char *dir, fileblob **fbref)
{
	uint32_t i32, length, todo;
	uint16_t i16, tag, type;
	off_t offset;
	char *string;

	if(fread(&i32, sizeof(uint32_t), 1, fp) != 1)
		return -1;

	i32 = host32(i32);
	tag = i32 & 0xFFFF;
	type = (i32 & 0xFFFF0000) >> 16;

	if(fread(&i32, sizeof(uint32_t), 1, fp) != 1)
		return -1;
	length = host32(i32);

	cli_dbgmsg("attachment tag 0x%x, type 0x%x, length %u\n", tag, type, length);

	offset = ftell(fp);

	switch(tag) {
		case attATTACHTITLE:
			if(*fbref != NULL)
				fileblobDestroy(*fbref);
			*fbref = fileblobCreate();

			if(*fbref == NULL)
				return -1;
			string = cli_malloc(length + 1);

			if(fread(string, 1, length, fp) != length)
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
			for(todo = length; todo; todo--) {
#if WORDS_BIGENDIAN == 1
				int c;
				unsigned char c2;

				if((c = fgetc(fp)) == EOF)
					break;
				c2 = (unsigned char)c;
				fileblobAddData(*fbref, (const unsigned char *)&c2, 1);
#else
				int c;

				if((c = fgetc(fp)) == EOF)
					break;
				fileblobAddData(*fbref, (const unsigned char *)&c, 1);
#endif
			}
			break;
		default:
			cli_dbgmsg("TNEF - unsupported attachment tag 0x%x type 0x%d length %u\n", tag, type, length);
			break;
	}

	/*cli_dbgmsg("%lu %lu\n", offset + length, lseek(desc, 0L, SEEK_CUR));*/

	fseek(fp, (long)(offset + length), SEEK_SET);	/* shouldn't be needed */

	/* Checksum - TODO, verify */
	if(fread(&i16, sizeof(uint16_t), 1, fp) != 1)
		return -1;

	return 0;
}

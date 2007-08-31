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
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 *
 * The algorithm is based on kdepim/ktnef/lib/ktnefparser.cpp from
 * KDE, rewritten in C by NJH. That algorithm is released under the GPL and is
 *	Copyright (C) 2002 Michael Goffioul <kdeprint@swing.be>
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

static	char	const	rcsid[] = "$Id: tnef.c,v 1.41 2007/02/12 22:22:27 njh Exp $";

#include <stdio.h>
#include <fcntl.h>

#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "cltypes.h"
#include "clamav.h"
#include "others.h"

#include "mbox.h"
#include "tnef.h"

static	int	tnef_message(FILE *fp, uint16_t type, uint16_t tag, int32_t length, off_t fsize);
static	int	tnef_attachment(FILE *fp, uint16_t type, uint16_t tag, int32_t length, const char *dir, fileblob **fbref, off_t fsize);
static	int	tnef_header(FILE *fp, uint8_t *part, uint16_t *type, uint16_t *tag, int32_t *length);

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

#define host16(v)	le16_to_host(v)
#define host32(v)	le32_to_host(v)


int
cli_tnef(const char *dir, int desc)
{
	uint32_t i32;
	uint16_t i16;
	fileblob *fb;
	int i, ret, alldone;
	FILE *fp;
	off_t fsize;
	struct stat statb;

	lseek(desc, 0L, SEEK_SET);

	if(fstat(desc, &statb) < 0) {
		cli_errmsg("Can't fstat descriptor %d\n", desc);
		return CL_EIO;
	}
	fsize = statb.st_size;

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
	ret = CL_CLEAN;	/* we don't know if it's clean or not :-) */
	alldone = 0;

	do {
		uint8_t part = 0;
		uint16_t type = 0, tag = 0;
		int32_t length = 0;

		switch(tnef_header(fp, &part, &type, &tag, &length)) {
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
		if(length == 0)
			continue;
		if(length < 0) {
			cli_warnmsg("Corrupt TNEF header detected - length %d\n",
				(int)length);
			ret = CL_EFORMAT;
			break;
		}
		if(alldone)
			break;
		switch(part) {
			case LVL_MESSAGE:
				cli_dbgmsg("TNEF - found message\n");
				if(fb != NULL) {
					fileblobDestroy(fb);
					fb = NULL;
				}
				fb = fileblobCreate();
				if(tnef_message(fp, type, tag, length, fsize) != 0) {
					cli_errmsg("Error reading TNEF message\n");
					ret = CL_EFORMAT;
					alldone = 1;
				}
				break;
			case LVL_ATTACHMENT:
				cli_dbgmsg("TNEF - found attachment\n");
				if(tnef_attachment(fp, type, tag, length, dir, &fb, fsize) != 0) {
					cli_errmsg("Error reading TNEF attachment\n");
					ret = CL_EFORMAT;
					alldone = 1;
				}
				break;
			case 0:
				break;
			default:
				cli_warnmsg("TNEF - unknown level %d tag 0x%x\n", (int)part, (int)tag);

				/*
				 * Dump the file incase it was part of an
				 * email that's about to be deleted
				 */
				if(cli_debug_flag) {
					int fout;
					char *filename = cli_gentemp(NULL);
					char buffer[BUFSIZ];

#ifdef	O_BINARY
					fout = open(filename, O_WRONLY|O_CREAT|O_EXCL|O_TRUNC|O_BINARY, 0600);
#else
					fout = open(filename, O_WRONLY|O_CREAT|O_EXCL|O_TRUNC, 0600);
#endif

					if(fout >= 0) {
						int count;

						cli_warnmsg("Saving dump to %s:  refer to http://www.clamav.net/bugs\n", filename);

						lseek(desc, 0L, SEEK_SET);
						while((count = cli_readn(desc, buffer, sizeof(buffer))) > 0)
							cli_writen(fout, buffer, count);
						close(fout);
					}
					free(filename);
				}
				ret = CL_EFORMAT;
				alldone = 1;
				break;
		}
	} while(!alldone);

	fclose(fp);

	if(fb) {
		cli_dbgmsg("cli_tnef: flushing final data\n");
		if(fileblobGetFilename(fb) == NULL) {
			cli_dbgmsg("Saving TNEF portion with an unknown name\n");
			fileblobSetFilename(fb, dir, "tnef");
		}
		fileblobDestroy(fb);
		fb = NULL;
	}

	cli_dbgmsg("cli_tnef: returning %d\n", ret);
	return ret;
}

static int
tnef_message(FILE *fp, uint16_t type, uint16_t tag, int32_t length, off_t fsize)
{
	uint16_t i16;
	off_t offset;
#ifdef	CL_DEBUG
	uint32_t i32;
	char *string;
#endif

	cli_dbgmsg("message tag 0x%x, type 0x%x, length %d\n", tag, type,
		(int)length);

	offset = ftell(fp);

	/*
	 * a lot of this stuff should be only discovered in debug mode...
	 */
	switch(tag) {
		case attBODY:
			cli_warnmsg("TNEF body not being scanned - if you believe this file contains a virus, submit it to www.clamav.net\n");
			break;
#ifdef	CL_DEBUG
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
			if(length <= 0)
				return -1;
			string = cli_malloc(length + 1);
			if(string == NULL)
				return -1;
			if(fread(string, 1, (uint32_t)length, fp) != (uint32_t)length) {
				free(string);
				return -1;
			}
			string[length] = '\0';
			cli_dbgmsg("TNEF class %s\n", string);
			free(string);
			break;
		default:
			cli_dbgmsg("TNEF - unsupported message tag 0x%x type 0x%d length %d\n", tag, type, length);
			break;
#endif
	}

	/*cli_dbgmsg("%lu %lu\n", (long)(offset + length), ftell(fp));*/

	if(!CLI_ISCONTAINED2(0, fsize, (off_t)offset, (off_t)length)) {
		cli_errmsg("TNEF: Incorrect length field in tnef_message\n");
		return -1;
	}
	if(fseek(fp, offset + length, SEEK_SET) < 0)
		return -1;

	/* Checksum - TODO, verify */
	if(fread(&i16, sizeof(uint16_t), 1, fp) != 1)
		return -1;

	return 0;
}

static int
tnef_attachment(FILE *fp, uint16_t type, uint16_t tag, int32_t length, const char *dir, fileblob **fbref, off_t fsize)
{
	uint32_t todo;
	uint16_t i16;
	off_t offset;
	char *string;

	cli_dbgmsg("attachment tag 0x%x, type 0x%x, length %d\n", tag, type,
		(int)length);

	offset = ftell(fp);

	switch(tag) {
		case attATTACHTITLE:
			if(length <= 0)
				return -1;
			string = cli_malloc(length + 1);
			if(string == NULL)
				return -1;
			if(fread(string, 1, (uint32_t)length, fp) != (uint32_t)length) {
				free(string);
				return -1;
			}
			string[length] = '\0';
			cli_dbgmsg("TNEF filename %s\n", string);
			if(*fbref == NULL) {
				*fbref = fileblobCreate();
				if(*fbref == NULL) {
					free(string);
					return -1;
				}
			}
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
			cli_dbgmsg("TNEF - unsupported attachment tag 0x%x type 0x%d length %d\n",
				tag, type, (int)length);
			break;
	}

	/*cli_dbgmsg("%lu %lu\n", (long)(offset + length), ftell(fp));*/

	if(!CLI_ISCONTAINED2(0, fsize, (off_t)offset, (off_t)length)) {
		cli_errmsg("TNEF: Incorrect length field in tnef_attachment\n");
		return -1;
	}
	if(fseek(fp, (long)(offset + length), SEEK_SET) < 0)	/* shouldn't be needed */
		return -1;

	/* Checksum - TODO, verify */
	if(fread(&i16, sizeof(uint16_t), 1, fp) != 1)
		return -1;

	return 0;
}

static int
tnef_header(FILE *fp, uint8_t *part, uint16_t *type, uint16_t *tag, int32_t *length)
{
	uint32_t i32;

	if(fread(part, sizeof(uint8_t), 1, fp) != 1)
		return 0;

	if(*part == (uint8_t)0)
		return 0;

	if(fread(&i32, sizeof(uint32_t), 1, fp) != 1) {
		if((*part == '\n') && feof(fp)) {
			/*
			 * trailing newline in the file, could be caused by
			 * broken quoted-printable encoding in the source
			 * message missing a final '='
			 */
			cli_dbgmsg("tnef_header: ignoring trailing newline\n");
			return 0;
		}
		return -1;
	}

	i32 = host32(i32);
	*tag = (uint16_t)(i32 & 0xFFFF);
	*type = (uint16_t)((i32 & 0xFFFF0000) >> 16);

	if(fread(&i32, sizeof(uint32_t), 1, fp) != 1)
		return -1;
	*length = (int32_t)host32(i32);

	cli_dbgmsg("message tag 0x%x, type 0x%x, length %d\n",
		*tag, *type, (int)*length);

	return 1;
}

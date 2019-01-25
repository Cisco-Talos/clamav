/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Nigel Horne
 * 
 *  Acknowledgements: The algorithm was based on 
 *                    kdepim/ktnef/lib/ktnefparser.cpp from KDE.
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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <fcntl.h>

#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "clamav.h"
#include "others.h"

#include "mbox.h"
#include "tnef.h"

static	int	tnef_message(fmap_t *map, off_t *pos, uint16_t type, uint16_t tag, int32_t length, off_t fsize);
static	int	tnef_attachment(fmap_t *map, off_t *pos, uint16_t type, uint16_t tag, int32_t length, const char *dir, fileblob **fbref, off_t fsize);
static	int	tnef_header(fmap_t *map, off_t *pos, uint8_t *part, uint16_t *type, uint16_t *tag, int32_t *length);

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

/* a TNEF file must be at least this size */
#define	MIN_SIZE	(sizeof(uint32_t) + sizeof(uint16_t))

int
cli_tnef(const char *dir, cli_ctx *ctx)
{
	uint32_t i32;
	uint16_t i16;
	fileblob *fb;
	int ret, alldone;
	off_t fsize, pos = 0;

	fsize = ctx->fmap[0]->len;

	if(fsize < (off_t) MIN_SIZE) {
		cli_dbgmsg("cli_tngs: file too small, ignoring\n");
		return CL_CLEAN;
	}

	if (fmap_readn(*ctx->fmap, &i32, pos, sizeof(uint32_t)) != sizeof(uint32_t)) {
		/* The file is at least MIN_SIZE bytes, so it "can't" fail */
		return CL_EREAD;
	}
	pos += sizeof(uint32_t);

	if(host32(i32) != TNEF_SIGNATURE) {
		return CL_EFORMAT;
	}

	if(fmap_readn(*ctx->fmap, &i16, pos, sizeof(uint16_t)) != sizeof(uint16_t)) {
		/* The file is at least MIN_SIZE bytes, so it "can't" fail */
		return CL_EREAD;
	}
	pos += sizeof(uint16_t);

	fb = NULL;
	ret = CL_CLEAN;	/* we don't know if it's clean or not :-) */
	alldone = 0;

	do {
		uint8_t part = 0;
		uint16_t type = 0, tag = 0;
		int32_t length = 0;

		switch(tnef_header(*ctx->fmap, &pos, &part, &type, &tag, &length)) {
			case 0:
				alldone = 1;
				break;
			case 1:
				break;
			default:
				/*
				 * Assume truncation, not file I/O error
				 */
				cli_warnmsg("cli_tnef: file truncated, returning CLEAN\n");
				ret = CL_CLEAN;
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
				if(tnef_message(*ctx->fmap, &pos, type, tag, length, fsize) != 0) {
					cli_dbgmsg("TNEF: Error reading TNEF message\n");
					ret = CL_EFORMAT;
					alldone = 1;
				}
				break;
			case LVL_ATTACHMENT:
				cli_dbgmsg("TNEF - found attachment\n");
				if(tnef_attachment(*ctx->fmap, &pos, type, tag, length, dir, &fb, fsize) != 0) {
					cli_dbgmsg("TNEF: Error reading TNEF attachment\n");
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
					int fout = -1;
					char *filename = cli_gentemp(ctx->engine->tmpdir);
					char buffer[BUFSIZ];

					if(filename)
						fout = open(filename, O_WRONLY|O_CREAT|O_EXCL|O_TRUNC|O_BINARY, 0600);

					if(fout >= 0) {
						int count;

						cli_warnmsg("Saving dump to %s:  refer to https://www.clamav.net/documents/installing-clamav\n", filename);

						pos = 0;
						while ((count = fmap_readn(*ctx->fmap, buffer, pos, sizeof(buffer))) > 0) {
						        pos += count;
							cli_writen(fout, buffer, count);
						}
						close(fout);
					}
					free(filename);
				}
				ret = CL_EFORMAT;
				alldone = 1;
				break;
		}
	} while(!alldone);

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
tnef_message(fmap_t *map, off_t *pos, uint16_t type, uint16_t tag, int32_t length, off_t fsize)
{
	off_t offset;
#ifdef	CL_DEBUG
	uint32_t i32;
	char *string;
#endif

	cli_dbgmsg("message tag 0x%x, type 0x%x, length %d\n", tag, type,
		(int)length);

	offset = *pos;

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
			if(fmap_readn(map, &i32, *pos, sizeof(uint32_t)) != sizeof(uint32_t))
				return -1;
			(*pos) += sizeof(uint32_t);
			i32 = host32(i32);
			cli_dbgmsg("TNEF version %d\n", i32);
			break;
		case attOEMCODEPAGE:
			/* 8 bytes, but just print the first 4 */
			/*assert(length == sizeof(uint32_t))*/
			if(fmap_readn(map, &i32, *pos, sizeof(uint32_t)) != sizeof(uint32_t))
				return -1;
			(*pos) += sizeof(uint32_t);
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
			if(string == NULL) {
                cli_errmsg("tnef_message: Unable to allocate memory for string\n");
				return -1;
            }
			if((uint32_t)fmap_readn(map, string, *pos, (uint32_t)length) != (uint32_t)length) {
				free(string);
				return -1;
			}
			(*pos) += (uint32_t)length;
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

	if(!CLI_ISCONTAINED2(0, fsize, offset, (off_t)length)) {
		cli_dbgmsg("TNEF: Incorrect length field in tnef_message\n");
		return -1;
	}
	(*pos) = offset + length;

	/* Checksum - TODO, verify */
	(*pos) += 2;

	return 0;
}

static int
tnef_attachment(fmap_t *map, off_t *pos, uint16_t type, uint16_t tag, int32_t length, const char *dir, fileblob **fbref, off_t fsize)
{
	uint32_t todo;
	off_t offset;
	char *string;

	cli_dbgmsg("attachment tag 0x%x, type 0x%x, length %d\n", tag, type,
		(int)length);

	offset = *pos;

	switch(tag) {
		case attATTACHTITLE:
			if(length <= 0)
				return -1;
			string = cli_malloc(length + 1);
			if(string == NULL) {
                cli_errmsg("tnef_attachment: Unable to allocate memory for string\n");
				return -1;
            }
			if((uint32_t)fmap_readn(map, string, *pos, (uint32_t)length) != (uint32_t)length) {
				free(string);
				return -1;
			}
			(*pos) += (uint32_t)length;
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
			todo = length;
			while(todo) {
			    unsigned char buf[BUFSIZ];
			    int32_t got = fmap_readn(map, buf, *pos, MIN(sizeof(buf), todo));
			    if (got <= 0)
				break;
			    (*pos) += got;

			    fileblobAddData(*fbref, buf, got);
			    todo -= got;
			}
			break;
		default:
			cli_dbgmsg("TNEF - unsupported attachment tag 0x%x type 0x%d length %d\n",
				tag, type, (int)length);
			break;
	}

	/*cli_dbgmsg("%lu %lu\n", (long)(offset + length), ftell(fp));*/

	if(!CLI_ISCONTAINED2(0, fsize, (off_t)offset, (off_t)length)) {
		cli_dbgmsg("TNEF: Incorrect length field in tnef_attachment\n");
		return -1;
	}
	(*pos) = (long)(offset + length);	/* shouldn't be needed */

	(*pos) += 2;

	return 0;
}

static int
tnef_header(fmap_t *map, off_t *pos, uint8_t *part, uint16_t *type, uint16_t *tag, int32_t *length)
{
	uint32_t i32;
	int rc;

	if (fmap_readn(map, part, *pos, 1) != 1)
		return 0;
	(*pos)++;

	if(*part == (uint8_t)0)
		return 0;

	rc = fmap_readn(map, &i32, *pos, sizeof(uint32_t));
	if (rc != sizeof(uint32_t)) {
		if(((*part == '\n') || (*part == '\r')) && (rc == 0)) {
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
	(*pos) += sizeof(uint32_t);

	i32 = host32(i32);
	*tag = (uint16_t)(i32 & 0xFFFF);
	*type = (uint16_t)((i32 & 0xFFFF0000) >> 16);

	if(fmap_readn(map, &i32, *pos, sizeof(uint32_t)) != sizeof(uint32_t))
		return -1;
	(*pos) += sizeof(uint32_t);
	*length = (int32_t)host32(i32);

	cli_dbgmsg("message tag 0x%x, type 0x%x, length %d\n",
		*tag, *type, (int)*length);

	return 1;
}

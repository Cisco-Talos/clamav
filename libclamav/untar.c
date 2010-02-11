/*
 *  Copyright (C) 2007-2008 Sourcefire, Inc.
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

static	char	const	rcsid[] = "$Id: untar.c,v 1.35 2007/02/12 20:46:09 njh Exp $";

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <errno.h>
#include <string.h>
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/stat.h>
#include <fcntl.h>
#ifdef	HAVE_SYS_PARAM_H
#include <sys/param.h>	/* for NAME_MAX */
#endif

#include "clamav.h"
#include "others.h"
#include "untar.h"
#include "mbox.h"
#include "blob.h"
#include "scanners.h"
#include "matcher.h"

#define BLOCKSIZE 512

static int
octal(const char *str)
{
	int ret;

	if(sscanf(str, "%o", (unsigned int *)&ret) != 1)
		return -1;
	return ret;
}

int
cli_untar(const char *dir, int desc, unsigned int posix, cli_ctx *ctx)
{
	int size = 0, ret, fout=-1;
	int in_block = 0;
	unsigned int files = 0;
	char fullname[NAME_MAX + 1];

	cli_dbgmsg("In untar(%s, %d)\n", dir, desc);

	for(;;) {
		char block[BLOCKSIZE];
		const int nread = cli_readn(desc, block, (unsigned int)sizeof(block));

		if(!in_block && nread == 0)
			break;

		if(nread < 0) {
			if(fout>=0)
				close(fout);
			cli_errmsg("cli_untar: block read error\n");
			return CL_EREAD;
		}

		if(!in_block) {
			char type;
			int directory, skipEntry = 0;
			char magic[7], name[101], osize[13];

			if(fout>=0) {
				lseek(fout, 0, SEEK_SET);
				ret = cli_magic_scandesc(fout, ctx);
				close(fout);
				if (!ctx->engine->keeptmp)
					if (cli_unlink(fullname)) return CL_EUNLINK;
				if (ret==CL_VIRUS)
					return CL_VIRUS;
				fout = -1;
			}

			if(block[0] == '\0')	/* We're done */
				break;
			if((ret=cli_checklimits("cli_untar", ctx, 0, 0, 0))!=CL_CLEAN)
				return ret;

			/* Notice assumption that BLOCKSIZE > 262 */
			if(posix) {
				strncpy(magic, block+257, 5);
				magic[5] = '\0';
				if(strcmp(magic, "ustar") != 0) {
					cli_dbgmsg("cli_untar: Incorrect magic string '%s' in tar header\n", magic);
					return CL_EFORMAT;
				}
			}

			type = block[156];

			switch(type) {
				default:
					cli_dbgmsg("cli_untar: unknown type flag %c\n", type);
				case '0':	/* plain file */
				case '\0':	/* plain file */
				case '7':	/* contiguous file */
				case 'M':	/* continuation of a file from another volume; might as well scan it. */
					files++;
					directory = 0;
					break;
				case '1':	/* Link to already archived file */
				case '5':	/* directory */
				case '2':	/* sym link */
				case '3':	/* char device */
				case '4':	/* block device */
				case '6':	/* fifo special */
				case 'V':	/* Volume header */
					directory = 1;
					break;
				case 'K':
				case 'L':
					/* GNU extension - ././@LongLink
					 * Discard the blocks with the extended filename,
					 * the last header will contain parts of it anyway
					 */
				case 'N': 	/* Old GNU format way of storing long filenames. */
				case 'A':	/* Solaris ACL */
				case 'E':	/* Solaris Extended attribute s*/
				case 'I':	/* Inode only */
				case 'g':	/* Global extended header */
				case 'x': 	/* Extended attributes */
				case 'X':	/* Extended attributes (POSIX) */
					directory = 0;
					skipEntry = 1;
					break;
			}

			if(directory) {
				in_block = 0;
				continue;
			}

			strncpy(osize, block+124, 12);
			osize[12] = '\0';
			size = octal(osize);
			if(size < 0) {
				cli_dbgmsg("cli_untar: Invalid size in tar header\n");
				skipEntry++;
			} else {
				cli_dbgmsg("cli_untar: size = %d\n", size);
				if((ret=cli_checklimits("cli_untar", ctx, size, 0, 0))!=CL_CLEAN)
					skipEntry++;
			}

			if(skipEntry) {
				const int nskip = (size % BLOCKSIZE || !size) ? size + BLOCKSIZE - (size % BLOCKSIZE) : size;
				
				if(nskip < 0) {
					cli_dbgmsg("cli_untar: got nagative skip size, giving up\n");
					return CL_CLEAN;
				}
				cli_dbgmsg("cli_untar: skipping entry\n");
				lseek(desc, nskip, SEEK_CUR);
				continue;
			}

			strncpy(name, block, 100);
			name[100] = '\0';
			if(cli_matchmeta(ctx, name, size, size, 0, files, 0, NULL) == CL_VIRUS)
			    return CL_VIRUS;

			snprintf(fullname, sizeof(fullname)-1, "%s"PATHSEP"tar%02u", dir, files);
			fullname[sizeof(fullname)-1] = '\0';
			fout = open(fullname, O_RDWR|O_CREAT|O_EXCL|O_TRUNC|O_BINARY, 0600);

			if(fout < 0) {
				char err[128];
				cli_errmsg("cli_untar: Can't create temporary file %s: %s\n", fullname, cli_strerror(errno, err, sizeof(err)));
				return CL_ETMPFILE;
			}

			cli_dbgmsg("cli_untar: extracting to %s\n", fullname);

			in_block = 1;
		} else { /* write or continue writing file contents */
			const int nbytes = size>512? 512:size;
			const int nwritten = (int)write(fout, block, (size_t)nbytes);

			if(nwritten != nbytes) {
				cli_errmsg("cli_untar: only wrote %d bytes to file %s (out of disc space?)\n",
					nwritten, fullname);
				close(fout);
				return CL_EWRITE;
			}
			size -= nbytes;
		}
		if (size == 0)
			in_block = 0;
        }	
	if(fout>=0) {
		lseek(fout, 0, SEEK_SET);
		ret = cli_magic_scandesc(fout, ctx);
		close(fout);
		if (!ctx->engine->keeptmp)
			if (cli_unlink(fullname)) return CL_EUNLINK;
		if (ret==CL_VIRUS)
			return CL_VIRUS;
	}
	return CL_CLEAN;
}

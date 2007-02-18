/*
 *  Copyright (C) 2004 Nigel Horne <njh@bandsman.co.uk>
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
 * Much of this code is based on minitar.c which is in the public domain.
 * Author: Charles G. Waldman (cgw@pgt.com),  Aug 4 1998
 * There are many tar files that this code cannot decode.
 *
 * Change History:
 * $Log: untar.c,v $
 * Revision 1.25  2005/03/22 21:26:27  kojm
 * add support for old fashioned tar archives
 *
 * Revision 1.24  2005/03/20 18:34:18  nigelhorne
 * Minor tidy
 *
 * Revision 1.23  2005/03/20 09:09:25  nigelhorne
 * Consolidate NAME_MAX
 *
 * Revision 1.22  2005/03/10 08:52:10  nigelhorne
 * Tidy
 *
 * Revision 1.21  2005/02/16 22:19:21  nigelhorne
 * Check file close
 *
 * Revision 1.20  2005/02/13 22:25:41  kojm
 * do not try to continue if there's no space on device
 *
 * Revision 1.19  2004/12/16 15:34:57  nigelhorne
 * Tidy
 *
 * Revision 1.18  2004/11/20 13:15:46  nigelhorne
 * Better handling of false file type identification
 *
 * Revision 1.17  2004/10/27 06:36:38  nigelhorne
 * Handle type '1' files
 *
 * Revision 1.16  2004/10/20 12:21:11  nigelhorne
 * Print warning message about LongLink
 *
 * Revision 1.15  2004/10/16 16:08:46  nigelhorne
 * Handle empty files in the middle of archives
 *
 * Revision 1.14  2004/10/13 10:18:54  nigelhorne
 * Added a few extra file types
 *
 * Revision 1.13  2004/10/04 13:46:50  nigelhorne
 * Handle GNU tar files
 *
 * Revision 1.12  2004/10/04 10:53:15  nigelhorne
 * Handle tar files less than 512 bytes
 *
 * Revision 1.11  2004/10/01 13:50:47  nigelhorne
 * Minor code tidy
 *
 * Revision 1.10  2004/09/20 13:37:44  kojm
 * 0.80rc
 *
 * Revision 1.9  2004/09/14 10:29:31  nigelhorne
 * Fix compilation error on AIX and OSF
 *
 * Revision 1.8  2004/09/12 23:43:45  kojm
 * return with CL_EFORMAT instead of CL_EDSIG
 *
 * Revision 1.7  2004/09/12 19:51:59  nigelhorne
 * Now builds with --enable-debug
 *
 * Revision 1.6  2004/09/08 16:02:34  nigelhorne
 * fclose on error
 *
 * Revision 1.5  2004/09/06 14:16:48  nigelhorne
 * Added CYGWIN support
 *
 * Revision 1.4  2004/09/06 08:45:44  nigelhorne
 * Code Tidy
 *
 * Revision 1.3  2004/09/06 08:34:47  nigelhorne
 * Randomise extracted file names from tar file
 *
 * Revision 1.2  2004/09/05 18:58:21  nigelhorne
 * Extract files completed
 *
 * Revision 1.1  2004/09/05 15:28:10  nigelhorne
 * First draft
 *
 */
static	char	const	rcsid[] = "$Id: untar.c,v 1.25 2005/03/22 21:26:27 kojm Exp $";

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/param.h>	/* for NAME_MAX */

#include "clamav.h"
#include "others.h"
#include "untar.h"
#include "mbox.h"
#include "blob.h"

#define BLOCKSIZE 512

#ifndef	O_BINARY
#define	O_BINARY	0
#endif

static int
octal(const char *str)
{
	int ret = -1;

	(void)sscanf(str, "%o", (unsigned int *)&ret);
	return ret;
}

int
cli_untar(const char *dir, int desc, unsigned int posix)
{
	int size = 0;
	int in_block = 0;
	char fullname[NAME_MAX + 1];
	FILE *outfile = NULL;

	cli_dbgmsg("In untar(%s, %d)\n", dir ? dir : "", desc);

	for(;;) {
		char block[BLOCKSIZE];
		const int nread = cli_readn(desc, block, (unsigned int)sizeof(block));

		if(!in_block && nread == 0)
			break;

		if(nread < 0) {
			if(outfile)
				fclose(outfile);
			cli_errmsg("cli_untar: block read error\n");
			return CL_EIO;
		}

		if(!in_block) {
			char type;
			const char *suffix;
			size_t suffixLen = 0;
			int fd, directory;
			char magic[7], name[101], osize[13];

			if(outfile) {
				if(fclose(outfile)) {
					cli_errmsg("cli_untar: cannot close file %s\n",
					    fullname);
					return CL_EIO;
				}
				outfile = (FILE*)0;
			}

			if(block[0] == '\0')	/* We're done */
				break;

			/* Notice assumption that BLOCKSIZE > 262 */
			if(posix) {
				strncpy(magic, block+257, 5);
				magic[5] = '\0';
				if(strcmp(magic, "ustar") != 0) {
					cli_dbgmsg("Incorrect magic string '%s' in tar header\n", magic);
					return CL_EFORMAT;
				}
			}

			type = block[156];

			/*
			 * Extra types from djgardner@users.sourceforge.net
			 */
			switch(type) {
				case '0':	/* plain file */
				case '\0':	/* plain file */
				case '7':	/* contiguous file */
					directory = 0;
					break;
				case '1':	/* Link to already archived file */
				case '5':	/* directory */
				case '2':	/* sym link */
				case '3':	/* char device */
				case '4':	/* block device */
				case '6':	/* fifo special */
					directory = 1;
					break;
				case 'L':	/* GNU extension - ././@LongLink */
					cli_errmsg("cli_untar: only standard TAR files are currently supported\n", type);
					return CL_EFORMAT;
				default:
					/*cli_errmsg("cli_untar: unknown type flag %c\n", type);
					return CL_EFORMAT;*/
					/*
					 * It isn't really a tar file
					 */
					cli_dbgmsg("cli_untar: unknown type flag %c\n", type);
					/*
					 * We don't know that it's clean at all,
					 * it would be better to have a
					 * CL_CONTINUE return value since it
					 * may be a different format
					 */
					return CL_CLEAN;
			}

			if(directory) {
				in_block = 0;
				continue;
			}

			strncpy(name, block, 100);
			name[100] = '\0';

			/*
			 * see also fileblobSetFilename()
			 * TODO: check if the suffix needs to be put back
			 */
			sanitiseName(name);
			suffix = strrchr(name, '.');
			if(suffix == NULL)
				suffix = "";
			else {
				suffixLen = strlen(suffix);
				if(suffixLen > 4) {
					/* Found a full stop which isn't a suffix */
					suffix = "";
					suffixLen = 0;
				}
			}
			snprintf(fullname, sizeof(fullname) - 1 - suffixLen, "%s/%.*sXXXXXX", dir,
				(int)(sizeof(fullname) - 9 - suffixLen - strlen(dir)), name);
#if    defined(C_LINUX) || defined(C_BSD) || defined(HAVE_MKSTEMP) || defined(C_SOLARIS) || defined(C_CYGWIN) || defined(C_KFREEBSD_GNU)
			fd = mkstemp(fullname);
#else
			(void)mktemp(fullname);
			fd = open(fullname, O_WRONLY|O_CREAT|O_EXCL|O_TRUNC|O_BINARY, 0600);
#endif

			if(fd < 0) {
				cli_errmsg("Can't create temporary file %s: %s\n", fullname, strerror(errno));
				cli_dbgmsg("%lu %d %d\n", suffixLen, sizeof(fullname), strlen(fullname));
				return CL_ETMPFILE;
			}

			cli_dbgmsg("cli_untar: extracting %s\n", fullname);

			in_block = 1;
			if((outfile = fdopen(fd, "wb")) == NULL) {
				cli_errmsg("cli_untar: cannot create file %s\n",
				    fullname);
				close(fd);
				return CL_ETMPFILE;
			}

			strncpy(osize, block+124, 12);
			osize[12] = '\0';
			size = octal(osize);
			if(size < 0) {
				cli_errmsg("Invalid size in tar header\n");
				fclose(outfile);
				return CL_EFORMAT;
			}
			cli_dbgmsg("cli_untar: size = %d\n", size);
		} else { /* write or continue writing file contents */
			const int nbytes = size>512? 512:size;
			const int nwritten = fwrite(block, 1, (size_t)nbytes, outfile);

			if(nwritten != nbytes) {
				cli_errmsg("cli_untar: only wrote %d bytes to file %s (out of disk space?)\n",
					nwritten, fullname);
				fclose(outfile);
				return CL_EIO;
			}
			size -= nbytes;
		}
		if (size == 0)
			in_block = 0;
	}
	if(outfile)
		return fclose(outfile);

	return 0;
}

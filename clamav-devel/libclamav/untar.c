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
 * Some of this code is based on minitar.c which is in the public domain.
 * Author: Charles G. Waldman (cgw@pgt.com),  Aug 4 1998
 *
 * Change History:
 * $Log: untar.c,v $
 * Revision 1.2  2004/09/05 18:58:21  nigelhorne
 * Extract files completed
 *
 * Revision 1.1  2004/09/05 15:28:10  nigelhorne
 * First draft
 *
 */
static	char	const	rcsid[] = "$Id: untar.c,v 1.2 2004/09/05 18:58:21 nigelhorne Exp $";

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "clamav.h"
#include "others.h"

#define BLOCKSIZE 512
#define MAXNAMELEN 1024

static
int octal(const char *str)
{
	int ret = -1;

	sscanf(str, "%o", &ret);
	return ret;
}

int
cli_untar(const char *dir, int desc)
{
	int size = 0;
	int in_block = 0;
	int directory = 0;
	FILE *outfile = (FILE*)0;

	cli_dbgmsg("In untar(%s, %d)\n", dir ? dir : "", desc);

	for(;;) {
		char fullname[MAXNAMELEN];
		char block[BLOCKSIZE];
		const int nread = read(desc, block, sizeof(block));

		if(!in_block && nread == 0)
			break;

		if(nread != BLOCKSIZE) {
			cli_errmsg("cli_untar: incomplete block read\n");
			return CL_EIO;
		}

		if(!in_block) {
			char magic[7];
			char name[101];
			char type;

			if(block[0] == '\0')  /* We're done */
				break;

			strncpy(magic, block+257, 6);
			magic[6] = '\0';
			if(strcmp(magic, "ustar ") != 0) {
				cli_errmsg("Incorrect magic number in tar header\n");
				return CL_EDSIG;
			}

			strncpy(name, block, 100);
			name[100] = '\0';
			sprintf(fullname, "%s/%s", dir, name);
			cli_dbgmsg("cli_untar: extracting %s\n", fullname);
			type = block[156];

			switch(type) {
				case '0':
				case '\0':
					directory = 0;
					break;
				case '5':
					directory = 1;
					break;
				default:
					cli_errmsg("cli_untar: unknown type flag %c\n", type);
					break;
			}

			if(directory)
				continue;
			else { /*file */
				char osize[13];

				in_block = 1;
				if(outfile) {
					if(fclose(outfile)) {
						cli_errmsg("cli_untar: cannot close file %s\n",
						    fullname);
						return CL_EIO;
					}
					outfile = (FILE*)0;
				}

				if(!(outfile = fopen(fullname,"wb"))) {
					cli_errmsg("cli_untar: cannot create file %s\n",
					    fullname);
					return CL_ETMPFILE;
				}

				strncpy(osize, block+124, 12);
				osize[12] = '\0';
				size = octal(osize);
				if(size < 0){
					cli_errmsg("Invalid size in tar header\n");
					return CL_EDSIG;
				}
			}
		} else { /* write or continue writing file contents */
			const int nbytes = size>512? 512:size;
			const int nwritten = fwrite(block, 1, nbytes, outfile);

			if(nwritten != nbytes) {
				cli_errmsg("cli_untar: only wrote %d bytes to file %s\n",
					nwritten, fullname);
			}
			size -= nbytes;
			if (size == 0)
				in_block = 0;
		}
	}
	return CL_CLEAN;
}

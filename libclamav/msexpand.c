/*
 *  msexpand: Microsoft "compress.exe/expand.exe" compatible decompressor
 *
 *  Copyright (c) 2000 Martin Hinner <mhi@penguin.cz>
 *  Algorithm & data structures by M. Winterhoff <100326.2776@compuserve.com>
 *
 *  Corrected and adapted to ClamAV by Tomasz Kojm <tkojm@clamav.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
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

#include <stdio.h>
#include <stdlib.h>
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif
#include "cltypes.h"
#include "others.h"
#include "msexpand.h"

int cli_msexpand(FILE *in, FILE *out)
{
	int bits, ch, i, j, len, mask;
	unsigned char *buffer;
	uint32_t magic1, magic2, magic3, filesize;
	uint16_t reserved;


    if(fread(&magic1, sizeof(magic1), 1, in) != 1) {
	return -1;
    }

    if(magic1 == le32_to_host(0x44445A53L))
    {
	if(fread(&magic2, sizeof(magic2), 1, in) != 1) {
	    return -1;
	}

	if(fread(&reserved, sizeof(reserved), 1, in) != 1) {
	    return -1;
	}

	if(fread(&filesize, sizeof(filesize), 1, in) != 1) {
	    return -1;
	}

	if(magic2 != le32_to_host(0x3327F088L))
	{
	    cli_warnmsg("msexpand: Not a MS-compressed file\n");
	    return -1;
	}

    } else
    if(magic1 == le32_to_host(0x4A41574BL))
    {
	if(fread(&magic2, sizeof(magic2), 1, in) != 1) {
	    return -1;
	}

	if(fread(&magic3, sizeof(magic3), 1, in) != 1) {
	    return -1;
	}

	if(fread(&reserved, sizeof(reserved), 1, in) != 1) {
	    return -1;
	}

	if(magic2 != le32_to_host(0xD127F088L) || magic3 != le32_to_host(0x00120003L))
	{
	    cli_warnmsg("msexpand: Not a MS-compressed file\n");
	    return -1;
	}

	cli_warnmsg("msexpand: unsupported version 6.22\n");
	return -1;

    } else {
	cli_warnmsg("msexpand: Not a MS-compressed file\n");
	return -1;
    }

    if((buffer = (unsigned char *) cli_calloc(4096, sizeof(char))) == NULL) {
	cli_errmsg("msexpand: Can't allocate memory\n");
	return -1;
    }

    i = 4096 - 16;

    while (1) {
	if((bits = fgetc(in)) == EOF)
	    break;

	for(mask = 0x01; mask & 0xFF; mask <<= 1) {
	    if(!(bits & mask)) {
		if((j = fgetc(in)) == EOF)
		    break;
		len = fgetc(in);
		j += (len & 0xF0) << 4;
		len = (len & 15) + 3;
		while(len--) {
		    buffer[i] = buffer[j];
		    if(fwrite(&buffer[i], sizeof(unsigned char), 1, out) != 1) {
			free(buffer);
			return -1;
		    }
		    j++;
		    j %= 4096;
		    i++;
		    i %= 4096;
		}
	    } else {
		if((ch = fgetc(in)) == EOF)
		    break;

		buffer[i] = ch;
		if(fwrite(&buffer[i], sizeof(unsigned char), 1, out) != 1) {
		    free(buffer);
		    return -1;
		}
		i++;
		i %= 4096;
	    }
	}
    }

    free(buffer);
    return 0;
}

/*
 *  Copyright (C) 2004 trog@uncon.org
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>

#include "clamav.h"
#include "others.h"


int cli_check_mydoom_log(int desc, const char **virname)
{
	int32_t record[8], check;
	int i, retval=CL_VIRUS, j;

    cli_dbgmsg("in cli_check_mydoom_log()\n");

    /* Check upto the first five records in the file */
    for (j=0 ; j<5 ; j++) {
	if (cli_readn(desc, &record, 32) != 32) {
	    break;
	}

	/* Decode the key */
	record[0] = ~ntohl(record[0]);
	cli_dbgmsg("Mydoom: key: %lu\n", record[0]);
	check = 0;
	for (i=1 ; i<8; i++) {
	    record[i] = ntohl(record[i]) ^ record[0];
	    check += record[i];
	}
	cli_dbgmsg("Mydoom: check: %lu\n", ~check);
	if ((~check) != record[0]) {
	    return CL_CLEAN;
	}
    }

    if (j < 2) {
	retval = CL_CLEAN;
    } else if (retval==CL_VIRUS) {
	if(virname)
	    *virname = "Worm.Mydoom.M.log";
    }

    return retval;
}

int cli_check_jpeg_exploit(int fd)
{
	unsigned char buffer[4];
	off_t offset;
	int retval;


	cli_dbgmsg("in cli_check_jpeg_exploit()\n");

	if (cli_readn(fd, buffer, 2) != 2) {
		return 0;
	}

	if ((buffer[0] != 0xff) || (buffer[1] != 0xd8)) {
		return 0;
	}
	for (;;) {
		if ((retval=cli_readn(fd, buffer, 4)) != 4) {
			return 0;
		}
		/* Check for multiple 0xFF values, we need to skip them */
		if ((buffer[0] == 0xff) && (buffer[1] == 0xff)) {
			lseek(fd, -3, SEEK_CUR);
			continue;
		}
		
		if ((buffer[0] == 0xff) && (buffer[1] == 0xfe)) {
			if (buffer[2] == 0x00) {
				if ((buffer[3] == 0x00) || (buffer[3] == 0x01)) {
					return 1;
				}
			}
		}
		if (buffer[0] != 0xff) {
			return -1;
		}
		if (buffer[1] == 0xda) {
			/* End of Image marker */
			return 0;
		}
		offset = ((unsigned int) buffer[2] << 8) + buffer[3];
		if (offset < 2) {
			return 1;
		}
		offset -= 2;
		offset += lseek(fd, 0, SEEK_CUR);
		if (lseek(fd, offset, SEEK_SET) != offset) {
			return -1;
		}
	}
}

/*
 *  Copyright (C) 2004-2005 trog@uncon.org
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

#include "clamav-config.h"
#include "clamav.h"
#include "others.h"

#define FALSE (0)
#define TRUE (1)

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

static uint32_t riff_endian_convert_32(uint32_t value, int big_endian)
{
	if (big_endian) {
#if WORDS_BIGENDIAN == 0
		return ((value >> 24) | ((value & 0x00FF0000) >> 8) |
			((value & 0x0000FF00) << 8) | (value << 24));
#else
		return value;
#endif
	} else {
#if WORDS_BIGENDIAN == 0
		return value;
#else
		return ((value >> 24) | ((value & 0x00FF0000) >> 8) |
			((value & 0x0000FF00) << 8) | (value << 24));
#endif
        }
}

static int riff_read_chunk(int fd, int big_endian, int rec_level)
{
	uint32_t chunk_id;
	uint32_t chunk_size;
	int length;
	uint32_t list_type;
	off_t offset, cur_offset;

	if (rec_level > 1000) {
		cli_dbgmsg("riff_read_chunk: recursion level exceeded\n");
		return 0;
	}
	
	length = sizeof(uint32_t);
	if (cli_readn(fd, &chunk_id, length) != length) {
		return 0;
	}
	if (cli_readn(fd, &chunk_size, length) != length) {
		return 0;
	}
	chunk_size = riff_endian_convert_32(chunk_size, big_endian);

	if (memcmp(&chunk_id, "RIFF", 4) == 0) {
		return 0;
	} else if (memcmp(&chunk_id, "RIFX", 4) == 0) {
		return 0;
	}
	
	if ((memcmp(&chunk_id, "LIST", 4) == 0) ||
		 (memcmp(&chunk_id, "PROP", 4) == 0) ||
		 (memcmp(&chunk_id, "FORM", 4) == 0) ||
		 (memcmp(&chunk_id, "CAT ", 4) == 0)) {
		if (cli_readn(fd, &list_type, sizeof(list_type)) != sizeof(list_type)) {
			cli_dbgmsg("riff_read_chunk: read list type failed\n");
			return 0;
		}
		return riff_read_chunk(fd, big_endian, ++rec_level);	
	}
	
	cur_offset = lseek(fd, 0, SEEK_CUR);
	offset = cur_offset + chunk_size;
	/* Check for odd alignment */
	if ((offset & 0x01) == 1) {
		offset++;
	}
	if (offset < cur_offset) {
		return 0;
	}
	if (lseek(fd, offset, SEEK_SET) != offset) {
		return 2;
	}
	return 1;
}

int cli_check_riff_exploit(int fd)
{
	uint32_t chunk_id;
	uint32_t chunk_size;
	uint32_t form_type;
	int length, big_endian, retval;
	off_t offset;
	
	cli_dbgmsg("in cli_check_riff_exploit()\n");

	length = sizeof(uint32_t);
	if (cli_readn(fd, &chunk_id, length) != length) {
		return 0;
	}
	if (cli_readn(fd, &chunk_size, length) != length) {
		return 0;
	}
	if (cli_readn(fd, &form_type, length) != length) {
		return 0;
	}
	
	if (memcmp(&chunk_id, "RIFF", 4) == 0) {
		big_endian = FALSE;
	} else if (memcmp(&chunk_id, "RIFX", 4) == 0) {
		big_endian = TRUE;
	} else {
		/* Not a RIFF file */
		return 0;
	}

	chunk_size = riff_endian_convert_32(chunk_size, big_endian);

	do {
		retval = riff_read_chunk(fd, big_endian, 1);
	} while (retval == 1);
		
	offset = lseek(fd, 0, SEEK_CUR);

	if (offset < chunk_size) {
		retval = 2;
	};
	return retval;
}

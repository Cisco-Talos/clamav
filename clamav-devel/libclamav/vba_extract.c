/*
 *  Extract VBA source code for component MS Office Documents)
 *
 *  Copyright (C) 2004 trog@uncon.org
 *
 *  This code is based on the OpenOffice and libgsf sources.
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

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <ctype.h>

#include "vba_extract.h"

#define FALSE (0)
#define TRUE (1)

typedef struct vba_version_tag {
	unsigned char signature[4];
	const char *name;
	int vba_version;
	int is_mac;
} vba_version_t;


typedef struct byte_array_tag {
	unsigned int length;
	unsigned char *data;
} byte_array_t;

#define NUM_VBA_VERSIONS 9
vba_version_t vba_version[] = {
	{ { 0x5e, 0x00, 0x00, 0x01 }, "Office 97",              5, FALSE},
	{ { 0x5f, 0x00, 0x00, 0x01 }, "Office 97 SR1",          5, FALSE },
	{ { 0x65, 0x00, 0x00, 0x01 }, "Office 2000 alpha?",     6, FALSE },
	{ { 0x6b, 0x00, 0x00, 0x01 }, "Office 2000 beta?",      6, FALSE },
	{ { 0x6d, 0x00, 0x00, 0x01 }, "Office 2000",            6, FALSE },
	{ { 0x70, 0x00, 0x00, 0x01 }, "Office XP beta 1/2",     6, FALSE },
	{ { 0x73, 0x00, 0x00, 0x01 }, "Office XP",              6, FALSE },
	{ { 0x60, 0x00, 0x00, 0x0e }, "MacOffice 98",           5, TRUE },
	{ { 0x62, 0x00, 0x00, 0x0e }, "MacOffice 2001",         5, TRUE },
};

#define VBA56_DIRENT_RECORD_COUNT (2 + /* magic */              \
                                   4 + /* version */            \
                                   2 + /* 0x00 0xff */          \
                                  22)  /* unknown */
#define VBA56_DIRENT_HEADER_SIZE (VBA56_DIRENT_RECORD_COUNT +   \
                                  2 +  /* type1 record count */ \
                                  2)   /* unknown */

/* Function: vba_readn
        Try hard to read the requested number of bytes
*/
int vba_readn(int fd, void *buff, unsigned int count)
{
        int retval;
        unsigned int todo;
        void *current;
 
        todo = count;
        current = buff;
 
        do {
                retval = read(fd, current, todo);
                if (retval == 0) {
                        return (count - todo);
                }
                if (retval < 0) {
                        return -1;
                }
                todo -= retval;
                current += retval;
        } while (todo > 0);
 
        return count;
}

/* Function: vba_writen
        Try hard to write the specified number of bytes
*/
int vba_writen(int fd, void *buff, unsigned int count)
{
        int retval;
        unsigned int todo;
        void *current;
                                                                                                                                                                          
        todo = count;
        current = buff;
                                                                                                                                                                          
        do {
                retval = write(fd, current, todo);
                if (retval < 0) {
                        return -1;
                }
                todo -= retval;
                current += retval;
        } while (todo > 0);
                                                                                                                                                                          
        return count;
}

char *get_unicode_name(char *name, int size)
{
        int i, j;
        char *newname;
                                                                                                                                                                          
        if (*name == 0 || size == 0) {
                return NULL;
        }
                                                                                                                                                                          
        newname = (char *) cli_malloc(size);
        if (!newname) {
                return NULL;
        }
        j=0;
        for (i=0 ; i < size; i+=2) {
                if (isprint(name[i])) {
                        newname[j++] = name[i];
                } else {
                        if (name[i] < 10 && name[i] >= 0) {
                                newname[j++] = '_';
                                newname[j++] = name[i] + '0';
                        }
                        newname[j++] = '_';
                }
        }
        newname[j] = '\0';
        return newname;
}
                                                                                                                                                                       
vba_project_t *vba56_dir_read(const char *dir)
{
	unsigned char magic[2];
	unsigned char version[4];
	unsigned char *buff, *name;
        unsigned char vba56_signature[] = { 0xcc, 0x61 };
	int16_t record_count, length;
	uint16_t ooff;
	uint8_t byte_count;
	uint32_t offset;
	uint32_t LidA;  //Language identifiers
	uint32_t LidB;
	uint16_t CharSet;
	uint16_t LenA;
	uint32_t UnknownB;
	uint32_t UnknownC;
	uint16_t LenB;
	uint16_t LenC;
	uint16_t LenD;
	int i, j, fd;
	vba_project_t *vba_project;
	char *fullname;

	unsigned char fixed_octet[8] = { 0x06, 0x02, 0x01, 0x00, 0x08, 0x02, 0x00, 0x00 };


	fullname = (char *) cli_malloc(strlen(dir) + 14);
	sprintf(fullname, "%s/_VBA_PROJECT", dir);
        fd = open(fullname, O_RDONLY);
	free(fullname);

        if (fd == -1) {
                cli_errmsg("Open failed\n");
                return NULL;
        }

	if (vba_readn(fd, &magic, 2) != 2) {
		return NULL;
	}
	if (strncmp(magic, vba56_signature, 2) != 0) {
		return NULL;
	}

	if (vba_readn(fd, &version, 4) != 4) {
		return NULL;
	}
	for (i=0 ; i < NUM_VBA_VERSIONS ; i++) {
		if (strncmp(version, vba_version[i].signature, 4) == 0) {
			break;
		}
	}

	if (i == NUM_VBA_VERSIONS) {
		cli_errmsg("Unknown VBA version signature x0%x0x%x0x%x0x%x\n",
			version[0], version[1], version[2], version[3]);
		return NULL;
	}

	cli_dbgmsg("VBA Project: %s, VBA Version=%d\n", vba_version[i].name,
				vba_version[i].vba_version);


	/*****************************************/

	/* two bytes, should be equal to 0x00ff */
	if (vba_readn(fd, &ooff, 2) != 2) {
		return NULL;
	}

	if (vba_readn(fd, &LidA, 4) != 4) {
		return NULL;
	}

	if (vba_readn(fd, &LidA, 4) != 4) {
		return NULL;
	}

	if (vba_readn(fd, &CharSet, 2) != 2) {
		return NULL;
	}
	if (vba_readn(fd, &LenA, 2) != 2) {
		return NULL;
	}

	if (vba_readn(fd, &UnknownB, 4) != 4) {
		return NULL;
	}
	if (vba_readn(fd, &UnknownC, 4) != 4) {
		return NULL;
	}

	if (vba_readn(fd, &LenB, 2) != 2) {
		return NULL;
	}
	if (vba_readn(fd, &LenC, 2) != 2) {
		return NULL;
	}
	if (vba_readn(fd, &LenD, 2) != 2) {
		return NULL;
	}

	cli_dbgmsg(" LidA: %d\n LidB: %d\n CharSet: %d\n", LidA, LidB, CharSet);
	cli_dbgmsg(" LenA: %d\n UnknownB: %d\n UnknownC: %d\n", LenA, UnknownB, UnknownC);
	cli_dbgmsg(" LenB: %d\n LenC: %d\n LenD: %d\n", LenB, LenC, LenD);

	record_count = LenC;
	/*******************************************/

	/* REPLACED THIS CODE WITH THE CODE ABOVE */
	/* read the rest of the header. most of this is unknown */
/*	buff = (char *) cli_malloc(24);
	if (!buff || vba_readn(fd, buff, 24) != 24) {
		return NULL;
	}
	free(buff);

	if (vba_readn(fd, &record_count, 2) != 2) {
		return NULL;
	}
	cli_dbgmsg("Record count: %d\n", record_count); */
	/* read two bytes and throw them away */
/*	if (vba_readn(fd, &length, 2) != 2) {
		return NULL;
	}*/

	for (i=0; record_count >0 ; record_count--) {

		if (vba_readn(fd, &length, 2) != 2) {
			return NULL;
		}
		cli_dbgmsg ("record: %d.%d, length: %d, ", record_count, i, length);
		buff = cli_malloc(length);
		if (!buff) {
			cli_errmsg("cli_malloc failed\n");
			return NULL;
		}
		if (vba_readn(fd, buff, length) != length) {
			cli_errmsg("read name failed\n");
			return NULL;
		}
		name = get_unicode_name(buff, length);
		cli_dbgmsg("name: %s\n", name);
		free(buff);

                /* Ignore twelve bytes from entries of type 'G'.
		   Type 'C' entries come in pairs, the second also
		   having a 12 byte trailer */
		/* TODO: Need to check if types H(same as G) and D(same as C) exist */
                if (!strncmp ("*\\G", name, 3)) {
			buff = cli_malloc(12);
                        if (vba_readn(fd, buff, 12) != 12) {
				cli_errmsg("failed to read blob\n");
                                free(buff);
				free(name);
				return NULL;
                        }
			free(buff);
                } else if (!strncmp("*\\C", name, 3)) {
			if (i == 1) {
				buff = cli_malloc(12);
                        	if (vba_readn(fd, buff, 12) != 12) {
					cli_errmsg("failed to read blob\n");
                                	free(buff);
					free(name);
					return NULL;
                        	}
				free(buff);
				i = 0;
			} else {
				i = 1;
				record_count++;
			}
		} else {
			cli_errmsg("unknown record type!!\n\n");
		}
		free(name);
	}

	/* TODO: may need to seek forward 20 bytes here. Bleh! */

	if (vba_readn(fd, &record_count, 2) != 2) {
		return NULL;
	}
	cli_dbgmsg("\nVBA Record count: %d\n", record_count);
	/*if (record_count <= 0) {
		return TRUE;
	}*/

	lseek(fd, 2*record_count, SEEK_CUR);
	lseek(fd, 4, SEEK_CUR);

	/* Read fixed octet */
	buff = cli_malloc(8);
	if (!buff) {
		return NULL;
	}
	if (vba_readn(fd, buff, 8) != 8) {
		free(buff);
		return NULL;
	}
	if (!strncmp(buff, fixed_octet, 8)) {
		free(buff);
		return NULL;
	}
	free(buff);
	cli_dbgmsg("Read fixed octet ok\n");

	/* junk some more stuff */
	do {
		if (vba_readn(fd, &ooff, 2) != 2) {
			return NULL;
		}
	} while(ooff != 0xFFFF);
	
	if (vba_readn(fd, &ooff, 2) != 2) {
		return NULL;
	}

	/* no idea what this stuff is */
	if (ooff != 0xFFFF) {
		lseek(fd, ooff, SEEK_CUR);
	}
	if (vba_readn(fd, &ooff, 2) != 2) {
		return NULL;
	}
	if (ooff != 0xFFFF) {
		lseek(fd, ooff, SEEK_CUR);
	}
	lseek(fd, 100, SEEK_CUR);

	if (vba_readn(fd, &record_count, 2) != 2) {
		return NULL;
	}
	cli_dbgmsg("\nVBA Record count: %d\n", record_count);
	
	vba_project = (vba_project_t *) cli_malloc(sizeof(struct vba_project_tag));
	vba_project->name = (char **) cli_malloc(sizeof(char *) * record_count);
	vba_project->dir = strdup(dir);
	vba_project->offset = (uint32_t *) cli_malloc (sizeof(uint32_t) *
					record_count);
	vba_project->count = record_count;
	for (i=0 ; i < record_count ; i++) {
		if (vba_readn(fd, &length, 2) != 2) {
			return NULL;
		}
		buff = cli_malloc(length);
		if (!buff) {
			cli_dbgmsg("cli_malloc failed\n");
			return NULL;
		}
		if (vba_readn(fd, buff, length) != length) {
			cli_dbgmsg("read name failed\n");
			return NULL;
		}
		vba_project->name[i] = get_unicode_name(buff, length);
		cli_dbgmsg("project name: %s, ", vba_project->name[i]);
		free(buff);

		/* some kind of string identifier ?? */
		if (vba_readn(fd, &length, 2) != 2) {
			return NULL;
		}
		lseek(fd, length, SEEK_CUR);

		/* unknown stuff */
		if (vba_readn(fd, &ooff, 2) != 2) {
			return NULL;
		}
		if (ooff == 0xFFFF) {
			lseek(fd, 2, SEEK_CUR);
			if (vba_readn(fd, &ooff, 2) != 2) {
				return NULL;
			}
			lseek(fd, ooff, SEEK_CUR);
		} else {
			lseek(fd, 2 + ooff, SEEK_CUR);
		}

		lseek(fd, 8, SEEK_CUR);
		if (vba_readn(fd, &byte_count, 1) != 1) {
			return NULL;
		}
		for (j=0 ; j<byte_count; j++) {
			lseek(fd, 8, SEEK_CUR);
		}
		lseek(fd, 6, SEEK_CUR);
		if (vba_readn(fd, &offset, 4) != 4) {
			return NULL;
		}
		vba_project->offset[i] = offset;
		cli_dbgmsg("offset:%d\n", offset);
		lseek(fd, 2, SEEK_CUR);
	}
	
	
	{ /* There appears to be some code in here */
	
	off_t foffset;

		foffset = lseek(fd, 0, SEEK_CUR);
		cli_dbgmsg("\nOffset: 0x%x\n", (unsigned int)foffset);
	}
	close(fd);
	return vba_project;
}

#define VBA_COMPRESSION_WINDOW 4096

void byte_array_append(byte_array_t *array, unsigned char *src, unsigned int len)
{
	if (array->length == 0) {
		array->data = cli_malloc(len);
		array->length = len;
		strncpy(array->data, src, len);
	} else {
		array->data = realloc(array->data, array->length+len);
		strncpy(array->data+array->length, src, len);
		array->length += len;
	}
}

unsigned char *vba_decompress(int fd, uint32_t offset)
{
	unsigned int i, pos=0, shift, win_pos, clean=TRUE, mask, distance;
	uint8_t flag;
	uint16_t token, len;
	unsigned char buffer[VBA_COMPRESSION_WINDOW];
	byte_array_t result;
	
	result.length=0;
	result.data=NULL;
	
	lseek(fd, offset+3, SEEK_SET); /* 1byte ?? , 2byte length ?? */ 
	
	while (vba_readn(fd, &flag, 1) == 1) {
		for (mask = 1; mask < 0x100; mask<<=1) {
			if (flag & mask) {
				if (vba_readn(fd, &token, 2) != 2) {
					return FALSE;
				}
				win_pos = pos % VBA_COMPRESSION_WINDOW;
				if (win_pos <= 0x80) {
					if (win_pos <= 0x20) {
						shift = (win_pos <= 0x10) ? 12:11;
					} else {
						shift = (win_pos <= 0x40) ? 10:9;
					}
				} else {
					if (win_pos <= 0x200) {
						shift = (win_pos <= 0x100) ? 8:7;
					} else if (win_pos <= 0x800) {
						shift = (win_pos <= 0x400) ? 6:5;
					} else {
						shift = 4;
					}
				}
				len = (token & ((1 << shift) -1)) + 3;
				distance = token >> shift;
				clean = TRUE;
				
				for (i=0 ; i < len; i++) {
					unsigned int srcpos;
					unsigned char c;
					
					srcpos = (pos - distance - 1) % VBA_COMPRESSION_WINDOW;
					c = buffer[srcpos];
					buffer[pos++ % VBA_COMPRESSION_WINDOW]= c;
				}
			} else {
				if ((pos != 0) &&
					((pos % VBA_COMPRESSION_WINDOW) == 0) && clean) {
					
					if (vba_readn(fd, &token, 2) != 2) {
						return FALSE;
					}
					clean = FALSE;
					byte_array_append(&result, buffer, VBA_COMPRESSION_WINDOW);
					break;
				}
				if (vba_readn(fd, buffer+(pos%VBA_COMPRESSION_WINDOW), 1) == 1){
					pos++;
				}
				clean = TRUE;
			}
		}
	}
			
	if (pos % VBA_COMPRESSION_WINDOW) {
		byte_array_append(&result, buffer, pos % VBA_COMPRESSION_WINDOW);
	}
	return result.data;

}

/*
int vba_dump(vba_project_t *vba_project)
{
	int i, fd;
	unsigned char *data;
	char *fullname;

	for (i=0 ; i<vba_project->count ; i++) {
	
		cli_dbgmsg("\n\n*****************************\n");
		cli_dbgmsg("Deocding file: %s\n", vba_project->name[i]);
		cli_dbgmsg("*****************************\n");
		fullname = (char *) cli_malloc(strlen(vba_project->dir) + strlen(vba_project->name[i]) + 2);
		sprintf(fullname, "%s/%s", vba_project->dir, vba_project->name[i]);
		fd = open(fullname, O_RDONLY);
		free(fullname);
		if (fd == -1) {
			cli_dbgmsg("Open failed\n");
			return FALSE;
		}
		
		data = vba_decompress(fd, vba_project->offset[i]);
		cli_dbgmsg("%s\n", data);
		close(fd);

	}
	return TRUE;
}

int main(int argc, char *argv[])
{
        int retval;
	char *dirname=NULL;
	vba_project_t *vba_project;
	
        while ((retval = getopt(argc, argv, "d:w")) != -1) {
                switch (retval) {
                        case 'd':
                                dirname = optarg;
                                break;
                        case ':':
                                cli_dbgmsg("missing option parameter\n");
                                exit(-1);
                        case '?':
                                cli_dbgmsg("unknown option\n");
                                break;
                }
        }
 
	vba_project = vba56_dir_read(dirname);

	if (vba_project != NULL) {
		vba_dump(vba_project);
	}
	return TRUE;
}
*/

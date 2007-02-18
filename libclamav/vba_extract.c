/*
 *  Extract VBA source code for component MS Office Documents
 *
 *  Copyright (C) 2004-2005 trog@uncon.org
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
#include <stdlib.h>
#include <ctype.h>
#include <zlib.h>

#include "clamav.h"

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "vba_extract.h"
#include "others.h"

#define FALSE (0)
#define TRUE (1)

typedef struct vba_version_tag {
	unsigned char signature[4];
	const char *name;
	int vba_version;
	int is_mac;
} vba_version_t;


static uint16_t vba_endian_convert_16(uint16_t value, int is_mac)
{
	if (is_mac) {
#if WORDS_BIGENDIAN == 0
		return ((value >> 8) + (value << 8));
#else
		return value;
#endif
	} else {
#if WORDS_BIGENDIAN == 0
		return value;
#else
		return ((value >> 8) + (value << 8));
#endif
	}
}
 
static uint32_t vba_endian_convert_32(uint32_t value, int is_mac)
{
	if (is_mac) {
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

typedef struct byte_array_tag {
	unsigned int length;
	unsigned char *data;
} byte_array_t;

#define NUM_VBA_VERSIONS 14
vba_version_t vba_version[] = {
	{ { 0x5e, 0x00, 0x00, 0x01 }, "Office 97",              5, FALSE},
	{ { 0x5f, 0x00, 0x00, 0x01 }, "Office 97 SR1",          5, FALSE },
	{ { 0x65, 0x00, 0x00, 0x01 }, "Office 2000 alpha?",     6, FALSE },
	{ { 0x6b, 0x00, 0x00, 0x01 }, "Office 2000 beta?",      6, FALSE },
	{ { 0x6d, 0x00, 0x00, 0x01 }, "Office 2000",            6, FALSE },
	{ { 0x6f, 0x00, 0x00, 0x01 }, "Office 2000",            6, FALSE },
	{ { 0x70, 0x00, 0x00, 0x01 }, "Office XP beta 1/2",     6, FALSE },
	{ { 0x73, 0x00, 0x00, 0x01 }, "Office XP",              6, FALSE },
	{ { 0x76, 0x00, 0x00, 0x01 }, "Office 2003",            6, FALSE },
	{ { 0x79, 0x00, 0x00, 0x01 }, "Office 2003",            6, FALSE },
	{ { 0x60, 0x00, 0x00, 0x0e }, "MacOffice 98",           5, TRUE },
	{ { 0x62, 0x00, 0x00, 0x0e }, "MacOffice 2001",         5, TRUE },
	{ { 0x63, 0x00, 0x00, 0x0e }, "MacOffice X",		6, TRUE },
	{ { 0x64, 0x00, 0x00, 0x0e }, "MacOffice 2004",         6, TRUE },
};

#define VBA56_DIRENT_RECORD_COUNT (2 + /* magic */              \
                                   4 + /* version */            \
                                   2 + /* 0x00 0xff */          \
                                  22)  /* unknown */
#define VBA56_DIRENT_HEADER_SIZE (VBA56_DIRENT_RECORD_COUNT +   \
                                  2 +  /* type1 record count */ \
                                  2)   /* unknown */

static char *get_unicode_name(char *name, int size, int is_mac)
{
        int i, j;
        char *newname;

	if (!name || *name == 0 || size <= 0) {
                return NULL;
        }

        newname = (char *) cli_malloc(size*4);
        if (!newname) {
                return NULL;
        }
        j=0;
        for (i=0 ; i < size; i += (is_mac ? 1 : 2) ) {
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

static void vba56_test_middle(int fd)
{
	char test_middle[20];

	/* MacOffice middle */
	static const uint8_t middle1_str[20] = {
		0x00, 0x01, 0x0d, 0x45, 0x2e, 0xe1, 0xe0, 0x8f, 0x10, 0x1a,
		0x85, 0x2e, 0x02, 0x60, 0x8c, 0x4d, 0x0b, 0xb4, 0x00, 0x00
	};
	/* MS Office middle */
	static const uint8_t middle2_str[20] = {
		0x00, 0x00, 0xe1, 0x2e, 0x45, 0x0d, 0x8f, 0xe0, 0x1a, 0x10, 
		0x85, 0x2e, 0x02, 0x60, 0x8c, 0x4d, 0x0b, 0xb4, 0x00, 0x00
	};

        if (cli_readn(fd, &test_middle, 20) != 20) {
                return;
        }

	if ((memcmp(test_middle, middle1_str, 20) != 0) &&
		(memcmp(test_middle, middle2_str, 20) != 0)) {
		cli_dbgmsg("middle not found\n");
	        lseek(fd, -20, SEEK_CUR);
	} else {
		cli_dbgmsg("middle found\n");
	}
	return;
}

static int vba_read_project_strings(int fd, int is_mac)
{
	uint16_t length;
	unsigned char *buff;
	char *name;
	uint32_t offset;

	for (;;) {
		if (cli_readn(fd, &length, 2) != 2) {
			return FALSE;
		}
		length = vba_endian_convert_16(length, is_mac);
		if (length < 6) {
			lseek(fd, -2, SEEK_CUR);
			break;
		}
		cli_dbgmsg ("length: %d, ", length);
		buff = (unsigned char *) cli_malloc(length);
		if (!buff) {
			cli_errmsg("cli_malloc failed\n");
			return FALSE;
		}
		offset = lseek(fd, 0, SEEK_CUR);
		if (cli_readn(fd, buff, length) != length) {
			cli_dbgmsg("read name failed - rewinding\n");
			lseek(fd, offset, SEEK_SET);
			free(buff);
			break;
		}
		name = get_unicode_name((char *) buff, length, is_mac);
		if (name) {
			cli_dbgmsg("name: %s\n", name);
		} else {
			cli_dbgmsg("name: [null]\n");
		}
		free(buff);

		/* Ignore twelve bytes from entries of type 'G'.
		   Type 'C' entries come in pairs, the second also
		   having a 12 byte trailer */
		/* TODO: Need to check if types H(same as G) and D(same as C) exist */
		if (name && (!strncmp ("*\\G", name, 3) || !strncmp ("*\\H", name, 3)
			 	|| !strncmp("*\\C", name, 3) || !strncmp("*\\D", name, 3))) {
			if (cli_readn(fd, &length, 2) != 2) {
				return FALSE;
			}
			length = vba_endian_convert_16(length, is_mac);
			if ((length != 0) && (length != 65535)) {
				lseek(fd, -2, SEEK_CUR);
				free(name);
				continue;
			}
			buff = (unsigned char *) cli_malloc(10);
			if (!buff) {
				free(name);
				close(fd);
				return FALSE;
			}
			if (cli_readn(fd, buff, 10) != 10) {
				cli_errmsg("failed to read blob\n");
				free(buff);
				free(name);
				close(fd);
				return FALSE;
			}
			free(buff);
		} else {
			/* Unknown type - probably ran out of strings - rewind */
			lseek(fd, -(length+2), SEEK_CUR);
			if (name) {
				free(name);
			}
			break;
		}
		free(name);
		offset = lseek(fd, 0, SEEK_CUR);
		cli_dbgmsg("offset: %u\n", offset);
		vba56_test_middle(fd);
	}
	return TRUE;
}

vba_project_t *vba56_dir_read(const char *dir)
{
	unsigned char magic[2];
	unsigned char version[4];
	unsigned char *buff;
        unsigned char vba56_signature[] = { 0xcc, 0x61 };
	uint16_t record_count, length;
	uint16_t ooff;
	uint16_t byte_count;
	uint32_t offset;
	uint32_t LidA;  /* Language identifiers */
	uint32_t LidB;
	uint16_t CharSet;
	uint16_t LenA;
	uint32_t UnknownB;
	uint32_t UnknownC;
	uint16_t LenB;
	uint16_t LenC;
	uint16_t LenD;
	int i, j, fd, is_mac;
	vba_project_t *vba_project;
	char *fullname;

	cli_dbgmsg("in vba56_dir_read()\n");

	fullname = (char *) cli_malloc(strlen(dir) + 14);
	if (!fullname) {
		return NULL;
	}
	sprintf(fullname, "%s/_VBA_PROJECT", dir);
        fd = open(fullname, O_RDONLY);

        if (fd == -1) {
                cli_dbgmsg("Can't open %s\n", fullname);
		free(fullname);
		/* vba56_old_dir_read(dir); */
                return NULL;
        }
	free(fullname);

	if (cli_readn(fd, &magic, 2) != 2) {
		close(fd);
		return NULL;
	}
	if (memcmp(magic, vba56_signature, 2) != 0) {
		close(fd);
		return NULL;
	}

	if (cli_readn(fd, &version, 4) != 4) {
		close(fd);
		return NULL;
	}
	for (i=0 ; i < NUM_VBA_VERSIONS ; i++) {
		if (memcmp(version, vba_version[i].signature, 4) == 0) {
			break;
		}
	}

	if (i == NUM_VBA_VERSIONS) {
		cli_warnmsg("Unknown VBA version signature %x %x %x %x\n",
			version[0], version[1], version[2], version[3]);
		if (version[3] == 0x01) {
			cli_warnmsg("Guessing little-endian\n");
			is_mac = FALSE;
		} else if (version[3] == 0x0e) {
			cli_warnmsg("Guessing big-endian\n");
			is_mac = TRUE;
		} else {
			cli_warnmsg("Unable to guess VBA type\n");
			close(fd);
			return NULL;
		}	
	} else {
		cli_dbgmsg("VBA Project: %s, VBA Version=%d\n", vba_version[i].name,
                                vba_version[i].vba_version);
		is_mac = vba_version[i].is_mac;
	}

	/*****************************************/

	/* two bytes, should be equal to 0x00ff */
	if (cli_readn(fd, &ooff, 2) != 2) {
		close(fd);
		return NULL;
	}

	if (cli_readn(fd, &LidA, 4) != 4) {
		close(fd);
		return NULL;
	}

	if (cli_readn(fd, &LidB, 4) != 4) {
		close(fd);
		return NULL;
	}

	if (cli_readn(fd, &CharSet, 2) != 2) {
		close(fd);
		return NULL;
	}
	if (cli_readn(fd, &LenA, 2) != 2) {
		close(fd);
		return NULL;
	}

	if (cli_readn(fd, &UnknownB, 4) != 4) {
		close(fd);
		return NULL;
	}
	if (cli_readn(fd, &UnknownC, 4) != 4) {
		close(fd);
		return NULL;
	}

	if (cli_readn(fd, &LenB, 2) != 2) {
		close(fd);
		return NULL;
	}
	if (cli_readn(fd, &LenC, 2) != 2) {
		close(fd);
		return NULL;
	}
	if (cli_readn(fd, &LenD, 2) != 2) {
		close(fd);
		return NULL;
	}

        LidA = vba_endian_convert_32(LidA, is_mac);
        LidB = vba_endian_convert_32(LidB, is_mac);
        CharSet = vba_endian_convert_16(CharSet, is_mac);
        LenA = vba_endian_convert_16(LenA, is_mac);
        LenB = vba_endian_convert_16(LenB, is_mac);
        LenC = vba_endian_convert_16(LenC, is_mac);
        LenD = vba_endian_convert_16(LenD, is_mac);

	cli_dbgmsg(" LidA: %d\n LidB: %d\n CharSet: %d\n", LidA, LidB, CharSet);
	cli_dbgmsg(" LenA: %d\n UnknownB: %d\n UnknownC: %d\n", LenA, UnknownB, UnknownC);
	cli_dbgmsg(" LenB: %d\n LenC: %d\n LenD: %d\n", LenB, LenC, LenD);

	record_count = LenC;

	if (!vba_read_project_strings(fd, is_mac)) {
		close(fd);
		return NULL;
	}
	
	/* junk some more stuff */
	do {
		if (cli_readn(fd, &ooff, 2) != 2) {
			close(fd);
			return NULL;
		}
	} while(ooff != 0xFFFF);

	/* check for alignment error */
	lseek(fd, -3, SEEK_CUR);
	if (cli_readn(fd, &ooff, 2) != 2) {
 		close(fd);
		return NULL;
	}
	if (ooff != 0xFFFF) {
		lseek(fd, 1, SEEK_CUR);
	}
	
	if (cli_readn(fd, &ooff, 2) != 2) {
		close(fd);
		return NULL;
	}

	/* no idea what this stuff is */
	if (ooff != 0xFFFF) {
		ooff = vba_endian_convert_16(ooff, is_mac);
		lseek(fd, ooff, SEEK_CUR);
	}
	if (cli_readn(fd, &ooff, 2) != 2) {
		close(fd);
		return NULL;
	}
	if (ooff != 0xFFFF) {
		ooff = vba_endian_convert_16(ooff, is_mac);
		lseek(fd, ooff, SEEK_CUR);
	}
	lseek(fd, 100, SEEK_CUR);

	if (cli_readn(fd, &record_count, 2) != 2) {
		close(fd);
		return NULL;
	}
	record_count = vba_endian_convert_16(record_count, is_mac);
	cli_dbgmsg("\nVBA Record count: %d\n", record_count);
	if (record_count == 0) {
		close(fd);
                return NULL;
        }
	if (record_count > 1000) {
		/* Almost certainly an error */
		cli_dbgmsg("\nVBA Record count too big");
		close(fd);
		return NULL;
	}
	
	vba_project = (vba_project_t *) cli_malloc(sizeof(struct vba_project_tag));
	if (!vba_project) {
		close(fd);
		return NULL;
	}
	vba_project->name = (char **) cli_malloc(sizeof(char *) * record_count);
	if (!vba_project->name) {
		free(vba_project);
		close(fd);
		return NULL;
	}
	vba_project->dir = strdup(dir);
	vba_project->offset = (uint32_t *) cli_malloc (sizeof(uint32_t) *
					record_count);
	if (!vba_project->offset) {
		free(vba_project->dir);
		free(vba_project->name);
		free(vba_project);
		close(fd);
		return NULL;
	}
	vba_project->count = record_count;
	for (i=0 ; i < record_count ; i++) {
		if (cli_readn(fd, &length, 2) != 2) {
			goto out_error;
		}
		length = vba_endian_convert_16(length, is_mac);
		if (length == 0) {
			cli_dbgmsg("zero name length\n");
			goto out_error;
                }
		buff = (unsigned char *) cli_malloc(length);
		if (!buff) {
			cli_dbgmsg("cli_malloc failed\n");
			goto out_error;
		}
		if (cli_readn(fd, buff, length) != length) {
			cli_dbgmsg("read name failed\n");
			free(buff);
			goto out_error;
		}
		vba_project->name[i] = get_unicode_name((char *) buff, length, is_mac);
		if (!vba_project->name[i]) {
			offset = lseek(fd, 0, SEEK_CUR);
			vba_project->name[i] = (char *) cli_malloc(18);
			snprintf(vba_project->name[i], 18, "clamav-%.10d", offset);
		}
		cli_dbgmsg("project name: %s, ", vba_project->name[i]);
		free(buff);

		/* some kind of string identifier ?? */
		if (cli_readn(fd, &length, 2) != 2) {
			free(vba_project->name[i]);
			goto out_error;
		}
		length = vba_endian_convert_16(length, is_mac);
		lseek(fd, length, SEEK_CUR);

		/* unknown stuff */
		if (cli_readn(fd, &ooff, 2) != 2) {
			free(vba_project->name[i]);
			goto out_error;
		}
		ooff = vba_endian_convert_16(ooff, is_mac);
		if (ooff == 0xFFFF) {
			lseek(fd, 2, SEEK_CUR);
			if (cli_readn(fd, &ooff, 2) != 2) {
				free(vba_project->name[i]);
				goto out_error;
			}
			ooff = vba_endian_convert_16(ooff, is_mac);
			lseek(fd, ooff, SEEK_CUR);
		} else {
			lseek(fd, 2 + ooff, SEEK_CUR);
		}

		lseek(fd, 8, SEEK_CUR);
		if (cli_readn(fd, &byte_count, 2) != 2) {
			free(vba_project->name[i]);
			goto out_error;
		}
		byte_count = vba_endian_convert_16(byte_count, is_mac);
		for (j=0 ; j<byte_count; j++) {
			lseek(fd, 8, SEEK_CUR);
		}
		lseek(fd, 5, SEEK_CUR);
		if (cli_readn(fd, &offset, 4) != 4) {
			free(vba_project->name[i]);
			goto out_error;
		}
		offset = vba_endian_convert_32(offset, is_mac);
		vba_project->offset[i] = offset;
		cli_dbgmsg("offset:%u\n", offset);
		lseek(fd, 2, SEEK_CUR);
	}
	
	
	{ /* There appears to be some code in here */
	
	off_t foffset;

		foffset = lseek(fd, 0, SEEK_CUR);
		cli_dbgmsg("\nOffset: 0x%x\n", (unsigned int)foffset);
	}
	close(fd);
	return vba_project;

out_error:
	/* Note: only to be called from the above loop
	   when i == number of allocated stings */
	for (j=0 ; j<i ; j++) {
		free(vba_project->name[j]);
	}
	free(vba_project->name);
	free(vba_project->dir);
	free(vba_project->offset);
	free(vba_project);
	close(fd);
	return NULL;
}

#define VBA_COMPRESSION_WINDOW 4096

static void byte_array_append(byte_array_t *array, unsigned char *src, unsigned int len)
{
	if (array->length == 0) {
		array->data = (unsigned char *) cli_malloc(len);
		if (!array->data) {
			return;
		}
		array->length = len;
		memcpy(array->data, src, len);
	} else {
		array->data = realloc(array->data, array->length+len);
		if (!array->data) {
			return;
		}	
		memcpy(array->data+array->length, src, len);
		array->length += len;
	}
}

unsigned char *vba_decompress(int fd, uint32_t offset, int *size)
{
	unsigned int i, pos=0, shift, win_pos, clean=TRUE, mask, distance;
	uint8_t flag;
	uint16_t token, len;
	unsigned char buffer[VBA_COMPRESSION_WINDOW];
	byte_array_t result;
	
	result.length=0;
	result.data=NULL;
	
	lseek(fd, offset+3, SEEK_SET); /* 1byte ?? , 2byte length ?? */ 
	
	while (cli_readn(fd, &flag, 1) == 1) {
		for (mask = 1; mask < 0x100; mask<<=1) {
			if (flag & mask) {
				if (cli_readn(fd, &token, 2) != 2) {
					if (result.data) {
						free(result.data);
					}
					if (size) {
						*size = 0;
					}
					return NULL;
				}
				token = vba_endian_convert_16(token, FALSE);
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
					
					if (cli_readn(fd, &token, 2) != 2) {
						if (result.data) {
							free(result.data);
						}
						if (size) {
                                         	       *size = 0;
                                        	}
						return NULL;
					}
					clean = FALSE;
					byte_array_append(&result, buffer, VBA_COMPRESSION_WINDOW);
					break;
				}
				if (cli_readn(fd, buffer+(pos%VBA_COMPRESSION_WINDOW), 1) == 1){
					pos++;
				}
				clean = TRUE;
			}
		}
	}
			
	if (pos % VBA_COMPRESSION_WINDOW) {
		byte_array_append(&result, buffer, pos % VBA_COMPRESSION_WINDOW);
	}
	if (size) {
		*size = result.length;
	}
	return result.data;

}

/* +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
/* Code to extract Power Point Embedded OLE2 Objects		     */
/* +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */

#define MIN(a, b)  (((a) < (b)) ? (a) : (b))

typedef struct atom_header_tag {
	off_t foffset;
	uint16_t ver_inst;
	uint8_t version;
	uint16_t instance;
	uint16_t type;
	uint32_t length;
} atom_header_t;

static int ppt_read_atom_header(int fd, atom_header_t *atom_header)
{
	atom_header->foffset = lseek(fd, 0, SEEK_CUR);
	if (cli_readn(fd, &atom_header->ver_inst, 2) != 2) {
		cli_dbgmsg("read ppt_current_user failed\n");
		return FALSE;
	}
	atom_header->ver_inst = vba_endian_convert_16(atom_header->ver_inst, FALSE);
	atom_header->version = atom_header->ver_inst & 0x000f;
	atom_header->instance = atom_header->ver_inst >> 4;
	if (cli_readn(fd, &atom_header->type, 2) != 2) {
		cli_dbgmsg("read ppt_current_user failed\n");
		return FALSE;
	}
	if (cli_readn(fd, &atom_header->length, 4) != 4) {
		cli_dbgmsg("read ppt_current_user failed\n");
		return FALSE;
	}
	atom_header->type = vba_endian_convert_16(atom_header->type, FALSE);
	atom_header->length = vba_endian_convert_32(atom_header->length, FALSE);
	return TRUE;
}

static void ppt_print_atom_header(atom_header_t *atom_header)
{
	cli_dbgmsg("Atom Hdr:\n");
	cli_dbgmsg("  Version: 0x%.2x\n", atom_header->version);
	cli_dbgmsg("  Instance: 0x%.4x\n", atom_header->instance);
	cli_dbgmsg("  Type: 0x%.4x\n", atom_header->type);
	cli_dbgmsg("  Length: 0x%.8x\n", atom_header->length);
}

#define PPT_LZW_BUFFSIZE 8192
static int ppt_unlzw(const char *dir, int fd, uint32_t length)
{
	int ofd, retval;
	unsigned char inbuff[PPT_LZW_BUFFSIZE], outbuff[PPT_LZW_BUFFSIZE];
	char *fullname;
	uint32_t bufflen;
	z_stream stream;
	
	fullname = cli_malloc(strlen(dir) + 17);
	if (!fullname) {
		return FALSE;
	}
	sprintf(fullname, "%s/ppt%.8lx.doc", dir, lseek(fd, 0, SEEK_CUR));
	
	ofd = open(fullname, O_WRONLY|O_CREAT|O_TRUNC, 0600);
	free(fullname);
        if (ofd == -1) {
                cli_dbgmsg("ppt_unlzw Open outfile failed\n");
                return FALSE;
        }
	
	stream.zalloc = Z_NULL;
	stream.zfree = Z_NULL;
	stream.opaque = (void *)0;
	
	stream.next_in = inbuff;
	bufflen = stream.avail_in = MIN(length, PPT_LZW_BUFFSIZE);
	
	if (cli_readn(fd, inbuff, stream.avail_in) != (int64_t)stream.avail_in) {
		close(ofd);
		return FALSE;
	}
	length -= stream.avail_in;
	
	retval = inflateInit(&stream);
	if (retval != Z_OK) {
		cli_dbgmsg(" ppt_unlzw !Z_OK: %d\n", retval);
	}
	
	stream.next_out = outbuff;
	stream.avail_out = PPT_LZW_BUFFSIZE;
	
	do {
		if (stream.avail_out == 0) {
			if (cli_writen(ofd, outbuff, PPT_LZW_BUFFSIZE)
						!= PPT_LZW_BUFFSIZE) {
				close(ofd);
				inflateEnd(&stream);
				return FALSE;
			}
			stream.next_out = outbuff;
			stream.avail_out = PPT_LZW_BUFFSIZE;
		}
		if (stream.avail_in == 0) {
			stream.next_in = inbuff;
			bufflen = stream.avail_in = MIN(length, PPT_LZW_BUFFSIZE);
			if (cli_readn(fd, inbuff, stream.avail_in) != (int64_t)stream.avail_in) {
				close(ofd);
				inflateEnd(&stream);
				return FALSE;
			}
			length -= stream.avail_in;
		}
		retval = inflate(&stream, Z_NO_FLUSH);
	} while (retval == Z_OK);
	
	if (cli_writen(ofd, outbuff, bufflen) != (int64_t)bufflen) {
		close(ofd);
		inflateEnd(&stream);
		return FALSE;
	}
	inflateEnd(&stream);
	close(ofd);
	return TRUE;
}

static char *ppt_stream_iter(int fd)
{
	atom_header_t atom_header;
	uint32_t ole_id;
	char *out_dir;
	off_t offset;
	
	/* Create a directory to store the extracted OLE2 objects */
	out_dir = cli_gentemp(NULL);
	if(mkdir(out_dir, 0700)) {
	    printf("ScanOLE2 -> Can't create temporary directory %s\n", out_dir);
	    free(out_dir);
	    close(fd);
	    return NULL;
	}

	while (1) {
		if (!ppt_read_atom_header(fd, &atom_header)) {
			break;
		}
		ppt_print_atom_header(&atom_header);

		if (atom_header.length == 0) {
			cli_rmdirs(out_dir);
			free(out_dir);
			return NULL;
		}

		if (atom_header.type == 0x1011) {
			if (cli_readn(fd, &ole_id, 4) != 4) {
				cli_dbgmsg("read ole_id failed\n");
				cli_rmdirs(out_dir);
				free(out_dir);
				return NULL;
			}
			ole_id = vba_endian_convert_32(ole_id, FALSE);
			cli_dbgmsg("OleID: %d, length: %d\n",
					ole_id, atom_header.length-4);
			if (!ppt_unlzw(out_dir, fd, atom_header.length-4)) {
				cli_dbgmsg("ppt_unlzw failed\n");
				cli_rmdirs(out_dir);
				free(out_dir);
				return NULL;
			}

		} else {
			offset = lseek(fd, 0, SEEK_CUR);
			/* Check we don't wrap */
			if ((offset + (off_t)atom_header.length) < offset) {
				break;
			}
			offset += atom_header.length;
			if (lseek(fd, offset, SEEK_SET) != offset ) {
				break;
			}
		}
	}
	return out_dir;
}

char *ppt_vba_read(const char *dir)
{
	char *fullname, *out_dir;
	int fd;

	fullname = (char *) cli_malloc(strlen(dir) + 21);
	if (!fullname) {
		return NULL;
	}
	sprintf(fullname, "%s/PowerPoint Document", dir);
	fd = open(fullname, O_RDONLY);
	free(fullname);
	if (fd == -1) {
		cli_dbgmsg("Open  PowerPoint Document failed\n");
		return NULL;
	}
	
	out_dir = ppt_stream_iter(fd);
	close(fd);
	return out_dir;
}


/* +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
/* Code to extract Word6 macros					     */
/* +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */

typedef struct mso_fib_tag {
	uint16_t magic;
	uint16_t version;
	uint16_t product;
	uint16_t lid;
	uint16_t next;
	uint16_t status;
	/* block of 268 bytes - ignore */
	uint32_t macro_offset;
	uint32_t macro_len;
} mso_fib_t;

typedef struct macro_entry_tag {
	unsigned char version;
	unsigned char key;
	uint16_t intname_i;
	uint16_t extname_i;
	uint16_t xname_i;
	uint32_t unknown;
	uint32_t len;
	uint32_t state;
	uint32_t offset;
} macro_entry_t;

typedef struct macro_info_tag {
	uint16_t count;
	struct macro_entry_tag *macro_entry;
} macro_info_t;

typedef struct macro_extname_tag {
	uint8_t length;
	char *extname;
	uint16_t numref;
} macro_extname_t;

typedef struct macro_extnames_tag {
	uint16_t count;
	struct macro_extname_tag *macro_extname;
} macro_extnames_t;

typedef struct macro_intnames_tag {
	uint16_t count;
	struct macro_intname_tag *macro_intname;
} macro_intnames_t;

typedef struct macro_intname_tag {
	uint16_t id;
	uint8_t length;
	char *intname;
} macro_intname_t;

typedef struct menu_entry_tag {
	uint16_t context;
	uint16_t menu;
	uint16_t extname_i;
	uint16_t unknown;
	uint16_t intname_i;
	uint16_t pos;
} menu_entry_t;

typedef struct menu_info_tag {
	uint16_t count;
	struct menu_entry_tag *menu_entry;
} menu_info_t;

typedef struct mac_token_tag {
	unsigned char token;
	unsigned char *str;
} mac_token_t;

typedef struct mac_token2_tag {
	uint16_t token;
	unsigned char *str;

} mac_token2_t;

static void wm_print_fib(mso_fib_t *fib)
{
	cli_dbgmsg("magic: 0x%.4x\n", fib->magic);
	cli_dbgmsg("version: 0x%.4x\n", fib->version);
	cli_dbgmsg("product: 0x%.4x\n", fib->product);
	cli_dbgmsg("lid: 0x%.4x\n", fib->lid);
	cli_dbgmsg("macro offset: 0x%.4x\n", fib->macro_offset);
	cli_dbgmsg("macro len: 0x%.4x\n\n", fib->macro_len);
}
	
static int wm_read_fib(int fd, mso_fib_t *fib)
{
	if (cli_readn(fd, &fib->magic, 2) != 2) {
		cli_dbgmsg("read wm_fib failed\n");
		return FALSE;
	}
	if (cli_readn(fd, &fib->version, 2) != 2) {
		cli_dbgmsg("read wm_fib failed\n");
		return FALSE;
	}
	if (cli_readn(fd, &fib->product, 2) != 2) {
		cli_dbgmsg("read wm_fib failed\n");
		return FALSE;
	}
	if (cli_readn(fd, &fib->lid, 2) != 2) {
		cli_dbgmsg("read wm_fib failed\n");
		return FALSE;
	}	
	if (cli_readn(fd, &fib->next, 2) != 2) {
		cli_dbgmsg("read wm_fib failed\n");
		return FALSE;
	}
	if (cli_readn(fd, &fib->status, 2) != 2) {
		cli_dbgmsg("read wm_fib failed\n");
		return FALSE;
	}
	
	/* don't need the information is this block, so seek forward */
	if (lseek(fd, 0x118, SEEK_SET) != 0x118) {
		cli_dbgmsg("lseek wm_fib failed\n");
		return FALSE;
	}
	
	if (cli_readn(fd, &fib->macro_offset, 4) != 4) {
		cli_dbgmsg("read wm_fib failed\n");
		return FALSE;
	}
	if (cli_readn(fd, &fib->macro_len, 4) != 4) {
		cli_dbgmsg("read wm_fib failed\n");
		return FALSE;
	}
	fib->magic = vba_endian_convert_16(fib->magic, FALSE);
	fib->version = vba_endian_convert_16(fib->version, FALSE);
	fib->product = vba_endian_convert_16(fib->product, FALSE);
	fib->lid = vba_endian_convert_16(fib->lid, FALSE);
	fib->next = vba_endian_convert_16(fib->next, FALSE);
	fib->status = vba_endian_convert_16(fib->status, FALSE);
	fib->macro_offset = vba_endian_convert_32(fib->macro_offset, FALSE);
	fib->macro_len = vba_endian_convert_32(fib->macro_len, FALSE);
	
	return TRUE;
}

static int wm_read_macro_entry(int fd, macro_entry_t *macro_entry)
{
	if (cli_readn(fd, &macro_entry->version, 1) != 1) {
		cli_dbgmsg("read macro_entry failed\n");
		return FALSE;
	}
	if (cli_readn(fd, &macro_entry->key, 1) != 1) {
		cli_dbgmsg("read macro_entry failed\n");
		return FALSE;
	}
	if (cli_readn(fd, &macro_entry->intname_i, 2) != 2) {
		cli_dbgmsg("read macro_entry failed\n");
		return FALSE;
	}	
	if (cli_readn(fd, &macro_entry->extname_i, 2) != 2) {
		cli_dbgmsg("read macro_entry failed\n");
		return FALSE;
	}
	if (cli_readn(fd, &macro_entry->xname_i, 2) != 2) {
		cli_dbgmsg("read macro_entry failed\n");
		return FALSE;
	}
	if (cli_readn(fd, &macro_entry->unknown, 4) != 4) {
		cli_dbgmsg("read macro_entry failed\n");
		return FALSE;
	}
	if (cli_readn(fd, &macro_entry->len, 4) != 4) {
		cli_dbgmsg("read macro_entry failed\n");
		return FALSE;
	}
	if (cli_readn(fd, &macro_entry->state, 4) != 4) {
		cli_dbgmsg("read macro_entry failed\n");
		return FALSE;
	}
	if (cli_readn(fd, &macro_entry->offset, 4) != 4) {
		cli_dbgmsg("read macro_entry failed\n");
		return FALSE;
	}
	
	macro_entry->intname_i = vba_endian_convert_16(macro_entry->intname_i, FALSE);
	macro_entry->extname_i = vba_endian_convert_16(macro_entry->extname_i, FALSE);
	macro_entry->xname_i = vba_endian_convert_16(macro_entry->xname_i, FALSE);
	macro_entry->len = vba_endian_convert_32(macro_entry->len, FALSE);
	macro_entry->state = vba_endian_convert_32(macro_entry->state, FALSE);
	macro_entry->offset = vba_endian_convert_32(macro_entry->offset, FALSE);
	return TRUE;
}

static macro_info_t *wm_read_macro_info(int fd)
{
	int i;
	macro_info_t *macro_info;

	macro_info = (macro_info_t *) cli_malloc(sizeof(macro_info_t));
	if (!macro_info) {
		return NULL;
	}
	if (cli_readn(fd, &macro_info->count, 2) != 2) {
		cli_dbgmsg("read macro_info failed\n");
		free(macro_info);
		return NULL;
	}
	macro_info->count = vba_endian_convert_16(macro_info->count, FALSE);
	cli_dbgmsg("macro count: %d\n", macro_info->count);
	macro_info->macro_entry = (macro_entry_t *)
			cli_malloc(sizeof(macro_entry_t) * macro_info->count);
	if (!macro_info->macro_entry) {
		free(macro_info);
		return NULL;
	}
	for (i=0 ; i < macro_info->count ; i++) {
		if (!wm_read_macro_entry(fd,
				&macro_info->macro_entry[i])) {
			free(macro_info->macro_entry);
			free(macro_info);
			return NULL;
		}
	}
	return macro_info;
}

static void wm_free_macro_info(macro_info_t *macro_info)
{
	if (macro_info) {
		free(macro_info->macro_entry);
		free(macro_info);
	}
	return;
}

static int wm_read_oxo3(int fd)
{
	uint8_t count;

	if (cli_readn(fd, &count, 1) != 1) {
		cli_dbgmsg("read oxo3 record1 failed\n");
		return FALSE;
	}
	if (lseek(fd, count*14, SEEK_CUR) == -1) {
		cli_dbgmsg("lseek oxo3 record1 failed\n");
		return FALSE;
	}
	cli_dbgmsg("oxo3 records1: %d\n", count);
	
	if (cli_readn(fd, &count, 1) != 1) {
		cli_dbgmsg("read oxo3 record2 failed\n");
		return FALSE;
	}
	if (count == 0) {
		if (cli_readn(fd, &count, 1) != 1) {
			cli_dbgmsg("read oxo3 failed\n");
			return FALSE;
		}
		if (count != 2) {
			lseek(fd, -1, SEEK_CUR);
			return TRUE;
		}
		if (cli_readn(fd, &count, 1) != 1) {
			cli_dbgmsg("read oxo3 failed\n");
			return FALSE;
		}
	}
	if (count > 0) {
		if (lseek(fd, (count*4)+1, SEEK_CUR) == -1) {
			cli_dbgmsg("lseek oxo3 failed\n");
			return FALSE;
		}
	}				
	cli_dbgmsg("oxo3 records2: %d\n", count);
	return TRUE;
}

static menu_info_t *wm_read_menu_info(int fd)
{
	int i;
	menu_info_t *menu_info;
	menu_entry_t *menu_entry;
	
	menu_info = (menu_info_t *) cli_malloc(sizeof(menu_info_t));
	if (!menu_info) {
		return NULL;
	}
	
	if (cli_readn(fd, &menu_info->count, 2) != 2) {
		cli_dbgmsg("read menu_info failed\n");
		free(menu_info);
		return NULL;
	}
	menu_info->count = vba_endian_convert_16(menu_info->count, FALSE);
	cli_dbgmsg("menu_info count: %d\n", menu_info->count);
	
	menu_info->menu_entry =
		(menu_entry_t *) cli_malloc(sizeof(menu_entry_t) * menu_info->count);
	if (!menu_info->menu_entry) {
		free(menu_info);
		return NULL;
	}
	
	for (i=0 ; i < menu_info->count ; i++) {
		menu_entry = &menu_info->menu_entry[i];
		if (cli_readn(fd, &menu_entry->context, 2) != 2) {
			goto abort;
		}
		if (cli_readn(fd, &menu_entry->menu, 2) != 2) {
			goto abort;
		}
		if (cli_readn(fd, &menu_entry->extname_i, 2) != 2) {
			goto abort;
		}
		if (cli_readn(fd, &menu_entry->unknown, 2) != 2) {
			goto abort;
		}
		if (cli_readn(fd, &menu_entry->intname_i, 2) != 2) {
			goto abort;
		}
		if (cli_readn(fd, &menu_entry->pos, 2) != 2) {
			goto abort;
		}
		menu_entry->context = vba_endian_convert_16(menu_entry->context, FALSE);
		menu_entry->menu = vba_endian_convert_16(menu_entry->menu, FALSE);
		menu_entry->extname_i = vba_endian_convert_16(menu_entry->extname_i, FALSE);
		menu_entry->intname_i = vba_endian_convert_16(menu_entry->intname_i, FALSE);
		menu_entry->pos = vba_endian_convert_16(menu_entry->pos, FALSE);
		cli_dbgmsg("menu entry: %d.%d\n", menu_entry->menu, menu_entry->pos);
	}
	return menu_info;
	
abort:
	cli_dbgmsg("read menu_entry failed\n");
	free(menu_info->menu_entry);
	free(menu_info);
	return NULL;
}

static void wm_free_menu_info(menu_info_t *menu_info)
{
	if (menu_info) {
		free(menu_info->menu_entry);
		free(menu_info);
	}
	return;
}

static macro_extnames_t *wm_read_macro_extnames(int fd)
{
	int i, is_unicode=0;
	int16_t size;
	off_t offset_end;	
	macro_extnames_t *macro_extnames;
	macro_extname_t *macro_extname;
	char *name_tmp;
	
	macro_extnames = (macro_extnames_t *) cli_malloc(sizeof(macro_extnames_t));
	if (!macro_extnames) {
		return NULL;
	}
	macro_extnames->count = 0;
	macro_extnames->macro_extname = NULL;
	
	offset_end = lseek(fd, 0, SEEK_CUR);
	if (cli_readn(fd, &size, 2) != 2) {
		cli_dbgmsg("read macro_extnames failed\n");
		free(macro_extnames);
		return NULL;
	}
	size = vba_endian_convert_16(size, FALSE);
	if (size == -1) { /* Unicode flag */
		is_unicode=1;
		if (cli_readn(fd, &size, 2) != 2) {
			cli_dbgmsg("read macro_extnames failed\n");
			free(macro_extnames);
			return NULL;
		}
		size = vba_endian_convert_16(size, FALSE);
	}
	cli_dbgmsg("ext names size: 0x%x\n", size);

	offset_end += size;
	while (lseek(fd, 0, SEEK_CUR) < offset_end) {
		macro_extnames->count++;
		macro_extnames->macro_extname = (macro_extname_t *)
			cli_realloc(macro_extnames->macro_extname,
				sizeof(macro_extname_t) * macro_extnames->count);
		if (macro_extnames->macro_extname == NULL) {
			cli_dbgmsg("read macro_extnames failed\n");
			goto abort;;
		}

		macro_extname = &macro_extnames->macro_extname[macro_extnames->count-1];
		if (is_unicode) {
			if (cli_readn(fd, &macro_extname->length, 1) != 1) {
				cli_dbgmsg("read macro_extnames failed\n");
				goto abort;
			}
			lseek(fd, 1, SEEK_CUR);
			if (macro_extname->length > 0) {
			    name_tmp = (char *) cli_malloc(macro_extname->length*2);
			    if (name_tmp == NULL) {
				goto abort;
			    }
			    if (cli_readn(fd, name_tmp, macro_extname->length*2) != 
						macro_extname->length*2) {
				cli_dbgmsg("read macro_extnames failed\n");
				free(name_tmp);
				goto abort;
			    }
			    macro_extname->extname =
				get_unicode_name(name_tmp, macro_extname->length*2, FALSE);
			    free(name_tmp);
			} else {
			    macro_extname->extname = strdup("[no name]");
			    macro_extname->length = 10;
			}
		} else {
			if (cli_readn(fd, &macro_extname->length, 1) != 1) {
				cli_dbgmsg("read macro_extnames failed\n");
				goto abort;
			}
			if (macro_extname->length > 0) {
			    macro_extname->extname = (char *) cli_malloc(macro_extname->length+1);
			    if (!macro_extname->extname) {
				goto abort;
			    }
			    if (cli_readn(fd, macro_extname->extname, macro_extname->length) != 
						macro_extname->length) {
				cli_dbgmsg("read macro_extnames failed\n");
				free(macro_extname->extname);
				goto abort;
			    }
			    macro_extname->extname[macro_extname->length] = '\0';
			} else {
			    macro_extname->extname = strdup("[no name]");
			    macro_extname->length = 10;
			}
		}
		if (cli_readn(fd, &macro_extname->numref, 2) != 2) {
			cli_dbgmsg("read macro_extnames failed\n");
			return NULL;
		}	
		macro_extname->numref = vba_endian_convert_16(macro_extname->numref, FALSE);
		cli_dbgmsg("ext name: %s\n", macro_extname->extname);
	}
	return macro_extnames;
	
abort:
	if (macro_extnames->macro_extname != NULL) {
		for (i=0 ; i < macro_extnames->count-1 ; i++) {
			free(macro_extnames->macro_extname[i].extname);
		}
		free(macro_extnames->macro_extname);
	}
	free(macro_extnames);
	return NULL;
}

static void wm_free_extnames(macro_extnames_t *macro_extnames)
{
	int i;
	
	if (macro_extnames) {
		for (i=0 ; i < macro_extnames->count ; i++) {
			free(macro_extnames->macro_extname[i].extname);
		}
		free(macro_extnames->macro_extname);
		free(macro_extnames);
	}
	return;
}

static macro_intnames_t *wm_read_macro_intnames(int fd)
{
	int i;
	macro_intnames_t *macro_intnames;
	macro_intname_t *macro_intname;
	uint16_t junk;
	
	macro_intnames = (macro_intnames_t *) cli_malloc(sizeof(macro_intnames_t));
	if (!macro_intnames) {
		return NULL;
	}
	
	if (cli_readn(fd, &macro_intnames->count, 2) != 2) {
		cli_dbgmsg("read macro_intnames failed\n");
		return NULL;
	}
	macro_intnames->count = vba_endian_convert_16(macro_intnames->count, FALSE);
	cli_dbgmsg("int names count: %d\n", macro_intnames->count);
	
	macro_intnames->macro_intname =
		(macro_intname_t *) cli_malloc(sizeof(macro_intname_t) * macro_intnames->count);
	if (!macro_intnames->macro_intname) {
		free(macro_intnames);
		return NULL;
	}
	for (i=0 ; i < macro_intnames->count ; i++) {
		macro_intname = &macro_intnames->macro_intname[i];
		if (cli_readn(fd, &macro_intname->id, 2) != 2) {
			cli_dbgmsg("read macro_intnames failed\n");
			macro_intnames->count = i;
			goto abort;
		}
		macro_intname->id = vba_endian_convert_16(macro_intname->id, FALSE);
		if (cli_readn(fd, &macro_intname->length, 1) != 1) {
			cli_dbgmsg("read macro_intnames failed\n");
			macro_intnames->count = i;
			goto abort;;
		}	
		macro_intname->intname = (char *) cli_malloc(macro_intname->length+1);
		if (!macro_intname->intname) {
			macro_intnames->count = i;
			goto abort;
		}
		if (cli_readn(fd, macro_intname->intname, macro_intname->length) != macro_intname->length) {
			cli_dbgmsg("read macro_intnames failed\n");
			macro_intnames->count = i+1;
			goto abort;
		}
		macro_intname->intname[macro_intname->length] = '\0';
		if (cli_readn(fd, &junk, 1) != 1) {
			cli_dbgmsg("read macro_intnames failed\n");
			macro_intnames->count = i+1;
			goto abort;
		}
		cli_dbgmsg("int name: %s\n", macro_intname->intname);
	}
	return macro_intnames;
abort:
	for (i=0 ; i < macro_intnames->count ; i++) {
		free(macro_intnames->macro_intname[i].intname);
	}
	free(macro_intnames->macro_intname);
	free(macro_intnames);
	return NULL;
}

static void wm_free_intnames(macro_intnames_t *macro_intnames)
{
	int i;
	
	if (macro_intnames) {
		for (i=0 ; i < macro_intnames->count ; i++) {
			free(macro_intnames->macro_intname[i].intname);
		}
		free(macro_intnames->macro_intname);
		free(macro_intnames);
	}
	return;
}

vba_project_t *wm_dir_read(const char *dir)
{
	int fd, done=FALSE, i;
	mso_fib_t fib;
	off_t end_offset;
	unsigned char start_id, info_id;
	macro_info_t *macro_info=NULL;
	menu_info_t *menu_info=NULL;
	macro_extnames_t *macro_extnames=NULL;
	macro_intnames_t *macro_intnames=NULL;
	vba_project_t *vba_project=NULL;
	char *fullname;
	
	fullname = (char *) cli_malloc(strlen(dir) + 14);
	if (!fullname) {
		return NULL;
	}
	sprintf(fullname, "%s/WordDocument", dir);
	fd = open(fullname, O_RDONLY);
	free(fullname);
	if (fd == -1) {
		cli_dbgmsg("Open WordDocument failed\n");
		return NULL;
	}
	
	if (!wm_read_fib(fd, &fib)) {
		close(fd);
		return NULL;
	}
	wm_print_fib(&fib);
	
	if (lseek(fd, fib.macro_offset, SEEK_SET) != (int64_t)fib.macro_offset) {
		cli_dbgmsg("lseek macro_offset failed\n");
		close(fd);
		return NULL;
	}
	
	end_offset = fib.macro_offset + fib.macro_len;
	
	if (cli_readn(fd, &start_id, 1) != 1) {
		cli_dbgmsg("read start_id failed\n");
		close(fd);
		return NULL;
	}
	cli_dbgmsg("start_id: %d\n", start_id);
	
	while ((lseek(fd, 0, SEEK_CUR) < end_offset) && !done) {
		if (cli_readn(fd, &info_id, 1) != 1) {
			cli_dbgmsg("read macro_info failed\n");
			close(fd);
			return NULL;
		}
		switch (info_id) {
			case 0x01:
				macro_info = wm_read_macro_info(fd);
				if (macro_info == NULL) {
					done = TRUE;
				}
				break;
			case 0x03:
				if (!wm_read_oxo3(fd)) {
					done = TRUE;
				}
				break;
			case 0x05:
				menu_info = wm_read_menu_info(fd);
				if (menu_info == NULL) {
					done = TRUE;
				}
				break;
			case 0x10:
				macro_extnames = wm_read_macro_extnames(fd);
				if (macro_extnames == NULL) {
					done = TRUE;
				}
				break;
			case 0x11:
				macro_intnames = wm_read_macro_intnames(fd);
				if (macro_intnames == NULL) {
					done = TRUE;
				}				
				break;
			case 0x12:
				/* No sure about these, always seems to
				come after the macros though, so finish
				*/
				done = 1;
				break;
			case 0x40:
				/* end marker */
				done = 1;
				break;
			default:
				cli_dbgmsg("\nunknown type: 0x%x\n", info_id);
				done = 1;
		}
	}
	
	if (macro_info) {
		vba_project = (vba_project_t *) cli_malloc(sizeof(struct vba_project_tag));
		if (!vba_project) {
			goto abort;
		}
		vba_project->name = (char **) cli_malloc(sizeof(char *) *macro_info->count);
		if (!vba_project->name) {
			free(vba_project);
			vba_project = NULL;
			goto abort;
		}
		vba_project->dir = strdup(dir);
		vba_project->offset = (uint32_t *) cli_malloc(sizeof(uint32_t) *
					macro_info->count);
		if (!vba_project->offset) {
			free(vba_project->name);
			free(vba_project->dir);
			free(vba_project);
			vba_project = NULL;
			goto abort;
		}
		vba_project->length = (uint32_t *) cli_malloc(sizeof(uint32_t) *
					macro_info->count);
		if (!vba_project->length) {
			free(vba_project->offset);
			free(vba_project->name);
			free(vba_project->dir);
			free(vba_project);
			vba_project = NULL;
			goto abort;
		}
		vba_project->key = (unsigned char *) cli_malloc(sizeof(unsigned char) *
					macro_info->count);
		if (!vba_project->key) {
			free(vba_project->length);
			free(vba_project->offset);
			free(vba_project->name);
			free(vba_project->dir);
			free(vba_project);
			vba_project = NULL;
			goto abort;
		}
		vba_project->count = macro_info->count;
		for (i=0 ; i < macro_info->count ; i++) {
			vba_project->name[i] = strdup("WordDocument");
			vba_project->offset[i] = macro_info->macro_entry[i].offset;
			vba_project->length[i] = macro_info->macro_entry[i].len;
			vba_project->key[i] = macro_info->macro_entry[i].key;
		}
	}
	/* Fall through */
abort:
	if (macro_info) {
		wm_free_macro_info(macro_info);
	}
	if (menu_info) {
		wm_free_menu_info(menu_info);
	}
	if (macro_extnames) {
		wm_free_extnames(macro_extnames);
	}
	if (macro_intnames) {
		wm_free_intnames(macro_intnames);
	}
	close(fd);
	return vba_project;
}

unsigned char *wm_decrypt_macro(int fd, uint32_t offset, uint32_t len,
					unsigned char key)
{
	unsigned char *buff;
	uint32_t i;
	
	if (lseek(fd, offset, SEEK_SET) != (int64_t)offset) {
		return NULL;
	}
	buff = (unsigned char *) cli_malloc(len);
	if (!buff) {
		return NULL;
	}

	if (cli_readn(fd, buff, len) != (int64_t)len) {
		free(buff);
		return NULL;
	}
	if (key != 0) {
		for (i=0 ; i < len; i++) {
			buff[i] = buff[i] ^ key;
		}
	}
	return buff;
}

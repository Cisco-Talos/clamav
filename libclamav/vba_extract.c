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
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */
#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <string.h>
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <ctype.h>
#include <zlib.h>

#include "clamav.h"

#include "vba_extract.h"
#include "others.h"
#ifdef  CL_DEBUG
#include "mbox.h"
#endif
#include "blob.h"

#ifndef	O_BINARY
#define	O_BINARY	0
#endif

#ifndef HAVE_ATTRIB_PACKED
#define __attribute__(x)
#endif

#define PPT_LZW_BUFFSIZE 8192
#define NUM_VBA_VERSIONS 14
#define VBA_COMPRESSION_WINDOW 4096

#ifdef HAVE_PRAGMA_PACK
#pragma pack(1)
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack 1
#endif

struct vba56_header {
	unsigned char magic[2];
	unsigned char version[4];
	uint16_t ooff __attribute__ ((packed));	/* 0x00FF */
	uint32_t LidA __attribute__ ((packed));  /* Language identifiers */
	uint32_t LidB __attribute__ ((packed));
	uint16_t CharSet __attribute__ ((packed));
	uint16_t LenA __attribute__ ((packed));
	uint32_t UnknownB __attribute__ ((packed));
	uint32_t UnknownC __attribute__ ((packed));
	uint16_t LenB __attribute__ ((packed));
	uint16_t LenC __attribute__ ((packed));
	uint16_t LenD __attribute__ ((packed));
};

#ifdef HAVE_PRAGMA_PACK
#pragma pack()
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack
#endif

typedef struct vba_version_tag {
	unsigned char signature[4];
	const char *name;
	int is_mac;
} vba_version_t;

static uint16_t vba_endian_convert_16(uint16_t value, int is_mac)
{
	if (is_mac)
		return (uint16_t)be16_to_host(value);
	else
		return le16_to_host(value);
}

static uint32_t vba_endian_convert_32(uint32_t value, int is_mac)
{
	if (is_mac)
		return be32_to_host(value);
	else
		return le32_to_host(value);
}

static const vba_version_t vba_version[NUM_VBA_VERSIONS] = {
	{ { 0x5e, 0x00, 0x00, 0x01 }, "Office 97",              FALSE},
	{ { 0x5f, 0x00, 0x00, 0x01 }, "Office 97 SR1",          FALSE },
	{ { 0x65, 0x00, 0x00, 0x01 }, "Office 2000 alpha?",     FALSE },
	{ { 0x6b, 0x00, 0x00, 0x01 }, "Office 2000 beta?",      FALSE },
	{ { 0x6d, 0x00, 0x00, 0x01 }, "Office 2000",            FALSE },
	{ { 0x6f, 0x00, 0x00, 0x01 }, "Office 2000",            FALSE },
	{ { 0x70, 0x00, 0x00, 0x01 }, "Office XP beta 1/2",     FALSE },
	{ { 0x73, 0x00, 0x00, 0x01 }, "Office XP",              FALSE },
	{ { 0x76, 0x00, 0x00, 0x01 }, "Office 2003",            FALSE },
	{ { 0x79, 0x00, 0x00, 0x01 }, "Office 2003",            FALSE },
	{ { 0x60, 0x00, 0x00, 0x0e }, "MacOffice 98",           TRUE },
	{ { 0x62, 0x00, 0x00, 0x0e }, "MacOffice 2001",         TRUE },
	{ { 0x63, 0x00, 0x00, 0x0e }, "MacOffice X",		TRUE },
	{ { 0x64, 0x00, 0x00, 0x0e }, "MacOffice 2004",         TRUE },
};

static char *
get_unicode_name(const char *name, int size, int is_mac)
{
        int i, increment;
        char *newname, *ret;

	if((name == NULL) || (*name == '\0') || (size <= 0))
                return NULL;

        newname = (char *)cli_malloc(size * 7);
        if(newname == NULL)
                return NULL;

	if((!is_mac) && (size & 0x1)) {
		cli_dbgmsg("get_unicode_name: odd number of bytes %d\n", size);
		--size;
	}

	increment = (is_mac) ? 1 : 2;
	ret = newname;

        for(i = 0; i < size; i += increment) {
                if(isprint(name[i]))
                        *ret++ = name[i];
                else {
			if(name[i] < 10 && name[i] >= 0) {
				*ret++ = '_';
				*ret++ = (char)(name[i] + '0');
			} else {
				const uint16_t x = (uint16_t)(((name[i]) << 8) | name[i + 1]);

				*ret++ = '_';
				*ret++ = (char)('a'+((x&0xF)));
				*ret++ = (char)('a'+((x>>4)&0xF));
				*ret++ = (char)('a'+((x>>8)&0xF));
#if	0
				*ret++ = (char)('a'+((x>>16)&0xF));	/* FIXME: x>>16 MUST == 0 */
				*ret++ = (char)('a'+((x>>24)&0xF));	/* FIXME: x>>24 MUST == 0 */
#endif
			}
			*ret++ = '_';
		}
	}

        *ret = '\0';
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

	if(cli_readn(fd, &test_middle, 20) != 20) {
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

static int
vba_read_project_strings(int fd, int is_mac)
{
	for (;;) {
		uint32_t offset;
		uint16_t length;
		unsigned char *buff;
		char *name;

		if (cli_readn(fd, &length, 2) != 2) {
			return FALSE;
		}
		length = vba_endian_convert_16(length, is_mac);
		if (length < 6) {
			lseek(fd, -2, SEEK_CUR);
			break;
		}
		buff = (unsigned char *) cli_malloc(length);
		if (!buff) {
			cli_errmsg("cli_malloc failed\n");
			return FALSE;
		}
		offset = lseek(fd, 0, SEEK_CUR);

		if (cli_readn(fd, buff, length) != (int)length) {
			cli_dbgmsg("read name failed - rewinding\n");
			lseek(fd, offset, SEEK_SET);
			free(buff);
			break;
		}
		name = get_unicode_name((const char *)buff, length, is_mac);
		if (name)
			cli_dbgmsg("length: %d, name: %s\n", length, name);
		else
			cli_dbgmsg("length: %d, name: [null]\n", length);
		free(buff);

		/* Ignore twelve bytes from entries of type 'G'.
		   Type 'C' entries come in pairs, the second also
		   having a 12 byte trailer */
		/* TODO: Need to check if types H(same as G) and D(same as C) exist */
		if((name == NULL) || (memcmp("*\\", name, 2) != 0) ||
		   (strchr("GCHD", name[2]) == NULL)) {
			/* Unknown type - probably ran out of strings - rewind */
			lseek(fd, -(length+2), SEEK_CUR);
			if(name)
				free(name);
			break;
		}
		free(name);

		if (cli_readn(fd, &length, 2) != 2)
			return FALSE;

		length = vba_endian_convert_16(length, is_mac);
		if ((length != 0) && (length != 65535)) {
			lseek(fd, -2, SEEK_CUR);
			continue;
		}
		offset = lseek(fd, 10, SEEK_CUR);
		cli_dbgmsg("offset: %u\n", offset);
		vba56_test_middle(fd);
	}
	return TRUE;
}

vba_project_t *vba56_dir_read(const char *dir)
{
	unsigned char *buff;
	const unsigned char vba56_signature[] = { 0xcc, 0x61 };
	uint16_t record_count, length;
	uint16_t ffff;
	uint16_t byte_count;
	uint32_t offset;
	int i, fd, is_mac;
	vba_project_t *vba_project;
	struct vba56_header v56h;
	char fullname[NAME_MAX + 1];

	cli_dbgmsg("in vba56_dir_read()\n");

	snprintf(fullname, sizeof(fullname) - 1, "%s/_VBA_PROJECT", dir);
        fd = open(fullname, O_RDONLY|O_BINARY);

        if (fd == -1) {
                cli_dbgmsg("Can't open %s\n", fullname);
		/* vba56_old_dir_read(dir); */
                return NULL;
        }

	if(cli_readn(fd, &v56h, sizeof(struct vba56_header)) != sizeof(struct vba56_header)) {
		close(fd);
		return NULL;
	}
	if (memcmp(v56h.magic, vba56_signature, sizeof(v56h.magic)) != 0) {
		close(fd);
		return NULL;
	}

	for(i = 0; i < NUM_VBA_VERSIONS; i++)
		if(memcmp(v56h.version, vba_version[i].signature, sizeof(vba_version[i].signature)) == 0)
			break;

	if (i == NUM_VBA_VERSIONS) {
		cli_warnmsg("Unknown VBA version signature %x %x %x %x\n",
			v56h.version[0], v56h.version[1],
			v56h.version[2], v56h.version[3]);
		switch(v56h.version[3]) {
			case 0x01:
				cli_warnmsg("Guessing little-endian\n");
				is_mac = FALSE;
				break;
			case 0x0E:
				cli_warnmsg("Guessing big-endian\n");
				is_mac = TRUE;
				break;
			default:
				cli_warnmsg("Unable to guess VBA type\n");
				close(fd);
				return NULL;
		}
	} else {
		cli_dbgmsg("VBA Project: %s\n", vba_version[i].name);
		is_mac = vba_version[i].is_mac;
	}

	if (!vba_read_project_strings(fd, is_mac)) {
		close(fd);
		return NULL;
	}

	/* junk some more stuff */
	do {
		if (cli_readn(fd, &ffff, 2) != 2) {
			close(fd);
			return NULL;
		}
	} while(ffff != 0xFFFF);

	/* check for alignment error */
	lseek(fd, -3, SEEK_CUR);
	if (cli_readn(fd, &ffff, 2) != 2) {
		close(fd);
		return NULL;
	}
	if (ffff != 0xFFFF) {
		lseek(fd, 1, SEEK_CUR);
	}

	if (cli_readn(fd, &ffff, 2) != 2) {
		close(fd);
		return NULL;
	}

	/* no idea what this stuff is */
	if (ffff != 0xFFFF) {
		ffff = vba_endian_convert_16(ffff, is_mac);
		lseek(fd, ffff, SEEK_CUR);
	}
	if (cli_readn(fd, &ffff, 2) != 2) {
		close(fd);
		return NULL;
	}
	if (ffff != 0xFFFF) {
		ffff = vba_endian_convert_16(ffff, is_mac);
		lseek(fd, ffff, SEEK_CUR);
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
	vba_project->dir = cli_strdup(dir);
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
	for(i = 0; i < record_count; i++) {
		if(cli_readn(fd, &length, 2) != 2)
			break;

		length = vba_endian_convert_16(length, is_mac);
		if (length == 0) {
			cli_dbgmsg("zero name length\n");
			break;
		}
		buff = (unsigned char *) cli_malloc(length);
		if (!buff) {
			cli_dbgmsg("cli_malloc failed\n");
			break;
		}
		if (cli_readn(fd, buff, length) != length) {
			cli_dbgmsg("read name failed\n");
			free(buff);
			break;
		}
		vba_project->name[i] = get_unicode_name((const char *)buff, length, is_mac);
		free(buff);
		if (!vba_project->name[i]) {
			offset = lseek(fd, 0, SEEK_CUR);
			vba_project->name[i] = (char *) cli_malloc(18);
			if(vba_project->name[i] == NULL) {
				break;
			}
			snprintf(vba_project->name[i], 18, "clamav-%.10d", (int)offset);
		}
		cli_dbgmsg("project name: %s, ", vba_project->name[i]);

		/* some kind of string identifier ?? */
		if (cli_readn(fd, &length, 2) != 2) {
			free(vba_project->name[i]);
			break;
		}
		length = vba_endian_convert_16(length, is_mac);
		lseek(fd, length, SEEK_CUR);

		/* unknown stuff */
		if (cli_readn(fd, &ffff, 2) != 2) {
			free(vba_project->name[i]);
			break;
		}
		ffff = vba_endian_convert_16(ffff, is_mac);
		if (ffff == 0xFFFF) {
			lseek(fd, 2, SEEK_CUR);
			if (cli_readn(fd, &ffff, 2) != 2) {
				free(vba_project->name[i]);
				break;
			}
			ffff = vba_endian_convert_16(ffff, is_mac);
			lseek(fd, ffff, SEEK_CUR);
		} else {
			lseek(fd, 2 + ffff, SEEK_CUR);
		}

		lseek(fd, 8, SEEK_CUR);
		if (cli_readn(fd, &byte_count, 2) != 2) {
			free(vba_project->name[i]);
			break;
		}
		byte_count = vba_endian_convert_16(byte_count, is_mac);
		lseek(fd, (8 * byte_count) + 5, SEEK_CUR);
		if (cli_readn(fd, &offset, 4) != 4) {
			free(vba_project->name[i]);
			break;
		}
		offset = vba_endian_convert_32(offset, is_mac);
		vba_project->offset[i] = offset;
		cli_dbgmsg("offset:%u\n", offset);
		lseek(fd, 2, SEEK_CUR);
	}

	close(fd);

	if(i < record_count) {
		/* above loop failed */
		while(--i >= 0)
			free(vba_project->name[i]);

		free(vba_project->name);
		free(vba_project->dir);
		free(vba_project->offset);
		free(vba_project);
		return NULL;
	}

	return vba_project;
}

unsigned char *vba_decompress(int fd, uint32_t offset, int *size)
{
	unsigned int i, pos=0, shift, win_pos, clean=TRUE, mask, distance;
	uint8_t flag;
	uint16_t token, len;
	size_t s;
	blob *b;
	unsigned char *ret;
	unsigned char buffer[VBA_COMPRESSION_WINDOW];

	b = blobCreate();

	if(b == NULL)
		return NULL;

	lseek(fd, offset+3, SEEK_SET); /* 1byte ?? , 2byte length ?? */

	while (cli_readn(fd, &flag, 1) == 1) {
		for (mask = 1; mask < 0x100; mask<<=1) {
			if (flag & mask) {
				if (cli_readn(fd, &token, 2) != 2) {
					blobDestroy(b);
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
				len = (uint16_t)((token & ((1 << shift) -1)) + 3);
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
						blobDestroy(b);
						if(size)
						       *size = 0;
						return NULL;
					}
					clean = FALSE;
					(void)blobAddData(b, buffer, VBA_COMPRESSION_WINDOW);
					break;
				}
				if (cli_readn(fd, buffer+(pos%VBA_COMPRESSION_WINDOW), 1) == 1){
					pos++;
				}
				clean = TRUE;
			}
		}
	}

	if (pos % VBA_COMPRESSION_WINDOW)
		if(blobAddData(b, buffer, pos%VBA_COMPRESSION_WINDOW) < 0) {
			if(size)
			       *size = 0;
			blobDestroy(b);
			return NULL;
		}
	s = blobGetDataSize(b);
	ret = cli_malloc(s);
	if(ret == NULL) {
		blobDestroy(b);
		if(size)
		       *size = 0;
		return NULL;
	}
	if(size)
		*size = (int)s;
	memcpy(ret, blobGetData(b), s);
	blobDestroy(b);
	return ret;
}

static uint32_t ole_copy_file_data(int ifd, int ofd, uint32_t len)
{
        unsigned int count, rem;
        unsigned char data[FILEBUFF];

        rem = len;

        while (rem > 0) {
                unsigned int todo = MIN(sizeof(data), rem);

                count = cli_readn(ifd, data, todo);
                if (count != todo) {
                        return len-rem;
                }
                if((unsigned int)cli_writen(ofd, data, count) != count)
                        return len-rem-count;
                rem -= count;
        }
        return len;
}

int cli_decode_ole_object(int fd, const char *dir)
{
	int ofd;
	struct stat statbuf;
	char ch;
	uint32_t object_size;
	char fullname[NAME_MAX + 1];

	if (fstat(fd, &statbuf) == -1) {
		return -1;
	}

	if (cli_readn(fd, &object_size, 4) != 4) {
		return -1;
	}
	object_size = vba_endian_convert_32(object_size, FALSE);

	if ((statbuf.st_size -  object_size) >= 4) {
		/* Probably the OLE type id */
		if (lseek(fd, 2, SEEK_CUR) == -1) {
			return -1;
		}

		/* Skip attachment name */
		do {
			if (cli_readn(fd, &ch, 1) != 1) {
				return -1;
			}
		} while (ch);

		/* Skip attachment full path */
		do {
			if (cli_readn(fd, &ch, 1) != 1) {
				return -1;
			}
		} while (ch);

		/* Skip unknown data */
		if (lseek(fd, 8, SEEK_CUR) == -1) {
			return -1;
		}

		/* Skip attachment full path */
		do {
			if (cli_readn(fd, &ch, 1) != 1) {
				return -1;
			}
		} while (ch);

		if (cli_readn(fd, &object_size, 4) != 4) {
			return -1;
		}
		object_size = vba_endian_convert_32(object_size, FALSE);
	}
	snprintf(fullname, sizeof(fullname) - 1, "%s/_clam_ole_object", dir);
	ofd = open(fullname, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, 0600);
	if (ofd < 0) {
		return -1;
	}
	ole_copy_file_data(fd, ofd, object_size);
	lseek(ofd, 0, SEEK_SET);
	return ofd;
}

/* +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */
/* Code to extract Power Point Embedded OLE2 Objects		     */
/* +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ */

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
	atom_header->version = (uint8_t)(atom_header->ver_inst & 0x000f);
	atom_header->instance = (uint16_t)(atom_header->ver_inst >> 4);
	if(cli_readn(fd, &atom_header->type, sizeof(uint16_t)) != sizeof(uint16_t)) {
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

static int ppt_unlzw(const char *dir, int fd, uint32_t length)
{
	int ofd, retval;
	unsigned char inbuff[PPT_LZW_BUFFSIZE], outbuff[PPT_LZW_BUFFSIZE];
	uint32_t bufflen;
	z_stream stream;
	char fullname[NAME_MAX + 1];

	snprintf(fullname, sizeof(fullname) - 1, "%s/ppt%.8lx.doc",
		dir, (long)lseek(fd, 0L, SEEK_CUR));

	ofd = open(fullname, O_WRONLY|O_CREAT|O_TRUNC|O_BINARY, 0600);
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
		unlink(fullname);
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
	return close(ofd);
}

static char *ppt_stream_iter(int fd)
{
	uint32_t ole_id;
	char *out_dir;
	off_t offset;
	atom_header_t atom_header;

	/* Create a directory to store the extracted OLE2 objects */
	out_dir = cli_gentemp(NULL);
	if(mkdir(out_dir, 0700)) {
		cli_errmsg("ScanOLE2 -> Can't create temporary directory %s\n", out_dir);
		free(out_dir);
		return NULL;
	}

	while(ppt_read_atom_header(fd, &atom_header)) {
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
					(int)ole_id, (int)atom_header.length-4);
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
	char *out_dir;
	int fd;
	char fullname[NAME_MAX + 1];

	snprintf(fullname, sizeof(fullname) - 1, "%s/PowerPoint Document", dir);
	fd = open(fullname, O_RDONLY|O_BINARY);
	if (fd == -1) {
		cli_dbgmsg("Open PowerPoint Document failed\n");
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
	char ununsed[sizeof(uint16_t) + sizeof(uint16_t) +
		sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint16_t) +
		sizeof(uint16_t)];
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

static	void	wm_free_macro_info(macro_info_t *macro_info);

static void wm_print_fib(mso_fib_t *fib)
{
	cli_dbgmsg("macro offset: 0x%.4x\n", fib->macro_offset);
	cli_dbgmsg("macro len: 0x%.4x\n\n", fib->macro_len);
}

static int wm_read_fib(int fd, mso_fib_t *fib)
{
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
			wm_free_macro_info(macro_info);
			return NULL;
		}
	}
	return macro_info;
}

static	void
wm_free_macro_info(macro_info_t *macro_info)
{
	if (macro_info) {
		free(macro_info->macro_entry);
		free(macro_info);
	}
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

static int
wm_skip_menu_info(int fd)
{
	uint16_t count;

	if (cli_readn(fd, &count, sizeof(uint16_t)) != sizeof(uint16_t)) {
		cli_dbgmsg("read menu_info failed\n");
		return FALSE;
	}
	count = vba_endian_convert_16(count, FALSE);
	cli_dbgmsg("menu_info count: %d\n", count);

	if(count)
		if(lseek(fd, count * 12, SEEK_CUR) == -1)
			return FALSE;
	return TRUE;
}

static int
wm_skip_macro_extnames(int fd)
{
	int is_unicode;
	int16_t size;
	off_t offset_end = lseek(fd, 0, SEEK_CUR);

	if(cli_readn(fd, &size, sizeof(int16_t)) != sizeof(int16_t)) {
		cli_dbgmsg("read macro_extnames failed\n");
		return FALSE;
	}
	size = vba_endian_convert_16(size, FALSE);
	if (size == -1) { /* Unicode flag */
		if(cli_readn(fd, &size, sizeof(int16_t)) != sizeof(int16_t)) {
			cli_dbgmsg("read macro_extnames failed\n");
			return FALSE;
		}
		size = vba_endian_convert_16(size, FALSE);
		is_unicode = 1;
	} else
		is_unicode = 0;

	cli_dbgmsg("ext names size: 0x%x\n", size);

	offset_end += size;
	while(lseek(fd, 0, SEEK_CUR) < offset_end) {
		uint8_t length;
		off_t offset;

		if (cli_readn(fd, &length, 1) != 1) {
			cli_dbgmsg("read macro_extnames failed\n");
			return FALSE;
		}

		if(is_unicode)
			offset = (off_t)length * 2 + 1;
		else
			offset = (off_t)length;

		offset += sizeof(uint16_t);	/* numref */
		if(lseek(fd, offset, SEEK_CUR) == -1) {
			cli_dbgmsg("read macro_extnames failed to seek\n");
			return FALSE;
		}
	}
	return TRUE;
}

static int
wm_skip_macro_intnames(int fd)
{
	uint16_t i, count;

	if (cli_readn(fd, &count, sizeof(uint16_t)) != sizeof(uint16_t)) {
		cli_dbgmsg("read macro_intnames failed\n");
		return FALSE;
	}
	count = vba_endian_convert_16(count, FALSE);
	cli_dbgmsg("int names count: %u\n", count);

	for(i = 0; i < count; i++) {
		uint8_t length;

		/* id */
		if(lseek(fd, sizeof(uint16_t), SEEK_CUR) == -1) {
			cli_dbgmsg("skip_macro_intnames failed\n");
			return FALSE;
		}

		if(cli_readn(fd, &length, sizeof(uint8_t)) != sizeof(uint8_t)) {
			cli_dbgmsg("skip_macro_intnames failed\n");
			return FALSE;
		}

		/* Internal name, plus one byte of unknown data */
		if(lseek(fd, length + 1, SEEK_CUR) == -1) {
			cli_dbgmsg("skip_macro_intnames failed\n");
			return FALSE;
		}
	}
	return TRUE;
}

vba_project_t *wm_dir_read(const char *dir)
{
	int fd, done;
	off_t end_offset;
	unsigned char info_id;
	macro_info_t *macro_info=NULL;
	vba_project_t *vba_project;
	mso_fib_t fib;
	char fullname[NAME_MAX + 1];

	snprintf(fullname, sizeof(fullname) - 1, "%s/WordDocument", dir);
	fd = open(fullname, O_RDONLY|O_BINARY);
	if (fd == -1) {
		cli_dbgmsg("Open WordDocument failed\n");
		return NULL;
	}

	if (!wm_read_fib(fd, &fib)) {
		close(fd);
		return NULL;
	}
	if(fib.macro_len == 0) {
		cli_dbgmsg("No macros detected\n");
		/* Must be clean */
		close(fd);
		return NULL;
	}
	wm_print_fib(&fib);

	/* Go one past the start to ignore start_id */
	if (lseek(fd, fib.macro_offset + 1, SEEK_SET) != (off_t)(fib.macro_offset + 1)) {
		cli_dbgmsg("lseek macro_offset failed\n");
		close(fd);
		return NULL;
	}

	end_offset = fib.macro_offset + fib.macro_len;
	done = FALSE;

	while ((lseek(fd, 0, SEEK_CUR) < end_offset) && !done) {
		if (cli_readn(fd, &info_id, 1) != 1) {
			cli_dbgmsg("read macro_info failed\n");
			close(fd);
			return NULL;
		}
		switch (info_id) {
			case 0x01:
				if(macro_info)
					wm_free_macro_info(macro_info);
				macro_info = wm_read_macro_info(fd);
				if(macro_info == NULL)
					done = TRUE;
				break;
			case 0x03:
				if(!wm_read_oxo3(fd))
					done = TRUE;
				break;
			case 0x05:
				if(!wm_skip_menu_info(fd))
					done = TRUE;
				break;
			case 0x10:
				if(!wm_skip_macro_extnames(fd))
					done = TRUE;
				break;
			case 0x11:
				if(!wm_skip_macro_intnames(fd))
					done = TRUE;
				break;
			case 0x12:
				/* No sure about these, always seems to
				come after the macros though, so finish
				*/
				done = TRUE;
				break;
			case 0x40:
				/* end marker */
				done = TRUE;
				break;
			default:
				cli_dbgmsg("unknown type: 0x%x\n", info_id);
				done = TRUE;
		}
	}

	close(fd);

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
		vba_project->dir = cli_strdup(dir);
		vba_project->offset = (uint32_t *) cli_malloc(sizeof(uint32_t) *
					macro_info->count);
		if (!vba_project->offset) {
			free(vba_project->name);
			if(vba_project->dir)
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
		} else {
			int i;

			vba_project->count = macro_info->count;
			for(i = 0; i < macro_info->count; i++) {
				vba_project->name[i] = cli_strdup("WordDocument");
				vba_project->offset[i] = macro_info->macro_entry[i].offset;
				vba_project->length[i] = macro_info->macro_entry[i].len;
				vba_project->key[i] = macro_info->macro_entry[i].key;
			}
		}
abort:
		wm_free_macro_info(macro_info);
		/* Fall through */
	} else
		vba_project = NULL;

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

	if (cli_readn(fd, buff, len) != (int)len) {
		free(buff);
		return NULL;
	}
	if (key != 0)
		for (i=0 ; i < len; i++)
			buff[i] ^= key;
	return buff;
}

/*
 *  Extract VBA source code for component MS Office Documents
 *
 *  Copyright (C) 2007-2008 Sourcefire, Inc.
 *
 *  Authors: Trog, Nigel Horne
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
#include <string.h>
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#include <stdlib.h>
#include <ctype.h>
#include <zlib.h>

#include "clamav.h"

#include "others.h"
#include "vba_extract.h"
#ifdef	CL_DEBUG
#include "mbox.h"
#endif
#include "blob.h"

#ifndef	O_BINARY
#define	O_BINARY	0
#endif

#define PPT_LZW_BUFFSIZE 8192
#define VBA_COMPRESSION_WINDOW 4096
#define	MIDDLE_SIZE	20
#define	MAX_VBA_COUNT	1000	/* If there's more than 1000 macros something's up! */

#ifndef HAVE_ATTRIB_PACKED
#define __attribute__(x)
#endif

/*
 * VBA (Visual Basic for Applications), versions 5 and 6
 */
struct vba56_header {
	unsigned char magic[2];
	unsigned char version[4];
	unsigned char ignore[28];
};

typedef struct {
	uint32_t sig;
	const char *ver;
	int	big_endian;	/* e.g. MAC Office */
} vba_version_t;

static const vba_version_t vba_versions[] = {
	{ 0x0100005e, "97",             FALSE },
	{ 0x0100005f, "97 SR1",         FALSE },
	{ 0x01000065, "2000 alpha",	FALSE },
	{ 0x0100006b, "2000 beta",	FALSE },
	{ 0x0100006d, "2000",           FALSE },
	{ 0x0100006f, "2000",           FALSE },
	{ 0x01000070, "XP beta 1/2",	FALSE },
	{ 0x01000073, "XP",             FALSE },
	{ 0x01000073, "2003",           FALSE },
	{ 0x01000079, "2003",           FALSE },
	{ 0x0e000060, "98",		TRUE  },
	{ 0x0e000062, "2001",		TRUE  },
	{ 0x0e000063, "X",		TRUE  },
	{ 0x0e000064, "2004",		TRUE  },
	{ 0x00000000, NULL,		FALSE },
};

static	int	skip_past_nul(int fd);
static	int	read_uint16(int fd, uint16_t *u, int big_endian);
static	int	read_uint32(int fd, uint32_t *u, int big_endian);
static	int	seekandread(int fd, off_t offset, int whence, void *data, size_t len);
static	vba_project_t	*create_vba_project(int record_count, const char *dir);

static uint16_t
vba_endian_convert_16(uint16_t value, int big_endian)
{
	if (big_endian)
		return (uint16_t)be16_to_host(value);
	else
		return le16_to_host(value);
}

/* Seems to be a duplicate of riff_endian_convert_32() */
static uint32_t
vba_endian_convert_32(uint32_t value, int big_endian)
{
	if (big_endian)
		return be32_to_host(value);
	else
		return le32_to_host(value);
}

static char *
get_unicode_name(const char *name, int size, int big_endian)
{
	int i, increment;
	char *newname, *ret;

	if((name == NULL) || (*name == '\0') || (size <= 0))
		return NULL;

	newname = (char *)cli_malloc(size * 7);
	if(newname == NULL)
		return NULL;

	if((!big_endian) && (size & 0x1)) {
		cli_dbgmsg("get_unicode_name: odd number of bytes %d\n", size);
		--size;
	}

	increment = (big_endian) ? 1 : 2;
	ret = newname;

	for(i = 0; i < size; i += increment) {
		if(isprint(name[i]))
			*ret++ = name[i];
		else {
			if((name[i] < 10) && (name[i] >= 0)) {
				*ret++ = '_';
				*ret++ = (char)(name[i] + '0');
			} else {
				const uint16_t x = (uint16_t)((name[i] << 8) | name[i + 1]);

				*ret++ = '_';
				*ret++ = (char)('a'+((x&0xF)));
				*ret++ = (char)('a'+((x>>4)&0xF));
				*ret++ = (char)('a'+((x>>8)&0xF));
				*ret++ = 'a';
				*ret++ = 'a';
			}
			*ret++ = '_';
		}
	}

	*ret = '\0';

	/* Saves a lot of memory */
	ret = cli_realloc(newname, (ret - newname) + 1);
	return ret ? ret : newname;
}


static void vba56_test_middle(int fd)
{
	char test_middle[MIDDLE_SIZE];

	/* MacOffice middle */
	static const uint8_t middle1_str[MIDDLE_SIZE] = {
		0x00, 0x01, 0x0d, 0x45, 0x2e, 0xe1, 0xe0, 0x8f, 0x10, 0x1a,
		0x85, 0x2e, 0x02, 0x60, 0x8c, 0x4d, 0x0b, 0xb4, 0x00, 0x00
	};
	/* MS Office middle */
	static const uint8_t middle2_str[MIDDLE_SIZE] = {
		0x00, 0x00, 0xe1, 0x2e, 0x45, 0x0d, 0x8f, 0xe0, 0x1a, 0x10,
		0x85, 0x2e, 0x02, 0x60, 0x8c, 0x4d, 0x0b, 0xb4, 0x00, 0x00
	};

	if(cli_readn(fd, &test_middle, MIDDLE_SIZE) != MIDDLE_SIZE)
		return;

	if((memcmp(test_middle, middle1_str, MIDDLE_SIZE) != 0) &&
	   (memcmp(test_middle, middle2_str, MIDDLE_SIZE) != 0)) {
		cli_dbgmsg("middle not found\n");
		lseek(fd, -MIDDLE_SIZE, SEEK_CUR);
	} else
		cli_dbgmsg("middle found\n");
}

static int
vba_read_project_strings(int fd, int big_endian)
{
	unsigned char *buf = NULL;
	uint16_t buflen = 0;

	for(;;) {
		off_t offset;
		uint16_t length;
		char *name;

		if(!read_uint16(fd, &length, big_endian)) {
			if(buf)
				free(buf);
			return FALSE;
		}
		if (length < 6) {
			lseek(fd, -2, SEEK_CUR);
			break;
		}
		if(length > buflen) {
			unsigned char *newbuf = (unsigned char *)cli_realloc(buf, length);
			if(newbuf == NULL) {
				if(buf)
					free(buf);
				return FALSE;
			}
			buflen = length;
			buf = newbuf;
		}

		offset = lseek(fd, 0, SEEK_CUR);

		if(cli_readn(fd, buf, length) != (int)length) {
			cli_dbgmsg("read name failed - rewinding\n");
			lseek(fd, offset, SEEK_SET);
			break;
		}
		name = get_unicode_name((const char *)buf, length, big_endian);
		cli_dbgmsg("length: %d, name: %s\n", length, (name) ? name : "[null]");

		if((name == NULL) || (memcmp("*\\", name, 2) != 0) ||
		   (strchr("GCHD", name[2]) == NULL)) {
			/* Not a string */
			lseek(fd, -(length+2), SEEK_CUR);
			if(name)
				free(name);
			break;
		}
		free(name);

		if(!read_uint16(fd, &length, big_endian)) {
			if(buf)
				free(buf);
			return FALSE;
		}

		if ((length != 0) && (length != 65535)) {
			lseek(fd, -2, SEEK_CUR);
			continue;
		}
		offset = lseek(fd, 10, SEEK_CUR);
		cli_dbgmsg("offset: %lu\n", (unsigned long)offset);
		vba56_test_middle(fd);
	}
	if(buf)
		free(buf);
	return TRUE;
}

vba_project_t *
cli_vba_readdir(const char *dir)
{
	unsigned char *buf;
	const unsigned char vba56_signature[] = { 0xcc, 0x61 };
	uint16_t record_count, buflen, ffff, byte_count;
	uint32_t offset, sig;
	int i, fd, big_endian;
	vba_project_t *vba_project;
	const vba_version_t *v;
	struct vba56_header v56h;
	char fullname[NAME_MAX + 1];

	cli_dbgmsg("in cli_vba_readdir()\n");

	if(dir == NULL)
		return NULL;

	/*
	 * _VBA_PROJECT files are embedded within office documents (OLE2)
	 */
	snprintf(fullname, sizeof(fullname) - 1, "%s/_VBA_PROJECT", dir);
	fd = open(fullname, O_RDONLY|O_BINARY);

	if(fd == -1) {
		cli_dbgmsg("Can't open %s\n", fullname);
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

	sig = cli_readint32(v56h.version);
	for(v = vba_versions; v->sig; v++)
		if(v->sig == sig)
			break;

	if(!v->sig) {
		cli_warnmsg("Unknown VBA version signature %x %x %x %x\n",
			v56h.version[0], v56h.version[1],
			v56h.version[2], v56h.version[3]);
		switch(v56h.version[3]) {
			case 0x01:
				cli_warnmsg("Guessing little-endian\n");
				big_endian = FALSE;
				break;
			case 0x0E:
				cli_warnmsg("Guessing big-endian\n");
				big_endian = TRUE;
				break;
			default:
				cli_warnmsg("Unable to guess VBA type\n");
				close(fd);
				return NULL;
		}
	} else {
		cli_dbgmsg("VBA Project: %s %s\n", v->big_endian ? "MacOffice" : "Office",  v->ver);
		big_endian = v->big_endian;
	}

	if (!vba_read_project_strings(fd, big_endian)) {
		close(fd);
		return NULL;
	}

	/* junk some more stuff */
	do
		if (cli_readn(fd, &ffff, 2) != 2) {
			close(fd);
			return NULL;
		}
	while(ffff != 0xFFFF);

	/* check for alignment error */
	if(!seekandread(fd, -3, SEEK_CUR, &ffff, sizeof(uint16_t))) {
		close(fd);
		return NULL;
	}
	if (ffff != 0xFFFF)
		lseek(fd, 1, SEEK_CUR);

	if(!read_uint16(fd, &ffff, big_endian)) {
		close(fd);
		return NULL;
	}

	if(ffff != 0xFFFF)
		lseek(fd, ffff, SEEK_CUR);

	if(!read_uint16(fd, &ffff, big_endian)) {
		close(fd);
		return NULL;
	}

	if(ffff == 0xFFFF)
		ffff = 0;

	lseek(fd, ffff + 100, SEEK_CUR);

	if(!read_uint16(fd, &record_count, big_endian)) {
		close(fd);
		return NULL;
	}
	cli_dbgmsg("VBA Record count: %d\n", record_count);
	if (record_count == 0) {
		/* No macros, assume clean */
		close(fd);
		return NULL;
	}
	if (record_count > MAX_VBA_COUNT) {
		/* Almost certainly an error */
		cli_dbgmsg("VBA Record count too big\n");
		close(fd);
		return NULL;
	}

	vba_project = create_vba_project(record_count, dir);
	if(vba_project == NULL) {
		close(fd);
		return NULL;
	}
	buf = NULL;
	buflen = 0;
	for(i = 0; i < record_count; i++) {
		uint16_t length;
		char *ptr;

		if(!read_uint16(fd, &length, big_endian))
			break;

		if (length == 0) {
			cli_dbgmsg("zero name length\n");
			break;
		}
		if(length > buflen) {
			unsigned char *newbuf = (unsigned char *)cli_realloc(buf, length);
			if(newbuf == NULL)
				break;
			buflen = length;
			buf = newbuf;
		}
		if (cli_readn(fd, buf, length) != length) {
			cli_dbgmsg("read name failed\n");
			break;
		}
		ptr = get_unicode_name((const char *)buf, length, big_endian);
		if(ptr == NULL) {
			offset = lseek(fd, 0, SEEK_CUR);
			ptr = (char *)cli_malloc(18);
			if(ptr == NULL)
				break;
			sprintf(ptr, "clamav-%.10d", (int)offset);
		}
		cli_dbgmsg("project name: %s\n", ptr);

		if(!read_uint16(fd, &length, big_endian)) {
			free(ptr);
			break;
		}
		lseek(fd, length, SEEK_CUR);

		if(!read_uint16(fd, &ffff, big_endian)) {
			free(ptr);
			break;
		}
		if (ffff == 0xFFFF) {
			lseek(fd, 2, SEEK_CUR);
			if(!read_uint16(fd, &ffff, big_endian)) {
				free(ptr);
				break;
			}
			lseek(fd, ffff + 8, SEEK_CUR);
		} else
			lseek(fd, ffff + 10, SEEK_CUR);

		if(!read_uint16(fd, &byte_count, big_endian)) {
			free(ptr);
			break;
		}
		lseek(fd, (8 * byte_count) + 5, SEEK_CUR);
		if(!read_uint32(fd, &offset, big_endian)) {
			free(ptr);
			break;
		}
		cli_dbgmsg("offset: %u\n", (unsigned int)offset);
		vba_project->offset[i] = offset;
		vba_project->name[i] = ptr;
		lseek(fd, 2, SEEK_CUR);
	}

	if(buf)
		free(buf);

	close(fd);

	if(i < record_count) {
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

unsigned char *
cli_vba_inflate(int fd, off_t offset, int *size)
{
	unsigned int pos, shift, mask, distance, clean;
	uint8_t flag;
	uint16_t token;
	blob *b;
	unsigned char buffer[VBA_COMPRESSION_WINDOW];

	if(fd < 0)
		return NULL;

	b = blobCreate();

	if(b == NULL)
		return NULL;

	lseek(fd, offset+3, SEEK_SET); /* 1byte ?? , 2byte length ?? */
	clean = TRUE;
	pos = 0;

	while (cli_readn(fd, &flag, 1) == 1) {
		for(mask = 1; mask < 0x100; mask<<=1) {
			unsigned int winpos = pos % VBA_COMPRESSION_WINDOW;
			if (flag & mask) {
				uint16_t len;
				unsigned int srcpos;

				if(!read_uint16(fd, &token, FALSE)) {
					blobDestroy(b);
					if(size)
						*size = 0;
					return NULL;
				}
				shift = 12 - (winpos > 0x10)
						- (winpos > 0x20)
						- (winpos > 0x40)
						- (winpos > 0x80)
						- (winpos > 0x100)
						- (winpos > 0x200)
						- (winpos > 0x400)
						- (winpos > 0x800);
				len = (uint16_t)((token & ((1 << shift) - 1)) + 3);
				distance = token >> shift;

				srcpos = pos - distance - 1;
				if((((srcpos + len) % VBA_COMPRESSION_WINDOW) < winpos) &&
				   ((winpos + len) < VBA_COMPRESSION_WINDOW) &&
				   (((srcpos % VBA_COMPRESSION_WINDOW) + len) < VBA_COMPRESSION_WINDOW) &&
				   (len <= VBA_COMPRESSION_WINDOW)) {
					srcpos %= VBA_COMPRESSION_WINDOW;
					memcpy(&buffer[winpos], &buffer[srcpos],
						len);
					pos += len;
				} else
					while(len-- > 0) {
						srcpos = (pos - distance - 1) % VBA_COMPRESSION_WINDOW;
						buffer[pos++ % VBA_COMPRESSION_WINDOW] = buffer[srcpos];
					}
			} else {
				if((pos != 0) && (winpos == 0) && clean) {
					if (cli_readn(fd, &token, 2) != 2) {
						blobDestroy(b);
						if(size)
							*size = 0;
						return NULL;
					}
					(void)blobAddData(b, buffer, VBA_COMPRESSION_WINDOW);
					clean = FALSE;
					break;
				}
				if(cli_readn(fd, &buffer[winpos], 1) == 1)
					pos++;
			}
			clean = TRUE;
		}
	}

	if(blobAddData(b, buffer, pos%VBA_COMPRESSION_WINDOW) < 0) {
		blobDestroy(b);
		if(size)
			*size = 0;
		return NULL;
	}

	if(size)
		*size = (int)blobGetDataSize(b);
	return (unsigned char *)blobToMem(b);
}

/*
 * See also cli_filecopy()
 */
static void
ole_copy_file_data(int s, int d, uint32_t len)
{
	unsigned char data[FILEBUFF];

	while(len > 0) {
		int todo = MIN(sizeof(data), len);

		if(cli_readn(s, data, (unsigned int)todo) != todo)
			break;
		if(cli_writen(d, data, (unsigned int)todo) != todo)
			break;
		len -= todo;
	}
}

int
cli_decode_ole_object(int fd, const char *dir)
{
	int ofd;
	uint32_t object_size;
	struct stat statbuf;
	char *fullname;

	if(dir == NULL)
		return -1;

	if(fd < 0)
		return -1;

	if(!read_uint32(fd, &object_size, FALSE))
		return -1;

	if(fstat(fd, &statbuf) == -1)
		return -1;

	if ((statbuf.st_size - object_size) >= 4) {
		/* Probably the OLE type id */
		if (lseek(fd, 2, SEEK_CUR) == -1) {
			return -1;
		}

		/* Attachment name */
		if(!skip_past_nul(fd))
			return -1;

		/* Attachment full path */
		if(!skip_past_nul(fd))
			return -1;

		/* ??? */
		if(lseek(fd, 8, SEEK_CUR) == -1)
			return -1;

		/* Attachment full path */
		if(!skip_past_nul(fd))
			return -1;

		if(!read_uint32(fd, &object_size, FALSE))
			return -1;
	}
	if(!(fullname = cli_gentemp(dir))) {
		return -1;
	}
	ofd = open(fullname, O_RDWR|O_CREAT|O_TRUNC|O_BINARY|O_EXCL,
		S_IWUSR|S_IRUSR);
	if (ofd < 0) {
		cli_warnmsg("cli_decode_ole_object: can't create %s\n",	fullname);
		free(fullname);
		return -1;
	} else {
		cli_dbgmsg("cli_decode_ole_object: decoding to %s\n", fullname);
	}
	free(fullname);
	ole_copy_file_data(fd, ofd, object_size);
	lseek(ofd, 0, SEEK_SET);
	return ofd;
}

/*
 * Powerpoint files
 */
typedef struct {
	uint16_t type;
	uint32_t length;
} atom_header_t;

static int
ppt_read_atom_header(int fd, atom_header_t *atom_header)
{
	uint16_t v;
	struct ppt_header {
		uint16_t ver;
		uint16_t type;
		uint32_t length;
	} h;

	cli_dbgmsg("in ppt_read_atom_header\n");
	if(cli_readn(fd, &h, sizeof(struct ppt_header)) != sizeof(struct ppt_header)) {
		cli_dbgmsg("read ppt_header failed\n");
		return FALSE;
	}
	v = vba_endian_convert_16(h.ver, FALSE);
	cli_dbgmsg("\tversion: 0x%.2x\n", v & 0xF);
	cli_dbgmsg("\tinstance: 0x%.2x\n", v >> 4);

	atom_header->type = vba_endian_convert_16(h.type, FALSE);
	cli_dbgmsg("\ttype: 0x%.4x\n", atom_header->type);
	atom_header->length = vba_endian_convert_32(h.length, FALSE);
	cli_dbgmsg("\tlength: 0x%.8x\n", (int)atom_header->length);

	return TRUE;
}

/*
 * TODO: combine shared code with flatedecode() or cli_unzip_single()
 *	Needs cli_unzip_single to have a "length" argument
 */
static int
ppt_unlzw(const char *dir, int fd, uint32_t length)
{
	int ofd;
	z_stream stream;
	unsigned char inbuff[PPT_LZW_BUFFSIZE], outbuff[PPT_LZW_BUFFSIZE];
	char fullname[NAME_MAX + 1];

	snprintf(fullname, sizeof(fullname) - 1, "%s/ppt%.8lx.doc",
		dir, (long)lseek(fd, 0L, SEEK_CUR));

	ofd = open(fullname, O_WRONLY|O_CREAT|O_TRUNC|O_BINARY|O_EXCL,
		S_IWUSR|S_IRUSR);
	if (ofd == -1) {
		cli_warnmsg("ppt_unlzw: can't create %s\n", fullname);
		return FALSE;
	}

	stream.zalloc = Z_NULL;
	stream.zfree = Z_NULL;
	stream.opaque = (void *)NULL;
	stream.next_in = (Bytef *)inbuff;
	stream.next_out = outbuff;
	stream.avail_out = sizeof(outbuff);
	stream.avail_in = MIN(length, PPT_LZW_BUFFSIZE);

	if(cli_readn(fd, inbuff, stream.avail_in) != (int)stream.avail_in) {
		close(ofd);
		unlink(fullname);
		return FALSE;
	}
	length -= stream.avail_in;

	if(inflateInit(&stream) != Z_OK) {
		close(ofd);
		unlink(fullname);
		cli_warnmsg("ppt_unlzw: inflateInit failed\n");
		return FALSE;
	}

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
			stream.avail_in = MIN(length, PPT_LZW_BUFFSIZE);
			if (cli_readn(fd, inbuff, stream.avail_in) != (int)stream.avail_in) {
				close(ofd);
				inflateEnd(&stream);
				return FALSE;
			}
			length -= stream.avail_in;
		}
	} while(inflate(&stream, Z_NO_FLUSH) == Z_OK);

	if (cli_writen(ofd, outbuff, PPT_LZW_BUFFSIZE-stream.avail_out) != (int)PPT_LZW_BUFFSIZE-stream.avail_out) {
		close(ofd);
		inflateEnd(&stream);
		return FALSE;
	}
	close(ofd);
	return inflateEnd(&stream) == Z_OK;
}

static const char *
ppt_stream_iter(int fd, const char *dir)
{
	atom_header_t atom_header;

	while(ppt_read_atom_header(fd, &atom_header)) {
		if(atom_header.length == 0)
			return NULL;

		if(atom_header.type == 0x1011) {
			uint32_t length;

			/* Skip over ID */
			if(lseek(fd, sizeof(uint32_t), SEEK_CUR) == -1) {
				cli_dbgmsg("ppt_stream_iter: seek failed\n");
				return NULL;
			}
			length = atom_header.length - 4;
			cli_dbgmsg("length: %d\n", (int)length);
			if (!ppt_unlzw(dir, fd, length)) {
				cli_dbgmsg("ppt_unlzw failed\n");
				return NULL;
			}
		} else {
			off_t offset = lseek(fd, 0, SEEK_CUR);
			/* Check we don't wrap */
			if ((offset + (off_t)atom_header.length) < offset) {
				break;
			}
			offset += atom_header.length;
			if (lseek(fd, offset, SEEK_SET) != offset) {
				break;
			}
		}
	}
	return dir;
}

char *
cli_ppt_vba_read(const char *filename)
{
	char *dir;
	const char *ret;
	int fd;
	char fullname[NAME_MAX + 1];

	if(filename == NULL)
		return NULL;

	snprintf(fullname, sizeof(fullname) - 1, "%s/PowerPoint Document",
		filename);
	fd = open(fullname, O_RDONLY|O_BINARY);
	if (fd == -1) {
		cli_dbgmsg("Open PowerPoint Document failed\n");
		return NULL;
	}

	/* Create a directory to store the extracted OLE2 objects */
	dir = cli_gentemp(NULL);
	if(dir == NULL)
		return NULL;
	if(mkdir(dir, 0700)) {
		cli_errmsg("cli_ppt_vba_read: Can't create temporary directory %s\n", dir);
		free(dir);
		return NULL;
	}
	ret = ppt_stream_iter(fd, dir);
	close(fd);
	if(ret == NULL) {
		cli_rmdirs(dir);
		free(dir);
		return NULL;
	}
	return dir;
}

/*
 * Word 6 macros
 */
typedef struct {
	unsigned	char unused[12];
	uint32_t	macro_offset;
	uint32_t	macro_len;
} mso_fib_t;

typedef struct macro_entry_tag {
	uint32_t len;
	uint32_t offset;
	unsigned char key;
} macro_entry_t;

typedef struct macro_info_tag {
	struct macro_entry_tag *entries;
	uint16_t count;
} macro_info_t;

static int
word_read_fib(int fd, mso_fib_t *fib)
{
	struct {
		uint32_t offset;
		uint32_t len;
	} macro_details;

	if(!seekandread(fd, 0x118, SEEK_SET, &macro_details, sizeof(macro_details))) {
		cli_dbgmsg("read word_fib failed\n");
		return FALSE;
	}
	fib->macro_offset = vba_endian_convert_32(macro_details.offset, FALSE);
	fib->macro_len = vba_endian_convert_32(macro_details.len, FALSE);

	return TRUE;
}

static int
word_read_macro_entry(int fd, macro_info_t *macro_info)
{
	int msize;
	int count = macro_info->count;
	macro_entry_t *macro_entry;
#ifdef HAVE_PRAGMA_PACK
#pragma pack(1)
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack 1
#endif
	struct macro {
		unsigned char version;
		unsigned char key;
		unsigned char ignore[10];
		uint32_t len	__attribute__ ((packed));
		uint32_t state	__attribute__ ((packed));
		uint32_t offset	__attribute__ ((packed));
	} *m;
	const struct macro *n;
#ifdef HAVE_PRAGMA_PACK
#pragma pack()
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack
#endif
	if(count == 0)
		return TRUE;

	msize = count * sizeof(struct macro);
	m = cli_malloc(msize);
	if(m == NULL)
		return FALSE;

	if(cli_readn(fd, m, msize) != msize) {
		free(m);
		cli_warnmsg("read %d macro_entries failed\n", count);
		return FALSE;
	}
	macro_entry = macro_info->entries;
	n = m;
	do {
		macro_entry->key = n->key;
		macro_entry->len = vba_endian_convert_32(n->len, FALSE);
		macro_entry->offset = vba_endian_convert_32(n->offset, FALSE);
		macro_entry++;
		n++;
	} while(--count > 0);
	free(m);
	return TRUE;
}

static macro_info_t *
word_read_macro_info(int fd, macro_info_t *macro_info)
{
	if(!read_uint16(fd, &macro_info->count, FALSE)) {
		cli_dbgmsg("read macro_info failed\n");
		macro_info->count = 0;
		return NULL;
	}
	cli_dbgmsg("macro count: %d\n", macro_info->count);
	if(macro_info->count == 0)
		return NULL;
	macro_info->entries = (macro_entry_t *)cli_malloc(sizeof(macro_entry_t) * macro_info->count);
	if(macro_info->entries == NULL) {
		macro_info->count = 0;
		return NULL;
	}
	if(!word_read_macro_entry(fd, macro_info)) {
		free(macro_info->entries);
		macro_info->count = 0;
		return NULL;
	}
	return macro_info;
}

static int
word_skip_oxo3(int fd)
{
	uint8_t count;

	if (cli_readn(fd, &count, 1) != 1) {
		cli_dbgmsg("read oxo3 record1 failed\n");
		return FALSE;
	}
	cli_dbgmsg("oxo3 records1: %d\n", count);

	if(!seekandread(fd, count * 14, SEEK_CUR, &count, 1)) {
		cli_dbgmsg("read oxo3 record2 failed\n");
		return FALSE;
	}

	if(count == 0) {
		uint8_t twobytes[2];

		if(cli_readn(fd, twobytes, 2) != 2) {
			cli_dbgmsg("read oxo3 failed\n");
			return FALSE;
		}
		if(twobytes[0] != 2) {
			lseek(fd, -2, SEEK_CUR);
			return TRUE;
		}
		count = twobytes[1];
	}
	if(count > 0)
		if (lseek(fd, (count*4)+1, SEEK_CUR) == -1) {
			cli_dbgmsg("lseek oxo3 failed\n");
			return FALSE;
		}

	cli_dbgmsg("oxo3 records2: %d\n", count);
	return TRUE;
}

static int
word_skip_menu_info(int fd)
{
	uint16_t count;

	if(!read_uint16(fd, &count, FALSE)) {
		cli_dbgmsg("read menu_info failed\n");
		return FALSE;
	}
	cli_dbgmsg("menu_info count: %d\n", count);

	if(count)
		if(lseek(fd, count * 12, SEEK_CUR) == -1)
			return FALSE;
	return TRUE;
}

static int
word_skip_macro_extnames(int fd)
{
	int is_unicode, nbytes;
	int16_t size;

	if(!read_uint16(fd, (uint16_t *)&size, FALSE)) {
		cli_dbgmsg("read macro_extnames failed\n");
		return FALSE;
	}
	if (size == -1) { /* Unicode flag */
		if(!read_uint16(fd, (uint16_t *)&size, FALSE)) {
			cli_dbgmsg("read macro_extnames failed\n");
			return FALSE;
		}
		is_unicode = 1;
	} else
		is_unicode = 0;

	cli_dbgmsg("ext names size: 0x%x\n", size);

	nbytes = size;
	while(nbytes > 0) {
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

		/* ignore numref as well */
		if(lseek(fd, offset + sizeof(uint16_t), SEEK_CUR) == -1) {
			cli_dbgmsg("read macro_extnames failed to seek\n");
			return FALSE;
		}
		nbytes -= size;
	}
	return TRUE;
}

static int
word_skip_macro_intnames(int fd)
{
	uint16_t count;

	if(!read_uint16(fd, &count, FALSE)) {
		cli_dbgmsg("read macro_intnames failed\n");
		return FALSE;
	}
	cli_dbgmsg("intnames count: %u\n", (unsigned int)count);

	while(count-- > 0) {
		uint8_t length;

		/* id */
		if(!seekandread(fd, sizeof(uint16_t), SEEK_CUR, &length, sizeof(uint8_t))) {
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

vba_project_t *
cli_wm_readdir(const char *dir)
{
	int fd, done;
	off_t end_offset;
	unsigned char info_id;
	macro_info_t macro_info;
	vba_project_t *vba_project;
	mso_fib_t fib;
	char fullname[NAME_MAX + 1];

	if(dir == NULL)
		return NULL;

	snprintf(fullname, sizeof(fullname) - 1, "%s/WordDocument", dir);
	fd = open(fullname, O_RDONLY|O_BINARY);
	if (fd == -1) {
		cli_dbgmsg("Open WordDocument failed\n");
		return NULL;
	}

	if (!word_read_fib(fd, &fib)) {
		close(fd);
		return NULL;
	}
	if(fib.macro_len == 0) {
		cli_dbgmsg("No macros detected\n");
		/* Must be clean */
		close(fd);
		return NULL;
	}
	cli_dbgmsg("macro offset: 0x%.4x\n", (int)fib.macro_offset);
	cli_dbgmsg("macro len: 0x%.4x\n\n", (int)fib.macro_len);

	/* Go one past the start to ignore start_id */
	if (lseek(fd, fib.macro_offset + 1, SEEK_SET) != (off_t)(fib.macro_offset + 1)) {
		cli_dbgmsg("lseek macro_offset failed\n");
		close(fd);
		return NULL;
	}

	end_offset = fib.macro_offset + fib.macro_len;
	done = FALSE;
	memset(&macro_info, '\0', sizeof(macro_info));

	while((lseek(fd, 0, SEEK_CUR) < end_offset) && !done) {
		if (cli_readn(fd, &info_id, 1) != 1) {
			cli_dbgmsg("read macro_info failed\n");
			break;
		}
		switch (info_id) {
			case 0x01:
				if(macro_info.count)
					free(macro_info.entries);
				word_read_macro_info(fd, &macro_info);
				done = TRUE;
				break;
			case 0x03:
				if(!word_skip_oxo3(fd))
					done = TRUE;
				break;
			case 0x05:
				if(!word_skip_menu_info(fd))
					done = TRUE;
				break;
			case 0x10:
				if(!word_skip_macro_extnames(fd))
					done = TRUE;
				break;
			case 0x11:
				if(!word_skip_macro_intnames(fd))
					done = TRUE;
				break;
			case 0x40:	/* end marker */
			case 0x12:	/* ??? */
				done = TRUE;
				break;
			default:
				cli_dbgmsg("unknown type: 0x%x\n", info_id);
				done = TRUE;
		}
	}

	close(fd);

	if(macro_info.count == 0)
		return NULL;

	vba_project = create_vba_project(macro_info.count, dir);

	if(vba_project) {
		vba_project->length = (uint32_t *)cli_malloc(sizeof(uint32_t) *
				macro_info.count);
		vba_project->key = (unsigned char *)cli_malloc(sizeof(unsigned char) *
				macro_info.count);
		if((vba_project->length != NULL) &&
		   (vba_project->key != NULL)) {
			int i;
			const macro_entry_t *m = macro_info.entries;

			for(i = 0; i < macro_info.count; i++) {
				vba_project->name[i] = cli_strdup("WordDocument");
				vba_project->offset[i] = m->offset;
				vba_project->length[i] = m->len;
				vba_project->key[i] = m->key;
				m++;
			}
		} else {
			free(vba_project->name);
			free(vba_project->dir);
			free(vba_project->offset);
			if(vba_project->length)
				free(vba_project->length);
			if(vba_project->key)
				free(vba_project->key);
			free(vba_project);
			vba_project = NULL;
		}
	}
	free(macro_info.entries);

	return vba_project;
}

unsigned char *
cli_wm_decrypt_macro(int fd, off_t offset, uint32_t len, unsigned char key)
{
	unsigned char *buff;

	if(len == 0)
		return NULL;

	if(fd < 0)
		return NULL;

	buff = (unsigned char *)cli_malloc(len);
	if(buff == NULL)
		return NULL;

	if(!seekandread(fd, offset, SEEK_SET, buff, len)) {
		free(buff);
		return NULL;
	}
	if(key) {
		unsigned char *p;

		for(p = buff; p < &buff[len]; p++)
			*p ^= key;
	}
	return buff;
}

/*
 * Keep reading bytes until we reach a NUL. Returns 0 if none is found
 */
static int
skip_past_nul(int fd)
{
	char ch;

	do
		if(cli_readn(fd, &ch, 1) != 1)
			return FALSE;
	while(ch);

	return TRUE;
}

/*
 * Read 2 bytes as a 16-bit number, host byte order. Return success or fail
 */
static int
read_uint16(int fd, uint16_t *u, int big_endian)
{
	if(cli_readn(fd, u, sizeof(uint16_t)) != sizeof(uint16_t))
		return FALSE;

	*u = vba_endian_convert_16(*u, big_endian);

	return TRUE;
}

/*
 * Read 4 bytes as a 32-bit number, host byte order. Return success or fail
 */
static int
read_uint32(int fd, uint32_t *u, int big_endian)
{
	if(cli_readn(fd, u, sizeof(uint32_t)) != sizeof(uint32_t))
		return FALSE;

	*u = vba_endian_convert_32(*u, big_endian);

	return TRUE;
}

/*
 * Miss some bytes then read a bit
 */
static int
seekandread(int fd, off_t offset, int whence, void *data, size_t len)
{
	if(lseek(fd, offset, whence) == (off_t)-1) {
		cli_dbgmsg("lseek failed\n");
		return FALSE;
	}
	return cli_readn(fd, data, (unsigned int)len) == (int)len;
}

/*
 * Create and initialise a vba_project structure
 */
static vba_project_t *
create_vba_project(int record_count, const char *dir)
{
	vba_project_t *ret;

	ret = (vba_project_t *) cli_malloc(sizeof(struct vba_project_tag));

	if(ret == NULL)
		return NULL;

	ret->name = (char **)cli_malloc(sizeof(char *) * record_count);
	ret->dir = cli_strdup(dir);
	ret->offset = (uint32_t *)cli_malloc (sizeof(uint32_t) * record_count);

	if((ret->name == NULL) || (ret->dir == NULL) || (ret->offset == NULL)) {
		if(ret->dir)
			free(ret->dir);
		if(ret->name)
			free(ret->name);
		if(ret->offset)
			free(ret->offset);
		free(ret);
		return NULL;
	}
	ret->count = record_count;

	return ret;
}

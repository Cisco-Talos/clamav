/*
 *  Extract VBA source code for component MS Office Documents
 *
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
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

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "libclamav/crypto.h"

#include "clamav.h"

#include "others.h"
#include "scanners.h"
#include "vba_extract.h"
#ifdef	CL_DEBUG
#include "mbox.h"
#endif
#include "blob.h"
#ifdef HAVE_JSON
#include "json/json.h"
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

static	int	skip_past_nul(int fd);
static	int	read_uint16(int fd, uint16_t *u, int big_endian);
static	int	read_uint32(int fd, uint32_t *u, int big_endian);
static	int	seekandread(int fd, off_t offset, int whence, void *data, size_t len);
static	vba_project_t	*create_vba_project(int record_count, const char *dir, struct uniq *U);

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

	newname = (char *)cli_malloc(size * 7 + 1);
	if(newname == NULL) {
        cli_errmsg("get_unicode_name: Unable to allocate memory for newname\n");
		return NULL;
    }

	if((!big_endian) && (size & 0x1)) {
		cli_dbgmsg("get_unicode_name: odd number of bytes %d\n", size);
		--size;
	}

	increment = (big_endian) ? 1 : 2;
	ret = newname;

	for(i = 0; i < size; i += increment) {
		if((!(name[i]&0x80)) && isprint(name[i])) {
		        *ret++ = tolower(name[i]);
		} else {
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
		if (lseek(fd, -MIDDLE_SIZE, SEEK_CUR) == -1) {
            cli_dbgmsg("vba_test_middle: call to lseek() failed\n");
            return;
        }
	} else
		cli_dbgmsg("middle found\n");
}

/* return count of valid strings found, 0 on error */
static int
vba_read_project_strings(int fd, int big_endian)
{
    unsigned char *buf = NULL;
    uint16_t buflen = 0;
    uint16_t length = 0;
    int ret = 0, getnewlength = 1;

    for(;;) {
        off_t offset;
        char *name;

        /* if no initial name length, exit */
        if(getnewlength && !read_uint16(fd, &length, big_endian)) {
            ret = 0;
            break;
        }
        getnewlength = 0;

        /* if too short, break */
        if (length < 6) {
            if (lseek(fd, -2, SEEK_CUR) == -1) {
                cli_dbgmsg("vba_read_project_strings: call to lseek() has failed\n");
                ret = 0;
            }
            break;
        }
        /* ensure buffer is large enough */
        if(length > buflen) {
            unsigned char *newbuf = (unsigned char *)cli_realloc(buf, length);
            if(newbuf == NULL) {
                ret = 0;
                break;
            }
            buflen = length;
            buf = newbuf;
        }

        /* save current offset */
        offset = lseek(fd, 0, SEEK_CUR);
        if (offset == -1) {
            cli_dbgmsg("vba_read_project_strings: call to lseek() has failed\n");
            ret = 0;
            break;
        }

        /* if read name failed, break */
        if(cli_readn(fd, buf, length) != (int)length) {
            cli_dbgmsg("read name failed - rewinding\n");
            if (lseek(fd, offset, SEEK_SET) == -1) {
                cli_dbgmsg("call to lseek() in read name failed\n");
                ret = 0;
            }
            break;
        }
        name = get_unicode_name((const char *)buf, length, big_endian);
        cli_dbgmsg("length: %d, name: %s\n", length, (name) ? name : "[null]");

        /* if invalid name, break */
        if((name == NULL) || (memcmp("*\\", name, 2) != 0) ||
           (strchr("ghcd", name[2]) == NULL)) {
            /* Not a valid string, rewind */
            if (lseek(fd, -(length+2), SEEK_CUR) == -1) {
                cli_dbgmsg("call to lseek() after get_unicode_name has failed\n");
                ret = 0;
            }
            free(name);
            break;
        }
        free(name);

        /* can't get length, break */
        if(!read_uint16(fd, &length, big_endian)) {
            break;
        }

        ret++;

        /* continue on reasonable length value */
        if ((length != 0) && (length != 65535)) {
            continue;
        }

        /* determine offset and run middle test */
        offset = lseek(fd, 10, SEEK_CUR);
        if (offset == -1) {
            cli_dbgmsg("call to lseek() has failed\n");
            ret = 0;
            break;
        }
        cli_dbgmsg("offset: %lu\n", (unsigned long)offset);
        vba56_test_middle(fd);
        getnewlength = 1;
    }

    free(buf);
    return ret;
}

vba_project_t *
cli_vba_readdir(const char *dir, struct uniq *U, uint32_t which)
{
	unsigned char *buf;
	const unsigned char vba56_signature[] = { 0xcc, 0x61 };
	uint16_t record_count, buflen, ffff, byte_count;
	uint32_t offset;
	int i, j, fd, big_endian = FALSE;
	vba_project_t *vba_project;
	struct vba56_header v56h;
	off_t seekback;
	char fullname[1024], *hash;

	cli_dbgmsg("in cli_vba_readdir()\n");

	if(dir == NULL)
		return NULL;

	/*
	 * _VBA_PROJECT files are embedded within office documents (OLE2)
	 */
	
	if (!uniq_get(U, "_vba_project", 12, &hash))
		return NULL;
	snprintf(fullname, sizeof(fullname), "%s"PATHSEP"%s_%u", dir, hash, which);
	fullname[sizeof(fullname)-1] = '\0';
	fd = open(fullname, O_RDONLY|O_BINARY);

	if(fd == -1)
		return NULL;

	if(cli_readn(fd, &v56h, sizeof(struct vba56_header)) != sizeof(struct vba56_header)) {
		close(fd);
		return NULL;
	}
	if (memcmp(v56h.magic, vba56_signature, sizeof(v56h.magic)) != 0) {
		close(fd);
		return NULL;
	}

	i = vba_read_project_strings(fd, TRUE);
	if ((seekback = lseek(fd, 0, SEEK_CUR)) == -1) {
		cli_dbgmsg("vba_readdir: lseek() failed. Unable to guess VBA type\n");
		close(fd);
		return NULL;
	}
	if (lseek(fd, sizeof(struct vba56_header), SEEK_SET) == -1) {
		cli_dbgmsg("vba_readdir: lseek() failed. Unable to guess VBA type\n");
		close(fd);
		return NULL;
	}
	j = vba_read_project_strings(fd, FALSE);
	if(!i && !j) {
		close(fd);
		cli_dbgmsg("vba_readdir: Unable to guess VBA type\n");
		return NULL;
	}
	if (i > j) {
		big_endian = TRUE;
		if (lseek(fd, seekback, SEEK_SET) == -1) {
			cli_dbgmsg("vba_readdir: call to lseek() while guessing big-endian has failed\n");
			close(fd);
			return NULL;
		}
		cli_dbgmsg("vba_readdir: Guessing big-endian\n");
	} else {
		cli_dbgmsg("vba_readdir: Guessing little-endian\n");
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
	if (ffff != 0xFFFF) {
		if (lseek(fd, 1, SEEK_CUR) == -1) {
            cli_dbgmsg("call to lseek() while checking alignment error has failed\n");
            close(fd);
            return NULL;
        }
    }

	if(!read_uint16(fd, &ffff, big_endian)) {
		close(fd);
		return NULL;
	}

	if(ffff != 0xFFFF) {
		if (lseek(fd, ffff, SEEK_CUR) == -1) {
            cli_dbgmsg("call to lseek() while checking alignment error has failed\n");
            close(fd);
            return NULL;
        }
    }

	if(!read_uint16(fd, &ffff, big_endian)) {
		close(fd);
		return NULL;
	}

	if(ffff == 0xFFFF)
		ffff = 0;

	if (lseek(fd, ffff + 100, SEEK_CUR) == -1) {
        cli_dbgmsg("call to lseek() failed\n");
        close(fd);
        return NULL;
    }

	if(!read_uint16(fd, &record_count, big_endian)) {
		close(fd);
		return NULL;
	}
	cli_dbgmsg("vba_readdir: VBA Record count %d\n", record_count);
	if (record_count == 0) {
		/* No macros, assume clean */
		close(fd);
		return NULL;
	}
	if (record_count > MAX_VBA_COUNT) {
		/* Almost certainly an error */
		cli_dbgmsg("vba_readdir: VBA Record count too big\n");
		close(fd);
		return NULL;
	}

	vba_project = create_vba_project(record_count, dir, U);
	if(vba_project == NULL) {
		close(fd);
		return NULL;
	}
	buf = NULL;
	buflen = 0;
	for(i = 0; i < record_count; i++) {
		uint16_t length;
		char *ptr;

		vba_project->colls[i] = 0;
		if(!read_uint16(fd, &length, big_endian))
			break;

		if (length == 0) {
			cli_dbgmsg("vba_readdir: zero name length\n");
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
			cli_dbgmsg("vba_readdir: read name failed\n");
			break;
		}
		ptr = get_unicode_name((const char *)buf, length, big_endian);
		if(ptr == NULL) break;
		if (!(vba_project->colls[i]=uniq_get(U, ptr, strlen(ptr), &hash))) {
			cli_dbgmsg("vba_readdir: cannot find project %s (%s)\n", ptr, hash);
			free(ptr);
			break;
		}
		cli_dbgmsg("vba_readdir: project name: %s (%s)\n", ptr, hash);
		free(ptr);
		vba_project->name[i] = hash;
		if(!read_uint16(fd, &length, big_endian))
			break;
		lseek(fd, length, SEEK_CUR);

		if(!read_uint16(fd, &ffff, big_endian))
			break;
		if (ffff == 0xFFFF) {
			lseek(fd, 2, SEEK_CUR);
			if(!read_uint16(fd, &ffff, big_endian))
				break;
			lseek(fd, ffff + 8, SEEK_CUR);
		} else
			lseek(fd, ffff + 10, SEEK_CUR);

		if(!read_uint16(fd, &byte_count, big_endian))
			break;
		lseek(fd, (8 * byte_count) + 5, SEEK_CUR);
		if(!read_uint32(fd, &offset, big_endian))
			break;
		cli_dbgmsg("vba_readdir: offset: %u\n", (unsigned int)offset);
		vba_project->offset[i] = offset;
		lseek(fd, 2, SEEK_CUR);
	}

	if(buf)
		free(buf);

	close(fd);

	if(i < record_count) {
		free(vba_project->name);
		free(vba_project->colls);
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
cli_scan_ole10(int fd, cli_ctx *ctx)
{
	int ofd, ret;
	uint32_t object_size;
	STATBUF statbuf;
	char *fullname;

	if(fd < 0)
		return CL_CLEAN;

	lseek(fd, 0, SEEK_SET);
	if(!read_uint32(fd, &object_size, FALSE))
		return CL_CLEAN;

	if(FSTAT(fd, &statbuf) == -1)
		return CL_ESTAT;

	if ((statbuf.st_size - object_size) >= 4) {
		/* Probably the OLE type id */
		if (lseek(fd, 2, SEEK_CUR) == -1) {
			return CL_CLEAN;
		}

		/* Attachment name */
		if(!skip_past_nul(fd))
			return CL_CLEAN;

		/* Attachment full path */
		if(!skip_past_nul(fd))
			return CL_CLEAN;

		/* ??? */
		if(lseek(fd, 8, SEEK_CUR) == -1)
			return CL_CLEAN;

		/* Attachment full path */
		if(!skip_past_nul(fd))
			return CL_CLEAN;

		if(!read_uint32(fd, &object_size, FALSE))
			return CL_CLEAN;
	}
	if(!(fullname = cli_gentemp(ctx ? ctx->engine->tmpdir : NULL))) {
		return CL_EMEM;
	}
	ofd = open(fullname, O_RDWR|O_CREAT|O_TRUNC|O_BINARY|O_EXCL,
		S_IWUSR|S_IRUSR);
	if (ofd < 0) {
		cli_warnmsg("cli_decode_ole_object: can't create %s\n",	fullname);
		free(fullname);
		return CL_ECREAT;
	}
	cli_dbgmsg("cli_decode_ole_object: decoding to %s\n", fullname);
	ole_copy_file_data(fd, ofd, object_size);
	lseek(ofd, 0, SEEK_SET);
	ret = cli_magic_scandesc(ofd, ctx);
	close(ofd);
	if(ctx && !ctx->engine->keeptmp)
	  if (cli_unlink(fullname))
	    ret = CL_EUNLINK;
	free(fullname);
	return ret;
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

	snprintf(fullname, sizeof(fullname) - 1, "%s"PATHSEP"ppt%.8lx.doc",
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
		cli_unlink(fullname);
		return FALSE;
	}
	length -= stream.avail_in;

	if(inflateInit(&stream) != Z_OK) {
		close(ofd);
		cli_unlink(fullname);
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

	if (cli_writen(ofd, outbuff, PPT_LZW_BUFFSIZE-stream.avail_out) != (int)(PPT_LZW_BUFFSIZE-stream.avail_out)) {
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
cli_ppt_vba_read(int ifd, cli_ctx *ctx)
{
	char *dir;
	const char *ret;

	/* Create a directory to store the extracted OLE2 objects */
	dir = cli_gentemp(ctx ? ctx->engine->tmpdir : NULL);
	if(dir == NULL)
		return NULL;
	if(mkdir(dir, 0700)) {
		cli_errmsg("cli_ppt_vba_read: Can't create temporary directory %s\n", dir);
		free(dir);
		return NULL;
	}
	ret = ppt_stream_iter(ifd, dir);
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
	if(m == NULL) {
        cli_errmsg("word_read_macro_entry: Unable to allocate memory for 'm'\n");
		return FALSE;
    }

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
        cli_errmsg("word_read_macro_info: Unable to allocate memory for macro_info->entries\n");
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
cli_wm_readdir(int fd)
{
	int done;
	off_t end_offset;
	unsigned char info_id;
	macro_info_t macro_info;
	vba_project_t *vba_project;
	mso_fib_t fib;

	if (!word_read_fib(fd, &fib))
		return NULL;

	if(fib.macro_len == 0) {
		cli_dbgmsg("wm_readdir: No macros detected\n");
		/* Must be clean */
		return NULL;
	}
	cli_dbgmsg("wm_readdir: macro offset: 0x%.4x\n", (int)fib.macro_offset);
	cli_dbgmsg("wm_readdir: macro len: 0x%.4x\n\n", (int)fib.macro_len);

	/* Go one past the start to ignore start_id */
	if (lseek(fd, fib.macro_offset + 1, SEEK_SET) != (off_t)(fib.macro_offset + 1)) {
		cli_dbgmsg("wm_readdir: lseek macro_offset failed\n");
		return NULL;
	}

	end_offset = fib.macro_offset + fib.macro_len;
	done = FALSE;
	macro_info.entries = NULL;
	macro_info.count = 0;

	while((lseek(fd, 0, SEEK_CUR) < end_offset) && !done) {
		if (cli_readn(fd, &info_id, 1) != 1) {
			cli_dbgmsg("wm_readdir: read macro_info failed\n");
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
				cli_dbgmsg("wm_readdir: unknown type: 0x%x\n", info_id);
				done = TRUE;
		}
	}


	if(macro_info.count == 0)
		return NULL;

	vba_project = create_vba_project(macro_info.count, "", NULL);

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
				vba_project->offset[i] = m->offset;
				vba_project->length[i] = m->len;
				vba_project->key[i] = m->key;
				m++;
			}
		} else {
            cli_errmsg("cli_wm_readdir: Unable to allocate memory for vba_project\n");
			free(vba_project->name);
			free(vba_project->colls);
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
	if(buff == NULL) {
        cli_errmsg("cli_wm_decrypt_macro: Unable to allocate memory for buff\n");
		return NULL;
    }

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
    char *end;
    char smallbuf[128];

    do {
	int nread = cli_readn(fd, smallbuf, sizeof(smallbuf));
	if (nread <= 0)
	    return FALSE;
	end = memchr(smallbuf, '\0', nread);
	if (end) {
	    if (lseek(fd, 1 + (end-smallbuf) - nread, SEEK_CUR) < 0)
		return FALSE;
	    return TRUE;
	}
    } while (1);
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
create_vba_project(int record_count, const char *dir, struct uniq *U)
{
	vba_project_t *ret;

	ret = (vba_project_t *) cli_malloc(sizeof(struct vba_project_tag));

	if(ret == NULL) {
        cli_errmsg("create_vba_project: Unable to allocate memory for vba project structure\n");
		return NULL;
    }

	ret->name = (char **)cli_malloc(sizeof(char *) * record_count);
	ret->colls = (uint32_t *)cli_malloc(sizeof(uint32_t) * record_count);
	ret->dir = cli_strdup(dir);
	ret->offset = (uint32_t *)cli_malloc (sizeof(uint32_t) * record_count);

	if((ret->name == NULL) || (ret->dir == NULL) || (ret->offset == NULL)) {
		if(ret->dir)
			free(ret->dir);
		if(ret->colls)
			free(ret->colls);
		if(ret->name)
			free(ret->name);
		if(ret->offset)
			free(ret->offset);
		free(ret);
        cli_errmsg("create_vba_project: Unable to allocate memory for vba project elements\n");
		return NULL;
	}
	ret->count = record_count;
	ret->U = U;

	return ret;
}

#ifdef HAVE_JSON
#define cli_jsonnull(o,n)\
	{                                                               \
		json_object *fpobj = json_object_new_string("null");	\
		if (NULL == fpobj) {                                    \
			cli_errmsg("json: no memory for json string object.\n"); \
			return CL_EMEM;                                 \
		}                                                       \
		json_object_object_add(o, n, fpobj);			\
        }

#define cli_jsonstr(o,n,s)						\
	{								\
		json_object *fpobj = json_object_new_string(s);		\
		if (NULL == fpobj) {					\
			cli_errmsg("json: no memory for json string object.\n"); \
			return CL_EMEM;					\
		}							\
		json_object_object_add(o, n, fpobj);			\
	}

#define cli_jsonint(o,n,i)						\
	{								\
		json_object *fpobj = json_object_new_int(i);		\
		if (NULL == fpobj) {					\
			cli_errmsg("json: no memory for json int object.\n"); \
			return CL_EMEM;					\
		}							\
		json_object_object_add(o, n, fpobj);			\
	}
/*
#define cli_jsonint64(o,n,i)						\
        {                                                               \
                json_object *fpobj = json_object_new_int64(i);		\
                if (NULL == fpobj) {                                    \
                        cli_errmsg("json: no memory for json int object.\n"); \
                        return CL_EMEM;                                 \
                }                                                       \
                json_object_object_add(o, n, fpobj);                    \
        }
*/
#define cli_jsonint64(o,n,i) cli_dbgmsg("%s: %lld [%llx]\n", n, i, i)

#define cli_jsonbool(o,n,b)						\
	{                                                               \
                json_object *fpobj = json_object_new_boolean(b);	\
                if (NULL == fpobj) {                                    \
                        cli_errmsg("json: no memory for json int object.\n"); \
                        return CL_EMEM;                                 \
                }                                                       \
                json_object_object_add(o, n, fpobj);                    \
        }

#define cli_jsondouble(o,n,d)						\
	{                                                               \
		json_object *fpobj = json_object_new_double(d);		\
		if (NULL == fpobj) {                                    \
			cli_errmsg("json: no memory for json int object.\n"); \
			return CL_EMEM;                                 \
		}                                                       \
		json_object_object_add(o, n, fpobj);                    \
        }

#else
#define cli_jsonnull(o,n)     cli_dbgmsg("%s: null\n", n)
#define cli_jsonstr(o,n,s)    cli_dbgmsg("%s: \"%s\"\n", n, s)
#define cli_jsonint(o,n,i)    cli_dbgmsg("%s: %d [%x]\n", n, i, i)
#define cli_jsonint64(o,n,i)  cli_dbgmsg("%s: %lld [%llx]\n", n, i, i)
#define cli_jsonbool(o,n,b)   cli_dbgmsg("%s: %s\n", n, b ? "true":"false")
#define cli_jsondouble(o,n,d) cli_dbgmsg("%s: %f\n", n, d)
#endif

#define WINUNICODE 0x04B0
#define PROPCNTLIMIT 25
#define PROPSTRLIMIT 100

#define sum16_endian_convert(v) le16_to_host((uint16_t)(v))
#define sum32_endian_convert(v) le32_to_host((uint32_t)(v))
#define sum64_endian_convert(v) le64_to_host((uint32_t)(v))

static char    *
get_property_name2(char *name, int size)
{
    int             i, j;
    char           *newname;

    if (*name == 0 || size <= 0 || size > 64) {
        return NULL;
    }
    newname = (char *)cli_malloc(size * 7);
    if (!newname) {
        cli_errmsg("OLE2 [get_property_name2]: Unable to allocate memory for newname: %u\n", size * 7);
        return NULL;
    }
    j = 0;
    /* size-2 to ignore trailing NULL */
    for (i = 0; i < size - 2; i += 2) {
        if ((!(name[i] & 0x80)) && isprint(name[i])) {
            newname[j++] = tolower(name[i]);
        } else {
            if (name[i] < 10 && name[i] >= 0) {
                newname[j++] = '_';
                newname[j++] = name[i] + '0';
            } else {
                const uint16_t  x = (((uint16_t) name[i]) << 8) | name[i + 1];

                newname[j++] = '_';
                newname[j++] = 'a' + ((x & 0xF));
                newname[j++] = 'a' + ((x >> 4) & 0xF);
                newname[j++] = 'a' + ((x >> 8) & 0xF);
                newname[j++] = 'a' + ((x >> 16) & 0xF);
                newname[j++] = 'a' + ((x >> 24) & 0xF);
            }
            newname[j++] = '_';
        }
    }
    newname[j] = '\0';
    if (strlen(newname) == 0) {
        free(newname);
        return NULL;
    }
    return newname;
}

enum summary_pidsi {
	SPID_CODEPAGE   = 0x00000001,
	SPID_TITLE      = 0x00000002,
	SPID_SUBJECT    = 0x00000003,
	SPID_AUTHOR     = 0x00000004,
	SPID_KEYWORDS   = 0x00000005,
	SPID_COMMENTS   = 0x00000006,
	SPID_TEMPLATE   = 0x00000007,
	SPID_LASTAUTHOR = 0x00000008,
	SPID_REVNUMBER  = 0x00000009,
	SPID_EDITTIME   = 0x0000000A,
	SPID_LASTPRINTED  = 0x0000000B,
	SPID_CREATEDTIME  = 0x0000000C,
	SPID_MODIFIEDTIME = 0x0000000D,
	SPID_PAGECOUNT = 0x0000000E,
	SPID_WORDCOUNT = 0x0000000F,
	SPID_CHARCOUNT = 0x00000010,
	SPID_THUMBNAIL = 0x00000011,
	SPID_APPNAME   = 0x00000012,
	SPID_SECURITY  = 0x00000013
};

enum docsum_pidsi {
        DSPID_CODEPAGE    = 0x00000001,
	DSPID_CATEGORY    = 0x00000002,
	DSPID_PRESFORMAT  = 0x00000003,
	DSPID_BYTECOUNT   = 0x00000004,
	DSPID_LINECOUNT   = 0x00000005,
	DSPID_PARCOUNT    = 0x00000006,
	DSPID_SLIDECOUNT  = 0x00000007,
	DSPID_NOTECOUNT   = 0x00000008,
	DSPID_HIDDENCOUNT = 0x00000009,
	DSPID_MMCLIPCOUNT = 0x0000000A,
	DSPID_SCALE       = 0x0000000B,
	DSPID_HEADINGPAIR = 0x0000000C, /* VT_VARIANT | VT_VECTOR */
	DSPID_DOCPARTS    = 0x0000000D, /* VT_VECTOR | VT_LPSTR */
	DSPID_MANAGER     = 0x0000000E,
	DSPID_COMPANY     = 0x0000000F,
	DSPID_LINKSDIRTY  = 0x00000010,
	DSPID_CCHWITHSPACES = 0x00000011,
	DSPID_SHAREDDOC   = 0x00000013, /* must be false */
	DSPID_LINKBASE    = 0x00000014, /* moved to user-defined */
	DSPID_HLINKS      = 0x00000015, /* moved to user-defined */
	DSPID_HYPERLINKSCHANGED = 0x00000016,
	DSPID_VERSION     = 0x00000017,
	DSPID_DIGSIG      = 0x00000018,
	DSPID_CONTENTTYPE   = 0x0000001A,
	DSPID_CONTENTSTATUS = 0x0000001B,
	DSPID_LANGUAGE      = 0x0000001C,
	DSPID_DOCVERSION    = 0x0000001D
};

enum property_type {
	PT_EMPTY    = 0x0000,
	PT_NULL     = 0x0001,
	PT_INT16    = 0x0002,
	PT_INT32    = 0x0003,
	PT_FLOAT32  = 0x0004,
	PT_DOUBLE64 = 0x0005,
	PT_CURRENCY = 0x0006,
	PT_DATE     = 0x0007,
	PT_BSTR     = 0x0008,
	PT_ERROR   = 0x000A,
	PT_BOOL    = 0x000B,
	PT_DECIMAL = 0x000E,
	PT_INT8v1  = 0x0010,
	PT_UINT8   = 0x0011,
	PT_UINT16  = 0x0012,
	PT_UINT32  = 0x0013,
	PT_INT64   = 0x0014,
	PT_UINT64  = 0x0015,
	PT_INT32v1  = 0x0016,
	PT_UINT32v1 = 0x0017,
	PT_LPSTR  = 0x001E,
	PT_LPWSTR = 0x001F,
	PT_FILETIME = 0x0040,
	PT_BLOB     = 0x0041
/* More Types not currently handled */
};

typedef struct summary_stub {
	uint16_t byte_order;
	uint16_t version;
	uint32_t system; /* implementation-specific */
	uint8_t CLSID[16];

	uint32_t num_propsets; /* 1 or 2 */
} summary_stub_t;

typedef struct propset_summary_entry {
	uint8_t FMTID[16];
	uint32_t offset;
} propset_entry_t;

typedef struct summary_ctx {
	cli_ctx *ctx;
#ifdef HAVE_JSON
	json_object *summary;
#else
	char *summary;
#endif

	uint16_t byte_order;
	uint16_t version;
	int16_t codepage;

	const char *propname;
	int writecp; /* used to trigger writing the codepage value */
} summary_ctx_t;

static int
cli_vba_process_prop(summary_ctx_t *sctx, unsigned char *databuf, size_t buflen, uint32_t offset)
{
	uint16_t proptype, padding;

	if (offset+4 > buflen) {
		return CL_EFORMAT;
	}

	memcpy(&proptype, databuf+offset, sizeof(proptype));
	offset+=sizeof(proptype);
	memcpy(&padding, databuf+offset, sizeof(padding));
	offset+=sizeof(padding);
	/* endian conversion */
	proptype = sum16_endian_convert(proptype);

	//cli_dbgmsg("proptype: 0x%04x\n", proptype);
	if (padding != 0) {
		return CL_EFORMAT;
	}

	switch (proptype) {
	case PT_EMPTY:
		cli_jsonnull(sctx->summary, sctx->propname);
		break;
	case PT_NULL:
		cli_jsonnull(sctx->summary, sctx->propname);
		break;
	case PT_INT16:
	{
		int16_t dout;
		if (offset+sizeof(dout) > buflen) {
			return CL_EFORMAT;
		}
		memcpy(&dout, databuf+offset, sizeof(dout));
		offset+=sizeof(dout);
		/* endian conversion */
		dout = sum16_endian_convert(dout);

		if (sctx->writecp) sctx->codepage = dout;

		cli_jsonint(sctx->summary, sctx->propname, dout);
		break;
	}
	case PT_INT32:
	case PT_INT32v1:
	{
		int32_t dout;
		if (offset+sizeof(dout) > buflen) {
                        return CL_EFORMAT;
                }
                memcpy(&dout, databuf+offset, sizeof(dout));
                offset+=sizeof(dout);
                /* endian conversion */
		dout = sum32_endian_convert(dout);

		cli_jsonint(sctx->summary, sctx->propname, dout);
                break;
	}
	case PT_FLOAT32: /* review this please */
	{
		float dout;
		if (offset+sizeof(dout) > buflen) {
                        return CL_EFORMAT;
                }
                memcpy(&dout, databuf+offset, sizeof(dout));
                offset+=sizeof(dout);
                /* TODO - endian conversion */

		cli_jsondouble(sctx->summary, sctx->propname, dout);
                break;
	}
	case PT_DATE:
	case PT_DOUBLE64: /* review this please */
	{
		double dout;
		if (offset+sizeof(dout) > buflen) {
                        return CL_EFORMAT;
                }
                memcpy(&dout, databuf+offset, sizeof(dout));
                offset+=sizeof(dout);
                /* TODO - endian conversion */

		cli_jsondouble(sctx->summary, sctx->propname, dout);
                break;
	}
	/*
	case PT_CURRENCY:
	break;
	case PT_ERROR:
	break;
	*/
	case PT_BOOL:
	{
		uint16_t dout;
		if (offset+sizeof(dout) > buflen) {
                        return CL_EFORMAT;
                }
                memcpy(&dout, databuf+offset, sizeof(dout));
                offset+=sizeof(dout);
		/* no need for endian conversion */

		cli_jsonbool(sctx->summary, sctx->propname, dout);
		break;
	}
		/*	case PT_DECIMAL:
	break;*/
	case PT_INT8v1:
	{
		int8_t dout;
		if (offset+sizeof(dout) > buflen) {
                        return CL_EFORMAT;
                }
                memcpy(&dout, databuf+offset, sizeof(dout));
                offset+=sizeof(dout);
                /* no need for endian conversion */

		cli_jsonint(sctx->summary, sctx->propname, dout);
                break;
	}
	case PT_UINT8:
	{
		uint8_t dout;
		if (offset+sizeof(dout) > buflen) {
                        return CL_EFORMAT;
                }
                memcpy(&dout, databuf+offset, sizeof(dout));
                offset+=sizeof(dout);
                /* no need for endian conversion */

		cli_jsonint(sctx->summary, sctx->propname, dout);
                break;
	}
	case PT_UINT16:
	{
		uint16_t dout;
		if (offset+sizeof(dout) > buflen) {
                        return CL_EFORMAT;
                }
                memcpy(&dout, databuf+offset, sizeof(dout));
                offset+=sizeof(dout);
                /* endian conversion */
		dout = sum16_endian_convert(dout);

		if (sctx->writecp) sctx->codepage = dout;

		cli_jsonint(sctx->summary, sctx->propname, dout);
                break;
	}
	case PT_UINT32:
	case PT_UINT32v1:
	{
		uint32_t dout;
		if (offset+sizeof(dout) > buflen) {
                        return CL_EFORMAT;
                }
                memcpy(&dout, databuf+offset, sizeof(dout));
                offset+=sizeof(dout);
                /* endian conversion */
		dout = sum32_endian_convert(dout);

		cli_jsonint(sctx->summary, sctx->propname, dout);
                break;
	}
	case PT_INT64:
	{
		int64_t dout;
		if (offset+sizeof(dout) > buflen) {
                        return CL_EFORMAT;
                }
                memcpy(&dout, databuf+offset, sizeof(dout));
                offset+=sizeof(dout);
                /* endian conversion */
		dout = sum64_endian_convert(dout);

		cli_jsonint64(sctx->summary, sctx->propname, dout);
                break;
	}
	case PT_UINT64:
	{
		uint64_t dout;
		if (offset+sizeof(dout) > buflen) {
                        return CL_EFORMAT;
                }
                memcpy(&dout, databuf+offset, sizeof(dout));
                offset+=sizeof(dout);
                /* endian conversion */
		dout = sum64_endian_convert(dout);

		cli_jsonint64(sctx->summary, sctx->propname, dout);
                break;
	}
	case PT_BSTR:
	case PT_LPSTR:
		if (sctx->codepage == 0) {
			cli_dbgmsg("vba_propset_json: current codepage is unknown, cannot parse char stream\n");
			break;
		}
		else if (sctx->codepage != WINUNICODE) {
			uint32_t strsize;
			char *outstr;

			if (offset+sizeof(strsize) > buflen) {
				return CL_EFORMAT;
			}

			memcpy(&strsize, databuf+offset, sizeof(strsize));
			offset+=sizeof(strsize);
			/* no need for endian conversion */

			if (offset+strsize > buflen) {
				return CL_EFORMAT;
			}

			/* limitation on string length */
			if (strsize > PROPSTRLIMIT) {
				cli_dbgmsg("vba_process_prop: property string sized %lu truncated to size %lu\n",
					   (unsigned long)strsize, (unsigned long)PROPSTRLIMIT);
				strsize = PROPSTRLIMIT;
			}

			outstr = cli_malloc(strsize+1);
			if (!outstr) {
				return CL_EMEM;
			}
			strncpy(outstr, databuf+offset, strsize);
			outstr[strsize] = '\0'; /* guarentee a NULL-termination */
			cli_jsonstr(sctx->summary, sctx->propname, outstr);
			free(outstr);
			break;
		}
		/* fall-through for unicode strings */
	case PT_LPWSTR:
	{
		uint32_t strsize;
		char *outstr, *outstr2;

		if (offset+sizeof(strsize) > buflen) {
			return CL_EFORMAT;
		}
		memcpy(&strsize, databuf+offset, sizeof(strsize));
		offset+=sizeof(strsize);
		/* no need for endian conversion */
		if (proptype == PT_LPSTR) { /* fall-through specifics */
			if (strsize % 2) {
				return CL_EFORMAT;
			}
		}
		else {
			strsize*=2; /* Unicode strings are by length, not size */
		}

		if (offset+strsize > buflen) {
			return CL_EFORMAT;
		}
		outstr = cli_malloc(strsize+2);
		if (!outstr) {
			return CL_EMEM;
		}
		strncpy(outstr, databuf+offset, strsize);
		outstr[strsize-1] = '\0'; /* guarentee a UTF-16 NULL-termination */
		outstr[strsize] = '\0';

		outstr2 = (char*)get_property_name2(outstr, strsize);
		cli_jsonstr(sctx->summary, sctx->propname, outstr);
		free(outstr);
		free(outstr2);
		break;
	}
	case PT_FILETIME:
	{
		uint32_t ltime, htime;
#ifdef HAVE_JSON
#else
		uint64_t wtime = 0, utime =0;
#endif

		if (offset+sizeof(ltime)+sizeof(htime) > buflen) {
			return CL_EFORMAT;
		}
		memcpy(&ltime, databuf+offset, sizeof(ltime));
		offset+=sizeof(ltime);
		memcpy(&htime, databuf+offset, sizeof(htime));
		offset+=sizeof(ltime);
		ltime = sum32_endian_convert(ltime);
		htime = sum32_endian_convert(htime);

#ifdef HAVE_JSON
		/* Raw Output */
		{
			json_object *fpobj0, *fpobj1;
			json_object *fparr = json_object_new_array();
			if (NULL == fparr) {
				cli_errmsg("vba_process_prop: no memory for json array object.\n");
				return CL_EMEM;
			}

			fpobj0 = json_object_new_int(ltime);
			if (NULL == fpobj0) {
				cli_errmsg("vba_process_prop: no memory for json int object.\n");
				return CL_EMEM;
                        }
			fpobj1 = json_object_new_int(htime);
			if (NULL == fpobj1) {
				cli_errmsg("vba_process_prop: no memory for json int object.\n");
				return CL_EMEM;
                        }

			json_object_array_add(fparr, fpobj0);
			json_object_array_add(fparr, fpobj1);
			json_object_object_add(sctx->summary, sctx->propname, fparr);
		}
#else
		/* human-readable formatting */
		wtime = htime;
		wtime <<= 32;
		wtime |= ltime;

		utime = wtime / 10000000;
		utime -= 11644473600LL;
		
		cli_jsonstr(sctx->summary, sctx->propname, ctime((timer_t*)&utime));
#endif					       
		break;
	}
		/*
	case PT_BLOB:
	break;*/
	default:
		cli_dbgmsg("vba_process_prop: unhandled property type %04x for %s property\n", 
			   proptype, sctx->propname);
	}

	return CL_SUCCESS;
}

static int
cli_vba_docsum_propset_json(summary_ctx_t *sctx, fmap_t *sumfmap, propset_entry_t *entry)
{
	uint32_t size, numprops, limitprops;
	uint32_t propid, poffset;
	unsigned char *databuf, *ptr = NULL;
	unsigned i;
	int ret;

	sctx->codepage = 0;
	sctx->writecp = 0;
	sctx->propname = NULL;

	/* examine property set metadata */
	databuf = (unsigned char*)fmap_need_off_once(sumfmap, entry->offset, 8);
	if (!databuf) {
                return CL_EREAD;
        }
	memcpy(&size, databuf, sizeof(size));
	memcpy(&numprops, databuf+sizeof(size), sizeof(numprops));

	/* endian conversion */
	size = sum32_endian_convert(size);
	numprops = sum32_endian_convert(numprops);

	cli_dbgmsg("vba_docsum_propset_json: size: %u, numprops: %u\n", size, numprops);

	/* extract the property packet and advance past metadata */
	databuf = (unsigned char*)fmap_need_off_once(sumfmap, entry->offset, size);
	if (!databuf) {
                return CL_EREAD;
        }
	ptr = databuf+sizeof(size)+sizeof(numprops);

	if (numprops > PROPCNTLIMIT) {
		limitprops = PROPCNTLIMIT;
	}
	else {
		limitprops = numprops;
	}
	cli_dbgmsg("vba_docsum_propset_json: processing %u of %u (%u max) propeties\n",
		   limitprops, numprops, PROPCNTLIMIT);

	for (i = 0; i < limitprops; ++i) {
		memcpy(&propid, ptr, sizeof(propid));
		ptr+=4;
		memcpy(&poffset, ptr, sizeof(poffset));
		ptr+=4;
		/* endian conversion */
		propid = sum32_endian_convert(propid);
		poffset = sum32_endian_convert(poffset);

		cli_dbgmsg("vba_docsum_propset_json: propid: 0x%08x, poffset: %u\n", propid, poffset);

		sctx->propname = NULL; sctx->writecp = 0;
		switch(propid) {
		case DSPID_CODEPAGE:
			sctx->writecp = 1; /* must be set ONLY for codepage */
			if (!sctx->propname) sctx->propname = "CodePage";
		case DSPID_CATEGORY:
			if (!sctx->propname) sctx->propname = "Category";
		case DSPID_PRESFORMAT:
			if (!sctx->propname) sctx->propname = "PresentationTarget";
		case DSPID_BYTECOUNT:
			if (!sctx->propname) sctx->propname = "Bytes";
		case DSPID_LINECOUNT:
			if (!sctx->propname) sctx->propname = "Lines";
		case DSPID_PARCOUNT:
			if (!sctx->propname) sctx->propname = "Paragraphs";
		case DSPID_SLIDECOUNT:
			if (!sctx->propname) sctx->propname = "Slides";
		case DSPID_NOTECOUNT:
			if (!sctx->propname) sctx->propname = "Notes";
		case DSPID_HIDDENCOUNT:
			if (!sctx->propname) sctx->propname = "HiddenSlides";
		case DSPID_MMCLIPCOUNT:
			if (!sctx->propname) sctx->propname = "MMClips";
		case DSPID_SCALE:
			if (!sctx->propname) sctx->propname = "Scale";
		case DSPID_HEADINGPAIR: /* VT_VARIANT | VT_VECTOR */
			if (!sctx->propname) sctx->propname = "HeadingPairs";
		case DSPID_DOCPARTS:    /* VT_VECTOR | VT_LPSTR */
			if (!sctx->propname) sctx->propname = "DocPartTitles";
		case DSPID_MANAGER:
			if (!sctx->propname) sctx->propname = "Manager";
		case DSPID_COMPANY:
			if (!sctx->propname) sctx->propname = "Company";
		case DSPID_LINKSDIRTY:
			if (!sctx->propname) sctx->propname = "LinksDirty";
		case DSPID_CCHWITHSPACES:
			if (!sctx->propname) sctx->propname = "Char&WSCount";
		case DSPID_SHAREDDOC:   /* SHOULD BE FALSE! */
			if (!sctx->propname) sctx->propname = "SharedDoc";
		case DSPID_LINKBASE:    /* moved to user-defined */
			if (!sctx->propname) sctx->propname = "LinkBase";
		case DSPID_HLINKS:      /* moved to user-defined */
			if (!sctx->propname) sctx->propname = "HyperLinks";
		case DSPID_HYPERLINKSCHANGED:
			if (!sctx->propname) sctx->propname = "HyperLinksChanged";
		case DSPID_VERSION:
			if (!sctx->propname) sctx->propname = "Version";
		case DSPID_DIGSIG:
			if (!sctx->propname) sctx->propname = "DigitalSig";
		case DSPID_CONTENTTYPE:
			if (!sctx->propname) sctx->propname = "ContentType";
		case DSPID_CONTENTSTATUS:
			if (!sctx->propname) sctx->propname = "ContentStatus";
		case DSPID_LANGUAGE:
			if (!sctx->propname) sctx->propname = "Language";
		case DSPID_DOCVERSION:
			if (!sctx->propname) sctx->propname = "DocVersion";

			ret = cli_vba_process_prop(sctx, databuf, size, poffset);
			break;
		default:
			cli_dbgmsg("vba_docsum_propset_json: unrecognized propid!\n");
		}
	}

	return CL_SUCCESS;
}

static int
cli_vba_summary_propset_json(summary_ctx_t *sctx, fmap_t *sumfmap, propset_entry_t *entry)
{
	uint32_t size, numprops, limitprops;
	uint32_t propid, poffset;
	unsigned char *databuf, *ptr = NULL;
	unsigned i;
	int ret;

	sctx->codepage = 0;
	sctx->writecp = 0;
	sctx->propname = NULL;

	/* examine property set metadata */
	databuf = (unsigned char*)fmap_need_off_once(sumfmap, entry->offset, 8);
	if (!databuf) {
                return CL_EREAD;
        }
	memcpy(&size, databuf, sizeof(size));
	memcpy(&numprops, databuf+sizeof(size), sizeof(numprops));

	/* endian conversion */
	size = sum32_endian_convert(size);
	numprops = sum32_endian_convert(numprops);

	cli_dbgmsg("vba_summary_propset_json: size: %u, numprops: %u\n", size, numprops);

	/* extract the property packet and advance past metadata */
	databuf = (unsigned char*)fmap_need_off_once(sumfmap, entry->offset, size);
	if (!databuf) {
                return CL_EREAD;
        }
	ptr = databuf+sizeof(size)+sizeof(numprops);

	if (numprops > PROPCNTLIMIT) {
		limitprops = PROPCNTLIMIT;
	}
	else {
		limitprops = numprops;
	}
	cli_dbgmsg("vba_summary_propset_json: processing %u of %u (%u max) propeties\n",
		   limitprops, numprops, PROPCNTLIMIT);

	for (i = 0; i < limitprops; ++i) {
		memcpy(&propid, ptr, sizeof(propid));
		ptr+=4;
		memcpy(&poffset, ptr, sizeof(poffset));
		ptr+=4;
		/* endian conversion */
		propid = sum32_endian_convert(propid);
		poffset = sum32_endian_convert(poffset);

		cli_dbgmsg("vba_summary_propset_json: propid: 0x%08x, poffset: %u\n", propid, poffset);

		sctx->propname = NULL; sctx->writecp = 0;
		switch(propid) {
		case SPID_CODEPAGE:
			sctx->writecp = 1; /* must be set ONLY for codepage */
			if (!sctx->propname) sctx->propname = "CodePage";
		case SPID_TITLE:
			if (!sctx->propname) sctx->propname = "Title";
		case SPID_SUBJECT:
			if (!sctx->propname) sctx->propname = "Subject";
		case SPID_AUTHOR:
			if (!sctx->propname) sctx->propname = "Author";
		case SPID_KEYWORDS:
			if (!sctx->propname) sctx->propname = "Keywords";
		case SPID_COMMENTS:
			if (!sctx->propname) sctx->propname = "Comments";
		case SPID_TEMPLATE:
			if (!sctx->propname) sctx->propname = "Template";
		case SPID_LASTAUTHOR:
			if (!sctx->propname) sctx->propname = "LastAuthor";
		case SPID_REVNUMBER:
			if (!sctx->propname) sctx->propname = "RevNumber";
		case SPID_EDITTIME:
			if (!sctx->propname) sctx->propname = "EditTime";
		case SPID_LASTPRINTED:
			if (!sctx->propname) sctx->propname = "LastPrinted";
		case SPID_CREATEDTIME:
			if (!sctx->propname) sctx->propname = "CreatedTime";
		case SPID_MODIFIEDTIME:
			if (!sctx->propname) sctx->propname = "ModifiedTime";
		case SPID_PAGECOUNT:
			if (!sctx->propname) sctx->propname = "PageCount";
		case SPID_WORDCOUNT:
			if (!sctx->propname) sctx->propname = "WordCount";
		case SPID_CHARCOUNT:
			if (!sctx->propname) sctx->propname = "CharCount";
		case SPID_THUMBNAIL:
			if (!sctx->propname) sctx->propname = "Thumbnail";
		case SPID_APPNAME:
			if (!sctx->propname) sctx->propname = "AppName";
		case SPID_SECURITY:
			if (!sctx->propname) sctx->propname = "Security";

			ret = cli_vba_process_prop(sctx, databuf, size, poffset);
			break;
		default:
			cli_dbgmsg("vba_summary_propset_json: unrecognized propid!\n");
		}
	}

	return CL_SUCCESS;
}

int
cli_vba_summary_json(cli_ctx *ctx, int fd, int mode)
{
	summary_ctx_t sctx;
	fmap_t *sumfmap;
	summary_stub_t sumstub;
	propset_entry_t pentry[2];
	STATBUF statbuf;
	unsigned char *databuf;
	size_t maplen;
	int ret = CL_SUCCESS;

	if (ctx == NULL) {
		return -42;
	}
	sctx.ctx = ctx;

	if (fd < 0) {
		cli_dbgmsg("vba_summary_json: invalid file descriptor\n");
		return -42; /* placeholder */
	}

	if (FSTAT(fd, &statbuf) == -1) {
		cli_dbgmsg("vba_summary_json: cannot stat file descriptor\n");
		return CL_ESTAT;
	}

	sumfmap = fmap(fd, 0, statbuf.st_size);
	if (!sumfmap) {
		cli_dbgmsg("vba_summary_json: failed to get fmap\n");
		return CL_EMAP;
        }

	maplen = sumfmap->len;
	cli_dbgmsg("vba_summary_json: streamsize: %u\n", maplen);
	if (maplen < sizeof(summary_stub_t)) {
		cli_dbgmsg("vba_summary_json: stream is too small to contain summary stub!");
		return CL_EFORMAT;
	}
	databuf = (unsigned char*)fmap_need_off_once(sumfmap, 0, sizeof(summary_stub_t));
	if (!databuf) {
		return CL_EREAD;
	}

	/* Process the Summary Stream */
	memcpy(&sumstub, databuf, sizeof(summary_stub_t));

	/* endian conversion */
	sumstub.byte_order = le16_to_host(sumstub.byte_order);
	if (sumstub.byte_order != 0xfffe) {
		cli_dbgmsg("vba_summary_json: byteorder 0x%x is invalid\n", sumstub.byte_order);
		return CL_EFORMAT;
	}
	sumstub.version = sum16_endian_convert(sumstub.version);
	sumstub.system = sum32_endian_convert(sumstub.system);
	sumstub.num_propsets = sum32_endian_convert(sumstub.num_propsets);

	cli_dbgmsg("vba_summary_json: byteorder 0x%x\n", sumstub.byte_order);

	/* summary context setup */
	sctx.byte_order = sumstub.byte_order;
	sctx.version = sumstub.version;
#ifdef HAVE_JSON
	sctx.summary = json_object_new_object();
	if (!sctx.summary) {
		cli_errmsg("vba_summary_json: no memory for json object.\n");
		return CL_EMEM;
	}
#else
	sctx.summary = NULL;
#endif

	sctx.codepage = 0;
	sctx.writecp = 0;

        cli_dbgmsg("vba_summary_json: %u property set(s) detected\n", sumstub.num_propsets);
	if (sumstub.num_propsets == 1) {
		databuf = (unsigned char*)fmap_need_off_once(sumfmap, sizeof(summary_stub_t),
							     sizeof(propset_entry_t));
		if (!databuf) {
			return CL_EREAD;
		}
		memcpy(pentry, databuf, sizeof(summary_stub_t));
		/* endian conversion */
		pentry[0].offset = sum32_endian_convert(pentry[0].offset);

		/* TODO - check return and mode */
		if (!mode) {
			ret = cli_vba_summary_propset_json(&sctx, sumfmap, &pentry[0]);
#ifdef HAVE_JSON
			json_object_object_add(ctx->properties, "SummaryInfo", sctx.summary);
#endif
		}
		else {
			ret = cli_vba_docsum_propset_json(&sctx, sumfmap, &pentry[0]);
#ifdef HAVE_JSON
			json_object_object_add(ctx->properties, "DocSummaryInfo", sctx.summary);
#endif			
		}
	}
	else if (sumstub.num_propsets == 2) {
		databuf = (unsigned char*)fmap_need_off_once(sumfmap, sizeof(summary_stub_t),
							     2*sizeof(propset_entry_t));
		if (!databuf) {
			return CL_EREAD;
		}
		memcpy(pentry, databuf, 2*sizeof(summary_stub_t));
		/* endian conversion */
		pentry[0].offset = sum32_endian_convert(pentry[0].offset);
		pentry[1].offset = sum32_endian_convert(pentry[1].offset);

		/* multi-propset handling */
		/* first propset is user-defined, ignored for now */
                /* TODO - check return and mode */
                if (!mode) {
                        ret = cli_vba_summary_propset_json(&sctx, sumfmap, &pentry[0]);
#ifdef HAVE_JSON
                        json_object_object_add(ctx->properties, "SummaryInfo", sctx.summary);
#endif
                }
                else {
                        ret = cli_vba_docsum_propset_json(&sctx, sumfmap, &pentry[0]);
#ifdef HAVE_JSON
                        json_object_object_add(ctx->properties, "DocSummaryInfo", sctx.summary);
#endif
		}
	}
	else {
		cli_dbgmsg("vba_summary_json: invalid number of property sets\n");
		return CL_EFORMAT;
	}

        /*------DEBUG------
        int i;
        cli_dbgmsg("byte_order: %x\n", sumstub.byte_order);
        cli_dbgmsg("version: %x\n", sumstub.version);
        cli_dbgmsg("system: %x\n", sumstub.system);
        cli_dbgmsg("CLSID: ");
        for (i = 0; i < 16; ++i) {
            if (i == 3 || i == 5 || i == 7) {
                fprintf(stderr, "-");
            }
            fprintf(stderr, "%02x", sumstub.CLSID[i]);
        }
        fprintf(stderr, "\n");

        cli_dbgmsg("num_propsets: %u\n", sumstub.num_propsets);
        cli_dbgmsg("FMTID0: ");
        for (i = 0; i < 16; ++i) {
            if (i == 3 || i == 5 || i == 7) {
                fprintf(stderr, "-");
            }
            fprintf(stderr, "%02x", pentry[0].FMTID[i]);
        }
        fprintf(stderr, "\n");
        cli_dbgmsg("offset0: %u\n", pentry[0].offset);

        if (sumstub.num_propsets == 2) {
            cli_dbgmsg("FMTID1: ");
            for (i = 0; i < 16; ++i) {
                if (i == 3 || i == 5 || i == 7) {
                    fprintf(stderr, "-");
                }
                fprintf(stderr, "%02x", pentry[1].FMTID[i]);
            }
            fprintf(stderr, "\n");
            cli_dbgmsg("offset1: %u\n", pentry[1].offset);
        }

	json_object* newobj = json_object_new_object();
	json_object* obj0 = json_object_new_boolean(1);
	json_object* obj1 = json_object_new_boolean(0);
	json_object* obj2 = json_object_new_int(-1);
	//json_object* obj3 = json_object_new_int64(-64);

	json_object* obj4 = json_object_new_string("hello world!");
	json_object* obj5 = json_object_new_string_len("hello world!", 5);

	json_object_object_add(newobj, "bool", obj0);
	json_object_object_add(newobj, "bool", obj1);
	json_object_object_add(newobj, "int", obj2);
	//json_object_object_add(newobj, "int64", obj3);
	json_object_object_add(newobj, "string", obj4);
	json_object_object_add(newobj, "string_len", obj5);

	json_object_object_add(ctx->properties, "summary2", newobj);

        -----------------*/

	funmap(sumfmap);
	return ret;
}

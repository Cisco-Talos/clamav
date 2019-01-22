/*
 *  Extract VBA source code for component MS Office Documents
 *
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

#include "clamav.h"

#include "others.h"
#include "scanners.h"
#include "vba_extract.h"
#ifdef	CL_DEBUG
#include "mbox.h"
#endif
#include "blob.h"
#ifdef HAVE_JSON
#include "json.h"
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
				uint16_t x;
				if ((i + 1) >= size)
					break;
				x = (uint16_t)((name[i] << 8) | name[i + 1]);

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
    uint32_t hashcnt = 0;

	cli_dbgmsg("in cli_vba_readdir()\n");

	if(dir == NULL)
		return NULL;

	/*
	 * _VBA_PROJECT files are embedded within office documents (OLE2)
	 */
	
    if (CL_SUCCESS != uniq_get(U, "_vba_project", 12, &hash, &hashcnt)) {
        cli_dbgmsg("vba_readdir: uniq_get('_vba_project') failed. Unable to check # of embedded vba proj files\n");
		return NULL;
    }
    if (hashcnt == 0) {
        return NULL;
    }
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
        if (CL_SUCCESS != uniq_get(U, ptr, strlen(ptr), &hash, &hashcnt)) {
            cli_dbgmsg("vba_readdir: uniq_get('%s') failed.\n", ptr);
            free(ptr);
            break;
        }
        vba_project->colls[i] = hashcnt;
        if (0 == vba_project->colls[i]) {
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

	memset(buffer, 0, sizeof(buffer));
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
	ret = cli_magic_scandesc(ofd, fullname, ctx);
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

    ret = (vba_project_t *)cli_calloc(1, sizeof(struct vba_project_tag));

	if(ret == NULL) {
        cli_errmsg("create_vba_project: Unable to allocate memory for vba project structure\n");
		return NULL;
    }

	ret->name = (char **)cli_malloc(sizeof(char *) * record_count);
	ret->colls = (uint32_t *)cli_malloc(sizeof(uint32_t) * record_count);
	ret->dir = cli_strdup(dir);
	ret->offset = (uint32_t *)cli_malloc (sizeof(uint32_t) * record_count);

    if ((ret->colls == NULL) || (ret->name == NULL) || (ret->dir == NULL) || (ret->offset == NULL)) {
        cli_free_vba_project(ret);
        cli_errmsg("create_vba_project: Unable to allocate memory for vba project elements\n");
		return NULL;
	}
	ret->count = record_count;
	ret->U = U;

	return ret;
}

/**
 * @brief Free up the memory associated with the vba_project_t type.
 *
 * @param project A vba_project_t type allocated by one of these:
 *  - create_vba_project()
 *  - cli_wm_readdir()
 *  - cli_vba_readdir()
 */
void cli_free_vba_project(vba_project_t *vba_project)
{
    if (vba_project) {
        if (vba_project->dir)
            free(vba_project->dir);
        if (vba_project->colls)
            free(vba_project->colls);
        if (vba_project->name)
            free(vba_project->name);
        if (vba_project->offset)
            free(vba_project->offset);
        if (vba_project->length)
            free(vba_project->length);
        if (vba_project->key)
            free(vba_project->key);
        free(vba_project);
    }

    return;
}
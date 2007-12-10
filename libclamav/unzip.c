/*
 *  Copyright (C) 2003 - 2005 Tomasz Kojm <tkojm@clamav.net>
 *	      (C) 2006 Sensory Networks, Inc.
 *
 *  The code of this module was based on zziplib 0.12.83:
 *  (c) 1999 - 2002 Guido Draheim <guidod@gmx.de>, published under
 *  the Lesser GNU General Public License
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
#include <stdlib.h>
#include <zlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>

#include "clamav.h"
#include "others.h"
#include "unzip.h"

#define EC32(x) le32_to_host(x) /* Convert little endian to host */
#define EC16(x) le16_to_host(x)

#define __sizeof(X) ((ssize_t)(sizeof(X)))

#define ZIPBUFSIZ   1024
#define ZIP32K	    32768

inline static void __fixup_rootseek(off_t offset_of_trailer, struct zip_disk_trailer *trailer)
{
    if((off_t) EC32(trailer->z_rootseek) >
	offset_of_trailer - (off_t) EC32(trailer->z_rootsize) &&
	offset_of_trailer > (off_t) EC32(trailer->z_rootsize))
	    trailer->z_rootseek = (uint32_t) (offset_of_trailer -  EC32(trailer->z_rootsize)); 
}

static int __zip_find_disk_trailer(int fd, off_t filesize, struct zip_disk_trailer *trailer, off_t *start)
{
	char *buf, *end, *tail;
	off_t offset = 0, bufsize;
	struct zip_root_dirent dirent;
	uint32_t u_rootseek, shift = 0;
	int i;


    if(!trailer) {
	cli_errmsg("Unzip: __zip_find_disk_trailer: trailer == NULL\n");
	return CL_ENULLARG;
    }

    if(filesize < __sizeof(struct zip_disk_trailer)) {
	cli_errmsg("Unzip: __zip_find_disk_trailer: File too short\n");
	return CL_EFORMAT;
    }

    if(!(buf = cli_malloc(ZIPBUFSIZ)))
	return CL_EMEM;

    offset = filesize;
    while(1) {

	if(offset <= 0) {
	     cli_dbgmsg("Unzip: __zip_find_disk_trailer: Central directory not found\n");
	     free(buf);
	     return CL_EFORMAT;
	}

	if(offset >= ZIPBUFSIZ) {
	    if(offset == filesize)
		offset -= ZIPBUFSIZ;
	    else
		offset -= ZIPBUFSIZ - sizeof(struct zip_disk_trailer);

	    bufsize = ZIPBUFSIZ;
	} else {
	    if(filesize < ZIPBUFSIZ)
		bufsize = offset;
	    else
		bufsize = ZIPBUFSIZ;

	    offset = 0;
	}

        if(lseek(fd, offset, SEEK_SET) < 0) {
	    cli_errmsg("Unzip: __zip_find_disk_trailer: Can't lseek descriptor %d\n", fd);
	    free(buf);
	    return CL_EIO;
	}

        if(cli_readn(fd, buf, (size_t) bufsize) < (ssize_t) bufsize) {
	    cli_errmsg("Unzip: __zip_find_disk_trailer: Can't read %u bytes\n", (unsigned int) bufsize);
	    free(buf);
	    return CL_EIO;
	}

	end = buf + bufsize;
	for(tail = end - 1; tail >= buf; tail--) {
	    if((*tail == 'P') && (end - tail >= __sizeof(struct zip_disk_trailer) - 2) && cli_readint32(tail) == ZIP_DISK_TRAILER_MAGIC) {
		if(end - tail >= __sizeof(struct zip_disk_trailer)) {
		    memcpy(trailer, tail, sizeof(struct zip_disk_trailer)); 
		} else {
		    memcpy(trailer, tail, sizeof(struct zip_disk_trailer) - 2);
		    trailer->z_comment = 0; 
		}
		__fixup_rootseek(offset + tail - buf, trailer);

		u_rootseek = EC32(trailer->z_rootseek);
		if(u_rootseek > (uint32_t) filesize) {
		    cli_dbgmsg("Unzip: __zip_find_disk_trailer: u_rootseek > filesize, continue search\n");
		    continue;
		}

		for(i = 0; i < 2; i++) {
		    if(u_rootseek + shift + sizeof(dirent) < (uint32_t) filesize) {
			if(lseek(fd, u_rootseek + shift, SEEK_SET) < 0) {
			    cli_errmsg("Unzip: __zip_find_disk_trailer: Can't lseek descriptor %d\n", fd);
			    free(buf);
			    return CL_EIO;
			}

			if(cli_readn(fd, &dirent, sizeof(dirent)) < __sizeof(dirent)) {
			    cli_errmsg("Unzip: __zip_find_disk_trailer: Can't read %u bytes\n", (unsigned int) bufsize);
			    free(buf);
			    return CL_EIO;
			}

			if(EC32(dirent.z_magic) == ZIP_ROOT_DIRENT_MAGIC) {
			    cli_dbgmsg("Unzip: __zip_find_disk_trailer: found file header at %u, shift %u\n", u_rootseek + shift, shift);
			    free(buf);
			    *start = shift;
			    return CL_SUCCESS;
			}

			shift = *start;
		    }
		}
	    }
	}
    }

    /* this should never be reached */
    free(buf);
    return CL_EFORMAT;
}

static int __zip_parse_root_directory(int fd, struct zip_disk_trailer *trailer, zip_dir_hdr **hdr_return, off_t start)
{
	struct zip_root_dirent dirent, *d;
	zip_dir_hdr *hdr, *hdr0, *prev_hdr;
	uint16_t *p_reclen = NULL, entries;
	uint32_t offset;
	struct stat sb;
	uint16_t u_entries  = EC16(trailer->z_entries);   
	uint32_t u_rootsize = EC32(trailer->z_rootsize);  
	uint32_t u_rootseek = EC32(trailer->z_rootseek) + start;
	uint16_t u_extras, u_comment, u_namlen, u_flags;
	unsigned int bfcnt;
	char *pt;


    if(fstat(fd, &sb) == -1) {
	cli_errmsg("Unzip: __zip_parse_root_directory: Can't fstat file descriptor %d\n", fd);
	return CL_EIO;
    }

    if(!u_entries) {
	cli_errmsg("Unzip: __zip_parse_root_directory: File contains no entries\n");
	return CL_EFORMAT;
    }

    if(u_rootsize > (uint32_t) sb.st_size) {
	cli_errmsg("Unzip: __zip_parse_root_directory: Incorrect root size\n");
	return CL_EFORMAT;
    }

    hdr0 = (zip_dir_hdr*) cli_malloc(u_rootsize);
    if (!hdr0) 
        return CL_EMEM;

    hdr = hdr0;

    for(entries = u_entries, offset = 0; entries > 0; entries--) {

	if(lseek(fd, u_rootseek + offset, SEEK_SET) < 0) {
	    free(hdr0);
	    cli_errmsg("Unzip: __zip_parse_root_directory: Can't lseek descriptor %d\n", fd);
            return CL_EIO;
	}

        if(cli_readn(fd, &dirent, sizeof(dirent)) < __sizeof(dirent)) {
	    if(entries != u_entries) {
		entries = 0;
		break;
	    } else {
		free(hdr0);
		cli_dbgmsg("Unzip: __zip_parse_root_directory: Can't read %d bytes\n", sizeof(dirent));
		return CL_EIO;
	    }
	}
        d = &dirent;

	if(offset + sizeof(struct zip_root_dirent) > u_rootsize) {
	    cli_dbgmsg("Unzip: __zip_parse_root_directory: Entry %d outside of root directory\n", entries);
	    break;
	}

        u_extras  = EC16(d->z_extras); 
        u_comment = EC16(d->z_comment); 

        u_namlen  = EC16(d->z_namlen); 
	if(u_namlen > 1024) {
	    cli_dbgmsg("Unzip: __zip_parse_root_directory: Entry %d name too long\n", entries);
	    break;
	}

	u_flags   = EC16(d->z_flags);

        hdr->d_crc32 = EC32(d->z_crc32);
        hdr->d_csize = EC32(d->z_csize); 
        hdr->d_usize = EC32(d->z_usize); 
        hdr->d_off   = EC32(d->z_off) + start;

        hdr->d_compr = EC16(d->z_compr);

	bfcnt = 0;
	if(!hdr->d_compr && hdr->d_csize != hdr->d_usize) {
	    cli_dbgmsg("Unzip: __zip_parse_root_directory: File claims to be stored but csize != usize\n");
	    cli_dbgmsg("Unzip: __zip_parse_root_directory: Also checking for method 'deflated'\n");
	    hdr->d_bf[bfcnt] = ZIP_METHOD_DEFLATED;
	    bfcnt++;
	} else if(hdr->d_compr && hdr->d_csize == hdr->d_usize) {
	    cli_dbgmsg("Unzip: __zip_parse_root_directory: File claims to be deflated but csize == usize\n");
	    cli_dbgmsg("Unzip: __zip_parse_root_directory: Also checking for method 'stored'\n");
	    hdr->d_bf[bfcnt] = ZIP_METHOD_STORED;
	    bfcnt++;
	}
	hdr->d_bf[bfcnt] = -1;

	hdr->d_flags = u_flags;

	if(offset + sizeof(struct zip_root_dirent) + u_namlen > u_rootsize) {
	    cli_dbgmsg("Unzip: __zip_parse_root_directory: Name of entry %d outside of root directory\n", entries);
	    break;
	}

	if(cli_readn(fd, hdr->d_name, u_namlen) != u_namlen) {
	    cli_dbgmsg("Unzip: __zip_parse_root_directory: Can't read name of entry %d\n", entries);
	    break;
	}

        hdr->d_name[u_namlen] = '\0'; 
        hdr->d_namlen = u_namlen;

        offset += sizeof(struct zip_root_dirent) + u_namlen + u_extras + u_comment;

        if(offset > u_rootsize) {
	    cli_dbgmsg("Unzip: __zip_parse_root_directory: End of entry %d outside of root directory\n", entries);
	    break;
	}

	pt = (char *) hdr + sizeof(zip_dir_hdr) + u_namlen + 1;
	pt += ((long) pt) & 1;
	pt += ((long) pt) & 2;
	hdr->d_reclen = (uint16_t) (pt - (char *) hdr);
	p_reclen = &hdr->d_reclen;

	prev_hdr = hdr;
	hdr = (zip_dir_hdr *) ((char *) hdr + hdr->d_reclen);
    }

    if(p_reclen) {
	*p_reclen = 0;
	if(hdr_return) 
	    *hdr_return = hdr0;
    } else {
	free(hdr0);
    }

    return entries ? CL_EFORMAT : CL_SUCCESS;
}

int zip_dir_close(zip_dir *dir)
{
    if(dir->hdr0)
	free(dir->hdr0);

    if(dir->cache.fp)
	free(dir->cache.fp);

    if(dir->cache.buf32k)
	free(dir->cache.buf32k);

    free(dir);
    return CL_SUCCESS;
}

static int __zip_dir_parse(zip_dir *dir, off_t start)
{
	int ret;
	struct zip_disk_trailer trailer;
	struct stat sb;


    if(fstat(dir->fd, &sb) == -1) {
	cli_errmsg("Unzip: __zip_dir_parse: Can't fstat file descriptor %d\n", dir->fd);
	return CL_EIO;
    }

    if((ret = __zip_find_disk_trailer(dir->fd, sb.st_size, &trailer, &start)))
	return ret;

    if((ret = __zip_parse_root_directory(dir->fd, &trailer, &dir->hdr0, start)))
	return ret;

    return CL_SUCCESS;
}

zip_dir *zip_dir_open(int fd, off_t start, int *errcode_p)
{
	int ret;
	zip_dir * dir;


    dir = (zip_dir *) cli_calloc(1, sizeof(zip_dir));
    if(!dir) {
	if(errcode_p)
	    *errcode_p = CL_EMEM;
	return NULL;
    }

    if(start) {
	if(lseek(fd, start, SEEK_SET) == -1) {
	    cli_errmsg("Unzip: zip_dir_open: Can't lseek descriptor %d\n", fd);
	    if(errcode_p)
		*errcode_p = CL_EIO;
	    return NULL;
	}
    }

    dir->fd = fd;

    if((ret = __zip_dir_parse(dir, start))) {
	zip_dir_close(dir);
	if(errcode_p)
	    *errcode_p = CL_EMEM;
	return NULL;
    }

    dir->hdr = dir->hdr0;

    if(errcode_p)
	*errcode_p = CL_SUCCESS;

    return dir;
}

int zip_dir_read(zip_dir *dir, zip_dirent *d)
{

    if(!dir || !dir->hdr || !d)
	return 0;

    d->d_compr = dir->hdr->d_compr;
    d->d_csize = dir->hdr->d_csize;
    d->st_size = dir->hdr->d_usize;
    d->d_name  = dir->hdr->d_name;
    d->d_flags = dir->hdr->d_flags;
    d->d_off   = dir->hdr->d_off;
    d->d_crc32 = dir->hdr->d_crc32;

    if(!dir->hdr->d_reclen)
	dir->hdr = NULL;
    else
	dir->hdr = (zip_dir_hdr *) ((char *) dir->hdr + dir->hdr->d_reclen);

    return 1;
}

int zip_file_close(zip_file *fp)
{
	zip_dir *dir;


    if(!fp) {
	cli_errmsg("Unzip: zip_file_close: fp == NULL\n");
	return CL_ENULLARG;
    }

    inflateEnd(&fp->d_stream);

    dir = fp->dir;
    if(fp->buf32k) {
        if(!dir->cache.buf32k)
	    dir->cache.buf32k = fp->buf32k;
        else
	    free(fp->buf32k);
    }

    memset(fp, 0, sizeof(zip_file)); 

    if(!dir->cache.fp)
	dir->cache.fp = fp;
    else
	free(fp);

    return CL_SUCCESS;
}

static int __zip_inflate_init(zip_file *fp, zip_dir_hdr *hdr)
{
	int ret;
	fp->method = hdr->d_compr;
	fp->restlen = hdr->d_usize;


    if(fp->method) {
        memset(&fp->d_stream, 0, sizeof(fp->d_stream));

        ret = inflateInit2(&fp->d_stream, -MAX_WBITS);

        if(ret != Z_OK) {
	    cli_errmsg("Unzip: __zip_inflate_init: inflateInit2 failed\n");
	    return CL_EZIP;
	}

        fp->crestlen = hdr->d_csize;
    }

    return CL_SUCCESS;
}

zip_file *zip_file_open(zip_dir *dir, const char *name, int d_off)
{
	int ret;
	zip_file *fp = NULL;
	zip_dir_hdr *hdr = dir->hdr0;
        const char *hdr_name;
        ssize_t dataoff;
        struct zip_file_header *hp;
 

    if(!dir || dir->fd < 0) {
	cli_errmsg("Unzip: zip_file_open: dir == NULL || dir->fd <= 0\n");
	return NULL;
    }

    if(!hdr) {
	cli_errmsg("Unzip: zip_file_open: hdr == NULL\n");
	dir->errcode = CL_ENULLARG;
	return NULL;
    }

    while(1) {
	hdr_name = hdr->d_name;

        if(!strcmp(hdr_name, name) && (d_off == -1 || (uint32_t) d_off == hdr->d_off)) {
	    switch (hdr->d_compr) {
		case ZIP_METHOD_STORED:
		case ZIP_METHOD_DEFLATED:
		case ZIP_METHOD_DEFLATED64:
		    break;

		case ZIP_METHOD_SHRUNK:
		case ZIP_METHOD_REDUCEDx1:
		case ZIP_METHOD_REDUCEDx2:
		case ZIP_METHOD_REDUCEDx3:
		case ZIP_METHOD_REDUCEDx4:
		case ZIP_METHOD_IMPLODED:
		case ZIP_METHOD_TOKENIZED:
		case ZIP_METHOD_IMPLODED_DCL:
		case ZIP_METHOD_BZIP2:
		case ZIP_METHOD_AES:
		    cli_dbgmsg("Unzip: zip_file_open: Not supported compression method (%d)\n", hdr->d_compr);
		    dir->errcode = CL_ESUPPORT;
		    return NULL;

		default:
		    cli_errmsg("Unzip: zip_file_read: Unknown compression method (%d)\n", hdr->d_compr);
		    dir->errcode = CL_EFORMAT;
		    return NULL;
            }

            if(dir->cache.fp) {
                fp = dir->cache.fp;
		dir->cache.fp = NULL;
            } else {
                fp = (zip_file *) cli_calloc(1, sizeof(zip_file));
                if(!fp) {
		    dir->errcode = CL_EMEM;
		    return NULL;
		}
            }

            fp->dir = dir;

            if(dir->cache.buf32k) {
		fp->buf32k = dir->cache.buf32k;
		dir->cache.buf32k = NULL;
	    } else {
                fp->buf32k = (char *) cli_malloc(ZIP32K);
                if(!fp->buf32k) {
		    dir->errcode = CL_EMEM;
		    zip_file_close(fp);
		    return NULL;
		}
            }

            if(lseek(dir->fd, hdr->d_off, SEEK_SET) < 0) {
		cli_errmsg("Unzip: zip_file_open: Can't lseek descriptor %d\n", dir->fd);
		dir->errcode = CL_EIO;
		zip_file_close(fp);
		return NULL;
	    }

	    hp = (void *) fp->buf32k;
	    dataoff = cli_readn(dir->fd, (void *) hp, sizeof(struct zip_file_header));

	    if(dataoff < __sizeof(struct zip_file_header)) {
		cli_errmsg("Unzip: zip_file_open: Can't read zip header (only read %d bytes)\n", dataoff);
		dir->errcode = CL_EIO;
		zip_file_close(fp);
		return NULL;
	    }

	    dataoff = EC16(hp->z_namlen) + EC16(hp->z_extras);

            if(lseek(dir->fd, dataoff, SEEK_CUR) < 0) {
		cli_errmsg("Unzip: zip_file_open: Can't lseek descriptor %d\n", dir->fd);
		dir->errcode = CL_EIO;
		zip_file_close(fp);
		return NULL;
	    }

            fp->usize = hdr->d_usize;
            fp->csize = hdr->d_csize;

	    fp->bf = hdr->d_bf;

            ret = __zip_inflate_init(fp, hdr);

	    if(ret) {
		dir->errcode = CL_EIO;
		zip_file_close(fp);
		return NULL;
	    }

            return fp;

        } else {
            if(!hdr->d_reclen)
                break;

            hdr = (zip_dir_hdr *) ((char *) hdr + hdr->d_reclen);
        }
    }

    dir->errcode = CL_EOPEN;
    if(fp)
	zip_file_close(fp);
    return NULL;
}

ssize_t zip_file_read(zip_file *fp, char *buf, size_t len)
{
	zip_dir *dir; 
	size_t l;
	ssize_t bread;


    if(!fp || !fp->dir) {
	cli_errmsg("Unzip: zip_file_read: fp == NULL || fp->dir == NULL\n");
	return -1;
    }

    dir = fp->dir;
    l = fp->restlen > len ? len : fp->restlen;
    if(!fp->restlen)
        return 0;

    switch(fp->method) {

	case ZIP_METHOD_STORED:
	    bread = cli_readn(dir->fd, buf, l);
	    if(bread > 0) {
		fp->restlen -= bread;
	    } else if(bread < 0) {
		cli_errmsg("Unzip: zip_file_read: Can't read %d bytes\n", l);
		dir->errcode = CL_EIO;
	    }
	    return bread;

	case ZIP_METHOD_DEFLATED:
	case ZIP_METHOD_DEFLATED64:
	    fp->d_stream.avail_out = l;
	    fp->d_stream.next_out = (unsigned char *) buf;
	    do {
		int ret;
		size_t startlen;

		if(fp->crestlen > 0 && fp->d_stream.avail_in == 0) {
		    size_t cl = (fp->crestlen < ZIP32K ? fp->crestlen : ZIP32K);
		    ssize_t i = cli_readn(dir->fd, fp->buf32k, cl);
		    if(i <= 0) {
			dir->errcode = CL_EIO;
			cli_errmsg("Unzip: zip_file_read: Can't read %d bytes (read %d)\n", cl, i);
			return -1;
		    }
		    fp->crestlen -= i;
		    fp->d_stream.avail_in = i;
		    fp->d_stream.next_in = (unsigned char *) fp->buf32k;
		}

		startlen = fp->d_stream.total_out;
		ret = inflate(&fp->d_stream, Z_NO_FLUSH);

		if(ret == Z_STREAM_END) {
		    fp->restlen = 0;
		} else {
		    if(ret == Z_OK) {
			fp->restlen -= (fp->d_stream.total_out - startlen);
		    } else {
			if(fp->method == ZIP_METHOD_DEFLATED64) {
			    cli_dbgmsg("Unzip: zip_file_read: Not supported compression method (%u)\n", fp->method);
			    dir->errcode = CL_ESUPPORT;
			} else {
			    dir->errcode = CL_EZIP;
			}
			return -1;
		    }
		}
	    } while(fp->restlen && fp->d_stream.avail_out);

	    return l - fp->d_stream.avail_out;

	default:
	    /* this should not be reached because of the previous check in
	     * zip_file_open
	     */
	    cli_errmsg("Unzip: zip_file_read: Unknown compression method (%d)\n", fp->method);
	    dir->errcode = CL_EZIP;
	    return -1;
    }
}

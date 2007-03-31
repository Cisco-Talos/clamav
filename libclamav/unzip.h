/*
 *  Copyright (C) 2003 - 2006 Tomasz Kojm <tkojm@clamav.net>
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

#ifndef __UNZIP_H
#define __UNZIP_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>

#include "cltypes.h"

#ifndef HAVE_ATTRIB_PACKED
#define __attribute__(x)
#endif

#ifdef HAVE_PRAGMA_PACK
#pragma pack(1)
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack 1
#endif

/******** Zip format structures *********/

/* Local file header */
struct zip_file_header
{
#   define ZIP_FILE_HEADER_MAGIC 0x04034b50
    uint32_t	    z_magic;	    /* local file header signature */
    uint16_t	    z_version;	    /* version needed to extract */
    uint16_t	    z_flags;	    /* general purpose bit flag */
    uint16_t	    z_compr;	    /* compression method */
    uint16_t	    z_modtime;	    /* last mod file time */
    uint16_t	    z_moddate;	    /* last mod file date */
    uint32_t	    z_crc32;	    /* crc-32 */
    uint32_t	    z_csize;	    /* compressed size */
    uint32_t	    z_usize;	    /* uncompressed size */
    uint16_t	    z_namlen;	    /* file name length */
    uint16_t	    z_extras;	    /* extra field length */

    /* followed by filename (of variable size) */
    /* followed by extra field (of variable size) */
} __attribute__((packed));

/* Data descriptor (only if bit 3 of z_flags is set) */
struct zip_file_trailer
{
#   define ZIP_FILE_TRAILER_MAGIC 0x08074B50
    uint32_t z_magic; /* data descriptor signature (0x08074b50) */
    uint32_t z_crc32; /* crc-32 */
    uint32_t z_csize; /* compressed size */
    uint32_t z_usize; /* uncompressed size */
} __attribute__((packed));

/* Central file header */
struct zip_root_dirent
{
#   define ZIP_ROOT_DIRENT_MAGIC 0x02014b50
    uint32_t	    z_magic;	    /* central file header signature */
    uint16_t	    z_version1;	    /* version made by */
    uint16_t	    z_version2;	    /* version needed to extract */
    uint16_t	    z_flags;	    /* general purpose bit flag */
    uint16_t	    z_compr;	    /* compression method */
    uint16_t	    z_modtime;	    /* last mod file time */
    uint16_t	    z_moddate;	    /* last mod file date */
    uint32_t	    z_crc32;	    /* crc-32 */
    uint32_t	    z_csize;	    /* compressed size */
    uint32_t	    z_usize;	    /* uncompressed size */
    uint16_t	    z_namlen;	    /* file name length */
    uint16_t	    z_extras;	    /* extra field length */
    uint16_t	    z_comment;	    /* file comment length */
    uint16_t	    z_diskstart;    /* disk number start */
    uint16_t	    z_filetype;	    /* internal file attributes */
    uint32_t	    z_filemode;	    /* extrnal file attributes */
    uint32_t	    z_off;	    /* relative offset of local header */

    /* followed by filename (of variable size) */
    /* followed by extra field (of variable size) */
    /* followed by file comment (of variable size) */
} __attribute__((packed));

/* End of central directory record */
struct zip_disk_trailer
{
#   define	    ZIP_DISK_TRAILER_MAGIC 0x06054b50
    uint32_t	    z_magic;		/* end of central dir signature */
    uint16_t	    z_disk;		/* number of this disk */
    uint16_t	    z_finaldisk;	/* number of the disk with the start
					 * of the central dir
					 */
    uint16_t	    z_entries;		/* total number of entries in the
					 * central dir on this disk
					 */
    uint16_t	    z_finalentries;	/* total number of entries in the
					 * central dir
					 */
    uint32_t	    z_rootsize;		/* size of the central directory */
    uint32_t	    z_rootseek;		/* offset of start of central directory
					 * with respect to the starting disk
					 * number
					 */
    uint16_t	    z_comment;		/* zipfile comment length */

    /* followed by zipfile comment (of variable size) */
} __attribute__((packed));

#define ZIP_METHOD_STORED	    0
#define ZIP_METHOD_SHRUNK	    1
#define ZIP_METHOD_REDUCEDx1	    2
#define ZIP_METHOD_REDUCEDx2	    3
#define ZIP_METHOD_REDUCEDx3	    4
#define ZIP_METHOD_REDUCEDx4	    5
#define ZIP_METHOD_IMPLODED	    6
#define ZIP_METHOD_TOKENIZED	    7
#define ZIP_METHOD_DEFLATED	    8
#define ZIP_METHOD_DEFLATED64	    9
#define ZIP_METHOD_IMPLODED_DCL	    10
#define ZIP_METHOD_BZIP2	    12
#define ZIP_METHOD_AES		    99


/******** Internal structures *********/

struct __zip_file
{
    struct __zip_dir *dir; 
    uint16_t method;
    int16_t *bf;
    size_t restlen;
    size_t crestlen;
    size_t usize;
    size_t csize;
    char *buf32k;
    z_stream d_stream;
};

struct __zip_dir_hdr
{
    uint32_t    d_usize;	/* uncompressed size */
    uint32_t    d_csize;        /* compressed size */
    uint32_t    d_crc32;        /* crc-32 */
    uint32_t    d_off;          /* offset of file in zipfile */
    uint16_t    d_reclen;       /* next dir_hdr structure offset */
    uint16_t    d_namlen;       /* explicit namelen of d_name */
    uint16_t    d_compr;        /* compression type */
    int16_t	d_bf[2];	/* compression type/brute force */
    uint16_t	d_flags;	/* general purpose flags */
    char        d_name[1];      /* actual name of the entry */
};

struct __zip_dirent
{
    uint16_t 	d_compr;	/* compression method */
    uint32_t    d_csize;        /* compressed size */
    uint32_t 	st_size;	/* file size / decompressed size */
    uint16_t	d_flags;	/* general purpose flags */
    char	*d_name;	/* file name / strdupped name */
    uint32_t    d_crc32;        /* crc-32 */
    uint32_t    d_off;          /* the offset in the file */
};

struct __zip_dir
{
    int fd;
    int errcode;
    struct {
        struct __zip_file *fp;
        char *buf32k;
    } cache;
    struct __zip_dir_hdr *hdr0;
    struct __zip_dir_hdr *hdr;
    struct __zip_dirent dirent;
}; 

/* typedefs */
typedef struct __zip_dir	zip_dir;
typedef struct __zip_dir_hdr	zip_dir_hdr;
typedef struct __zip_file	zip_file;
typedef struct __zip_dirent 	zip_dirent;

zip_dir *zip_dir_open(int fd, off_t start, int *errcode_p);
int zip_dir_read(zip_dir *dir, zip_dirent *d);
zip_file *zip_file_open(zip_dir *dir, const char *name, int d_off);
ssize_t zip_file_read(zip_file *fp, char *buf, size_t len);
int zip_file_close(zip_file *fp);
int zip_dir_close(zip_dir *dir);

#ifdef HAVE_PRAGMA_PACK
#pragma pack()
#endif

#ifdef HAVE_PRAGMA_PACK_HPPA
#pragma pack
#endif

#endif /* __UNZIP_H */

/*
 * Author: 
 *	Guido Draheim <guidod@gmx.de>
 *
 *	Copyright (c) 2000,2001 Guido Draheim
 * 	    All rights reserved
 *	    use under the restrictions of the
 *	    Lesser GNU General Public License
 *
 *  The information was taken from appnote-981119-iz.zip
 *  at http://www.freesoftware.com/pub/infozip/doc/
 *  which in turn is based on PKWARE's appnote.txt
 */
#ifndef _ZZIP_FORMAT_H /* zzipformat.h */
#define _ZZIP_FORMAT_H
 
#include <zzip.h>
/* we have ICO C 9X types defined */

/* 
 * Overall zipfile format 
 *  [local file header + file data + data descriptr] ... [central directory] [EOD record] 
 */
 
# ifdef _MSC_VER
# pragma pack(push, 1)
# endif

struct zzip_version 
{ 
    char   version[1]; 
    char   ostype[1]; 
} __attribute__((packed));

struct zzip_dostime 
{ 
    char   time[2]; 
    char   date[2]; 
} __attribute__((packed)); 

#define ZZIP_CHECKMAGIC(__p,__A,__B,__C,__D) \
    ( (((char*)(__p))[0]==(__A)) && \
      (((char*)(__p))[1]==(__B)) && \
      (((char*)(__p))[2]==(__C)) && \
      (((char*)(__p))[3]==(__D)) )

/* A. Local file header */
struct zzip_file_header
{
#   define ZZIP_FILE_HEADER_MAGIC 0x04034b50
#   define ZZIP_FILE_HEADER_CHECKMAGIC(__p) ZZIP_CHECKMAGIC(__p,'P','K','\3','\4')
    char   z_magic[4]; /* local file header signature (0x04034b50) */
    struct zzip_version z_extract; /* version needed to extract */
    char   z_flags[2]; /* general purpose bit flag */
    char   z_compr[2]; /* compression method */
    struct zzip_dostime z_dostime; /* last mod file time (dos format) */
    char   z_crc32[4]; /* crc-32 */
    char   z_csize[4]; /* compressed size */
    char   z_usize[4]; /* uncompressed size */
    char   z_namlen[2]; /* filename length (null if stdin) */
    char   z_extras[2]; /* extra field length */
    /* followed by filename (of variable size) */
    /* followed by extra field (of variable size) */
} __attribute__((packed));

/* B. data descriptor 
 * the data descriptor exists only if bit 3 of z_flags is set. It is byte aligned
 * and immediately follows the last byte of compressed data. It is only used if
 * the output media of the compressor was not seekable, eg. standard output.
 */
struct zzip_file_trailer
{
#   define ZZIP_FILE_TRAILER_MAGIC 0x08074B50
#   define ZZIP_FILE_TRAILER_CHECKMAGIC(__p) ZZIP_CHECKMAGIC(__p,'P','K','\7','\8')
    uint32_t z_magic; /* data descriptor signature (0x08074b50) */
    uint32_t z_crc32; /* crc-32 */
    uint32_t z_csize; /* compressed size */
    uint32_t z_usize; /* uncompressed size */
} __attribute__((packed));

/* C. central directory structure:
    [file header] . . . end of central dir record  
*/

/* directory file header 
 * - a single entry including filename, extras and comment may not exceed 64k.
 */

struct zzip_root_dirent
{
#   define ZZIP_ROOT_DIRENT_MAGIC 0x02014b50
#   define ZZIP_ROOT_DIRENT_CHECKMAGIC(__p) ZZIP_CHECKMAGIC(__p,'P','K','\1','\2')
    char  z_magic[4];  /* central file header signature (0x02014b50) */
    struct zzip_version z_encoder;  /* version made by */
    struct zzip_version z_extract;  /* version need to extract */
    char  z_flags[2];  /* general purpose bit flag */
    char  z_compr[2];  /* compression method */
    struct zzip_dostime z_dostime;  /* last mod file time&date (dos format) */
    char  z_crc32[4];  /* crc-32 */
    char  z_csize[4];  /* compressed size */
    char  z_usize[4];  /* uncompressed size */
    char  z_namlen[2]; /* filename length (null if stdin) */
    char  z_extras[2];  /* extra field length */
    char  z_comment[2]; /* file comment length */
    char  z_diskstart[2]; /* disk number of start (if spanning zip over multiple disks) */
    char  z_filetype[2];  /* internal file attributes, bit0 = ascii */
    char  z_filemode[4];  /* extrnal file attributes, eg. msdos attrib byte */
    char  z_off[4];    /* relative offset of local file header, seekval if singledisk */
    /* followed by filename (of variable size) */
    /* followed by extra field (of variable size) */
    /* followed by file comment (of variable size) */
} __attribute__((packed)); 

/* end of central dir record */
struct zzip_disk_trailer
{
#   define ZZIP_DISK_TRAILER_MAGIC 0x06054b50
#   define ZZIP_DISK_TRAILER_CHECKMAGIC(__p) ZZIP_CHECKMAGIC(__p,'P','K','\5','\6')
    char  z_magic[4]; /* end of central dir signature (0x06054b50) */
    char  z_disk[2];  /* number of this disk */
    char  z_finaldisk[2]; /* number of the disk with the start of the central dir */
    char  z_entries[2]; /* total number of entries in the central dir on this disk */
    char  z_finalentries[2]; /* total number of entries in the central dir */
    char  z_rootsize[4]; /* size of the central directory */
    char  z_rootseek[4]; /* offset of start of central directory with respect to *
                          * the starting disk number */
    char  z_comment[2];  /* zipfile comment length */
    /* followed by zipfile comment (of variable size) */
} __attribute__((packed));

/* z_flags */
#define ZZIP_IS_ENCRYPTED(p)    ((*(unsigned char*)p)&1)
#define ZZIP_IS_COMPRLEVEL(p)  (((*(unsigned char*)p)>>1)&3)
#define ZZIP_IS_STREAMED(p)    (((*(unsigned char*)p)>>3)&1)

/* z_compr */
#define ZZIP_IS_STORED          0
#define ZZIP_IS_SHRUNK          1
#define ZZIP_IS_REDUCEDx1       2
#define ZZIP_IS_REDUCEDx2       3
#define ZZIP_IS_REDUCEDx3       4
#define ZZIP_IS_REDUCEDx4       5
#define ZZIP_IS_IMPLODED        6
#define ZZIP_IS_TOKENIZED       7
#define ZZIP_IS_DEFLATED        8
#define ZZIP_IS_DEFLATED_BETTER 9
#define ZZIP_IS_IMPLODED_BETTER 10

# ifdef _MSC_VER
# pragma pack(pop)
# endif

#endif /* _ZZIPFORMAT_H */





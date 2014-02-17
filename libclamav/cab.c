/*
 *  Copyright (C) 2007-2008 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm
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
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "libclamav/crypto.h"

#include "cltypes.h"
#include "others.h"
#include "mspack.h"
#include "cab.h"

#define EC32(x) cli_readint32(&x) /* Convert little endian to host */
#define EC16(x) cli_readint16(&x)

/* hard limits */
#define CAB_FOLDER_LIMIT    5000
#define CAB_FILE_LIMIT	    5000

/* Cabinet format data structures */

struct cab_hdr {
    uint32_t	signature;	/* file signature */
    uint32_t	res1;		/* reserved */
    uint32_t	cbCabinet;	/* size of cabinet file */
    uint32_t	res2;		/* reserved */
    uint32_t	coffFiles;	/* offset of the first file entry */
    uint32_t	res3;		/* reserved */
    uint8_t	versionMinor;   /* file format version, minor */
    uint8_t	versionMajor;	/* file format version, major */
    uint16_t	cFolders;	/* number of folder entries */
    uint16_t	cFiles;		/* number of file entries */
    uint16_t	flags;		/* option flags */
    uint16_t	setID;		/* multiple cabs related */
    uint16_t	iCabinet;	/* multiple cabs related */
};

struct cab_hdr_opt {
    uint16_t	cbCFHeader;	/* size of reserved header area */
    uint8_t	cbCFFolder;	/* size of reserved folder area */
    uint8_t	cbCFData;	/* size of reserved block area */
};

struct cab_folder_hdr
{
    uint32_t	coffCabStart;	/* offset of the first data block */
    uint16_t	cCFData;	/* number of data blocks */
    uint16_t	typeCompress;	/* compression type */
};

struct cab_file_hdr
{
    uint32_t	cbFile;		    /* uncompressed size */
    uint32_t	uoffFolderStart;    /* uncompressed offset of file in folder */
    uint16_t	iFolder;	    /* folder index */
    uint16_t	date;		    /* date stamp */
    uint16_t	time;		    /* time stamp */
    uint16_t	attribs;	    /* attribute flags */
};

struct cab_block_hdr
{
    uint32_t	csum;	    /* data block checksum */
    uint16_t	cbData;	    /* number of compressed bytes */
    uint16_t	cbUncomp;   /* number of uncompressed bytes */
};

static char *cab_readstr(fmap_t *map, off_t *offset, int *ret)
{
	int i;
	const char *str;
	char *retstr;

    if(!(str = fmap_need_offstr(map, *offset, 256))) {
	*ret = CL_EFORMAT;
	return NULL;
    }

    i = strlen(str) + 1;
    if(i>=255) {
	fmap_unneed_ptr(map, str, i);
	*ret = CL_EFORMAT;
	return NULL;
    }

    *offset += i;
    if((retstr = cli_malloc(i)))
	memcpy(retstr, str, i);
    fmap_unneed_ptr(map, str, i);

    if(!retstr) {
	*ret = CL_EMEM;
	return NULL;
    }

    *ret = CL_SUCCESS;
    return retstr;
}

static int cab_chkname(char *name, int san)
{
	size_t i, len = strlen(name);


    for(i = 0; i < len; i++) {
	if(!san && (strchr("%/*?|\\\"+=<>;:\t ", name[i]) || !isascii(name[i]))) {
	    cli_dbgmsg("cab_chkname: File name contains disallowed characters\n");
	    return 1;
	} else if(san && !isalnum(name[i])) {
	    name[i] = '*';
	}
    }

    return 0;
}

void cab_free(struct cab_archive *cab)
{
	struct cab_folder *folder;
	struct cab_file *file;


    if(cab->state) {
	if(cab->state->stream) {
	    switch(cab->state->cmethod & 0x000f) {
		case 0x0001:
		    mszip_free(cab->state->stream);
		    break;
		case 0x0002:
		    qtm_free(cab->state->stream);
		    break;
		case 0x0003:
		    lzx_free(cab->state->stream);
	    }
	}
	free(cab->state);
    }

    while(cab->folders) {
	folder = cab->folders;
	cab->folders = cab->folders->next;
	free(folder);
    }

    while(cab->files) {
	file = cab->files;
	cab->files = cab->files->next;
	free(file->name);
	free(file);
    }
}

int cab_open(fmap_t *map, off_t offset, struct cab_archive *cab)
{
	unsigned int i, folders = 0;
	struct cab_file *file, *lfile = NULL;
	struct cab_folder *folder, *lfolder = NULL;
	const struct cab_hdr *hdr;
	const struct cab_hdr_opt *hdr_opt;
	uint16_t fidx;
	uint32_t coffFiles;
	char *pt;
	int ret;
	off_t resfold = 0, rsize, cur_offset = offset;

    if(!(hdr=fmap_need_off_once(map, cur_offset, sizeof(*hdr)))) {
	cli_dbgmsg("cab_open: Can't read cabinet header\n");
	return CL_EFORMAT; /* most likely a corrupted file */
    }
    cur_offset += sizeof(*hdr);

    if(EC32(hdr->signature) != 0x4643534d) {
	cli_dbgmsg("cab_open: Incorrect CAB signature\n");
	return CL_EFORMAT;
    } else {
	cli_dbgmsg("CAB: -------------- Cabinet file ----------------\n");
    }

    rsize = map->len;

    memset(cab, 0, sizeof(struct cab_archive));

    cab->length = EC32(hdr->cbCabinet);
    cli_dbgmsg("CAB: Cabinet length: %u\n", cab->length);
    if((off_t) cab->length > rsize) {
	cli_dbgmsg("CAB: Truncating file size from %lu to %lu\n", (unsigned long int) cab->length, (unsigned long int) rsize);
	cab->length = (uint32_t) rsize;
    }

    cab->nfolders = EC16(hdr->cFolders);
    if(!cab->nfolders) {
	cli_dbgmsg("cab_open: No folders in cabinet (fake cab?)\n");
	return CL_EFORMAT;
    } else {
	cli_dbgmsg("CAB: Folders: %u\n", cab->nfolders);
	if(cab->nfolders > CAB_FOLDER_LIMIT) {
	    cab->nfolders = CAB_FOLDER_LIMIT;
	    cli_dbgmsg("CAB: *** Number of folders limited to %u ***\n", cab->nfolders);
	}
    }

    cab->nfiles = EC16(hdr->cFiles);
    if(!cab->nfiles) {
	cli_dbgmsg("cab_open: No files in cabinet (fake cab?)\n");
	return CL_EFORMAT;
    } else {
	cli_dbgmsg("CAB: Files: %u\n", cab->nfiles);
	if(cab->nfiles > CAB_FILE_LIMIT) {
	    cab->nfiles = CAB_FILE_LIMIT;
	    cli_dbgmsg("CAB: *** Number of files limited to %u ***\n", cab->nfiles);
	}
    }

    cli_dbgmsg("CAB: File format version: %u.%u\n", hdr->versionMajor, hdr->versionMinor);

    cab->flags = EC16(hdr->flags);
    coffFiles = EC16(hdr->coffFiles);

    if(cab->flags & 0x0004) {
	if(!(hdr_opt = fmap_need_off_once(map, cur_offset, sizeof(*hdr_opt)))) {
	    cli_dbgmsg("cab_open: Can't read file header (fake cab?)\n");
	    return CL_EFORMAT; /* most likely a corrupted file */
	}

	cab->reshdr = EC16(hdr_opt->cbCFHeader);
	resfold = hdr_opt->cbCFFolder;
	cab->resdata = hdr_opt->cbCFData;

	cur_offset += sizeof(*hdr_opt) + cab->reshdr;
	if(cab->reshdr) {
	    if(cab->reshdr >= rsize) {
		cli_dbgmsg("cab_open: Can't lseek to %u (fake cab?)\n", cab->reshdr);
		return CL_EFORMAT; /* most likely a corrupted file */
	    }
	}
    }

    if(cab->flags & 0x0001) { /* preceding cabinet */
	/* name */
	pt = cab_readstr(map, &cur_offset, &ret);
	if(ret)
	    return ret;
	if(cab_chkname(pt, 0))
	    cli_dbgmsg("CAB: Invalid name of preceding cabinet\n");
	else
	    cli_dbgmsg("CAB: Preceding cabinet name: %s\n", pt);
	free(pt);
	/* info */
	pt = cab_readstr(map, &cur_offset, &ret);
	if(ret)
	    return ret;
	if(cab_chkname(pt, 0))
	    cli_dbgmsg("CAB: Invalid info for preceding cabinet\n");
	else
	    cli_dbgmsg("CAB: Preceding cabinet info: %s\n", pt);
	free(pt);
    }

    if(cab->flags & 0x0002) { /* next cabinet */
	/* name */
	pt = cab_readstr(map, &cur_offset, &ret);
	if(ret)
	    return ret;
	if(cab_chkname(pt, 0))
	    cli_dbgmsg("CAB: Invalid name of next cabinet\n");
	else
	    cli_dbgmsg("CAB: Next cabinet name: %s\n", pt);
	free(pt);
	/* info */
	pt = cab_readstr(map, &cur_offset, &ret);
	if(ret)
	    return ret;
	if(cab_chkname(pt, 0))
	    cli_dbgmsg("CAB: Invalid info for next cabinet\n");
	else
	    cli_dbgmsg("CAB: Next cabinet info: %s\n", pt);
	free(pt);
    }

    /* folders */
    for(i = 0; i < cab->nfolders; i++) {
	const struct cab_folder_hdr *folder_hdr;

	if(!(folder_hdr = fmap_need_off_once(map, cur_offset, sizeof(*folder_hdr)))) {
	    cli_dbgmsg("cab_open: Can't read header for folder %u\n", i);
	    break;
	}

	cur_offset += sizeof(*folder_hdr) + resfold;

	if(EC32(folder_hdr->coffCabStart) + offset > rsize) {
	    cli_dbgmsg("CAB: Folder out of file\n");
	    continue;
	}

	if((EC16(folder_hdr->typeCompress) & 0x000f) > 3) {
	    cli_dbgmsg("CAB: Unknown compression method\n");
	    continue;
	}

	folder = (struct cab_folder *) cli_calloc(1, sizeof(struct cab_folder));
	if(!folder) {
	    cli_errmsg("cab_open: Can't allocate memory for folder\n");
	    cab_free(cab);
	    return CL_EMEM;
	}

	folder->cab = (struct cab_archive *) cab;
	folder->offset = (off_t) EC32(folder_hdr->coffCabStart) + offset;
	folder->nblocks = EC16(folder_hdr->cCFData);
	folder->cmethod = EC16(folder_hdr->typeCompress);

	cli_dbgmsg("CAB: Folder record %u\n", i);
	cli_dbgmsg("CAB: Folder offset: %u\n", (unsigned int) folder->offset);
	cli_dbgmsg("CAB: Folder compression method: %d\n", folder->cmethod);

	if(!lfolder)
	    cab->folders = folder;
	else
	    lfolder->next = folder;

	lfolder = folder;
	folders++;
    }
    cli_dbgmsg("CAB: Recorded folders: %u\n", folders);

    /* files */
    if(cab->nfolders != folders) {
	if(coffFiles >= rsize) {
	    cli_dbgmsg("cab_open: Can't lseek to hdr.coffFiles\n");
	    cab_free(cab);
	    return CL_EFORMAT;
	}
	cur_offset = coffFiles;
    }
    for(i = 0; i < cab->nfiles; i++) {
	const struct cab_file_hdr *file_hdr;

	if(!(file_hdr = fmap_need_off_once(map, cur_offset, sizeof(*file_hdr)))) {
	    cli_dbgmsg("cab_open: Can't read file %u header\n", i);
	    break;
	}
	cur_offset += sizeof(*file_hdr);

	file = (struct cab_file *) cli_calloc(1, sizeof(struct cab_file));
	if(!file) {
	    cli_errmsg("cab_open: Can't allocate memory for file\n");
	    cab_free(cab);
	    return CL_EMEM;
	}

	file->cab = cab;
	cab->map = map;
	file->offset = EC32(file_hdr->uoffFolderStart);
	file->length = EC32(file_hdr->cbFile);
	file->attribs = EC16(file_hdr->attribs);
	fidx = EC16(file_hdr->iFolder);
	file->error = CL_SUCCESS;

	file->name = cab_readstr(map, &cur_offset, &ret);
	if(ret) {
	    free(file);
	    continue;
	}
	cab_chkname(file->name, 1);

	cli_dbgmsg("CAB: File record %u\n", i);
	cli_dbgmsg("CAB: File name: %s\n", file->name);
	cli_dbgmsg("CAB: File offset: %u\n", (unsigned int) file->offset);
	cli_dbgmsg("CAB: File folder index: %u\n", fidx);
	cli_dbgmsg("CAB: File attribs: 0x%x\n", file->attribs);
	if(file->attribs & 0x01)
	    cli_dbgmsg("CAB:   * file is read-only\n");
	if(file->attribs & 0x02)
	    cli_dbgmsg("CAB:   * file is hidden\n");
	if(file->attribs & 0x04)
	    cli_dbgmsg("CAB:   * file is a system file\n");
	if(file->attribs & 0x20)
	    cli_dbgmsg("CAB:   * file modified since last backup\n");
	if(file->attribs & 0x40)
	    cli_dbgmsg("CAB:   * file to be run after extraction\n");
	if(file->attribs & 0x80)
	    cli_dbgmsg("CAB:   * file name contains UTF\n");

	/* folder index */
	if(fidx < 0xfffd) {
	    if(fidx > cab->nfolders) {
		cli_dbgmsg("cab_open: File %s is not associated with any folder\n", file->name);
		free(file->name);
		free(file);
		continue;
	    }

	    file->folder = cab->folders;
	    while(file->folder && fidx--)
		file->folder = file->folder->next;

	    if(!file->folder) {
		cli_dbgmsg("cab_open: Folder not found for file %s\n", file->name);
		free(file->name);
		free(file);
		continue;
	    }

	} else {
	    cli_dbgmsg("CAB: File is split *skipping*\n");
	    free(file->name);
	    free(file);
	    continue;
	}

	if(!lfile)
	    cab->files = file;
	else
	    lfile->next = file;

	lfile = file;

    }

    return CL_SUCCESS;
}

static int cab_read_block(struct cab_file *file)
{
	const struct cab_block_hdr *block_hdr;
	struct cab_state *state = file->cab->state;

    if(!(block_hdr = fmap_need_off_once(file->cab->map, file->cab->cur_offset, sizeof(*block_hdr)))) {
	cli_dbgmsg("cab_read_block: Can't read block header\n");
	return CL_EFORMAT; /* most likely a corrupted file */
    }

    file->cab->cur_offset += sizeof(*block_hdr) + file->cab->resdata;
    state->blklen = EC16(block_hdr->cbData);
    state->outlen = EC16(block_hdr->cbUncomp);

    if(fmap_readn(file->cab->map, state->block, file->cab->cur_offset, state->blklen) != state->blklen) {
	cli_dbgmsg("cab_read_block: Can't read block data\n");
	return CL_EFORMAT; /* most likely a corrupted file */
    }

    file->cab->cur_offset += state->blklen;
    state->pt = state->end = state->block;
    state->end += state->blklen;

    return CL_SUCCESS;
}

static int cab_read(struct cab_file *file, unsigned char *buffer, int bytes)
{
	uint16_t todo, left;


    if((file->cab->state->blknum > file->folder->nblocks) && !file->lread) {
	file->error = CL_BREAK;
	return -1;
    }

    todo = bytes;
    while(todo > 0) {
	left = file->cab->state->end - file->cab->state->pt;

	if(left) {
	    if(left > todo)
		left = todo;

	    memcpy(buffer, file->cab->state->pt, left);
	    file->cab->state->pt += left;
	    buffer += left;
	    todo -= left;

	} else {
	    if(file->cab->state->blknum++ >= file->folder->nblocks)
		break;

	    file->error = cab_read_block(file);
	    if(file->error)
		return -1;

	    if((file->folder->cmethod & 0x000f) == 0x0002) /* Quantum hack */
		*file->cab->state->end++ = 0xff;

	    if(file->cab->state->blknum >= file->folder->nblocks) {
		if((file->folder->cmethod & 0x000f) == 0x0003) { /* LZX hack */
		    lzx_set_output_length(file->cab->state->stream, (off_t) ((file->cab->state->blknum - 1) * 32768 + file->cab->state->outlen));
		}
	    } else {
		if(file->cab->state->outlen != 32768) {
		    cli_dbgmsg("cab_read: WARNING: partial data block\n");
		}
	    }
	}
    }

    return file->lread = bytes - todo;
}

static int cab_unstore(struct cab_file *file)
{
	int todo, bread, bytes = file->length;
	unsigned char buff[4096];


    if(bytes < 0) {
	cli_dbgmsg("cab_unstore: bytes < 0\n");
	return CL_EFORMAT;
    }

    todo = MIN((unsigned int) bytes, file->max_size);

    while(1) {

	if((unsigned int) todo <= sizeof(buff))
	    bread = todo;
	else
	    bread = sizeof(buff);

	if((bread = cab_read(file, buff, bread)) == -1) {
	    cli_dbgmsg("cab_unstore: cab_read failed\n");
	    return file->error;
	} else if(cli_writen(file->ofd, buff, bread) != bread) {
	    cli_warnmsg("cab_unstore: Can't write %d bytes to descriptor %d\n", bread, file->ofd);
	    return CL_EWRITE;
	}

	todo -= bread;

	if(!bread || todo <= 0)
	    break;
    }

    return CL_SUCCESS;
}

#define CAB_CHGFOLDER							\
    if(!file->cab->actfol || (file->folder != file->cab->actfol)        \
       || (file->cab->state && file->cab->state->cmethod != file->folder->cmethod)) { \
	if(file->cab->state) {						\
	    if(file->cab->state->stream) {				\
		switch(file->cab->state->cmethod & 0x000f) {		\
		    case 0x0001:					\
			mszip_free(file->cab->state->stream);		\
			break;						\
		    case 0x0002:					\
			qtm_free(file->cab->state->stream);		\
			break;						\
		    case 0x0003:					\
			lzx_free(file->cab->state->stream);		\
		}							\
	    }								\
	    free(file->cab->state);					\
	    file->cab->state = NULL;					\
	}								\
	file->cab->cur_offset = file->folder->offset;			\
	file->cab->state = (struct cab_state *) cli_calloc(1, sizeof(struct cab_state));	\
	if(!file->cab->state) {						\
	    cli_errmsg("cab_extract: Can't allocate memory for internal state\n");	   	\
	    close(file->ofd);						\
	    return CL_EMEM;						\
	}								\
	file->cab->state->cmethod = file->folder->cmethod;		\
	switch(file->folder->cmethod & 0x000f) {			\
	    case 0x0001:						\
		file->cab->state->stream = (struct mszip_stream *) mszip_init(file->ofd, 4096, 1, file, &cab_read);	\
		break;							\
	    case 0x0002:						\
		file->cab->state->stream = (struct qtm_stream *) qtm_init(file->ofd, (int) (file->folder->cmethod >> 8) & 0x1f, 4096, file, &cab_read);									\
		break;							\
	    case 0x0003:						\
		file->cab->state->stream = (struct lzx_stream *) lzx_init(file->ofd, (int) (file->folder->cmethod >> 8) & 0x1f, 0, 4096, 0, file, &cab_read);									\
	}								\
	if((file->folder->cmethod & 0x000f) && !file->cab->state->stream) { \
	    close(file->ofd);						\
	    return CL_EUNPACK;						\
	}								\
	file->cab->actfol = file->folder;				\
    } else {								\
    	if(file->cab->state && file->cab->state->stream) {		\
	    switch(file->cab->state->cmethod & 0x000f) {		\
		case 0x0001:						\
		    ((struct mszip_stream *) file->cab->state->stream)->ofd = file->ofd;	\
		    break;						\
		case 0x0002:						\
		    ((struct qtm_stream *) file->cab->state->stream)->ofd = file->ofd;	     	\
		    break;						\
		case 0x0003:						\
		    ((struct lzx_stream *) file->cab->state->stream)->ofd = file->ofd;	      	\
		    break;						\
	    }								\
	}								\
    }


int cab_extract(struct cab_file *file, const char *name)
{
	int ret;


    if(!file || !name) {
	cli_errmsg("cab_extract: !file || !name\n");
	return CL_ENULLARG;
    }

    if(!file->folder) {
	cli_errmsg("cab_extract: file->folder == NULL\n");
	return CL_ENULLARG;
    }

    file->ofd = open(name, O_WRONLY|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU);
    if(file->ofd == -1) {
	cli_errmsg("cab_extract: Can't open file %s in write mode\n", name);
	return CL_ECREAT;
    }

    switch(file->folder->cmethod & 0x000f) {
	case 0x0000: /* STORE */
	    cli_dbgmsg("CAB: Compression method: STORED\n");
	    CAB_CHGFOLDER;
	    if(file->length > file->cab->length) {
		cli_dbgmsg("cab_extract: Stored file larger than archive itself, trimming down\n");
		file->length = file->cab->length;
	    }
	    ret = cab_unstore(file);
	    break;

	case 0x0001: /* MSZIP */
	    cli_dbgmsg("CAB: Compression method: MSZIP\n");
	    CAB_CHGFOLDER;
	    ret = mszip_decompress(file->cab->state->stream, file->length);
	    break;

	case 0x0002: /* QUANTUM */
	    cli_dbgmsg("CAB: Compression method: QUANTUM\n");
	    CAB_CHGFOLDER;
	    ret = qtm_decompress(file->cab->state->stream, file->length);
	    break;

	case 0x0003: /* LZX */
	    cli_dbgmsg("CAB: Compression method: LZX\n");
	    CAB_CHGFOLDER;
	    ret = lzx_decompress(file->cab->state->stream, file->length);
	    break;

	default:
	    cli_dbgmsg("CAB: Not supported compression method: 0x%x\n", file->folder->cmethod & 0x000f);
	    ret = CL_EFORMAT;
    }

    close(file->ofd);

    if(ret == CL_BREAK)
	ret = CL_SUCCESS;

    return ret;
}

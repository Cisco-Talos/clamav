/*
 *  Copyright (C) 2006 Tomasz Kojm <tkojm@clamav.net>
 *
 *  This code is based on the work of Stuart Caie and the official
 *  specification.
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

#include "cltypes.h"
#include "others.h"
#include "mspack.h"
#include "cab.h"

#define EC32(x) le32_to_host(x) /* Convert little endian to host */
#define EC16(x) le16_to_host(x)

#ifndef O_BINARY
#define O_BINARY        0
#endif

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

static char *cab_readstr(int fd, int *ret)
{
	int i, bread, found = 0;
	char buff[256], *str;
	off_t pos;


    if((pos = lseek(fd, 0, SEEK_CUR)) == -1) {
	*ret = CL_EIO;
	return NULL;
    }

    bread = read(fd, buff, sizeof(buff));
    for(i = 0; i < bread; i++) {
	if(!buff[i]) {
	    found = 1;
	    break;
	}
    }

    if(!found) {
	*ret = CL_EFORMAT;
	return NULL;
    }

    if(lseek(fd, (off_t) (pos + i + 1), SEEK_SET) == -1) {
	*ret = CL_EIO;
	return NULL;
    }

    if(!(str = cli_strdup(buff))) {
	*ret = CL_EMEM;
	return NULL;
    }

    *ret = CL_SUCCESS;
    return str;
}

static int cab_chkname(const char *name)
{
	size_t i, len = strlen(name);


    for(i = 0; i < len; i++) {
	if(strchr("%/*?|\\\"+=<>;:\t ", name[i]) || !isascii(name[i])) {
	    cli_dbgmsg("cab_chkname: File name contains disallowed characters\n");
	    return 1;
	}
    }

    return 0;
}

void cab_free(struct cab_archive *cab)
{
	struct cab_folder *folder;
	struct cab_file *file;


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

int cab_open(int fd, off_t offset, struct cab_archive *cab)
{
	unsigned int i, bscore = 0, badname = 0;
	struct cab_file *file, *lfile = NULL;
	struct cab_folder *folder, *lfolder = NULL;
	struct cab_hdr hdr;
	struct cab_hdr_opt hdr_opt;
	struct cab_folder_hdr folder_hdr;
	struct cab_file_hdr file_hdr;
	struct stat sb;
	uint16_t fidx;
	char *pt;
	int ret;
	off_t resfold = 0, rsize;


    if(lseek(fd, offset, SEEK_SET) == -1) {
	cli_errmsg("cab_open: Can't lseek to %u (offset)\n", (unsigned int) offset);
	return CL_EIO;
    }

    if(cli_readn(fd, &hdr, sizeof(hdr)) != sizeof(hdr)) {
	cli_dbgmsg("cab_open: Can't read cabinet header\n");
	return CL_EIO;
    }

    if(EC32(hdr.signature) != 0x4643534d) {
	cli_dbgmsg("cab_open: Incorrect CAB signature\n");
	return CL_EFORMAT;
    } else {
	cli_dbgmsg("CAB: -------------- Cabinet file ----------------\n");
    }

    if(fstat(fd, &sb) == -1) {
	cli_errmsg("cab_open: Can't fstat descriptor %d\n", fd);
	return CL_EIO;
    }
    rsize = sb.st_size;

    memset(cab, 0, sizeof(struct cab_archive));

    cab->length = EC32(hdr.cbCabinet);
    cli_dbgmsg("CAB: Cabinet length: %u\n", cab->length);
    if((off_t) cab->length > rsize)
	bscore++;

    cab->nfolders = EC16(hdr.cFolders);
    if(!cab->nfolders) {
	cli_dbgmsg("cab_open: No folders in cabinet (fake cab?)\n");
	return CL_EFORMAT;
    } else {
	cli_dbgmsg("CAB: Folders: %u\n", cab->nfolders);
	if(cab->nfolders > CAB_FOLDER_LIMIT) {
	    cab->nfolders = CAB_FOLDER_LIMIT;
	    cli_dbgmsg("CAB: *** Number of folders limited to %u ***\n", cab->nfolders);
	    bscore++;
	}
    }

    cab->nfiles = EC16(hdr.cFiles);
    if(!cab->nfiles) {
	cli_dbgmsg("cab_open: No files in cabinet (fake cab?)\n");
	return CL_EFORMAT;
    } else {
	cli_dbgmsg("CAB: Files: %u\n", cab->nfiles);
	if(cab->nfiles > CAB_FILE_LIMIT) {
	    cab->nfiles = CAB_FILE_LIMIT;
	    cli_dbgmsg("CAB: *** Number of files limited to %u ***\n", cab->nfiles);
	    bscore++;
	}
    }

    cli_dbgmsg("CAB: File format version: %u.%u\n", hdr.versionMajor, hdr.versionMinor);
    if(hdr.versionMajor != 1 || hdr.versionMinor != 3)
	bscore++;

    cab->flags = EC16(hdr.flags);
    if(cab->flags & 0x0004) {
	if(cli_readn(fd, &hdr_opt, sizeof(hdr_opt)) != sizeof(hdr_opt)) {
	    cli_dbgmsg("cab_open: Can't read file header (fake cab?)\n");
	    return CL_EIO;
	}

	cab->reshdr = EC16(hdr_opt.cbCFHeader);
	resfold = hdr_opt.cbCFFolder;
	cab->resdata = hdr_opt.cbCFData;

	if(cab->reshdr) {
	    if(lseek(fd, cab->reshdr, SEEK_CUR) == -1) {
		cli_dbgmsg("cab_open: Can't lseek to %u (fake cab?)\n", cab->reshdr);
		return CL_EIO;
	    }
	}
    }

    if(cab->flags & 0x0001) { /* preceeding cabinet */
	/* name */
	pt = cab_readstr(fd, &ret);
	if(ret)
	    return ret;
	if(cab_chkname(pt))
	    badname = 1;
	else
	    cli_dbgmsg("CAB: Preceeding cabinet name: %s\n", pt);
	free(pt);
	/* info */
	pt = cab_readstr(fd, &ret);
	if(ret)
	    return ret;
	if(cab_chkname(pt))
	    badname = 1;
	else
	    cli_dbgmsg("CAB: Preceeding cabinet info: %s\n", pt);
	free(pt);
    }

    if(cab->flags & 0x0002) { /* next cabinet */
	/* name */
	pt = cab_readstr(fd, &ret);
	if(ret)
	    return ret;
	if(cab_chkname(pt))
	    badname = 1;
	else
	    cli_dbgmsg("CAB: Next cabinet name: %s\n", pt);
	free(pt);
	/* info */
	pt = cab_readstr(fd, &ret);
	if(ret)
	    return ret;
	if(cab_chkname(pt))
	    badname = 1;
	else
	    cli_dbgmsg("CAB: Next cabinet info: %s\n", pt);
	free(pt);
    }
    bscore += badname;

    if(bscore >= 4) {
	cli_dbgmsg("CAB: bscore == %u, most likely a fake cabinet\n", bscore);
	return CL_EFORMAT;
    }

    /* folders */
    for(i = 0; i < cab->nfolders; i++) {
	if(cli_readn(fd, &folder_hdr, sizeof(folder_hdr)) != sizeof(folder_hdr)) {
	    cli_errmsg("cab_open: Can't read header for folder %u\n", i);
	    cab_free(cab);
	    return CL_EIO;
	}

	if(resfold) {
	    if(lseek(fd, resfold, SEEK_CUR) == -1) {
		cli_errmsg("cab_open: Can't lseek to %u (resfold)\n", (unsigned int) resfold);
		cab_free(cab);
		return CL_EIO;
	    }
	}

	folder = (struct cab_folder *) cli_calloc(1, sizeof(struct cab_folder));
	if(!folder) {
	    cli_errmsg("cab_open: Can't allocate memory for folder\n");
	    cab_free(cab);
	    return CL_EMEM;
	}

	folder->cab = (struct cab_archive *) cab;
	folder->offset = (off_t) EC32(folder_hdr.coffCabStart) + offset;
	if(folder->offset > rsize)
	    bscore++;
	folder->nblocks = EC16(folder_hdr.cCFData);
	folder->cmethod = EC16(folder_hdr.typeCompress);

	cli_dbgmsg("CAB: Folder record %u\n", i);
	cli_dbgmsg("CAB: Folder offset: %u\n", (unsigned int) folder->offset);
	cli_dbgmsg("CAB: Folder compression method: %d\n", folder->cmethod);
	if((folder->cmethod & 0x000f) > 3)
	    bscore++;

	if(!lfolder)
	    cab->folders = folder;
	else
	    lfolder->next = folder;

	lfolder = folder;

	if(bscore > 10) {
	    cab_free(cab);
	    cli_dbgmsg("CAB: bscore == %u, most likely a fake cabinet\n", bscore);
	    return CL_EFORMAT;
	}
    }

    /* files */
    for(i = 0; i < cab->nfiles; i++) {
	if(bscore > 10) {
	    cab_free(cab);
	    cli_dbgmsg("CAB: bscore == %u, most likely a fake cabinet\n", bscore);
	    return CL_EFORMAT;
	}

	if(cli_readn(fd, &file_hdr, sizeof(file_hdr)) != sizeof(file_hdr)) {
	    cli_errmsg("cab_open: Can't read file %u header\n", i);
	    cab_free(cab);
	    return CL_EIO;
	}

	file = (struct cab_file *) cli_calloc(1, sizeof(struct cab_file));
	if(!file) {
	    cli_errmsg("cab_open: Can't allocate memory for file\n");
	    cab_free(cab);
	    return CL_EMEM;
	}

	file->cab = cab;
	file->fd = fd;
	file->length = EC32(file_hdr.cbFile);
	file->offset = EC32(file_hdr.uoffFolderStart);
	file->attribs = EC32(file_hdr.attribs);
	fidx = EC32(file_hdr.iFolder);

	file->name = cab_readstr(fd, &ret);
	if(ret) {
	    free(file);
	    cab_free(cab);
	    return ret;
	}

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
		if(bscore < 3)
		    cli_dbgmsg("cab_open: File %s is not associated with any folder\n", file->name);
		bscore++;
		free(file->name);
		free(file);
		continue;
	    }

	    file->folder = cab->folders;
	    while(file->folder && fidx--)
		file->folder = file->folder->next;

	    if(!file->folder) {
		cli_errmsg("cab_open: Folder not found for file %s\n", file->name);
		free(file->name);
		free(file);
		cab_free(cab);
		return CL_EFORMAT;
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

static int cab_read_block(int fd, struct cab_state *state, uint16_t resdata)
{
	struct cab_block_hdr block_hdr;


    if(cli_readn(fd, &block_hdr, sizeof(block_hdr)) != sizeof(block_hdr)) {
	cli_dbgmsg("cab_read_block: Can't read block header\n");
	return CL_EIO;
    }

    if(resdata && lseek(fd, (off_t) resdata, SEEK_CUR) == -1) {
	cli_dbgmsg("cab_read_block: lseek failed\n");
	return CL_EIO;
    }

    state->blklen = EC16(block_hdr.cbData);
    if(state->blklen > CAB_INPUTMAX) {
	cli_dbgmsg("cab_read_block: block size > CAB_INPUTMAX\n");
	return CL_EFORMAT;
    }

    state->outlen = EC16(block_hdr.cbUncomp);

    if(state->outlen > CAB_BLOCKMAX) {
	cli_dbgmsg("cab_read_block: output size > CAB_BLOCKMAX\n");
	return CL_EFORMAT;
    }

    if(cli_readn(fd, state->block, state->blklen) != state->blklen) {
	cli_dbgmsg("cab_read_block: Can't read block data\n");
	return CL_EIO;
    }

    state->pt = state->end = state->block;
    state->end += state->blklen;

    return CL_SUCCESS;
}

static int cab_read(struct cab_file *file, unsigned char *buffer, int bytes)
{
	uint16_t todo, left;


    todo = bytes;
    while(todo > 0) {
	left = file->state->end - file->state->pt;

	if(left) {
	    if(left > todo)
		left = todo;

	    memcpy(buffer, file->state->pt, left);
	    file->state->pt += left;
	    buffer += left;
	    todo -= left;

	} else {
	    if(file->state->blknum++ >= file->folder->nblocks) {
		file->error = CL_EFORMAT;
		break;
	    }

	    file->error = cab_read_block(file->fd, file->state, file->cab->resdata);
	    if(file->error)
		return -1;

	    if((file->folder->cmethod & 0x000f) == 0x0002) /* Quantum hack */
		*file->state->end++ = 0xff;

	    if(file->state->blknum >= file->folder->nblocks) {
		if((file->folder->cmethod & 0x000f) == 0x0003) { /* LZX hack */
		    lzx_set_output_length(file->state->stream, (off_t) ((file->state->blknum - 1) * CAB_BLOCKMAX + file->state->outlen));
		}
	    } else {
		if(file->state->outlen != CAB_BLOCKMAX) {
		    cli_dbgmsg("cab_read: WARNING: partial data block\n");
		}
	    }
	}
    }

    return bytes - todo;
}

static int cab_unstore(struct cab_file *file, int bytes, uint8_t wflag)
{
	int todo;
	unsigned char buff[4096];


    if(bytes < 0) {
	cli_warnmsg("cab_unstore: bytes < 0\n");
	return CL_EFORMAT;
    }

    todo = bytes;

    while(1) {

	if((unsigned int) todo <= sizeof(buff)) {
	    if(cab_read(file, buff, todo) == -1) {
		cli_dbgmsg("cab_unstore: cab_read failed for descriptor %d\n", file->fd);
		return CL_EIO;
	    } else if(wflag && cli_writen(file->ofd, buff, todo) == -1) {
		cli_dbgmsg("cab_unstore: Can't write to descriptor %d\n", file->ofd);
		return CL_EIO;
	    }
	    break;

	} else {
	    if(cab_read(file, buff, sizeof(buff)) == -1) {
		cli_dbgmsg("cab_unstore: cab_read failed for descriptor %d\n", file->fd);
		return CL_EIO;
	    } else if(wflag && cli_writen(file->ofd, buff, sizeof(buff)) == -1) {
		cli_dbgmsg("cab_unstore: Can't write to descriptor %d\n", file->ofd);
		return CL_EIO;
	    }
	    todo -= sizeof(buff);
	}
    }

    return CL_SUCCESS;
}

int cab_extract(struct cab_file *file, const char *name)
{
	struct cab_folder *folder;
	int ret;


    if(!file || !name) {
	cli_errmsg("cab_extract: !file || !name\n");
	return CL_ENULLARG;
    }

    if(!(folder = file->folder)) {
	cli_errmsg("cab_extract: file->folder == NULL\n");
	return CL_ENULLARG;
    }

    if(lseek(file->fd, file->folder->offset, SEEK_SET) == -1) {
	cli_errmsg("cab_extract: Can't lseek to %u\n", (unsigned int) file->folder->offset);
	return CL_EIO;
    }

    file->state = (struct cab_state *) cli_calloc(1, sizeof(struct cab_state));
    if(!file->state) {
	cli_errmsg("cab_extract: Can't allocate memory for internal state\n");
	return CL_EIO;
    }

    file->ofd = open(name, O_WRONLY|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU);
    if(file->ofd == -1) {
	cli_errmsg("cab_extract: Can't open file %s in write mode\n", name);
	free(file->state);
	return CL_EIO;
    }

    switch(file->folder->cmethod & 0x000f) {
	case 0x0000: /* STORE */
	    if(file->offset > 0)
		cab_unstore(file, file->offset, 0);

	    ret = cab_unstore(file, file->length, 1);
	    break;

	case 0x0001: /* MSZIP */
	    cli_dbgmsg("CAB: Compression method: MSZIP\n");
	    file->state->stream = (struct mszip_stream *) mszip_init(file->fd, file->ofd, 4096, 1, file, &cab_read);
	    if(!file->state->stream) {
		free(file->state);
		close(file->ofd);
		return CL_EMSCAB;
	    }
	    if(file->offset > 0) {
		((struct mszip_stream *) file->state->stream)->wflag = 0;
		ret = mszip_decompress(file->state->stream, file->offset);
		((struct mszip_stream *) file->state->stream)->wflag = 1;
		if(ret < 0) {
		    mszip_free(file->state->stream);
		    memset(file->state, 0, sizeof(struct cab_state));
		    file->state->stream = (struct mszip_stream *) mszip_init(file->fd, file->ofd, 4096, 1, file, &cab_read);
		    if(!file->state->stream) {
			free(file->state);
			close(file->ofd);
			return CL_EMSCAB;
		    }
                    lseek(file->fd, file->folder->offset, SEEK_SET);
		}
	    }
	    ret = mszip_decompress(file->state->stream, file->length);
	    mszip_free(file->state->stream);
	    break;

	case 0x0002: /* QUANTUM */
	    cli_dbgmsg("CAB: Compression method: QUANTUM\n");
	    file->state->stream = (struct qtm_stream *) qtm_init(file->fd, file->ofd, (int) (file->folder->cmethod >> 8) & 0x1f, 4096, file, &cab_read);
	    if(!file->state->stream) {
		free(file->state);
		close(file->ofd);
		return CL_EMSCAB;
	    }
	    if(file->offset > 0) {
		((struct qtm_stream *) file->state->stream)->wflag = 0;
		qtm_decompress(file->state->stream, file->offset);
		((struct qtm_stream *) file->state->stream)->wflag = 1;
	    }
	    ret = qtm_decompress(file->state->stream, file->length);
	    qtm_free(file->state->stream);
	    break;

	case 0x0003: /* LZX */
	    cli_dbgmsg("CAB: Compression method: LZX\n");
	    file->state->stream = (struct lzx_stream *) lzx_init(file->fd, file->ofd, (int) (file->folder->cmethod >> 8) & 0x1f, 0, 4096, 0, file, &cab_read);
	    if(!file->state->stream) {
		free(file->state);
		close(file->ofd);
		return CL_EMSCAB;
	    }
	    if(file->offset > 0) {
		((struct lzx_stream *) file->state->stream)->wflag = 0;
		ret = lzx_decompress(file->state->stream, file->offset);
		((struct lzx_stream *) file->state->stream)->wflag = 1;
		if(ret < 0) {
		    lzx_free(file->state->stream);
		    memset(file->state, 0, sizeof(struct cab_state));
		    file->state->stream = (struct lzx_stream *) lzx_init(file->fd, file->ofd, (int) (file->folder->cmethod >> 8) & 0x1f, 0, 4096, 0, file, &cab_read);
		    if(!file->state->stream) {
			free(file->state);
			close(file->ofd);
			return CL_EMSCAB;
		    }
                    lseek(file->fd, file->folder->offset, SEEK_SET);
		}
	    }
	    ret = lzx_decompress(file->state->stream, file->length);
	    lzx_free(file->state->stream);
	    break;

	default:
	    cli_warnmsg("CAB: Not supported compression method: 0x%x\n", file->folder->cmethod & 0x000f);
	    ret = CL_EFORMAT;
    }

    free(file->state);
    close(file->ofd);

    return ret;
}

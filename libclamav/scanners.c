/*
 *  Copyright (C) 2002 - 2007 Tomasz Kojm <tkojm@clamav.net>
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
#include <sys/types.h>
#include <sys/stat.h>
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef	HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <fcntl.h>
#ifndef	C_WINDOWS
#include <dirent.h>
#include <netinet/in.h>
#endif

#if HAVE_MMAP
#if HAVE_SYS_MMAN_H
#include <sys/mman.h>
#else /* HAVE_SYS_MMAN_H */
#undef HAVE_MMAP
#endif
#endif

#ifndef	O_BINARY
#define	O_BINARY	0
#endif


#define DCONF_ARCH  ctx->dconf->archive
#define DCONF_DOC   ctx->dconf->doc
#define DCONF_MAIL  ctx->dconf->mail
#define DCONF_OTHER ctx->dconf->other

#include "clamav.h"
#include "others.h"
#include "dconf.h"
#include "scanners.h"
#include "matcher-ac.h"
#include "matcher-bm.h"
#include "matcher.h"
#include "ole2_extract.h"
#include "vba_extract.h"
#include "msexpand.h"
#include "mbox.h"
#include "chmunpack.h"
#include "pe.h"
#include "elf.h"
#include "filetypes.h"
#include "htmlnorm.h"
#include "untar.h"
#include "special.h"
#include "binhex.h"
/* #include "uuencode.h" */
#include "tnef.h"
#include "pst.h"
#include "sis.h"
#include "pdf.h"
#include "str.h"
#include "mspack.h"
#include "cab.h"
#include "rtf.h"
#include "unarj.h"
#include "nulsft.h"

#ifdef HAVE_ZLIB_H
#include <zlib.h>
#include "unzip.h"
#endif

#ifdef HAVE_BZLIB_H
#include <bzlib.h>
#endif

#ifdef ENABLE_UNRAR
#include "unrar.h"
#endif

#if defined(HAVE_READDIR_R_3) || defined(HAVE_READDIR_R_2)
#include <limits.h>
#include <stddef.h>
#endif

#define MAX_MAIL_RECURSION  15


static int cli_scanfile(const char *filename, cli_ctx *ctx);

#ifdef ENABLE_UNRAR
static int cli_unrar_scanmetadata(int desc, rar_metadata_t *metadata, cli_ctx *ctx, unsigned int files, uint32_t* sfx_check)
{
	int ret = CL_SUCCESS;
	struct cli_meta_node* mdata;


    if(files == 1 && sfx_check) {
	if(*sfx_check == metadata->crc)
	    return CL_BREAK;/* break extract loop */
	else
	    *sfx_check = metadata->crc;
    }

    cli_dbgmsg("RAR: %s, crc32: 0x%x, encrypted: %u, compressed: %u, normal: %u, method: %u, ratio: %u (max: %u)\n",
	metadata->filename, metadata->crc, metadata->encrypted, (unsigned int) metadata->pack_size,
	(unsigned int) metadata->unpack_size, metadata->method,
	metadata->pack_size ? (unsigned int) (metadata->unpack_size / metadata->pack_size) : 0, ctx->limits ? ctx->limits->maxratio : 0);

    /* Scan metadata */
    mdata = ctx->engine->rar_mlist;
    if(mdata) do {
	if(mdata->encrypted != metadata->encrypted)
	    continue;

	if(mdata->crc32 && (unsigned int) mdata->crc32 != metadata->crc)
	    continue;

	if(mdata->csize > 0 && (unsigned int) mdata->csize != metadata->pack_size)
	    continue;

	if(mdata->size >= 0 && (unsigned int) mdata->size != metadata->unpack_size)
	    continue;

	if(mdata->method >= 0 && mdata->method != metadata->method)
	    continue;

	if(mdata->fileno && mdata->fileno != files)
	    continue;

	if(mdata->maxdepth && ctx->arec > mdata->maxdepth)
	    continue;

	/* TODO add support for regex */
	/*if(mdata->filename && !strstr(zdirent.d_name, mdata->filename))*/
	if(mdata->filename && strcmp((char *) metadata->filename, mdata->filename))
	    continue;

	break; /* matched */

    } while((mdata = mdata->next));

    if(mdata) {
	*ctx->virname = mdata->virname;
	return CL_VIRUS;	   
    }

    if(DETECT_ENCRYPTED && metadata->encrypted) {
	cli_dbgmsg("RAR: Encrypted files found in archive.\n");
	lseek(desc, 0, SEEK_SET);
	ret = cli_scandesc(desc, ctx, 0, 0, 0, NULL);
	if(ret != CL_VIRUS) {
	    *ctx->virname = "Encrypted.RAR";
	    return CL_VIRUS;
	}
    }

/*
    TROG - TODO: multi-volume files
    if((rarlist->item.Flags & 0x03) != 0) {
	cli_dbgmsg("RAR: Skipping %s (split)\n", rarlist->item.Name);
	rarlist = rarlist->next;
	continue;
    }
*/
    return ret;
}

static int cli_unrar_checklimits(const cli_ctx *ctx, const rar_metadata_t *metadata, unsigned int files)
{
    if(ctx->limits) {
	if(ctx->limits->maxratio && metadata->unpack_size && metadata->pack_size) {
	    if(metadata->unpack_size / metadata->pack_size >= ctx->limits->maxratio) {
		cli_dbgmsg("RAR: Max ratio reached (%u, max: %u)\n", (unsigned int) (metadata->unpack_size / metadata->pack_size), ctx->limits->maxratio);
		if(BLOCKMAX) {
		    *ctx->virname = "Oversized.RAR";
		    return CL_VIRUS;
		}
		return CL_EMAXSIZE;
	    }
	}

	if(ctx->limits->maxfilesize && (metadata->unpack_size > ctx->limits->maxfilesize)) {
	    cli_dbgmsg("RAR: %s: Size exceeded (%lu, max: %lu)\n", metadata->filename, (unsigned long int) metadata->unpack_size, ctx->limits->maxfilesize);
	    if(BLOCKMAX) {
		*ctx->virname = "RAR.ExceededFileSize";
		return CL_VIRUS;
	    }
	    return CL_EMAXSIZE;
	}

	if(ctx->limits->maxfiles && (files > ctx->limits->maxfiles)) {
	    cli_dbgmsg("RAR: Files limit reached (max: %u)\n", ctx->limits->maxfiles);
	    if(BLOCKMAX) {
		*ctx->virname = "RAR.ExceededFilesLimit";
		return CL_VIRUS;
	    }
	    return CL_EMAXFILES;
	}
    }

    return CL_SUCCESS;
}

static int cli_scanrar(int desc, cli_ctx *ctx, off_t sfx_offset, uint32_t *sfx_check)
{
	int ret = CL_CLEAN;
	rar_metadata_t *metadata, *metadata_tmp;
	char *dir;
	rar_state_t rar_state;


    cli_dbgmsg("in scanrar()\n");

    /* generate the temporary directory */
    dir = cli_gentemp(NULL);
    if(mkdir(dir, 0700)) {
	cli_dbgmsg("RAR: Can't create temporary directory %s\n", dir);
	free(dir);
	return CL_ETMPDIR;
    }

    if(sfx_offset)
	lseek(desc, sfx_offset, SEEK_SET);

    if((ret = cli_unrar_open(desc, dir, &rar_state)) != CL_SUCCESS) {
	if(!cli_leavetemps_flag)
	    cli_rmdirs(dir);
	free(dir);
	cli_dbgmsg("RAR: Error: %s\n", cl_strerror(ret));
	return ret;
    }

    do {
	int rc;
	rar_state.unpack_data->ofd = -1;
	ret = cli_unrar_extract_next_prepare(&rar_state,dir);
	if(ret != CL_SUCCESS) 
	    break;
	ret = cli_unrar_checklimits(ctx, rar_state.metadata_tail, rar_state.file_count);
	if(ret && ret != CL_VIRUS) {
	    free(rar_state.file_header->filename);
	    free(rar_state.file_header);
	    ret = CL_CLEAN;
	    continue;
	} else if(ret == CL_VIRUS) {
	    /* needed since we didn't reach unrar_extract_next to clean this up*/
	    free(rar_state.file_header->filename);
	    free(rar_state.file_header);	   
	    break;
	}
	ret = cli_unrar_extract_next(&rar_state,dir);
	if(rar_state.unpack_data->ofd > 0) {
	    lseek(rar_state.unpack_data->ofd,0,SEEK_SET);
	    rc = cli_magic_scandesc(rar_state.unpack_data->ofd,ctx);
	    close(rar_state.unpack_data->ofd);
	    if(!cli_leavetemps_flag) 
		unlink(rar_state.filename);
	    if(rc == CL_VIRUS ) {
		cli_dbgmsg("RAR: infected with %s\n",*ctx->virname);
		ret = CL_VIRUS;
		break;
	    }
	}

	if(ret == CL_SUCCESS)
	    ret = cli_unrar_scanmetadata(desc,rar_state.metadata_tail, ctx, rar_state.file_count, sfx_check);

    } while(ret == CL_SUCCESS);

    if(ret == CL_BREAK)
	ret = CL_CLEAN;

    metadata = metadata_tmp = rar_state.metadata; 

    if(cli_scandir(rar_state.comment_dir, ctx) == CL_VIRUS)
	ret = CL_VIRUS;

    cli_unrar_close(&rar_state);

    if(!cli_leavetemps_flag)
        cli_rmdirs(dir);

    free(dir);

    metadata = metadata_tmp;
    while (metadata) {
    	metadata_tmp = metadata->next;
    	free(metadata->filename);
    	free(metadata);
    	metadata = metadata_tmp;
    }
    cli_dbgmsg("RAR: Exit code: %d\n", ret);

    return ret;
}
#endif /* ENABLE_UNRAR */

static int cli_unarj_checklimits(const cli_ctx *ctx, const arj_metadata_t *metadata, unsigned int files)
{
    if (ctx->limits) {
	if (ctx->limits->maxfilesize && (metadata->orig_size > ctx->limits->maxfilesize)) {
	    cli_dbgmsg("ARJ: %s: Size exceeded (%lu, max: %lu)\n", metadata->filename ? metadata->filename : "(none)",
	    		(unsigned long int) metadata->orig_size, ctx->limits->maxfilesize);
	    if (BLOCKMAX) {
		*ctx->virname = "ARJ.ExceededFileSize";
		return CL_VIRUS;
	    }
	    return CL_EMAXSIZE;
	}
	
	if (ctx->limits->maxratio && metadata->orig_size && metadata->comp_size) {
	    if (metadata->orig_size / metadata->comp_size >= ctx->limits->maxratio) {
		cli_dbgmsg("ARJ: Max ratio reached (%u, max: %u)\n", (unsigned int) (metadata->orig_size / metadata->comp_size), ctx->limits->maxratio);
		if (ctx->limits->maxfilesize && (metadata->orig_size <= ctx->limits->maxfilesize)) {
		    cli_dbgmsg("ARJ: Ignoring ratio limit (file size doesn't hit limits)\n");
		} else {
		    if(BLOCKMAX) {
		    	*ctx->virname = "Oversized.ARJ";
			return CL_VIRUS;
		    }
		}
	    }
	}
	
	if(ctx->limits->maxfiles && (files > ctx->limits->maxfiles)) {
	    cli_dbgmsg("ARJ: Files limit reached (max: %u)\n", ctx->limits->maxfiles);
	    if (BLOCKMAX) {
	    	*ctx->virname = "ARJ.ExceededFilesLimit";
		return CL_VIRUS;
	    }
	    return CL_EMAXFILES;
	}
    }
    
    return CL_SUCCESS;
}

static int cli_scanarj(int desc, cli_ctx *ctx, off_t sfx_offset, uint32_t *sfx_check)
{
	int ret = CL_CLEAN, rc;
	arj_metadata_t metadata;
	char *dir;
	unsigned int file_count = 1;

    cli_dbgmsg("in cli_scanarj()\n");

     /* generate the temporary directory */
    dir = cli_gentemp(NULL);
    if(mkdir(dir, 0700)) {
	cli_dbgmsg("RAR: Can't create temporary directory %s\n", dir);
	free(dir);
	return CL_ETMPDIR;
    }

    if(sfx_offset)
	lseek(desc, sfx_offset, SEEK_SET);

    ret = cli_unarj_open(desc, dir);
    if (ret != CL_SUCCESS) {
	if(!cli_leavetemps_flag)
	    cli_rmdirs(dir);
	free(dir);
	cli_dbgmsg("ARJ: Error: %s\n", cl_strerror(ret));
	return ret;
    }
    
   metadata.filename = NULL;

   do {
	ret = cli_unarj_prepare_file(desc, dir, &metadata);
	if (ret != CL_SUCCESS) {
	   break;
	}
	ret = cli_unarj_checklimits(ctx, &metadata, file_count);
	if (ret == CL_VIRUS) {
		break;
	}
	ret = cli_unarj_extract_file(desc, dir, &metadata);
	if (metadata.ofd >= 0) {
	    lseek(metadata.ofd, 0, SEEK_SET);
	    rc = cli_magic_scandesc(metadata.ofd, ctx);
	    close(metadata.ofd);
	    if (rc == CL_VIRUS) {
		cli_dbgmsg("ARJ: infected with %s\n",*ctx->virname);
		ret = CL_VIRUS;
		break;
	    }
	}
	if (metadata.filename) {
		free(metadata.filename);
		metadata.filename = NULL;
	}

    } while(ret == CL_SUCCESS);
    
    if(!cli_leavetemps_flag)
	cli_rmdirs(dir);

    free(dir);
    if (metadata.filename) {
	free(metadata.filename);
    }

    cli_dbgmsg("ARJ: Exit code: %d\n", ret);

    return ret;
}
#ifdef HAVE_ZLIB_H
static int cli_scanzip(int desc, cli_ctx *ctx, off_t sfx_offset, uint32_t *sfx_check)
{
	zip_dir *zdir;
	zip_dirent zdirent;
	zip_file *zfp;
	char *tmpname = NULL, *buff;
	int fd = -1, bytes, ret = CL_CLEAN;
	unsigned long int size = 0;
	unsigned int files = 0, encrypted, bfcnt;
	struct stat source;
	struct cli_meta_node *mdata;
	int err;
	uint8_t swarning = 0, fail, success;


    cli_dbgmsg("in scanzip()\n");

    if((zdir = zip_dir_open(desc, sfx_offset, &err)) == NULL) {
	cli_dbgmsg("Zip: zip_dir_open() return code: %d\n", err);
	/* no return with CL_EZIP due to password protected zips */
	return CL_CLEAN;
    }

    fstat(desc, &source);

    if(!(buff = (char *) cli_malloc(FILEBUFF))) {
	cli_dbgmsg("Zip: unable to malloc(%u)\n", FILEBUFF);
	zip_dir_close(zdir);
	return CL_EMEM;
    }

    while(zip_dir_read(zdir, &zdirent)) {
	files++;

	if(files == 1 && sfx_check) {
	    if(*sfx_check == zdirent.d_crc32)
		break;
	    else
		*sfx_check = zdirent.d_crc32;
	}

	if(!zdirent.d_name) {
	    cli_dbgmsg("Zip: zdirent.d_name == NULL\n");
	    *ctx->virname = "Suspect.Zip";
	    ret = CL_VIRUS;
	    break;
	}

        /* Bit 0: file is encrypted
	 * Bit 6: Strong encryption was used
	 * Bit 13: Encrypted central directory
	 */
	encrypted = ((zdirent.d_flags & 0x2041) != 0);

	cli_dbgmsg("Zip: %s, crc32: 0x%x, offset: %u, encrypted: %u, compressed: %u, normal: %u, method: %u, ratio: %u (max: %u)\n", zdirent.d_name, zdirent.d_crc32, zdirent.d_off, encrypted, zdirent.d_csize, zdirent.st_size, zdirent.d_compr, zdirent.d_csize ? (zdirent.st_size / zdirent.d_csize) : 0, ctx->limits ? ctx->limits->maxratio : 0);

	if(!zdirent.st_size) {
	    if(zdirent.d_crc32) {
		cli_dbgmsg("Zip: Broken file or modified information in local header part of archive\n");
		*ctx->virname = "Exploit.Zip.ModifiedHeaders";
		ret = CL_VIRUS;
		break;
	    }
	    continue;
	}

	/* Scan metadata */
	mdata = ctx->engine->zip_mlist;
	if(mdata) do {
	    if(mdata->encrypted != encrypted)
		continue;

	    if(mdata->crc32 && mdata->crc32 != zdirent.d_crc32)
		continue;

	    if(mdata->csize > 0 && (uint32_t) mdata->csize != zdirent.d_csize)
		continue;

	    if(mdata->size >= 0 && (uint32_t) mdata->size != zdirent.st_size)
		continue;

	    if(mdata->method >= 0 && (uint16_t) mdata->method != zdirent.d_compr)
		continue;

	    if(mdata->fileno && mdata->fileno != files)
		continue;

	    if(mdata->maxdepth && ctx->arec > mdata->maxdepth)
		continue;

	    /* TODO add support for regex */
	    /*if(mdata->filename && !strstr(zdirent.d_name, mdata->filename))*/
	    if(mdata->filename && strcmp(zdirent.d_name, mdata->filename))
		continue;

	    break; /* matched */

	} while((mdata = mdata->next));

	if(mdata) {
	    *ctx->virname = mdata->virname;
	    ret = CL_VIRUS;
	    break;
	}

	/* 
	 * Workaround for archives created with ICEOWS.
	 * ZZIP_DIRENT does not contain information on file type
	 * so we try to determine a directory via a filename
	 */
	if(zdirent.d_name[strlen(zdirent.d_name) - 1] == '/') {
	    cli_dbgmsg("Zip: Directory entry with st_size != 0\n");
	    continue;
	}

	if(!zdirent.d_csize) {
	    cli_dbgmsg("Zip: Malformed file (d_csize == 0 but st_size != 0)\n");
	    *ctx->virname = "Suspect.Zip";
	    ret = CL_VIRUS;
	    break;
	}

	if(ctx->limits && ctx->limits->maxratio > 0 && ((unsigned) zdirent.st_size / (unsigned) zdirent.d_csize) >= ctx->limits->maxratio) {
	    *ctx->virname = "Oversized.Zip";
	    ret = CL_VIRUS;
	    break;
        }

	if(encrypted) {
	    if(DETECT_ENCRYPTED) {
		cli_dbgmsg("Zip: Encrypted files found in archive.\n");
		lseek(desc, 0, SEEK_SET);
		ret = cli_scandesc(desc, ctx, 0, 0, 0, NULL);
		if(ret < 0) {
		    break;
		} else if(ret != CL_VIRUS) {
		    *ctx->virname = "Encrypted.Zip";
		    ret = CL_VIRUS;
		}
		break;
	    } else continue;
	}

	if(ctx->limits) {
	    if(ctx->limits->maxfilesize && ((unsigned int) zdirent.st_size > ctx->limits->maxfilesize)) {
		cli_dbgmsg("Zip: %s: Size exceeded (%u, max: %lu)\n", zdirent.d_name, zdirent.st_size, ctx->limits->maxfilesize);
		/* ret = CL_EMAXSIZE; */
		if(BLOCKMAX) {
		    *ctx->virname = "Zip.ExceededFileSize";
		    ret = CL_VIRUS;
		    break;
		}
		continue; /* continue scanning */
	    }

	    if(ctx->limits->maxfiles && (files > ctx->limits->maxfiles)) {
		cli_dbgmsg("Zip: Files limit reached (max: %u)\n", ctx->limits->maxfiles);
		if(BLOCKMAX) {
		    *ctx->virname = "Zip.ExceededFilesLimit";
		    ret = CL_VIRUS;
		    break;
		}
		break;
	    }
	}

	if((zfp = zip_file_open(zdir, zdirent.d_name, zdirent.d_off)) == NULL) {
	    if(zdir->errcode == CL_ESUPPORT) {
		ret = CL_ESUPPORT;
		if(!swarning) {
		    cli_warnmsg("Not supported compression method in one or more files\n");
		    swarning = 1;
		}
		continue;
	    } else {
		cli_dbgmsg("Zip: Can't open file %s\n", zdirent.d_name);
		ret = CL_EZIP;
		break;
	    }
	}

	bfcnt = 0;
	success = 0;
	while(1) {
	    fail = 0;

	    if((ret = cli_gentempfd(NULL, &tmpname, &fd)))
		break;

	    size = 0;
	    while((bytes = zip_file_read(zfp, buff, FILEBUFF)) > 0) {
		size += bytes;
		if(cli_writen(fd, buff, bytes) != bytes) {
		    cli_dbgmsg("Zip: Can't write to file.\n");
		    ret = CL_EIO;
		    break;
		}
	    }

	    if(!encrypted) {
		if(size != zdirent.st_size) {
		    cli_dbgmsg("Zip: Incorrectly decompressed (%lu != %lu)\n", size, (unsigned long int) zdirent.st_size);
		    if(zfp->bf[0] == -1) {
			ret = CL_EZIP;
			break;
		    } else {
			fail = 1;
		    }
		} else {
		    cli_dbgmsg("Zip: File decompressed to %s\n", tmpname);
		    success = 1;
		}
	    }

	    if(!fail) {
		if(fsync(fd) == -1) {
		    cli_dbgmsg("Zip: fsync() failed\n");
		    ret = CL_EFSYNC;
		    break;
		}
		lseek(fd, 0, SEEK_SET);

		if((ret = cli_magic_scandesc(fd, ctx)) == CL_VIRUS ) {
		    cli_dbgmsg("Zip: Infected with %s\n", *ctx->virname);
		    ret = CL_VIRUS;
		    break;
		}
	    }

	    close(fd);
	    if(!cli_leavetemps_flag)
		unlink(tmpname);
	    free(tmpname);
	    fd = -1;

	    if(zfp->bf[bfcnt] == -1)
		break;

	    zfp->method = (uint16_t) zfp->bf[bfcnt];
	    cli_dbgmsg("Zip: Brute force mode - checking compression method %u\n", zfp->method);
	    bfcnt++;
	}
	zip_file_close(zfp);


	if(!ret && !encrypted && !success) { /* brute-force decompression failed */
	    cli_dbgmsg("Zip: All attempts to decompress file failed\n");
	    ret = CL_EZIP;
	}

	if(ret) 
	    break;
    }

    zip_dir_close(zdir);
    if(fd != -1) {
	close(fd);
	if(!cli_leavetemps_flag)
	    unlink(tmpname);
	free(tmpname);
    }

    free(buff);
    return ret;
}

static int cli_scangzip(int desc, cli_ctx *ctx)
{
	int fd, bytes, ret = CL_CLEAN;
	unsigned long int size = 0;
	char *buff;
	char *tmpname;
	gzFile gd;


    cli_dbgmsg("in cli_scangzip()\n");

    if((gd = gzdopen(dup(desc), "rb")) == NULL) {
	cli_dbgmsg("GZip: Can't open descriptor %d\n", desc);
	return CL_EGZIP;
    }

    if((ret = cli_gentempfd(NULL, &tmpname, &fd))) {
	cli_dbgmsg("GZip: Can't generate temporary file.\n");
	gzclose(gd);
	return ret;
    }

    if(!(buff = (char *) cli_malloc(FILEBUFF))) {
	cli_dbgmsg("GZip: Unable to malloc %u bytes.\n", FILEBUFF);
	gzclose(gd);
	close(fd);
	if(!cli_leavetemps_flag)
	    unlink(tmpname);
	free(tmpname);	
	return CL_EMEM;
    }

    while((bytes = gzread(gd, buff, FILEBUFF)) > 0) {
	size += bytes;

	if(ctx->limits)
	    if(ctx->limits->maxfilesize && (size + FILEBUFF > ctx->limits->maxfilesize)) {
		cli_dbgmsg("GZip: Size exceeded (stopped at %ld, max: %ld)\n", size, ctx->limits->maxfilesize);
		if(BLOCKMAX) {
		    *ctx->virname = "GZip.ExceededFileSize";
		    ret = CL_VIRUS;
		}
		break;
	    }

	if(cli_writen(fd, buff, bytes) != bytes) {
	    cli_dbgmsg("GZip: Can't write to file.\n");
	    close(fd);
	    if(!cli_leavetemps_flag)
		unlink(tmpname);
	    free(tmpname);	
	    gzclose(gd);
	    free(buff);
	    return CL_EGZIP;
	}
    }

    free(buff);
    gzclose(gd);

    if(ret == CL_VIRUS) {
	close(fd);
	if(!cli_leavetemps_flag)
	    unlink(tmpname);
	free(tmpname);	
	return ret;
    }

    if(fsync(fd) == -1) {
	cli_dbgmsg("GZip: Can't synchronise descriptor %d\n", fd);
	close(fd);
	if(!cli_leavetemps_flag)
	    unlink(tmpname);
	free(tmpname);	
	return CL_EFSYNC;
    }

    lseek(fd, 0, SEEK_SET);
    if((ret = cli_magic_scandesc(fd, ctx)) == CL_VIRUS ) {
	cli_dbgmsg("GZip: Infected with %s\n", *ctx->virname);
	close(fd);
	if(!cli_leavetemps_flag)
	    unlink(tmpname);
	free(tmpname);	
	return CL_VIRUS;
    }
    close(fd);
    if(!cli_leavetemps_flag)
	unlink(tmpname);
    free(tmpname);	

    return ret;
}
#endif

#ifdef HAVE_BZLIB_H

#ifdef NOBZ2PREFIX
#define BZ2_bzReadOpen bzReadOpen
#define BZ2_bzReadClose bzReadClose
#define BZ2_bzRead bzRead
#endif

static int cli_scanbzip(int desc, cli_ctx *ctx)
{
	int fd, bytes, ret = CL_CLEAN, bzerror = 0;
	short memlim = 0;
	unsigned long int size = 0;
	char *buff;
	FILE *fs;
	char *tmpname;
	BZFILE *bfd;


    if((fs = fdopen(dup(desc), "rb")) == NULL) {
	cli_dbgmsg("Bzip: Can't open descriptor %d.\n", desc);
	return CL_EBZIP;
    }

    if(ctx->limits)
	if(ctx->limits->archivememlim)
	    memlim = 1;

    if((bfd = BZ2_bzReadOpen(&bzerror, fs, 0, memlim, NULL, 0)) == NULL) {
	cli_dbgmsg("Bzip: Can't initialize bzip2 library (descriptor: %d).\n", desc);
	fclose(fs);
	return CL_EBZIP;
    }

    if((ret = cli_gentempfd(NULL, &tmpname, &fd))) {
	cli_dbgmsg("Bzip: Can't generate temporary file.\n");
	BZ2_bzReadClose(&bzerror, bfd);
	fclose(fs);
	return ret;
    }

    if(!(buff = (char *) cli_malloc(FILEBUFF))) {
	cli_dbgmsg("Bzip: Unable to malloc %u bytes.\n", FILEBUFF);
	close(fd);
	if(!cli_leavetemps_flag)
	    unlink(tmpname);
	free(tmpname);	
	fclose(fs);
	BZ2_bzReadClose(&bzerror, bfd);
	return CL_EMEM;
    }

    while((bytes = BZ2_bzRead(&bzerror, bfd, buff, FILEBUFF)) > 0) {
	size += bytes;

	if(ctx->limits)
	    if(ctx->limits->maxfilesize && (size + FILEBUFF > ctx->limits->maxfilesize)) {
		cli_dbgmsg("Bzip: Size exceeded (stopped at %ld, max: %ld)\n", size, ctx->limits->maxfilesize);
		if(BLOCKMAX) {
		    *ctx->virname = "BZip.ExceededFileSize";
		    ret = CL_VIRUS;
		}
		break;
	    }

	if(cli_writen(fd, buff, bytes) != bytes) {
	    cli_dbgmsg("Bzip: Can't write to file.\n");
	    BZ2_bzReadClose(&bzerror, bfd);
	    close(fd);
	    if(!cli_leavetemps_flag)
		unlink(tmpname);
	    free(tmpname);	
	    free(buff);
	    fclose(fs);
	    return CL_EGZIP;
	}
    }

    free(buff);
    BZ2_bzReadClose(&bzerror, bfd);

    if(ret == CL_VIRUS) {
	close(fd);
	if(!cli_leavetemps_flag)
	    unlink(tmpname);
	free(tmpname);	
	fclose(fs);
	return ret;
    }

    if(fsync(fd) == -1) {
	cli_dbgmsg("Bzip: Synchronisation failed for descriptor %d\n", fd);
	close(fd);
	if(!cli_leavetemps_flag)
	    unlink(tmpname);
	free(tmpname);	
	fclose(fs);
	return CL_EFSYNC;
    }

    lseek(fd, 0, SEEK_SET);
    if((ret = cli_magic_scandesc(fd, ctx)) == CL_VIRUS ) {
	cli_dbgmsg("Bzip: Infected with %s\n", *ctx->virname);
    }
    close(fd);
    if(!cli_leavetemps_flag)
	unlink(tmpname);
    free(tmpname);	
    fclose(fs);

    return ret;
}
#endif

/*
static int cli_scanszdd(int desc, cli_ctx *ctx)
{
	int fd, ret = CL_CLEAN, dcpy;
	FILE *tmp = NULL, *in;
	char *tmpname;


    cli_dbgmsg("in cli_scanszdd()\n");

    if((dcpy = dup(desc)) == -1) {
	cli_dbgmsg("SZDD: Can't duplicate descriptor %d\n", desc);
	return CL_EIO;
    }

    if((in = fdopen(dcpy, "rb")) == NULL) {
	cli_dbgmsg("SZDD: Can't open descriptor %d\n", desc);
	close(dcpy);
	return CL_EMSCOMP;
    }

    if((tmpname = cli_gentempstream(NULL, &tmp)) == NULL) {
	cli_dbgmsg("SZDD: Can't generate temporary file.\n");
	fclose(in);
	return CL_ETMPFILE;
    }

    if(cli_msexpand(in, tmp) == -1) {
	cli_dbgmsg("SZDD: msexpand failed.\n");
	fclose(in);
	fclose(tmp);
	if(!cli_leavetemps_flag)
	    unlink(tmpname);
	free(tmpname);	
	return CL_EMSCOMP;
    }

    fclose(in);
    if(fflush(tmp)) {
	cli_dbgmsg("SZDD: fflush() failed.\n");
	fclose(tmp);
	if(!cli_leavetemps_flag)
	    unlink(tmpname);
	free(tmpname);	
	return CL_EFSYNC;
    }

    fd = fileno(tmp);
    lseek(fd, 0, SEEK_SET);
    if((ret = cli_magic_scandesc(fd, ctx)) == CL_VIRUS) {
	cli_dbgmsg("SZDD: Infected with %s\n", *ctx->virname);
	fclose(tmp);
	if(!cli_leavetemps_flag)
	    unlink(tmpname);
	free(tmpname);	
	return CL_VIRUS;
    }

    fclose(tmp);
    if(!cli_leavetemps_flag)
	unlink(tmpname);
    free(tmpname);	
    return ret;
}
*/

static int cli_scanmscab(int desc, cli_ctx *ctx, off_t sfx_offset)
{
	char *tempname;
	int ret;
	unsigned int files = 0;
	struct cab_archive cab;
	struct cab_file *file;


    cli_dbgmsg("in cli_scanmscab()\n");

    if((ret = cab_open(desc, sfx_offset, &cab)))
	return ret;

    for(file = cab.files; file; file = file->next) {
	files++;

	if(ctx->limits && ctx->limits->maxfilesize && (file->length > ctx->limits->maxfilesize)) {
	    cli_dbgmsg("CAB: %s: Size exceeded (%u, max: %lu)\n", file->name, file->length, ctx->limits->maxfilesize);
	    if(BLOCKMAX) {
		*ctx->virname = "CAB.ExceededFileSize";
		cab_free(&cab);
		return CL_VIRUS;
	    }
	    continue;
	}

	if(ctx->limits && ctx->limits->maxfiles && (files > ctx->limits->maxfiles)) {
	    cli_dbgmsg("CAB: Files limit reached (max: %u)\n", ctx->limits->maxfiles);
            cab_free(&cab);
	    if(BLOCKMAX) {
		*ctx->virname = "CAB.ExceededFilesLimit";
		return CL_VIRUS;
	    }
	    return CL_CLEAN;
	}

	tempname = cli_gentemp(NULL);
	cli_dbgmsg("CAB: Extracting file %s to %s, size %u\n", file->name, tempname, file->length);
	if((ret = cab_extract(file, tempname)))
	    cli_dbgmsg("CAB: Failed to extract file: %s\n", cl_strerror(ret));
	else
	    ret = cli_scanfile(tempname, ctx);

	if(!cli_leavetemps_flag)
	    unlink(tempname);
	free(tempname);
	if(ret == CL_VIRUS)
	    break;
    }

    cab_free(&cab);
    return ret;
}

int cli_scandir(const char *dirname, cli_ctx *ctx)
{
	DIR *dd;
	struct dirent *dent;
#if defined(HAVE_READDIR_R_3) || defined(HAVE_READDIR_R_2)
	union {
	    struct dirent d;
	    char b[offsetof(struct dirent, d_name) + NAME_MAX + 1];
	} result;
#endif
	struct stat statbuf;
	char *fname;


    if((dd = opendir(dirname)) != NULL) {
#ifdef HAVE_READDIR_R_3
	while(!readdir_r(dd, &result.d, &dent) && dent) {
#elif defined(HAVE_READDIR_R_2)
	while((dent = (struct dirent *) readdir_r(dd, &result.d))) {
#else
	while((dent = readdir(dd))) {
#endif
#if	(!defined(C_CYGWIN)) && (!defined(C_INTERIX)) && (!defined(C_WINDOWS))
	    if(dent->d_ino)
#endif
	    {
		if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..")) {
		    /* build the full name */
		    fname = cli_malloc(strlen(dirname) + strlen(dent->d_name) + 2);
		    if(!fname) {
			closedir(dd);
			return CL_EMEM;
		    }

		    sprintf(fname, "%s/%s", dirname, dent->d_name);

		    /* stat the file */
		    if(lstat(fname, &statbuf) != -1) {
			if(S_ISDIR(statbuf.st_mode) && !S_ISLNK(statbuf.st_mode)) {
			    if (cli_scandir(fname, ctx) == CL_VIRUS) {
				free(fname);
				closedir(dd);
				return CL_VIRUS;
			    }
			} else
			    if(S_ISREG(statbuf.st_mode))
				if(cli_scanfile(fname, ctx) == CL_VIRUS) {
				    free(fname);
				    closedir(dd);
				    return CL_VIRUS;
				}

		    }
		    free(fname);
		}
	    }
	}
    } else {
	cli_dbgmsg("ScanDir: Can't open directory %s.\n", dirname);
	return CL_EOPEN;
    }

    closedir(dd);
    return 0;
}

static int cli_vba_scandir(const char *dirname, cli_ctx *ctx)
{
	int ret = CL_CLEAN, i, fd, ofd, data_len;
	vba_project_t *vba_project;
	DIR *dd;
	struct dirent *dent;
#if defined(HAVE_READDIR_R_3) || defined(HAVE_READDIR_R_2)
	union {
	    struct dirent d;
	    char b[offsetof(struct dirent, d_name) + NAME_MAX + 1];
	} result;
#endif
	struct stat statbuf;
	char *fname, *fullname;
	unsigned char *data;


    cli_dbgmsg("VBADir: %s\n", dirname);
    if((vba_project = (vba_project_t *) vba56_dir_read(dirname))) {

	for(i = 0; i < vba_project->count; i++) {
	    fullname = (char *) cli_malloc(strlen(vba_project->dir) + strlen(vba_project->name[i]) + 2);
	    if(!fullname) {
		ret = CL_EMEM;
		break;
	    }
	    sprintf(fullname, "%s/%s", vba_project->dir, vba_project->name[i]);
	    fd = open(fullname, O_RDONLY|O_BINARY);
	    if(fd == -1) {
		cli_dbgmsg("VBADir: Can't open file %s\n", fullname);
		free(fullname);
		ret = CL_EOPEN;
		break;
	    }
	    free(fullname);
            cli_dbgmsg("VBADir: Decompress VBA project '%s'\n", vba_project->name[i]);
	    data = (unsigned char *) vba_decompress(fd, vba_project->offset[i], &data_len);
	    close(fd);

	    if(!data) {
		cli_dbgmsg("VBADir: WARNING: VBA project '%s' decompressed to NULL\n", vba_project->name[i]);
	    } else {
		if(ctx->scanned)
		    *ctx->scanned += data_len / CL_COUNT_PRECISION;

		if(cli_scanbuff(data, data_len, ctx->virname, ctx->engine, CL_TYPE_MSOLE2) == CL_VIRUS) {
		    free(data);
		    ret = CL_VIRUS;
		    break;
		}

		free(data);
	    }
	}

	for(i = 0; i < vba_project->count; i++)
	    free(vba_project->name[i]);
	free(vba_project->name);
	free(vba_project->dir);
	free(vba_project->offset);
	free(vba_project);
    } else if ((fullname = ppt_vba_read(dirname))) {
    	if(cli_scandir(fullname, ctx) == CL_VIRUS) {
	    ret = CL_VIRUS;
	}
	if(!cli_leavetemps_flag)
	    cli_rmdirs(fullname);
    	free(fullname);
    } else if ((vba_project = (vba_project_t *) wm_dir_read(dirname))) {
    	for (i = 0; i < vba_project->count; i++) {
		fullname = (char *) cli_malloc(strlen(vba_project->dir) + strlen(vba_project->name[i]) + 2);
		if(!fullname) {
		    ret = CL_EMEM;
		    break;
		}
		sprintf(fullname, "%s/%s", vba_project->dir, vba_project->name[i]);
		fd = open(fullname, O_RDONLY|O_BINARY);
		if(fd == -1) {
			cli_dbgmsg("VBADir: Can't open file %s\n", fullname);
			free(fullname);
			ret = CL_EOPEN;
			break;
		}
		free(fullname);
		cli_dbgmsg("VBADir: Decompress WM project '%s' macro:%d key:%d length:%d\n", vba_project->name[i], i, vba_project->key[i], vba_project->length[i]);
		if(vba_project->length[i])
		    data = (unsigned char *) wm_decrypt_macro(fd, vba_project->offset[i], vba_project->length[i], vba_project->key[i]);
		else
		    data = NULL;
		close(fd);
		
		if(!data) {
			cli_dbgmsg("VBADir: WARNING: WM project '%s' macro %d decrypted to NULL\n", vba_project->name[i], i);
		} else {
			if(ctx->scanned)
			    *ctx->scanned += vba_project->length[i] / CL_COUNT_PRECISION;
			if(cli_scanbuff(data, vba_project->length[i], ctx->virname, ctx->engine, CL_TYPE_MSOLE2) == CL_VIRUS) {
				free(data);
				ret = CL_VIRUS;
				break;
			}
			free(data);
		}
	}
	for(i = 0; i < vba_project->count; i++)
	    free(vba_project->name[i]);
	free(vba_project->key);
	free(vba_project->length);
	free(vba_project->offset);
	free(vba_project->name);
	free(vba_project->dir);
	free(vba_project);
    }

    if(ret != CL_CLEAN)
    	return ret;

    /* Check directory for embedded OLE objects */
    fullname = (char *) cli_malloc(strlen(dirname) + 16);
    if(!fullname)
	return CL_EMEM;

    sprintf(fullname, "%s/_1_Ole10Native", dirname);
    fd = open(fullname, O_RDONLY|O_BINARY);
    free(fullname);
    if (fd >= 0) {
    	ofd = cli_decode_ole_object(fd, dirname);
	if (ofd >= 0) {
		ret = cli_scandesc(ofd, ctx, 0, 0, 0, NULL);
		close(ofd);
	}
	close(fd);
	if(ret != CL_CLEAN)
	    return ret;
    }

    if((dd = opendir(dirname)) != NULL) {
#ifdef HAVE_READDIR_R_3
	while(!readdir_r(dd, &result.d, &dent) && dent) {
#elif defined(HAVE_READDIR_R_2)
	while((dent = (struct dirent *) readdir_r(dd, &result.d))) {
#else
	while((dent = readdir(dd))) {
#endif
#if	(!defined(C_CYGWIN)) && (!defined(C_INTERIX)) && (!defined(C_WINDOWS))
	    if(dent->d_ino)
#endif
	    {
		if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..")) {
		    /* build the full name */
		    fname = cli_malloc(strlen(dirname) + strlen(dent->d_name) + 2);
		    if(!fname) {
			ret = CL_EMEM;
			break;
		    }
		    sprintf(fname, "%s/%s", dirname, dent->d_name);

		    /* stat the file */
		    if(lstat(fname, &statbuf) != -1) {
			if(S_ISDIR(statbuf.st_mode) && !S_ISLNK(statbuf.st_mode))
			    if (cli_vba_scandir(fname, ctx) == CL_VIRUS) {
			    	ret = CL_VIRUS;
				free(fname);
				break;
			    }
		    }
		    free(fname);
		}
	    }
	}
    } else {
	cli_dbgmsg("VBADir: Can't open directory %s.\n", dirname);
	return CL_EOPEN;
    }

    closedir(dd);
    return ret;
}

static int cli_scanhtml(int desc, cli_ctx *ctx)
{
	char *tempname, fullname[1024];
	int ret=CL_CLEAN, fd;
	struct stat sb;


    cli_dbgmsg("in cli_scanhtml()\n");

    if(fstat(desc, &sb) == -1) {
        cli_errmsg("cli_scanhtml: fstat() failed for descriptor %d\n", desc);
	return CL_EIO;
    }

    /* Because HTML detection is FP-prone and html_normalise_fd() needs to
     * mmap the file don't normalise files larger than 10 MB.
     */
    if(sb.st_size > 10485760) {
	cli_dbgmsg("cli_scanhtml: exiting (file larger than 10 MB)\n");
	return CL_CLEAN;
    }

    tempname = cli_gentemp(NULL);
    if(mkdir(tempname, 0700)) {
        cli_errmsg("cli_scanhtml: Can't create temporary directory %s\n", tempname);
	free(tempname);
        return CL_ETMPDIR;
    }

    html_normalise_fd(desc, tempname, NULL, ctx->dconf);
    snprintf(fullname, 1024, "%s/comment.html", tempname);
    fd = open(fullname, O_RDONLY|O_BINARY);
    if (fd >= 0) {
        ret = cli_scandesc(fd, ctx, 0, CL_TYPE_HTML, 0, NULL);
	close(fd);
    }

    if(ret < 0 || ret == CL_VIRUS) {
	if(!cli_leavetemps_flag)
	    cli_rmdirs(tempname);
	free(tempname);
	return ret;
    }

    if (ret == CL_CLEAN) {
	snprintf(fullname, 1024, "%s/nocomment.html", tempname);
	fd = open(fullname, O_RDONLY|O_BINARY);
	if (fd >= 0) {
	    ret = cli_scandesc(fd, ctx, 0, CL_TYPE_HTML, 0, NULL);
	    close(fd);
	}
    }

    if(ret < 0 || ret == CL_VIRUS) {
	if(!cli_leavetemps_flag)
	    cli_rmdirs(tempname);
	free(tempname);
	return ret;
    }

    if (ret == CL_CLEAN) {
	snprintf(fullname, 1024, "%s/script.html", tempname);
	fd = open(fullname, O_RDONLY|O_BINARY);
	if (fd >= 0) {
	    ret = cli_scandesc(fd, ctx, 0, CL_TYPE_HTML, 0, NULL);
	    close(fd);
	}
    }

    if(ret < 0 || ret == CL_VIRUS) {
	if(!cli_leavetemps_flag)
	    cli_rmdirs(tempname);
	free(tempname);
	return ret;
    }

    if (ret == CL_CLEAN) {
    	snprintf(fullname, 1024, "%s/rfc2397", tempname);
    	ret = cli_scandir(fullname, ctx);
    }

    if(!cli_leavetemps_flag)
        cli_rmdirs(tempname);

    free(tempname);
    return ret;
}

static int cli_scanhtml_utf16(int desc, cli_ctx *ctx)
{
	char *tempname, buff[512], *decoded;
	int ret = CL_CLEAN, fd, bytes;


    cli_dbgmsg("in cli_scanhtml_utf16()\n");

    tempname = cli_gentemp(NULL);
    if((fd = open(tempname, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU)) < 0) {
	cli_errmsg("cli_scanhtml_utf16: Can't create file %s\n", tempname);
	free(tempname);
	return CL_EIO;
    }

    while((bytes = read(desc, buff, sizeof(buff))) > 0) {
	decoded = cli_utf16toascii(buff, bytes);
	if(decoded) {
	    if(write(fd, decoded, strlen(decoded)) == -1) {
		cli_errmsg("cli_scanhtml_utf16: Can't write to file %s\n", tempname);
		free(decoded);
		unlink(tempname);
		free(tempname);
		close(fd);
		return CL_EIO;
	    }
	    free(decoded);
	}
    }

    fsync(fd);
    lseek(fd, 0, SEEK_SET);
    ret = cli_scanhtml(fd, ctx);
    close(fd);

    if(!cli_leavetemps_flag)
	unlink(tempname);
    else
	cli_dbgmsg("cli_scanhtml_utf16: Decoded HTML data saved in %s\n", tempname);
    free(tempname);

    return ret;
}

static int cli_scanole2(int desc, cli_ctx *ctx)
{
	char *dir;
	int ret = CL_CLEAN;


    cli_dbgmsg("in cli_scanole2()\n");

    /* generate the temporary directory */
    dir = cli_gentemp(NULL);
    if(mkdir(dir, 0700)) {
	cli_dbgmsg("OLE2: Can't create temporary directory %s\n", dir);
	free(dir);
	return CL_ETMPDIR;
    }

    if((ret = cli_ole2_extract(desc, dir, ctx->limits))) {
	cli_dbgmsg("OLE2: %s\n", cl_strerror(ret));
	if(!cli_leavetemps_flag)
	    cli_rmdirs(dir);
	free(dir);
	return ret;
    }

    if((ret = cli_vba_scandir(dir, ctx)) != CL_VIRUS) {
	if(cli_scandir(dir, ctx) == CL_VIRUS) {
	    ret = CL_VIRUS;
	}
    }

    if(!cli_leavetemps_flag)
	cli_rmdirs(dir);
    free(dir);
    return ret;
}

static int cli_scantar(int desc, cli_ctx *ctx, unsigned int posix)
{
	char *dir;
	int ret = CL_CLEAN;


    cli_dbgmsg("in cli_scantar()\n");

    /* generate temporary directory */
    dir = cli_gentemp(NULL);
    if(mkdir(dir, 0700)) {
	cli_errmsg("Tar: Can't create temporary directory %s\n", dir);
	free(dir);
	return CL_ETMPDIR;
    }

    if((ret = cli_untar(dir, desc, posix, ctx->limits)))
	cli_dbgmsg("Tar: %s\n", cl_strerror(ret));
    else
	ret = cli_scandir(dir, ctx);

    if(!cli_leavetemps_flag)
	cli_rmdirs(dir);

    free(dir);
    return ret;
}

static int cli_scanbinhex(int desc, cli_ctx *ctx)
{
	char *dir;
	int ret = CL_CLEAN;


    cli_dbgmsg("in cli_scanbinhex()\n");

    /* generate temporary directory */
    dir = cli_gentemp(NULL);

    if(mkdir(dir, 0700)) {
	cli_errmsg("Binhex: Can't create temporary directory %s\n", dir);
	free(dir);
	return CL_ETMPDIR;
    }

    if((ret = cli_binhex(dir, desc)))
	cli_dbgmsg("Binhex: %s\n", cl_strerror(ret));
    else
	ret = cli_scandir(dir, ctx);

    if(!cli_leavetemps_flag)
	cli_rmdirs(dir);

    free(dir);
    return ret;
}

static int cli_scanmschm(int desc, cli_ctx *ctx)
{
	char *tempname;
	int ret = CL_CLEAN;


    cli_dbgmsg("in cli_scanmschm()\n");	

    tempname = cli_gentemp(NULL);
    if(mkdir(tempname, 0700)) {
	cli_dbgmsg("CHM: Can't create temporary directory %s\n", tempname);
	free(tempname);
	return CL_ETMPDIR;
    }

    if(chm_unpack(desc, tempname))
	ret = cli_scandir(tempname, ctx);

    if(!cli_leavetemps_flag)
	cli_rmdirs(tempname);

    free(tempname);
    return ret;
}

static int cli_scanscrenc(int desc, cli_ctx *ctx)
{
	char *tempname;
	int ret = CL_CLEAN;

    cli_dbgmsg("in cli_scanscrenc()\n");

    tempname = cli_gentemp(NULL);
    if(mkdir(tempname, 0700)) {
	cli_dbgmsg("CHM: Can't create temporary directory %s\n", tempname);
	free(tempname);
	return CL_ETMPDIR;
    }

    if (html_screnc_decode(desc, tempname))
	ret = cli_scandir(tempname, ctx);

    if(!cli_leavetemps_flag)
	cli_rmdirs(tempname);

    free(tempname);
    return ret;
}

static int cli_scanriff(int desc, const char **virname)
{
	int ret = CL_CLEAN;

    if(cli_check_riff_exploit(desc) == 2) {
	ret = CL_VIRUS;
	*virname = "Exploit.W32.MS05-002";
    }

    return ret;
}

static int cli_scanjpeg(int desc, const char **virname)
{
	int ret = CL_CLEAN;

    if(cli_check_jpeg_exploit(desc) == 1) {
	ret = CL_VIRUS;
	*virname = "Exploit.W32.MS04-028";
    }

    return ret;
}

static int cli_scancryptff(int desc, cli_ctx *ctx)
{
	int ret = CL_CLEAN, ndesc;
	unsigned int length, i;
	unsigned char *src = NULL, *dest = NULL;
	char *tempfile;
	struct stat sb;


    if(fstat(desc, &sb) == -1) {
	cli_errmsg("CryptFF: Can't fstat descriptor %d\n", desc);
	return CL_EIO;
    }

    /* Skip the CryptFF file header */
    if(lseek(desc, 0x10, SEEK_SET) < 0) {
	cli_errmsg("CryptFF: Can't lseek descriptor %d\n", desc);
	return ret;
    }

    length = sb.st_size  - 0x10;
 
    if((dest = (unsigned char *) cli_malloc(length)) == NULL) {
	cli_dbgmsg("CryptFF: Can't allocate memory\n");
        return CL_EMEM;
    }

    if((src = (unsigned char *) cli_malloc(length)) == NULL) {
	cli_dbgmsg("CryptFF: Can't allocate memory\n");
	free(dest);
        return CL_EMEM;
    }

    if((unsigned int) read(desc, src, length) != length) {
	cli_dbgmsg("CryptFF: Can't read from descriptor %d\n", desc);
	free(dest);
	free(src);
	return CL_EIO;
    }

    for(i = 0; i < length; i++)
	dest[i] = src[i] ^ (unsigned char) 0xff;

    free(src);

    tempfile = cli_gentemp(NULL);
    if((ndesc = open(tempfile, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU)) < 0) {
	cli_errmsg("CryptFF: Can't create file %s\n", tempfile);
	free(dest);
	free(tempfile);
	return CL_EIO;
    }

    if(write(ndesc, dest, length) == -1) {
	cli_dbgmsg("CryptFF: Can't write to descriptor %d\n", ndesc);
	free(dest);
	close(ndesc);
	free(tempfile);
	return CL_EIO;
    }

    free(dest);

    if(fsync(ndesc) == -1) {
	cli_errmsg("CryptFF: Can't fsync descriptor %d\n", ndesc);
	close(ndesc);
	free(tempfile);
	return CL_EIO;
    }

    lseek(ndesc, 0, SEEK_SET);

    cli_dbgmsg("CryptFF: Scanning decrypted data\n");

    if((ret = cli_magic_scandesc(ndesc, ctx)) == CL_VIRUS)
	cli_dbgmsg("CryptFF: Infected with %s\n", *ctx->virname);

    close(ndesc);

    if(cli_leavetemps_flag)
	cli_dbgmsg("CryptFF: Decompressed data saved in %s\n", tempfile);
    else
	unlink(tempfile);

    free(tempfile);
    return ret;
}

static int cli_scanpdf(int desc, cli_ctx *ctx)
{
	int ret;
	char *dir = cli_gentemp(NULL);


    if(mkdir(dir, 0700)) {
	cli_dbgmsg("Can't create temporary directory for PDF file %s\n", dir);
	free(dir);
	return CL_ETMPDIR;
    }

    ret = cli_pdf(dir, desc, ctx);

    if(ret == CL_CLEAN)
	ret = cli_scandir(dir, ctx);

    if(!cli_leavetemps_flag)
	cli_rmdirs(dir);

    free(dir);
    return ret;
}

static int cli_scantnef(int desc, cli_ctx *ctx)
{
	int ret;
	char *dir = cli_gentemp(NULL);


    if(mkdir(dir, 0700)) {
	cli_dbgmsg("Can't create temporary directory for tnef file %s\n", dir);
	free(dir);
	return CL_ETMPDIR;
    }

    ret = cli_tnef(dir, desc);

    if(ret == CL_CLEAN)
	ret = cli_scandir(dir, ctx);

    if(!cli_leavetemps_flag)
	cli_rmdirs(dir);

    free(dir);
    return ret;
}

static int cli_scanuuencoded(int desc, cli_ctx *ctx)
{
	int ret;
	char *dir = cli_gentemp(NULL);

    if(mkdir(dir, 0700)) {
	cli_dbgmsg("Can't create temporary directory for uuencoded file %s\n", dir);
	free(dir);
	return CL_ETMPDIR;
    }

    ret = cli_uuencode(dir, desc);

    if(ret == CL_CLEAN)
	ret = cli_scandir(dir, ctx);

    if(!cli_leavetemps_flag)
	cli_rmdirs(dir);

    free(dir);
    return ret;
}

/* Outlook PST file */
static int cli_scanpst(int desc, cli_ctx *ctx)
{
	int ret;
	char *dir = cli_gentemp(NULL);

    if(mkdir(dir, 0700)) {
	cli_dbgmsg("Can't create temporary directory for PST file %s\n", dir);
	free(dir);
	return CL_ETMPDIR;
    }

    ret = cli_pst(dir, desc);

    if(ret == CL_SUCCESS)
	ret = cli_scandir(dir, ctx);

    if(!cli_leavetemps_flag)
	cli_rmdirs(dir);

    free(dir);
    return ret;
}

static int cli_scanmail(int desc, cli_ctx *ctx)
{
	char *dir;
	int ret;


    cli_dbgmsg("Starting cli_scanmail(), mrec == %u, arec == %u\n", ctx->mrec, ctx->arec);

    /* generate the temporary directory */
    dir = cli_gentemp(NULL);
    if(mkdir(dir, 0700)) {
	cli_dbgmsg("Mail: Can't create temporary directory %s\n", dir);
	free(dir);
	return CL_ETMPDIR;
    }

    /*
     * Extract the attachments into the temporary directory
     */
    if((ret = cli_mbox(dir, desc, ctx))) {
	if(!cli_leavetemps_flag)
	    cli_rmdirs(dir);
	free(dir);
	return ret;
    }

    ret = cli_scandir(dir, ctx);

    if(!cli_leavetemps_flag)
	cli_rmdirs(dir);

    free(dir);
    return ret;
}

static int cli_scanembpe(int desc, cli_ctx *ctx)
{
	int fd, bytes, ret = CL_CLEAN;
	unsigned long int size = 0;
	char buff[512];
	char *tmpname;


    tmpname = cli_gentemp(NULL);
    if(!tmpname)
	return CL_EMEM;

    if((fd = open(tmpname, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU)) < 0) {
	cli_errmsg("cli_scanembpe: Can't create file %s\n", tmpname);
	free(tmpname);
	return CL_EIO;
    }

    while((bytes = read(desc, buff, sizeof(buff))) > 0) {
	size += bytes;

	if(ctx->limits && ctx->limits->maxfilesize && (size + sizeof(buff) > ctx->limits->maxfilesize)) {
	    cli_dbgmsg("cli_scanembpe: Size exceeded (stopped at %lu, max: %lu)\n", size, ctx->limits->maxfilesize);
	    /* BLOCKMAX should be ignored here */
	    break;
	}

	if(cli_writen(fd, buff, bytes) != bytes) {
	    cli_dbgmsg("cli_scanembpe: Can't write to temporary file\n");
	    close(fd);
	    if(!cli_leavetemps_flag)
		unlink(tmpname);
	    free(tmpname);	
	    return CL_EIO;
	}
    }

    if(fsync(fd) == -1) {
	cli_dbgmsg("cli_scanembpe: Can't synchronise descriptor %d\n", fd);
	close(fd);
	if(!cli_leavetemps_flag)
	    unlink(tmpname);
	free(tmpname);	
	return CL_EFSYNC;
    }

    lseek(fd, 0, SEEK_SET);
    if((ret = cli_magic_scandesc(fd, ctx)) == CL_VIRUS) {
	cli_dbgmsg("cli_scanembpe: Infected with %s\n", *ctx->virname);
	close(fd);
	if(!cli_leavetemps_flag)
	    unlink(tmpname);
	free(tmpname);	
	return CL_VIRUS;
    }

    close(fd);
    if(!cli_leavetemps_flag)
	unlink(tmpname);
    free(tmpname);

    /* intentionally ignore possible errors from cli_magic_scandesc */
    return CL_CLEAN;
}

static int cli_scanraw(int desc, cli_ctx *ctx, cli_file_t type, uint8_t typercg)
{
	int ret = CL_CLEAN, nret = CL_CLEAN;
	uint8_t ftrec = 0, break_loop = 0;
	struct cli_matched_type *ftoffset = NULL, *fpt;
	uint32_t lastzip, lastrar;
	struct cli_exe_info peinfo;


    if(typercg) switch(type) {
	case CL_TYPE_UNKNOWN_TEXT:
	case CL_TYPE_MSEXE:
	case CL_TYPE_ZIP:
	    ftrec = 1;
	    break;
	default:
	    ftrec = 0;
    }

    if(lseek(desc, 0, SEEK_SET) < 0) {
	cli_errmsg("cli_scanraw: lseek() failed\n");
	return CL_EIO;
    }

    ret = cli_scandesc(desc, ctx, ftrec, type, 0, &ftoffset);

    if(ret >= CL_TYPENO) {

	if(type == CL_TYPE_UNKNOWN_TEXT) {
	    lseek(desc, 0, SEEK_SET);

	    nret = cli_scandesc(desc, ctx, 0, ret, 1, NULL);
	    if(nret == CL_VIRUS)
		cli_dbgmsg("%s found in descriptor %d when scanning file type %u\n", *ctx->virname, desc, ret);
	}

	if(nret != CL_VIRUS && (type == CL_TYPE_MSEXE || type == CL_TYPE_ZIP)) {
	    lastzip = lastrar = 0xdeadbeef;
	    fpt = ftoffset;
	    while(fpt) {
		switch(fpt->type) {
		    case CL_TYPE_RARSFX:
#ifdef ENABLE_UNRAR
			if(SCAN_ARCHIVE && type == CL_TYPE_MSEXE && (DCONF_ARCH & ARCH_CONF_RAR)) {
			    cli_dbgmsg("RAR-SFX signature found at %u\n", (unsigned int) fpt->offset);
			    nret = cli_scanrar(desc, ctx, fpt->offset, &lastrar);
			}
#endif
			break;

		    case CL_TYPE_ZIPSFX:
			if(SCAN_ARCHIVE && type == CL_TYPE_MSEXE && (DCONF_ARCH & ARCH_CONF_ZIP) && fpt->offset) {
			    cli_dbgmsg("ZIP-SFX signature found at %u\n", (unsigned int) fpt->offset);
			    nret = cli_scanzip(desc, ctx, fpt->offset, &lastzip);
			}
			break;

		    case CL_TYPE_CABSFX:
			if(SCAN_ARCHIVE && type == CL_TYPE_MSEXE && (DCONF_ARCH & ARCH_CONF_CAB)) {
			    cli_dbgmsg("CAB-SFX signature found at %u\n", (unsigned int) fpt->offset);
			    nret = cli_scanmscab(desc, ctx, fpt->offset);
			}
			break;
		    case CL_TYPE_ARJSFX:
			if(SCAN_ARCHIVE && type == CL_TYPE_MSEXE && (DCONF_ARCH & ARCH_CONF_ARJ)) {
			    cli_dbgmsg("ARJ-SFX signature found at %u\n", (unsigned int) fpt->offset);
			    nret = cli_scanarj(desc, ctx, fpt->offset, &lastrar);
			}
			break;

		    case CL_TYPE_NULSFT:
		        if(SCAN_ARCHIVE && type == CL_TYPE_MSEXE && (DCONF_ARCH & ARCH_CONF_NSIS) && fpt->offset > 4) {
			    cli_dbgmsg("NSIS signature found at %u\n", (unsigned int) fpt->offset-4);
			    nret = cli_scannulsft(desc, ctx, fpt->offset - 4);
			}
			break;

		    case CL_TYPE_MSEXE:
			if(SCAN_PE && ctx->dconf->pe && fpt->offset) {
			    cli_dbgmsg("PE signature found at %u\n", (unsigned int) fpt->offset);
			    memset(&peinfo, 0, sizeof(struct cli_exe_info));
			    peinfo.offset = fpt->offset;
			    lseek(desc, fpt->offset, SEEK_SET);
			    if(cli_peheader(desc, &peinfo) == 0) {
				cli_dbgmsg("*** Detected embedded PE file ***\n");
				if(peinfo.section)
				    free(peinfo.section);

				lseek(desc, fpt->offset, SEEK_SET);
				nret = cli_scanembpe(desc, ctx);
				break_loop = 1; /* we can stop here and other
						 * embedded executables will
						 * be found recursively
						 * through the above call
						 */
			    }
			}
			break;

		    default:
			cli_warnmsg("cli_scanraw: Type %u not handled in fpt loop\n", fpt->type);
		}

		if(nret == CL_VIRUS || break_loop)
		    break;

		fpt = fpt->next;
	    }
	}

	ret == CL_TYPE_MAIL ? ctx->mrec++ : ctx->arec++;

	if(nret != CL_VIRUS) switch(ret) {
	    case CL_TYPE_HTML:
		if(SCAN_HTML && type == CL_TYPE_UNKNOWN_TEXT && (DCONF_DOC & DOC_CONF_HTML))
		    nret = cli_scanhtml(desc, ctx);
		break;

	    case CL_TYPE_MAIL:
		if(SCAN_MAIL && type == CL_TYPE_UNKNOWN_TEXT && (DCONF_MAIL & MAIL_CONF_MBOX))
		    nret = cli_scanmail(desc, ctx);
		break;

	    default:
		break;
	}
	ret == CL_TYPE_MAIL ? ctx->mrec-- : ctx->arec--;
	ret = nret;
    }

    while(ftoffset) {
	fpt = ftoffset;
	ftoffset = ftoffset->next;
	free(fpt);
    }

    if(ret == CL_VIRUS)
	cli_dbgmsg("%s found in descriptor %d\n", *ctx->virname, desc);

    return ret;
}

int cli_magic_scandesc(int desc, cli_ctx *ctx)
{
	int ret = CL_CLEAN;
	cli_file_t type;
	struct stat sb;
	uint8_t typercg = 1;


    if(fstat(desc, &sb) == -1) {
	cli_errmsg("Can't fstat descriptor %d\n", desc);
	return CL_EIO;
    }

    if(sb.st_size <= 5) {
	cli_dbgmsg("Small data (%u bytes)\n", (unsigned int) sb.st_size);
	return CL_CLEAN;
    }

    if(!ctx->engine) {
	cli_errmsg("CRITICAL: engine == NULL\n");
	return CL_EMALFDB;
    }

    if(!ctx->options) { /* raw mode (stdin, etc.) */
	cli_dbgmsg("Raw mode: No support for special files\n");
	if((ret = cli_scandesc(desc, ctx, 0, 0, 0, NULL)) == CL_VIRUS)
	    cli_dbgmsg("%s found in descriptor %d\n", *ctx->virname, desc);
	return ret;
    }

    if(SCAN_ARCHIVE && ctx->limits && ctx->limits->maxreclevel)
	if(ctx->arec > ctx->limits->maxreclevel) {
	    cli_dbgmsg("Archive recursion limit exceeded (arec == %u).\n", ctx->arec);
	    if(BLOCKMAX) {
		*ctx->virname = "Archive.ExceededRecursionLimit";
		return CL_VIRUS;
	    }
	    return CL_CLEAN;
	}

    if(SCAN_MAIL)
	if(ctx->mrec > MAX_MAIL_RECURSION) {
	    cli_dbgmsg("Mail recursion level exceeded (mrec == %u).\n", ctx->mrec);
	    /* return CL_EMAXREC; */
	    return CL_CLEAN;
	}

    lseek(desc, 0, SEEK_SET);
    type = cli_filetype2(desc, ctx->engine);
    lseek(desc, 0, SEEK_SET);

    if(type != CL_TYPE_DATA && ctx->engine->sdb) {
	if((ret = cli_scanraw(desc, ctx, type, 0)) == CL_VIRUS)
	    return CL_VIRUS;
	lseek(desc, 0, SEEK_SET);
    }

    type == CL_TYPE_MAIL ? ctx->mrec++ : ctx->arec++;

    switch(type) {
	case CL_TYPE_RAR:
#ifdef ENABLE_UNRAR
	    if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_RAR))
		ret = cli_scanrar(desc, ctx, 0, NULL);
#else
	    cli_warnmsg("RAR support not compiled in\n");
#endif
	    break;

	case CL_TYPE_ZIP:
	    if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_ZIP))
		ret = cli_scanzip(desc, ctx, 0, NULL);
	    break;

	case CL_TYPE_GZ:
	    if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_GZ))
		ret = cli_scangzip(desc, ctx);
	    break;

	case CL_TYPE_BZ:
#ifdef HAVE_BZLIB_H
	    if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_BZ))
		ret = cli_scanbzip(desc, ctx);
#endif
	    break;
	case CL_TYPE_ARJ:
	    if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_ARJ))
		ret = cli_scanarj(desc, ctx, 0, NULL);
	    break;

        case CL_TYPE_NULSFT:
	    if(SCAN_ARCHIVE)
		ret = cli_scannulsft(desc, ctx, 0);
	    break;
/*
	case CL_TYPE_MSSZDD:
	    if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_SZDD))
		ret = cli_scanszdd(desc, ctx);
	    break;
*/
	case CL_TYPE_MSCAB:
	    if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_CAB))
		ret = cli_scanmscab(desc, ctx, 0);
	    break;

	case CL_TYPE_HTML:
	    if(SCAN_HTML && (DCONF_DOC & DOC_CONF_HTML))
		ret = cli_scanhtml(desc, ctx);
	    break;

	case CL_TYPE_HTML_UTF16:
	    if(SCAN_HTML && (DCONF_DOC & DOC_CONF_HTML))
		ret = cli_scanhtml_utf16(desc, ctx);
	    break;

	case CL_TYPE_RTF:
	    if(DCONF_DOC & DOC_CONF_RTF)
		ret = cli_scanrtf(desc, ctx);
	    break;

	case CL_TYPE_MAIL:
	    if(SCAN_MAIL && (DCONF_MAIL & MAIL_CONF_MBOX))
		ret = cli_scanmail(desc, ctx);
	    break;

	case CL_TYPE_TNEF:
	    if(SCAN_MAIL && (DCONF_MAIL & MAIL_CONF_TNEF))
		ret = cli_scantnef(desc, ctx);
	    break;

	case CL_TYPE_UUENCODED:
	    if(DCONF_OTHER & OTHER_CONF_UUENC)
		ret = cli_scanuuencoded(desc, ctx);
	    break;

	case CL_TYPE_PST:
	    if(SCAN_MAIL && (DCONF_MAIL & MAIL_CONF_PST))
		ret = cli_scanpst(desc, ctx);
	    break;

	case CL_TYPE_MSCHM:
	    if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_CHM))
		ret = cli_scanmschm(desc, ctx);
	    break;

	case CL_TYPE_MSOLE2:
	    if(SCAN_OLE2 && (DCONF_ARCH & ARCH_CONF_OLE2))
		ret = cli_scanole2(desc, ctx);
	    break;

	case CL_TYPE_POSIX_TAR:
	    if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_TAR))
		ret = cli_scantar(desc, ctx, 1);
	    break;

	case CL_TYPE_OLD_TAR:
	    if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_TAR))
		ret = cli_scantar(desc, ctx, 0);
	    break;

	case CL_TYPE_BINHEX:
	    if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_BINHEX))
		ret = cli_scanbinhex(desc, ctx);
	    break;

	case CL_TYPE_SCRENC:
	    if(DCONF_OTHER & OTHER_CONF_SCRENC)
		ret = cli_scanscrenc(desc, ctx);
	    break;

	case CL_TYPE_RIFF:
	    if(SCAN_ALGO && (DCONF_OTHER & OTHER_CONF_RIFF))
		ret = cli_scanriff(desc, ctx->virname);
	    break;

	case CL_TYPE_GRAPHICS:
	    if(SCAN_ALGO && (DCONF_OTHER & OTHER_CONF_JPEG))
		ret = cli_scanjpeg(desc, ctx->virname);
	    break;

	case CL_TYPE_PDF:
	    if(SCAN_PDF && (DCONF_DOC & DOC_CONF_PDF))
		ret = cli_scanpdf(desc, ctx);
	    break;

	case CL_TYPE_CRYPTFF:
	    if(DCONF_OTHER & OTHER_CONF_CRYPTFF)
		ret = cli_scancryptff(desc, ctx);
	    break;

	case CL_TYPE_ELF:
	    if(SCAN_ELF && ctx->dconf->elf)
		ret = cli_scanelf(desc, ctx);
	    break;

	case CL_TYPE_SIS:
	    if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_SIS))
		ret = cli_scansis(desc, ctx);
	    break;

	case CL_TYPE_DATA:
	    /* it could be a false positive and a standard DOS .COM file */
	    {
		struct stat s;
		if(fstat(desc, &s) == 0 && S_ISREG(s.st_mode) && s.st_size < 65536)
		type = CL_TYPE_UNKNOWN_DATA;
	    }

	case CL_TYPE_UNKNOWN_DATA:
	    ret = cli_check_mydoom_log(desc, ctx->virname);
	    break;

	default:
	    break;
    }

    type == CL_TYPE_MAIL ? ctx->mrec-- : ctx->arec--;

    if(type == CL_TYPE_ZIP && SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_ZIP)) {
	if(sb.st_size > 1048576) {
	    cli_dbgmsg("cli_magic_scandesc: Not checking for embedded PEs (zip file > 1 MB)\n");
	    typercg = 0;
	}
    }

    if(type != CL_TYPE_DATA && ret != CL_VIRUS && !ctx->engine->sdb) {
	if(cli_scanraw(desc, ctx, type, typercg) == CL_VIRUS)
	    return CL_VIRUS;
    }

    ctx->arec++;
    lseek(desc, 0, SEEK_SET);
    switch(type) {
	/* Due to performance reasons all executables were first scanned
	 * in raw mode. Now we will try to unpack them
	 */
	case CL_TYPE_MSEXE:
	    if(SCAN_PE && ctx->dconf->pe)
		ret = cli_scanpe(desc, ctx);
	    break;

	default:
	    break;
    }
    ctx->arec--;

    if(ret == CL_EFORMAT) {
	cli_dbgmsg("Descriptor[%d]: %s\n", desc, cl_strerror(CL_EFORMAT));
	return CL_CLEAN;
    } else {
	return ret;
    }
}

int cl_scandesc(int desc, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, const struct cl_limits *limits, unsigned int options)
{
    cli_ctx ctx;
    int rc;

    memset(&ctx, '\0', sizeof(cli_ctx));
    ctx.engine = engine;
    ctx.virname = virname;
    ctx.limits = limits;
    ctx.scanned = scanned;
    ctx.options = options;
    ctx.found_possibly_unwanted = 0;
    ctx.dconf = (struct cli_dconf *) engine->dconf;

    rc = cli_magic_scandesc(desc, &ctx);
    if(rc == CL_CLEAN && ctx.found_possibly_unwanted)
    	rc = CL_VIRUS;
    return rc;
}

static int cli_scanfile(const char *filename, cli_ctx *ctx)
{
	int fd, ret;

    /* internal version of cl_scanfile with arec/mrec preserved */
    if((fd = open(filename, O_RDONLY|O_BINARY)) == -1)
	return CL_EOPEN;

    ret = cli_magic_scandesc(fd, ctx);

    close(fd);
    return ret;
}

int cl_scanfile(const char *filename, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, const struct cl_limits *limits, unsigned int options)
{
	int fd, ret;


    if((fd = open(filename, O_RDONLY|O_BINARY)) == -1)
	return CL_EOPEN;

    ret = cl_scandesc(fd, virname, scanned, engine, limits, options);
    close(fd);

    return ret;
}

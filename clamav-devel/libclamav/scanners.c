/*
 *  Copyright (C) 2002 - 2005 Tomasz Kojm <tkojm@clamav.net>
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
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/param.h>
#include <fcntl.h>
#include <dirent.h>
#include <netinet/in.h>


#if HAVE_MMAP
#if HAVE_SYS_MMAN_H
#include <sys/mman.h>
#else /* HAVE_SYS_MMAN_H */
#undef HAVE_MMAP
#endif
#endif

#include <mspack.h>

extern short cli_leavetemps_flag;

#include "clamav.h"
#include "others.h"
#include "scanners.h"
#include "matcher-ac.h"
#include "matcher-bm.h"
#include "matcher.h"
#include "unrar.h"
#include "ole2_extract.h"
#include "vba_extract.h"
#include "msexpand.h"
#include "chmunpack.h"
#include "pe.h"
#include "filetypes.h"
#include "htmlnorm.h"
#include "untar.h"
#include "special.h"
#include "binhex.h"
#include "tnef.h"
#include "sis.h"
#include "pdf.h"

#ifdef HAVE_ZLIB_H
#include <zlib.h>
#include <zzip.h>
#endif

#ifdef HAVE_BZLIB_H
#include <bzlib.h>
#endif

#if defined(HAVE_READDIR_R_3) || defined(HAVE_READDIR_R_2)
#include <limits.h>
#include <stddef.h>
#endif

/* Maximum filenames under various systems - njh */
#ifndef	NAME_MAX	/* e.g. Linux */
# ifdef	MAXNAMELEN	/* e.g. Solaris */
#   define	NAME_MAX	MAXNAMELEN
# else
#   ifdef	FILENAME_MAX	/* e.g. SCO */
#     define	NAME_MAX	FILENAME_MAX
#   else
#     define	NAME_MAX	256
#   endif
# endif
#endif

#define MAX_MAIL_RECURSION  15

extern int cli_mbox(const char *dir, int desc, cli_ctx *ctx); /* FIXME */
static int cli_scanfile(const char *filename, cli_ctx *ctx);

/*
#ifdef CL_THREAD_SAFE
static void cli_unlock_mutex(void *mtx)
{
    cli_dbgmsg("Pthread cancelled. Unlocking mutex.\n");
    pthread_mutex_unlock(mtx);
}
#endif
*/

static int cli_scanrar(int desc, cli_ctx *ctx, off_t sfx_offset, uint32_t *sfx_check)
{
	int fd, ret = CL_CLEAN;
	unsigned int files = 0;
	rar_metadata_t *metadata, *metadata_tmp;
	struct cli_meta_node *mdata;
	char *dir;


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

    metadata = metadata_tmp = cli_unrar(desc, dir, ctx->limits);

    if(cli_scandir(dir, ctx) == CL_VIRUS) {
	    ret = CL_VIRUS;
    } else while(metadata) {

	files++;

	if(files == 1 && sfx_check) {
	    if(*sfx_check == metadata->crc)
		break;
	    else
		*sfx_check = metadata->crc;
	}

	cli_dbgmsg("RAR: %s, crc32: 0x%x, encrypted: %d, compressed: %u, normal: %u, method: %d, ratio: %d (max: %d)\n",
		metadata->filename, metadata->crc, metadata->encrypted, metadata->pack_size,
		metadata->unpack_size, metadata->method,
		metadata->pack_size ? ((unsigned int) metadata->unpack_size / (unsigned int) metadata->pack_size) : 0, ctx->limits ? ctx->limits->maxratio : 0);

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
	    ret = CL_VIRUS;
	    break;
	}

	if(DETECT_ENCRYPTED && metadata->encrypted) {
	    cli_dbgmsg("RAR: Encrypted files found in archive.\n");
	    lseek(desc, 0, SEEK_SET);
	    ret = cli_scandesc(desc, ctx, 0, 0, NULL);
	    if(ret < 0) {
		break;
	    } else if(ret != CL_VIRUS) {
		*ctx->virname = "Encrypted.RAR";
		ret = CL_VIRUS;
	    }
	    break;
	}

/*
	TROG - TODO: multi-volume files
	if((rarlist->item.Flags & 0x03) != 0) {
	    cli_dbgmsg("RAR: Skipping %s (split)\n", rarlist->item.Name);
	    rarlist = rarlist->next;
	    continue;
	}
*/
	if(ctx->limits) {
	    if(ctx->limits->maxratio && metadata->unpack_size && metadata->pack_size) {
		if((unsigned int) metadata->unpack_size / (unsigned int) metadata->pack_size >= ctx->limits->maxratio) {
		    cli_dbgmsg("RAR: Max ratio reached (normal: %u, compressed: %u, max: %ld)\n", metadata->unpack_size,
		    		metadata->pack_size, ctx->limits->maxratio);
		    *ctx->virname = "Oversized.RAR";
		    ret = CL_VIRUS;
		    break;
		}
	    }

	    if(ctx->limits->maxfilesize && (metadata->unpack_size > (unsigned int) ctx->limits->maxfilesize)) {
		cli_dbgmsg("RAR: %s: Size exceeded (%u, max: %lu)\n", metadata->filename,
					metadata->unpack_size, ctx->limits->maxfilesize);
		if(BLOCKMAX) {
		    *ctx->virname = "RAR.ExceededFileSize";
		    ret = CL_VIRUS;
		    break;
		}
		metadata = metadata->next;
		continue;
	    }

	    if(ctx->limits->maxfiles && (files > ctx->limits->maxfiles)) {
		cli_dbgmsg("RAR: Files limit reached (max: %d)\n", ctx->limits->maxfiles);
		if(BLOCKMAX) {
		    *ctx->virname = "RAR.ExceededFilesLimit";
		    ret = CL_VIRUS;
		    break;
		}
		break;
	    }
	}

	metadata = metadata->next;
    }

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

#ifdef HAVE_ZLIB_H
static int cli_scanzip(int desc, cli_ctx *ctx, off_t sfx_offset, uint32_t *sfx_check)
{
	ZZIP_DIR *zdir;
	ZZIP_DIRENT zdirent;
	ZZIP_FILE *zfp;
	FILE *tmp = NULL;
	char *tmpname;
	char *buff;
	int fd, bytes, ret = CL_CLEAN;
	unsigned long int size = 0;
	unsigned int files = 0, encrypted;
	struct stat source;
	struct cli_meta_node *mdata;
	zzip_error_t err;


    cli_dbgmsg("in scanzip()\n");

    if(sfx_offset)
	lseek(desc, sfx_offset, SEEK_SET);

    if((zdir = zzip_dir_fdopen(dup(desc), &err)) == NULL) {
	cli_dbgmsg("Zip: zzip_dir_fdopen() return code: %d\n", err);
	/* no return with CL_EZIP due to password protected zips */
	return CL_CLEAN;
    }

    fstat(desc, &source);

    if(!(buff = (char *) cli_malloc(FILEBUFF))) {
	cli_dbgmsg("Zip: unable to malloc(%d)\n", FILEBUFF);
	zzip_dir_close(zdir);
	return CL_EMEM;
    }

    while(zzip_dir_read(zdir, &zdirent)) {
	files++;

	if(files == 1 && sfx_check) {
	    if(*sfx_check == zdirent.d_crc32)
		break;
	    else
		*sfx_check = zdirent.d_crc32;
	}

	if(!zdirent.d_name || !strlen(zdirent.d_name)) { /* Mimail fix */
	    cli_dbgmsg("Zip: strlen(zdirent.d_name) == %d\n", strlen(zdirent.d_name));
	    *ctx->virname = "Suspect.Zip";
	    ret = CL_VIRUS;
	    break;
	}

        /* Bit 0: file is encrypted
	 * Bit 6: Strong encryption was used
	 * Bit 13: Encrypted central directory
	 */
	encrypted = ((zdirent.d_flags & 0x2041) != 0);

	cli_dbgmsg("Zip: %s, crc32: 0x%x, offset: %d, encrypted: %d, compressed: %u, normal: %u, method: %d, ratio: %d (max: %d)\n", zdirent.d_name, zdirent.d_crc32, zdirent.d_off, encrypted, zdirent.d_csize, zdirent.st_size, zdirent.d_compr, zdirent.d_csize ? (zdirent.st_size / zdirent.d_csize) : 0, ctx->limits ? ctx->limits->maxratio : 0);

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

	    if(mdata->crc32 && mdata->crc32 != (unsigned int) zdirent.d_crc32)
		continue;

	    if(mdata->csize > 0 && mdata->csize != zdirent.d_csize)
		continue;

	    if(mdata->size >= 0 && mdata->size != zdirent.st_size)
		continue;

	    if(mdata->method >= 0 && mdata->method != (unsigned int) zdirent.d_compr)
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

	/* work-around for problematic zips (zziplib crashes with them) */
	if(zdirent.d_csize <= 0 || zdirent.st_size < 0) {
	    cli_dbgmsg("Zip: Malformed archive detected.\n");
	    *ctx->virname = "Suspect.Zip";
	    ret = CL_VIRUS;
	    break;
	}

	if(ctx->limits && ctx->limits->maxratio > 0 && ((unsigned) zdirent.st_size / (unsigned) zdirent.d_csize) >= ctx->limits->maxratio) {
	    *ctx->virname = "Oversized.Zip";
	    ret = CL_VIRUS;
	    break;
        }

	if(DETECT_ENCRYPTED && encrypted) {
	    cli_dbgmsg("Zip: Encrypted files found in archive.\n");
	    lseek(desc, 0, SEEK_SET);
	    ret = cli_scandesc(desc, ctx, 0, 0, NULL);
	    if(ret < 0) {
		break;
	    } else if(ret != CL_VIRUS) {
		*ctx->virname = "Encrypted.Zip";
		ret = CL_VIRUS;
	    }
	    break;
	}

	if(ctx->limits) {
	    if(ctx->limits->maxfilesize && ((unsigned int) zdirent.st_size > ctx->limits->maxfilesize)) {
		cli_dbgmsg("Zip: %s: Size exceeded (%d, max: %ld)\n", zdirent.d_name, zdirent.st_size, ctx->limits->maxfilesize);
		/* ret = CL_EMAXSIZE; */
		if(BLOCKMAX) {
		    *ctx->virname = "Zip.ExceededFileSize";
		    ret = CL_VIRUS;
		    break;
		}
		continue; /* continue scanning */
	    }

	    if(ctx->limits->maxfiles && (files > ctx->limits->maxfiles)) {
		cli_dbgmsg("Zip: Files limit reached (max: %d)\n", ctx->limits->maxfiles);
		if(BLOCKMAX) {
		    *ctx->virname = "Zip.ExceededFilesLimit";
		    ret = CL_VIRUS;
		    break;
		}
		break;
	    }
	}

	if((zfp = zzip_file_open(zdir, zdirent.d_name, 0, zdirent.d_off)) == NULL) {
	    cli_dbgmsg("Zip: Can't open file %s\n", zdirent.d_name);
	    ret = CL_EZIP;
	    break;
	}

	/* generate temporary file and get its descriptor */
	if((tmpname = cli_gentempstream(NULL, &tmp)) == NULL) {
	    cli_dbgmsg("Zip: Can't generate tmpfile().\n");
	    zzip_file_close(zfp);
	    ret = CL_ETMPFILE;
	    break;
	}

	size = 0;
	while((bytes = zzip_file_read(zfp, buff, FILEBUFF)) > 0) {
	    size += bytes;
	    if(fwrite(buff, 1, bytes, tmp) != (size_t) bytes) {
		cli_dbgmsg("Zip: Can't write to file.\n");
		zzip_file_close(zfp);
		zzip_dir_close(zdir);
		fclose(tmp);
		if(!cli_leavetemps_flag)
		    unlink(tmpname);
		free(tmpname);
		free(buff);
		return CL_EIO;
	    }
	}

	zzip_file_close(zfp);

	if(!encrypted && size != zdirent.st_size) {
	    cli_dbgmsg("Zip: Incorrectly decompressed (%d != %d)\n", size, zdirent.st_size);
	    ret = CL_EZIP;
	    break;
	}

	if(fflush(tmp) != 0) {
	    cli_dbgmsg("Zip: fflush() failed: %s\n", strerror(errno));
	    ret = CL_EFSYNC;
	    break;
	}

	fd = fileno(tmp);

	lseek(fd, 0, SEEK_SET);
	if((ret = cli_magic_scandesc(fd, ctx)) == CL_VIRUS ) {
	    cli_dbgmsg("Zip: Infected with %s\n", *ctx->virname);
	    ret = CL_VIRUS;
	    break;
	} else if(ret == CL_EMALFZIP) {
	    cli_dbgmsg("Zip: Malformed Zip file, scanning stopped.\n");
	    *ctx->virname = "Suspect.Zip";
	    ret = CL_VIRUS;
	    break;
	}

	if (tmp) {
	    fclose(tmp);
	    if(!cli_leavetemps_flag)
		unlink(tmpname);
	    free(tmpname);
	    tmp = NULL;
	}
    }

    zzip_dir_close(zdir);
    if (tmp) {
	fclose(tmp);
	if(!cli_leavetemps_flag)
	    unlink(tmpname);
	free(tmpname);
	tmp = NULL;
    }

    free(buff);
    return ret;
}

static int cli_scangzip(int desc, cli_ctx *ctx)
{
	int fd, bytes, ret = CL_CLEAN;
	unsigned long int size = 0;
	char *buff;
	FILE *tmp = NULL;
	char *tmpname;
	gzFile gd;


    cli_dbgmsg("in cli_scangzip()\n");

    if((gd = gzdopen(dup(desc), "rb")) == NULL) {
	cli_dbgmsg("GZip: Can't open descriptor %d\n", desc);
	return CL_EGZIP;
    }

    if((tmpname = cli_gentempstream(NULL, &tmp)) == NULL) {
	cli_dbgmsg("GZip: Can't generate temporary file.\n");
	gzclose(gd);
	return CL_ETMPFILE;
    }
    fd = fileno(tmp);

    if(!(buff = (char *) cli_malloc(FILEBUFF))) {
	cli_dbgmsg("GZip: Unable to malloc %d bytes.\n", FILEBUFF);
	gzclose(gd);
	fclose(tmp);
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
	    fclose(tmp);
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
	fclose(tmp);
	if(!cli_leavetemps_flag)
	    unlink(tmpname);
	free(tmpname);	
	return ret;
    }

    if(fsync(fd) == -1) {
	cli_dbgmsg("GZip: Can't synchronise descriptor %d\n", fd);
	fclose(tmp);
	if(!cli_leavetemps_flag)
	    unlink(tmpname);
	free(tmpname);	
	return CL_EFSYNC;
    }

    lseek(fd, 0, SEEK_SET);
    if((ret = cli_magic_scandesc(fd, ctx)) == CL_VIRUS ) {
	cli_dbgmsg("GZip: Infected with %s\n", *ctx->virname);
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
	FILE *fs, *tmp = NULL;
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

    if((tmpname = cli_gentempstream(NULL, &tmp)) == NULL) {
	cli_dbgmsg("Bzip: Can't generate temporary file.\n");
	BZ2_bzReadClose(&bzerror, bfd);
	fclose(fs);
	return CL_ETMPFILE;
    }
    fd = fileno(tmp);

    if(!(buff = (char *) malloc(FILEBUFF))) {
	cli_dbgmsg("Bzip: Unable to malloc %d bytes.\n", FILEBUFF);
	fclose(tmp);
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
	    fclose(tmp);
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
	fclose(tmp);
	if(!cli_leavetemps_flag)
	    unlink(tmpname);
	free(tmpname);	
	fclose(fs);
	return ret;
    }

    if(fsync(fd) == -1) {
	cli_dbgmsg("Bzip: Synchronisation failed for descriptor %d\n", fd);
	fclose(tmp);
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
    fclose(tmp);
    if(!cli_leavetemps_flag)
	unlink(tmpname);
    free(tmpname);	
    fclose(fs);

    return ret;
}
#endif

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

static int cli_scanmscab(int desc, cli_ctx *ctx)
{
	struct mscab_decompressor *cabd = NULL;
	struct mscabd_cabinet *base, *cab;
	struct mscabd_file *file;
	char *tempname;
	int ret = CL_CLEAN;


    cli_dbgmsg("in cli_scanmscab()\n");

    if((cabd = mspack_create_cab_decompressor(NULL)) == NULL) {
	cli_dbgmsg("MSCAB: Can't create libmspack CAB decompressor\n");
	return CL_EMSCAB;
    }

    if((base = cabd->dsearch(cabd, dup(desc))) == NULL) {
	cli_dbgmsg("MSCAB: I/O error or no valid cabinets found\n");
	mspack_destroy_cab_decompressor(cabd);
	return CL_EMSCAB;
    }

    for(cab = base; cab; cab = cab->next) {
	for(file = cab->files; file; file = file->next) {

	    if(ctx->limits && ctx->limits->maxfilesize && (file->length > (unsigned int) ctx->limits->maxfilesize)) {
		cli_dbgmsg("MSCAB: %s: Size exceeded (%u, max: %lu)\n", file->filename, file->length, ctx->limits->maxfilesize);
		if(BLOCKMAX) {
		    *ctx->virname = "MSCAB.ExceededFileSize";
		    cabd->close(cabd, base);
		    mspack_destroy_cab_decompressor(cabd);
		    return CL_VIRUS;
		}
		continue;
	    }

	    tempname = cli_gentemp(NULL);
	    cli_dbgmsg("MSCAB: Extracting data to %s\n", tempname);
	    if(cabd->extract(cabd, file, tempname)) {
		cli_dbgmsg("MSCAB: libmscab error code: %d\n", cabd->last_error(cabd));
	    } else {
		ret = cli_scanfile(tempname, ctx);
	    }
	    if(!cli_leavetemps_flag)
		unlink(tempname);
	    free(tempname);
	    if(ret == CL_VIRUS)
		break;
	}
	if(ret == CL_VIRUS)
	    break;
    }

    cabd->close(cabd, base);
    mspack_destroy_cab_decompressor(cabd);

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
#ifndef C_INTERIX
	    if(dent->d_ino)
#endif
	    {
		if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..")) {
		    /* build the full name */
		    fname = cli_calloc(strlen(dirname) + strlen(dent->d_name) + 2, sizeof(char));
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
	    sprintf(fullname, "%s/%s", vba_project->dir, vba_project->name[i]);
	    fd = open(fullname, O_RDONLY);
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

		if(cli_scanbuff((char *) data, data_len, ctx->virname, ctx->engine, CL_TYPE_MSOLE2) == CL_VIRUS) {
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
		sprintf(fullname, "%s/%s", vba_project->dir, vba_project->name[i]);
		fd = open(fullname, O_RDONLY);
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
			if(cli_scanbuff((char *) data, vba_project->length[i], ctx->virname, ctx->engine, CL_TYPE_MSOLE2) == CL_VIRUS) {
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
    sprintf(fullname, "%s/_1_Ole10Native", dirname);
    fd = open(fullname, O_RDONLY);
    free(fullname);
    if (fd >= 0) {
    	ofd = cli_decode_ole_object(fd, dirname);
	if (ofd >= 0) {
		ret = cli_scandesc(ofd, ctx, 0, 0, NULL);
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
#ifndef C_INTERIX
	    if(dent->d_ino)
#endif
	    {
		if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..")) {
		    /* build the full name */
		    fname = cli_calloc(strlen(dirname) + strlen(dent->d_name) + 2, sizeof(char));
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


    cli_dbgmsg("in cli_scanhtml()\n");

    tempname = cli_gentemp(NULL);
    if(mkdir(tempname, 0700)) {
        cli_dbgmsg("ScanHTML -> Can't create temporary directory %s\n", tempname);
	free(tempname);
        return CL_ETMPDIR;
    }

    html_normalise_fd(desc, tempname, NULL);
    snprintf(fullname, 1024, "%s/comment.html", tempname);
    fd = open(fullname, O_RDONLY);
    if (fd >= 0) {
        ret = cli_scandesc(fd, ctx, 0, CL_TYPE_HTML, NULL);
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
	fd = open(fullname, O_RDONLY);
	if (fd >= 0) {
	    ret = cli_scandesc(fd, ctx, 0, CL_TYPE_HTML, NULL);
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
	fd = open(fullname, O_RDONLY);
	if (fd >= 0) {
	    ret = cli_scandesc(fd, ctx, 0, CL_TYPE_HTML, NULL);
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

    if((ret = cli_untar(dir, desc, posix)))
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
	int ret = CL_CLEAN, i, ndesc;
	unsigned int length;
	unsigned char *src = NULL, *dest = NULL;
	char *tempfile;
	struct stat sb;


    if(fstat(desc, &sb) == -1) {
	cli_errmsg("CryptFF: Can's fstat descriptor %d\n", desc);
	return CL_EIO;
    }

    /* Skip the CryptFF file header */
    if(lseek(desc, 0x10, SEEK_SET) < 0) {
	cli_errmsg("CryptFF: Can's fstat descriptor %d\n", desc);
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
    if((ndesc = open(tempfile, O_RDWR|O_CREAT|O_TRUNC, S_IRWXU)) < 0) {
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


    cli_dbgmsg("Starting cli_scanmail(), mrec == %d, arec == %d\n", ctx->mrec, ctx->arec);

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

static int cli_scanraw(int desc, cli_ctx *ctx, cli_file_t type)
{
	int ret = CL_CLEAN, nret = CL_CLEAN;
	unsigned short ftrec;
	struct cli_matched_type *ftoffset = NULL, *fpt;
	uint32_t lastzip, lastrar;


    switch(type) {
	case CL_TYPE_UNKNOWN_TEXT:
	case CL_TYPE_MSEXE:
	    ftrec = 1;
	    break;
	default:
	    ftrec = 0;
    }

    if(lseek(desc, 0, SEEK_SET) < 0) {
	cli_errmsg("cli_scanraw: lseek() failed\n");
	return CL_EIO;
    }

    if((ret = cli_scandesc(desc, ctx, ftrec, type, &ftoffset)) == CL_VIRUS) {
	cli_dbgmsg("%s found in descriptor %d.\n", *ctx->virname, desc);
	return CL_VIRUS;

    } else if(ret < 0) {
	return ret;

    } else if(ret >= CL_TYPENO) {
	lseek(desc, 0, SEEK_SET);

	ret == CL_TYPE_MAIL ? ctx->mrec++ : ctx->arec++;
	switch(ret) {
	    case CL_TYPE_HTML:
		if(SCAN_HTML && type == CL_TYPE_UNKNOWN_TEXT)
		    if((nret = cli_scanhtml(desc, ctx)) == CL_VIRUS)
			return CL_VIRUS;
		break;

	    case CL_TYPE_MAIL:
		if(SCAN_MAIL && type == CL_TYPE_UNKNOWN_TEXT)
		    if((nret = cli_scanmail(desc, ctx)) == CL_VIRUS)
			return CL_VIRUS;
		break;

	    case CL_TYPE_RARSFX:
	    case CL_TYPE_ZIPSFX:
		if(type == CL_TYPE_MSEXE) {
		    if(SCAN_ARCHIVE) {
			lastzip = lastrar = 0xdeadbeef;
			fpt = ftoffset;
			while(fpt) {
			    if(fpt->type == CL_TYPE_RARSFX) {
				cli_dbgmsg("RAR-SFX signature found at %d\n", fpt->offset);
				if((nret = cli_scanrar(desc, ctx, fpt->offset, &lastrar)) == CL_VIRUS)
				    break;
			    } else if(fpt->type == CL_TYPE_ZIPSFX) {
				cli_dbgmsg("ZIP-SFX signature found at %d\n", fpt->offset);
				if((nret = cli_scanzip(desc, ctx, fpt->offset, &lastzip)) == CL_VIRUS)
				    break;
			    }
			    fpt = fpt->next;
			}
		    }

		    while(ftoffset) {
			fpt = ftoffset;
			ftoffset = ftoffset->next;
			free(fpt);
		    }

		    if(nret == CL_VIRUS)
			return nret;
		}
		break;

	    default:
		break;
	}
	ret == CL_TYPE_MAIL ? ctx->mrec-- : ctx->arec--;
	ret = nret;
    }

    return ret;
}

int cli_magic_scandesc(int desc, cli_ctx *ctx)
{
	int ret = CL_CLEAN;
	cli_file_t type;
	struct stat sb;


    if(fstat(desc, &sb) == -1) {
	cli_errmsg("Can's fstat descriptor %d\n", desc);
	return CL_EIO;
    }

    if(sb.st_size <= 5) {
	cli_dbgmsg("Small data (%d bytes)\n", sb.st_size);
	return CL_CLEAN;
    }

    if(!ctx->engine) {
	cli_errmsg("CRITICAL: engine == NULL\n");
	return CL_EMALFDB;
    }

    if(!ctx->options) { /* raw mode (stdin, etc.) */
	cli_dbgmsg("Raw mode: No support for special files\n");
	if((ret = cli_scandesc(desc, ctx, 0, 0, NULL)) == CL_VIRUS)
	    cli_dbgmsg("%s found in descriptor %d\n", *ctx->virname, desc);
	return ret;
    }

    if(SCAN_ARCHIVE && ctx->limits && ctx->limits->maxreclevel)
	if(ctx->arec > ctx->limits->maxreclevel) {
	    cli_dbgmsg("Archive recursion limit exceeded (arec == %d).\n", ctx->arec);
	    if(BLOCKMAX) {
		*ctx->virname = "Archive.ExceededRecursionLimit";
		return CL_VIRUS;
	    }
	    return CL_CLEAN;
	}

    if(SCAN_MAIL)
	if(ctx->mrec > MAX_MAIL_RECURSION) {
	    cli_dbgmsg("Mail recursion level exceeded (mrec == %d).\n", ctx->mrec);
	    /* return CL_EMAXREC; */
	    return CL_CLEAN;
	}

    lseek(desc, 0, SEEK_SET);
    type = cli_filetype2(desc);
    lseek(desc, 0, SEEK_SET);

    if(type != CL_TYPE_DATA && ctx->engine->sdb) {
	if((ret = cli_scanraw(desc, ctx, type)) == CL_VIRUS)
	    return CL_VIRUS;
	lseek(desc, 0, SEEK_SET);
    }

    type == CL_TYPE_MAIL ? ctx->mrec++ : ctx->arec++;

    switch(type) {
	case CL_TYPE_RAR:
	    if(SCAN_ARCHIVE)
		ret = cli_scanrar(desc, ctx, 0, NULL);
	    break;

	case CL_TYPE_ZIP:
	    if(SCAN_ARCHIVE)
		ret = cli_scanzip(desc, ctx, 0, NULL);
	    break;

	case CL_TYPE_GZ:
	    if(SCAN_ARCHIVE)
		ret = cli_scangzip(desc, ctx);
	    break;

	case CL_TYPE_BZ:
#ifdef HAVE_BZLIB_H
	    if(SCAN_ARCHIVE)
		ret = cli_scanbzip(desc, ctx);
#endif
	    break;

	case CL_TYPE_MSSZDD:
	    if(SCAN_ARCHIVE)
		ret = cli_scanszdd(desc, ctx);
	    break;

	case CL_TYPE_MSCAB:
	    if(SCAN_ARCHIVE)
		ret = cli_scanmscab(desc, ctx);
	    break;

	case CL_TYPE_MAIL:
	    if(SCAN_MAIL)
		ret = cli_scanmail(desc, ctx);
	    break;

	case CL_TYPE_TNEF:
	    if(SCAN_MAIL)
		ret = cli_scantnef(desc, ctx);
	    break;

	case CL_TYPE_UUENCODED:
		ret = cli_scanuuencoded(desc, ctx);
	    break;

	case CL_TYPE_PST:
	    if(SCAN_MAIL)
		ret = cli_scanpst(desc, ctx);
	    break;

	case CL_TYPE_MSCHM:
	    if(SCAN_ARCHIVE)
		ret = cli_scanmschm(desc, ctx);
	    break;

	case CL_TYPE_MSOLE2:
	    if(SCAN_OLE2)
		ret = cli_scanole2(desc, ctx);
	    break;

	case CL_TYPE_POSIX_TAR:
	    if(SCAN_ARCHIVE)
		ret = cli_scantar(desc, ctx, 1);
	    break;

	case CL_TYPE_OLD_TAR:
	    if(SCAN_ARCHIVE)
		ret = cli_scantar(desc, ctx, 0);
	    break;

	case CL_TYPE_BINHEX:
	    if(SCAN_ARCHIVE)
		ret = cli_scanbinhex(desc, ctx);
	    break;

	case CL_TYPE_SCRENC:
	    ret = cli_scanscrenc(desc, ctx);
	    break;

	case CL_TYPE_RIFF:
	    if(SCAN_ALGO)
		ret = cli_scanriff(desc, ctx->virname);
	    break;

	case CL_TYPE_GRAPHICS:
	    if(SCAN_ALGO)
		ret = cli_scanjpeg(desc, ctx->virname);
	    break;

	case CL_TYPE_PDF:
	    if(SCAN_ARCHIVE)    /* you may wish to change this line */
		ret = cli_scanpdf(desc, ctx);
	    break;

	case CL_TYPE_CRYPTFF:
	    ret = cli_scancryptff(desc, ctx);
	    break;

	case CL_TYPE_ELF: /* TODO: Add ScanELF option */
		ret = cli_scanelf(desc, ctx);
	    break;

	case CL_TYPE_SIS:
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

    if(type != CL_TYPE_DATA && ret != CL_VIRUS && !ctx->engine->sdb) {
	if(cli_scanraw(desc, ctx, type) == CL_VIRUS)
	    return CL_VIRUS;
    }

    ctx->arec++;
    lseek(desc, 0, SEEK_SET);
    switch(type) {
	/* Due to performance reasons all executables were first scanned
	 * in raw mode. Now we will try to unpack them
	 */
	case CL_TYPE_MSEXE:
	    if(SCAN_PE)
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

    memset(&ctx, '\0', sizeof(cli_ctx));
    ctx.engine = engine;
    ctx.virname = virname;
    ctx.limits = limits;
    ctx.scanned = scanned;
    ctx.options = options;

    return cli_magic_scandesc(desc, &ctx);
}

static int cli_scanfile(const char *filename, cli_ctx *ctx)
{
	int fd, ret;

    /* internal version of cl_scanfile with arec/mrec preserved */
    if((fd = open(filename, O_RDONLY)) == -1)
	return CL_EOPEN;

    ret = cli_magic_scandesc(fd, ctx);

    close(fd);
    return ret;
}

int cl_scanfile(const char *filename, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, const struct cl_limits *limits, unsigned int options)
{
	int fd, ret;


    if((fd = open(filename, O_RDONLY)) == -1)
	return CL_EOPEN;

    ret = cl_scandesc(fd, virname, scanned, engine, limits, options);
    close(fd);

    return ret;
}

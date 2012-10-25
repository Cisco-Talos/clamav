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

#ifndef _WIN32
#include <sys/time.h>
#endif
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef	HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <fcntl.h>
#include <dirent.h>

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
#include "sis.h"
#include "pdf.h"
#include "str.h"
#include "mspack.h"
#include "cab.h"
#include "rtf.h"
#include "unarj.h"
#include "nsis/nulsft.h"
#include "autoit.h"
#include "textnorm.h"
#include <zlib.h>
#include "unzip.h"
#include "dlp.h"
#include "default.h"
#include "cpio.h"
#include "macho.h"
#include "ishield.h"
#include "7z.h"
#include "fmap.h"
#include "cache.h"
#include "events.h"

#ifdef HAVE_BZLIB_H
#include <bzlib.h>
#endif

#if defined(HAVE_READDIR_R_3) || defined(HAVE_READDIR_R_2)
#include <limits.h>
#include <stddef.h>
#endif

static int cli_scanfile(const char *filename, cli_ctx *ctx);

static int cli_scandir(const char *dirname, cli_ctx *ctx)
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
	unsigned int viruses_found = 0;

    if((dd = opendir(dirname)) != NULL) {
#ifdef HAVE_READDIR_R_3
	while(!readdir_r(dd, &result.d, &dent) && dent) {
#elif defined(HAVE_READDIR_R_2)
	while((dent = (struct dirent *) readdir_r(dd, &result.d))) {
#else
	while((dent = readdir(dd))) {
#endif
	    if(dent->d_ino)
	    {
		if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..")) {
		    /* build the full name */
		    fname = cli_malloc(strlen(dirname) + strlen(dent->d_name) + 2);
		    if(!fname) {
			closedir(dd);
			return CL_EMEM;
		    }

		    sprintf(fname, "%s"PATHSEP"%s", dirname, dent->d_name);

		    /* stat the file */
		    if(lstat(fname, &statbuf) != -1) {
			if(S_ISDIR(statbuf.st_mode) && !S_ISLNK(statbuf.st_mode)) {
			    if(cli_scandir(fname, ctx) == CL_VIRUS) {
				free(fname);

				if (SCAN_ALL) {
				    viruses_found++;
				    continue;
				}

                                closedir(dd);
                                return CL_VIRUS;
 			    }
			} else {
			    if(S_ISREG(statbuf.st_mode)) {
				if(cli_scanfile(fname, ctx) == CL_VIRUS) {
				    free(fname);

				    if (SCAN_ALL) {
					viruses_found++;
					continue;
				    }

                                    closedir(dd);
                                    return CL_VIRUS;
 				}
			    }
			}
		    }
		    free(fname);
		}
	    }
	}
    } else {
	cli_dbgmsg("cli_scandir: Can't open directory %s.\n", dirname);
	return CL_EOPEN;
    }

    closedir(dd);
    if (SCAN_ALL && viruses_found)
	return CL_VIRUS;
    return CL_CLEAN;
}

static int cli_unrar_scanmetadata(int desc, unrar_metadata_t *metadata, cli_ctx *ctx, unsigned int files, uint32_t* sfx_check)
{
	int ret = CL_SUCCESS;

    if(files == 1 && sfx_check) {
	if(*sfx_check == metadata->crc)
	    return CL_BREAK;/* break extract loop */
	else
	    *sfx_check = metadata->crc;
    }

    cli_dbgmsg("RAR: %s, crc32: 0x%x, encrypted: %u, compressed: %u, normal: %u, method: %u, ratio: %u\n",
	metadata->filename, metadata->crc, metadata->encrypted, (unsigned int) metadata->pack_size,
	(unsigned int) metadata->unpack_size, metadata->method,
	metadata->pack_size ? (unsigned int) (metadata->unpack_size / metadata->pack_size) : 0);

    if(cli_matchmeta(ctx, metadata->filename, metadata->pack_size, metadata->unpack_size, metadata->encrypted, files, metadata->crc, NULL) == CL_VIRUS)
	return CL_VIRUS;

    if(DETECT_ENCRYPTED && metadata->encrypted) {
	cli_dbgmsg("RAR: Encrypted files found in archive.\n");
	lseek(desc, 0, SEEK_SET);
	ret = cli_scandesc(desc, ctx, 0, 0, NULL, AC_SCAN_VIR, NULL);
	if(ret != CL_VIRUS) {
	    cli_append_virus(ctx, "Heuristics.Encrypted.RAR");
	    return CL_VIRUS;
	}
    }

    return ret;
}

static int cli_scanrar(int desc, cli_ctx *ctx, off_t sfx_offset, uint32_t *sfx_check)
{
	int ret = CL_CLEAN;
	unrar_metadata_t *metadata, *metadata_tmp;
	char *dir;
	unrar_state_t rar_state;
	unsigned int viruses_found = 0;

    cli_dbgmsg("in scanrar()\n");

    if(sfx_offset)
	if(lseek(desc, sfx_offset, SEEK_SET) == -1)
	    return CL_ESEEK;

    /* generate the temporary directory */
    if(!(dir = cli_gentemp(ctx->engine->tmpdir)))
	return CL_EMEM;

    if(mkdir(dir, 0700)) {
	cli_dbgmsg("RAR: Can't create temporary directory %s\n", dir);
	free(dir);
	return CL_ETMPDIR;
    }

    if((ret = cli_unrar_open(desc, dir, &rar_state)) != UNRAR_OK) {
	if(!ctx->engine->keeptmp)
	    cli_rmdirs(dir);
	free(dir);
	if(ret == UNRAR_PASSWD) {
	    cli_dbgmsg("RAR: Encrypted main header\n");
	    if(DETECT_ENCRYPTED) {
		lseek(desc, 0, SEEK_SET);
		ret = cli_scandesc(desc, ctx, 0, 0, NULL, AC_SCAN_VIR, NULL);
		if(ret != CL_VIRUS)
		    cli_append_virus(ctx, "Heuristics.Encrypted.RAR");
		return CL_VIRUS;
	    }
	    return CL_CLEAN;
	} if(ret == UNRAR_EMEM) {
	    return CL_EMEM;
	} else {
	    return CL_EUNPACK;
	}
    }

    do {
	int rc;
	rar_state.ofd = -1;
	ret = cli_unrar_extract_next_prepare(&rar_state,dir);
	if(ret != UNRAR_OK) {
	    if(ret == UNRAR_BREAK)
		ret = CL_BREAK;
	    else if(ret == UNRAR_EMEM)
		ret = CL_EMEM;
	    else
		ret = CL_EUNPACK;
	    break;
	}
	if(ctx->engine->maxscansize && ctx->scansize >= ctx->engine->maxscansize) {
	    free(rar_state.file_header->filename);
	    free(rar_state.file_header);
	    ret = CL_CLEAN;
	    break;
	}
	if(ctx->engine->maxscansize && ctx->scansize + ctx->engine->maxfilesize >= ctx->engine->maxscansize)
	    rar_state.maxfilesize = ctx->engine->maxscansize - ctx->scansize;
	else
	    rar_state.maxfilesize = ctx->engine->maxfilesize;

	ret = cli_unrar_extract_next(&rar_state,dir);
	if(ret == UNRAR_OK)
	    ret = CL_SUCCESS;
	else if(ret == UNRAR_EMEM)
	    ret = CL_EMEM;
	else
	    ret = CL_EFORMAT;

	if(rar_state.ofd > 0) {
	    lseek(rar_state.ofd,0,SEEK_SET);
	    rc = cli_magic_scandesc(rar_state.ofd,ctx);
	    close(rar_state.ofd);
	    if(!ctx->engine->keeptmp) 
		if (cli_unlink(rar_state.filename)) ret = CL_EUNLINK;
	    if(rc == CL_VIRUS ) {
		cli_dbgmsg("RAR: infected with %s\n", cli_get_last_virus(ctx));
		ret = CL_VIRUS;
		viruses_found++;
	    }
	}

	if(ret == CL_VIRUS) {
	    if(SCAN_ALL)
		ret = CL_SUCCESS;
	    else
		break;
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

    if(!ctx->engine->keeptmp)
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

    if (SCAN_ALL && viruses_found)
	return CL_VIRUS;
    return ret;
}

static int cli_scanarj(int desc, cli_ctx *ctx, off_t sfx_offset, uint32_t *sfx_check)
{
	int ret = CL_CLEAN, rc, file = 0;
	arj_metadata_t metadata;
	char *dir;

    cli_dbgmsg("in cli_scanarj()\n");

     /* generate the temporary directory */
    if(!(dir = cli_gentemp(ctx->engine->tmpdir)))
	return CL_EMEM;

    if(mkdir(dir, 0700)) {
	cli_dbgmsg("ARJ: Can't create temporary directory %s\n", dir);
	free(dir);
	return CL_ETMPDIR;
    }

    if(sfx_offset)
	lseek(desc, sfx_offset, SEEK_SET);

    ret = cli_unarj_open(desc, dir);
    if (ret != CL_SUCCESS) {
	if(!ctx->engine->keeptmp)
	    cli_rmdirs(dir);
	free(dir);
	cli_dbgmsg("ARJ: Error: %s\n", cl_strerror(ret));
	return ret;
    }
    
   do {
        metadata.filename = NULL;
	ret = cli_unarj_prepare_file(desc, dir, &metadata);
	if (ret != CL_SUCCESS) {
	   break;
	}
	file++;
	if(cli_matchmeta(ctx, metadata.filename, metadata.comp_size, metadata.orig_size, metadata.encrypted, file, 0, NULL) == CL_VIRUS)
	    return CL_VIRUS;

	if ((ret = cli_checklimits("ARJ", ctx, metadata.orig_size, metadata.comp_size, 0))!=CL_CLEAN) {
	    ret = CL_SUCCESS;
	    if (metadata.filename)
		free(metadata.filename);
	    continue;
	}
	ret = cli_unarj_extract_file(desc, dir, &metadata);
	if (metadata.ofd >= 0) {
	    lseek(metadata.ofd, 0, SEEK_SET);
	    rc = cli_magic_scandesc(metadata.ofd, ctx);
	    close(metadata.ofd);
	    if (rc == CL_VIRUS) {
		cli_dbgmsg("ARJ: infected with %s\n", cli_get_last_virus(ctx));
		ret = CL_VIRUS;
		if (metadata.filename) {
		    free(metadata.filename);
		    metadata.filename = NULL;
		}
		break;
	    }
	}
	if (metadata.filename) {
		free(metadata.filename);
		metadata.filename = NULL;
	}

    } while(ret == CL_SUCCESS);
    
    if(!ctx->engine->keeptmp)
	cli_rmdirs(dir);

    free(dir);
    if (metadata.filename) {
	free(metadata.filename);
    }

    cli_dbgmsg("ARJ: Exit code: %d\n", ret);
    if (ret == CL_BREAK)
	ret = CL_CLEAN;

    return ret;
}


static int cli_scangzip_with_zib_from_the_80s(cli_ctx *ctx, unsigned char *buff) {
    int fd, ret, outsize = 0, bytes;
    fmap_t *map = *ctx->fmap;
    char *tmpname;
    gzFile gz;

    fd = dup(map->fd);
    if(fd < 0)
	return CL_EDUP;

    lseek(fd, 0, SEEK_SET);
    if(!(gz = gzdopen(fd, "rb"))) {
	close(fd);
	return CL_EOPEN;
    }

    if((ret = cli_gentempfd(ctx->engine->tmpdir, &tmpname, &fd)) != CL_SUCCESS) {
	cli_dbgmsg("GZip: Can't generate temporary file.\n");
	gzclose(gz);
	return ret;
    }
    
    while((bytes = gzread(gz, buff, FILEBUFF)) > 0) {
	outsize += bytes;
	if(cli_checklimits("GZip", ctx, outsize, 0, 0)!=CL_CLEAN)
	    break;
	if(cli_writen(fd, buff, bytes) != bytes) {
	    close(fd);
	    gzclose(gz);
	    if(cli_unlink(tmpname)) {
		free(tmpname);
		return CL_EUNLINK;
	    }
	    free(tmpname);
	    return CL_EWRITE;
	}
    }

    gzclose(gz);

    if((ret = cli_magic_scandesc(fd, ctx)) == CL_VIRUS) {
	cli_dbgmsg("GZip: Infected with %s\n", cli_get_last_virus(ctx));
	close(fd);
	if(!ctx->engine->keeptmp) {
	    if (cli_unlink(tmpname)) {
	    	free(tmpname);
		return CL_EUNLINK;
	    }
	}
	free(tmpname);
	return CL_VIRUS;
    }
    close(fd);
    if(!ctx->engine->keeptmp)
	if (cli_unlink(tmpname)) ret = CL_EUNLINK;
    free(tmpname);
    return ret;
}

static int cli_scangzip(cli_ctx *ctx)
{
	int fd, ret = CL_CLEAN;
	unsigned char buff[FILEBUFF];
	char *tmpname;
	z_stream z;
	size_t at = 0, outsize = 0;
	fmap_t *map = *ctx->fmap;
 	
    cli_dbgmsg("in cli_scangzip()\n");

    memset(&z, 0, sizeof(z));
    if((ret = inflateInit2(&z, MAX_WBITS + 16)) != Z_OK) {
	cli_dbgmsg("GZip: InflateInit failed: %d\n", ret);
	return cli_scangzip_with_zib_from_the_80s(ctx, buff);
    }

    if((ret = cli_gentempfd(ctx->engine->tmpdir, &tmpname, &fd)) != CL_SUCCESS) {
	cli_dbgmsg("GZip: Can't generate temporary file.\n");
	inflateEnd(&z);
	return ret;
    }

    while (at < map->len) {
	unsigned int bytes = MIN(map->len - at, map->pgsz);
	if(!(z.next_in = fmap_need_off_once(map, at, bytes))) {
	    cli_dbgmsg("GZip: Can't read %u bytes @ %lu.\n", bytes, (long unsigned)at);
	    inflateEnd(&z);
	    close(fd);
	    if (cli_unlink(tmpname)) {
		free(tmpname);
		return CL_EUNLINK;
	    }
	    free(tmpname);
	    return CL_EREAD;
	}
	at += bytes;
	z.avail_in = bytes;
	do {
	    int inf;
	    z.avail_out = sizeof(buff);
            z.next_out = buff;
	    inf = inflate(&z, Z_NO_FLUSH);
	    if(inf != Z_OK && inf != Z_STREAM_END && inf != Z_BUF_ERROR) {
		cli_dbgmsg("GZip: Bad stream.\n");
		at = map->len;
		break;
	    }
	    if(cli_writen(fd, buff, sizeof(buff) - z.avail_out) < 0) {
		inflateEnd(&z);	    
		close(fd);
		if (cli_unlink(tmpname)) {
		    free(tmpname);
		    return CL_EUNLINK;
		}
		free(tmpname);
		return CL_EWRITE;
	    }
	    outsize += sizeof(buff) - z.avail_out;
	    if(cli_checklimits("GZip", ctx, outsize, 0, 0)!=CL_CLEAN) {
		at = map->len;
		break;
	    }
	    if(inf == Z_STREAM_END) {
		at -= z.avail_in;
		inflateReset(&z);
		break;
	    }
	} while (z.avail_out == 0);
    }

    inflateEnd(&z);	    

    if((ret = cli_magic_scandesc(fd, ctx)) == CL_VIRUS) {
	cli_dbgmsg("GZip: Infected with %s\n", cli_get_last_virus(ctx));
	close(fd);
	if(!ctx->engine->keeptmp) {
	    if (cli_unlink(tmpname)) {
	    	free(tmpname);
		return CL_EUNLINK;
	    }
	}
	free(tmpname);
	return CL_VIRUS;
    }
    close(fd);
    if(!ctx->engine->keeptmp)
	if (cli_unlink(tmpname)) ret = CL_EUNLINK;
    free(tmpname);
    return ret;
}


#ifndef HAVE_BZLIB_H
static int cli_scanbzip(int desc, cli_ctx *ctx) {
    cli_warnmsg("cli_scanbzip: bzip2 support not compiled in\n");
    return CL_CLEAN;
}

#else

#ifdef NOBZ2PREFIX
#define BZ2_bzReadOpen bzReadOpen
#define BZ2_bzReadClose bzReadClose
#define BZ2_bzRead bzRead
#endif

static int cli_scanbzip(int desc, cli_ctx *ctx)
{
	int fd, bytes, ret = CL_CLEAN, bzerror = 0;
	unsigned long int size = 0;
	char *buff;
	FILE *fs;
	char *tmpname;
	BZFILE *bfd;


    if((fs = fdopen(dup(desc), "rb")) == NULL) {
	cli_dbgmsg("Bzip: Can't open descriptor %d.\n", desc);
	return CL_EOPEN;
    }

    if((bfd = BZ2_bzReadOpen(&bzerror, fs, 0, 0, NULL, 0)) == NULL) {
	cli_dbgmsg("Bzip: Can't initialize bzip2 library (descriptor: %d).\n", desc);
	fclose(fs);
	return CL_EOPEN;
    }

    if((ret = cli_gentempfd(ctx->engine->tmpdir, &tmpname, &fd))) {
	cli_dbgmsg("Bzip: Can't generate temporary file.\n");
	BZ2_bzReadClose(&bzerror, bfd);
	fclose(fs);
	return ret;
    }

    if(!(buff = (char *) cli_malloc(FILEBUFF))) {
	cli_dbgmsg("Bzip: Unable to malloc %u bytes.\n", FILEBUFF);
	close(fd);
	if(!ctx->engine->keeptmp) {
	    if (cli_unlink(tmpname)) {
	    	free(tmpname);
		fclose(fs);
		BZ2_bzReadClose(&bzerror, bfd);
		return CL_EUNLINK;
	    }
	}
	free(tmpname);	
	fclose(fs);
	BZ2_bzReadClose(&bzerror, bfd);
	return CL_EMEM;
    }

    while((bytes = BZ2_bzRead(&bzerror, bfd, buff, FILEBUFF)) > 0) {
	size += bytes;

	if(cli_checklimits("Bzip", ctx, size + FILEBUFF, 0, 0)!=CL_CLEAN)
	    break;

	if(cli_writen(fd, buff, bytes) != bytes) {
	    cli_dbgmsg("Bzip: Can't write to file.\n");
	    BZ2_bzReadClose(&bzerror, bfd);
	    close(fd);
	    if(!ctx->engine->keeptmp) {
		if (cli_unlink(tmpname)) {
		    free(tmpname);
		    free(buff);
		    fclose(fs);
		    return CL_EUNLINK;
		}
	    }
	    free(tmpname);	
	    free(buff);
	    fclose(fs);
	    return CL_EWRITE;
	}
    }

    free(buff);
    BZ2_bzReadClose(&bzerror, bfd);

    if(ret == CL_VIRUS) {
	close(fd);
	if(!ctx->engine->keeptmp)
	    if (cli_unlink(tmpname)) ret = CL_EUNLINK;
	free(tmpname);	
	fclose(fs);
	return ret;
    }

    lseek(fd, 0, SEEK_SET);
    if((ret = cli_magic_scandesc(fd, ctx)) == CL_VIRUS ) {
	cli_dbgmsg("Bzip: Infected with %s\n", cli_get_last_virus(ctx));
    }
    close(fd);
    if(!ctx->engine->keeptmp)
	if (cli_unlink(tmpname)) ret = CL_EUNLINK;
    free(tmpname);	
    fclose(fs);

    return ret;
}
#endif

static int cli_scanszdd(int desc, cli_ctx *ctx)
{
	int ofd, ret;
	char *tmpname;


    cli_dbgmsg("in cli_scanszdd()\n");

    if((ret = cli_gentempfd(ctx->engine->tmpdir, &tmpname, &ofd))) {
	cli_dbgmsg("MSEXPAND: Can't generate temporary file/descriptor\n");
	return ret;
    }

    lseek(desc, 0, SEEK_SET);
    ret = cli_msexpand(desc, ofd, ctx);

    if(ret != CL_SUCCESS) { /* CL_VIRUS or some error */
	close(ofd);
	if(!ctx->engine->keeptmp)
	    if (cli_unlink(tmpname)) ret = CL_EUNLINK;
	free(tmpname);	
	return ret;
    }

    cli_dbgmsg("MSEXPAND: Decompressed into %s\n", tmpname);
    lseek(ofd, 0, SEEK_SET);
    ret = cli_magic_scandesc(ofd, ctx);
    close(ofd);
    if(!ctx->engine->keeptmp)
	if (cli_unlink(tmpname)) ret = CL_EUNLINK;
    free(tmpname);	

    return ret;
}

static int cli_scanmscab(int desc, cli_ctx *ctx, off_t sfx_offset)
{
	char *tempname;
	int ret;
	unsigned int files = 0;
	struct cab_archive cab;
	struct cab_file *file;
	unsigned int corrupted_input;
	unsigned int viruses_found = 0;

    cli_dbgmsg("in cli_scanmscab()\n");

    if((ret = cab_open(desc, sfx_offset, &cab)))
	return ret;

    for(file = cab.files; file; file = file->next) {
	files++;

	if(cli_matchmeta(ctx, file->name, 0, file->length, 0, files, 0, NULL) == CL_VIRUS) {
	    if (!SCAN_ALL) {
		ret = CL_VIRUS;
		break;
	    }
	    viruses_found++;
	}

	if(ctx->engine->maxscansize && ctx->scansize >= ctx->engine->maxscansize) {
	    ret = CL_CLEAN;
	    break;
	}

	if(!(tempname = cli_gentemp(ctx->engine->tmpdir))) {
	    ret = CL_EMEM;
	    break;
	}

	if(ctx->engine->maxscansize && ctx->scansize + ctx->engine->maxfilesize >= ctx->engine->maxscansize)
	    file->max_size = ctx->engine->maxscansize - ctx->scansize;
	else
	    file->max_size = ctx->engine->maxfilesize ? ctx->engine->maxfilesize : 0xffffffff;

	cli_dbgmsg("CAB: Extracting file %s to %s, size %u, max_size: %u\n", file->name, tempname, file->length, (unsigned int) file->max_size);
	file->written_size = 0;
	if((ret = cab_extract(file, tempname))) {
	    cli_dbgmsg("CAB: Failed to extract file: %s\n", cl_strerror(ret));
	} else {
	    corrupted_input = ctx->corrupted_input;
	    if(file->length != file->written_size) {
		cli_dbgmsg("CAB: Length from header %u but wrote %u bytes\n", (unsigned int) file->length, (unsigned int) file->written_size);
		ctx->corrupted_input = 1;
	    }
	    ret = cli_scanfile(tempname, ctx);
	    ctx->corrupted_input = corrupted_input;
	}
	if(!ctx->engine->keeptmp) {
	    if (!access(tempname, R_OK) && cli_unlink(tempname)) {
	    	free(tempname);
		ret = CL_EUNLINK;
		break;
	    }
	}
	free(tempname);
	if(ret == CL_VIRUS) {
	    if (SCAN_ALL)
		viruses_found++;
	    else
		break;
	}
    }

    cab_free(&cab);
    if (viruses_found)
	return CL_VIRUS;
    return ret;
}

static int vba_scandata(const unsigned char *data, unsigned int len, cli_ctx *ctx)
{
	struct cli_matcher *groot = ctx->engine->root[0];
	struct cli_matcher *troot = ctx->engine->root[2];
	struct cli_ac_data gmdata, tmdata;
	struct cli_ac_data *mdata[2];
	int ret;
	unsigned int viruses_found = 0;

    if((ret = cli_ac_initdata(&tmdata, troot->ac_partsigs, troot->ac_lsigs, troot->ac_reloff_num, CLI_DEFAULT_AC_TRACKLEN)))
	return ret;

    if((ret = cli_ac_initdata(&gmdata, groot->ac_partsigs, groot->ac_lsigs, groot->ac_reloff_num, CLI_DEFAULT_AC_TRACKLEN))) {
	cli_ac_freedata(&tmdata);
	return ret;
    }
    mdata[0] = &tmdata;
    mdata[1] = &gmdata;

    ret = cli_scanbuff(data, len, 0, ctx, CL_TYPE_MSOLE2, mdata);

    if(ret != CL_VIRUS || SCAN_ALL) {
	if (SCAN_ALL)
	    viruses_found++;
	ret = cli_lsig_eval(ctx, troot, &tmdata, NULL, NULL);
	if(ret != CL_VIRUS || SCAN_ALL)
	    if (SCAN_ALL)
		viruses_found++;
	    ret = cli_lsig_eval(ctx, groot, &gmdata, NULL, NULL);
    }
    cli_ac_freedata(&tmdata);
    cli_ac_freedata(&gmdata);

    if (viruses_found)
	return CL_VIRUS;
    return ret;
}

static int cli_vba_scandir(const char *dirname, cli_ctx *ctx, struct uniq *U)
{
	int ret = CL_CLEAN, i, j, fd, data_len, hasmacros = 0;
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
	char *fullname, vbaname[1024];
	unsigned char *data;
	char *hash;
	uint32_t hashcnt;
	unsigned int viruses_found = 0;


    cli_dbgmsg("VBADir: %s\n", dirname);
    hashcnt = uniq_get(U, "_vba_project", 12, NULL);
    while(hashcnt--) {
	if(!(vba_project = (vba_project_t *)cli_vba_readdir(dirname, U, hashcnt))) continue;

	for(i = 0; i < vba_project->count; i++) {
	    for(j = 0; (unsigned int)j < vba_project->colls[i]; j++) {
		snprintf(vbaname, 1024, "%s"PATHSEP"%s_%u", vba_project->dir, vba_project->name[i], j);
		vbaname[sizeof(vbaname)-1] = '\0';
		fd = open(vbaname, O_RDONLY|O_BINARY);
		if(fd == -1) continue;
		cli_dbgmsg("VBADir: Decompress VBA project '%s_%u'\n", vba_project->name[i], j);
		data = (unsigned char *)cli_vba_inflate(fd, vba_project->offset[i], &data_len);
		close(fd);
		hasmacros++;
		if(!data) {
		    cli_dbgmsg("VBADir: WARNING: VBA project '%s_%u' decompressed to NULL\n", vba_project->name[i], j);
		} else {
		    /* cli_dbgmsg("Project content:\n%s", data); */
		    if(ctx->scanned)
			*ctx->scanned += data_len / CL_COUNT_PRECISION;
		    if(vba_scandata(data, data_len, ctx) == CL_VIRUS) {
			if (SCAN_ALL) 
			    viruses_found++;
			else {
			    free(data);
			    ret = CL_VIRUS;
			    break;
			}
		    }
		    free(data);
		}
	    }
	}

	free(vba_project->name);
	free(vba_project->colls);
	free(vba_project->dir);
	free(vba_project->offset);
	free(vba_project);
	if (ret == CL_VIRUS && !SCAN_ALL)
	    break;
    }

    if((ret == CL_CLEAN || (ret == CL_VIRUS && SCAN_ALL)) && 
	(hashcnt = uniq_get(U, "powerpoint document", 19, &hash))) {
	while(hashcnt--) {
	    snprintf(vbaname, 1024, "%s"PATHSEP"%s_%u", dirname, hash, hashcnt);
	    vbaname[sizeof(vbaname)-1] = '\0';
	    fd = open(vbaname, O_RDONLY|O_BINARY);
	    if (fd == -1) continue;
	    if ((fullname = cli_ppt_vba_read(fd, ctx))) {
		if(cli_scandir(fullname, ctx) == CL_VIRUS) {
		    ret = CL_VIRUS;
		    viruses_found++;
		}
		if(!ctx->engine->keeptmp)
		    cli_rmdirs(fullname);
		free(fullname);
	    }
	    close(fd);
	}
    }

    if ((ret == CL_CLEAN || (ret == CL_VIRUS && SCAN_ALL)) && 
	(hashcnt = uniq_get(U, "worddocument", 12, &hash))) {
	while(hashcnt--) {
	    snprintf(vbaname, sizeof(vbaname), "%s"PATHSEP"%s_%u", dirname, hash, hashcnt);
	    vbaname[sizeof(vbaname)-1] = '\0';
	    fd = open(vbaname, O_RDONLY|O_BINARY);
	    if (fd == -1) continue;
	    
	    if (!(vba_project = (vba_project_t *)cli_wm_readdir(fd))) {
		close(fd);
		continue;
	    }

	    for (i = 0; i < vba_project->count; i++) {
		cli_dbgmsg("VBADir: Decompress WM project macro:%d key:%d length:%d\n", i, vba_project->key[i], vba_project->length[i]);
		data = (unsigned char *)cli_wm_decrypt_macro(fd, vba_project->offset[i], vba_project->length[i], vba_project->key[i]);
		if(!data) {
			cli_dbgmsg("VBADir: WARNING: WM project '%s' macro %d decrypted to NULL\n", vba_project->name[i], i);
		} else {
			cli_dbgmsg("Project content:\n%s", data);
			if(ctx->scanned)
			    *ctx->scanned += vba_project->length[i] / CL_COUNT_PRECISION;
			if(vba_scandata(data, vba_project->length[i], ctx) == CL_VIRUS) {
			    if (SCAN_ALL)
				viruses_found++;
			    else {
				free(data);
				ret = CL_VIRUS;
				break;
			    }
			}
			free(data);
		}
	    }

	    close(fd);
	    free(vba_project->name);
	    free(vba_project->colls);
	    free(vba_project->dir);
	    free(vba_project->offset);
	    free(vba_project->key);
	    free(vba_project->length);
	    free(vba_project);
	    if(ret == CL_VIRUS) {
		if (SCAN_ALL)
		    viruses_found++;
		else
		    break;
	    }
	}
    }

    if(ret != CL_CLEAN && !(ret == CL_VIRUS && SCAN_ALL))
    	return ret;

    /* Check directory for embedded OLE objects */
    hashcnt = uniq_get(U, "_1_ole10native", 14, &hash);
    while(hashcnt--) {
	snprintf(vbaname, sizeof(vbaname), "%s"PATHSEP"%s_%u", dirname, hash, hashcnt);
	vbaname[sizeof(vbaname)-1] = '\0';

	fd = open(vbaname, O_RDONLY|O_BINARY);
	if (fd >= 0) {
	    ret = cli_scan_ole10(fd, ctx);
	    close(fd);
	    if(ret != CL_CLEAN && !(ret == CL_VIRUS && SCAN_ALL))
		return ret;
	}
    }


    /* ACAB: since we now hash filenames and handle collisions we
     * could avoid recursion by removing the block below and by
     * flattening the paths in ole2_walk_property_tree (case 1) */

    if((dd = opendir(dirname)) != NULL) {
#ifdef HAVE_READDIR_R_3
	while(!readdir_r(dd, &result.d, &dent) && dent) {
#elif defined(HAVE_READDIR_R_2)
	while((dent = (struct dirent *) readdir_r(dd, &result.d))) {
#else
	while((dent = readdir(dd))) {
#endif
	    if(dent->d_ino)
	    {
		if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..")) {
		    /* build the full name */
		    fullname = cli_malloc(strlen(dirname) + strlen(dent->d_name) + 2);
		    if(!fullname) {
			ret = CL_EMEM;
			break;
		    }
		    sprintf(fullname, "%s"PATHSEP"%s", dirname, dent->d_name);

		    /* stat the file */
		    if(lstat(fullname, &statbuf) != -1) {
			if(S_ISDIR(statbuf.st_mode) && !S_ISLNK(statbuf.st_mode))
			  if (cli_vba_scandir(fullname, ctx, U) == CL_VIRUS) {
			      if (SCAN_ALL)
				  viruses_found++;
			      else {
				  ret = CL_VIRUS;
				  free(fullname);
				  break;
			      }
			  }
		    }
		    free(fullname);
		}
	    }
	}
    } else {
	cli_dbgmsg("VBADir: Can't open directory %s.\n", dirname);
	return CL_EOPEN;
    }

    closedir(dd);
    if(BLOCK_MACROS && hasmacros) {
	cli_append_virus(ctx, "Heuristics.OLE2.ContainsMacros");
	ret = CL_VIRUS;
	viruses_found++;
    }
    if (SCAN_ALL && viruses_found)
	return CL_VIRUS;
    return ret;
}

static int cli_scanhtml(cli_ctx *ctx)
{
	char *tempname, fullname[1024];
	int ret=CL_CLEAN, fd;
	fmap_t *map = *ctx->fmap;
	unsigned int viruses_found = 0;

    cli_dbgmsg("in cli_scanhtml()\n");

    /* Because HTML detection is FP-prone and html_normalise_fd() needs to
     * mmap the file don't normalise files larger than 10 MB.
     */

    if(map->len > 10485760) {
	cli_dbgmsg("cli_scanhtml: exiting (file larger than 10 MB)\n");
	return CL_CLEAN;
    }

    if(!(tempname = cli_gentemp(ctx->engine->tmpdir)))
	return CL_EMEM;

    if(mkdir(tempname, 0700)) {
        cli_errmsg("cli_scanhtml: Can't create temporary directory %s\n", tempname);
	free(tempname);
        return CL_ETMPDIR;
    }

    cli_dbgmsg("cli_scanhtml: using tempdir %s\n", tempname);

    html_normalise_map(map, tempname, NULL, ctx->dconf);
    snprintf(fullname, 1024, "%s"PATHSEP"nocomment.html", tempname);
    fd = open(fullname, O_RDONLY|O_BINARY);
    if (fd >= 0) {
	if ((ret = cli_scandesc(fd, ctx, CL_TYPE_HTML, 0, NULL, AC_SCAN_VIR, NULL)) == CL_VIRUS)
	    viruses_found++;
	close(fd);
    }

    if((ret == CL_CLEAN || (ret == CL_VIRUS && SCAN_ALL)) && map->len < 2097152) {
	    /* limit to 2 MB, we're not interesting in scanning large files in notags form */
	    /* TODO: don't even create notags if file is over 2 MB */
	    snprintf(fullname, 1024, "%s"PATHSEP"notags.html", tempname);
	    fd = open(fullname, O_RDONLY|O_BINARY);
	    if(fd >= 0) {
		if ((ret = cli_scandesc(fd, ctx, CL_TYPE_HTML, 0, NULL, AC_SCAN_VIR, NULL)) == CL_VIRUS) 
		    viruses_found++;
		close(fd);
	    }
    }

    if(ret == CL_CLEAN || (ret == CL_VIRUS && SCAN_ALL)) {
	    snprintf(fullname, 1024, "%s"PATHSEP"javascript", tempname);
	    fd = open(fullname, O_RDONLY|O_BINARY);
	    if(fd >= 0) {
		if ((ret = cli_scandesc(fd, ctx, CL_TYPE_HTML, 0, NULL, AC_SCAN_VIR, NULL)) == CL_VIRUS)
		    viruses_found++;
		if (ret == CL_CLEAN || (ret == CL_VIRUS && SCAN_ALL)) {
		    if ((ret = cli_scandesc(fd, ctx, CL_TYPE_TEXT_ASCII, 0, NULL, AC_SCAN_VIR, NULL)) == CL_VIRUS)
			viruses_found++;
		}
		close(fd);
	    }
    }

    if (ret == CL_CLEAN || (ret == CL_VIRUS && SCAN_ALL)) {
	snprintf(fullname, 1024, "%s"PATHSEP"rfc2397", tempname);
	ret = cli_scandir(fullname, ctx);
    }

    if(!ctx->engine->keeptmp)
        cli_rmdirs(tempname);

    free(tempname);
    if (SCAN_ALL && viruses_found)
	return CL_VIRUS;
    return ret;
}

static int cli_scanscript(cli_ctx *ctx)
{
	unsigned char *buff;
	unsigned char* normalized;
	struct text_norm_state state;
	char *tmpname = NULL;
	int ofd = -1, ret;
	struct cli_matcher *troot = ctx->engine->root[7];
	uint32_t maxpatlen = troot ? troot->maxpatlen : 0, offset = 0;
	struct cli_matcher *groot = ctx->engine->root[0];
	struct cli_ac_data gmdata, tmdata;
	struct cli_ac_data *mdata[2];
	fmap_t *map = *ctx->fmap;
	size_t at = 0;
        unsigned int viruses_found = 0;

	cli_dbgmsg("in cli_scanscript()\n");

	if(map->len > 5242880) {
		cli_dbgmsg("cli_scanscript: exiting (file larger than 5 MB)\n");
		return CL_CLEAN;
	}

	/* dump to disk only if explicitly asked to,
	 * otherwise we can process just in-memory */
	if(ctx->engine->keeptmp) {
		if((ret = cli_gentempfd(ctx->engine->tmpdir, &tmpname, &ofd))) {
			cli_dbgmsg("cli_scanscript: Can't generate temporary file/descriptor\n");
			return ret;
		}
		cli_dbgmsg("cli_scanscript: saving normalized file to %s\n", tmpname);
	}

	if(!(normalized = cli_malloc(SCANBUFF + maxpatlen))) {
		cli_dbgmsg("cli_scanscript: Unable to malloc %u bytes\n", SCANBUFF);
		return CL_EMEM;
	}

	text_normalize_init(&state, normalized, SCANBUFF + maxpatlen);
	ret = CL_CLEAN;

	if ((ret = cli_ac_initdata(&tmdata, troot->ac_partsigs, troot->ac_lsigs, troot->ac_reloff_num, CLI_DEFAULT_AC_TRACKLEN)))
	    return ret;

	if ((ret = cli_ac_initdata(&gmdata, groot->ac_partsigs, groot->ac_lsigs, groot->ac_reloff_num, CLI_DEFAULT_AC_TRACKLEN))) {
	    cli_ac_freedata(&tmdata);
	    return ret;
	}
	mdata[0] = &tmdata;
	mdata[1] = &gmdata;

	while(1) {
	    size_t len = MIN(map->pgsz, map->len - at);
	    buff = fmap_need_off_once(map, at, len);
	    at += len;
	    if(!buff || !len || state.out_pos + len > state.out_len) {
		/* flush if error/EOF, or too little buffer space left */
		if((ofd != -1) && (write(ofd, state.out, state.out_pos) == -1)) {
		    cli_errmsg("cli_scanscript: can't write to file %s\n",tmpname);
		    close(ofd);
		    ofd = -1;
		    /* we can continue to scan in memory */
		}
		/* when we flush the buffer also scan */
		if(cli_scanbuff(state.out, state.out_pos, offset, ctx, CL_TYPE_TEXT_ASCII, mdata) == CL_VIRUS) {
		    if (SCAN_ALL)
			viruses_found++;
		    else {
			ret = CL_VIRUS;
			break;
		    }
		}
		if(ctx->scanned)
		    *ctx->scanned += state.out_pos / CL_COUNT_PRECISION;
		offset += state.out_pos;
		/* carry over maxpatlen from previous buffer */
		if (state.out_pos > maxpatlen)
		    memmove(state.out, state.out + state.out_pos - maxpatlen, maxpatlen); 
		text_normalize_reset(&state);
		state.out_pos = maxpatlen;
	    }
	    if(!len) break;
	    if(text_normalize_buffer(&state, buff, len) != len) {
		cli_dbgmsg("cli_scanscript: short read during normalizing\n");
	    }
	}
	if(ctx->engine->keeptmp) {
		free(tmpname);
		close(ofd);
	}
	free(normalized);
	if(ret != CL_VIRUS || SCAN_ALL)  {
	    if ((ret = cli_lsig_eval(ctx, troot, &tmdata, NULL, NULL)) == CL_VIRUS)
		viruses_found++;
	    if(ret != CL_VIRUS || SCAN_ALL)
		if ((ret = cli_lsig_eval(ctx, groot, &gmdata, NULL, NULL)) == CL_VIRUS)
		    viruses_found++;
	}
	cli_ac_freedata(&tmdata);
	cli_ac_freedata(&gmdata);

	if (SCAN_ALL && viruses_found)
	    return CL_VIRUS;
	return ret;
}

static int cli_scanhtml_utf16(cli_ctx *ctx)
{
	char *tempname, *decoded, *buff;
	int ret = CL_CLEAN, fd, bytes;
	size_t at = 0;
	fmap_t *map = *ctx->fmap;

    cli_dbgmsg("in cli_scanhtml_utf16()\n");

    if(!(tempname = cli_gentemp(ctx->engine->tmpdir)))
	return CL_EMEM;

    if((fd = open(tempname, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU)) < 0) {
	cli_errmsg("cli_scanhtml_utf16: Can't create file %s\n", tempname);
	free(tempname);
	return CL_EOPEN;
    }

    cli_dbgmsg("cli_scanhtml_utf16: using tempfile %s\n", tempname);

    while(at < map->len) {
	bytes = MIN(map->len - at, map->pgsz * 16);
	if(!(buff = fmap_need_off_once(map, at, bytes))) {
	    close(fd);
	    cli_unlink(tempname);
	    free(tempname);
	    return CL_EREAD;
	}
	at += bytes;
	decoded = cli_utf16toascii(buff, bytes);
	if(decoded) {
	    if(write(fd, decoded, bytes / 2) == -1) {
		cli_errmsg("cli_scanhtml_utf16: Can't write to file %s\n", tempname);
		free(decoded);
		close(fd);
		cli_unlink(tempname);
		free(tempname);
		return CL_EWRITE;
	    }
	    free(decoded);
	}
    }

    *ctx->fmap = fmap(fd, 0, 0);
    if(*ctx->fmap) {
	ret = cli_scanhtml(ctx);
	funmap(*ctx->fmap);
    } else
	cli_errmsg("cli_scanhtml_utf16: fmap of %s failed\n", tempname);

    *ctx->fmap = map;
    close(fd);

    if(!ctx->engine->keeptmp) {
	if (cli_unlink(tempname)) ret = CL_EUNLINK;
    } else
	cli_dbgmsg("cli_scanhtml_utf16: Decoded HTML data saved in %s\n", tempname);
    free(tempname);

    return ret;
}

static int cli_scanole2(cli_ctx *ctx)
{
	char *dir;
	int ret = CL_CLEAN;
	struct uniq *vba = NULL;

    cli_dbgmsg("in cli_scanole2()\n");

    if(ctx->engine->maxreclevel && ctx->recursion >= ctx->engine->maxreclevel)
        return CL_EMAXREC;

    /* generate the temporary directory */
    if(!(dir = cli_gentemp(ctx->engine->tmpdir)))
	return CL_EMEM;

    if(mkdir(dir, 0700)) {
	cli_dbgmsg("OLE2: Can't create temporary directory %s\n", dir);
	free(dir);
	return CL_ETMPDIR;
    }

    ret = cli_ole2_extract(dir, ctx, &vba);
    if(ret!=CL_CLEAN && ret!=CL_VIRUS) {
	cli_dbgmsg("OLE2: %s\n", cl_strerror(ret));
	if(!ctx->engine->keeptmp)
	    cli_rmdirs(dir);
	free(dir);
	return ret;
    }

    if (vba) {
        ctx->recursion++;

	ret = cli_vba_scandir(dir, ctx, vba);
	uniq_free(vba);
	if(ret != CL_VIRUS)
	    if(cli_scandir(dir, ctx) == CL_VIRUS)
	        ret = CL_VIRUS;
	ctx->recursion--;
    }

    if(!ctx->engine->keeptmp)
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
    if(!(dir = cli_gentemp(ctx->engine->tmpdir)))
	return CL_EMEM;

    if(mkdir(dir, 0700)) {
	cli_errmsg("Tar: Can't create temporary directory %s\n", dir);
	free(dir);
	return CL_ETMPDIR;
    }

    ret = cli_untar(dir, desc, posix, ctx);

    if(!ctx->engine->keeptmp)
	cli_rmdirs(dir);

    free(dir);
    return ret;
}

static int cli_scanmschm(int desc, cli_ctx *ctx)
{
	int ret = CL_CLEAN, rc;
	chm_metadata_t metadata;
	char *dir;
	unsigned int viruses_found = 0;

    cli_dbgmsg("in cli_scanmschm()\n");

     /* generate the temporary directory */
    if(!(dir = cli_gentemp(ctx->engine->tmpdir)))
	return CL_EMEM;

    if(mkdir(dir, 0700)) {
	cli_dbgmsg("CHM: Can't create temporary directory %s\n", dir);
	free(dir);
	return CL_ETMPDIR;
    }

    ret = cli_chm_open(desc, dir, &metadata, ctx);
    if (ret != CL_SUCCESS) {
	if(!ctx->engine->keeptmp)
	    cli_rmdirs(dir);
	free(dir);
	cli_dbgmsg("CHM: Error: %s\n", cl_strerror(ret));
	return ret;
    }

   do {
	ret = cli_chm_prepare_file(&metadata);
	if (ret != CL_SUCCESS) {
	   break;
	}
	ret = cli_chm_extract_file(dir, &metadata, ctx);
	if (ret == CL_SUCCESS) {
	    lseek(metadata.ofd, 0, SEEK_SET);
	    rc = cli_magic_scandesc(metadata.ofd, ctx);
	    close(metadata.ofd);
	    if (rc == CL_VIRUS) {
		cli_dbgmsg("CHM: infected with %s\n", cli_get_last_virus(ctx));
		if (SCAN_ALL)
		    viruses_found++;
		else {
		    ret = CL_VIRUS;
		    break;
		}
	    }
	}

    } while(ret == CL_SUCCESS);

    cli_chm_close(&metadata);
   
    if(!ctx->engine->keeptmp)
	cli_rmdirs(dir);

    free(dir);

    cli_dbgmsg("CHM: Exit code: %d\n", ret);
    if (ret == CL_BREAK)
	ret = CL_CLEAN;

    if (SCAN_ALL && viruses_found)
	return CL_VIRUS;
    return ret;
}

static int cli_scanscrenc(int desc, cli_ctx *ctx)
{
	char *tempname;
	int ret = CL_CLEAN;

    cli_dbgmsg("in cli_scanscrenc()\n");

    if(!(tempname = cli_gentemp(ctx->engine->tmpdir)))
	return CL_EMEM;

    if(mkdir(tempname, 0700)) {
	cli_dbgmsg("CHM: Can't create temporary directory %s\n", tempname);
	free(tempname);
	return CL_ETMPDIR;
    }

    if (html_screnc_decode(desc, tempname))
	ret = cli_scandir(tempname, ctx);

    if(!ctx->engine->keeptmp)
	cli_rmdirs(tempname);

    free(tempname);
    return ret;
}

static int cli_scanriff(int desc, cli_ctx *ctx)
{
	int ret = CL_CLEAN;

    if(cli_check_riff_exploit(desc) == 2) {
	ret = CL_VIRUS;
	cli_append_virus(ctx, "Heuristics.Exploit.W32.MS05-002");
    }

    return ret;
}

static int cli_scanjpeg(int desc, cli_ctx *ctx)
{
	int ret = CL_CLEAN;

    if(cli_check_jpeg_exploit(desc, ctx) == 1) {
	ret = CL_VIRUS;
	cli_append_virus(ctx, "Heuristics.Exploit.W32.MS04-028");
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
	return CL_ESTAT;
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
	return CL_EREAD;
    }

    for(i = 0; i < length; i++)
	dest[i] = src[i] ^ (unsigned char) 0xff;

    free(src);

    if(!(tempfile = cli_gentemp(ctx->engine->tmpdir))) {
	free(dest);
	return CL_EMEM;
    }

    if((ndesc = open(tempfile, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU)) < 0) {
	cli_errmsg("CryptFF: Can't create file %s\n", tempfile);
	free(dest);
	free(tempfile);
	return CL_ECREAT;
    }

    if(write(ndesc, dest, length) == -1) {
	cli_dbgmsg("CryptFF: Can't write to descriptor %d\n", ndesc);
	free(dest);
	close(ndesc);
	free(tempfile);
	return CL_EWRITE;
    }

    free(dest);

    lseek(ndesc, 0, SEEK_SET);

    cli_dbgmsg("CryptFF: Scanning decrypted data\n");

    if((ret = cli_magic_scandesc(ndesc, ctx)) == CL_VIRUS)
	cli_dbgmsg("CryptFF: Infected with %s\n", cli_get_last_virus_str(ctx));

    close(ndesc);

    if(ctx->engine->keeptmp)
	cli_dbgmsg("CryptFF: Decompressed data saved in %s\n", tempfile);
    else
	if (cli_unlink(tempfile)) ret = CL_EUNLINK;

    free(tempfile);
    return ret;
}

static int cli_scanpdf(cli_ctx *ctx, off_t offset)
{
	int ret;
	char *dir = cli_gentemp(ctx->engine->tmpdir);

    if(!dir)
	return CL_EMEM;

    if(mkdir(dir, 0700)) {
	cli_dbgmsg("Can't create temporary directory for PDF file %s\n", dir);
	free(dir);
	return CL_ETMPDIR;
    }

    ret = cli_pdf(dir, ctx, offset);

    if(!ctx->engine->keeptmp)
	cli_rmdirs(dir);

    free(dir);
    return ret;
}

static int cli_scantnef(int desc, cli_ctx *ctx)
{
	int ret;
	char *dir = cli_gentemp(ctx->engine->tmpdir);

    if(!dir)
	return CL_EMEM;

    if(mkdir(dir, 0700)) {
	cli_dbgmsg("Can't create temporary directory for tnef file %s\n", dir);
	free(dir);
	return CL_ETMPDIR;
    }

    ret = cli_tnef(dir, desc, ctx);

    if(ret == CL_CLEAN)
	ret = cli_scandir(dir, ctx);

    if(!ctx->engine->keeptmp)
	cli_rmdirs(dir);

    free(dir);
    return ret;
}

static int cli_scanuuencoded(cli_ctx *ctx)
{
	int ret;
	char *dir = cli_gentemp(ctx->engine->tmpdir);

    if(!dir)
	return CL_EMEM;

    if(mkdir(dir, 0700)) {
	cli_dbgmsg("Can't create temporary directory for uuencoded file %s\n", dir);
	free(dir);
	return CL_ETMPDIR;
    }

    ret = cli_uuencode(dir, *ctx->fmap);

    if(ret == CL_CLEAN)
	ret = cli_scandir(dir, ctx);

    if(!ctx->engine->keeptmp)
	cli_rmdirs(dir);

    free(dir);
    return ret;
}

static int cli_scanmail(int desc, cli_ctx *ctx)
{
	char *dir;
	int ret;
	unsigned int viruses_found = 0;

    cli_dbgmsg("Starting cli_scanmail(), recursion = %u\n", ctx->recursion);

    /* generate the temporary directory */
    if(!(dir = cli_gentemp(ctx->engine->tmpdir)))
	return CL_EMEM;

    if(mkdir(dir, 0700)) {
	cli_dbgmsg("Mail: Can't create temporary directory %s\n", dir);
	free(dir);
	return CL_ETMPDIR;
    }

    /*
     * Extract the attachments into the temporary directory
     */
    if((ret = cli_mbox(dir, desc, ctx))) {
	if (ret == CL_VIRUS && SCAN_ALL)
	    viruses_found++;
	else {
	    if(!ctx->engine->keeptmp)
		cli_rmdirs(dir);
	    free(dir);
	    return ret;
	}
    }

    ret = cli_scandir(dir, ctx);

    if(!ctx->engine->keeptmp)
	cli_rmdirs(dir);

    free(dir);
    if (SCAN_ALL && viruses_found)
	return CL_VIRUS;
    return ret;
}

static int cli_scan_structured(int desc, cli_ctx *ctx)
{
	char buf[8192];
	int result = 0;
	unsigned int cc_count = 0;
	unsigned int ssn_count = 0;
	int done = 0;
	int (*ccfunc)(const unsigned char *buffer, int length);
	int (*ssnfunc)(const unsigned char *buffer, int length);
	unsigned int viruses_found = 0;

    if(ctx == NULL)
	return CL_ENULLARG;

    if(ctx->engine->min_cc_count == 1)
	ccfunc = dlp_has_cc;
    else
	ccfunc = dlp_get_cc_count;

    switch((ctx->options & CL_SCAN_STRUCTURED_SSN_NORMAL) | (ctx->options & CL_SCAN_STRUCTURED_SSN_STRIPPED)) {

	case (CL_SCAN_STRUCTURED_SSN_NORMAL | CL_SCAN_STRUCTURED_SSN_STRIPPED):
	    if(ctx->engine->min_ssn_count == 1)
		ssnfunc = dlp_has_ssn;
	    else
		ssnfunc = dlp_get_ssn_count;
	    break;

	case CL_SCAN_STRUCTURED_SSN_NORMAL:
	    if(ctx->engine->min_ssn_count == 1)
		ssnfunc = dlp_has_normal_ssn;
	    else
		ssnfunc = dlp_get_normal_ssn_count;
	    break;

	case CL_SCAN_STRUCTURED_SSN_STRIPPED:
	    if(ctx->engine->min_ssn_count == 1)
		ssnfunc = dlp_has_stripped_ssn;
	    else
		ssnfunc = dlp_get_stripped_ssn_count;
	    break;

	default:
	    ssnfunc = NULL;
    }

    while(!done && ((result = cli_readn(desc, buf, 8191)) > 0)) {
	if((cc_count += ccfunc((const unsigned char *)buf, result)) >= ctx->engine->min_cc_count)
	    done = 1;

	if(ssnfunc && ((ssn_count += ssnfunc((const unsigned char *)buf, result)) >= ctx->engine->min_ssn_count))
	    done = 1;
    }

    if(cc_count != 0 && cc_count >= ctx->engine->min_cc_count) {
	cli_dbgmsg("cli_scan_structured: %u credit card numbers detected\n", cc_count);
	cli_append_virus(ctx,"Heuristics.Structured.CreditCardNumber");
	if (SCAN_ALL)
	    viruses_found++;
	else
	    return CL_VIRUS;
    }

    if(ssn_count != 0 && ssn_count >= ctx->engine->min_ssn_count) {
	cli_dbgmsg("cli_scan_structured: %u social security numbers detected\n", ssn_count);
	cli_append_virus(ctx,"Heuristics.Structured.SSN");
	if (SCAN_ALL)
	    viruses_found++;
	else
	    return CL_VIRUS;
    }

    if (SCAN_ALL && viruses_found)
	return CL_VIRUS;
    return CL_CLEAN;
}

static int cli_scanembpe(cli_ctx *ctx, off_t offset)
{
	int fd, bytes, ret = CL_CLEAN;
	unsigned long int size = 0, todo;
	char *buff;
	char *tmpname;
	fmap_t *map = *ctx->fmap;
	unsigned int corrupted_input;

    tmpname = cli_gentemp(ctx->engine->tmpdir);
    if(!tmpname)
	return CL_EMEM;

    if((fd = open(tmpname, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU)) < 0) {
	cli_errmsg("cli_scanembpe: Can't create file %s\n", tmpname);
	free(tmpname);
	return CL_ECREAT;
    }

    todo = map->len - offset;
    while(1) {
	bytes = MIN(todo, map->pgsz);
	if(!bytes)
	    break;

	if(!(buff = fmap_need_off_once(map, offset + size, bytes))) {
	    close(fd);
	    if(!ctx->engine->keeptmp) {
		if (cli_unlink(tmpname)) {
		    free(tmpname);
		    return CL_EUNLINK;
		}
	    }
	    free(tmpname);
	    return CL_EREAD;
	}
	size += bytes;
	todo -= bytes;

	if(cli_checklimits("cli_scanembpe", ctx, size, 0, 0)!=CL_CLEAN)
	    break;

	if(cli_writen(fd, buff, bytes) != bytes) {
	    cli_dbgmsg("cli_scanembpe: Can't write to temporary file\n");
	    close(fd);
	    if(!ctx->engine->keeptmp) {
		if (cli_unlink(tmpname)) {
		    free(tmpname);
		    return CL_EUNLINK;
		}
	    }
	    free(tmpname);
	    return CL_EWRITE;
	}
    }

    ctx->recursion++;
    lseek(fd, 0, SEEK_SET);
    corrupted_input = ctx->corrupted_input;
    ctx->corrupted_input = 1;
    ret = cli_magic_scandesc(fd, ctx);
    ctx->corrupted_input = corrupted_input;
    if(ret == CL_VIRUS) {
	cli_dbgmsg("cli_scanembpe: Infected with %s\n", cli_get_last_virus(ctx));
	close(fd);
	if(!ctx->engine->keeptmp) {
	    if (cli_unlink(tmpname)) {
	    	free(tmpname);
		return CL_EUNLINK;
	    }
	}
	free(tmpname);	
	return CL_VIRUS;
    }
    ctx->recursion--;

    close(fd);
    if(!ctx->engine->keeptmp) {
	if (cli_unlink(tmpname)) {
	    free(tmpname);
	    return CL_EUNLINK;
	}
    }
    free(tmpname);

    /* intentionally ignore possible errors from cli_magic_scandesc */
    return CL_CLEAN;
}

static int cli_scanraw(cli_ctx *ctx, cli_file_t type, uint8_t typercg, cli_file_t *dettype, unsigned char *refhash)
{
	int ret = CL_CLEAN, nret = CL_CLEAN;
	struct cli_matched_type *ftoffset = NULL, *fpt;
	uint32_t lastzip, lastrar;
	struct cli_exe_info peinfo;
	unsigned int acmode = AC_SCAN_VIR, break_loop = 0;
	fmap_t *map = *ctx->fmap;
	cli_file_t current_container_type = ctx->container_type;
	size_t current_container_size = ctx->container_size;


    if(ctx->engine->maxreclevel && ctx->recursion >= ctx->engine->maxreclevel)
        return CL_EMAXREC;

    if(typercg)
	acmode |= AC_SCAN_FT;

    ret = cli_fmap_scandesc(ctx, type == CL_TYPE_TEXT_ASCII ? 0 : type, 0, &ftoffset, acmode, NULL, refhash);

    if(ret >= CL_TYPENO) {
	ctx->recursion++;
	if(nret != CL_VIRUS) {
	    lastzip = lastrar = 0xdeadbeef;
	    fpt = ftoffset;
	    while(fpt) {
		if(fpt->offset) switch(fpt->type) {
		    case CL_TYPE_RARSFX:
			if(type != CL_TYPE_RAR && have_rar && SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_RAR)) {
			    ctx->container_type = CL_TYPE_RAR;
			    ctx->container_size = map->len - fpt->offset; /* not precise */
			    cli_dbgmsg("RAR/RAR-SFX signature found at %u\n", (unsigned int) fpt->offset);
			    nret = cli_scanrar(map->fd, ctx, fpt->offset, &lastrar);
			}
			break;

		    case CL_TYPE_ZIPSFX:
			if(type != CL_TYPE_ZIP && SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_ZIP)) {
			    ctx->container_type = CL_TYPE_ZIP;
			    ctx->container_size = map->len - fpt->offset; /* not precise */
			    cli_dbgmsg("ZIP/ZIP-SFX signature found at %u\n", (unsigned int) fpt->offset);
			    nret = cli_unzip_single(ctx, fpt->offset);
			}
			break;

		    case CL_TYPE_CABSFX:
			if(type != CL_TYPE_MSCAB && SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_CAB)) {
			    ctx->container_type = CL_TYPE_MSCAB;
			    ctx->container_size = map->len - fpt->offset; /* not precise */
			    cli_dbgmsg("CAB/CAB-SFX signature found at %u\n", (unsigned int) fpt->offset);
			    nret = cli_scanmscab(map->fd, ctx, fpt->offset);
			}
			break;
		    case CL_TYPE_ARJSFX:
			if(type != CL_TYPE_ARJ && SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_ARJ)) {
			    ctx->container_type = CL_TYPE_ARJ;
			    ctx->container_size = map->len - fpt->offset; /* not precise */
			    cli_dbgmsg("ARJ-SFX signature found at %u\n", (unsigned int) fpt->offset);
			    nret = cli_scanarj(map->fd, ctx, fpt->offset, &lastrar);
			}
			break;

		    case CL_TYPE_NULSFT:
		        if(SCAN_ARCHIVE && type == CL_TYPE_MSEXE && (DCONF_ARCH & ARCH_CONF_NSIS) && fpt->offset > 4) {
			    ctx->container_type = CL_TYPE_NULSFT;
			    ctx->container_size = map->len - fpt->offset; /* not precise */
			    cli_dbgmsg("NSIS signature found at %u\n", (unsigned int) fpt->offset-4);
			    nret = cli_scannulsft(map->fd, ctx, fpt->offset - 4);
			}
			break;

		    case CL_TYPE_AUTOIT:
		        if(SCAN_ARCHIVE && type == CL_TYPE_MSEXE && (DCONF_ARCH & ARCH_CONF_AUTOIT)) {
			    ctx->container_type = CL_TYPE_AUTOIT;
			    ctx->container_size = map->len - fpt->offset; /* not precise */
			    cli_dbgmsg("AUTOIT signature found at %u\n", (unsigned int) fpt->offset);
			    nret = cli_scanautoit(ctx, fpt->offset + 23);
			}
			break;

		    case CL_TYPE_ISHIELD_MSI:
		        if(SCAN_ARCHIVE && type == CL_TYPE_MSEXE && (DCONF_ARCH & ARCH_CONF_ISHIELD)) {
			    ctx->container_type = CL_TYPE_AUTOIT;
			    ctx->container_size = map->len - fpt->offset; /* not precise */
			    cli_dbgmsg("ISHIELD-MSI signature found at %u\n", (unsigned int) fpt->offset);
			    nret = cli_scanishield_msi(ctx, fpt->offset + 14);
			}
			break;

		    case CL_TYPE_PDF:
			if(type != CL_TYPE_PDF && SCAN_PDF && (DCONF_DOC & DOC_CONF_PDF)) {
			    ctx->container_type = CL_TYPE_PDF;
			    ctx->container_size = map->len - fpt->offset; /* not precise */
			    cli_dbgmsg("PDF signature found at %u\n", (unsigned int) fpt->offset);
			    nret = cli_scanpdf(ctx, fpt->offset);
			}
			break;

		    case CL_TYPE_MSEXE:
 			if(SCAN_PE && (type == CL_TYPE_MSEXE || type == CL_TYPE_ZIP || type == CL_TYPE_MSOLE2) && ctx->dconf->pe) {
			    if(map->len > 10485760)
				break;
			    ctx->container_type = CL_TYPE_MSEXE; /* PE is a container for another executable here */
			    ctx->container_size = map->len - fpt->offset; /* not precise */
			    memset(&peinfo, 0, sizeof(struct cli_exe_info));
			    peinfo.offset = fpt->offset;
			    if(cli_peheader(map, &peinfo) == 0) {
				cli_dbgmsg("*** Detected embedded PE file at %u ***\n", (unsigned int) fpt->offset);
				if(peinfo.section)
				    free(peinfo.section);
				cli_hashset_destroy(&peinfo.vinfo);

				nret = cli_scanembpe(ctx, fpt->offset);
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
	    ctx->container_type = current_container_type;
	    ctx->container_size = current_container_size;
	}

	if(nret != CL_VIRUS) switch(ret) {
	    case CL_TYPE_HTML:
		if(SCAN_HTML && type == CL_TYPE_TEXT_ASCII && (DCONF_DOC & DOC_CONF_HTML)) {
		    *dettype = CL_TYPE_HTML;
		    nret = cli_scanhtml(ctx);
		}
		break;

	    case CL_TYPE_MAIL:
		ctx->container_type = CL_TYPE_MAIL;
		ctx->container_size = map->len;
		if(SCAN_MAIL && type == CL_TYPE_TEXT_ASCII && (DCONF_MAIL & MAIL_CONF_MBOX)) {
		    *dettype = CL_TYPE_MAIL;
		    nret = cli_scanmail(map->fd, ctx);
		}
		ctx->container_type = current_container_type;
		ctx->container_size = current_container_size;
		break;

	    default:
		break;
	}
	ctx->recursion--;
	ret = nret;
    }

    while(ftoffset) {
	fpt = ftoffset;
	ftoffset = ftoffset->next;
	free(fpt);
    }

    if(ret == CL_VIRUS)
	cli_dbgmsg("%s found\n", cli_get_last_virus(ctx));

    return ret;
}


static void emax_reached(cli_ctx *ctx) {
    fmap_t **ctx_fmap = ctx->fmap;
    if (!ctx_fmap)
	return;
    while(*ctx_fmap) {
	fmap_t *map = *ctx_fmap;
	map->dont_cache_flag = 1;
	ctx_fmap--;
    }
    cli_dbgmsg("emax_reached: marked parents as non cacheable\n");
}

#define LINESTR(x) #x
#define LINESTR2(x) LINESTR(x)
#define __AT__  " at line "LINESTR2(__LINE__)
#define ret_from_magicscan(retcode) do {							\
    cli_dbgmsg("cli_magic_scandesc: returning %d %s\n", retcode, __AT__);			\
    if(ctx->engine->cb_post_scan) {								\
	switch(ctx->engine->cb_post_scan(desc, retcode, retcode == CL_VIRUS ? cli_get_last_virus(ctx) : NULL, ctx->cb_ctx)) { \
	case CL_BREAK:										\
	    cli_dbgmsg("cli_magic_scandesc: file whitelisted by callback\n");			\
	    return CL_CLEAN;									\
	case CL_VIRUS:										\
	    cli_dbgmsg("cli_magic_scandesc: file blacklisted by callback\n");			\
	    cli_append_virus(ctx, "Detected.By.Callback");					\
	    return CL_VIRUS;									\
	case CL_CLEAN:										\
	    break;										\
	default:										\
	    cli_warnmsg("cli_magic_scandesc: ignoring bad return code from callback\n");	\
	}											\
    }\
    return retcode;										\
    } while(0)

static int magic_scandesc(int desc, cli_ctx *ctx, cli_file_t type)
{
	int ret = CL_CLEAN, res;
	cli_file_t dettype = 0;
	struct stat sb;
	uint8_t typercg = 1;
	cli_file_t current_container_type = ctx->container_type;
	size_t current_container_size = ctx->container_size, hashed_size;
	unsigned char hash[16];
	bitset_t *old_hook_lsig_matches;
	unsigned int viruses_found = 0;

#ifdef HAVE__INTERNAL__SHA_COLLECT
    if(ctx->sha_collect>0) ctx->sha_collect = 0;
#endif

    cli_dbgmsg("in cli_magic_scandesc (reclevel: %u/%u)\n", ctx->recursion, ctx->engine->maxreclevel);
    if(ctx->engine->maxreclevel && ctx->recursion > ctx->engine->maxreclevel) {
        cli_dbgmsg("cli_magic_scandesc: Archive recursion limit exceeded (%u, max: %u)\n", ctx->recursion, ctx->engine->maxreclevel);
	emax_reached(ctx);
	ret_from_magicscan(CL_CLEAN);
    }

    if(fstat(desc, &sb) == -1) {
	cli_errmsg("magic_scandesc: Can't fstat descriptor %d\n", desc);
	ret_from_magicscan(CL_ESTAT);
    }

    if(sb.st_size <= 5) {
	cli_dbgmsg("Small data (%u bytes)\n", (unsigned int) sb.st_size);
	ret_from_magicscan(CL_CLEAN);
    }

    if(!ctx->engine) {
	cli_errmsg("CRITICAL: engine == NULL\n");
	ret_from_magicscan(CL_ENULLARG);
    }

    if(!(ctx->engine->dboptions & CL_DB_COMPILED)) {
	cli_errmsg("CRITICAL: engine not compiled\n");
	ret_from_magicscan(CL_EMALFDB);
    }

    if(cli_updatelimits(ctx, sb.st_size)!=CL_CLEAN) {
	emax_reached(ctx);
        ret_from_magicscan(CL_CLEAN);
    }

    ctx->fmap++;
    if(!(*ctx->fmap = fmap(desc, 0, sb.st_size))) {
	cli_errmsg("CRITICAL: fmap() failed\n");
	ctx->fmap--;
	ret_from_magicscan(CL_EMEM);
    }

    if(ctx->engine->cb_pre_scan) {
	switch(ctx->engine->cb_pre_scan(desc, ctx->cb_ctx)) {
	case CL_BREAK:
	    cli_dbgmsg("cli_magic_scandesc: file whitelisted by callback\n");
	    funmap(*ctx->fmap);
	    ctx->fmap--;
	    ret_from_magicscan(CL_CLEAN);
	case CL_VIRUS:
	    cli_dbgmsg("cli_magic_scandesc: file blacklisted by callback\n");
	    cli_append_virus(ctx, "Detected.By.Callback");
	    funmap(*ctx->fmap);
	    ctx->fmap--;
	    ret_from_magicscan(CL_VIRUS);
	case CL_CLEAN:
	    break;
	default:
	    cli_warnmsg("cli_magic_scandesc: ignoring bad return code from callback\n");
	}
    }

    res = cache_check(hash, ctx);
    if(res != CL_VIRUS) {
	funmap(*ctx->fmap);
	ctx->fmap--;
	ret_from_magicscan(res);
    }
    hashed_size = (*ctx->fmap)->len;
    old_hook_lsig_matches = ctx->hook_lsig_matches;
    ctx->hook_lsig_matches = NULL;

    if(!(ctx->options&~CL_SCAN_ALLMATCHES) || (ctx->recursion == ctx->engine->maxreclevel)) { /* raw mode (stdin, etc.) or last level of recursion */
	if(ctx->recursion == ctx->engine->maxreclevel)
	    cli_dbgmsg("cli_magic_scandesc: Hit recursion limit, only scanning raw file\n");
	else
	    cli_dbgmsg("Raw mode: No support for special files\n");

	if((ret = cli_fmap_scandesc(ctx, 0, 0, NULL, AC_SCAN_VIR, NULL, hash)) == CL_VIRUS)
	    cli_dbgmsg("%s found in descriptor %d\n", cli_get_last_virus(ctx), desc);
	else if(ret == CL_CLEAN) {
	    if(ctx->recursion != ctx->engine->maxreclevel)
		cache_add(hash, hashed_size, ctx); /* Only cache if limits are not reached */
	    else 
		emax_reached(ctx);
	}

	ctx->hook_lsig_matches = old_hook_lsig_matches;
	funmap(*ctx->fmap);
	ctx->fmap--;
	ret_from_magicscan(ret);
    }

    if(type == CL_TYPE_ANY)
	type = cli_filetype2(*ctx->fmap, ctx->engine); /* FIXMEFMAP: port to fmap */
    if(type == CL_TYPE_ERROR) {
	cli_dbgmsg("cli_magic_scandesc: cli_filetype2 returned CL_TYPE_ERROR\n");
	funmap(*ctx->fmap);
	ctx->fmap--;
	ctx->hook_lsig_matches = old_hook_lsig_matches;
	ret_from_magicscan(CL_EREAD);
    }

#ifdef HAVE__INTERNAL__SHA_COLLECT
    if(!ctx->sha_collect && type==CL_TYPE_MSEXE) ctx->sha_collect = 1;
#endif
    lseek(desc, 0, SEEK_SET); /* FIXMEFMAP: remove ? */

    ctx->hook_lsig_matches = cli_bitset_init();
    if (!ctx->hook_lsig_matches) {
	ctx->hook_lsig_matches = old_hook_lsig_matches;
	ctx->fmap--;
	ret_from_magicscan(CL_EMEM);
    }

    if(type != CL_TYPE_IGNORED && ctx->engine->sdb) {
	if((ret = cli_scanraw(ctx, type, 0, &dettype, hash)) == CL_VIRUS) {
	    ret = cli_checkfp(hash, hashed_size, ctx);
	    funmap(*ctx->fmap);
	    ctx->fmap--;
	    cli_bitset_free(ctx->hook_lsig_matches);
	    ctx->hook_lsig_matches = old_hook_lsig_matches;
	    ret_from_magicscan(ret);
	}
	lseek(desc, 0, SEEK_SET); /* FIXMEFMAP: remove ? */
    }

    ctx->recursion++;
    switch(type) {
	case CL_TYPE_IGNORED:
	    break;

	case CL_TYPE_RAR:
	    ctx->container_type = CL_TYPE_RAR;
	    ctx->container_size = sb.st_size;
	    if(have_rar && SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_RAR))
		ret = cli_scanrar(desc, ctx, 0, NULL);
	    break;

	case CL_TYPE_ZIP:
	    ctx->container_type = CL_TYPE_ZIP;
	    ctx->container_size = sb.st_size;
	    if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_ZIP))
		ret = cli_unzip(ctx);
	    break;

	case CL_TYPE_GZ:
	    if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_GZ))
		ret = cli_scangzip(ctx);
	    break;

	case CL_TYPE_BZ:
	    if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_BZ))
		ret = cli_scanbzip(desc, ctx);
	    break;

	case CL_TYPE_ARJ:
	    ctx->container_type = CL_TYPE_ARJ;
	    ctx->container_size = sb.st_size;
	    if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_ARJ))
		ret = cli_scanarj(desc, ctx, 0, NULL);
	    break;

        case CL_TYPE_NULSFT:
	    ctx->container_type = CL_TYPE_NULSFT;
	    ctx->container_size = sb.st_size;
	    if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_NSIS))
		ret = cli_scannulsft(desc, ctx, 0);
	    break;

        case CL_TYPE_AUTOIT:
	    ctx->container_type = CL_TYPE_AUTOIT;
	    ctx->container_size = sb.st_size;
	    if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_AUTOIT))
		ret = cli_scanautoit(ctx, 23);
	    break;

	case CL_TYPE_MSSZDD:
	    if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_SZDD))
		ret = cli_scanszdd(desc, ctx);
	    break;

	case CL_TYPE_MSCAB:
	    ctx->container_type = CL_TYPE_MSCAB;
	    ctx->container_size = sb.st_size;
	    if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_CAB))
		ret = cli_scanmscab(desc, ctx, 0);
	    break;

	case CL_TYPE_HTML:
	    if(SCAN_HTML && (DCONF_DOC & DOC_CONF_HTML))
		ret = cli_scanhtml(ctx);
	    break;

	case CL_TYPE_HTML_UTF16:
	    if(SCAN_HTML && (DCONF_DOC & DOC_CONF_HTML))
		ret = cli_scanhtml_utf16(ctx);
	    break;

	case CL_TYPE_SCRIPT:
	    if((DCONF_DOC & DOC_CONF_SCRIPT) && dettype != CL_TYPE_HTML)
	        ret = cli_scanscript(ctx);
	    break;

	case CL_TYPE_RTF:
	    ctx->container_type = CL_TYPE_RTF;
	    ctx->container_size = sb.st_size;
	    if(SCAN_ARCHIVE && (DCONF_DOC & DOC_CONF_RTF))
		ret = cli_scanrtf(desc, ctx);
	    break;

	case CL_TYPE_MAIL:
	    ctx->container_type = CL_TYPE_MAIL;
	    ctx->container_size = sb.st_size;
	    if(SCAN_MAIL && (DCONF_MAIL & MAIL_CONF_MBOX))
		ret = cli_scanmail(desc, ctx);
	    break;

	case CL_TYPE_TNEF:
	    if(SCAN_MAIL && (DCONF_MAIL & MAIL_CONF_TNEF))
		ret = cli_scantnef(desc, ctx);
	    break;

	case CL_TYPE_UUENCODED:
	    if(DCONF_OTHER & OTHER_CONF_UUENC)
		ret = cli_scanuuencoded(ctx);
	    break;

	case CL_TYPE_MSCHM:
	    ctx->container_type = CL_TYPE_MSCHM;
	    ctx->container_size = sb.st_size;
	    if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_CHM))
		ret = cli_scanmschm(desc, ctx);
	    break;

	case CL_TYPE_MSOLE2:
	    ctx->container_type = CL_TYPE_MSOLE2;
	    ctx->container_size = sb.st_size;
	    if(SCAN_OLE2 && (DCONF_ARCH & ARCH_CONF_OLE2))
		ret = cli_scanole2(ctx);
	    break;

	case CL_TYPE_7Z:
	    ctx->container_type = CL_TYPE_7Z;
	    ctx->container_size = sb.st_size;
	    if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_7Z))
		ret = cli_7unz(desc, ctx);
	    break;

	case CL_TYPE_POSIX_TAR:
	    ctx->container_type = CL_TYPE_POSIX_TAR;
	    ctx->container_size = sb.st_size;
	    if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_TAR))
		ret = cli_scantar(desc, ctx, 1);
	    break;

	case CL_TYPE_OLD_TAR:
	    ctx->container_type = CL_TYPE_OLD_TAR;
	    ctx->container_size = sb.st_size;
	    if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_TAR))
		ret = cli_scantar(desc, ctx, 0);
	    break;

	case CL_TYPE_CPIO_OLD:
	    ctx->container_type = CL_TYPE_CPIO_OLD;
	    ctx->container_size = sb.st_size;
	    if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_CPIO))
		ret = cli_scancpio_old(desc, ctx);
	    break;

	case CL_TYPE_CPIO_ODC:
	    ctx->container_type = CL_TYPE_CPIO_ODC;
	    ctx->container_size = sb.st_size;
	    if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_CPIO))
		ret = cli_scancpio_odc(desc, ctx);
	    break;

	case CL_TYPE_CPIO_NEWC:
	    ctx->container_type = CL_TYPE_CPIO_NEWC;
	    ctx->container_size = sb.st_size;
	    if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_CPIO))
		ret = cli_scancpio_newc(desc, ctx, 0);
	    break;

	case CL_TYPE_CPIO_CRC:
	    ctx->container_type = CL_TYPE_CPIO_CRC;
	    ctx->container_size = sb.st_size;
	    if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_CPIO))
		ret = cli_scancpio_newc(desc, ctx, 1);
	    break;

	case CL_TYPE_BINHEX:
	    if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_BINHEX))
		ret = cli_binhex(ctx);
	    break;

	case CL_TYPE_SCRENC:
	    if(DCONF_OTHER & OTHER_CONF_SCRENC)
		ret = cli_scanscrenc(desc, ctx);
	    break;

	case CL_TYPE_RIFF:
	    if(SCAN_ALGO && (DCONF_OTHER & OTHER_CONF_RIFF))
		ret = cli_scanriff(desc, ctx);
	    break;

	case CL_TYPE_GRAPHICS:
	    if(SCAN_ALGO && (DCONF_OTHER & OTHER_CONF_JPEG))
		ret = cli_scanjpeg(desc, ctx);
	    break;

        case CL_TYPE_PDF: /* FIXMELIMITS: pdf should be an archive! */
	    ctx->container_type = CL_TYPE_PDF;
	    ctx->container_size = sb.st_size;
	    if(SCAN_PDF && (DCONF_DOC & DOC_CONF_PDF))
		ret = cli_scanpdf(ctx, 0);
	    break;

	case CL_TYPE_CRYPTFF:
	    if(DCONF_OTHER & OTHER_CONF_CRYPTFF)
		ret = cli_scancryptff(desc, ctx);
	    break;

	case CL_TYPE_ELF:
	    if(SCAN_ELF && ctx->dconf->elf)
		ret = cli_scanelf(ctx);
	    break;

	case CL_TYPE_MACHO:
	    if(ctx->dconf->macho)
		ret = cli_scanmacho(ctx, NULL);
	    break;

	case CL_TYPE_MACHO_UNIBIN:
	    if(ctx->dconf->macho)
		ret = cli_scanmacho_unibin(ctx);
	    break;

	case CL_TYPE_SIS:
	    ctx->container_type = CL_TYPE_SIS;
	    ctx->container_size = sb.st_size;
	    if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_SIS))
		ret = cli_scansis(desc, ctx);
	    break;

	case CL_TYPE_BINARY_DATA:
	    if(SCAN_ALGO && (DCONF_OTHER & OTHER_CONF_MYDOOMLOG))
		ret = cli_check_mydoom_log(desc, ctx);
	    break;

	case CL_TYPE_TEXT_ASCII:
	    if(SCAN_STRUCTURED && (DCONF_OTHER & OTHER_CONF_DLP))
		/* TODO: consider calling this from cli_scanscript() for
		 * a normalised text
		 */
		ret = cli_scan_structured(desc, ctx);
	    break;

	default:
	    break;
    }
    ctx->recursion--;
    ctx->container_type = current_container_type;
    ctx->container_size = current_container_size;

    if(ret == CL_VIRUS) {
	ret = cli_checkfp(hash, hashed_size, ctx);
	funmap(*ctx->fmap);
	ctx->fmap--;
	cli_bitset_free(ctx->hook_lsig_matches);
	ctx->hook_lsig_matches = old_hook_lsig_matches;
	ret_from_magicscan(ret);
    }

    if(type == CL_TYPE_ZIP && SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_ZIP)) {
	if(sb.st_size > 1048576) {
	    cli_dbgmsg("cli_magic_scandesc: Not checking for embedded PEs (zip file > 1 MB)\n");
	    typercg = 0;
	}
    }

    /* CL_TYPE_HTML: raw HTML files are not scanned, unless safety measure activated via DCONF */
    if(type != CL_TYPE_IGNORED && (type != CL_TYPE_HTML || !(DCONF_DOC & DOC_CONF_HTML_SKIPRAW)) && !ctx->engine->sdb) {
	res = cli_scanraw(ctx, type, typercg, &dettype, hash);
	if(res != CL_CLEAN) {
	    switch(res) {
		/* List of scan halts, runtime errors only! */
		case CL_EUNLINK:
		case CL_ESTAT:
		case CL_ESEEK:
		case CL_EWRITE:
		case CL_EDUP:
		case CL_ETMPFILE:
		case CL_ETMPDIR:
		case CL_EMEM:
		case CL_ETIMEOUT:
		    cli_dbgmsg("Descriptor[%d]: cli_scanraw error %s\n", desc, cl_strerror(res));
		    funmap(*ctx->fmap);
		    ctx->fmap--;
		    cli_bitset_free(ctx->hook_lsig_matches);
		    ctx->hook_lsig_matches = old_hook_lsig_matches;
		    ret_from_magicscan(res);
		/* CL_VIRUS = malware found, check FP and report */
		case CL_VIRUS:
		    ret = cli_checkfp(hash, hashed_size, ctx);
		    if (SCAN_ALL)
			break;
		    funmap(*ctx->fmap);
		    ctx->fmap--;
		    cli_bitset_free(ctx->hook_lsig_matches);
		    ctx->hook_lsig_matches = old_hook_lsig_matches;
		    ret_from_magicscan(ret);
		/* "MAX" conditions should still fully scan the current file */
		case CL_EMAXREC:
		case CL_EMAXSIZE:
		case CL_EMAXFILES:
		    ret = res;
		    cli_dbgmsg("Descriptor[%d]: Continuing after cli_scanraw reached %s\n",
			desc, cl_strerror(res));
		    break;
		/* Other errors must not block further scans below
		 * This specifically includes CL_EFORMAT & CL_EREAD & CL_EUNPACK
		 * Malformed/truncated files could report as any of these three.
		 */
		default:
		    ret = res;
		    cli_dbgmsg("Descriptor[%d]: Continuing after cli_scanraw error %s\n",
			desc, cl_strerror(res));
	    }
	}
    }

    ctx->recursion++;
    lseek(desc, 0, SEEK_SET);
    switch(type) {
	/* bytecode hooks triggered by a lsig must be a hook
	 * called from one of the functions here */
	case CL_TYPE_TEXT_ASCII:
	case CL_TYPE_TEXT_UTF16BE:
	case CL_TYPE_TEXT_UTF16LE:
	case CL_TYPE_TEXT_UTF8:
	    if((DCONF_DOC & DOC_CONF_SCRIPT) && dettype != CL_TYPE_HTML && ret != CL_VIRUS)
	        ret = cli_scanscript(ctx);
	    if(SCAN_MAIL && (DCONF_MAIL & MAIL_CONF_MBOX) && ret != CL_VIRUS && (ctx->container_type == CL_TYPE_MAIL || dettype == CL_TYPE_MAIL)) {
		ret = cli_fmap_scandesc(ctx, CL_TYPE_MAIL, 0, NULL, AC_SCAN_VIR, NULL, NULL);
	    }
	    break;
	/* Due to performance reasons all executables were first scanned
	 * in raw mode. Now we will try to unpack them
	 */
	case CL_TYPE_MSEXE:
	    if(SCAN_PE && ctx->dconf->pe) {
		unsigned int corrupted_input = ctx->corrupted_input;
		ret = cli_scanpe(ctx);
		ctx->corrupted_input = corrupted_input;
	    }
	    break;
	default:
	    break;
    }

    if(ret == CL_VIRUS)
	ret = cli_checkfp(hash, hashed_size, ctx);
    ctx->recursion--;
    funmap(*ctx->fmap);
    ctx->fmap--;
    cli_bitset_free(ctx->hook_lsig_matches);
    ctx->hook_lsig_matches = old_hook_lsig_matches;

    switch(ret) {
	/* Malformed file cases */
	case CL_EFORMAT:
	case CL_EREAD:
	case CL_EUNPACK:
	/* Limits exceeded */
	case CL_EMAXREC:
	case CL_EMAXSIZE:
	case CL_EMAXFILES:
	    cli_dbgmsg("Descriptor[%d]: %s\n", desc, cl_strerror(ret));
	    ret_from_magicscan(CL_CLEAN);
	case CL_CLEAN:
	    cache_add(hash, hashed_size, ctx);
	    ret_from_magicscan(CL_CLEAN);
	default:
	    ret_from_magicscan(ret);
    }
}

int cli_magic_scandesc(int desc, cli_ctx *ctx)
{
    return magic_scandesc(desc, ctx, CL_TYPE_ANY);
}

int cli_magic_scandesc_type(int desc, cli_ctx *ctx, cli_file_t type)
{
    return magic_scandesc(desc, ctx, type);
}

int cl_scandesc(int desc, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, unsigned int scanoptions)
{
    return cl_scandesc_callback(desc, virname, scanned, engine, scanoptions, NULL);
}

int cl_scandesc_callback(int desc, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, unsigned int scanoptions, void *context)
{
    cli_ctx ctx;
    int rc;

    memset(&ctx, '\0', sizeof(cli_ctx));
    ctx.engine = engine;
    ctx.virname = virname;
    ctx.scanned = scanned;
    ctx.options = scanoptions;
    ctx.found_possibly_unwanted = 0;
    ctx.container_type = CL_TYPE_ANY;
    ctx.container_size = 0;
    ctx.dconf = (struct cli_dconf *) engine->dconf;
    ctx.cb_ctx = context;
    ctx.fmap = cli_calloc(sizeof(fmap_t *), ctx.engine->maxreclevel + 2);
    if(!ctx.fmap)
	return CL_EMEM;
    if (!(ctx.hook_lsig_matches = cli_bitset_init())) {
	free(ctx.fmap);
	return CL_EMEM;
    }

#ifdef HAVE__INTERNAL__SHA_COLLECT
    if(scanoptions & CL_SCAN_INTERNAL_COLLECT_SHA) {
	char link[32];
	ssize_t linksz;

	snprintf(link, sizeof(link), "/proc/self/fd/%u", desc);
	link[sizeof(link)-1]='\0';
	if((linksz=readlink(link, ctx.entry_filename, sizeof(ctx.entry_filename)))==-1) {
	    cli_errmsg("failed to resolve filename for descriptor %d (%s)\n", desc, link);
	    strcpy(ctx.entry_filename, "NO_IDEA");
	} else
	    ctx.entry_filename[linksz]='\0';
    } while(0);
#endif

    cli_logg_setup(&ctx);
    rc = cli_magic_scandesc(desc, &ctx);

    if (ctx.options & CL_SCAN_ALLMATCHES) {
	*virname = (char *)ctx.virname; /* temp hack for scanall mode until api augmentation */
	if (rc == CL_CLEAN && ctx.num_viruses)
	    rc = CL_VIRUS;
    }

    cli_bitset_free(ctx.hook_lsig_matches);
    free(ctx.fmap);
    if(rc == CL_CLEAN && ctx.found_possibly_unwanted)
	rc = CL_VIRUS;
    cli_logg_unsetup();
    return rc;
}

int cli_found_possibly_unwanted(cli_ctx* ctx)
{
    if(cli_get_last_virus(ctx)) {
	cli_dbgmsg("found Possibly Unwanted: %s\n", cli_get_last_virus(ctx));
	if(ctx->options & CL_SCAN_HEURISTIC_PRECEDENCE) {
	    /* we found a heuristic match, don't scan further,
	     * but consider it a virus. */
	    cli_dbgmsg("cli_found_possibly_unwanted: CL_VIRUS\n");
	    return CL_VIRUS;
	}
	/* heuristic scan isn't taking precedence, keep scanning.
	 * If this is part of an archive, and 
	 * we find a real malware we report that instead of the 
	 * heuristic match */
	ctx->found_possibly_unwanted = 1;
    } else {
	cli_warnmsg("cli_found_possibly_unwanted called, but virname is not set\n");
    }
    emax_reached(ctx);
    return CL_CLEAN;
}

static int cli_scanfile(const char *filename, cli_ctx *ctx)
{
	int fd, ret;

    /* internal version of cl_scanfile with arec/mrec preserved */
    if((fd = safe_open(filename, O_RDONLY|O_BINARY)) == -1)
	return CL_EOPEN;

    ret = cli_magic_scandesc(fd, ctx);

    close(fd);
    return ret;
}

int cl_scanfile(const char *filename, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, unsigned int scanoptions)
{
    return cl_scanfile_callback(filename, virname, scanned, engine, scanoptions, NULL);
}

int cl_scanfile_callback(const char *filename, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, unsigned int scanoptions, void *context)
{
	int fd, ret;

    if((fd = safe_open(filename, O_RDONLY|O_BINARY)) == -1)
	return CL_EOPEN;

    ret = cl_scandesc_callback(fd, virname, scanned, engine, scanoptions, context);
    close(fd);

    return ret;
}

/*
Local Variables:
   c-basic-offset: 4
End:
*/

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
#include "sis.h"
#include "pdf.h"
#include "str.h"
#include "mspack.h"
#include "cab.h"
#include "rtf.h"
#include "unarj.h"
#include "nulsft.h"
#include "autoit.h"
#include "textnorm.h"
#include <zlib.h>
#include "unzip.h"
#include "dlp.h"

#ifdef HAVE_BZLIB_H
#include <bzlib.h>
#endif

#ifdef ENABLE_UNRAR
#include "libclamunrar_iface/unrar_iface.h"
#endif

#if defined(HAVE_READDIR_R_3) || defined(HAVE_READDIR_R_2)
#include <limits.h>
#include <stddef.h>
#endif

static int cli_scanfile(const char *filename, cli_ctx *ctx);

static int cli_scandir(const char *dirname, cli_ctx *ctx, cli_file_t container)
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
	int fd, ret = CL_CLEAN;
	cli_file_t ftype;


    if((dd = opendir(dirname)) != NULL) {
#ifdef HAVE_READDIR_R_3
	while(!readdir_r(dd, &result.d, &dent) && dent) {
#elif defined(HAVE_READDIR_R_2)
	while((dent = (struct dirent *) readdir_r(dd, &result.d))) {
#else
	while((dent = readdir(dd))) {
#endif
#if	(!defined(C_INTERIX)) && (!defined(C_WINDOWS))
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
			    if(cli_scandir(fname, ctx, container) == CL_VIRUS) {
				free(fname);
				closedir(dd);
				return CL_VIRUS;
			    }
			} else {
			    if(S_ISREG(statbuf.st_mode)) {
				if(cli_scanfile(fname, ctx) == CL_VIRUS) {
				    free(fname);
				    closedir(dd);
				    return CL_VIRUS;
				}

				if(container == CL_TYPE_MAIL) {
				    fd = open(fname, O_RDONLY|O_BINARY);
				    if(fd == -1) {
					    cli_warnmsg("Cannot open file %s: %s, mode: %x\n", fname, strerror(errno), statbuf.st_mode);
					    free(fname);
					    continue;
				    }
				    ftype = cli_filetype2(fd, ctx->engine);
				    if(ftype >= CL_TYPE_TEXT_ASCII && ftype <= CL_TYPE_TEXT_UTF16BE) {
					lseek(fd, 0, SEEK_SET);
					ret = cli_scandesc(fd, ctx, CL_TYPE_MAIL, 0, NULL, AC_SCAN_VIR);
				    }
				    close(fd);
				    if(ret == CL_VIRUS) {
					free(fname);
					closedir(dd);
					return CL_VIRUS;
				    }
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
    return CL_CLEAN;
}

#ifdef ENABLE_UNRAR
static int cli_unrar_scanmetadata(int desc, unrar_metadata_t *metadata, cli_ctx *ctx, unsigned int files, uint32_t* sfx_check)
{
	int ret = CL_SUCCESS;
	struct cli_meta_node* mdata;


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

	if(mdata->maxdepth && ctx->recursion > mdata->maxdepth)
	    continue;

	if(mdata->filename && !cli_matchregex(metadata->filename, mdata->filename))
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
	ret = cli_scandesc(desc, ctx, 0, 0, NULL, AC_SCAN_VIR);
	if(ret != CL_VIRUS) {
	    *ctx->virname = "Encrypted.RAR";
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


    cli_dbgmsg("in scanrar()\n");

    if(sfx_offset)
	if(lseek(desc, sfx_offset, SEEK_SET) == -1)
	    return CL_EIO;

    /* generate the temporary directory */
    if(!(dir = cli_gentemp(NULL)))
	return CL_EMEM;

    if(mkdir(dir, 0700)) {
	cli_dbgmsg("RAR: Can't create temporary directory %s\n", dir);
	free(dir);
	return CL_ETMPDIR;
    }

    if((ret = unrar_open(desc, dir, &rar_state)) != UNRAR_OK) {
	if(!cli_leavetemps_flag)
	    cli_rmdirs(dir);
	free(dir);
	if(ret == UNRAR_PASSWD) {
	    cli_dbgmsg("RAR: Encrypted main header\n");
	    if(DETECT_ENCRYPTED) {
		lseek(desc, 0, SEEK_SET);
		ret = cli_scandesc(desc, ctx, 0, 0, NULL, AC_SCAN_VIR);
		if(ret != CL_VIRUS)
		    *ctx->virname = "Encrypted.RAR";
		return CL_VIRUS;
	    }
	    return CL_CLEAN;
	} if(ret == UNRAR_EMEM) {
	    return CL_EMEM;
	} else {
	    return CL_ERAR;
	}
    }

    do {
	int rc;
	rar_state.ofd = -1;
	ret = unrar_extract_next_prepare(&rar_state,dir);
	if(ret != UNRAR_OK) {
	    if(ret == UNRAR_BREAK)
		ret = CL_BREAK;
	    else if(ret == UNRAR_EMEM)
		ret = CL_EMEM;
	    else
		ret = CL_ERAR;
	    break;
	}
	if((ret=cli_checklimits("RAR", ctx, rar_state.metadata_tail->unpack_size, rar_state.metadata_tail->pack_size, 0)!=CL_CLEAN)) {
	    free(rar_state.file_header->filename);
	    free(rar_state.file_header);
	    ret = CL_CLEAN;
	    continue;
	}
	ret = unrar_extract_next(&rar_state,dir);
	if(ret == UNRAR_OK)
	    ret = CL_SUCCESS;
	else if(ret == UNRAR_EMEM)
	    ret = CL_EMEM;
	else
	    ret = CL_ERAR;

	if(rar_state.ofd > 0) {
	    lseek(rar_state.ofd,0,SEEK_SET);
	    rc = cli_magic_scandesc(rar_state.ofd,ctx);
	    close(rar_state.ofd);
	    if(!cli_leavetemps_flag) 
		if (cli_unlink(rar_state.filename)) ret = CL_EIO;
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

    if(cli_scandir(rar_state.comment_dir, ctx, 0) == CL_VIRUS)
	ret = CL_VIRUS;

    unrar_close(&rar_state);

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

static int cli_scanarj(int desc, cli_ctx *ctx, off_t sfx_offset, uint32_t *sfx_check)
{
	int ret = CL_CLEAN, rc;
	arj_metadata_t metadata;
	char *dir;

    cli_dbgmsg("in cli_scanarj()\n");

     /* generate the temporary directory */
    if(!(dir = cli_gentemp(NULL)))
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
	if ((ret = cli_checklimits("ARJ", ctx, metadata.orig_size, metadata.comp_size, 0))!=CL_CLEAN) {
	    ret = CL_SUCCESS;
	    continue;
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
    if (ret == CL_BREAK)
	ret = CL_CLEAN;

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
	if(!cli_leavetemps_flag) {
	    if(cli_unlink(tmpname)) {
	    	free(tmpname);
		return CL_EIO;
	    }
	}
	return CL_EMEM;
    }

    while((bytes = gzread(gd, buff, FILEBUFF)) > 0) {
	size += bytes;

	if(cli_checklimits("GZip", ctx, size + FILEBUFF, 0, 0)!=CL_CLEAN)
	    break;

	if(cli_writen(fd, buff, bytes) != bytes) {
	    cli_dbgmsg("GZip: Can't write to file.\n");
	    close(fd);
	    if(!cli_leavetemps_flag) {
	    	if (cli_unlink(tmpname)) {
		    free(tmpname);
		    gzclose(gd);
		    free(buff);
		    return CL_EIO;
		}
	    }
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
	    if (cli_unlink(tmpname)) ret = CL_EIO;
	free(tmpname);	
	return ret;
    }

    lseek(fd, 0, SEEK_SET);
    if((ret = cli_magic_scandesc(fd, ctx)) == CL_VIRUS ) {
	cli_dbgmsg("GZip: Infected with %s\n", *ctx->virname);
	close(fd);
	if(!cli_leavetemps_flag) {
	    if (cli_unlink(tmpname)) {
	    	free(tmpname);
		return CL_EIO;
	    }
	}
	free(tmpname);	
	return CL_VIRUS;
    }
    close(fd);
    if(!cli_leavetemps_flag)
	if (cli_unlink(tmpname)) ret = CL_EIO;
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
	if(!cli_leavetemps_flag) {
	    if (cli_unlink(tmpname)) {
	    	free(tmpname);
		fclose(fs);
		BZ2_bzReadClose(&bzerror, bfd);
		return CL_EIO;
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
	    if(!cli_leavetemps_flag) {
		if (cli_unlink(tmpname)) {
		    free(tmpname);
		    free(buff);
		    fclose(fs);
		    return CL_EIO;
		}
	    }
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
	    if (cli_unlink(tmpname)) ret = CL_EIO;
	free(tmpname);	
	fclose(fs);
	return ret;
    }

    lseek(fd, 0, SEEK_SET);
    if((ret = cli_magic_scandesc(fd, ctx)) == CL_VIRUS ) {
	cli_dbgmsg("Bzip: Infected with %s\n", *ctx->virname);
    }
    close(fd);
    if(!cli_leavetemps_flag)
	if (cli_unlink(tmpname)) ret = CL_EIO;
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

    if((ret = cli_gentempfd(NULL, &tmpname, &ofd))) {
	cli_dbgmsg("MSEXPAND: Can't generate temporary file/descriptor\n");
	return ret;
    }

    lseek(desc, 0, SEEK_SET);
    ret = cli_msexpand(desc, ofd, ctx);

    if(ret != CL_SUCCESS) { /* CL_VIRUS or some error */
	close(ofd);
	if(!cli_leavetemps_flag)
	    if (cli_unlink(tmpname)) ret = CL_EIO;
	free(tmpname);	
	return ret;
    }

    cli_dbgmsg("MSEXPAND: Decompressed into %s\n", tmpname);
    lseek(ofd, 0, SEEK_SET);
    ret = cli_magic_scandesc(ofd, ctx);
    close(ofd);
    if(!cli_leavetemps_flag)
	if (cli_unlink(tmpname)) ret = CL_EIO;
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


    cli_dbgmsg("in cli_scanmscab()\n");

    if((ret = cab_open(desc, sfx_offset, &cab)))
	return ret;

    for(file = cab.files; file; file = file->next) {
	files++;

	if(cli_checklimits("CAB", ctx, file->length, 0, 0)!=CL_CLEAN)
	    continue;

	if(!(tempname = cli_gentemp(NULL))) {
	    ret = CL_EMEM;
	    break;
	}
	cli_dbgmsg("CAB: Extracting file %s to %s, size %u\n", file->name, tempname, file->length);
	if((ret = cab_extract(file, tempname)))
	    cli_dbgmsg("CAB: Failed to extract file: %s\n", cl_strerror(ret));
	else
	    ret = cli_scanfile(tempname, ctx);

	if(!cli_leavetemps_flag) {
	    if (cli_unlink(tempname)) {
	    	free(tempname);
		ret = CL_EIO;
		break;
	    }
	}
	free(tempname);
	if(ret == CL_VIRUS)
	    break;
    }

    cab_free(&cab);
    return ret;
}

static int cli_vba_scandir(const char *dirname, cli_ctx *ctx, struct uniq *U)
{
    int ret = CL_CLEAN, i, j, fd, data_len;
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


    cli_dbgmsg("VBADir: %s\n", dirname);
    hashcnt = uniq_get(U, "_vba_project", 12, NULL);
    while(hashcnt--) {
	if(!(vba_project = (vba_project_t *)cli_vba_readdir(dirname, U, hashcnt))) continue;

	for(i = 0; i < vba_project->count; i++) {
	    for(j = 0; (unsigned int)j < vba_project->colls[i]; j++) {
		snprintf(vbaname, 1024, "%s/%s_%u", vba_project->dir, vba_project->name[i], j);
		vbaname[sizeof(vbaname)-1] = '\0';
		fd = open(vbaname, O_RDONLY|O_BINARY);
		if(fd == -1) continue;
		cli_dbgmsg("VBADir: Decompress VBA project '%s_%u'\n", vba_project->name[i], j);
		data = (unsigned char *)cli_vba_inflate(fd, vba_project->offset[i], &data_len);
		close(fd);

		if(!data) {
		    cli_dbgmsg("VBADir: WARNING: VBA project '%s_%u' decompressed to NULL\n", vba_project->name[i], j);
		} else {
		    /* cli_dbgmsg("Project content:\n%s", data); */
		    if(ctx->scanned)
			*ctx->scanned += data_len / CL_COUNT_PRECISION;
		    if(cli_scanbuff(data, data_len, ctx, CL_TYPE_MSOLE2) == CL_VIRUS) {
			free(data);
			ret = CL_VIRUS;
			break;
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
	if (ret == CL_VIRUS) break;
    }

    if(ret == CL_CLEAN && (hashcnt = uniq_get(U, "powerpoint document", 19, &hash))) {
	while(hashcnt--) {
	    snprintf(vbaname, 1024, "%s/%s_%u", dirname, hash, hashcnt);
	    vbaname[sizeof(vbaname)-1] = '\0';
	    fd = open(vbaname, O_RDONLY|O_BINARY);
	    if (fd == -1) continue;
	    if ((fullname = cli_ppt_vba_read(fd))) {
		if(cli_scandir(fullname, ctx, 0) == CL_VIRUS) {
		    ret = CL_VIRUS;
		}
		if(!cli_leavetemps_flag)
		    cli_rmdirs(fullname);
		free(fullname);
	    }
	    close(fd);
	}
    }

    if (ret == CL_CLEAN && (hashcnt = uniq_get(U, "worddocument", 12, &hash))) {
	while(hashcnt--) {
	    snprintf(vbaname, sizeof(vbaname), "%s/%s_%u", dirname, hash, hashcnt);
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
			if(cli_scanbuff(data, vba_project->length[i], ctx, CL_TYPE_MSOLE2) == CL_VIRUS) {
				free(data);
				ret = CL_VIRUS;
				break;
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
	    if(ret == CL_VIRUS) break;
	}
    }

    if(ret != CL_CLEAN)
    	return ret;

    /* Check directory for embedded OLE objects */
    hashcnt = uniq_get(U, "_1_ole10native", 14, &hash);
    while(hashcnt--) {
	snprintf(vbaname, sizeof(vbaname), "%s/%s_%u", dirname, hash, hashcnt);
	vbaname[sizeof(vbaname)-1] = '\0';

	fd = open(vbaname, O_RDONLY|O_BINARY);
	if (fd >= 0) {
	    ret = cli_scan_ole10(fd, ctx);
	    close(fd);
	    if(ret != CL_CLEAN)
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
#if	(!defined(C_INTERIX)) && (!defined(C_WINDOWS))
	    if(dent->d_ino)
#endif
	    {
		if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..")) {
		    /* build the full name */
		    fullname = cli_malloc(strlen(dirname) + strlen(dent->d_name) + 2);
		    if(!fullname) {
			ret = CL_EMEM;
			break;
		    }
		    sprintf(fullname, "%s/%s", dirname, dent->d_name);

		    /* stat the file */
		    if(lstat(fullname, &statbuf) != -1) {
			if(S_ISDIR(statbuf.st_mode) && !S_ISLNK(statbuf.st_mode))
			  if (cli_vba_scandir(fullname, ctx, U) == CL_VIRUS) {
			    	ret = CL_VIRUS;
				free(fullname);
				break;
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

    if(!(tempname = cli_gentemp(NULL)))
	return CL_EMEM;

    if(mkdir(tempname, 0700)) {
        cli_errmsg("cli_scanhtml: Can't create temporary directory %s\n", tempname);
	free(tempname);
        return CL_ETMPDIR;
    }

    cli_dbgmsg("cli_scanhtml: using tempdir %s\n", tempname);

    html_normalise_fd(desc, tempname, NULL, ctx->dconf);
    snprintf(fullname, 1024, "%s/nocomment.html", tempname);
    fd = open(fullname, O_RDONLY|O_BINARY);
    if (fd >= 0) {
	    ret = cli_scandesc(fd, ctx, CL_TYPE_HTML, 0, NULL, AC_SCAN_VIR);
	    close(fd);
    }

    if(ret == CL_CLEAN && sb.st_size < 2097152) {
	    /* limit to 2 MB, we're not interesting in scanning large files in notags form */
	    /* TODO: don't even create notags if file is over 2 MB */
	    snprintf(fullname, 1024, "%s/notags.html", tempname);
	    fd = open(fullname, O_RDONLY|O_BINARY);
	    if(fd >= 0) {
		    ret = cli_scandesc(fd, ctx, CL_TYPE_HTML, 0, NULL, AC_SCAN_VIR);
		    close(fd);
	    }
    }

    if(ret == CL_CLEAN) {
	    snprintf(fullname, 1024, "%s/javascript", tempname);
	    fd = open(fullname, O_RDONLY|O_BINARY);
	    if(fd >= 0) {
		    ret = cli_scandesc(fd, ctx, CL_TYPE_SCRIPT, 0, NULL, AC_SCAN_VIR);
		    close(fd);
	    }
    }

    if (ret == CL_CLEAN) {
	snprintf(fullname, 1024, "%s/rfc2397", tempname);
	ret = cli_scandir(fullname, ctx, 0);
    }

    if(!cli_leavetemps_flag)
        cli_rmdirs(tempname);

    free(tempname);
    return ret;
}

static int cli_scanscript(int desc, cli_ctx *ctx)
{
	unsigned char buff[FILEBUFF];
	unsigned char* normalized;
	struct text_norm_state state;
	struct stat sb;
	char *tmpname = NULL;
	int ofd = -1, ret;
	ssize_t nread;

	cli_dbgmsg("in cli_scanscript()\n");

	if(fstat(desc, &sb) == -1) {
		cli_errmsg("cli_scanscript: fstat() failed for descriptor %d\n", desc);
		return CL_EIO;
	}

	/* don't normalize files that are too large */
	if(sb.st_size > 524288) {
		cli_dbgmsg("cli_scanscript: exiting (file larger than 400 kB)\n");
		return CL_CLEAN;
	}

	/* dump to disk only if explicitly asked to,
	 * otherwise we can process just in-memory */
	if(cli_leavetemps_flag) {
		if((ret = cli_gentempfd(NULL, &tmpname, &ofd))) {
			cli_dbgmsg("cli_scanscript: Can't generate temporary file/descriptor\n");
			return ret;
		}
	}

	if(!(normalized = cli_malloc(SCANBUFF))) {
		cli_dbgmsg("cli_scanscript: Unable to malloc %u bytes\n", SCANBUFF);
		return CL_EMEM;
	}

	text_normalize_init(&state, normalized, SCANBUFF);
	ret = CL_CLEAN;

	do {
		nread = cli_readn(desc, buff, sizeof(buff));
		if(nread <= 0 || state.out_pos + nread > state.out_len) {
			/* flush if error/EOF, or too little buffer space left */
			if((ofd != -1) && (write(ofd, state.out, state.out_pos) == -1)) {
				cli_errmsg("cli_scanscript: can't write to file %s\n",tmpname);
				close(ofd);
				ofd = -1;
				/* we can continue to scan in memory */
			}
			/* when we flush the buffer also scan */
			if(cli_scanbuff(state.out, state.out_pos, ctx, CL_TYPE_TEXT_ASCII) == CL_VIRUS) {
				ret = CL_VIRUS;
				break;
			}
			text_normalize_reset(&state);
		}
		if(nread > 0 && (text_normalize_buffer(&state, buff, nread) != nread)) {
			cli_dbgmsg("cli_scanscript: short read during normalizing\n");
		}
		/* used a do {}while() here, since we need to flush our buffers at the end,
		 * and using while(){} loop would mean code duplication */
	} while (nread > 0);

	if(cli_leavetemps_flag) {
		free(tmpname);
		close(ofd);
	}
	free(normalized);

	return ret;
}

static int cli_scanhtml_utf16(int desc, cli_ctx *ctx)
{
	char *tempname, buff[512], *decoded;
	int ret = CL_CLEAN, fd, bytes;


    cli_dbgmsg("in cli_scanhtml_utf16()\n");

    if(!(tempname = cli_gentemp(NULL)))
	return CL_EMEM;

    if((fd = open(tempname, O_RDWR|O_CREAT|O_TRUNC|O_BINARY, S_IRWXU)) < 0) {
	cli_errmsg("cli_scanhtml_utf16: Can't create file %s\n", tempname);
	free(tempname);
	return CL_EIO;
    }

    cli_dbgmsg("cli_scanhtml_utf16: using tempfile %s\n", tempname);

    while((bytes = read(desc, buff, sizeof(buff))) > 0) {
	decoded = cli_utf16toascii(buff, bytes);
	if(decoded) {
	    if(write(fd, decoded, strlen(decoded)) == -1) {
		cli_errmsg("cli_scanhtml_utf16: Can't write to file %s\n", tempname);
		free(decoded);
		cli_unlink(tempname);
		free(tempname);
		close(fd);
		return CL_EIO;
	    }
	    free(decoded);
	}
    }

    lseek(fd, 0, SEEK_SET);
    ret = cli_scanhtml(fd, ctx);
    close(fd);

    if(!cli_leavetemps_flag) {
	if (cli_unlink(tempname)) ret = CL_EIO;
    } else
	cli_dbgmsg("cli_scanhtml_utf16: Decoded HTML data saved in %s\n", tempname);
    free(tempname);

    return ret;
}

static int cli_scanole2(int desc, cli_ctx *ctx)
{
	char *dir;
	int ret = CL_CLEAN;
	struct uniq *vba = NULL;

    cli_dbgmsg("in cli_scanole2()\n");

    if(ctx->limits && ctx->limits->maxreclevel && ctx->recursion >= ctx->limits->maxreclevel)
        return CL_EMAXREC;

    /* generate the temporary directory */
    if(!(dir = cli_gentemp(NULL)))
	return CL_EMEM;

    if(mkdir(dir, 0700)) {
	cli_dbgmsg("OLE2: Can't create temporary directory %s\n", dir);
	free(dir);
	return CL_ETMPDIR;
    }

    ret = cli_ole2_extract(desc, dir, ctx, &vba);
    if(ret!=CL_CLEAN && ret!=CL_VIRUS) {
	cli_dbgmsg("OLE2: %s\n", cl_strerror(ret));
	if(!cli_leavetemps_flag)
	    cli_rmdirs(dir);
	free(dir);
	return ret;
    }

    if (vba) {
        ctx->recursion++;

	ret = cli_vba_scandir(dir, ctx, vba);
	uniq_free(vba);
	if(ret != CL_VIRUS)
	    if(cli_scandir(dir, ctx, 0) == CL_VIRUS)
	        ret = CL_VIRUS;
	ctx->recursion--;
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
    if(!(dir = cli_gentemp(NULL)))
	return CL_EMEM;

    if(mkdir(dir, 0700)) {
	cli_errmsg("Tar: Can't create temporary directory %s\n", dir);
	free(dir);
	return CL_ETMPDIR;
    }

    ret = cli_untar(dir, desc, posix, ctx);

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
    if(!(dir = cli_gentemp(NULL)))
	return CL_EMEM;

    if(mkdir(dir, 0700)) {
	cli_errmsg("Binhex: Can't create temporary directory %s\n", dir);
	free(dir);
	return CL_ETMPDIR;
    }

    if((ret = cli_binhex(dir, desc)))
	cli_dbgmsg("Binhex: %s\n", cl_strerror(ret));
    else
	ret = cli_scandir(dir, ctx, 0);

    if(!cli_leavetemps_flag)
	cli_rmdirs(dir);

    free(dir);
    return ret;
}

static int cli_scanmschm(int desc, cli_ctx *ctx)
{
	int ret = CL_CLEAN, rc;
	chm_metadata_t metadata;
	char *dir;

    cli_dbgmsg("in cli_scanmschm()\n");

     /* generate the temporary directory */
    if(!(dir = cli_gentemp(NULL)))
	return CL_EMEM;

    if(mkdir(dir, 0700)) {
	cli_dbgmsg("CHM: Can't create temporary directory %s\n", dir);
	free(dir);
	return CL_ETMPDIR;
    }

    ret = cli_chm_open(desc, dir, &metadata);
    if (ret != CL_SUCCESS) {
	if(!cli_leavetemps_flag)
	    cli_rmdirs(dir);
	free(dir);
	cli_dbgmsg("CHM: Error: %s\n", cl_strerror(ret));
	return ret;
    }

   do {
	ret = cli_chm_prepare_file(desc, dir, &metadata);
	if (ret != CL_SUCCESS) {
	   break;
	}
	ret = cli_chm_extract_file(desc, dir, &metadata);
	if (ret == CL_SUCCESS) {
	    lseek(metadata.ofd, 0, SEEK_SET);
	    rc = cli_magic_scandesc(metadata.ofd, ctx);
	    close(metadata.ofd);
	    if (rc == CL_VIRUS) {
		cli_dbgmsg("CHM: infected with %s\n",*ctx->virname);
		ret = CL_VIRUS;
		break;
	    }
	}

    } while(ret == CL_SUCCESS);

    cli_chm_close(&metadata);
   
    if(!cli_leavetemps_flag)
	cli_rmdirs(dir);

    free(dir);

    cli_dbgmsg("CHM: Exit code: %d\n", ret);
    if (ret == CL_BREAK)
	ret = CL_CLEAN;

    return ret;
}

static int cli_scanscrenc(int desc, cli_ctx *ctx)
{
	char *tempname;
	int ret = CL_CLEAN;

    cli_dbgmsg("in cli_scanscrenc()\n");

    if(!(tempname = cli_gentemp(NULL)))
	return CL_EMEM;

    if(mkdir(tempname, 0700)) {
	cli_dbgmsg("CHM: Can't create temporary directory %s\n", tempname);
	free(tempname);
	return CL_ETMPDIR;
    }

    if (html_screnc_decode(desc, tempname))
	ret = cli_scandir(tempname, ctx, 0);

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

    if(!(tempfile = cli_gentemp(NULL))) {
	free(dest);
	return CL_EMEM;
    }

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

    lseek(ndesc, 0, SEEK_SET);

    cli_dbgmsg("CryptFF: Scanning decrypted data\n");

    if((ret = cli_magic_scandesc(ndesc, ctx)) == CL_VIRUS)
	cli_dbgmsg("CryptFF: Infected with %s\n", *ctx->virname);

    close(ndesc);

    if(cli_leavetemps_flag)
	cli_dbgmsg("CryptFF: Decompressed data saved in %s\n", tempfile);
    else
	if (cli_unlink(tempfile)) ret = CL_EIO;

    free(tempfile);
    return ret;
}

static int cli_scanpdf(int desc, cli_ctx *ctx, off_t offset)
{
	int ret;
	char *dir = cli_gentemp(NULL);

    if(!dir)
	return CL_EMEM;

    if(mkdir(dir, 0700)) {
	cli_dbgmsg("Can't create temporary directory for PDF file %s\n", dir);
	free(dir);
	return CL_ETMPDIR;
    }

    ret = cli_pdf(dir, desc, ctx, offset);

    if(!cli_leavetemps_flag)
	cli_rmdirs(dir);

    free(dir);
    return ret;
}

static int cli_scantnef(int desc, cli_ctx *ctx)
{
	int ret;
	char *dir = cli_gentemp(NULL);

    if(!dir)
	return CL_EMEM;

    if(mkdir(dir, 0700)) {
	cli_dbgmsg("Can't create temporary directory for tnef file %s\n", dir);
	free(dir);
	return CL_ETMPDIR;
    }

    ret = cli_tnef(dir, desc);

    if(ret == CL_CLEAN)
	ret = cli_scandir(dir, ctx, 0);

    if(!cli_leavetemps_flag)
	cli_rmdirs(dir);

    free(dir);
    return ret;
}

static int cli_scanuuencoded(int desc, cli_ctx *ctx)
{
	int ret;
	char *dir = cli_gentemp(NULL);

    if(!dir)
	return CL_EMEM;

    if(mkdir(dir, 0700)) {
	cli_dbgmsg("Can't create temporary directory for uuencoded file %s\n", dir);
	free(dir);
	return CL_ETMPDIR;
    }

    ret = cli_uuencode(dir, desc);

    if(ret == CL_CLEAN)
	ret = cli_scandir(dir, ctx, 0);

    if(!cli_leavetemps_flag)
	cli_rmdirs(dir);

    free(dir);
    return ret;
}

static int cli_scanmail(int desc, cli_ctx *ctx)
{
	char *dir;
	int ret;


    cli_dbgmsg("Starting cli_scanmail(), recursion = %u\n", ctx->recursion);

    /* generate the temporary directory */
    if(!(dir = cli_gentemp(NULL)))
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
	if(!cli_leavetemps_flag)
	    cli_rmdirs(dir);
	free(dir);
	return ret;
    }

    ret = cli_scandir(dir, ctx, CL_TYPE_MAIL);

    if(!cli_leavetemps_flag)
	cli_rmdirs(dir);

    free(dir);
    return ret;
}

static int cli_scan_structured(int desc, cli_ctx *ctx)
{
	char buf[8192];
	int result = 0;
	unsigned int cc_count = 0;
	unsigned int ssn_count = 0;
	int done = 0;
	const struct cl_limits *lim = NULL;
	int (*ccfunc)(const unsigned char *buffer, int length);
	int (*ssnfunc)(const unsigned char *buffer, int length);


    if(ctx == NULL || ctx->limits == NULL)
	return CL_ENULLARG;

    lim = ctx->limits;

    if(lim->min_cc_count == 1)
	ccfunc = dlp_has_cc;
    else
	ccfunc = dlp_get_cc_count;

    switch((ctx->options & CL_SCAN_STRUCTURED_SSN_NORMAL) | (ctx->options & CL_SCAN_STRUCTURED_SSN_STRIPPED)) {

	case (CL_SCAN_STRUCTURED_SSN_NORMAL | CL_SCAN_STRUCTURED_SSN_STRIPPED):
	    if(lim->min_ssn_count == 1)
		ssnfunc = dlp_has_ssn;
	    else
		ssnfunc = dlp_get_ssn_count;
	    break;

	case CL_SCAN_STRUCTURED_SSN_NORMAL:
	    if(lim->min_ssn_count == 1)
		ssnfunc = dlp_has_normal_ssn;
	    else
		ssnfunc = dlp_get_normal_ssn_count;
	    break;

	case CL_SCAN_STRUCTURED_SSN_STRIPPED:
	    if(lim->min_ssn_count == 1)
		ssnfunc = dlp_has_stripped_ssn;
	    else
		ssnfunc = dlp_get_stripped_ssn_count;
	    break;

	default:
	    ssnfunc = NULL;
    }

    while(!done && ((result = cli_readn(desc, buf, 8191)) > 0)) {
	if((cc_count += ccfunc((const unsigned char *)buf, result)) >= lim->min_cc_count)
	    done = 1;

	if(ssnfunc && ((ssn_count += ssnfunc((const unsigned char *)buf, result)) >= lim->min_ssn_count))
	    done = 1;
    }

    if(cc_count != 0 && cc_count >= lim->min_cc_count) {
	cli_dbgmsg("cli_scan_structured: %u credit card numbers detected\n", cc_count);
	*ctx->virname = "Structured.CreditCardNumber";
	return CL_VIRUS;
    }

    if(ssn_count != 0 && ssn_count >= lim->min_ssn_count) {
	cli_dbgmsg("cli_scan_structured: %u social security numbers detected\n", ssn_count);
	*ctx->virname = "Structured.SSN";
	return CL_VIRUS;
    }

    return CL_CLEAN;
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

	if(cli_checklimits("cli_scanembpe", ctx, size + sizeof(buff), 0, 0)!=CL_CLEAN)
	    break;

	if(cli_writen(fd, buff, bytes) != bytes) {
	    cli_dbgmsg("cli_scanembpe: Can't write to temporary file\n");
	    close(fd);
	    if(!cli_leavetemps_flag) {
		if (cli_unlink(tmpname)) {
		    free(tmpname);
		    return CL_EIO;
		}
	    }
	    free(tmpname);	
	    return CL_EIO;
	}
    }

    ctx->recursion++;
    lseek(fd, 0, SEEK_SET);
    if((ret = cli_magic_scandesc(fd, ctx)) == CL_VIRUS) {
	cli_dbgmsg("cli_scanembpe: Infected with %s\n", *ctx->virname);
	close(fd);
	if(!cli_leavetemps_flag) {
	    if (cli_unlink(tmpname)) {
	    	free(tmpname);
		return CL_EIO;
	    }
	}
	free(tmpname);	
	return CL_VIRUS;
    }
    ctx->recursion--;

    close(fd);
    if(!cli_leavetemps_flag) {
	if (cli_unlink(tmpname)) {
	    free(tmpname);
	    return CL_EIO;
	}
    }
    free(tmpname);

    /* intentionally ignore possible errors from cli_magic_scandesc */
    return CL_CLEAN;
}

static int cli_scanraw(int desc, cli_ctx *ctx, cli_file_t type, uint8_t typercg, cli_file_t *dettype)
{
	int ret = CL_CLEAN, nret = CL_CLEAN;
	struct cli_matched_type *ftoffset = NULL, *fpt;
	uint32_t lastzip, lastrar;
	struct cli_exe_info peinfo;
	unsigned int acmode = AC_SCAN_VIR, break_loop = 0;


    if(typercg) switch(type) {
	case CL_TYPE_TEXT_ASCII:
	case CL_TYPE_MSEXE:
	case CL_TYPE_ZIP:
	case CL_TYPE_MSOLE2:
	    acmode |= AC_SCAN_FT;
	default:
	    break;
    }

    if(lseek(desc, 0, SEEK_SET) < 0) {
	cli_errmsg("cli_scanraw: lseek() failed\n");
	return CL_EIO;
    }

    ret = cli_scandesc(desc, ctx, type == CL_TYPE_TEXT_ASCII ? 0 : type, 0, &ftoffset, acmode);

    if(ret >= CL_TYPENO) {

/*
	if(type == CL_TYPE_TEXT_ASCII) {
	    lseek(desc, 0, SEEK_SET);

	    nret = cli_scandesc(desc, ctx, 0, ret, 1, NULL);
	    if(nret == CL_VIRUS)
		cli_dbgmsg("%s found in descriptor %d when scanning file type %u\n", *ctx->virname, desc, ret);
	}
*/

	if(nret != CL_VIRUS && (type == CL_TYPE_MSEXE || type == CL_TYPE_ZIP || type == CL_TYPE_MSOLE2)) {
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
			    nret = cli_unzip_single(desc, ctx, fpt->offset);
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

		    case CL_TYPE_AUTOIT:
		        if(SCAN_ARCHIVE && type == CL_TYPE_MSEXE && (DCONF_ARCH & ARCH_CONF_AUTOIT)) {
			    cli_dbgmsg("AUTOIT signature found at %u\n", (unsigned int) fpt->offset);
			    nret = cli_scanautoit(desc, ctx, fpt->offset + 23);
			}
			break;

		    case CL_TYPE_PDF:
			if(SCAN_PDF && (DCONF_DOC & DOC_CONF_PDF)) {
			    cli_dbgmsg("PDF signature found at %u\n", (unsigned int) fpt->offset);
			    nret = cli_scanpdf(desc, ctx, fpt->offset);
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

	ctx->recursion++;

	if(nret != CL_VIRUS) switch(ret) {
	    case CL_TYPE_HTML:
		if(SCAN_HTML && type == CL_TYPE_TEXT_ASCII && (DCONF_DOC & DOC_CONF_HTML)) {
		    *dettype = CL_TYPE_HTML;
		    nret = cli_scanhtml(desc, ctx);
		}
		break;

	    case CL_TYPE_MAIL:
		if(SCAN_MAIL && type == CL_TYPE_TEXT_ASCII && (DCONF_MAIL & MAIL_CONF_MBOX))
		    nret = cli_scanmail(desc, ctx);
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
	cli_dbgmsg("%s found in descriptor %d\n", *ctx->virname, desc);

    return ret;
}

int cli_magic_scandesc(int desc, cli_ctx *ctx)
{
	int ret = CL_CLEAN;
	cli_file_t type, dettype = 0;
	struct stat sb;
	uint8_t typercg = 1;


    if(fstat(desc, &sb) == -1) {
	cli_errmsg("magic_scandesc: Can't fstat descriptor %d\n", desc);
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
	if((ret = cli_scandesc(desc, ctx, 0, 0, NULL, AC_SCAN_VIR)) == CL_VIRUS)
	    cli_dbgmsg("%s found in descriptor %d\n", *ctx->virname, desc);
	return ret;
    }

    if(cli_updatelimits(ctx, sb.st_size)!=CL_CLEAN)
        return CL_CLEAN;

    if((SCAN_MAIL || SCAN_ARCHIVE) && ctx->limits && ctx->limits->maxreclevel && ctx->recursion > ctx->limits->maxreclevel) {
        cli_dbgmsg("Archive recursion limit exceeded (level = %u).\n", ctx->recursion);
	return CL_CLEAN;
    }

    lseek(desc, 0, SEEK_SET);
    type = cli_filetype2(desc, ctx->engine);
    if(type == CL_TYPE_ERROR) {
	cli_dbgmsg("cli_magic_scandesc: cli_filetype2 returned CL_TYPE_ERROR\n");
	return CL_EIO;
    }
    lseek(desc, 0, SEEK_SET);

    if(type != CL_TYPE_IGNORED && ctx->engine->sdb) {
	if((ret = cli_scanraw(desc, ctx, type, 0, &dettype)) == CL_VIRUS)
	    return CL_VIRUS;
	lseek(desc, 0, SEEK_SET);
    }

    ctx->recursion++;

    switch(type) {
	case CL_TYPE_IGNORED:
	    break;

	case CL_TYPE_RAR:
#ifdef ENABLE_UNRAR
	    if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_RAR))
		ret = cli_scanrar(desc, ctx, 0, NULL);
#else
	    cli_warnmsg("RAR code not compiled-in\n");
#endif
	    break;

	case CL_TYPE_ZIP:
	    if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_ZIP))
		ret = cli_unzip(desc, ctx);
	    break;

	case CL_TYPE_GZ:
	    if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_GZ))
		ret = cli_scangzip(desc, ctx);
	    break;

	case CL_TYPE_BZ:
	    if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_BZ))
		ret = cli_scanbzip(desc, ctx);
	    break;
	case CL_TYPE_ARJ:
	    if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_ARJ))
		ret = cli_scanarj(desc, ctx, 0, NULL);
	    break;

        case CL_TYPE_NULSFT:
	  if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_NSIS))
		ret = cli_scannulsft(desc, ctx, 0);
	    break;

        case CL_TYPE_AUTOIT:
	    if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_AUTOIT))
		ret = cli_scanautoit(desc, ctx, 23);
	    break;

	case CL_TYPE_MSSZDD:
	    if(SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_SZDD))
		ret = cli_scanszdd(desc, ctx);
	    break;

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

	case CL_TYPE_SCRIPT:
	    if((DCONF_DOC & DOC_CONF_SCRIPT) && dettype != CL_TYPE_HTML)
	        ret = cli_scanscript(desc, ctx);
	    break;

	case CL_TYPE_RTF:
	    if(SCAN_ARCHIVE && (DCONF_DOC & DOC_CONF_RTF))
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

        case CL_TYPE_PDF: /* FIXMELIMITS: pdf should be an archive! */
	    if(SCAN_PDF && (DCONF_DOC & DOC_CONF_PDF))
		ret = cli_scanpdf(desc, ctx, 0);
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

	case CL_TYPE_BINARY_DATA:
	    ret = cli_check_mydoom_log(desc, ctx->virname);
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

    if(ret == CL_VIRUS)
	return CL_VIRUS;

    if(type == CL_TYPE_ZIP && SCAN_ARCHIVE && (DCONF_ARCH & ARCH_CONF_ZIP)) {
	if(sb.st_size > 1048576) {
	    cli_dbgmsg("cli_magic_scandesc: Not checking for embedded PEs (zip file > 1 MB)\n");
	    typercg = 0;
	}
    }

    /* CL_TYPE_HTML: raw HTML files are not scanned, unless safety measure activated via DCONF */
    if(type != CL_TYPE_IGNORED && (type != CL_TYPE_HTML || !(DCONF_DOC & DOC_CONF_HTML_SKIPRAW)) && !ctx->engine->sdb) {
	if(cli_scanraw(desc, ctx, type, typercg, &dettype) == CL_VIRUS)
	    return CL_VIRUS;
    }

    ctx->recursion++;
    lseek(desc, 0, SEEK_SET);
    switch(type) {
	case CL_TYPE_TEXT_ASCII:
	case CL_TYPE_TEXT_UTF16BE:
	case CL_TYPE_TEXT_UTF16LE:
	case CL_TYPE_TEXT_UTF8:
	    if((DCONF_DOC & DOC_CONF_SCRIPT) && dettype != CL_TYPE_HTML)
	        ret = cli_scanscript(desc, ctx);
	    break;
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
    ctx->recursion--;

    switch(ret) {
	case CL_EFORMAT:
	case CL_EMAXREC:
	case CL_EMAXSIZE:
	case CL_EMAXFILES:
	    cli_dbgmsg("Descriptor[%d]: %s\n", desc, cl_strerror(ret));
	    return CL_CLEAN;
	default:
	    return ret;
    }
}

int cl_scandesc(int desc, const char **virname, unsigned long int *scanned, const struct cl_engine *engine, const struct cl_limits *limits, unsigned int options)
{
    cli_ctx ctx;
    struct cl_limits l_limits;
    int rc;

    if(!limits) {
	cli_errmsg("cl_scandesc: limits == NULL\n");
	return CL_ENULLARG;
    }
    memset(&ctx, '\0', sizeof(cli_ctx));
    ctx.engine = engine;
    ctx.virname = virname;
    ctx.scanned = scanned;
    ctx.options = options;
    ctx.found_possibly_unwanted = 0;
    ctx.dconf = (struct cli_dconf *) engine->dconf;
    ctx.limits = &l_limits;
    memcpy(&l_limits, limits, sizeof(struct cl_limits));

    rc = cli_magic_scandesc(desc, &ctx);
    if(rc == CL_CLEAN && ctx.found_possibly_unwanted)
    	rc = CL_VIRUS;
    return rc;
}

int cli_found_possibly_unwanted(cli_ctx* ctx)
{
	if(ctx->virname) {
		cli_dbgmsg("found Possibly Unwanted: %s\n",*ctx->virname);
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
	return CL_CLEAN;
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

/*
Local Variables:
   c-basic-offset: 4
End:
*/

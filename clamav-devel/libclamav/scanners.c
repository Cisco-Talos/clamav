/*
 *  Copyright (C) 2002 - 2004 Tomasz Kojm <tkojm@clamav.net>
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
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

#ifdef CL_THREAD_SAFE
#  include <pthread.h>
pthread_mutex_t cli_scanrar_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif
int cli_scanrar_inuse = 0;

extern short cli_leavetemps_flag;

extern int cli_mbox(const char *dir, int desc, unsigned int options); /* FIXME */

#include "clamav.h"
#include "others.h"
#include "scanners.h"
#include "matcher-ac.h"
#include "matcher-bm.h"
#include "matcher.h"
#include "unrarlib.h"
#include "ole2_extract.h"
#include "vba_extract.h"
#include "msexpand.h"
#include "chmunpack.h"
#include "pe.h"
#include "filetypes.h"
#include "htmlnorm.h"
#include "untar.h"
#include "special.h"

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
#   endif
# endif
#endif

#define SCAN_ARCHIVE	    (options & CL_SCAN_ARCHIVE)
#define SCAN_MAIL	    (options & CL_SCAN_MAIL)
#define SCAN_OLE2	    (options & CL_SCAN_OLE2)
#define SCAN_HTML	    (options & CL_SCAN_HTML)
#define SCAN_PE		    (options & CL_SCAN_PE)
#define DISABLE_RAR	    (options & CL_SCAN_DISABLERAR)
#define DETECT_ENCRYPTED    (options & CL_SCAN_BLOCKENCRYPTED)
#define BLOCKMAX	    (options & CL_SCAN_BLOCKMAX)

#define MAX_MAIL_RECURSION  15

static int cli_scanfile(const char *filename, const char **virname, unsigned long int *scanned, const struct cl_node *root, const struct cl_limits *limits, unsigned int options, int *arec, int *mrec);


#ifdef CL_THREAD_SAFE
static void cli_unlock_mutex(void *mtx)
{
    cli_dbgmsg("Pthread cancelled. Unlocking mutex.\n");
    pthread_mutex_unlock(mtx);
}
#endif

static int cli_scanrar(int desc, const char **virname, long int *scanned, const struct cl_node *root, const struct cl_limits *limits, unsigned int options, int *arec, int *mrec)
{
	FILE *tmp = NULL;
	int files = 0, fd, ret = CL_CLEAN, afiles;
	ArchiveList_struct *rarlist = NULL;
	ArchiveList_struct *rarlist_head = NULL;
	char *rar_data_ptr;
	unsigned long rar_data_size;


    cli_dbgmsg("in scanrar()\n");


#ifdef CL_THREAD_SAFE
    pthread_cleanup_push(cli_unlock_mutex, &cli_scanrar_mutex);
    pthread_mutex_lock(&cli_scanrar_mutex);
    cli_scanrar_inuse = 1;
#endif

    if(! (afiles = urarlib_list(desc, (ArchiveList_struct *) &rarlist))) {
#ifdef CL_THREAD_SAFE
	pthread_mutex_unlock(&cli_scanrar_mutex);
	cli_scanrar_inuse = 0;
#endif
	return CL_ERAR;
    }

    cli_dbgmsg("RAR: Number of archived files: %d\n", afiles);

    rarlist_head = rarlist;

    while(rarlist) {
	if(DETECT_ENCRYPTED && (rarlist->item.Flags & 4)) {
	    files++;
	    cli_dbgmsg("RAR: Encrypted files found in archive.\n");
	    lseek(desc, 0, SEEK_SET);
	    ret = cli_scandesc(desc, virname, scanned, root, 0, 0);
	    if(ret < 0) {
		break;
	    } else if(ret != CL_VIRUS) {
		*virname = "Encrypted.RAR";
		ret = CL_VIRUS;
	    }
	    break;
	}

	if(limits) {

	    if(limits->maxratio && rarlist->item.UnpSize && rarlist->item.PackSize) {
		if((unsigned int) rarlist->item.UnpSize / (unsigned int) rarlist->item.PackSize >= limits->maxratio) {
		    cli_dbgmsg("RAR: Max ratio reached (normal: %d, compressed: %d, max: %ld)\n", (int) rarlist->item.UnpSize, (int) rarlist->item.PackSize, limits->maxratio);
		    *virname = "Oversized.RAR";
		    ret = CL_VIRUS;
		    break;
		}
	    }

	    if(limits->maxfilesize && (rarlist->item.UnpSize > (unsigned int) limits->maxfilesize)) {
		cli_dbgmsg("RAR: %s: Size exceeded (%u, max: %lu)\n", rarlist->item.Name, (unsigned int) rarlist->item.UnpSize, limits->maxfilesize);
		rarlist = rarlist->next;
		files++;
		if(BLOCKMAX) {
		    *virname = "RAR.ExceededFileSize";
		    ret = CL_VIRUS;
		    break;
		}
		continue;
	    }

	    if(limits->maxfiles && (files > limits->maxfiles)) {
		cli_dbgmsg("RAR: Files limit reached (max: %d)\n", limits->maxfiles);
		if(BLOCKMAX) {
		    *virname = "RAR.ExceededFilesLimit";
		    ret = CL_VIRUS;
		    break;
		}
		break;
	    }
	}

        if(rarlist->item.FileAttr & RAR_FENTRY_ATTR_DIRECTORY) {
            rarlist = rarlist->next;
            files++;
            continue;
        }

	if((tmp = tmpfile()) == NULL) {
	    cli_dbgmsg("RAR: Can't generate temporary file.\n");
#ifdef CL_THREAD_SAFE
	    pthread_mutex_unlock(&cli_scanrar_mutex);
	    cli_scanrar_inuse = 0;
#endif
	    return CL_ETMPFILE;
	}
	fd = fileno(tmp);

	if( urarlib_get(&rar_data_ptr, &rar_data_size, rarlist->item.Name, desc, "clam")) {
	    cli_dbgmsg("RAR: Extracted: %s, size: %lu\n", rarlist->item.Name, rar_data_size);
	    if(fwrite(rar_data_ptr, 1, rar_data_size, tmp) != rar_data_size) {
		cli_dbgmsg("RAR: Can't write to file.\n");
		fclose(tmp);
		tmp = NULL;
		ret = CL_ERAR;
		if(rar_data_ptr) {
		    free(rar_data_ptr);
		    rar_data_ptr = NULL;
		}
		break;
	    }

	    if(rar_data_ptr) {
		free(rar_data_ptr);
		rar_data_ptr = NULL;
	    }
	    if(fflush(tmp) != 0) {
		cli_dbgmsg("RAR: fflush() failed: %s\n", strerror(errno));
		fclose(tmp);
		urarlib_freelist(rarlist_head);
#ifdef CL_THREAD_SAFE
		pthread_mutex_unlock(&cli_scanrar_mutex);
		cli_scanrar_inuse = 0;
#endif
		return CL_EFSYNC;
	    }

	    lseek(fd, 0, SEEK_SET);
	    if((ret = cli_magic_scandesc(fd, virname, scanned, root, limits, options, arec, mrec)) == CL_VIRUS ) {
		cli_dbgmsg("RAR: Infected with %s\n", *virname);

		fclose(tmp);
		urarlib_freelist(rarlist);
#ifdef CL_THREAD_SAFE
		pthread_mutex_unlock(&cli_scanrar_mutex);
		cli_scanrar_inuse = 0;
#endif
  		return ret;
	    }

	} else {
	    cli_dbgmsg("RAR: Can't decompress file %s\n", rarlist->item.Name);
	    fclose(tmp);
	    tmp = NULL;
	    ret = CL_ERAR; /* WinRAR 3.0 ? */
	    break;
	}

	fclose(tmp);
	tmp = NULL;
	rarlist = rarlist->next;
	files++;
    }

    urarlib_freelist(rarlist_head);
#ifdef CL_THREAD_SAFE
    pthread_mutex_unlock(&cli_scanrar_mutex);
    cli_scanrar_inuse = 0;
    pthread_cleanup_pop(0);
#endif
    
    cli_dbgmsg("RAR: Exit code: %d\n", ret);

    return ret;
}

#ifdef HAVE_ZLIB_H
static int cli_scanzip(int desc, const char **virname, long int *scanned, const struct cl_node *root, const struct cl_limits *limits, unsigned int options, int *arec, int *mrec)
{
	ZZIP_DIR *zdir;
	ZZIP_DIRENT zdirent;
	ZZIP_FILE *zfp;
	FILE *tmp = NULL;
	char *buff;
	int fd, bytes, files = 0, ret = CL_CLEAN;
	struct stat source;
	zzip_error_t err;


    cli_dbgmsg("in scanzip()\n");

    if((zdir = zzip_dir_fdopen(dup(desc), &err)) == NULL) {
	cli_dbgmsg("Zip: Not supported file format ?.\n");
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

	if(!zdirent.d_name || !strlen(zdirent.d_name)) { /* Mimail fix */
	    cli_dbgmsg("Zip: strlen(zdirent.d_name) == %d\n", strlen(zdirent.d_name));
	    *virname = "Suspected.Zip";
	    ret = CL_VIRUS;
	    break;
	}

	cli_dbgmsg("Zip: %s, compressed: %u, normal: %u, ratio: %d (max: %d)\n", zdirent.d_name, zdirent.d_csize, zdirent.st_size, zdirent.st_size / (zdirent.d_csize+1), limits ? limits->maxratio : -1 );

	/*
	if(!zdirent.st_size) {
	    files++;
	    continue;
	}
	*/

	/* work-around for problematic zips (zziplib crashes with them) */
	if(zdirent.d_csize <= 0 || zdirent.st_size < 0) {
	    files++;
	    cli_dbgmsg("Zip: Malformed archive detected.\n");
	    /* ret = CL_EMALFZIP; */
	    /* report it as a virus */
	    *virname = "Suspected.Zip";
	    ret = CL_VIRUS;
	    break;
	}

	if(limits && limits->maxratio > 0 && ((unsigned) zdirent.st_size / (unsigned) zdirent.d_csize) >= limits->maxratio) {
	    *virname = "Oversized.Zip";
	    ret = CL_VIRUS;
	    break;
        }

	if(DETECT_ENCRYPTED && (zdirent.d_flags & 1 )) {
	    files++;
	    cli_dbgmsg("Zip: Encrypted files found in archive.\n");
	    lseek(desc, 0, SEEK_SET);
	    ret = cli_scandesc(desc, virname, scanned, root, 0, 0);
	    if(ret < 0) {
		break;
	    } else if(ret != CL_VIRUS) {
		*virname = "Encrypted.Zip";
		ret = CL_VIRUS;
	    }
	    break;
	}

	if(limits) {
	    if(limits->maxfilesize && (zdirent.st_size > limits->maxfilesize)) {
		cli_dbgmsg("Zip: %s: Size exceeded (%d, max: %ld)\n", zdirent.d_name, zdirent.st_size, limits->maxfilesize);
		files++;
		/* ret = CL_EMAXSIZE; */
		if(BLOCKMAX) {
		    *virname = "Zip.ExceededFileSize";
		    ret = CL_VIRUS;
		    break;
		}
		continue; /* continue scanning */
	    }

	    if(limits->maxfiles && (files > limits->maxfiles)) {
		cli_dbgmsg("Zip: Files limit reached (max: %d)\n", limits->maxfiles);
		if(BLOCKMAX) {
		    *virname = "Zip.ExceededFilesLimit";
		    ret = CL_VIRUS;
		    break;
		}
		break;
	    }
	}

	/* generate temporary file and get its descriptor */
	if((tmp = tmpfile()) == NULL) {
	    cli_dbgmsg("Zip: Can't generate tmpfile().\n");
	    ret = CL_ETMPFILE;
	    break;
	}

	if((zfp = zzip_file_open(zdir, zdirent.d_name, 0)) == NULL) {
	    cli_dbgmsg("Zip: Can't open file %s\n", zdirent.d_name);
	    ret = CL_EZIP;
	    break;
	}

	while((bytes = zzip_file_read(zfp, buff, FILEBUFF)) > 0) {
	    if(fwrite(buff, 1, bytes, tmp) != (size_t) bytes) {
		cli_dbgmsg("Zip: Can't write to file.\n");
		zzip_file_close(zfp);
		zzip_dir_close(zdir);
		fclose(tmp);
		free(buff);
		return CL_EZIP;
	    }
	}

	zzip_file_close(zfp);


	if(fflush(tmp) != 0) {
	    cli_dbgmsg("Zip: fflush() failed: %s\n", strerror(errno));
	    ret = CL_EFSYNC;
	    break;
	}

	fd = fileno(tmp);

	lseek(fd, 0, SEEK_SET);
	if((ret = cli_magic_scandesc(fd, virname, scanned, root, limits, options, arec, mrec)) == CL_VIRUS ) {
	    cli_dbgmsg("Zip: Infected with %s\n", *virname);
	    ret = CL_VIRUS;
	    break;
	} else if(ret == CL_EMALFZIP) {
	    /* 
	     * The trick with detection of ZoD only works with higher (>= 5)
	     * recursion limit level.
	     */
	    cli_dbgmsg("Zip: Malformed Zip file, scanning stopped.\n");
	    *virname = "Suspected.Zip";
	    ret = CL_VIRUS;
	    break;
	}

	if (tmp) {
	    fclose(tmp);
	    tmp = NULL;
	}
	files++;
    }

    zzip_dir_close(zdir);
    if (tmp) {
	fclose(tmp);
	tmp = NULL;
    }

    free(buff);
    return ret;
}

static int cli_scangzip(int desc, const char **virname, long int *scanned, const struct cl_node *root, const struct cl_limits *limits, unsigned int options, int *arec, int *mrec)
{
	int fd, bytes, ret = CL_CLEAN;
	long int size = 0;
	char *buff;
	FILE *tmp = NULL;
	gzFile gd;


    cli_dbgmsg("in cli_scangzip()\n");

    if((gd = gzdopen(dup(desc), "rb")) == NULL) {
	cli_dbgmsg("GZip: Can't open descriptor %d\n", desc);
	return CL_EGZIP;
    }

    if((tmp = tmpfile()) == NULL) {
	cli_dbgmsg("GZip: Can't generate temporary file.\n");
	gzclose(gd);
	return CL_ETMPFILE;
    }
    fd = fileno(tmp);

    if(!(buff = (char *) cli_malloc(FILEBUFF))) {
	cli_dbgmsg("GZip: Unable to malloc %d bytes.\n", FILEBUFF);
	gzclose(gd);
	return CL_EMEM;
    }

    while((bytes = gzread(gd, buff, FILEBUFF)) > 0) {
	size += bytes;

	if(limits)
	    if(limits->maxfilesize && (size + FILEBUFF > limits->maxfilesize)) {
		cli_dbgmsg("GZip: Size exceeded (stopped at %ld, max: %ld)\n", size, limits->maxfilesize);
		/* ret = CL_EMAXSIZE; */
		break;
	    }

	if(cli_writen(fd, buff, bytes) != bytes) {
	    cli_dbgmsg("GZip: Can't write to file.\n");
	    fclose(tmp);
	    gzclose(gd);
	    free(buff);
	    return CL_EGZIP;
	}
    }

    free(buff);
    gzclose(gd);
    if(fsync(fd) == -1) {
	cli_dbgmsg("GZip: Can't synchronise descriptor %d\n", fd);
	fclose(tmp);
	return CL_EFSYNC;
    }

    lseek(fd, 0, SEEK_SET);
    if((ret = cli_magic_scandesc(fd, virname, scanned, root, limits, options, arec, mrec)) == CL_VIRUS ) {
	cli_dbgmsg("GZip: Infected with %s\n", *virname);
	fclose(tmp);
	return CL_VIRUS;
    }
    fclose(tmp);

    return ret;
}
#endif

#ifdef HAVE_BZLIB_H

#ifdef NOBZ2PREFIX
#define BZ2_bzReadOpen bzReadOpen
#define BZ2_bzReadClose bzReadClose
#define BZ2_bzRead bzRead
#endif

static int cli_scanbzip(int desc, const char **virname, long int *scanned, const struct cl_node *root, const struct cl_limits *limits, unsigned int options, int *arec, int *mrec)
{
	int fd, bytes, ret = CL_CLEAN, bzerror = 0;
	short memlim = 0;
	long int size = 0;
	char *buff;
	FILE *fs, *tmp = NULL;
	BZFILE *bfd;


    if((fs = fdopen(dup(desc), "rb")) == NULL) {
	cli_dbgmsg("Bzip: Can't open descriptor %d.\n", desc);
	return CL_EBZIP;
    }

    if(limits)
	if(limits->archivememlim)
	    memlim = 1;

    if((bfd = BZ2_bzReadOpen(&bzerror, fs, 0, memlim, NULL, 0)) == NULL) {
	cli_dbgmsg("Bzip: Can't initialize bzip2 library (descriptor: %d).\n", desc);
	fclose(fs);
	return CL_EBZIP;
    }

    if((tmp = tmpfile()) == NULL) {
	cli_dbgmsg("Bzip: Can't generate temporary file.\n");
	BZ2_bzReadClose(&bzerror, bfd);
	fclose(fs);
	return CL_ETMPFILE;
    }
    fd = fileno(tmp);

    if(!(buff = (char *) malloc(FILEBUFF))) {
	cli_dbgmsg("Bzip: Unable to malloc %d bytes.\n", FILEBUFF);
	fclose(tmp);
	fclose(fs);
	BZ2_bzReadClose(&bzerror, bfd);
	return CL_EMEM;
    }

    while((bytes = BZ2_bzRead(&bzerror, bfd, buff, FILEBUFF)) > 0) {
	size += bytes;

	if(limits)
	    if(limits->maxfilesize && (size + FILEBUFF > limits->maxfilesize)) {
		cli_dbgmsg("Bzip: Size exceeded (stopped at %ld, max: %ld)\n", size, limits->maxfilesize);
		/* ret = CL_EMAXSIZE; */
		break;
	    }

	if(cli_writen(fd, buff, bytes) != bytes) {
	    cli_dbgmsg("Bzip: Can't write to file.\n");
	    BZ2_bzReadClose(&bzerror, bfd);
	    fclose(tmp);
	    free(buff);
	    fclose(fs);
	    return CL_EGZIP;
	}
    }

    free(buff);
    BZ2_bzReadClose(&bzerror, bfd);
    if(fsync(fd) == -1) {
	cli_dbgmsg("Bzip: Synchronisation failed for descriptor %d\n", fd);
	fclose(tmp);
	fclose(fs);
	return CL_EFSYNC;
    }

    lseek(fd, 0, SEEK_SET);
    if((ret = cli_magic_scandesc(fd, virname, scanned, root, limits, options, arec, mrec)) == CL_VIRUS ) {
	cli_dbgmsg("Bzip: Infected with %s\n", *virname);
    }
    fclose(tmp);
    fclose(fs);

    return ret;
}
#endif

static int cli_scanszdd(int desc, const char **virname, long int *scanned, const struct cl_node *root, const struct cl_limits *limits, unsigned int options, int *arec, int *mrec)
{
	int fd, ret = CL_CLEAN;
	FILE *tmp = NULL, *in;


    cli_dbgmsg("in cli_scanmscomp()\n");

    if((in = fdopen(dup(desc), "rb")) == NULL) {
	cli_dbgmsg("SZDD: Can't open descriptor %d\n", desc);
	return CL_EMSCOMP;
    }

    if((tmp = tmpfile()) == NULL) {
	cli_dbgmsg("SZDD: Can't generate temporary file.\n");
	fclose(in);
	return CL_ETMPFILE;
    }

    if(cli_msexpand(in, tmp) == -1) {
	cli_dbgmsg("SZDD: msexpand failed.\n");
	return CL_EMSCOMP;
    }

    fclose(in);
    if(fflush(tmp)) {
	cli_dbgmsg("SZDD: fflush() failed.\n");
	fclose(tmp);
	return CL_EFSYNC;
    }

    fd = fileno(tmp);
    lseek(fd, 0, SEEK_SET);
    if((ret = cli_magic_scandesc(fd, virname, scanned, root, limits, options, arec, mrec)) == CL_VIRUS) {
	cli_dbgmsg("SZDD: Infected with %s\n", *virname);
	fclose(tmp);
	return CL_VIRUS;
    }

    fclose(tmp);
    return ret;
}

static int cli_scanmscab(int desc, const char **virname, long int *scanned, const struct cl_node *root, const struct cl_limits *limits, unsigned int options, int *arec, int *mrec)
{
	struct mscab_decompressor *cabd = NULL;
	struct mscabd_cabinet *base, *cab;
	struct mscabd_file *file;
	const char *tmpdir;
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

    if((tmpdir = getenv("TMPDIR")) == NULL)
#ifdef P_tmpdir
	tmpdir = P_tmpdir;
#else
	tmpdir = "/tmp";
#endif

    for(cab = base; cab; cab = cab->next) {
	for(file = cab->files; file; file = file->next) {

	    if(limits && limits->maxfilesize && (file->length > (unsigned int) limits->maxfilesize)) {
		cli_dbgmsg("MSCAB: %s: Size exceeded (%u, max: %lu)\n", file->filename, file->length, limits->maxfilesize);
		if(BLOCKMAX) {
		    *virname = "MSCAB.ExceededFileSize";
		    cabd->close(cabd, base);
		    mspack_destroy_cab_decompressor(cabd);
		    return CL_VIRUS;
		}
		continue;
	    }

	    tempname = cli_gentemp(tmpdir);
	    cli_dbgmsg("MSCAB: Extracting data to %s\n", tempname);
	    if(cabd->extract(cabd, file, tempname)) {
		cli_dbgmsg("MSCAB: libmscab error code: %d\n", cabd->last_error(cabd));
	    } else {
		ret = cli_scanfile(tempname, virname, scanned, root, limits, options, arec, mrec);
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

static int cli_scanhtml(int desc, const char **virname, long int *scanned, const struct cl_node *root, const struct cl_limits *limits, unsigned int options, int *arec, int *mrec)
{
	char *tempname, fullname[1024];
	const char *tmpdir;
	int ret=CL_CLEAN, fd;


    cli_dbgmsg("in cli_scanhtml()\n");

    if((tmpdir = getenv("TMPDIR")) == NULL)
#ifdef P_tmpdir
        tmpdir = P_tmpdir;
#else
        tmpdir = "/tmp";
#endif
                                                                                                                                           
    tempname = cli_gentemp(tmpdir);
                                                                                                                                           
    if(mkdir(tempname, 0700)) {
        cli_dbgmsg("ScanHTML -> Can't create temporary directory %s\n", tempname);
        return CL_ETMPDIR;
    }

    html_normalise_fd(desc, tempname, NULL);
    snprintf(fullname, 1024, "%s/comment.html", tempname);
    fd = open(fullname, O_RDONLY);
    if (fd >= 0) {
        ret = cli_scandesc(fd, virname, scanned, root, 0, CL_TYPE_HTML);
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
	    ret = cli_scandesc(fd, virname, scanned, root, 0, CL_TYPE_HTML);
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
	    ret = cli_scandesc(fd, virname, scanned, root, 0, CL_TYPE_HTML);
	    close(fd);
	}
    }

    if(!cli_leavetemps_flag)
        cli_rmdirs(tempname);

    free(tempname);
    return ret;
}

static int cli_scandir(const char *dirname, const char **virname, long int *scanned, const struct cl_node *root, const struct cl_limits *limits, unsigned int options, int *arec, int *mrec)
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
			    if (cli_scandir(fname, virname, scanned, root, limits, options, arec, mrec) == CL_VIRUS) {
				free(fname);
				closedir(dd);
				return CL_VIRUS;
			    }
			} else
			    if(S_ISREG(statbuf.st_mode))
				if(cli_scanfile(fname, virname, scanned, root, limits, options, arec, mrec) == CL_VIRUS) {
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

static int cli_vba_scandir(const char *dirname, const char **virname, long int *scanned, const struct cl_node *root, const struct cl_limits *limits, unsigned int options, int *arec, int *mrec)
{
	int ret = CL_CLEAN, i, fd, data_len;
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
		if(scanned)
		    *scanned += data_len / CL_COUNT_PRECISION;

		if(cli_scanbuff(data, data_len, virname, root, CL_TYPE_MSOLE2) == CL_VIRUS) {
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
    	if(cli_scandir(fullname, virname, scanned, root, limits, options, arec, mrec) == CL_VIRUS) {
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
		cli_dbgmsg("VBADir: Decompress WM project '%s' macro:%d key:%d\n", vba_project->name[i], i, vba_project->key[i]);
		data = (unsigned char *) wm_decrypt_macro(fd, vba_project->offset[i], vba_project->length[i], vba_project->key[i]);
		close(fd);
		
		if(!data) {
			cli_dbgmsg("VBADir: WARNING: WM project '%s' macro %d decrypted to NULL\n", vba_project->name[i], i);
		} else {
			if(scanned)
			    *scanned += vba_project->length[i] / CL_COUNT_PRECISION;
			if(cli_scanbuff(data, vba_project->length[i], virname, root, CL_TYPE_MSOLE2) == CL_VIRUS) {
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
			    if (cli_vba_scandir(fname, virname, scanned, root, limits, options, arec, mrec) == CL_VIRUS) {
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

static int cli_scanole2(int desc, const char **virname, long int *scanned, const struct cl_node *root, const struct cl_limits *limits, unsigned int options, int *arec, int *mrec)
{
	const char *tmpdir;
	char *dir;
	int ret = CL_CLEAN;


    cli_dbgmsg("in cli_scanole2()\n");

    if((tmpdir = getenv("TMPDIR")) == NULL)
#ifdef P_tmpdir
	tmpdir = P_tmpdir;
#else
	tmpdir = "/tmp";
#endif

    /* generate the temporary directory */
    dir = cli_gentemp(tmpdir);
    if(mkdir(dir, 0700)) {
	cli_dbgmsg("OLE2: Can't create temporary directory %s\n", dir);
	return CL_ETMPDIR;
    }

    if((ret = cli_ole2_extract(desc, dir, limits))) {
	cli_dbgmsg("OLE2: %s\n", cl_strerror(ret));
	if(!cli_leavetemps_flag)
	    cli_rmdirs(dir);
	free(dir);
	return ret;
    }

    if((ret = cli_vba_scandir(dir, virname, scanned, root, limits, options, arec, mrec)) != CL_VIRUS) {
	if(cli_scandir(dir, virname, scanned, root, limits, options, arec, mrec) == CL_VIRUS) {
	    ret = CL_VIRUS;
	}
    }

    if(!cli_leavetemps_flag)
	cli_rmdirs(dir);
    free(dir);
    return ret;
}

static int cli_scantar(int desc, const char **virname, long int *scanned, const struct cl_node *root, const struct cl_limits *limits, unsigned int options, int *arec, int *mrec)
{
	const char *tmpdir;
	char *dir;
	int ret = CL_CLEAN;


    cli_dbgmsg("in cli_scantar()\n");

    if((tmpdir = getenv("TMPDIR")) == NULL)
#ifdef P_tmpdir
	tmpdir = P_tmpdir;
#else
	tmpdir = "/tmp";
#endif

    /* generate temporary directory */
    dir = cli_gentemp(tmpdir);
    if(mkdir(dir, 0700)) {
	cli_errmsg("Tar: Can't create temporary directory %s\n", dir);
	return CL_ETMPDIR;
    }

    if((ret = cli_untar(dir, desc)))
	cli_dbgmsg("Tar: %s\n", cl_strerror(ret));
    else
	ret = cli_scandir(dir, virname, scanned, root, limits, options, arec, mrec);

    if(!cli_leavetemps_flag)
	cli_rmdirs(dir);

    free(dir);
    return ret;
}

static int cli_scanmschm(int desc, const char **virname, long int *scanned, const struct cl_node *root, const struct cl_limits *limits, unsigned int options, int *arec, int *mrec)
{
	const char *tmpdir;
	char *tempname;
	int ret = CL_CLEAN;


    cli_dbgmsg("in cli_scanmschm()\n");	

    if((tmpdir = getenv("TMPDIR")) == NULL)
#ifdef P_tmpdir
	tmpdir = P_tmpdir;
#else
	tmpdir = "/tmp";
#endif

    tempname = cli_gentemp(tmpdir);

    if(mkdir(tempname, 0700)) {
	cli_dbgmsg("CHM: Can't create temporary directory %s\n", tempname);
	return CL_ETMPDIR;
    }

    if(chm_unpack(desc, tempname))
	ret = cli_scandir(tempname, virname, scanned, root, limits, options, arec, mrec);

    if(!cli_leavetemps_flag)
	cli_rmdirs(tempname);

    free(tempname);
    return ret;
}

static int cli_scanscrenc(int desc, const char **virname, long int *scanned, const struct cl_node *root, const struct cl_limits *limits, unsigned int options, int *arec, int *mrec)
{
	const char *tmpdir;
	char *tempname;
	int ret = CL_CLEAN;

    cli_dbgmsg("in cli_scanscrenc()\n");

    if((tmpdir = getenv("TMPDIR")) == NULL)
#ifdef P_tmpdir
        tmpdir = P_tmpdir;
#else
        tmpdir = "/tmp";
#endif
                                                                                                                               
    tempname = cli_gentemp(tmpdir);
                                                                                                                               
    if(mkdir(tempname, 0700)) {
	cli_dbgmsg("CHM: Can't create temporary directory %s\n", tempname);
	return CL_ETMPDIR;
    }

    if (html_screnc_decode(desc, tempname))
	ret = cli_scandir(tempname, virname, scanned, root, limits, options, arec, mrec);

    if(!cli_leavetemps_flag)
	cli_rmdirs(tempname);

    free(tempname);
    return ret;
}

static int cli_scanmail(int desc, const char **virname, long int *scanned, const struct cl_node *root, const struct cl_limits *limits, unsigned int options, int *arec, int *mrec)
{
	const char *tmpdir;
	char *dir;
	int ret;


    cli_dbgmsg("Starting cli_scanmail(), mrec == %d, arec == %d\n", *mrec, *arec);

    if((tmpdir = getenv("TMPDIR")) == NULL)
#ifdef P_tmpdir
	tmpdir = P_tmpdir;
#else
	tmpdir = "/tmp";
#endif

	/* generate the temporary directory */
	dir = cli_gentemp(tmpdir);
	if(mkdir(dir, 0700)) {
	    cli_dbgmsg("Mail: Can't create temporary directory %s\n", dir);
	    free(dir);
	    return CL_ETMPDIR;
	}

	/*
	 * Extract the attachments into the temporary directory
	 */
	if((ret = cli_mbox(dir, desc, options))) {
	    if(!cli_leavetemps_flag)
		cli_rmdirs(dir);
	    free(dir);
	    return ret;
	}

	ret = cli_scandir(dir, virname, scanned, root, limits, options, arec, mrec);

	if(!cli_leavetemps_flag)
	    cli_rmdirs(dir);
	free(dir);

	return ret;
}

int cli_magic_scandesc(int desc, const char **virname, long int *scanned, const struct cl_node *root, const struct cl_limits *limits, unsigned int options, int *arec, int *mrec)
{
	char magic[MAGIC_BUFFER_SIZE + 1];
	int ret = CL_CLEAN, nret;
	int bread = 0;
	cli_file_t type;


    if(!root) {
	cli_errmsg("CRITICAL: root == NULL\n");
	return CL_EMALFDB;
    }

    if(!options) { /* raw mode (stdin, etc.) */
	cli_dbgmsg("Raw mode: No support for special files\n");
	if((ret = cli_scandesc(desc, virname, scanned, root, 0, 0) == CL_VIRUS))
	    cli_dbgmsg("%s found in descriptor %d\n", *virname, desc);
	return ret;
    }

    if(SCAN_ARCHIVE && limits && limits->maxreclevel)
	if(*arec > limits->maxreclevel) {
	    cli_dbgmsg("Archive recursion limit exceeded (arec == %d).\n", *arec);
	    /* return CL_EMAXREC; */
	    return CL_CLEAN;
	}

    if(SCAN_MAIL)
	if(*mrec > MAX_MAIL_RECURSION) {
	    cli_dbgmsg("Mail recursion level exceeded (mrec == %d).\n", *mrec);
	    /* return CL_EMAXREC; */
	    return CL_CLEAN;
	}

    lseek(desc, 0, SEEK_SET);
    memset(magic, 0, sizeof(magic));

    if((bread = read(desc, magic, MAGIC_BUFFER_SIZE)) == -1) {
	cli_dbgmsg("Can't read from descriptor %d\n");
	return CL_EIO;
    } else if(bread < 2) {
	/* short read - no need to do magic */
	return CL_CLEAN;
    }

    lseek(desc, 0, SEEK_SET);
    type = cli_filetype(magic, bread);

    type == CL_TYPE_MAIL ? (*mrec)++ : (*arec)++;

    switch(type) {
	case CL_TYPE_RAR:
	    if(!DISABLE_RAR && SCAN_ARCHIVE && !cli_scanrar_inuse)
		ret = cli_scanrar(desc, virname, scanned, root, limits, options, arec, mrec);
	    break;

	case CL_TYPE_ZIP:
	    if(SCAN_ARCHIVE)
		ret = cli_scanzip(desc, virname, scanned, root, limits, options, arec, mrec);
	    break;

	case CL_TYPE_GZ:
	    if(SCAN_ARCHIVE)
		ret = cli_scangzip(desc, virname, scanned, root, limits, options, arec, mrec);
	    break;

	case CL_TYPE_BZ:
#ifdef HAVE_BZLIB_H
	    if(SCAN_ARCHIVE)
		ret = cli_scanbzip(desc, virname, scanned, root, limits, options, arec, mrec);
#endif
	    break;

	case CL_TYPE_MSSZDD:
	    if(SCAN_ARCHIVE)
		ret = cli_scanszdd(desc, virname, scanned, root, limits, options, arec, mrec);
	    break;

	case CL_TYPE_MSCAB:
	    if(SCAN_ARCHIVE)
		ret = cli_scanmscab(desc, virname, scanned, root, limits, options, arec, mrec);
	    break;

	case CL_TYPE_MAIL:
	    if(SCAN_MAIL)
		ret = cli_scanmail(desc, virname, scanned, root, limits, options, arec, mrec);
	    break;

	case CL_TYPE_MSCHM:
	    if(SCAN_ARCHIVE)
		ret = cli_scanmschm(desc, virname, scanned, root, limits, options, arec, mrec);
	    break;

	case CL_TYPE_MSOLE2:
	    if(SCAN_OLE2)
		ret = cli_scanole2(desc, virname, scanned, root, limits, options, arec, mrec);
	    break;

	case CL_TYPE_TAR:
	    if(SCAN_ARCHIVE)
		ret = cli_scantar(desc, virname, scanned, root, limits, options, arec, mrec);
	    break;

	case CL_TYPE_SCRENC:
	    ret = cli_scanscrenc(desc, virname, scanned, root, limits, options, arec, mrec);
	    break;

	case CL_TYPE_DATA:
	    /* it could be a false positive and a standard DOS .COM file */
	    {
		struct stat s;
		if(fstat(desc, &s) == 0 && S_ISREG(s.st_mode) && s.st_size < 65536)
		type = CL_TYPE_UNKNOWN_DATA;
	    }

	case CL_TYPE_UNKNOWN_DATA:
	    ret = cli_check_mydoom_log(desc, virname);
	    break;

	default:
	    break;
    }

    type == CL_TYPE_MAIL ? (*mrec)-- : (*arec)--;

    if(type != CL_TYPE_DATA && ret != CL_VIRUS) { /* scan the raw file */
	    int typerec;

	type == CL_TYPE_UNKNOWN_TEXT ? (typerec = 1) : (typerec = 0);
	if(lseek(desc, 0, SEEK_SET) < 0)
	    cli_errmsg("lseek() failed, trying to continue anyway...\n");

	if((nret = cli_scandesc(desc, virname, scanned, root, typerec, type)) == CL_VIRUS) {
	    cli_dbgmsg("%s found in descriptor %d.\n", *virname, desc);
	    return CL_VIRUS;

	} else if(nret < 0) {
	    return nret;

	} else if(nret >= CL_TYPENO) {
	    lseek(desc, 0, SEEK_SET);

	    switch(nret) {
		case CL_TYPE_HTML:
		    if(SCAN_HTML)
			if(cli_scanhtml(desc, virname, scanned, root, limits, options, arec, mrec) == CL_VIRUS)
			    return CL_VIRUS;
		    break;

		case CL_TYPE_MAIL:
		    if(SCAN_MAIL)
			if(cli_scanmail(desc, virname, scanned, root, limits, options, arec, mrec) == CL_VIRUS)
			    return CL_VIRUS;
		    break;
	    }
	}
    }

    (*arec)++;
    lseek(desc, 0, SEEK_SET);
    switch(type) {
	/* Due to performance reasons all executables were first scanned
	 * in raw mode. Now we will try to unpack them
	 */
	case CL_TYPE_MSEXE:
	    if(SCAN_PE)
		ret = cli_scanpe(desc, virname, scanned, root, limits, options, arec, mrec);
	    break;

	default:
	    break;
    }
    (*arec)--;

    if(ret == CL_EFORMAT) {
	cli_warnmsg("Descriptor[%d]: %s\n", desc, cl_strerror(CL_EFORMAT));
	return CL_CLEAN;
    } else {
	return ret;
    }
}

int cl_scandesc(int desc, const char **virname, unsigned long int *scanned, const struct cl_node *root, const struct cl_limits *limits, unsigned int options)
{
	int arec = 0, mrec = 0;

    return cli_magic_scandesc(desc, virname, scanned, root, limits, options, &arec, &mrec);
}

static int cli_scanfile(const char *filename, const char **virname, unsigned long int *scanned, const struct cl_node *root, const struct cl_limits *limits, unsigned int options, int *arec, int *mrec)
{
	int fd, ret;


    /* internal version of cl_scanfile with arec/mrec preserved */
    if((fd = open(filename, O_RDONLY)) == -1)
	return CL_EOPEN;

    ret = cli_magic_scandesc(fd, virname, scanned, root, limits, options, arec, mrec);

    close(fd);
    return ret;
}

int cl_scanfile(const char *filename, const char **virname, unsigned long int *scanned, const struct cl_node *root, const struct cl_limits *limits, unsigned int options)
{
	int fd, ret;


    if((fd = open(filename, O_RDONLY)) == -1)
	return CL_EOPEN;

    ret = cl_scandesc(fd, virname, scanned, root, limits, options);
    close(fd);

    return ret;
}

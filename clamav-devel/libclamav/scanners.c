/*
 *  Copyright (C) 2002 - 2004 Tomasz Kojm <tkojm@clamav.net>
 *  With enhancements from Thomas Lamy <Thomas.Lamy@in-online.net>
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
#include <fcntl.h>
#include <dirent.h>

#ifdef CL_THREAD_SAFE
#  include <pthread.h>
pthread_mutex_t cli_scanrar_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif
int cli_scanrar_inuse = 0;

#include "clamav.h"
#include "others.h"
#include "matcher.h"
#include "unrarlib.h"
#include "ole2_extract.h"
#include "vba_extract.h"
#include "scanners.h"

#ifdef HAVE_ZLIB_H
#include <zlib.h>
#include <zzip.h>
#endif

#ifdef HAVE_BZLIB_H
#include <bzlib.h>
#endif

#define SCAN_ARCHIVE	    (options & CL_ARCHIVE)
#define SCAN_MAIL	    (options & CL_MAIL)
#define SCAN_OLE2	    (options & CL_OLE2)
#define DISABLE_RAR	    (options & CL_DISABLERAR)
#define DETECT_ENCRYPTED    (options & CL_ENCRYPTED)

struct cli_magic_s {
    int offset;
    const char *magic;
    size_t length;
    const char *descr;
    cli_file_t type;
};

#define MAGIC_BUFFER_SIZE 26
static const struct cli_magic_s cli_magic[] = {
    {0,  "Rar!",			4,  "RAR",		  CL_RARFILE},
    {0,  "PK\003\004",			4,  "ZIP",		  CL_ZIPFILE},
    {0,  "\037\213",			2,  "GZip",		  CL_GZFILE},
    {0,  "BZh",				3,  "BZip",		  CL_BZFILE},
    {0,  "From ",			5,  "MBox",		  CL_MAILFILE},
    {0,  "Received: ",			10, "Raw mail",		  CL_MAILFILE},
    {0,  "Return-Path: ",		13, "Maildir",		  CL_MAILFILE},
    {0,  "Return-path: ",		13, "Maildir",		  CL_MAILFILE},
    {0,  "Delivered-To: ",		14, "Mail",		  CL_MAILFILE},
    {0,  "X-UIDL: ",			8,  "Mail",		  CL_MAILFILE},
    {0,  "For: ",			5,  "Eserv mail",	  CL_MAILFILE},
    {0,  "From: ",			6,  "Exim mail",	  CL_MAILFILE},
    {0,  "X-Symantec-",			11, "Symantec",		  CL_MAILFILE},
    {0,  "X-Apparently-To: ",		17, "Mail",		  CL_MAILFILE},
    {0,  "For: ",			5,  "Eserv mail",	  CL_MAILFILE},
    {0,  "X-EVS",			5,  "EVS mail",		  CL_MAILFILE},
    {0,  ">From ",			6,  "Symantec",		  CL_MAILFILE},
    {0,  "v:\015\012Received: ",	14, "VPOP3 Mail (DOS)",	  CL_MAILFILE},
    {0,  "v:\012Received: ",		13, "VPOP3 Mail (UNIX)",  CL_MAILFILE},
    {0,  "Hi. This is the qmail-send",  26, "Qmail bounce",	  CL_MAILFILE},
    {0,  "\320\317\021\340\241\261\032\341",
	                    8, "OLE2 container",  CL_OLE2FILE},
    {-1, NULL,              0, NULL,              CL_UNKNOWN_TYPE}
};

cli_file_t cli_filetype(const char *buf, size_t buflen)
{
	int i;

    for (i = 0; cli_magic[i].magic; i++) {
	if (buflen >= cli_magic[i].offset+cli_magic[i].length) {
	    if (memcmp(buf+cli_magic[i].offset, cli_magic[i].magic, cli_magic[i].length) == 0) {
		cli_dbgmsg("Recognized %s file\n", cli_magic[i].descr);
		return cli_magic[i].type;
	    }
	}
    }

    return CL_UNKNOWN_TYPE;
}

static int cli_magic_scandesc(int desc, const char **virname, long int *scanned, const struct cl_node *root, const struct cl_limits *limits, int options, int *reclev);
static int cli_scanfile(const char *filename, const char **virname, unsigned long int *scanned, const struct cl_node *root, const struct cl_limits *limits, int options, int *reclev);

static int cli_scandesc(int desc, const char **virname, long int *scanned, const struct 
cl_node *root)
{
 	char *buffer, *buff, *endbl, *pt;
	int bytes, buffsize, length, ret, *partcnt;

    /* prepare the buffer */
    buffsize = root->maxpatlen + SCANBUFF;
    if(!(buffer = (char *) cli_calloc(buffsize, sizeof(char)))) {
	cli_dbgmsg("cli_scandesc(): unable to cli_malloc(%d)\n", buffsize);
	return CL_EMEM;
    }

    if((partcnt = (int *) cli_calloc(root->partsigs + 1, sizeof(int))) == NULL) {
	cli_dbgmsg("cli_scandesc(): unable to cli_calloc(%d, %d)\n", root->partsigs + 1, sizeof(int));
	free(buffer);
	return CL_EMEM;
    }

    buff = buffer;
    buff += root->maxpatlen; /* pointer to read data block */
    endbl = buff + SCANBUFF - root->maxpatlen; /* pointer to the last block
						* length of root->maxpatlen
						*/

    pt= buff;
    length = SCANBUFF;
    while((bytes = read(desc, buff, SCANBUFF)) > 0) {

	if(scanned != NULL)
	    *scanned += bytes / CL_COUNT_PRECISION;

	if(bytes < SCANBUFF)
	    length -= SCANBUFF - bytes;

	if((ret = cli_scanbuff(pt, length, virname, root, partcnt)) != CL_CLEAN) {
	    free(buffer);
	    free(partcnt);
	    return ret;
	}

	if(bytes == SCANBUFF)
	    memmove(buffer, endbl, root->maxpatlen);

        pt = buffer;
        length=buffsize;

    }

    free(buffer);
    free(partcnt);
    return CL_CLEAN;
}

#ifdef CL_THREAD_SAFE
static void cli_unlock_mutex(void *mtx)
{
    cli_dbgmsg("Pthread cancelled. Unlocking mutex.\n");
    pthread_mutex_unlock(mtx);
}
#endif

static int cli_scanrar(int desc, const char **virname, long int *scanned, const struct cl_node *root, const struct cl_limits *limits, int options, int *reclev)
{
	FILE *tmp = NULL;
	int files = 0, fd, ret = CL_CLEAN, afiles;
	ArchiveList_struct *rarlist = NULL;
	ArchiveList_struct *rarlist_head = NULL;
	char *rar_data_ptr;
	unsigned long rar_data_size;

    cli_dbgmsg("Starting scanrar()\n");


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

    cli_dbgmsg("Rar -> Number of archived files: %d\n", afiles);

    rarlist_head = rarlist;

    while(rarlist) {
	if(DETECT_ENCRYPTED && (rarlist->item.Flags & 4)) {
	    files++;
	    cli_dbgmsg("Rar -> Encrypted files found in archive.\n");
	    *virname = "Encrypted.RAR";
	    ret = CL_VIRUS;
	    break;
	}

	if(limits) {
	    if(limits->maxfilesize && (rarlist->item.UnpSize > (unsigned int) limits->maxfilesize)) {
		cli_dbgmsg("RAR->%s: Size exceeded (%u, max: %lu)\n", rarlist->item.Name, (unsigned int) rarlist->item.UnpSize, limits->maxfilesize);
		rarlist = rarlist->next;
		files++;
		/* ret = CL_EMAXSIZE; */
		continue;
	    }

	    if(limits->maxfiles && (files > limits->maxfiles)) {
		cli_dbgmsg("RAR: Files limit reached (max: %d)\n", limits->maxfiles);
		/* ret = CL_EMAXFILES; */
		break;
	    }
	}

        if(!!( rarlist->item.FileAttr & RAR_FENTRY_ATTR_DIRECTORY)) {
            rarlist = rarlist->next;
            files++;
            continue;
        }

	if((tmp = tmpfile()) == NULL) {
	    cli_dbgmsg("RAR -> Can't generate tmpfile().\n");
#ifdef CL_THREAD_SAFE
	    pthread_mutex_unlock(&cli_scanrar_mutex);
	    cli_scanrar_inuse = 0;
#endif
	    return CL_ETMPFILE;
	}
	fd = fileno(tmp);

	if( urarlib_get(&rar_data_ptr, &rar_data_size, rarlist->item.Name, desc, "clam")) {
	    cli_dbgmsg("RAR -> Extracted: %s, size: %lu\n", rarlist->item.Name, rar_data_size);
	    if(fwrite(rar_data_ptr, 1, rar_data_size, tmp) != rar_data_size) {
		cli_dbgmsg("RAR -> Can't write() file.\n");
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
		cli_dbgmsg("fflush() failed: %s\n", strerror(errno));
		fclose(tmp);
		urarlib_freelist(rarlist_head);
#ifdef CL_THREAD_SAFE
		pthread_mutex_unlock(&cli_scanrar_mutex);
		cli_scanrar_inuse = 0;
#endif
		return CL_EFSYNC;
	    }

	    lseek(fd, 0, SEEK_SET);
	    if((ret = cli_magic_scandesc(fd, virname, scanned, root, limits, options, reclev)) == CL_VIRUS ) {
		cli_dbgmsg("RAR -> Found %s virus.\n", *virname);

		fclose(tmp);
		urarlib_freelist(rarlist);
#ifdef CL_THREAD_SAFE
		pthread_mutex_unlock(&cli_scanrar_mutex);
		cli_scanrar_inuse = 0;
#endif
  		return ret;
	    }

	} else {
	    cli_dbgmsg("RAR -> Can't decompress file %s\n", rarlist->item.Name);
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
    
    cli_dbgmsg("RAR -> Exit code: %d\n", ret);

    return ret;
}

#ifdef HAVE_ZLIB_H
static int cli_scanzip(int desc, const char **virname, long int *scanned, const struct cl_node *root, const struct cl_limits *limits, int options, int *reclev)
{
	ZZIP_DIR *zdir;
	ZZIP_DIRENT zdirent;
	ZZIP_FILE *zfp;
	FILE *tmp = NULL;
	char *buff;
	int fd, bytes, files = 0, ret = CL_CLEAN;
	struct stat source;
	zzip_error_t err;

    cli_dbgmsg("Starting scanzip()\n");

    if((zdir = zzip_dir_fdopen(dup(desc), &err)) == NULL) {
	cli_dbgmsg("Zip -> Not supported file format ?.\n");
	cli_dbgmsg("zzip_dir_fdopen() return code: %d\n", err);
	/* no return with CL_EZIP due to password protected zips */
	return CL_CLEAN;
    }

    fstat(desc, &source);

    if(!(buff = (char *) cli_malloc(FILEBUFF))) {
	cli_dbgmsg("cli_scanzip(): unable to malloc(%d)\n", FILEBUFF);
	zzip_dir_close(zdir);
	return CL_EMEM;
    }

    while(zzip_dir_read(zdir, &zdirent)) {

	if(!zdirent.d_name || !strlen(zdirent.d_name)) { /* Mimail fix */
	    cli_dbgmsg("strlen(zdirent.d_name) == %d\n", strlen(zdirent.d_name));
	    *virname = "Suspected.Zip";
	    ret = CL_VIRUS;
	    break;
	}

	cli_dbgmsg("Zip -> %s, compressed: %d, normal: %d, encrypted flag: %d\n", zdirent.d_name, zdirent.d_csize, zdirent.st_size, zdirent.d_flags);

	if(limits && limits->maxratio > 0 && source.st_size && (zdirent.st_size / source.st_size) >= limits->maxratio) {
	    *virname = "Oversized.Zip";
	    ret = CL_VIRUS;
	    break;
	}

	if(!zdirent.st_size) { /* omit directories and null files */
	    files++;
	    continue;
	}

	/* work-around for problematic zips (zziplib crashes with them) */
	if(zdirent.d_csize < 0 || zdirent.st_size < 0) {
	    files++;
	    cli_dbgmsg("Zip -> Malformed archive detected.\n");
	    /* ret = CL_EMALFZIP; */
	    /* report it as a virus */
	    *virname = "Suspected.Zip";
	    ret = CL_VIRUS;
	    break;
	}

	if(DETECT_ENCRYPTED && (zdirent.d_flags & 1 )) {
	    files++;
	    cli_dbgmsg("Zip -> Encrypted files found in archive.\n");
	    *virname = "Encrypted.Zip";
	    ret = CL_VIRUS;
	    break;
	}

	if(limits) {
	    if(limits->maxfilesize && (zdirent.st_size > limits->maxfilesize)) {
		cli_dbgmsg("Zip -> %s: Size exceeded (%d, max: %ld)\n", zdirent.d_name, zdirent.st_size, limits->maxfilesize);
		files++;
		/* ret = CL_EMAXSIZE; */
		continue; /* this is not a bug */
	    }

	    if(limits->maxfiles && (files > limits->maxfiles)) {
		cli_dbgmsg("Zip: Files limit reached (max: %d)\n", limits->maxfiles);
		/* ret = CL_EMAXFILES; */
		break;
	    }
	}

	/* generate temporary file and get its descriptor */
	if((tmp = tmpfile()) == NULL) {
	    cli_dbgmsg("Zip -> Can't generate tmpfile().\n");
	    ret = CL_ETMPFILE;
	    break;
	}

	if((zfp = zzip_file_open(zdir, zdirent.d_name, 0)) == NULL) {
	    cli_dbgmsg("Zip -> %s: Can't open file.\n", zdirent.d_name);
	    ret = CL_EZIP;
	    break;
	}


	while((bytes = zzip_file_read(zfp, buff, FILEBUFF)) > 0) {
	    if(fwrite(buff, bytes, 1, tmp)*bytes != bytes) {
		cli_dbgmsg("Zip -> Can't fwrite() file: %s\n", strerror(errno));
		zzip_file_close(zfp);
		zzip_dir_close(zdir);
		fclose(tmp);
		free(buff);
		return CL_EZIP;
	    }
	}

	zzip_file_close(zfp);

	if(fflush(tmp) != 0) {
	    cli_errmsg("fflush() failed: %s\n", strerror(errno));
	    ret = CL_EFSYNC;
	    break;
	}

	fd = fileno(tmp);

	lseek(fd, 0, SEEK_SET);
	if((ret = cli_magic_scandesc(fd, virname, scanned, root, limits, options, reclev)) == CL_VIRUS ) {
	    cli_dbgmsg("Zip -> Found %s virus.\n", *virname);
	    ret = CL_VIRUS;
	    break;
	} else if(ret == CL_EMALFZIP) {
	    /* 
	     * The trick with detection of ZoD only works with higher (>= 5)
	     * recursion limit level.
	     */
	    cli_dbgmsg("Zip -> Malformed Zip, scanning stopped.\n");
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

static int cli_scangzip(int desc, const char **virname, long int *scanned, const struct cl_node *root, const struct cl_limits *limits, int options, int *reclev)
{
	int fd, bytes, ret = CL_CLEAN;
	long int size = 0;
	char *buff;
	FILE *tmp = NULL;
	gzFile gd;


    cli_dbgmsg("in cli_scangzip()\n");

    if((gd = gzdopen(dup(desc), "rb")) == NULL) {
	cli_dbgmsg("Can't gzdopen() descriptor %d.\n", desc);
	return CL_EGZIP;
    }

    if((tmp = tmpfile()) == NULL) {
	cli_dbgmsg("Can't generate tmpfile().\n");
	gzclose(gd);
	return CL_ETMPFILE;
    }
    fd = fileno(tmp);

    if(!(buff = (char *) cli_malloc(FILEBUFF))) {
	cli_dbgmsg("cli_scangzip(): unable to malloc(%d)\n", FILEBUFF);
	gzclose(gd);
	return CL_EMEM;
    }

    while((bytes = gzread(gd, buff, FILEBUFF)) > 0) {
	size += bytes;

	if(limits)
	    if(limits->maxfilesize && (size + FILEBUFF > limits->maxfilesize)) {
		cli_dbgmsg("Gzip->desc(%d): Size exceeded (stopped at %ld, max: %ld)\n", desc, size, limits->maxfilesize);
		/* ret = CL_EMAXSIZE; */
		break;
	    }

	if(cli_writen(fd, buff, bytes) != bytes) {
	    cli_dbgmsg("Gzip -> Can't write() file.\n");
	    fclose(tmp);
	    gzclose(gd);
	    free(buff);
	    return CL_EGZIP;
	}
    }

    free(buff);
    gzclose(gd);
    if(fsync(fd) == -1) {
	cli_dbgmsg("fsync() failed for descriptor %d\n", fd);
	fclose(tmp);
	return CL_EFSYNC;
    }

    lseek(fd, 0, SEEK_SET);
    if((ret = cli_magic_scandesc(fd, virname, scanned, root, limits, options, reclev)) == CL_VIRUS ) {
	cli_dbgmsg("Gzip -> Found %s virus.\n", *virname);
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

static int cli_scanbzip(int desc, const char **virname, long int *scanned, const struct cl_node *root, const struct cl_limits *limits, int options, int *reclev)
{
	int fd, bytes, ret = CL_CLEAN, bzerror = 0;
	short memlim = 0;
	long int size = 0;
	char *buff;
	FILE *fs, *tmp = NULL;
	BZFILE *bfd;


    if((fs = fdopen(dup(desc), "rb")) == NULL) {
	cli_errmsg("Can't fdopen() descriptor %d.\n", desc);
	return CL_EBZIP;
    }

    if(limits)
	if(limits->archivememlim)
	    memlim = 1;

    if((bfd = BZ2_bzReadOpen(&bzerror, fs, 0, memlim, NULL, 0)) == NULL) {
	cli_dbgmsg("Can't initialize bzip2 library (descriptor %d).\n", desc);
	fclose(fs);
	return CL_EBZIP;
    }

    if((tmp = tmpfile()) == NULL) {
	cli_dbgmsg("Can't generate tmpfile().\n");
	BZ2_bzReadClose(&bzerror, bfd);
	fclose(fs);
	return CL_ETMPFILE;
    }
    fd = fileno(tmp);

    if(!(buff = (char *) malloc(FILEBUFF))) {
	cli_dbgmsg("cli_scanbzip(): unable to malloc(%d)\n", FILEBUFF);
	fclose(tmp);
	fclose(fs);
	BZ2_bzReadClose(&bzerror, bfd);
	return CL_EMEM;
    }

    while((bytes = BZ2_bzRead(&bzerror, bfd, buff, FILEBUFF)) > 0) {
	size += bytes;

	if(limits)
	    if(limits->maxfilesize && (size + FILEBUFF > limits->maxfilesize)) {
		cli_dbgmsg("Bzip2->desc(%d): Size exceeded (stopped at %ld, max: %ld)\n", desc, size, limits->maxfilesize);
		/* ret = CL_EMAXSIZE; */
		break;
	    }

	if(cli_writen(fd, buff, bytes) != bytes) {
	    cli_dbgmsg("Bzip2 -> Can't write() file.\n");
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
	cli_dbgmsg("fsync() failed for descriptor %d\n", fd);
	fclose(tmp);
	fclose(fs);
	return CL_EFSYNC;
    }

    lseek(fd, 0, SEEK_SET);
    if((ret = cli_magic_scandesc(fd, virname, scanned, root, limits, options, reclev)) == CL_VIRUS ) {
	cli_dbgmsg("Bzip2 -> Found %s virus.\n", *virname);
    }
    fclose(tmp);
    fclose(fs);

    return ret;
}
#endif

static int cli_scanole2(int desc, const char **virname, long int *scanned, const struct cl_node *root, const struct cl_limits *limits, int options, int *reclev)
{
	const char *tmpdir;
	char *dir, *fullname;
	unsigned char *data;
	int ret = CL_CLEAN, fd, i, data_len;
	vba_project_t *vba_project;

    cli_dbgmsg("in cli_scanole2()\n");

    tmpdir = getenv("TMPDIR");

    if(tmpdir == NULL)
#ifdef P_tmpdir
	tmpdir = P_tmpdir;
#else
	tmpdir = "/tmp";
#endif

	/* generate the temporary directory */
	dir = cl_gentemp(tmpdir);
	if(mkdir(dir, 0700)) {
	    cli_errmsg("ScanOLE2 -> Can't create temporary directory %s\n", dir);
	    return CL_ETMPDIR;
	}

	if((ret = cli_ole2_extract(desc, dir))) {
	    cli_errmsg("ScanOLE2 -> %s\n", cl_strerror(ret));
	    cli_rmdirs(dir);
	    free(dir);
	    return ret;
	}

	if((vba_project = (vba_project_t *) vba56_dir_read(dir))) {

	    for(i = 0; i < vba_project->count; i++) {
		fullname = (char *) malloc(strlen(vba_project->dir) + strlen(vba_project->name[i]) + 2);
		sprintf(fullname, "%s/%s", vba_project->dir, vba_project->name[i]);
		fd = open(fullname, O_RDONLY);
		if(fd == -1) {
			cli_errmsg("Scan->OLE2 -> Can't open file %s\n", fullname);
			free(fullname);
			ret = CL_EOPEN;
			break;
		}
		free(fullname);
                cli_dbgmsg("decompress VBA project '%s'\n", vba_project->name[i]);
		data = (unsigned char *) vba_decompress(fd, vba_project->offset[i], &data_len);
		close(fd);

		if(!data) {
		    cli_dbgmsg("WARNING: VBA project '%s' decompressed to NULL\n", vba_project->name[i]);
		} else {
		    if(cl_scanbuff(data, data_len, virname, root) == CL_VIRUS) {
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
	}


	cli_rmdirs(dir);
	free(dir);
	return ret;
}
static int cli_scandir(char *dirname, const char **virname, long int *scanned, const struct cl_node *root, const struct cl_limits *limits, int options, int *reclev)
{
	DIR *dd;
	struct dirent *dent;
	struct stat statbuf;
	char *fname;


    if((dd = opendir(dirname)) != NULL) {
	while((dent = readdir(dd))) {
	    if(dent->d_ino) {
		if(strcmp(dent->d_name, ".") && strcmp(dent->d_name, "..")) {
		    /* build the full name */
		    fname = cli_calloc(strlen(dirname) + strlen(dent->d_name) + 2, sizeof(char));
		    sprintf(fname, "%s/%s", dirname, dent->d_name);

		    /* stat the file */
		    if(lstat(fname, &statbuf) != -1) {
			if(S_ISDIR(statbuf.st_mode) && !S_ISLNK(statbuf.st_mode))
			    cli_scandir(fname, virname, scanned, root, limits, options, reclev);
			else
			    if(S_ISREG(statbuf.st_mode))
				if(cli_scanfile(fname, virname, scanned, root, limits, options, reclev) == CL_VIRUS) {
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
	cli_errmsg("ScanDir -> Can't open directory %s.\n", dirname);
	return CL_EOPEN;
    }

    closedir(dd);
    return 0;
}

static int cli_scanmail(int desc, const char **virname, long int *scanned, const struct cl_node *root, const struct cl_limits *limits, int options, int *reclev)
{
	const char *tmpdir;
	char *dir;
	int ret;


    cli_dbgmsg("Starting cli_scanmail(), reclev %d\n", *reclev);

    if(*reclev > 5) /* FIXME: a temporary workaround */
	return CL_CLEAN;

    tmpdir = getenv("TMPDIR");

    if(tmpdir == NULL)
#ifdef P_tmpdir
	tmpdir = P_tmpdir;
#else
	tmpdir = "/tmp";
#endif

	/* generate the temporary directory */
	dir = cl_gentemp(tmpdir);
	if(mkdir(dir, 0700)) {
	    cli_errmsg("ScanMail -> Can't create temporary directory %s\n", dir);
	    return CL_ETMPDIR;
	}

	/*
	 * Extract the attachments into the temporary directory
	 */
	ret = cl_mbox(dir, desc);
	/* FIXME: check mbox return code */

	ret = cli_scandir(dir, virname, scanned, root, limits, options, reclev);

	cli_rmdirs(dir);
	free(dir);

	return ret;
}

static int cli_magic_scandesc(int desc, const char **virname, long int *scanned, const struct cl_node *root, const struct cl_limits *limits, int options, int *reclev)
{
	char magic[MAGIC_BUFFER_SIZE+1];
	int ret = CL_CLEAN;
	int bread = 0;
	cli_file_t type;


    if(!root) {
	cli_errmsg("root == NULL\n");
	return -1;
    }


    if(SCAN_ARCHIVE || SCAN_MAIL) {
        /* Need to examine file type */

	if(SCAN_ARCHIVE && limits && limits->maxreclevel)
	    if(*reclev > limits->maxreclevel)
		/* return CL_EMAXREC; */
		return CL_CLEAN;

	(*reclev)++;


	lseek(desc, 0, SEEK_SET);
	bread = read(desc, magic, MAGIC_BUFFER_SIZE);
	magic[MAGIC_BUFFER_SIZE] = '\0';	/* terminate magic string properly */
	lseek(desc, 0, SEEK_SET);


	if (bread != MAGIC_BUFFER_SIZE) {
	    /* short read: No need to do magic */
	    (*reclev)--;
	    return ret;
	}

	type = cli_filetype(magic, bread);

	switch(type) {
	    case CL_RARFILE:
		if(!DISABLE_RAR && SCAN_ARCHIVE && !cli_scanrar_inuse) {
		    ret = cli_scanrar(desc, virname, scanned, root, limits, options, reclev);
		}
		break;

	    case CL_ZIPFILE:
		if(SCAN_ARCHIVE) {
		    ret = cli_scanzip(desc, virname, scanned, root, limits, options, reclev);
		}
		break;

	    case CL_GZFILE:
		if(SCAN_ARCHIVE) {
		    ret = cli_scangzip(desc, virname, scanned, root, limits, options, reclev);
		}
		break;

	    case CL_BZFILE:
#ifdef HAVE_BZLIB_H
		if(SCAN_ARCHIVE) {
		    ret = cli_scanbzip(desc, virname, scanned, root, limits, options, reclev);
		}
#endif
		break;

	    case CL_MAILFILE:
		if (SCAN_MAIL) {
		    ret = cli_scanmail(desc, virname, scanned, root, limits, options, reclev);
		}
		break;

	    case CL_OLE2FILE:
		if(SCAN_OLE2) {
		    ret = cli_scanole2(desc, virname, scanned, root, limits, options, reclev);
		}
            case CL_UNKNOWN_TYPE:
		break;
	}

	(*reclev)--;
    }

    if(ret != CL_VIRUS) { /* scan the raw file */
	lseek(desc, 0, SEEK_SET); /* If archive scan didn't rewind desc */
	if(cli_scandesc(desc, virname, scanned, root) == CL_VIRUS) {
	    cli_dbgmsg("%s virus found in descriptor %d.\n", *virname, desc);
	    return CL_VIRUS;
	}
    }

    return ret;
}

int cl_scandesc(int desc, const char **virname, unsigned long int *scanned, const struct cl_node *root, const struct cl_limits *limits, int options)
{
	int reclev = 0;

    return cli_magic_scandesc(desc, virname, scanned, root, limits, options, &reclev);
}

static int cli_scanfile(const char *filename, const char **virname, unsigned long int *scanned, const struct cl_node *root, const struct cl_limits *limits, int options, int *reclev)
{
	int fd, ret;

    /* internal version of cl_scanfile with reclev preserved */

    if((fd = open(filename, O_RDONLY)) == -1)
	return CL_EOPEN;

    ret = cli_magic_scandesc(fd, virname, scanned, root, limits, options, reclev);

    close(fd);
    return ret;
}

int cl_scanfile(const char *filename, const char **virname, unsigned long int *scanned, const struct cl_node *root, const struct cl_limits *limits, int options)
{
	int fd, ret;

    if((fd = open(filename, O_RDONLY)) == -1)
	return CL_EOPEN;

    ret = cl_scandesc(fd, virname, scanned, root, limits, options);
    close(fd);

    return ret;
}

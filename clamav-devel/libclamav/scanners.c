/*
 *  Copyright (C) 2002, 2003 Tomasz Kojm <zolw@konarski.edu.pl>
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
int cli_scanrar_inuse = 0;
//pthread_mutex_t cli_mbox_mutex = PTHREAD_MUTEX_INITIALIZER;
//int cli_mbox_inuse = 0;
#endif

#include "clamav.h"
#include "others.h"
#include "matcher.h"
#include "unrarlib.h"

#ifdef HAVE_ZLIB_H
#include <zlib.h>
#include <zzip.h>
#endif

#ifdef HAVE_BZLIB_H
#include <bzlib.h>
#endif

#define SCAN_ARCHIVE	(options & CL_ARCHIVE)
#define SCAN_MAIL	(options & CL_MAIL)
#define DISABLE_RAR	(options & CL_DISABLERAR)

#define MAGIC_BUFFER_SIZE 14
#define RAR_MAGIC_STR "Rar!"
#define ZIP_MAGIC_STR "PK\003\004"
#define GZIP_MAGIC_STR "\037\213"
#define MAIL_MAGIC_STR "From "
#define RAWMAIL_MAGIC_STR "Received: "
#define MAILDIR_MAGIC_STR "Return-Path: "
#define DELIVERED_MAGIC_STR "Delivered-To: "
#define BZIP_MAGIC_STR "BZh"


int cli_magic_scandesc(int desc, char **virname, long int *scanned, const struct cl_node *root, const struct cl_limits *limits, int options, int *reclev);

int cli_scandesc(int desc, char **virname, long int *scanned, const struct 
cl_node *root)
{
 	char *buffer, *buff, *endbl, *pt;
	int bytes, buffsize, length;


    /* prepare the buffer */
    buffsize = root->maxpatlen + BUFFSIZE;
    if(!(buffer = (char *) cli_calloc(buffsize, sizeof(char))))
	return CL_EMEM;

    buff = buffer;
    buff += root->maxpatlen; /* pointer to read data block */
    endbl = buff + BUFFSIZE - root->maxpatlen; /* pointer to the last block
						* length of root->maxpatlen
						*/

    pt= buff;
    length = BUFFSIZE;

    while((bytes = read(desc, buff, BUFFSIZE)) > 0) {

	if(scanned != NULL)
	    *scanned += bytes / CL_COUNT_PRECISION;

	if(bytes < BUFFSIZE)
	    length -= BUFFSIZE - bytes;

	if(cl_scanbuff(pt, length, virname, root) == CL_VIRUS) {
	    free(buffer);
	    return CL_VIRUS;
	}

	if(bytes == BUFFSIZE)
	    memmove(buffer, endbl, root->maxpatlen);

        pt = buffer;
        length=buffsize;

    }

    free(buffer);
    return CL_CLEAN;
}

#ifdef CL_THREAD_SAFE
void cli_unlock_mutex(void *mtx)
{
    cli_dbgmsg("Pthread cancelled. Unlocking mutex.\n");
    pthread_mutex_unlock(mtx);
}
#endif

int cli_scanrar(int desc, char **virname, long int *scanned, const struct cl_node *root, const struct cl_limits *limits, int options, int *reclev)
{
	FILE *tmp;
	int files = 0, fd, ret = CL_CLEAN;
	ArchiveList_struct *rarlist = NULL;
	char *rar_data_ptr;
	unsigned long rar_data_size;

    cli_dbgmsg("Starting scanrar()\n");


#ifdef CL_THREAD_SAFE
    pthread_cleanup_push(cli_unlock_mutex, &cli_scanrar_mutex);
    pthread_mutex_lock(&cli_scanrar_mutex);
    cli_scanrar_inuse = 1;
#endif

    if(!urarlib_list(desc, (ArchiveList_struct *) &rarlist)) {
#ifdef CL_THREAD_SAFE
	pthread_mutex_unlock(&cli_scanrar_mutex);
	cli_scanrar_inuse = 0;
#endif
	return CL_ERAR;
    }

    while(rarlist) {

	if(limits) {
	    if(limits->maxfilesize && (rarlist->item.UnpSize > limits->maxfilesize)) {
		cli_dbgmsg("RAR->%s: Size exceeded (%d, max: %d)\n", rarlist->item.Name, rarlist->item.UnpSize, limits->maxfilesize);
		rarlist = rarlist->next;
		files++;
		ret = CL_EMAXSIZE;
		continue;
	    }

	    if(limits->maxfiles && (files > limits->maxfiles)) {
		cli_dbgmsg("RAR: Files limit reached (max: %d)\n", limits->maxfiles);
		ret = CL_EMAXFILES;
		break;
	    }
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

	if(urarlib_get(&rar_data_ptr, &rar_data_size, rarlist->item.Name, desc, "clam")) {
	    cli_dbgmsg("RAR -> Extracted: %s, size: %d\n", rarlist->item.Name, rar_data_size);
	    if(fwrite(rar_data_ptr, rar_data_size, 1, tmp) != 1) {
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
		urarlib_freelist(rarlist);
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
		return CL_VIRUS;
	    }

	} else {
	    cli_dbgmsg("RAR -> Can't decompress file %s\n", rarlist->item.Name);
	    fclose(tmp);
	    ret = CL_ERAR; /* WinRAR 3.0 ? */
	    break;
	}

	fclose(tmp);
	tmp = NULL;
	rarlist = rarlist->next;
	files++;
    }

    urarlib_freelist(rarlist);
#ifdef CL_THREAD_SAFE
    pthread_mutex_unlock(&cli_scanrar_mutex);
    cli_scanrar_inuse = 0;
    pthread_cleanup_pop(0);
#endif
    return ret;
}

#ifdef HAVE_ZLIB_H
int cli_scanzip(int desc, char **virname, long int *scanned, const struct cl_node *root, const struct cl_limits *limits, int options, int *reclev)
{
	ZZIP_DIR *zdir;
	ZZIP_DIRENT zdirent;
	ZZIP_FILE *zfp;
	FILE *tmp;
	char buff[BUFFSIZE];
	int fd, bytes, files = 0, ret = CL_CLEAN, err;


    cli_dbgmsg("Starting scanzip()\n");

    if((zdir = zzip_dir_fdopen(dup(desc), &err)) == NULL) {
	cli_dbgmsg("Zip -> Not supported file format ?.\n");
	cli_dbgmsg("zzip_dir_fdopen() return code: %d\n", err);
	return CL_EZIP;
    }

    while(zzip_dir_read(zdir, &zdirent)) {
	cli_dbgmsg("Zip -> %s, compressed: %d, normal: %d.\n", zdirent.d_name, zdirent.d_csize, zdirent.st_size);

	if(!zdirent.st_size) { /* omit directories and null files */
	    files++;
	    continue;
	}

	/* work-around for problematic zips (zziplib crashes with them) */
	if(zdirent.d_csize < 0 || zdirent.st_size < 0) {
	    files++;
	    cli_dbgmsg("Zip -> Malformed archive detected.\n");
	    ret = CL_EMALFZIP;
	    break;
	}

	if(limits) {
	    if(limits->maxfilesize && (zdirent.st_size > limits->maxfilesize)) {
		cli_dbgmsg("Zip -> %s: Size exceeded (%d, max: %d)\n", zdirent.d_name, zdirent.st_size, limits->maxfilesize);
		files++;
		ret = CL_EMAXSIZE;
		continue;
	    }

	    if(limits->maxfiles && (files > limits->maxfiles)) {
		cli_dbgmsg("Zip: Files limit reached (max: %d)\n", limits->maxfiles);
		ret = CL_EMAXFILES;
		break;
	    }
	}

	/* generate temporary file and get its descriptor */
	if((tmp = tmpfile()) == NULL) {
	    cli_dbgmsg("Zip -> Can't generate tmpfile().\n");
	    zzip_dir_close(zdir);
	    return CL_ETMPFILE;
	}

	if((zfp = zzip_file_open(zdir, zdirent.d_name, 0)) == NULL) {
	    cli_dbgmsg("Zip -> %s: Can't open file.\n", zdirent.d_name);
	    ret = CL_EZIP;
	    continue;
	}

	while((bytes = zzip_file_read(zfp, buff, BUFFSIZE)) > 0) {
	    if(fwrite(buff, bytes, 1, tmp)*bytes != bytes) {
		cli_dbgmsg("Zip -> Can't fwrite() file: %s\n", strerror(errno));
		zzip_file_close(zfp);
		zzip_dir_close(zdir);
		files++;
		fclose(tmp);
		return CL_EZIP;
	    }
	}

	zzip_file_close(zfp);

	if(fflush(tmp) != 0) {
	    cli_errmsg("fflush() failed: %s\n", strerror(errno));
	    zzip_dir_close(zdir);
	    fclose(tmp);
	    return CL_EFSYNC;
	}

	fd = fileno(tmp);

	lseek(fd, 0, SEEK_SET);
	if((ret = cli_magic_scandesc(fd, virname, scanned, root, limits, options, reclev)) == CL_VIRUS ) {
	    cli_dbgmsg("Zip -> Found %s virus.\n", *virname);
	    fclose(tmp);
	    tmp = NULL;
	    ret = CL_VIRUS;
	    break;
	} else if(ret == CL_EMALFZIP) {
	    /* 
	     * The trick with detection of ZoD works with higher (>= 5)
	     * recursion limit level.
	     */
	    cli_dbgmsg("Zip -> Malformed Zip, scanning stopped.\n");
	    fclose(tmp);
	    tmp = NULL;
	    *virname = "Malformed Zip";
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
    return ret;
}

int cli_scangzip(int desc, char **virname, long int *scanned, const struct cl_node *root, const struct cl_limits *limits, int options, int *reclev)
{
	int fd, bytes, ret = CL_CLEAN;
	long int size = 0;
	char buff[BUFFSIZE];
	FILE *tmp;
	gzFile gd;


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

    while((bytes = gzread(gd, buff, BUFFSIZE)) > 0) {
	size += bytes;

	if(limits)
	    if(limits->maxfilesize && (size + BUFFSIZE > limits->maxfilesize)) {
		cli_dbgmsg("Gzip->desc(%d): Size exceeded (stopped at %d, max: %d)\n", desc, size, limits->maxfilesize);
		ret = CL_EMAXSIZE;
		break;
	    }

	if(write(fd, buff, bytes) != bytes) {
	    cli_dbgmsg("Gzip -> Can't write() file.\n");
	    fclose(tmp);
	    gzclose(gd);
	    return CL_EGZIP;
	}
    }

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

int cli_scanbzip(int desc, char **virname, long int *scanned, const struct cl_node *root, const struct cl_limits *limits, int options, int *reclev)
{
	int fd, bytes, ret = CL_CLEAN, bzerror = 0;
	short memlim = 0;
	long int size = 0;
	char buff[BUFFSIZE];
	FILE *fs, *tmp;
	BZFILE *bfd;


    if((fs = fdopen(desc, "rb")) == NULL) {
	cli_errmsg("Can't fdopen() descriptor %d.\n", desc);
	return CL_EBZIP;
    }

    if(limits)
	if(limits->archivememlim)
	    memlim = 1;

    if((bfd = BZ2_bzReadOpen(&bzerror, fs, memlim, 0, NULL, 0)) == NULL) {
	cli_dbgmsg("Can't initialize bzip2 library (descriptor %d).\n", desc);
	return CL_EBZIP;
    }

    if((tmp = tmpfile()) == NULL) {
	cli_dbgmsg("Can't generate tmpfile().\n");
	BZ2_bzReadClose(&bzerror, bfd);
	return CL_ETMPFILE;
    }
    fd = fileno(tmp);

    while((bytes = BZ2_bzRead(&bzerror, bfd, buff, BUFFSIZE)) > 0) {
	size += bytes;

	if(limits)
	    if(limits->maxfilesize && (size + BUFFSIZE > limits->maxfilesize)) {
		cli_dbgmsg("Bzip2->desc(%d): Size exceeded (stopped at %d, max: %d)\n", desc, size, limits->maxfilesize);
		ret = CL_EMAXSIZE;
		break;
	    }

	if(write(fd, buff, bytes) != bytes) {
	    cli_dbgmsg("Bzip2 -> Can't write() file.\n");
	    BZ2_bzReadClose(&bzerror, bfd);
	    fclose(tmp);
	    return CL_EGZIP;
	}
    }

    BZ2_bzReadClose(&bzerror, bfd);
    if(fsync(fd) == -1) {
	cli_dbgmsg("fsync() failed for descriptor %d\n", fd);
	fclose(tmp);
	return CL_EFSYNC;
    }

    lseek(fd, 0, SEEK_SET);
    if((ret = cli_magic_scandesc(fd, virname, scanned, root, limits, options, reclev)) == CL_VIRUS ) {
	cli_dbgmsg("Bzip2 -> Found %s virus.\n", *virname);
	fclose(tmp);
	return CL_VIRUS;
    }
    fclose(tmp);

    return ret;
}
#endif

int cli_scandir(char *dirname, char **virname, long int *scanned, const struct cl_node *root, const struct cl_limits *limits, int options, int *reclev)
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
			    cli_scandir(dirname, virname, scanned, root, limits, options, reclev);
			else
			    if(S_ISREG(statbuf.st_mode))
				if(cl_scanfile(fname, virname, scanned, root, limits, options) == CL_VIRUS) {
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

int cli_scanmail(int desc, char **virname, long int *scanned, const struct cl_node *root, const struct cl_limits *limits, int options, int *reclev)
{
	const char *tmpdir;
	char *dir;
	int ret;


    cli_dbgmsg("Starting scanmail()\n");

/*
#ifdef CL_THREAD_SAFE
    pthread_cleanup_push(cli_unlock_mutex, &cli_mbox_mutex);
    pthread_mutex_lock(&cli_mbox_mutex);
    cli_mbox_inuse = 1;
#endif
*/
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
/*
#ifdef CL_THREAD_SAFE
	    pthread_mutex_unlock(&cli_mbox_mutex);
	    cli_mbox_inuse = 0;
#endif
*/
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

/*
#ifdef CL_THREAD_SAFE
	pthread_mutex_unlock(&cli_mbox_mutex);
        cli_mbox_inuse = 0;
	pthread_cleanup_pop(0);
#endif
*/

	return ret;
}

int cli_magic_scandesc(int desc, char **virname, long int *scanned, const struct cl_node *root, const struct cl_limits *limits, int options, int *reclev)
{
	char magic[MAGIC_BUFFER_SIZE+1];
	int ret = CL_CLEAN;
	int bread = 0;


    if(!root) {
	cli_errmsg("root == NULL\n");
	return -1;
    }

    if(SCAN_ARCHIVE || SCAN_MAIL) {
        /* Need to examine file type */

	if(limits && limits->maxreclevel)
	    if(*reclev > limits->maxreclevel)
		return CL_EMAXREC;

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
#ifdef CL_THREAD_SAFE
	/* this check protects against recursive deadlock */
	if(!DISABLE_RAR && SCAN_ARCHIVE && !cli_scanrar_inuse && !strncmp(magic, RAR_MAGIC_STR, strlen(RAR_MAGIC_STR))) {
	    ret = cli_scanrar(desc, virname, scanned, root, limits, options, reclev);
	}
#else
	if(!DISABLE_RAR && SCAN_ARCHIVE && !strncmp(magic, RAR_MAGIC_STR, strlen(RAR_MAGIC_STR))) {
	    ret = cli_scanrar(desc, virname, scanned, root, limits, options, reclev);
	}
#endif
#ifdef HAVE_ZLIB_H
	else if(SCAN_ARCHIVE && !strncmp(magic, ZIP_MAGIC_STR, strlen(ZIP_MAGIC_STR))) {
	    ret = cli_scanzip(desc, virname, scanned, root, limits, options, reclev);
	} else if(SCAN_ARCHIVE && !strncmp(magic, GZIP_MAGIC_STR, strlen(GZIP_MAGIC_STR))) {
	    ret = cli_scangzip(desc, virname, scanned, root, limits, options, reclev);
	}
#endif
#ifdef HAVE_BZLIB_H
	else if(SCAN_ARCHIVE && !strncmp(magic, BZIP_MAGIC_STR, strlen(BZIP_MAGIC_STR))) {
	    ret = cli_scanbzip(desc, virname, scanned, root, limits, options, reclev);
	}
#endif
	else if(SCAN_MAIL && !strncmp(magic, MAIL_MAGIC_STR, strlen(MAIL_MAGIC_STR))) {
	    ret = cli_scanmail(desc, virname, scanned, root, limits, options, reclev);
	}
	else if(SCAN_MAIL && !strncmp(magic, RAWMAIL_MAGIC_STR, strlen(RAWMAIL_MAGIC_STR))) {
	    ret = cli_scanmail(desc, virname, scanned, root, limits, options, reclev);
	} else if(SCAN_MAIL && !strncmp(magic, MAILDIR_MAGIC_STR, strlen(MAILDIR_MAGIC_STR))) {
	    cli_dbgmsg("Recognized Maildir mail file.\n");
	    ret = cli_scanmail(desc, virname, scanned, root, limits, options, reclev);
	} else if(SCAN_MAIL && !strncmp(magic, DELIVERED_MAGIC_STR, strlen(DELIVERED_MAGIC_STR))) {
	    cli_dbgmsg("Recognized (Delivered-To) mail file.\n");
	    ret = cli_scanmail(desc, virname, scanned, root, limits, options, reclev);
	}
	(*reclev)--;
    }

    if(ret != CL_VIRUS) /* scan the raw file */
	lseek(desc, 0, SEEK_SET); /* If archive scan didn't rewind desc */
	if(cli_scandesc(desc, virname, scanned, root) == CL_VIRUS) {
	    cli_dbgmsg("%s virus found in descriptor %d.\n", *virname, desc);
	    return CL_VIRUS;
	}

    return ret;
}

int cl_scandesc(int desc, char **virname, unsigned long int *scanned, const struct cl_node *root, const struct cl_limits *limits, int options)
{
	int reclev = 0;

    return cli_magic_scandesc(desc, virname, scanned, root, limits, options, &reclev);
}

int cl_scanfile(const char *filename, char **virname, unsigned long int *scanned, const struct cl_node *root, const struct cl_limits *limits, int options)
{
	int fd, ret;

    if((fd = open(filename, O_RDONLY)) == -1)
	return CL_EOPEN;

    cli_dbgmsg("Scanning %s\n", filename);
    ret = cl_scandesc(fd, virname, scanned, root, limits, options);
    close(fd);

    return ret;
}

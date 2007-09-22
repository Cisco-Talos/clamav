/*
 *  Copyright (C) 2003 - 2006 Tomasz Kojm <tkojm@clamav.net>
 *
 *  untgz() is based on public domain minitar utility by Charles G. Waldman
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
#include <fcntl.h>
#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif
#include "zlib.h"
#include <time.h>
#include <errno.h>

#include "clamav.h"
#include "others.h"
#include "dsig.h"
#include "str.h"
#include "cvd.h"

#define TAR_BLOCKSIZE 512

int cli_untgz(int fd, const char *destdir)
{
	char *path, osize[13], name[101], type;
	char block[TAR_BLOCKSIZE];
	int nbytes, nread, nwritten, in_block = 0, fdd;
	unsigned int size, pathlen = strlen(destdir) + 100 + 5;
	FILE *outfile = NULL;
	gzFile *infile;


    cli_dbgmsg("in cli_untgz()\n");

    if((fdd = dup(fd)) == -1) {
	cli_errmsg("cli_untgz: Can't duplicate descriptor %d\n", fd);
	return -1;
    }

    if((infile = gzdopen(fdd, "rb")) == NULL) {
	cli_errmsg("cli_untgz: Can't gzdopen() descriptor %d, errno = %d\n", fdd, errno);
	return -1;
    }

    path = (char *) cli_calloc(sizeof(char), pathlen);
    if(!path) {
	cli_errmsg("cli_untgz: Can't allocate memory for path\n");
	return -1;
    }

    while(1) {

	nread = gzread(infile, block, TAR_BLOCKSIZE);

	if(!in_block && !nread)
	    break;

	if(nread != TAR_BLOCKSIZE) {
	    cli_errmsg("cli_untgz: Incomplete block read\n");
	    free(path);
	    gzclose(infile);
	    return -1;
	}

	if(!in_block) {
	    if (block[0] == '\0')  /* We're done */
		break;

	    strncpy(name, block, 100);
	    name[100] = '\0';

	    if(strchr(name, '/')) {
		cli_errmsg("cli_untgz: Slash separators are not allowed in CVD\n");
		free(path);
	        gzclose(infile);
		return -1;
	    }

	    snprintf(path, pathlen, "%s/%s", destdir, name);
	    cli_dbgmsg("cli_untgz: Unpacking %s\n", path);
	    type = block[156];

	    switch(type) {
		case '0':
		case '\0':
		    break;
		case '5':
		    cli_errmsg("cli_untgz: Directories are not supported in CVD\n");
		    free(path);
	            gzclose(infile);
		    return -1;
		default:
		    cli_errmsg("cli_untgz: Unknown type flag '%c'\n", type);
		    free(path);
	            gzclose(infile);
		    return -1;
	    }
	    in_block = 1;

	    if(outfile) {
		if(fclose(outfile)) {
		    cli_errmsg("cli_untgz: Cannot close file %s\n", path);
		    free(path);
	            gzclose(infile);
		    return -1;
		}
		outfile = NULL;
	    }

	    if(!(outfile = fopen(path, "wb"))) {
		cli_errmsg("cli_untgz: Cannot create file %s\n", path);
		free(path);
	        gzclose(infile);
		return -1;
	    }

	    strncpy(osize, block + 124, 12);
	    osize[12] = '\0';

	    if((sscanf(osize, "%o", &size)) == 0) {
		cli_errmsg("cli_untgz: Invalid size in header\n");
		free(path);
	        gzclose(infile);
		fclose(outfile);
		return -1;
	    }

	} else { /* write or continue writing file contents */
	    nbytes = size > TAR_BLOCKSIZE ? TAR_BLOCKSIZE : size;
	    nwritten = fwrite(block, 1, nbytes, outfile);

	    if(nwritten != nbytes) {
		cli_errmsg("cli_untgz: Wrote %d instead of %d (%s)\n", nwritten, nbytes, path);
		free(path);
	        gzclose(infile);
		return -1;
	    }

	    size -= nbytes;
	    if(size == 0)
		in_block = 0;
	}
    }

    if(outfile)
	fclose(outfile);

    gzclose(infile);
    free(path);
    return 0;
}

struct cl_cvd *cl_cvdparse(const char *head)
{
	struct cl_cvd *cvd;
	char *pt;


    if(strncmp(head, "ClamAV-VDB:", 11)) {
	cli_errmsg("cli_cvdparse: Not a CVD file\n");
	return NULL;
    }

    if(!(cvd = (struct cl_cvd *) cli_malloc(sizeof(struct cl_cvd)))) {
	cli_errmsg("cl_cvdparse: Can't allocate memory for cvd\n");
	return NULL;
    }

    if(!(cvd->time = cli_strtok(head, 1, ":"))) {
	cli_errmsg("cli_cvdparse: Can't parse the creation time\n");
	free(cvd);
	return NULL;
    }

    if(!(pt = cli_strtok(head, 2, ":"))) {
	cli_errmsg("cli_cvdparse: Can't parse the version number\n");
	free(cvd->time);
	free(cvd);
	return NULL;
    }
    cvd->version = atoi(pt);
    free(pt);

    if(!(pt = cli_strtok(head, 3, ":"))) {
	cli_errmsg("cli_cvdparse: Can't parse the number of signatures\n");
	free(cvd->time);
	free(cvd);
	return NULL;
    }
    cvd->sigs = atoi(pt);
    free(pt);

    if(!(pt = cli_strtok(head, 4, ":"))) {
	cli_errmsg("cli_cvdparse: Can't parse the functionality level\n");
	free(cvd->time);
	free(cvd);
	return NULL;
    }
    cvd->fl = atoi(pt);
    free(pt);

    if(!(cvd->md5 = cli_strtok(head, 5, ":"))) {
	cli_errmsg("cli_cvdparse: Can't parse the MD5 checksum\n");
	free(cvd->time);
	free(cvd);
	return NULL;
    }

    if(!(cvd->dsig = cli_strtok(head, 6, ":"))) {
	cli_errmsg("cli_cvdparse: Can't parse the digital signature\n");
	free(cvd->time);
	free(cvd->md5);
	free(cvd);
	return NULL;
    }

    if(!(cvd->builder = cli_strtok(head, 7, ":"))) {
	cli_errmsg("cli_cvdparse: Can't parse the builder name\n");
	free(cvd->time);
	free(cvd->md5);
	free(cvd->dsig);
	free(cvd);
	return NULL;
    }

    if((pt = cli_strtok(head, 8, ":"))) {
	cvd->stime = atoi(pt);
	free(pt);
    } else {
	cli_dbgmsg("cli_cvdparse: No creation time in seconds (old file format)\n");
	cvd->stime = 0;
    }

    return cvd;
}

struct cl_cvd *cl_cvdhead(const char *file)
{
	FILE *fs;
	char head[513], *pt;
	int i;
	unsigned int bread;


    if((fs = fopen(file, "rb")) == NULL) {
	cli_errmsg("cl_cvdhead: Can't open file %s\n", file);
	return NULL;
    }

    if(!(bread = fread(head, 1, 512, fs))) {
	cli_errmsg("cl_cvdhead: Can't read CVD header in %s\n", file);
	fclose(fs);
	return NULL;
    }

    fclose(fs);

    head[bread] = 0;
    if((pt = strpbrk(head, "\n\r")))
	*pt = 0;
    
    for(i = bread - 1; i > 0 && (head[i] == ' ' || head[i] == '\n' || head[i] == '\r'); head[i] = 0, i--);

    return cl_cvdparse(head);
}

void cl_cvdfree(struct cl_cvd *cvd)
{
    free(cvd->time);
    free(cvd->md5);
    free(cvd->dsig);
    free(cvd->builder);
    free(cvd);
}

static int cli_cvdverify(FILE *fs, struct cl_cvd *cvdpt)
{
	struct cl_cvd *cvd;
	char *md5, head[513];
	int i;


    fseek(fs, 0, SEEK_SET);
    if(fread(head, 1, 512, fs) != 512) {
	cli_errmsg("cli_cvdverify: Can't read CVD header\n");
	return CL_ECVD;
    }

    head[512] = 0;
    for(i = 511; i > 0 && (head[i] == ' ' || head[i] == 10); head[i] = 0, i--);

    if((cvd = cl_cvdparse(head)) == NULL)
	return CL_ECVD;

    if(cvdpt)
	memcpy(cvdpt, cvd, sizeof(struct cl_cvd));

    md5 = cli_md5stream(fs, NULL);
    cli_dbgmsg("MD5(.tar.gz) = %s\n", md5);

    if(strncmp(md5, cvd->md5, 32)) {
	cli_dbgmsg("cli_cvdverify: MD5 verification error\n");
	free(md5);
	cl_cvdfree(cvd);
	return CL_EMD5;
    }

#ifdef HAVE_GMP
    if(cli_versig(md5, cvd->dsig)) {
	cli_dbgmsg("cli_cvdverify: Digital signature verification error\n");
	free(md5);
	cl_cvdfree(cvd);
	return CL_EDSIG;
    }
#endif

    free(md5);
    cl_cvdfree(cvd);
    return 0;
}

int cl_cvdverify(const char *file)
{
	FILE *fs;
	int ret;


    if((fs = fopen(file, "rb")) == NULL) {
	cli_errmsg("cl_cvdverify: Can't open file %s\n", file);
	return CL_EOPEN;
    }

    ret = cli_cvdverify(fs, NULL);
    fclose(fs);

    return ret;
}

int cli_cvdload(FILE *fs, struct cl_engine **engine, unsigned int *signo, short warn, unsigned int options)
{
        char *dir;
	struct cl_cvd cvd;
	int ret;
	time_t s_time;
	int cfd;

    cli_dbgmsg("in cli_cvdload()\n");

    /* verify */

    if((ret = cli_cvdverify(fs, &cvd)))
	return ret;

    if(cvd.stime && warn) {
	time(&s_time);
	if((int) s_time - cvd.stime > 604800) {
	    cli_warnmsg("**************************************************\n");
	    cli_warnmsg("***  The virus database is older than 7 days!  ***\n");
	    cli_warnmsg("***   Please update it as soon as possible.    ***\n");
	    cli_warnmsg("**************************************************\n");
	}
    }

    if(cvd.fl > cl_retflevel()) {
	cli_warnmsg("***********************************************************\n");
	cli_warnmsg("***  This version of the ClamAV engine is outdated.     ***\n");
	cli_warnmsg("*** DON'T PANIC! Read http://www.clamav.net/support/faq ***\n");
	cli_warnmsg("***********************************************************\n");
    }

    dir = cli_gentemp(NULL);
    if(mkdir(dir, 0700)) {
	cli_errmsg("cli_cvdload(): Can't create temporary directory %s\n", dir);
	free(dir);
	return CL_ETMPDIR;
    }

    cfd = fileno(fs);

    /* use only operations on file descriptors, and not on the FILE* from here on 
     * if we seek the FILE*, the underlying descriptor may not seek as expected
     * (for example on OpenBSD, cygwin, etc.).
     * So seek the descriptor directly.
     */ 

    if(lseek(cfd, 512, SEEK_SET) == -1) {
	cli_errmsg("cli_cvdload(): lseek(fs, 512, SEEK_SET) failed\n");
	return CL_EIO;
    }

    if(cli_untgz(cfd, dir)) {
	cli_errmsg("cli_cvdload(): Can't unpack CVD file.\n");
	free(dir);
	return CL_ECVDEXTR;
    }

    /* load extracted directory */
    ret = cl_load(dir, engine, signo, options);

    cli_rmdirs(dir);
    free(dir);

    return ret;
}

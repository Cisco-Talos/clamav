/*
 *  Copyright (C) 2003 - 2005 Tomasz Kojm <tkojm@clamav.net>
 *
 *  untgz() is based on public domain minitar utility by Charles G. Waldman
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <zlib.h>
#include <time.h>

#include "clamav.h"
#include "others.h"
#include "dsig.h"
#include "str.h"

#define TAR_BLOCKSIZE 512

int cli_untgz(int fd, const char *destdir)
{
	char *fullname, osize[13], name[101], type;
	char block[TAR_BLOCKSIZE];
	int nbytes, nread, nwritten, in_block = 0;
	unsigned int size;
	FILE *outfile = NULL;
	gzFile *infile;

    cli_dbgmsg("in cli_untgz()\n");

    if((infile = gzdopen(fd, "rb")) == NULL) {
	cli_errmsg("Can't gzdopen() descriptor %d\n", fd);
	return -1;
    }


    fullname = (char *) calloc(sizeof(char), strlen(destdir) + 100 + 5);

    while(1) {

	nread = gzread(infile, block, TAR_BLOCKSIZE);

	if(!in_block && nread == 0)
	    break;

	if(nread != TAR_BLOCKSIZE) {
	    cli_errmsg("Incomplete block read.\n");
	    free(fullname);
	    gzclose(infile);
	    return -1;
	}

	if(!in_block) {
	    if (block[0] == '\0')  /* We're done */
		break;

	    strncpy(name, block, 100);
	    name[100] = '\0';

	    if(strchr(name, '/')) {
		cli_errmsg("Slash separators are not allowed in CVD.\n");
		free(fullname);
	        gzclose(infile);
		return -1;
	    }

	    strcpy(fullname, destdir);
	    strcat(fullname, "/");
	    strcat(fullname, name);
	    cli_dbgmsg("Unpacking %s\n",fullname);
	    type = block[156];

	    switch(type) {
		case '0':
		case '\0':
		    break;
		case '5':
		    cli_errmsg("Directories in CVD are not supported.\n");
		    free(fullname);
	            gzclose(infile);
		    return -1;
		default:
		    cli_errmsg("Unknown type flag %c.\n",type);
		    free(fullname);
	            gzclose(infile);
		    return -1;
	    }

	    in_block = 1;

	    if(outfile) {
		if(fclose(outfile)) {
		    cli_errmsg("Cannot close file %s.\n", fullname);
		    free(fullname);
	            gzclose(infile);
		    return -1;
		}
		outfile = NULL;
	    }

	    if(!(outfile = fopen(fullname, "wb"))) {
		cli_errmsg("Cannot create file %s.\n", fullname);
		free(fullname);
	        gzclose(infile);
		return -1;
	    }

	    strncpy(osize, block + 124, 12);
	    osize[12] = '\0';

	    if((sscanf(osize, "%o", &size)) == 0) {
		cli_errmsg("Invalid size in header.\n");
		free(fullname);
	        gzclose(infile);
		fclose(outfile);
		return -1;
	    }

	} else { /* write or continue writing file contents */
	    nbytes = size > TAR_BLOCKSIZE ? TAR_BLOCKSIZE : size;
	    nwritten = fwrite(block, 1, nbytes, outfile);

	    if(nwritten != nbytes) {
		cli_errmsg("Wrote %d instead of %d (%s).\n", nwritten, nbytes, fullname);
		free(fullname);
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
    free(fullname);
    return 0;
}

struct cl_cvd *cl_cvdparse(const char *head)
{
	char *pt;
	struct cl_cvd *cvd;

    if(strncmp(head, "ClamAV-VDB:", 11)) {
	cli_dbgmsg("Not a CVD head.\n");
	return NULL;
    }

    cvd = (struct cl_cvd *) cli_calloc(1, sizeof(struct cl_cvd));

    if(!(cvd->time = cli_strtok(head, 1, ":"))) {
	cli_errmsg("CVD -> Can't extract time from header.\n");
	free(cvd);
	return NULL;
    }

    if(!(pt = cli_strtok(head, 2, ":"))) {
	cli_errmsg("CVD -> Can't extract version from header.\n");
	free(cvd->time);
	free(cvd);
	return NULL;
    }
    cvd->version = atoi(pt);
    free(pt);

    if(!(pt = cli_strtok(head, 3, ":"))) {
	cli_errmsg("CVD -> Can't extract signature number from header.\n");
	free(cvd->time);
	free(cvd);
	return NULL;
    }
    cvd->sigs = atoi(pt);
    free(pt);

    if(!(pt = cli_strtok(head, 4, ":"))) {
	cli_errmsg("CVD -> Can't extract functionality level from header.\n");
	free(cvd->time);
	free(cvd);
	return NULL;
    }
    cvd->fl = (short int) atoi(pt);
    free(pt);

    if(!(cvd->md5 = cli_strtok(head, 5, ":"))) {
	cli_errmsg("CVD -> Can't extract MD5 checksum from header.\n");
	free(cvd->time);
	free(cvd);
	return NULL;
    }

    if(!(cvd->dsig = cli_strtok(head, 6, ":"))) {
	cli_errmsg("CVD -> Can't extract digital signature from header.\n");
	free(cvd->time);
	free(cvd->md5);
	free(cvd);
	return NULL;
    }

    if(!(cvd->builder = cli_strtok(head, 7, ":"))) {
	cli_errmsg("CVD -> Can't extract builder name from header.\n");
	free(cvd->time);
	free(cvd->md5);
	free(cvd->dsig);
	free(cvd);
	return NULL;
    }

    if((pt = cli_strtok(head, 8, ":"))) {
	cvd->stime = atoi(pt);
	free(pt);
    } else
	cli_dbgmsg("CVD -> No creation time in seconds (old file format)\n");


    return cvd;
}

struct cl_cvd *cl_cvdhead(const char *file)
{
	FILE *fd;
	char head[513];
	int i;

    if((fd = fopen(file, "rb")) == NULL) {
	cli_dbgmsg("Can't open CVD file %s\n", file);
	return NULL;
    }

    if((i = fread(head, 1, 512, fd)) != 512) {
	cli_dbgmsg("Short read (%d) while reading CVD head from %s\n", i, file);
	fclose(fd);
	return NULL;
    }

    fclose(fd);

    head[512] = 0;
    for(i = 511; i > 0 && (head[i] == ' ' || head[i] == 10); head[i] = 0, i--);

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

int cli_cvdverify(FILE *fd, struct cl_cvd *cvdpt)
{
	struct cl_cvd *cvd;
	char *md5, head[513];
	int i;

    fseek(fd, 0, SEEK_SET);
    if(fread(head, 1, 512, fd) != 512) {
	cli_dbgmsg("Can't read CVD head from stream\n");
	return CL_ECVD;
    }

    head[512] = 0;
    for(i = 511; i > 0 && (head[i] == ' ' || head[i] == 10); head[i] = 0, i--);

    if((cvd = cl_cvdparse(head)) == NULL)
	return CL_ECVD;

    if(cvdpt)
	memcpy(cvdpt, cvd, sizeof(struct cl_cvd));

    md5 = cli_md5stream(fd, NULL);
    cli_dbgmsg("MD5(.tar.gz) = %s\n", md5);

    if(strncmp(md5, cvd->md5, 32)) {
	cli_dbgmsg("MD5 verification error.\n");
	free(md5);
	cl_cvdfree(cvd);
	return CL_EMD5;
    }

#ifdef HAVE_GMP
    if(cli_versig(md5, cvd->dsig)) {
	cli_dbgmsg("Digital signature verification error.\n");
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
	FILE *fd;
	int ret;

    if((fd = fopen(file, "rb")) == NULL) {
	cli_errmsg("Can't open CVD file %s\n", file);
	return CL_EOPEN;
    }

    ret = cli_cvdverify(fd, NULL);
    fclose(fd);

    return ret;
}

int cli_cvdload(FILE *fd, struct cl_node **root, unsigned int *signo, short warn)
{
        char *dir, *tmp, *buffer;
	struct cl_cvd cvd;
	int bytes, ret;
	FILE *tmpd;
	time_t stime;


    cli_dbgmsg("in cli_cvdload()\n");

    /* verify */

    if((ret = cli_cvdverify(fd, &cvd)))
	return ret;

    if(cvd.stime && warn) {
	time(&stime);
	if((int) stime - cvd.stime > 604800) {
	    cli_warnmsg("**************************************************\n");
	    cli_warnmsg("***  The virus database is older than 7 days.  ***\n");
	    cli_warnmsg("***        Please update it IMMEDIATELY!       ***\n");
	    cli_warnmsg("**************************************************\n");
	}
    }

    if(cvd.fl > cl_retflevel()) {
	cli_warnmsg("********************************************************\n");
	cli_warnmsg("***  This version of the ClamAV engine is outdated.  ***\n");
	cli_warnmsg("*** DON'T PANIC! Read http://www.clamav.net/faq.html ***\n");
	cli_warnmsg("********************************************************\n");
    }

    fseek(fd, 512, SEEK_SET);

    dir = cli_gentemp(NULL);
    if(mkdir(dir, 0700)) {
	cli_errmsg("cli_cvdload():  Can't create temporary directory %s\n", dir);
	return CL_ETMPDIR;
    }

    /* 
    if(cli_untgz(fileno(fd), dir)) {
	cli_errmsg("cli_cvdload(): Can't unpack CVD file.\n");
	return CL_ECVDEXTR;
    }
    */

    /* FIXME: it seems there is some problem with current position indicator
     * after gzdopen() call in cli_untgz(). Temporarily we need this wrapper:
     */

	    /* start */

	    tmp = cli_gentemp(NULL);
	    if((tmpd = fopen(tmp, "wb+")) == NULL) {
		cli_errmsg("Can't create temporary file %s\n", tmp);
		free(dir);
		free(tmp);
		return CL_ETMPFILE;
	    }

	    if(!(buffer = (char *) cli_malloc(FILEBUFF))) {
		free(dir);
		free(tmp);
		fclose(tmpd);
		return CL_EMEM;
	    }

	    while((bytes = fread(buffer, 1, FILEBUFF, fd)) > 0)
		fwrite(buffer, 1, bytes, tmpd);

	    free(buffer);

	    fflush(tmpd);
	    fseek(tmpd, 0L, SEEK_SET);

	    if(cli_untgz(fileno(tmpd), dir)) {
		perror("cli_untgz");
		cli_errmsg("cli_cvdload(): Can't unpack CVD file.\n");
		cli_rmdirs(dir);
		free(dir);
		fclose(tmpd);
		unlink(tmp);
		free(tmp);
		return CL_ECVDEXTR;
	    }

	    fclose(tmpd);
	    unlink(tmp);
	    free(tmp);

	    /* end */

    /* load extracted directory */
    cl_loaddbdir(dir, root, signo);

    cli_rmdirs(dir);
    free(dir);

    return 0;
}

/*
 *  Copyright (C) 2003 Tomasz Kojm <zolw@konarski.edu.pl>
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <zlib.h>

#include "clamav.h"
#include "others.h"
#include "dsig.h"

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
	    return -1;
	}

	if(!in_block) {
	    if (block[0] == '\0')  /* We're done */
		break;

	    strncpy(name, block, 100);
	    name[100] = '\0';
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
		    return -1;
		default:
		    cli_errmsg("Unknown type flag %c.\n",type);
		    free(fullname);
		    return -1;
	    }

	    in_block = 1;

	    if(outfile) {
		if(fclose(outfile)) {
		    cli_errmsg("Cannot close file %s.\n", fullname);
		    free(fullname);
		    return -1;
		}
		outfile = NULL;
	    }

	    if(!(outfile = fopen(fullname, "wb"))) {
		cli_errmsg("Cannot create file %s.\n", fullname);
		free(fullname);
		return -1;
	    }

	    strncpy(osize, block + 124, 12);
	    osize[12] = '\0';
	    size = -1;
	    sscanf(osize, "%o", &size);

	    if(size < 0) {
		cli_errmsg("Invalid size in header.\n");
		free(fullname);
		return -1;
	    }

	} else { /* write or continue writing file contents */
	    nbytes = size > TAR_BLOCKSIZE ? TAR_BLOCKSIZE : size;
	    nwritten = fwrite(block, 1, nbytes, outfile);

	    if(nwritten != nbytes) {
		cli_errmsg("Wrote %d instead of %d (%s).\n", nwritten, nbytes, fullname);
		free(fullname);
		return -1;
	    }

	    size -= nbytes;
	    if(size == 0)
		in_block = 0;
	}
    }

    if(outfile)
	fclose(outfile);

    return 0;
}

char *cli_cut(const char *line, int field)
{
        int length, counter = 0, i, j = 0;
        char *buffer;

    length = strlen(line);
    buffer = (char *) cli_calloc(length, sizeof(char));

    for(i = 0; i < length; i++) {
        if(line[i] == ':') {
            counter++;
            if(counter == field) {
		break;
	    } else {
		memset(buffer, 0, length);
		j = 0;
	    }
        } else {
            buffer[j++] = line[i];
        }
    }

    return (char *) cli_realloc(buffer, strlen(buffer) + 1);
}

struct cl_cvd *cli_cvdhead(FILE *fd)
{
	char *pt, head[513];
	struct cl_cvd *cvd;
	int i;


    if(fread(head, 1, 512, fd) != 512) {
	cli_errmsg("Can't read CVD head from stream\n");
	return NULL;
    }

    head[512] = 0;
    for(i = 511; i > 0 && (head[i] == ' ' || head[i] == 10); head[i] = 0, i--);

    if(strncmp(head, "ClamAV-VDB:", 11)) {
	cli_errmsg("Not a CVD file.\n");
	return NULL;
    }

    cvd = (struct cl_cvd *) cli_calloc(1, sizeof(struct cl_cvd));
    cvd->time = cli_cut(head, 2);

    pt = cli_cut(head, 3);
    cvd->version = atoi(pt);
    free(pt);

    pt = cli_cut(head, 4);
    cvd->sigs = atoi(pt);
    free(pt);

    pt = cli_cut(head, 5);
    cvd->fl = (short int) atoi(pt);
    free(pt);

    cvd->md5 = cli_cut(head, 6);
    cvd->dsig = cli_cut(head, 7);
    cvd->builder = cli_cut(head, 8);

    return cvd;
}

struct cl_cvd *cl_cvdhead(const char *file)
{
	FILE *fd;

    if((fd = fopen(file, "rb")) == NULL) {
	cli_errmsg("Can't open CVD file %s\n", file);
	return NULL;
    }

    return cli_cvdhead(fd);
}

void cl_cvdfree(struct cl_cvd *cvd)
{
    free(cvd->time);
    free(cvd->md5);
    free(cvd->dsig);
    free(cvd->builder);
    free(cvd);
}

int cli_cvdverify(FILE *fd)
{
	struct cl_cvd *head;
	char *md5;

    if((head = cli_cvdhead(fd)) == NULL)
	return CL_ECVD;

    //fseek(fd, 512, SEEK_SET);

    md5 = cli_md5stream(fd);

    cli_dbgmsg("MD5(.tar.gz) = %s\n", md5);

    if(strncmp(md5, head->md5, 32)) {
	cli_dbgmsg("MD5 verification error.\n");
	return CL_EMD5;
    }

#ifdef HAVE_GMP
    if(cli_versig(md5, head->dsig)) {
	cli_dbgmsg("Digital signature verification error.\n");
	return CL_EDSIG;
    }
#endif

    return 0;
}

struct cl_cvd *cl_cvdverify(const char *file)
{
	FILE *fd;

    if((fd = fopen(file, "rb")) == NULL) {
	cli_errmsg("Can't open CVD file %s\n", file);
	return NULL;
    }

    return cli_cvdverify(fd);
}

int cli_cvdload(FILE *fd, struct cl_node **root, int *virnum)
{
        char *dir, *tmp, buffer[BUFFSIZE];
	int bytes, ret;
	const char *tmpdir;
	FILE *tmpd;

    cli_dbgmsg("in cli_cvdload()\n");

    /* verify */

    if((ret = cli_cvdverify(fd)))
	return ret;

    fseek(fd, 512, SEEK_SET);

    tmpdir = getenv("TMPDIR");

    if(tmpdir == NULL)
#ifdef P_tmpdir
	tmpdir = P_tmpdir;
#else
	tmpdir = "/tmp";
#endif

    dir = cl_gentemp(tmpdir);
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

	    tmp = cl_gentemp(tmpdir);
	    if((tmpd = fopen(tmp, "wb+")) == NULL) {
		cli_errmsg("Can't create temporary file %s\n", tmp);
		free(dir);
		free(tmp);
		return -1;
	    }
	    while((bytes = fread(buffer, 1, BUFFSIZE, fd)) > 0)
		fwrite(buffer, 1, bytes, tmpd);

	    fflush(tmpd);
	    fseek(tmpd, 0L, SEEK_SET);

	    if(cli_untgz(fileno(tmpd), dir)) {
		cli_errmsg("cli_cvdload(): Can't unpack CVD file.\n");
		cli_rmdirs(dir);
		free(dir);
		unlink(tmp);
		free(tmp);
		return CL_ECVDEXTR;
	    }

	    fclose(tmpd);
	    unlink(tmp);
	    free(tmp);

	    /* end */

    /* load extracted directory */
    cl_loaddbdir(dir, root, virnum);

    cli_rmdirs(dir);
    free(dir);

    return 0;
}

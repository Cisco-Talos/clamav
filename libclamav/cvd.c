/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm
 * 
 *  Summary: Code to parse Clamav CVD database format.
 * 
 *  Acknowledgements: ClamAV untar code is based on a public domain minitar utility
 *                    by Charles G. Waldman.
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
#include "readdb.h"
#include "default.h"

#define TAR_BLOCKSIZE 512

static void cli_untgz_cleanup(char *path, gzFile infile, FILE *outfile, int fdd)
{
    UNUSEDPARAM(fdd);
    cli_dbgmsg("in cli_untgz_cleanup()\n");
    if (path != NULL)
        free (path);
    if (infile != NULL) 
        gzclose (infile);
    if (outfile != NULL)
        fclose(outfile);
}

static int cli_untgz(int fd, const char *destdir)
{
	char *path, osize[13], name[101], type;
	char block[TAR_BLOCKSIZE];
	int nbytes, nread, nwritten, in_block = 0, fdd = -1;
	unsigned int size, pathlen = strlen(destdir) + 100 + 5;
	FILE *outfile = NULL;
	STATBUF foo;
	gzFile infile = NULL;


    cli_dbgmsg("in cli_untgz()\n");

    if((fdd = dup(fd)) == -1) {
	cli_errmsg("cli_untgz: Can't duplicate descriptor %d\n", fd);
	return -1;
    }

    if((infile = gzdopen(fdd, "rb")) == NULL) {
	cli_errmsg("cli_untgz: Can't gzdopen() descriptor %d, errno = %d\n", fdd, errno);
	if(FSTAT(fdd, &foo) == 0)
	    close(fdd);
	return -1;
    }

    path = (char *) cli_calloc(sizeof(char), pathlen);
    if(!path) {
	cli_errmsg("cli_untgz: Can't allocate memory for path\n");
	cli_untgz_cleanup(NULL, infile, NULL, fdd);
	return -1;
    }

    while(1) {

	nread = gzread(infile, block, TAR_BLOCKSIZE);

	if(!in_block && !nread)
	    break;

	if(nread != TAR_BLOCKSIZE) {
	    cli_errmsg("cli_untgz: Incomplete block read\n");
	    cli_untgz_cleanup(path, infile, outfile, fdd);
	    return -1;
	}

	if(!in_block) {
	    if (block[0] == '\0')  /* We're done */
		break;

	    strncpy(name, block, 100);
	    name[100] = '\0';

	    if(strchr(name, '/')) {
		cli_errmsg("cli_untgz: Slash separators are not allowed in CVD\n");
		cli_untgz_cleanup(path, infile, outfile, fdd);
		return -1;
	    }

	    snprintf(path, pathlen, "%s"PATHSEP"%s", destdir, name);
	    cli_dbgmsg("cli_untgz: Unpacking %s\n", path);
	    type = block[156];

	    switch(type) {
		case '0':
		case '\0':
		    break;
		case '5':
		    cli_errmsg("cli_untgz: Directories are not supported in CVD\n");
		    cli_untgz_cleanup(path, infile, outfile, fdd);
		    return -1;
		default:
		    cli_errmsg("cli_untgz: Unknown type flag '%c'\n", type);
		    cli_untgz_cleanup(path, infile, outfile, fdd);
		    return -1;
	    }

	    if(outfile) {
		if(fclose(outfile)) {
		    cli_errmsg("cli_untgz: Cannot close file %s\n", path);
		    outfile = NULL;
		    cli_untgz_cleanup(path, infile, outfile, fdd);
		    return -1;
		}
		outfile = NULL;
	    }

	    if(!(outfile = fopen(path, "wb"))) {
		cli_errmsg("cli_untgz: Cannot create file %s\n", path);
		cli_untgz_cleanup(path, infile, outfile, fdd);
		return -1;
	    }

	    strncpy(osize, block + 124, 12);
	    osize[12] = '\0';

	    if((sscanf(osize, "%o", &size)) == 0) {
		cli_errmsg("cli_untgz: Invalid size in header\n");
		cli_untgz_cleanup(path, infile, outfile, fdd);
		return -1;
	    }

	    if (size > 0)
		in_block = 1;

	} else { /* write or continue writing file contents */
	    nbytes = size > TAR_BLOCKSIZE ? TAR_BLOCKSIZE : size;
	    nwritten = fwrite(block, 1, nbytes, outfile);

	    if(nwritten != nbytes) {
		cli_errmsg("cli_untgz: Wrote %d instead of %d (%s)\n", nwritten, nbytes, path);
		cli_untgz_cleanup(path, infile, outfile, fdd);
		return -1;
	    }

	    size -= nbytes;
	    if(size == 0)
		in_block = 0;
	}
    }

    cli_untgz_cleanup(path, infile, outfile, fdd);
    return 0;
}

static void cli_tgzload_cleanup(int comp, struct cli_dbio *dbio, int fdd)
{
    UNUSEDPARAM(fdd);
    cli_dbgmsg("in cli_tgzload_cleanup()\n");
    if(comp) {
        gzclose(dbio->gzs);
        dbio->gzs = NULL;
    }
    else {
        fclose(dbio->fs);
        dbio->fs = NULL;
    }
    if(dbio->buf != NULL) {
        free(dbio->buf);
        dbio->buf = NULL;
    }

    if (dbio->hashctx) {
        cl_hash_destroy(dbio->hashctx);
        dbio->hashctx = NULL;
    }
}

static int cli_tgzload(int fd, struct cl_engine *engine, unsigned int *signo, unsigned int options, struct cli_dbio *dbio, struct cli_dbinfo *dbinfo)
{
	char osize[13], name[101];
	char block[TAR_BLOCKSIZE];
	int nread, fdd, ret;
	unsigned int type, size, pad, compr = 1;
	off_t off;
	struct cli_dbinfo *db;
	char hash[32];

    cli_dbgmsg("in cli_tgzload()\n");

    if(lseek(fd, 512, SEEK_SET) < 0) {
        return CL_ESEEK;
    }

    if(cli_readn(fd, block, 7) != 7)
	return CL_EFORMAT; /* truncated file? */

    if(!strncmp(block, "COPYING", 7))
	compr = 0;

    if(lseek(fd, 512, SEEK_SET) < 0) {
        return CL_ESEEK;
    }

    if((fdd = dup(fd)) == -1) {
	cli_errmsg("cli_tgzload: Can't duplicate descriptor %d\n", fd);
	return CL_EDUP;
    }

    if(compr) {
	if((dbio->gzs = gzdopen(fdd, "rb")) == NULL) {
	    cli_errmsg("cli_tgzload: Can't gzdopen() descriptor %d, errno = %d\n", fdd, errno);
	    if (fdd > -1)
		close(fdd);
	    return CL_EOPEN;
	}
	dbio->fs = NULL;
    } else {
	if((dbio->fs = fdopen(fdd, "rb")) == NULL) {
	    cli_errmsg("cli_tgzload: Can't fdopen() descriptor %d, errno = %d\n", fdd, errno);
	    if (fdd > -1)
		close(fdd);
	    return CL_EOPEN;
	}
	dbio->gzs = NULL;
    }

    dbio->bufsize = CLI_DEFAULT_DBIO_BUFSIZE;
    dbio->buf = cli_malloc(dbio->bufsize);
    if(!dbio->buf) {
	cli_errmsg("cli_tgzload: Can't allocate memory for dbio->buf\n");
	cli_tgzload_cleanup(compr, dbio, fdd);
	return CL_EMALFDB;
    }
    dbio->bufpt = NULL;
    dbio->usebuf = 1;
    dbio->readpt = dbio->buf;

    while(1) {

	if(compr)
	    nread = gzread(dbio->gzs, block, TAR_BLOCKSIZE);
	else
	    nread = fread(block, 1, TAR_BLOCKSIZE, dbio->fs);

	if(!nread)
	    break;

	if(nread != TAR_BLOCKSIZE) {
	    cli_errmsg("cli_tgzload: Incomplete block read\n");
	    cli_tgzload_cleanup(compr, dbio, fdd);
	    return CL_EMALFDB;
	}

	if(block[0] == '\0')  /* We're done */
	    break;

	strncpy(name, block, 100);
	name[100] = '\0';

	if(strchr(name, '/')) {
	    cli_errmsg("cli_tgzload: Slash separators are not allowed in CVD\n");
	    cli_tgzload_cleanup(compr, dbio, fdd);
	    return CL_EMALFDB;
	}

	type = block[156];

	switch(type) {
	    case '0':
	    case '\0':
		break;
	    case '5':
		cli_errmsg("cli_tgzload: Directories are not supported in CVD\n");
		cli_tgzload_cleanup(compr, dbio, fdd);
		return CL_EMALFDB;
	    default:
		cli_errmsg("cli_tgzload: Unknown type flag '%c'\n", type);
		cli_tgzload_cleanup(compr, dbio, fdd);
		return CL_EMALFDB;
	}

	strncpy(osize, block + 124, 12);
	osize[12] = '\0';

	if((sscanf(osize, "%o", &size)) == 0) {
	    cli_errmsg("cli_tgzload: Invalid size in header\n");
	    cli_tgzload_cleanup(compr, dbio, fdd);
	    return CL_EMALFDB;
	}
	dbio->size = size;
	dbio->readsize = dbio->size < dbio->bufsize ? dbio->size : dbio->bufsize - 1;
	dbio->bufpt = NULL;
	dbio->readpt = dbio->buf;
    if (!(dbio->hashctx)) {
        dbio->hashctx = cl_hash_init("sha256");
        if (!(dbio->hashctx)) {
            cli_tgzload_cleanup(compr, dbio, fdd);
            return CL_EMALFDB;
        }
    }
	dbio->bread = 0;

	/* cli_dbgmsg("cli_tgzload: Loading %s, size: %u\n", name, size); */
	if(compr)
	    off = (off_t) gzseek(dbio->gzs, 0, SEEK_CUR);
	else
	    off = ftell(dbio->fs);

	if((!dbinfo && cli_strbcasestr(name, ".info")) || (dbinfo && (CLI_DBEXT(name) || cli_strbcasestr(name, ".ign") || cli_strbcasestr(name, ".ign2")))) {
	    ret = cli_load(name, engine, signo, options, dbio);
	    if(ret) {
		cli_errmsg("cli_tgzload: Can't load %s\n", name);
		cli_tgzload_cleanup(compr, dbio, fdd);
		return CL_EMALFDB;
	    }
	    if(!dbinfo) {
		cli_tgzload_cleanup(compr, dbio, fdd);
		return CL_SUCCESS;
	    } else {
		db = dbinfo;
		while(db && strcmp(db->name, name))
		    db = db->next;
		if(!db) {
		    cli_errmsg("cli_tgzload: File %s not found in .info\n", name);
		    cli_tgzload_cleanup(compr, dbio, fdd);
		    return CL_EMALFDB;
		}
		if(dbio->bread) {
		    if(db->size != dbio->bread) {
			cli_errmsg("cli_tgzload: File %s not correctly loaded\n", name);
			cli_tgzload_cleanup(compr, dbio, fdd);
			return CL_EMALFDB;
		    }
            cl_finish_hash(dbio->hashctx, hash);
            dbio->hashctx = cl_hash_init("sha256");
            if (!(dbio->hashctx)) {
                cli_tgzload_cleanup(compr, dbio, fdd);
                return CL_EMALFDB;
            }
		    if(memcmp(db->hash, hash, 32)) {
			cli_errmsg("cli_tgzload: Invalid checksum for file %s\n", name);
			cli_tgzload_cleanup(compr, dbio, fdd);
			return CL_EMALFDB;
		    }
		}
	    }
	}
	pad = size % TAR_BLOCKSIZE ? (TAR_BLOCKSIZE - (size % TAR_BLOCKSIZE)) : 0;
	if(compr) {
	    if(off == gzseek(dbio->gzs, 0, SEEK_CUR))
		gzseek(dbio->gzs, size + pad, SEEK_CUR);
	    else if(pad)
		gzseek(dbio->gzs, pad, SEEK_CUR);
	} else {
	    if(off == ftell(dbio->fs))
		fseek(dbio->fs, size + pad, SEEK_CUR);
	    else if(pad)
		fseek(dbio->fs, pad, SEEK_CUR);
	}
    }

    cli_tgzload_cleanup(compr, dbio, fdd);
    return CL_SUCCESS;
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

static int cli_cvdverify(FILE *fs, struct cl_cvd *cvdpt, unsigned int skipsig)
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

    if(skipsig) {
	cl_cvdfree(cvd);
	return CL_SUCCESS;
    }

    md5 = cli_hashstream(fs, NULL, 1);
    if (md5 == NULL) {
	cli_dbgmsg("cli_cvdverify: Cannot generate hash, out of memory\n");
	cl_cvdfree(cvd);
	return CL_EMEM;
    }
    cli_dbgmsg("MD5(.tar.gz) = %s\n", md5);

    if(strncmp(md5, cvd->md5, 32)) {
	cli_dbgmsg("cli_cvdverify: MD5 verification error\n");
	free(md5);
	cl_cvdfree(cvd);
	return CL_EVERIFY;
    }

    if(cli_versig(md5, cvd->dsig)) {
	cli_dbgmsg("cli_cvdverify: Digital signature verification error\n");
	free(md5);
	cl_cvdfree(cvd);
	return CL_EVERIFY;
    }

    free(md5);
    cl_cvdfree(cvd);
    return CL_SUCCESS;
}

int cl_cvdverify(const char *file)
{
	struct cl_engine *engine;
	FILE *fs;
	int ret, dbtype = 0;


    if((fs = fopen(file, "rb")) == NULL) {
	cli_errmsg("cl_cvdverify: Can't open file %s\n", file);
	return CL_EOPEN;
    }

    if(!(engine = cl_engine_new())) {
	cli_errmsg("cld_cvdverify: Can't create new engine\n");
	fclose(fs);
	return CL_EMEM;
    }
    engine->cb_stats_submit = NULL; /* Don't submit stats if we're just verifying a CVD */

    if (!!cli_strbcasestr(file, ".cld"))
	dbtype = 1;
    else if (!!cli_strbcasestr(file, ".cud"))
	dbtype = 2;

    ret = cli_cvdload(fs, engine, NULL, CL_DB_STDOPT | CL_DB_PUA, dbtype, file, 1);

    cl_engine_free(engine);
    fclose(fs);
    return ret;
}

int cli_cvdload(FILE *fs, struct cl_engine *engine, unsigned int *signo, unsigned int options, unsigned int dbtype, const char *filename, unsigned int chkonly)
{
	struct cl_cvd cvd, dupcvd;
	FILE *dupfs;
	int ret;
	time_t s_time;
	int cfd;
	struct cli_dbio dbio;
	struct cli_dbinfo *dbinfo = NULL;
	char *dupname;

    dbio.hashctx = NULL;

    cli_dbgmsg("in cli_cvdload()\n");

    /* verify */
    if((ret = cli_cvdverify(fs, &cvd, dbtype)))
	return ret;

    if(dbtype <= 1) {
	/* check for duplicate db */
	dupname = cli_strdup(filename);
	if(!dupname)
	    return CL_EMEM;
	dupname[strlen(dupname) - 2] = (dbtype == 1 ? 'v' : 'l');
	if(!access(dupname, R_OK) && (dupfs = fopen(dupname, "rb"))) {
	    if((ret = cli_cvdverify(dupfs, &dupcvd, !dbtype))) {
		fclose(dupfs);
		free(dupname);
		return ret;
	    }
	    fclose(dupfs);
	    if(dupcvd.version > cvd.version) {
		cli_warnmsg("Detected duplicate databases %s and %s. The %s database is older and will not be loaded, you should manually remove it from the database directory.\n", filename, dupname, filename);
		free(dupname);
		return CL_SUCCESS;
	    } else if(dupcvd.version == cvd.version && !dbtype) {
		cli_warnmsg("Detected duplicate databases %s and %s, please manually remove one of them\n", filename, dupname);
		free(dupname);
		return CL_SUCCESS;
	    }
	}
	free(dupname);
    }

    if(strstr(filename, "daily.")) {
	time(&s_time);
	if(cvd.stime > s_time) {
	    if(cvd.stime - (unsigned int ) s_time > 3600) {
		cli_warnmsg("******************************************************\n");
		cli_warnmsg("***      Virus database timestamp in the future!   ***\n");
		cli_warnmsg("***  Please check the timezone and clock settings  ***\n");
		cli_warnmsg("******************************************************\n");
	    }
	} else if((unsigned int) s_time - cvd.stime > 604800) {
	    cli_warnmsg("**************************************************\n");
	    cli_warnmsg("***  The virus database is older than 7 days!  ***\n");
	    cli_warnmsg("***   Please update it as soon as possible.    ***\n");
	    cli_warnmsg("**************************************************\n");
	}
	engine->dbversion[0] = cvd.version;
	engine->dbversion[1] = cvd.stime;
    }

    if(cvd.fl > cl_retflevel()) {
	cli_warnmsg("*******************************************************************\n");
	cli_warnmsg("***  This version of the ClamAV engine is outdated.             ***\n");
	cli_warnmsg("***   Read https://www.clamav.net/documents/installing-clamav   ***\n");
	cli_warnmsg("*******************************************************************\n");
    }

    cfd = fileno(fs);
    dbio.chkonly = 0;
    if(dbtype == 2)
	ret = cli_tgzload(cfd, engine, signo, options | CL_DB_UNSIGNED, &dbio, NULL);
    else
	ret = cli_tgzload(cfd, engine, signo, options | CL_DB_OFFICIAL, &dbio, NULL);
    if(ret != CL_SUCCESS)
	return ret;

    dbinfo = engine->dbinfo;
    if(!dbinfo || !dbinfo->cvd || (dbinfo->cvd->version != cvd.version) || (dbinfo->cvd->sigs != cvd.sigs) || (dbinfo->cvd->fl != cvd.fl) || (dbinfo->cvd->stime != cvd.stime)) {
	cli_errmsg("cli_cvdload: Corrupted CVD header\n");
	return CL_EMALFDB;
    }
    dbinfo = engine->dbinfo ? engine->dbinfo->next : NULL;
    if(!dbinfo) {
	cli_errmsg("cli_cvdload: dbinfo error\n");
	return CL_EMALFDB;
    }

    dbio.chkonly = chkonly;
    if(dbtype == 2)
	options |= CL_DB_UNSIGNED;
    else
	options |= CL_DB_SIGNED | CL_DB_OFFICIAL;

    ret = cli_tgzload(cfd, engine, signo, options, &dbio, dbinfo);

    while(engine->dbinfo) {
	dbinfo = engine->dbinfo;
	engine->dbinfo = dbinfo->next;
	mpool_free(engine->mempool, dbinfo->name);
	mpool_free(engine->mempool, dbinfo->hash);
	if(dbinfo->cvd)
	    cl_cvdfree(dbinfo->cvd);
	mpool_free(engine->mempool, dbinfo);
    }

    return ret;
}

int cli_cvdunpack(const char *file, const char *dir)
{
	int fd, ret;


    fd = open(file, O_RDONLY|O_BINARY);
    if(fd == -1)
	return -1;

    if(lseek(fd, 512, SEEK_SET) < 0) {
	close(fd);
	return -1;
    }

    ret = cli_untgz(fd, dir);
    close(fd);
    return ret;
}

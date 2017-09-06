/*
 *  Copyright (C) 2006 Sensory Networks, Inc.
 *	      (C) 2007 Tomasz Kojm <tkojm@clamav.net>
 *	      Written by Tomasz Kojm
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
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "clamav.h"
#include "shared/misc.h"
#include "shared/output.h"
#include "shared/cdiff.h"

#include "libclamav/str.h"
#include "libclamav/others.h"
#include "libclamav/cvd.h"
#include "libclamav/default.h"

#include "zlib.h"

#include "libclamav/dsig.h"

#include <openssl/evp.h>

#define PSS_NSTR "14783905874077467090262228516557917570254599638376203532031989214105552847269687489771975792123442185817287694951949800908791527542017115600501303394778618535864845235700041590056318230102449612217458549016089313306591388590790796515819654102320725712300822356348724011232654837503241736177907784198700834440681124727060540035754699658105895050096576226753008596881698828185652424901921668758326578462003247906470982092298106789657211905488986281078346361469524484829559560886227198091995498440676639639830463593211386055065360288422394053998134458623712540683294034953818412458362198117811990006021989844180721010947"
#define PSS_ESTR "100002053"
#define PSS_NBITS 2048
#define PSS_DIGEST_LENGTH 32

/* the line size can be changed from within .cdiff */
#define CDIFF_LINE_SIZE CLI_DEFAULT_LSIG_BUFSIZE + 32

struct cdiff_node {
    unsigned int lineno;
    char *str, *str2;
    struct cdiff_node *next;
};

struct cdiff_ctx {
    char *open_db;
    struct cdiff_node *add_start, *add_last;
    struct cdiff_node *del_start;
    struct cdiff_node *xchg_start, *xchg_last;
};

struct cdiff_cmd {
    const char *name;
    unsigned short argc;
    int (*handler)(const char *, struct cdiff_ctx *, char *, unsigned int);
};

static int cdiff_cmd_open(const char *cmdstr, struct cdiff_ctx *ctx, char *lbuf, unsigned int lbuflen);
static int cdiff_cmd_add(const char *cmdstr, struct cdiff_ctx *ctx, char *lbuf, unsigned int lbuflen);
static int cdiff_cmd_del(const char *cmdstr, struct cdiff_ctx *ctx, char *lbuf, unsigned int lbuflen);
static int cdiff_cmd_xchg(const char *cmdstr, struct cdiff_ctx *ctx, char *lbuf, unsigned int lbuflen);
static int cdiff_cmd_close(const char *cmdstr, struct cdiff_ctx *ctx, char *lbuf, unsigned int lbuflen);
static int cdiff_cmd_move(const char *cmdstr, struct cdiff_ctx *ctx, char *lbuf, unsigned int lbuflen);
static int cdiff_cmd_unlink(const char *cmdstr, struct cdiff_ctx *ctx, char *lbuf, unsigned int lbuflen);

static struct cdiff_cmd commands[] = {
    /* OPEN db_name */
    { "OPEN", 1, &cdiff_cmd_open },

    /* ADD newsig */
    { "ADD", 1, &cdiff_cmd_add },

    /* DEL line_no some_first_bytes */
    { "DEL", 2, &cdiff_cmd_del },

    /* XCHG line_no some_first_bytes_of_old_line new_line */
    { "XCHG", 3, &cdiff_cmd_xchg },

    /* CLOSE */
    { "CLOSE", 0, &cdiff_cmd_close },

    /* MOVE src_db dst_db start_line first_16b end_line first_16b */
    { "MOVE", 6, &cdiff_cmd_move },

    /* UNLINK db_name */
    { "UNLINK", 1, &cdiff_cmd_unlink },

    { NULL, 0, NULL }
};

static void cdiff_ctx_free(struct cdiff_ctx *ctx)
{
	struct cdiff_node *pt;


    if(ctx->open_db) {
	free(ctx->open_db);
	ctx->open_db = NULL;
    }

    while(ctx->add_start) {
	free(ctx->add_start->str);
	pt = ctx->add_start;
	ctx->add_start = ctx->add_start->next;
	free(pt);
    }
    ctx->add_last = NULL;

    while(ctx->del_start) {
	free(ctx->del_start->str);
	pt = ctx->del_start;
	ctx->del_start = ctx->del_start->next;
	free(pt);
    }

    while(ctx->xchg_start) {
	free(ctx->xchg_start->str);
	free(ctx->xchg_start->str2);
	pt = ctx->xchg_start;
	ctx->xchg_start = ctx->xchg_start->next;
	free(pt);
    }
}

static char *cdiff_token(const char *line, unsigned int token, unsigned int last)
{
	unsigned int counter = 0, i, j;
	char *buffer;


    for(i = 0; line[i] && counter != token; i++)
	if(line[i] == ' ')
	    counter++;

    if(!line[i])
	return NULL;

    if(last)
	return strdup(&line[i]);

    for(j = i; line[j]; j++)
	if(line[j] == ' ')
	    break;

    if(i == j)
	return NULL;

    buffer = malloc(j - i + 1);
    if(!buffer)
	return NULL;

    strncpy(buffer, line + i, j - i);
    buffer[j - i] = '\0';

    return buffer;
}

static int cdiff_cmd_open(const char *cmdstr, struct cdiff_ctx *ctx, char *lbuf, unsigned int lbuflen)
{
	char *db;
	unsigned int i;

    UNUSEDPARAM(lbuf);
    UNUSEDPARAM(lbuflen);

    if(!(db = cdiff_token(cmdstr, 1, 1))) {
	logg("!cdiff_cmd_open: Can't get first argument\n");
	return -1;
    }

    if(ctx->open_db) {
	logg("!cdiff_cmd_open: %s not closed before opening %s\n", ctx->open_db, db);
	free(db);
	return -1;
    }

    for(i = 0; i < strlen(db); i++) {
	if((db[i] != '.' && !isalnum(db[i])) || strchr("/\\", db[i])) {
	    logg("!cdiff_cmd_open: Forbidden characters found in database name\n");
	    free(db);
	    return -1;
	}
    }

    ctx->open_db = db;
    return 0;
}

static int cdiff_cmd_add(const char *cmdstr, struct cdiff_ctx *ctx, char *lbuf, unsigned int lbuflen)
{
	char *sig;
	struct cdiff_node *new;

    UNUSEDPARAM(lbuf);
    UNUSEDPARAM(lbuflen);

    if(!(sig = cdiff_token(cmdstr, 1, 1))) {
	logg("!cdiff_cmd_add: Can't get first argument\n");
	return -1;
    }

    new = (struct cdiff_node *) calloc(1, sizeof(struct cdiff_node));
    if(!new) {
	logg("!cdiff_cmd_add: Can't allocate memory for cdiff_node\n");
	free(sig);
	return -1;
    }
    new->str = sig;

    if(!ctx->add_last) {
	ctx->add_start = ctx->add_last = new;
    } else { 
	ctx->add_last->next = new;
	ctx->add_last = new;
    }

    return 0;
}

static int cdiff_cmd_del(const char *cmdstr, struct cdiff_ctx *ctx, char *lbuf, unsigned int lbuflen)
{
	char *arg;
	struct cdiff_node *pt, *last, *new;
	unsigned int lineno;

    UNUSEDPARAM(lbuf);
    UNUSEDPARAM(lbuflen);


    if(!(arg = cdiff_token(cmdstr, 1, 0))) {
	logg("!cdiff_cmd_del: Can't get first argument\n");
	return -1;
    }
    lineno = (unsigned int) atoi(arg);
    free(arg);

    if(!(arg = cdiff_token(cmdstr, 2, 1))) {
	logg("!cdiff_cmd_del: Can't get second argument\n");
	return -1;
    }

    new = (struct cdiff_node *) calloc(1, sizeof(struct cdiff_node));
    if(!new) {
	logg("!cdiff_cmd_del: Can't allocate memory for cdiff_node\n");
	free(arg);
	return -1;
    }
    new->str = arg;
    new->lineno = lineno;

    if(!ctx->del_start) {

	ctx->del_start = new;

    } else { 

	if(lineno < ctx->del_start->lineno) {
	    new->next = ctx->del_start;
	    ctx->del_start = new;

	} else {
	    pt = ctx->del_start;

	    while(pt) {
		last = pt;
		if((pt->lineno < lineno) && (!pt->next || lineno < pt->next->lineno))
		    break;

		pt = pt->next;
	    }

	    new->next = last->next;
	    last->next = new;
	}
    }

    return 0;
}

static int cdiff_cmd_xchg(const char *cmdstr, struct cdiff_ctx *ctx, char *lbuf, unsigned int lbuflen)
{
	char *arg, *arg2;
	struct cdiff_node *new;
	unsigned int lineno;

    UNUSEDPARAM(lbuf);
    UNUSEDPARAM(lbuflen);


    if(!(arg = cdiff_token(cmdstr, 1, 0))) {
	logg("!cdiff_cmd_xchg: Can't get first argument\n");
	return -1;
    }
    lineno = (unsigned int) atoi(arg);
    free(arg);

    if(!(arg = cdiff_token(cmdstr, 2, 0))) {
	logg("!cdiff_cmd_xchg: Can't get second argument\n");
	return -1;
    }

    if(!(arg2 = cdiff_token(cmdstr, 3, 1))) {
	free(arg);
	logg("!cdiff_cmd_xchg: Can't get second argument\n");
	return -1;
    }

    new = (struct cdiff_node *) calloc(1, sizeof(struct cdiff_node));
    if(!new) {
	logg("!cdiff_cmd_xchg: Can't allocate memory for cdiff_node\n");
	free(arg);
	free(arg2);
	return -1;
    }
    new->str = arg;
    new->str2 = arg2;
    new->lineno = lineno;

    if(!ctx->xchg_start)
	ctx->xchg_start = new;
    else
	ctx->xchg_last->next = new;

    ctx->xchg_last = new;
    return 0;
}

static int cdiff_cmd_close(const char *cmdstr, struct cdiff_ctx *ctx, char *lbuf, unsigned int lbuflen)
{
	struct cdiff_node *add, *del, *xchg;
	unsigned int lines = 0;
	char *tmp;
	FILE *fh, *tmpfh;

    UNUSEDPARAM(cmdstr);


    if(!ctx->open_db) {
	logg("!cdiff_cmd_close: No database to close\n");
	return -1;
    }

    add = ctx->add_start;
    del = ctx->del_start;
    xchg = ctx->xchg_start;

    if(del || xchg) {

	if(!(fh = fopen(ctx->open_db, "rb"))) {
	    logg("!cdiff_cmd_close: Can't open file %s for reading\n", ctx->open_db);
	    return -1;
	}

	if(!(tmp = cli_gentemp("."))) {
	    logg("!cdiff_cmd_close: Can't generate temporary name\n");
	    fclose(fh);
	    return -1;
	}

	if(!(tmpfh = fopen(tmp, "wb"))) {
	    logg("!cdiff_cmd_close: Can't open file %s for writing\n", tmp);
	    fclose(fh);
	    free(tmp);
	    return -1;
	}

	while(fgets(lbuf, lbuflen, fh)) {
	    lines++;

	    if(del && del->lineno == lines) {
		if(strncmp(lbuf, del->str, strlen(del->str))) {
		    fclose(fh);
		    fclose(tmpfh);
		    unlink(tmp);
		    free(tmp);
		    logg("!cdiff_cmd_close: Can't apply DEL at line %d of %s\n", lines, ctx->open_db);
		    return -1;
		}
		del = del->next;
		continue;
	    }

	    if(xchg && xchg->lineno == lines) {
		if(strncmp(lbuf, xchg->str, strlen(xchg->str))) {
		    fclose(fh);
		    fclose(tmpfh);
		    unlink(tmp);
		    free(tmp);
		    logg("!cdiff_cmd_close: Can't apply XCHG at line %d of %s\n", lines, ctx->open_db);
		    return -1;
		}

		if(fputs(xchg->str2, tmpfh) == EOF || fputc('\n', tmpfh) == EOF) {
		    fclose(fh);
		    fclose(tmpfh);
		    unlink(tmp);
		    logg("!cdiff_cmd_close: Can't write to %s\n", tmp);
		    free(tmp);
		    return -1;
		}
		xchg = xchg->next;
		continue;
	    }

	    if(fputs(lbuf, tmpfh) == EOF) {
		fclose(fh);
		fclose(tmpfh);
		unlink(tmp);
		logg("!cdiff_cmd_close: Can't write to %s\n", tmp);
		free(tmp);
		return -1;
	    }
	}

	fclose(fh);
	fclose(tmpfh);

	if(del || xchg) {
	    logg("!cdiff_cmd_close: Not all DEL/XCHG have been executed\n");
	    unlink(tmp);
	    free(tmp);
	    return -1;
	}

	if(unlink(ctx->open_db) == -1) {
	    logg("!cdiff_cmd_close: Can't unlink %s\n", ctx->open_db);
	    unlink(tmp);
	    free(tmp);
	    return -1;
	}

	if(rename(tmp, ctx->open_db) == -1) {
	    logg("!cdiff_cmd_close: Can't rename %s to %s\n", tmp, ctx->open_db);
	    unlink(tmp);
	    free(tmp);
	    return -1;
	}

	free(tmp);
    }

    if(add) {

	if(!(fh = fopen(ctx->open_db, "ab"))) {
	    logg("!cdiff_cmd_close: Can't open file %s for appending\n", ctx->open_db);
	    return -1;
	}

	while(add) {
	    if(fputs(add->str, fh) == EOF || fputc('\n', fh) == EOF) {
		fclose(fh);
		logg("!cdiff_cmd_close: Can't write to %s\n", ctx->open_db);
		return -1;
	    }
	    add = add->next;
	}

	fclose(fh);
    }

    cdiff_ctx_free(ctx);

    return 0;
}

static int cdiff_cmd_move(const char *cmdstr, struct cdiff_ctx *ctx, char *lbuf, unsigned int lbuflen)
{
	unsigned int lines = 0, start_line, end_line;
	char *arg, *srcdb, *dstdb, *tmpdb, *start_str, *end_str;
	FILE *src, *dst, *tmp;


    if(ctx->open_db) {
	logg("!cdiff_cmd_move: Database %s is still open\n", ctx->open_db);
	return -1;
    }

    if(!(arg = cdiff_token(cmdstr, 3, 0))) {
	logg("!cdiff_cmd_move: Can't get third argument\n");
	return -1;
    }
    start_line = atoi(arg);
    free(arg);

    if(!(arg = cdiff_token(cmdstr, 5, 0))) {
	logg("!cdiff_cmd_move: Can't get fifth argument\n");
	return -1;
    }
    end_line = atoi(arg);
    free(arg);

    if(end_line < start_line) {
	logg("!cdiff_cmd_move: end_line < start_line\n");
	return -1;
    }

    if(!(start_str = cdiff_token(cmdstr, 4, 0))) {
	logg("!cdiff_cmd_move: Can't get fourth argument\n");
	return -1;
    }

    if(!(end_str = cdiff_token(cmdstr, 6, 0))) {
	logg("!cdiff_cmd_move: Can't get sixth argument\n");
	free(start_str);
	return -1;
    }

    if(!(srcdb = cdiff_token(cmdstr, 1, 0))) {
	logg("!cdiff_cmd_move: Can't get first argument\n");
	free(start_str);
	free(end_str);
	return -1;
    }

    if(!(src = fopen(srcdb, "rb"))) {
	logg("!cdiff_cmd_move: Can't open %s for reading\n", srcdb);
	free(start_str);
	free(end_str);
	free(srcdb);
	return -1;
    }

    if(!(dstdb = cdiff_token(cmdstr, 2, 0))) {
	logg("!cdiff_cmd_move: Can't get second argument\n");
	free(start_str);
	free(end_str);
	free(srcdb);
	fclose(src);
	return -1;
    }

    if(!(dst = fopen(dstdb, "ab"))) {
	logg("!cdiff_cmd_move: Can't open %s for appending\n", dstdb);
	free(start_str);
	free(end_str);
	free(srcdb);
	fclose(src);
	free(dstdb);
	return -1;
    }

    if(!(tmpdb = cli_gentemp("."))) {
	logg("!cdiff_cmd_move: Can't generate temporary name\n");
	free(start_str);
	free(end_str);
	free(srcdb);
	fclose(src);
	free(dstdb);
	fclose(dst);
	return -1;
    }

    if(!(tmp = fopen(tmpdb, "wb"))) {
	logg("!cdiff_cmd_move: Can't open file %s for writing\n", tmpdb);
	free(start_str);
	free(end_str);
	free(srcdb);
	fclose(src);
	free(dstdb);
	fclose(dst);
	free(tmpdb);
	return -1;
    }

    while(fgets(lbuf, lbuflen, src)) {
	lines++;

	if(lines == start_line) {
	    if(strncmp(lbuf, start_str, strlen(start_str))) {
		free(start_str);
		free(end_str);
		free(srcdb);
		fclose(src);
		free(dstdb);
		fclose(dst);
		fclose(tmp);
		unlink(tmpdb);
		free(tmpdb);
		logg("!cdiff_cmd_close: Can't apply MOVE due to conflict at line %d\n", lines);
		return -1;
	    }

	    do {
		if(fputs(lbuf, dst) == EOF) {
		    free(start_str);
		    free(end_str);
		    free(srcdb);
		    fclose(src);
		    fclose(dst);
		    fclose(tmp);
		    unlink(tmpdb);
		    free(tmpdb);
		    logg("!cdiff_cmd_move: Can't write to %s\n", dstdb);
		    free(dstdb);
		    return -1;
		}
	    } while((lines < end_line) && fgets(lbuf, lbuflen, src) && lines++);

	    fclose(dst);
	    dst = NULL;
	    free(dstdb);
	    free(start_str);

	    if(strncmp(lbuf, end_str, strlen(end_str))) {
		free(end_str);
		free(srcdb);
		fclose(src);
		fclose(tmp);
		unlink(tmpdb);
		free(tmpdb);
		logg("!cdiff_cmd_close: Can't apply MOVE due to conflict at line %d\n", lines);
		return -1;
	    }

	    free(end_str);
	    continue;
	}

	if(fputs(lbuf, tmp) == EOF) {
	    if(dst) {
		fclose(dst);
		free(dstdb);
		free(start_str);
		free(end_str);
	    }
	    free(srcdb);
	    fclose(src);
	    fclose(tmp);
	    unlink(tmpdb);
	    logg("!cdiff_cmd_move: Can't write to %s\n", tmpdb);
	    free(tmpdb);
	    return -1;
	}
    }

    fclose(src);
    fclose(tmp);

    if(dst) {
	fclose(dst);
	free(start_str);
	free(end_str);
	unlink(tmpdb);
	free(tmpdb);
	logg("!cdiff_cmd_move: No data was moved from %s to %s\n", srcdb, dstdb);
	free(srcdb);
	free(dstdb);
	return -1;
    }

    if(unlink(srcdb) == -1) {
	logg("!cdiff_cmd_move: Can't unlink %s\n", srcdb);
	free(srcdb);
	unlink(tmpdb);
	free(tmpdb);
	return -1;
    }

    if(rename(tmpdb, srcdb) == -1) {
	logg("!cdiff_cmd_move: Can't rename %s to %s\n", tmpdb, srcdb);
	free(srcdb);
	unlink(tmpdb);
	free(tmpdb);
	return -1;
    }

    free(srcdb);
    free(tmpdb);

    return 0;
}

static int cdiff_cmd_unlink(const char *cmdstr, struct cdiff_ctx *ctx, char *lbuf, unsigned int lbuflen)
{
	char *db;
	unsigned int i;

    UNUSEDPARAM(lbuf);
    UNUSEDPARAM(lbuflen);

    if(ctx->open_db) {
	logg("!cdiff_cmd_unlink: Database %s is still open\n", ctx->open_db);
	return -1;
    }

    if(!(db = cdiff_token(cmdstr, 1, 1))) {
	logg("!cdiff_cmd_unlink: Can't get first argument\n");
	return -1;
    }

    for(i = 0; i < strlen(db); i++) {
	if((db[i] != '.' && !isalnum(db[i])) || strchr("/\\", db[i])) {
	    logg("!cdiff_cmd_unlink: Forbidden characters found in database name\n");
	    free(db);
	    return -1;
	}
    }

    if(unlink(db) == -1) {
	logg("!cdiff_cmd_unlink: Can't unlink %s\n", db);
	free(db);
	return -1;
    }

    free(db);
    return 0;
}

static int cdiff_execute(const char *cmdstr, struct cdiff_ctx *ctx, char *lbuf, unsigned int lbuflen)
{
	char *cmd_name, *tmp;
	int (*cmd_handler)(const char *, struct cdiff_ctx *, char *, unsigned int) = NULL;
	unsigned int i;


    cmd_name = cdiff_token(cmdstr, 0, 0);
    if(!cmd_name) {
	logg("!cdiff_apply: Problem parsing line\n");
	return -1;
    }

    for(i = 0; commands[i].name; i++) {
	if(!strcmp(commands[i].name, cmd_name)) {
	    cmd_handler = commands[i].handler;
	    break;
	}
    }

    if(!cmd_handler) {
	logg("!cdiff_apply: Unknown command %s\n", cmd_name);
	free(cmd_name);
	return -1;
    }

    if(!(tmp = cdiff_token(cmdstr, commands[i].argc, 1))) {
	logg("!cdiff_apply: Not enough arguments for %s\n", cmd_name);
	free(cmd_name);
	return -1;
    }
    free(tmp);

    if(cmd_handler(cmdstr, ctx, lbuf, lbuflen)) {
	logg("!cdiff_apply: Can't execute command %s\n", cmd_name);
	free(cmd_name);
	return -1;
    }

    free(cmd_name);
    return 0;
}

int cdiff_apply(int fd, unsigned short mode)
{
	struct cdiff_ctx ctx;
	FILE *fh;
	gzFile gzh;
	char *line, *lbuf, buff[FILEBUFF], *dsig = NULL;
	unsigned int lines = 0, cmds = 0;
	unsigned int difflen, diffremain, line_size = CDIFF_LINE_SIZE;
	int end, i, n;
	struct stat sb;
	int desc;
	EVP_MD_CTX *sha256ctx;
	unsigned char digest[32];
	int sum, bread;
#define DSIGBUFF 350

    memset(&ctx, 0, sizeof(ctx));

    if((desc = dup(fd)) == -1) {
	logg("!cdiff_apply: Can't duplicate descriptor %d\n", fd);
	return -1;
    }

    if(!(line = malloc(line_size))) {
	logg("!cdiff_apply: Can't allocate memory for 'line'\n");
	close(desc);
	return -1;
    }

    if(!(lbuf = malloc(line_size))) {
	logg("!cdiff_apply: Can't allocate memory for 'lbuf'\n");
	close(desc);
	free(line);
	return -1;
    }

    if(mode == 1) { /* .cdiff */

	if(lseek(desc, -DSIGBUFF, SEEK_END) == -1) {
	    logg("!cdiff_apply: lseek(desc, %d, SEEK_END) failed\n", -DSIGBUFF);
	    close(desc);
	    free(line);
	    free(lbuf);
	    return -1;
	}

	memset(line, 0, line_size);
	if(read(desc, line, DSIGBUFF) != DSIGBUFF) {
	    logg("!cdiff_apply: Can't read %d bytes\n", DSIGBUFF);
	    close(desc);
	    free(line);
	    free(lbuf);
	    return -1;
	}

	for(i = DSIGBUFF - 1; i >= 0; i--) {
	    if(line[i] == ':') {
		dsig = &line[i + 1];
		break;
	    }
	}

	if(!dsig) {
	    logg("!cdiff_apply: No digital signature in cdiff file\n");
	    close(desc);
	    free(line);
	    free(lbuf);
	    return -1;
	}

	if(fstat(desc, &sb) == -1) {
	    logg("!cdiff_apply: Can't fstat file\n");
	    close(desc);
	    free(line);
	    free(lbuf);
	    return -1;
	}

	end = sb.st_size - (DSIGBUFF - i);
	if(end < 0) {
	    logg("!cdiff_apply: compressed data end offset < 0\n");
	    close(desc);
	    free(line);
	    free(lbuf);
	    return -1;
	}

	if(lseek(desc, 0, SEEK_SET) == -1) {
	    logg("!cdiff_apply: lseek(desc, 0, SEEK_SET) failed\n");
	    close(desc);
	    free(line);
	    free(lbuf);
	    return -1;
	}

    sha256ctx = EVP_MD_CTX_create();
    if (!(sha256ctx)) {
        close(desc);
        free(line);
        free(lbuf);
        return -1;
    }

	EVP_DigestInit_ex(sha256ctx, EVP_sha256(), NULL);
	sum = 0;
	while((bread = read(desc, buff, FILEBUFF)) > 0) {
	    if(sum + bread >= end) {
		EVP_DigestUpdate(sha256ctx, (unsigned char *) buff, end - sum);
		break;
	    } else {
		EVP_DigestUpdate(sha256ctx, (unsigned char *) buff, bread);
	    }
	    sum += bread;
	}
	EVP_DigestFinal_ex(sha256ctx, digest, NULL);
    EVP_MD_CTX_destroy(sha256ctx);

	if(cli_versig2(digest, dsig, PSS_NSTR, PSS_ESTR) != CL_SUCCESS) {
	    logg("!cdiff_apply: Incorrect digital signature\n");
	    close(desc);
	    free(line);
	    free(lbuf);
	    return -1;
	}

	if(lseek(desc, 0, SEEK_SET) == -1) {
	    logg("!cdiff_apply: lseek(desc, 0, SEEK_SET) failed\n");
	    close(desc);
	    free(line);
	    free(lbuf);
	    return -1;
	}

	i = 0;
	n = 0;
	while(n < FILEBUFF - 1 && read(desc, &buff[n], 1) > 0) {
	    if(buff[n++] == ':')
		if(++i == 3)
		    break;
	}
	buff[n] = 0;

	if(sscanf(buff, "ClamAV-Diff:%*u:%u:", &difflen) != 1) {
	    logg("!cdiff_apply: Incorrect file format\n");
	    close(desc);
	    free(line);
	    free(lbuf);
	    return -1;
	}

	if(!(gzh = gzdopen(desc, "rb"))) {
	    logg("!cdiff_apply: Can't gzdopen descriptor %d\n", desc);
	    close(desc);
	    free(line);
	    free(lbuf);
	    return -1;
	}

	diffremain = difflen;
	while(diffremain) {
	    unsigned int bufsize = diffremain < line_size ? diffremain + 1 : line_size;

	    if(!gzgets(gzh, line, bufsize)) {
		logg("!cdiff_apply: Premature EOF at line %d\n", lines + 1);
		cdiff_ctx_free(&ctx);
		gzclose(gzh);
		free(line);
		free(lbuf);
		return -1;
	    }
	    diffremain -= strlen(line);
	    lines++;
	    cli_chomp(line);

	    if(!strlen(line))
		continue;
	    if(line[0] == '#') {
		if(!strncmp(line, "#LSIZE", 6) && sscanf(line, "#LSIZE %u", &line_size) == 1) {
			char *r1, *r2;
		    if(line_size < CDIFF_LINE_SIZE || line_size > 10485760) {
			logg("^cdiff_apply: Ignoring new buffer size request - invalid size %d\n", line_size);
			line_size = CDIFF_LINE_SIZE;
			continue;
		    }
		    r1 = realloc(line, line_size);
		    r2 = realloc(lbuf, line_size);
		    if(!r1 || !r2) {
			logg("!cdiff_apply: Can't resize line buffer to %d bytes\n", line_size);
			cdiff_ctx_free(&ctx);
			gzclose(gzh);
			if(!r1 && !r2) {
			    free(line);
			    free(lbuf);
			} else if(!r1) {
			    free(line);
			    free(r2);
			} else {
			    free(r1);
			    free(lbuf);
			}
			return -1;
		    }
		    line = r1;
		    lbuf = r2;
		}
		continue;
	    }

	    if(cdiff_execute(line, &ctx, lbuf, line_size) == -1) {
		logg("!cdiff_apply: Error executing command at line %d\n", lines);
		cdiff_ctx_free(&ctx);
		gzclose(gzh);
		free(line);
		free(lbuf);
		return -1;
	    } else {
		cmds++;
	    }
	}
	gzclose(gzh);

    } else { /* .script */

	if(!(fh = fdopen(desc, "rb"))) {
	    logg("!cdiff_apply: fdopen() failed for descriptor %d\n", desc);
	    close(desc);
	    free(line);
	    free(lbuf);
	    return -1;
	}

	while(fgets(line, line_size, fh)) {
	    lines++;
	    cli_chomp(line);

	    if(!strlen(line))
		continue;
	    if(line[0] == '#') {
		if(!strncmp(line, "#LSIZE", 6) && sscanf(line, "#LSIZE %u", &line_size) == 1) {
			char *r1, *r2;
		    if(line_size < CDIFF_LINE_SIZE || line_size > 10485760) {
			logg("^cdiff_apply: Ignoring new buffer size request - invalid size %d\n", line_size);
			line_size = CDIFF_LINE_SIZE;
			continue;
		    }
		    r1 = realloc(line, line_size);
		    r2 = realloc(lbuf, line_size);
		    if(!r1 || !r2) {
			logg("!cdiff_apply: Can't resize line buffer to %d bytes\n", line_size);
			cdiff_ctx_free(&ctx);
			fclose(fh);
			if(!r1 && !r2) {
			    free(line);
			    free(lbuf);
			} else if(!r1) {
			    free(line);
			    free(r2);
			} else {
			    free(r1);
			    free(lbuf);
			}
			return -1;
		    }
		    line = r1;
		    lbuf = r2;
		}
		continue;
	    }

	    if(cdiff_execute(line, &ctx, lbuf, line_size) == -1) {
		logg("!cdiff_apply: Error executing command at line %d\n", lines);
		cdiff_ctx_free(&ctx);
		fclose(fh);
		free(line);
		free(lbuf);
		return -1;
	    } else {
		cmds++;
	    }
	}

	fclose(fh);
    }

    free(line);
    free(lbuf);

    if(ctx.open_db) {
	logg("*cdiff_apply: File %s was not properly closed\n", ctx.open_db);
	cdiff_ctx_free(&ctx);
	return -1;
    }

    logg("*cdiff_apply: Parsed %d lines and executed %d commands\n", lines, cmds);
    return 0;
}

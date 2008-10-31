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

#include "shared/misc.h"
#include "shared/output.h"
#include "shared/cdiff.h"
#include "shared/sha256.h"

#include "libclamav/str.h"
#include "libclamav/others.h"
#include "libclamav/cvd.h"

#include "zlib.h"

#ifdef HAVE_LIBGMP
#include "libclamav/dsig.h"

#define PSS_NSTR "14783905874077467090262228516557917570254599638376203532031989214105552847269687489771975792123442185817287694951949800908791527542017115600501303394778618535864845235700041590056318230102449612217458549016089313306591388590790796515819654102320725712300822356348724011232654837503241736177907784198700834440681124727060540035754699658105895050096576226753008596881698828185652424901921668758326578462003247906470982092298106789657211905488986281078346361469524484829559560886227198091995498440676639639830463593211386055065360288422394053998134458623712540683294034953818412458362198117811990006021989844180721010947"
#define PSS_ESTR "100002053"
#define PSS_NBITS 2048
#define PSS_DIGEST_LENGTH 32
#endif /* HAVE_LIBGMP */

struct cdiff_node {
    unsigned int lineno;
    char *str, *str2;
    struct cdiff_node *next;
};

struct cdiff_ctx {
    char *open_db;
    struct cdiff_node *add_start, *add_last;
    struct cdiff_node *del_start;
    struct cdiff_node *xchg_start;
};

struct cdiff_cmd {
    const char *name;
    unsigned short argc;
    int (*handler)(const char *, struct cdiff_ctx *);
};

static int cdiff_cmd_open(const char *cmdstr, struct cdiff_ctx *ctx);
static int cdiff_cmd_add(const char *cmdstr, struct cdiff_ctx *ctx);
static int cdiff_cmd_del(const char *cmdstr, struct cdiff_ctx *ctx);
static int cdiff_cmd_xchg(const char *cmdstr, struct cdiff_ctx *ctx);
static int cdiff_cmd_close(const char *cmdstr, struct cdiff_ctx *ctx);
static int cdiff_cmd_move(const char *cmdstr, struct cdiff_ctx *ctx);
static int cdiff_cmd_unlink(const char *cmdstr, struct cdiff_ctx *ctx);

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

static int cdiff_cmd_open(const char *cmdstr, struct cdiff_ctx *ctx)
{
	char *db;
	unsigned int i;


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

static int cdiff_cmd_add(const char *cmdstr, struct cdiff_ctx *ctx)
{
	char *sig;
	struct cdiff_node *new;


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

static int cdiff_cmd_del(const char *cmdstr, struct cdiff_ctx *ctx)
{
	char *arg;
	struct cdiff_node *pt, *last, *new;
	unsigned int lineno;


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

static int cdiff_cmd_xchg(const char *cmdstr, struct cdiff_ctx *ctx)
{
	char *arg, *arg2;
	struct cdiff_node *pt, *last, *new;
	unsigned int lineno;


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

    if(!ctx->xchg_start) {

	ctx->xchg_start = new;

    } else { 

	if(lineno < ctx->xchg_start->lineno) {
	    new->next = ctx->xchg_start;
	    ctx->xchg_start = new;

	} else {
	    pt = ctx->xchg_start;

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

static int cdiff_cmd_close(const char *cmdstr, struct cdiff_ctx *ctx)
{
	struct cdiff_node *add, *del, *xchg;
	unsigned int lines = 0;
	char *tmp, line[1024];
	FILE *fh, *tmpfh;


    if(!ctx->open_db) {
	logg("!cdiff_cmd_close: No database to close\n");
	return -1;
    }

    add = ctx->add_start;
    del = ctx->del_start;
    xchg = ctx->xchg_start;

    if(del || xchg) {

	if(!(fh = fopen(ctx->open_db, "r"))) {
	    logg("!cdiff_cmd_close: Can't open file %s for reading\n", ctx->open_db);
	    return -1;
	}

	if(!(tmp = cli_gentemp("."))) {
	    logg("!cdiff_cmd_close: Can't generate temporary name\n");
	    fclose(fh);
	    return -1;
	}

	if(!(tmpfh = fopen(tmp, "w"))) {
	    logg("!cdiff_cmd_close: Can't open file %s for writing\n", tmp);
	    fclose(fh);
	    free(tmp);
	    return -1;
	}

	while(fgets(line, sizeof(line), fh)) {
	    lines++;

	    if(del && del->lineno == lines) {
		if(strncmp(line, del->str, strlen(del->str))) {
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
		if(strncmp(line, xchg->str, strlen(xchg->str))) {
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

	    if(fputs(line, tmpfh) == EOF) {
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

	if(!(fh = fopen(ctx->open_db, "a"))) {
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

static int cdiff_cmd_move(const char *cmdstr, struct cdiff_ctx *ctx)
{
	unsigned int lines = 0, start_line, end_line;
	char *arg, *srcdb, *dstdb, *tmpdb, line[1024], *start_str, *end_str;
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

    if(!(src = fopen(srcdb, "r"))) {
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

    if(!(dst = fopen(dstdb, "a"))) {
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

    if(!(tmp = fopen(tmpdb, "w"))) {
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

    while(fgets(line, sizeof(line), src)) {
	lines++;

	if(lines == start_line) {
	    if(strncmp(line, start_str, strlen(start_str))) {
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
		if(fputs(line, dst) == EOF) {
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
	    } while((lines < end_line) && fgets(line, sizeof(line), src) && lines++);

	    fclose(dst);
	    free(dstdb);
	    dstdb = NULL;
	    free(start_str);

	    if(strncmp(line, end_str, strlen(end_str))) {
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

	if(fputs(line, tmp) == EOF) {
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

    if(dstdb) {
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

static int cdiff_cmd_unlink(const char *cmdstr, struct cdiff_ctx *ctx)
{
	char *db;
	unsigned int i;


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

static int cdiff_execute(const char *cmdstr, struct cdiff_ctx *ctx)
{
	char *cmd_name, *tmp;
	int (*cmd_handler)(const char *, struct cdiff_ctx *) = NULL;
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

    if(cmd_handler(cmdstr, ctx)) {
	logg("!cdiff_apply: Can't execute command %s\n", cmd_name);
	free(cmd_name);
	return -1;
    }

    free(cmd_name);
    return 0;
}

#ifdef HAVE_LIBGMP
static void pss_mgf(unsigned char *in, unsigned int inlen, unsigned char *out, unsigned int outlen)
{
	SHA256_CTX ctx;
	unsigned int i, laps;
	unsigned char cnt[4], digest[PSS_DIGEST_LENGTH];


    laps = (outlen + PSS_DIGEST_LENGTH - 1) / PSS_DIGEST_LENGTH;

    for(i = 0; i < laps; i++) {
	cnt[0] = (unsigned char) 0;
	cnt[1] = (unsigned char) 0;
	cnt[2] = (unsigned char) (i / 256);
	cnt[3] = (unsigned char) i;

	sha256_init(&ctx);
	sha256_update(&ctx, in, inlen);
	sha256_update(&ctx, cnt, sizeof(cnt));
	sha256_final(&ctx);
	sha256_digest(&ctx, digest);

	if(i != laps - 1)
	    memcpy(&out[i * PSS_DIGEST_LENGTH], digest, PSS_DIGEST_LENGTH);
	else
	    memcpy(&out[i * PSS_DIGEST_LENGTH], digest, outlen - i * PSS_DIGEST_LENGTH);
    }
}

static int pss_versig(const unsigned char *sha256, const char *dsig)
{
	mpz_t n, e;
	SHA256_CTX ctx;
	unsigned char *pt, digest1[PSS_DIGEST_LENGTH], digest2[PSS_DIGEST_LENGTH], *salt;
	unsigned int plen = PSS_NBITS / 8, hlen, slen, i;
	unsigned char dblock[PSS_NBITS / 8 - PSS_DIGEST_LENGTH - 1];
	unsigned char mblock[PSS_NBITS / 8 - PSS_DIGEST_LENGTH - 1];
	unsigned char fblock[8 + 2 * PSS_DIGEST_LENGTH];


    hlen = slen = PSS_DIGEST_LENGTH;
    mpz_init_set_str(n, PSS_NSTR, 10);
    mpz_init_set_str(e, PSS_ESTR, 10);

    if(!(pt = cli_decodesig(dsig, plen, e, n))) {
	mpz_clear(n);
	mpz_clear(e);
	return -1;
    }

    mpz_clear(n);
    mpz_clear(e);

    if(pt[plen - 1] != 0xbc) {
	/* cli_dbgmsg("cli_versigpss: Incorrect signature syntax (0xbc)\n"); */
	free(pt);
	return -1;
    }

    memcpy(mblock, pt, plen - hlen - 1);
    memcpy(digest2, &pt[plen - hlen - 1], hlen);
    free(pt);

    pss_mgf(digest2, hlen, dblock, plen - hlen - 1);

    for(i = 0; i < plen - hlen - 1; i++)
	dblock[i] ^= mblock[i];

    dblock[0] &= (0xff >> 1);

    salt = memchr(dblock, 0x01, sizeof(dblock));
    if(!salt) {
	/* cli_dbgmsg("cli_versigpss: Can't find salt\n"); */
	return -1;
    }
    salt++;

    if((unsigned int) (dblock + sizeof(dblock) - salt) != slen) {
	/* cli_dbgmsg("cli_versigpss: Bad salt size\n"); */
	return -1;
    }

    memset(fblock, 0, 8);
    memcpy(&fblock[8], sha256, hlen);
    memcpy(&fblock[8 + hlen], salt, slen);

    sha256_init(&ctx);
    sha256_update(&ctx, fblock, sizeof(fblock));
    sha256_final(&ctx);
    sha256_digest(&ctx, digest1);

    if(memcmp(digest1, digest2, hlen)) {
	/* cli_dbgmsg("cli_versigpss: Signature doesn't match.\n"); */
	return -1;
    }

    return 0;
}
#endif /* HAVE_LIBGMP */

int cdiff_apply(int fd, unsigned short mode)
{
	struct cdiff_ctx ctx;
	FILE *fh;
	gzFile *gzh;
	char line[1024], buff[FILEBUFF], *dsig = NULL;
	unsigned int lines = 0, cmds = 0;
	unsigned int difflen, diffremain;
	int end, i, n;
	struct stat sb;
	int desc;
#ifdef HAVE_LIBGMP
	SHA256_CTX sha256ctx;
	unsigned char digest[32];
	int sum, bread;
#endif
#define DSIGBUFF 350

    memset(&ctx, 0, sizeof(ctx));

    if((desc = dup(fd)) == -1) {
	logg("!cdiff_apply: Can't duplicate descriptor %d\n", fd);
	return -1;
    }

    if(mode == 1) { /* .cdiff */

	if(lseek(desc, -DSIGBUFF, SEEK_END) == -1) {
	    logg("!cdiff_apply: lseek(desc, %d, SEEK_END) failed\n", -DSIGBUFF);
	    close(desc);
	    return -1;
	}

	memset(line, 0, sizeof(line));
	if(read(desc, line, DSIGBUFF) != DSIGBUFF) {
	    logg("!cdiff_apply: Can't read %d bytes\n", DSIGBUFF);
	    close(desc);
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
	    return -1;
	}

	if(fstat(desc, &sb) == -1) {
	    logg("!cdiff_apply: Can't fstat file\n");
	    close(desc);
	    return -1;
	}

	end = sb.st_size - (DSIGBUFF - i);
	if(end < 0) {
	    logg("!cdiff_apply: compressed data end offset < 0\n");
	    close(desc);
	    return -1;
	}

	if(lseek(desc, 0, SEEK_SET) == -1) {
	    logg("!cdiff_apply: lseek(desc, 0, SEEK_SET) failed\n");
	    close(desc);
	    return -1;
	}

#ifdef HAVE_LIBGMP
	sha256_init(&sha256ctx);
	sum = 0;
	while((bread = read(desc, buff, FILEBUFF)) > 0) {
	    if(sum + bread >= end) {
		sha256_update(&sha256ctx, (unsigned char *) buff, end - sum);
		break;
	    } else {
		sha256_update(&sha256ctx, (unsigned char *) buff, bread);
	    }
	    sum += bread;
	}
	sha256_final(&sha256ctx);
	sha256_digest(&sha256ctx, digest);

	if(pss_versig(digest, dsig)) {
	    logg("!cdiff_apply: Incorrect digital signature\n");
	    close(desc);
	    return -1;
	}
#endif

	if(lseek(desc, 0, SEEK_SET) == -1) {
	    logg("!cdiff_apply: lseek(desc, 0, SEEK_SET) failed\n");
	    close(desc);
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
	    return -1;
	}

	if(!(gzh = gzdopen(desc, "rb"))) {
	    logg("!cdiff_apply: Can't gzdopen descriptor %d\n", desc);
	    close(desc);
	    return -1;
	}

	diffremain = difflen;
	while(diffremain) {
	    unsigned int bufsize = diffremain < sizeof(line) ? diffremain + 1 : sizeof(line);

	    if(!gzgets(gzh, line, bufsize)) {
		logg("!cdiff_apply: Premature EOF at line %d\n", lines + 1);
		cdiff_ctx_free(&ctx);
		gzclose(gzh);
		return -1;
	    }
	    diffremain -= strlen(line);
	    lines++;
	    cli_chomp(line);

	    if(line[0] == '#' || !strlen(line))
		continue;

	    if(cdiff_execute(line, &ctx) == -1) {
		logg("!cdiff_apply: Error executing command at line %d\n", lines);
		cdiff_ctx_free(&ctx);
		gzclose(gzh);
		return -1;
	    } else {
		cmds++;
	    }
	}
	gzclose(gzh);

    } else { /* .script */

	if(!(fh = fdopen(desc, "r"))) {
	    logg("!cdiff_apply: fdopen() failed for descriptor %d\n", desc);
	    close(desc);
	    return -1;
	}

	while(fgets(line, sizeof(line), fh)) {
	    lines++;
	    cli_chomp(line);

	    if(line[0] == '#' || !strlen(line))
		continue;

	    if(cdiff_execute(line, &ctx) == -1) {
		logg("!cdiff_apply: Error executing command at line %d\n", lines);
		cdiff_ctx_free(&ctx);
		fclose(fh);
		return -1;
	    } else {
		cmds++;
	    }
	}

	fclose(fh);
    }

    if(ctx.open_db) {
	logg("*cdiff_apply: File %s was not properly closed\n", ctx.open_db);
	cdiff_ctx_free(&ctx);
	return -1;
    }

    logg("*cdiff_apply: Parsed %d lines and executed %d commands\n", lines, cmds);
    return 0;
}

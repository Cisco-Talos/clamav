/*
 *  Copyright (C) 2006 Tomasz Kojm <tkojm@clamav.net>
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
#include <unistd.h>

#include "shared/memory.h"
#include "shared/misc.h"
#include "shared/output.h"

#include "libclamav/str.h"
#include "libclamav/others.h"
#include "libclamav/cvd.h"


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
    char *name;
    unsigned short argc;
    int (*handler)(const char *, struct cdiff_ctx *);
};

static int cdiff_cmd_open(const char *cmdstr, struct cdiff_ctx *ctx);
static int cdiff_cmd_add(const char *cmdstr, struct cdiff_ctx *ctx);
static int cdiff_cmd_del(const char *cmdstr, struct cdiff_ctx *ctx);
static int cdiff_cmd_xchg(const char *cmdstr, struct cdiff_ctx *ctx);
static int cdiff_cmd_close(const char *cmdstr, struct cdiff_ctx *ctx);
static int cdiff_cmd_move(const char *cmdstr, struct cdiff_ctx *ctx);

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

    { NULL, 0, NULL }
};

void cdiff_ctx_free(struct cdiff_ctx *ctx)
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

    buffer = mmalloc(j - i + 1);
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

    new = mcalloc(1, sizeof(struct cdiff_node));
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

    new = mcalloc(1, sizeof(struct cdiff_node));
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

    new = mcalloc(1, sizeof(struct cdiff_node));
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
		    logg("!cdiff_cmd_close: Can't apply DEL at line %d\n", lines);
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
		    logg("!cdiff_cmd_close: Can't apply XCHG at line %d\n", lines);
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

int cdiff_apply(int fd)
{
	struct cdiff_ctx ctx;
	FILE *fh;
	char line[1024], *cmd_name, *tmp;
	int (*cmd_handler)(const char *, struct cdiff_ctx *);
	unsigned int lines = 0, cmds = 0;
	int i, desc;


    if((desc = dup(fd)) == -1) {
	logg("!cdiff_apply: Can't duplicate descriptor %d\n", fd);
	return -1;
    }

    if(!(fh = fdopen(desc, "r"))) {
	logg("!cdiff_apply: fdopen() failed for descriptor %d\n", desc);
	close(desc);
	return -1;
    }

    memset(&ctx, 0, sizeof(ctx));

    while(fgets(line, sizeof(line), fh)) {
	lines++;
	cli_chomp(line);
	cmd_handler = NULL;

	if(line[0] == '#' || !strlen(line))
	    continue;

	cmd_name = cdiff_token(line, 0, 0);
	if(!cmd_name) {
	    logg("!cdiff_apply: Problem parsing line %d\n", lines);
	    fclose(fh);
	    cdiff_ctx_free(&ctx);
	    return -1;
	}

	for(i = 0; commands[i].name; i++) {
	    if(!strcmp(commands[i].name, cmd_name)) {
		cmd_handler = commands[i].handler;
		break;
	    }
	}

	if(!cmd_handler) {
	    logg("!cdiff_apply: Unknown command %s at line %d\n", cmd_name, lines);
	    free(cmd_name);
	    fclose(fh);
	    cdiff_ctx_free(&ctx);
	    return -1;
	}

	if(!(tmp = cdiff_token(line, commands[i].argc, 1))) {
	    logg("!cdiff_apply: Not enough arguments for %s at line %d\n", cmd_name, lines);
	    free(cmd_name);
	    fclose(fh);
	    cdiff_ctx_free(&ctx);
	    return -1;
	}
	free(tmp);

	if(cmd_handler(line, &ctx)) {
	    logg("!cdiff_apply: Can't execute command %s at line %d\n", cmd_name, lines);
	    fclose(fh);
	    free(cmd_name);
	    cdiff_ctx_free(&ctx);
	    return -1;
	} else {
	    cmds++;
	}

	free(cmd_name);
    }

    fclose(fh);

    if(ctx.open_db) {
	logg("*cdiff_apply: File %s was not properly closed\n", ctx.open_db);
	cdiff_ctx_free(&ctx);
	return -1;
    }

    logg("*cdiff_apply: Parsed %d lines and executed %d commands\n", lines, cmds);
    return 0;
}

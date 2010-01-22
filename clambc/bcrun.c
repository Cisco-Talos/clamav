/*
 *  ClamAV bytecode handler tool.
 *
 *  Copyright (C) 2009 Sourcefire, Inc.
 *
 *  Authors: Török Edvin
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
#include "cltypes.h"
#ifndef _WIN32
#include <sys/time.h>
#endif
#include <stdlib.h>
#include "bytecode.h"
#include "bytecode_priv.h"
#include "clamav.h"
#include "shared/optparser.h"
#include "shared/misc.h"

#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

static void help(void)
{
    printf("\n");
    printf("           Clam AntiVirus: Bytecode Testing Tool %s\n",
	   get_version());
    printf("           By The ClamAV Team: http://www.clamav.net/team\n");
    printf("           (C) 2009 Sourcefire, Inc.\n\n");
    printf("clambc <file> [function] [param1 ...]\n\n");
    printf("    --help                 -h         Show help\n");
    printf("    --version              -V         Show version\n");
    printf("    --trace <level>                   Set bytecode trace level 0..7 (default 7)\n");
    printf("    --no-trace-showsource             Don't show source line during tracing\n");
    printf("    file                              file to test\n");
    printf("\n");
    return;
}

static struct dbg_state {
    const char *directory;
    const char *file;
    const char *scope;
    uint32_t scopeid;
    unsigned line;
    unsigned col;
    unsigned showline;
} dbg_state;

static void tracehook(struct cli_bc_ctx *ctx, unsigned event)
{
    dbg_state.directory = ctx->directory;
    if (*ctx->file == '?')
	return;
    switch (event) {
	case trace_func:
	    fprintf(stderr, "[trace] %s:%u:%u -> %s:%u:%u Entered function %s\n",
		   dbg_state.file, dbg_state.line, dbg_state.col,
		   ctx->file, ctx->line, ctx->col, ctx->scope);
	    dbg_state.scope = ctx->scope;
	    break;
	case trace_param:
	    fprintf(stderr, "[trace] function parameter:\n");
	    return;
	case trace_scope:
	    fprintf(stderr, "[trace] %s:%u:%u -> %s:%u:%u\n",
		   dbg_state.file, dbg_state.line, dbg_state.col,
		   ctx->file, ctx->line, ctx->col);
	    dbg_state.scope = ctx->scope;
	    break;
	case trace_line:
	case trace_col:
	    if (dbg_state.showline)
		cli_bytecode_debug_printsrc(ctx);
	    else
		fprintf(stderr, "[trace] %s:%u:%u\n",
		       dbg_state.file, dbg_state.line, dbg_state.col);
	    break;
	default:
	    break;
    }
    dbg_state.file = ctx->file;
    dbg_state.line = ctx->line;
    dbg_state.col = ctx->col;
}

static void tracehook_op(struct cli_bc_ctx *ctx, const char *op)
{
    fprintf(stderr, "[trace] %s\n", op);
}

static void tracehook_val(struct cli_bc_ctx *ctx, const char *name, uint32_t value)
{
    fprintf(stderr, "[trace] %s = %u\n", name, value);
}

static void tracehook_ptr(struct cli_bc_ctx *ctx, const void *ptr)
{
    fprintf(stderr, "[trace] %p\n", ptr);
}

int main(int argc, char *argv[])
{
    FILE *f;
    struct cli_bc *bc;
    struct cli_bc_ctx *ctx;
    int rc, dbgargc;
    struct optstruct *opts;
    const struct optstruct *opt;
    unsigned funcid=0, i;
    struct cli_all_bc bcs;
    unsigned int fd = -1;
    unsigned tracelevel;

    opts = optparse(NULL, argc, argv, 1, OPT_CLAMBC, 0, NULL);
    if (!opts) {
	fprintf(stderr, "ERROR: Can't parse command line options\n");
	exit(1);
    }
    if(optget(opts, "version")->enabled) {
	printf("Clam AntiVirus Bytecode Testing Tool %s\n", get_version());
	cl_init(CL_INIT_DEFAULT);
	cli_bytecode_printversion();
	optfree(opts);
	exit(0);
    }
    if(optget(opts, "help")->enabled || !opts->filename) {
	optfree(opts);
	help();
	exit(0);
    }
    f = fopen(opts->filename[0], "r");
    if (!f) {
	fprintf(stderr, "Unable to load %s\n", argv[1]);
	optfree(opts);
	exit(2);
    }

    bc = malloc(sizeof(*bc));
    if (!bc) {
	fprintf(stderr, "Out of memory\n");
	optfree(opts);
	exit(3);
    }

    cl_debug();
    rc = cl_init(CL_INIT_DEFAULT);
    if (rc != CL_SUCCESS) {
	fprintf(stderr,"Unable to init libclamav: %s\n", cl_strerror(rc));
	optfree(opts);
	exit(4);
    }

    dbgargc=1;
    while (opts->filename[dbgargc]) dbgargc++;

    if (dbgargc > 1)
	cli_bytecode_debug(dbgargc, opts->filename);

    if (optget(opts, "force-interpreter")->enabled) {
	bcs.engine = NULL;
    } else {
	rc = cli_bytecode_init(&bcs);
	if (rc != CL_SUCCESS) {
	    fprintf(stderr,"Unable to init bytecode engine: %s\n", cl_strerror(rc));
	    optfree(opts);
	    exit(4);
	}
    }

    bcs.all_bcs = bc;
    bcs.count = 1;

    rc = cli_bytecode_load(bc, f, NULL, 0);
    if (rc != CL_SUCCESS) {
	fprintf(stderr,"Unable to load bytecode: %s\n", cl_strerror(rc));
	optfree(opts);
	exit(4);
    }

    rc = cli_bytecode_prepare(&bcs);
    if (rc != CL_SUCCESS) {
	fprintf(stderr,"Unable to prepare bytecode: %s\n", cl_strerror(rc));
	optfree(opts);
	exit(4);
    }
    fclose(f);

    printf("Bytecode loaded\n");
    if (optget(opts, "describe")->enabled) {
	cli_bytecode_describe(bc);
    } else {

	ctx = cli_bytecode_context_alloc();
	if (!ctx) {
	    fprintf(stderr,"Out of memory\n");
	    exit(3);
	}
	memset(&dbg_state, 0, sizeof(dbg_state));
	dbg_state.file = "<libclamav>";
	dbg_state.line = 0;
	dbg_state.col = 0;
	dbg_state.showline = !optget(opts, "no-trace-showsource")->enabled;
	tracelevel = optget(opts, "trace")->numarg;
	cli_bytecode_context_set_trace(ctx, tracelevel,
				       tracehook,
				       tracehook_op,
				       tracehook_val,
				       tracehook_ptr);

	if (opts->filename[1]) {
	    funcid = atoi(opts->filename[1]);
	}
	cli_bytecode_context_setfuncid(ctx, bc, funcid);
	printf("Running bytecode function :%u\n", funcid);

	if (opts->filename[1]) {
	    i=2;
	    while (opts->filename[i]) {
		rc = cli_bytecode_context_setparam_int(ctx, i-2, atoi(opts->filename[i]));
		if (rc != CL_SUCCESS) {
		    fprintf(stderr,"Unable to set param %u: %s\n", i-2, cl_strerror(rc));
		}
		i++;
	    }
	}

	if ((opt = optget(opts,"input"))->enabled) {
	    fmap_t *map;
	    fd = open(opt->strarg, O_RDONLY);
	    if (fd == -1) {
		fprintf(stderr, "Unable to open input file %s: %s\n", opt->strarg, strerror(errno));
		optfree(opts);
		exit(5);
	    }
	    map = fmap(fd, 0, 0);
	    if (!map) {
		fprintf(stderr, "Unable to map input file %s\n", opt->strarg);
	    }
	    rc = cli_bytecode_context_setfile(ctx, map);
	    if (rc != CL_SUCCESS) {
		fprintf(stderr, "Unable to set file %s: %s\n", opt->strarg, cl_strerror(rc));
		optfree(opts);
		exit(5);
	    }
	    funmap(map);
	}

	rc = cli_bytecode_run(&bcs, bc, ctx);
	if (rc != CL_SUCCESS) {
	    fprintf(stderr,"Unable to run bytecode: %s\n", cl_strerror(rc));
	} else {
	    uint64_t v;
	    printf("Bytecode run finished\n");
	    v = cli_bytecode_context_getresult_int(ctx);
	    printf("Bytecode returned: 0x%llx\n", (long long)v);
	}
	cli_bytecode_context_destroy(ctx);
    }
    cli_bytecode_destroy(bc);
    cli_bytecode_done(&bcs);
    free(bc);
    optfree(opts);
    if (fd != -1)
	close(fd);
    printf("Exiting\n");
    return 0;
}

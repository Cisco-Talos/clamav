/*
 *  ClamAV bytecode handler tool.
 *
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
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
#ifndef _WIN32
#include <sys/time.h>
#endif
#include <stdlib.h>

#include "bytecode.h"
#include "bytecode_priv.h"
#include "clamav.h"
#include "shared/optparser.h"
#include "shared/misc.h"
#include "libclamav/dconf.h"
#include "libclamav/others.h"

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
    printf("                       Clam AntiVirus: Bytecode Testing Tool %s\n", get_version());
    printf("           By The ClamAV Team: https://www.clamav.net/about.html#credits\n");
    printf("           (C) 2019 Cisco Systems, Inc.\n");
    printf("\n");
    printf("    clambc <file> [function] [param1 ...]\n");
    printf("\n");
    printf("    --help                 -h         Show this help\n");
    printf("    --version              -V         Show version\n");
    printf("    --debug                           Show debug\n");
    printf("    --force-interpreter    -f         Force using the interpreter instead of the JIT\n");
    printf("    --trust-bytecode       -t         Trust loaded bytecode (default yes)\n");
    printf("    --info                 -i         Print information about bytecode\n");
    printf("    --printsrc             -p         Print bytecode source\n");
    printf("    --printbcir            -c         Print IR of bytecode signature\n");
    printf("    --input                -c         Input file to run the bytecode on\n");
    printf("    --trace <level>        -T         Set bytecode trace level 0..7 (default 7)\n");
    printf("    --no-trace-showsource  -s         Don't show source line during tracing\n");
    printf("    --statistics=bytecode             Collect and print bytecode execution statistics\n");
    printf("    file                              File to test\n");
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
    UNUSEDPARAM(ctx);
    fprintf(stderr, "[trace] %s\n", op);
}

static void tracehook_val(struct cli_bc_ctx *ctx, const char *name, uint32_t value)
{
    UNUSEDPARAM(ctx);
    fprintf(stderr, "[trace] %s = %u\n", name, value);
}

static void tracehook_ptr(struct cli_bc_ctx *ctx, const void *ptr)
{
    UNUSEDPARAM(ctx);
    fprintf(stderr, "[trace] %p\n", ptr);
}

static uint8_t debug_flag = 0;
static void print_src(const char *file)
{
  char buf[4096];
  int nread, i, found = 0, lcnt = 0;
  FILE *f = fopen(file, "r");
  if (!f) {
    fprintf(stderr,"Unable to reopen %s\n", file);
    return;
  }
  do {
    nread = fread(buf, 1, sizeof(buf), f);
    for (i=0;i<nread-1;i++) {
      if (buf[i] == '\n') {
        lcnt++;
      }
      /* skip over the logical trigger */
      if (lcnt >= 2 && buf[i] == '\n' && buf[i+1] == 'S') {
        found = 1;
        i+=2;
        break;
      }
    }
  } while (!found && (nread == sizeof(buf)));
  if (debug_flag)
      printf("[clambc] Source code:");
  do {
    for (;i+1<nread;i++) {
      if (buf[i] == 'S' || buf[i] == '\n') {
        putc('\n', stdout);
        continue;
      }
      putc(((buf[i]&0xf) | ((buf[i+1]&0xf)<<4)), stdout);
      i++;
    }
    if (i == nread-1 && nread != 1)
	fseek(f, -1, SEEK_CUR);
    i=0;
    nread = fread(buf, 1, sizeof(buf), f);
  } while (nread > 0);
  fclose(f);
}
static uint32_t deadbeefcounts[64] = {
    0xdeadbeef,
    0,
    0xbeefdead,
    0,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
    0xdeadbeef,
};
int main(int argc, char *argv[])
{
    FILE *f;
    struct cli_bc *bc;
    struct cli_bc_ctx *ctx;
    int rc, dbgargc, bc_stats=0;
    struct optstruct *opts;
    const struct optstruct *opt;
    unsigned funcid=0, i;
    struct cli_all_bc bcs;
    int fd = -1;
    unsigned tracelevel;

    if(check_flevel())
	exit(1);

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

    if (optget(opts,"debug")->enabled) {
	cl_debug();
	debug_flag=1;
    }
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

    if((opt = optget(opts, "statistics"))->enabled) {
	while(opt) {
	    if (!strcasecmp(opt->strarg, "bytecode"))
		bc_stats=1;
	    opt = opt->nextarg;
        }
    }

    rc = cli_bytecode_load(bc, f, NULL, optget(opts, "trust-bytecode")->enabled, bc_stats);
    if (rc != CL_SUCCESS) {
	fprintf(stderr,"Unable to load bytecode: %s\n", cl_strerror(rc));
	optfree(opts);
	exit(4);
    }
    fclose(f);
    if (bc->state == bc_skip) {
	fprintf(stderr,"bytecode load skipped\n");
	exit(0);
    }
    if (debug_flag)
	printf("[clambc] Bytecode loaded\n");
    if (optget(opts, "info")->enabled) {
	cli_bytecode_describe(bc);
    } else if (optget(opts, "printsrc")->enabled) {
        print_src(opts->filename[0]);
    } else if (optget(opts, "printbcir")->enabled) {
        cli_bytetype_describe(bc);
        cli_bytevalue_describe(bc, 0);
        cli_bytefunc_describe(bc, 0);
    } else {
	cli_ctx cctx;
	struct cl_engine *engine = cl_engine_new();
	fmap_t *map = NULL;
	memset(&cctx, 0, sizeof(cctx));
	if (!engine) {
	    fprintf(stderr,"Unable to create engine\n");
	    optfree(opts);
	    exit(3);
	}
	rc = cl_engine_compile(engine);
	if (rc) {
	    fprintf(stderr,"Unable to compile engine: %s\n", cl_strerror(rc));
	    optfree(opts);
	    exit(4);
	}
	rc = cli_bytecode_prepare2(engine, &bcs, BYTECODE_ENGINE_MASK);
	if (rc != CL_SUCCESS) {
	    fprintf(stderr,"Unable to prepare bytecode: %s\n", cl_strerror(rc));
	    optfree(opts);
	    exit(4);
	}
	if (debug_flag)
	    printf("[clambc] Bytecode prepared\n");

	ctx = cli_bytecode_context_alloc();
	if (!ctx) {
	    fprintf(stderr,"Out of memory\n");
	    exit(3);
	}
	ctx->ctx = &cctx;
	cctx.engine = engine;
	cctx.fmap = cli_calloc(sizeof(fmap_t*), engine->maxreclevel+2);
	if (!cctx.fmap) {
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
	if (debug_flag)
	    printf("[clambc] Running bytecode function :%u\n", funcid);

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
	    fd = open(opt->strarg, O_RDONLY);
	    if (fd == -1) {
		fprintf(stderr, "Unable to open input file %s: %s\n", opt->strarg, strerror(errno));
		optfree(opts);
		exit(5);
	    }
	    map = fmap(fd, 0, 0);
	    if (!map) {
		fprintf(stderr, "Unable to map input file %s\n", opt->strarg);
		exit(5);
	    }
	    rc = cli_bytecode_context_setfile(ctx, map);
	    if (rc != CL_SUCCESS) {
		fprintf(stderr, "Unable to set file %s: %s\n", opt->strarg, cl_strerror(rc));
		optfree(opts);
		exit(5);
	    }
	}
	/* for testing */
	ctx->hooks.match_counts = deadbeefcounts;
	ctx->hooks.match_offsets = deadbeefcounts;
	rc = cli_bytecode_run(&bcs, bc, ctx);
	if (rc != CL_SUCCESS) {
	    fprintf(stderr,"Unable to run bytecode: %s\n", cl_strerror(rc));
	} else {
	    uint64_t v;
	    if (debug_flag)
		printf("[clambc] Bytecode run finished\n");
	    v = cli_bytecode_context_getresult_int(ctx);
	    if (debug_flag)
		printf("[clambc] Bytecode returned: 0x%llx\n", (long long)v);
	}
	cli_bytecode_context_destroy(ctx);
	if (map)
	    funmap(map);
	cl_engine_free(engine);
	free(cctx.fmap);
    }
    cli_bytecode_destroy(bc);
    cli_bytecode_done(&bcs);
    free(bc);
    optfree(opts);
    if (fd != -1)
	close(fd);
    if (debug_flag)
	printf("[clambc] Exiting\n");
    cl_cleanup_crypto();
    return 0;
}

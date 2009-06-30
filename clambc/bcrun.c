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
#include "bytecode.h"
#include "clamav.h"
#include "shared/optparser.h"
#include "shared/misc.h"

#include <stdlib.h>

static void help(void)
{
    printf("\n");
    printf("           Clam AntiVirus: Bytecode Test Tool %s\n", get_version());
    printf("           By The ClamAV Team: http://www.clamav.net/team\n");
    printf("           (C) 2009 Sourcefire, Inc.\n\n");
    printf("clambc <file>\n\n");
    printf("    --help                 -h         Show help\n");
    printf("    --version              -V         Show version\n");
    printf("    file                              file to test\n");
    printf("\n");
    return;
}

int main(int argc, char *argv[])
{
    FILE *f;
    struct cli_bc *bc;
    struct cli_bc_ctx *ctx;
    int rc;
    struct optstruct *opts;

    opts = optparse(NULL, argc, argv, 1, OPT_CLAMBC, 0, NULL);
    if (!opts) {
	fprintf(stderr, "ERROR: Can't parse command line options\n");
	exit(1);
    }
    if(optget(opts, "help")->enabled) {
	optfree(opts);
	help();
	exit(0);
    }
    if(optget(opts, "version")->enabled) {
	printf("Clam AntiVirus Monitoring Tool %s\n", get_version());
	optfree(opts);
	exit(0);
    }
    f = fopen(argv[1], "r");
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
    rc = cli_bytecode_load(bc, f, NULL);
    if (rc != CL_SUCCESS) {
	fprintf(stderr,"Unable to load bytecode: %s\n", cl_strerror(rc));
	optfree(opts);
	exit(4);
    }
    fclose(f);

    printf("Bytecode loaded\n");
    ctx = cli_bytecode_alloc_context();
    if (!ctx) {
	fprintf(stderr,"Out of memory\n");
	exit(3);
    }

    printf("Running bytecode\n");
    cli_bytecode_run(bc, ctx);
    printf("Bytecode run finished\n");
    cli_bytecode_destroy_context(ctx);
    cli_bytecode_destroy(bc);
    free(bc);
    optfree(opts);
    return 0;
}

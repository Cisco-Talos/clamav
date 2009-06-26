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

#include <stdlib.h>

int main(int argc, char *argv[])
{
    FILE *f;
    struct cli_bc *bc;
    struct cli_bc_ctx *ctx;
    int rc;
    /* TODO: use optparser */
    if (argc != 2) {
	fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
	exit(1);
    }

    f = fopen(argv[1], "r");
    if (!f) {
	fprintf(stderr, "Unable to load %s\n", argv[1]);
	exit(2);
    }

    bc = malloc(sizeof(*bc));
    if (!bc) {
	fprintf(stderr, "Out of memory\n");
	exit(3);
    }

    cl_debug();
    rc = cli_bytecode_load(bc, f, NULL);
    if (rc != CL_SUCCESS) {
	fprintf(stderr,"Unable to load bytecode: %s\n", cl_strerror(rc));
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
    return 0;
}

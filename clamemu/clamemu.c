/*
 *  ClamAV bytecode emulator VMM
 *
 *  Copyright (C) 2011 Sourcefire, Inc.
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
#include "clamav.h"
#include "emulator.h"
#include "vmm.h"
#include "others.h"

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>

#ifndef O_BINARY
#define O_BINARY 0
#endif

static int emupe(struct cli_pe_hook_data *pedata, struct cli_exe_section *sections, int fd, const char **virname, void *context)
{
    emu_vmm_t *v;
    cli_emu_t *emu;
    cli_dbgmsg("emulating -----------------------------------------------------\n\n");
    v = cli_emu_vmm_new(pedata, sections, fd);
    if (!v)
	return -1;
    emu = cli_emulator_new(v, pedata);

    while (!cli_emulator_step(emu)) {
	cli_emulator_dbgstate(emu);
    }

    cli_emulator_free(emu);
    cli_emu_vmm_rebuild(v);
    cli_dbgmsg("emulation done ------------------------------------------------\n\n");
    cli_emu_vmm_free(v);
    return 0;
}

int main(int argc, char *argv[])
{
    unsigned ret;
    unsigned long size;
    long double mb;
    const char *virname;
    int rc;
    struct cl_engine *engine;
    int fd;

    /* TODO: use getopt */
    if (argc != 2) {
	fprintf(stderr,"usage: %s <file>\n", argv[0]);
	return 1;
    }

    fd = open(argv[1], O_RDONLY | O_BINARY);
    if (fd < 0) {
	perror("open");
	return 1;
    }
    do {
	unsigned options;

	rc = cl_init(CL_INIT_DEFAULT);
	if (rc)
	    break;
	engine = cl_engine_new();
	if (!engine) {
	    fprintf(stderr,"failed to create engine\n");
	    return 2;
	}

	/* build engine */
	rc = cl_engine_compile(engine);
	if (rc)
	    break;
	fprintf(stderr,"scanning %s\n", argv[1]);

	cli_set_pe_emulator(engine, emupe);

	/* scan file descriptor */
	size = 0;
	cl_debug();
	options = CL_SCAN_STDOPT &~ (CL_SCAN_HTML | CL_SCAN_ELF);
	ret = cl_scandesc_callback(fd, &virname, &size, engine, CL_SCAN_STDOPT, argv[1]);
	if (ret == CL_VIRUS) {
	    printf("malware found: %s\n", virname);
	} else if (ret == CL_CLEAN) {
	    printf("%s: CLEAN\n", argv[1]);
	} else {
	    rc = ret;
	    break;
	}
	rc = 0;
	mb = size * (CL_COUNT_PRECISION / 1024) / 1024.0;
    } while (0);
    if (engine)
	cl_engine_free(engine);
    close(fd);
    if (rc)
	fprintf(stderr, "libclamav error: %s\n", cl_strerror(rc));

    return rc;
}





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
#include <sys/time.h>

#ifndef O_BINARY
#define O_BINARY 0
#endif

#define MAXEMU 10000000

static int topfd;
static void spam_disasm(int fd, uint32_t ep, long len)
{
    char *data = cli_malloc(len);
    if (!data)
	return;
    len = pread(fd, data, len, ep);
    if (len > 0) {
    }
    free(data);
}

/* TODO: fmap this */

static int emupe(struct cli_pe_hook_data *pedata, struct cli_exe_section *sections, int fd, const char **virname, void *context)
{
    struct timeval tv0, tv1;
    unsigned long i = 0, delta;
    uint64_t speed;
    emu_vmm_t *v = NULL;
    cli_emu_t *emu;
    int rc, done = 0;
    jmp_buf seh_handler;
    uint32_t eip_save;

    if (fd != topfd)
	return 0;
    cli_dbgmsg("emulating -----------------------------------------------------\n\n");
    if (!setjmp(seh_handler))
	v = cli_emu_vmm_new(pedata, sections, fd, &seh_handler);
    else {
	fprintf(stderr,"exception raised during map_pages\n");
	cli_emu_vmm_free(v);
	v = NULL;
	exit(1);
    }

    if (!v)
	return -1;
    cli_dbgmsg("disasm dump ---\n");
    emu = cli_emulator_new(v, pedata);
    cli_emu_disasm(emu, 1024);
    cli_emulator_free(emu);
    cli_dbgmsg("disasm end ---\n");

    emu = cli_emulator_new(v, pedata);

    gettimeofday(&tv0, NULL);

    i = 0;
    cli_dbgmsg("emulation start ------------------------------------------------\n\n");
    do {
    if (!(rc = setjmp(seh_handler))) {
	for (;!cli_emulator_step(emu) && i < MAXEMU;i++) {
//		cli_emulator_dbgstate(emu);
	}
	done = 1;
    } else {
	i++;
	/* VMM raised exception */
	printf("emulator raised exception\n");
//        cli_emulator_dbgstate(emu);
	if (cli_emulator_seh(emu, rc) == -1) {
	    printf("no handler\n");
	    done = 1;
	}
    }
    } while(!done);
    gettimeofday(&tv1, NULL);

    cli_emu_vmm_rebuild(v);
    cli_emulator_free(emu);
    cli_dbgmsg("emulation done ------------------------------------------------\n\n");
    delta = (tv1.tv_sec - tv0.tv_sec)*1000000 + (tv1.tv_usec - tv0.tv_usec);
    if (!delta) delta = 1;
    speed = (uint64_t)i*1000000 / delta;
    printf("Emulated %lu instructions in %.3fms: %u instr/s\n", i,
	   delta/1000.0, (uint32_t) speed);

    cli_emu_vmm_free(v);
    exit(0);
    return 0;
}

int main(int argc, char *argv[])
{
    unsigned ret;
    unsigned long size;
    long double mb;
    const char *virname;
    int rc;
    struct cl_engine *engine = NULL;

    /* TODO: use getopt */
    if (argc != 2) {
	fprintf(stderr,"usage: %s <file>\n", argv[0]);
	return 1;
    }

    topfd = open(argv[1], O_RDONLY | O_BINARY);
    if (topfd < 0) {
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
	ret = cl_scandesc_callback(topfd, &virname, &size, engine, CL_SCAN_STDOPT, argv[1]);
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
    close(topfd);
    if (rc)
	fprintf(stderr, "libclamav error: %s\n", cl_strerror(rc));

    return rc;
}





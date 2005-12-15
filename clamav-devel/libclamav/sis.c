/*
 *  Copyright (C) 2005 Tomasz Kojm <tkojm@clamav.net>
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

#include "cltypes.h"
#include "clamav.h"
#include "others.h"
#include "sis.h"

#if WORDS_BIGENDIAN == 0
#define EC16(v)	(v)
#define EC32(v) (v)
#else
static inline uint16_t EC16(uint16_t v)
{
    return ((v >> 8) + (v << 8));
}

static inline uint32_t EC32(uint32_t v)
{
    return ((v >> 24) | ((v & 0x00FF0000) >> 8) | ((v & 0x0000FF00) << 8) | (v << 24));
}
#endif

extern short cli_leavetemps_flag;

static char *langcodes[] = {
    "",   "EN", "FR", "GE", "SP", "IT", "SW", "DA", "NO", "FI", "AM",
    "SF", "SG", "PO", "TU", "IC", "RU", "HU", "DU", "BL", "AU", "BG",
    "AS", "NZ", "IF", "CS", "SK", "PL", "SL", "TC", "HK", "ZH", "JA",
    "TH", "AF", "SQ", "AH", "AR", "HY", "TL", "BE", "BN", "BG", "MY",
    "CA", "HR", "CE", "IE", "SF", "ET", "FA", "CF", "GD", "KA", "EL",
    "CG", "GU", "HE", "HI", "IN", "GA", "SZ", "KN", "KK", "KM", "KO",
    "LO", "LV", "LT", "MK", "MS", "ML", "MR", "MO", "MN", "NN", "BP",
    "PA", "RO", "SR", "SI", "SO", "OS", "LS", "SH", "FS", "TA", "TE",
    "BO", "TI", "CT", "TK", "UK", "UR", "",   "VI", "CY", "ZU"
};

int cli_scansis(int desc, const char **virname, long int *scanned, const struct cl_engine *engine, const struct cl_limits *limits, unsigned int options, unsigned int arec, unsigned int mrec)
{
	struct sis_file_hdr file_hdr;
	struct sis_file_hdr6 file_hdr6;
	uint8_t release = 0;
	uint16_t opts, nlangs, *langrecs;
	char *langs;
	int i;


    if(read(desc, &file_hdr, sizeof(struct sis_file_hdr)) != sizeof(struct sis_file_hdr)) {
	cli_dbgmsg("SIS: Can't read file header\n"); /* Not a SIS file? */
	return CL_CLEAN;
    }

    if(EC32(file_hdr.uid3) != 0x10000419) {
	cli_dbgmsg("SIS: Not a SIS file\n");
	return CL_CLEAN;
    }

    switch(EC32(file_hdr.uid2)) {
	case 0x1000006d:
	    cli_dbgmsg("SIS: EPOC release 3, 4 or 5\n");
	    release = 3;
	    break;
	case 0x10003a12:
	    cli_dbgmsg("SIS: EPOC release 6\n");
	    release = 6;
	    break;
	default:
	    cli_warnmsg("SIS: Unknown value of UID 2 (EPOC release)\n");
    }

    /* TODO: Verify checksums (uid4 and checksum) */

    /* Languages */
    nlangs = EC16(file_hdr.nlangs);
    cli_dbgmsg("SIS: Number of languages: %d\n", nlangs);
    cli_dbgmsg("SIS: Offset of languages records: %d\n", EC32(file_hdr.plangs));

    if(nlangs && nlangs < 100) {
	if(lseek(desc, EC32(file_hdr.plangs), SEEK_SET) < 0) {
	    cli_errmsg("SIS: No language records\n");
	    return CL_EFORMAT;
	}

	langrecs = (uint16_t *) cli_malloc(nlangs * 2);

	if(read(desc, langrecs, nlangs * 2) != nlangs * 2) {
	    cli_errmsg("SIS: Can't read language records\n");
	    free(langrecs);
	    return CL_EFORMAT;
	}

	langs = (char *) cli_calloc(nlangs * 3 + 1, sizeof(char));
	for(i = 0; i < nlangs; i++) {
	    strncat(langs, langcodes[EC16(langrecs[i]) % 98], 2);
	    if(i != nlangs - 1)
		strncat(langs, " ", 1);
	}
	cli_dbgmsg("SIS: Supported languages: %s\n", langs);
	free(langrecs);
	free(langs);
    }

    if(EC16(file_hdr.ilang))
	cli_dbgmsg("SIS: Installation language: %d\n", EC16(file_hdr.ilang));

    /* Files */
    cli_dbgmsg("SIS: Number of files: %d\n", EC16(file_hdr.nfiles));
    cli_dbgmsg("SIS: Offset of files records: %d\n", EC32(file_hdr.pfiles));


    /* Requisites */
    cli_dbgmsg("SIS: Number of requisites: %d\n", EC16(file_hdr.nreqs));
    cli_dbgmsg("SIS: Offset of requisites records: %d\n", EC32(file_hdr.preqs));


    /* Options flags */
    opts = EC16(file_hdr.options);
    cli_dbgmsg("SIS: Options:\n");
    if(opts & 0x0001)
	cli_dbgmsg("SIS:    * File is in Unicode format\n");
    if(opts & 0x0002)
	cli_dbgmsg("SIS:    * File is distributable\n");
    if(opts & 0x0008)
	cli_dbgmsg("SIS:    * Packed files are not compressed\n");
    else
	cli_dbgmsg("SIS:    * Packed files are compressed\n");
    if(opts & 0x0010)
	cli_dbgmsg("SIS:    * File installation shuts down all applications\n");

    /* Type flags */
    switch(EC16(file_hdr.type)) {
	case 0x0000:
	    cli_dbgmsg("SIS: Type: Contains an application\n");
	    break;
	case 0x0001:
	    cli_dbgmsg("SIS: Type: Contains a shared/system component\n");
	    break;
	case 0x0002:
	    cli_dbgmsg("SIS: Type: Contains an optional (selectable) component\n");
	    break;
	case 0x0003:
	    cli_dbgmsg("SIS: Type: Configures an existing application or service\n");
	    break;
	case 0x0004:
	    cli_dbgmsg("SIS: Type: Patches an existing component\n");
	    break;
	case 0x0005:
	    cli_dbgmsg("SIS: Type: Upgrades an existing component\n");
	    break;
	default:
	    cli_warnmsg("SIS: Unknown value of type\n");
    } 

    cli_dbgmsg("SIS: Major version: %d\n", EC16(file_hdr.majorver));
    cli_dbgmsg("SIS: Minor version: %d\n", EC16(file_hdr.minorver));

    if(release == 6) {

	lseek(desc, sizeof(struct sis_file_hdr), SEEK_SET);

	if(read(desc, &file_hdr6, sizeof(struct sis_file_hdr6)) != sizeof(struct sis_file_hdr6)) {
	    cli_dbgmsg("SIS: Can't read additional data of EPOC 6 file header\n"); /* Not a SIS file? */
	    return CL_EFORMAT;
	}

	cli_dbgmsg("SIS: Maximum space required: %d\n", EC32(file_hdr6.maxispace));
    }


    return CL_CLEAN;
}

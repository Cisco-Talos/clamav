/*
 *  Copyright (C) 2007-2014 Cisco Systems, Inc.
 *
 *  Authors: Tomasz Kojm
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

#ifndef __READDB_H
#define __READDB_H

#include "clamav.h"
#include "matcher.h"
#include "str.h"
#include "cltypes.h"
#include "cvd.h"

#define CLI_DBEXT(ext)				\
    (						\
	cli_strbcasestr(ext, ".db")    ||	\
	cli_strbcasestr(ext, ".db2")   ||	\
	cli_strbcasestr(ext, ".db3")   ||	\
	cli_strbcasestr(ext, ".hdb")   ||	\
	cli_strbcasestr(ext, ".hdu")   ||	\
	cli_strbcasestr(ext, ".fp")    ||	\
	cli_strbcasestr(ext, ".mdb")   ||	\
	cli_strbcasestr(ext, ".mdu")   ||	\
	cli_strbcasestr(ext, ".hsb")   ||	\
	cli_strbcasestr(ext, ".hsu")   ||	\
	cli_strbcasestr(ext, ".sfp")   ||	\
	cli_strbcasestr(ext, ".msb")   ||	\
	cli_strbcasestr(ext, ".msu")   ||	\
	cli_strbcasestr(ext, ".ndb")   ||	\
	cli_strbcasestr(ext, ".ndu")   ||	\
	cli_strbcasestr(ext, ".ldb")   ||	\
	cli_strbcasestr(ext, ".ldu")   ||	\
	cli_strbcasestr(ext, ".sdb")   ||	\
	cli_strbcasestr(ext, ".zmd")   ||	\
	cli_strbcasestr(ext, ".rmd")   ||	\
	cli_strbcasestr(ext, ".pdb")   ||	\
	cli_strbcasestr(ext, ".gdb")   ||	\
	cli_strbcasestr(ext, ".wdb")   ||	\
	cli_strbcasestr(ext, ".cbc")   ||	\
	cli_strbcasestr(ext, ".ftm")   ||	\
	cli_strbcasestr(ext, ".cfg")   ||	\
	cli_strbcasestr(ext, ".cvd")   ||	\
	cli_strbcasestr(ext, ".cld")   ||	\
	cli_strbcasestr(ext, ".cud")   ||	\
	cli_strbcasestr(ext, ".cdb")   ||	\
	cli_strbcasestr(ext, ".cat")   ||	\
	cli_strbcasestr(ext, ".crb")   ||	\
	cli_strbcasestr(ext, ".idb")   ||	\
	cli_strbcasestr(ext, ".ioc")		\
    )

char *cli_virname(char *virname, unsigned int official);

int cli_parse_add(struct cli_matcher *root, const char *virname, const char *hexsig, uint16_t rtype, uint16_t type, const char *offset, uint8_t target, const uint32_t *lsigid, unsigned int options);

int cli_load(const char *filename, struct cl_engine *engine, unsigned int *signo, unsigned int options, struct cli_dbio *dbio);

char *cli_dbgets(char *buff, unsigned int size, FILE *fs, struct cli_dbio *dbio);

int cli_initroots(struct cl_engine *engine, unsigned int options);

#endif

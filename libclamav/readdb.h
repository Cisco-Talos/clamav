/*
 *  Copyright (C) 2004 - 2005 Tomasz Kojm <tkojm@clamav.net>
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

#include <zlib.h>

#include "clamav.h"
#include "matcher.h"
#include "str.h"

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
	cli_strbcasestr(ext, ".ndb")   ||	\
	cli_strbcasestr(ext, ".ndu")   ||	\
	cli_strbcasestr(ext, ".sdb")   ||	\
	cli_strbcasestr(ext, ".zmd")   ||	\
	cli_strbcasestr(ext, ".rmd")   ||	\
	cli_strbcasestr(ext, ".pdb")   ||	\
	cli_strbcasestr(ext, ".wdb")   ||	\
	cli_strbcasestr(ext, ".ft")    ||	\
	cli_strbcasestr(ext, ".ign")   ||	\
	cli_strbcasestr(ext, ".cvd")   ||	\
	cli_strbcasestr(ext, ".cld")		\
    )


int cli_parse_add(struct cli_matcher *root, const char *virname, const char *hexsig, unsigned short type, const char *offset, unsigned short target);

int cli_initengine(struct cl_engine **engine, unsigned int options);

int cli_load(const char *filename, struct cl_engine **engine, unsigned int *signo, unsigned int options, gzFile *gzs, unsigned int gzrsize);

char *cli_dbgets(char *buff, unsigned int size, FILE *fs, gzFile *gzs, unsigned int *gzrsize);

#endif

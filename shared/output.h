/*
 *  Copyright (C) 2002 - 2004 Tomasz Kojm <tkojm@clamav.net>
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

#ifndef __OUTPUT_H
#define __OUTPUT_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdlib.h>
#include "cfgparser.h"

int mdprintf(int desc, const char *str, ...);

#ifdef __GNUC__
int logg(const char *str, ...)      __attribute__((format(printf, 1, 2)));
#else
int logg(const char *str, ...);
#endif

void logg_close(void);
extern short int logg_verbose, logg_lock, logg_time;
extern unsigned int logg_size;
extern const char *logg_file;

#if defined(USE_SYSLOG) && !defined(C_AIX)
extern short logg_syslog;
int logg_facility(const char *name);
#endif

#ifdef __GNUC__
void mprintf(const char *str, ...) __attribute__((format(printf, 1, 2)));
#else
void mprintf(const char *str, ...);
#endif

extern short int mprintf_disabled, mprintf_verbose, mprintf_quiet, mprintf_stdout;

#endif

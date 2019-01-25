/*
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Selim Menouar, Verene Houdebine
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

#ifndef __IDMEF_LOGGING_H_
#define __IDMEF_LOGGING_H_
#endif

#ifdef PRELUDE
int prelude_initialize_client(const char *analyzer_name);
#endif

void prelude_logging(const char *filename, const char *virname, const char *virhash, int virsize);


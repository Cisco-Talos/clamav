/*
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
#ifndef BC_FEATURES_H
#define BC_FEATURES_H

/* Compatibility for non-clang compilers */
#ifndef __has_feature
#define __has_feature(x) 0
#endif

#ifdef __has_feature(attribute_bounds)
#define EBOUNDS(fieldname) __attribute__((bounds(fieldname)))
#else
#define EBOUNDS(x)
#endif

#endif

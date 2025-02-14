/*
 *  Copyright (C) 2014-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 *  Author: Shawn Webb
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

#ifndef __LIBFRESHCLAM_H
#define __LIBFRESHCLAM_H

extern char hostid[37];

/**
 * @brief
 *
 * @return int
 */
int is_valid_hostid(void);

/**
 * @brief Get the hostid object
 *
 * @param cbdata
 * @return char*
 */
char *get_hostid(void *cbdata);

#endif //__LIBFRESHCLAM_H

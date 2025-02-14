/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
 *
 *  Authors: aCaB
 *
 *  These functions are actions that may be taken when a sample alerts.
 *  The user may wish to:
 *  - move file to destination directory.
 *  - copy file to destination directory.
 *  - remove (delete) the file.
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

#ifndef ACTIONS_H
#define ACTIONS_H

#include "optparser.h"

/**
 * @brief Callback function to perform the action requested when actsetup() was invoked.
 *
 * @param filename
 */
extern void (*action)(const char *);

/**
 * @brief Select the appropriate callback function based on the configuration options.
 *
 * @param opts Application configuration options.
 * @return int 0 if success.
 * @return int 1 if move or copy were selected but the destination directory does not exist.
 */
int actsetup(const struct optstruct *opts);

extern unsigned int notremoved, notmoved;

#endif

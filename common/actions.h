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

#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "clamav.h"
#include "optparser.h"

/**
 * @brief Opened source object used for quarantine I/O.
 *
 * The source owns scan_fd and any platform-specific handle state. Callers scan
 * scan_fd, then pass the same source to the selected action before closing it.
 */
typedef struct action_source {
    char *display_path;
    char *action_path;
    int scan_fd;
    STATBUF statbuf;
    bool has_stat;
#ifdef _WIN32
    void *handle;
    bool handle_can_delete;
#endif
} action_source_t;

/**
 * @brief Callback function to perform the action requested when actsetup() was invoked.
 *
 * @param source  Open source object that was submitted for scanning.
 */
extern void (*action)(const action_source_t *);

/**
 * @brief Initialize an action source to an empty closed state.
 *
 * @param source Source object to initialize.
 */
void action_source_init(action_source_t *source);

/**
 * @brief Open a path for scan and later quarantine action.
 *
 * @param display_path Original path to use for scan output.
 * @param source       Source object to populate.
 * @return cl_error_t  CL_SUCCESS if the source is open.
 */
cl_error_t action_source_open(const char *display_path, action_source_t *source);

/**
 * @brief Open a resolved path for scan and later quarantine action.
 *
 * @param display_path Original path to use for scan output.
 * @param open_path    Path to open for scan and quarantine action.
 * @param source       Source object to populate.
 * @return cl_error_t  CL_SUCCESS if the source is open.
 */
cl_error_t action_source_open_path(const char *display_path, const char *open_path, action_source_t *source);

/**
 * @brief Duplicate an existing descriptor for later quarantine action.
 *
 * @param display_path Original path to use for scan output.
 * @param fd           Existing descriptor for the scan target.
 * @param source       Source object to populate.
 * @return cl_error_t  CL_SUCCESS if the source is open.
 */
cl_error_t action_source_from_fd(const char *display_path, int fd, action_source_t *source);

/**
 * @brief Close and reset an action source.
 *
 * @param source Source object to close.
 */
void action_source_close(action_source_t *source);

/**
 * @brief Select the appropriate callback function based on the configuration options.
 *
 * @param opts Application configuration options.
 * @return int 0 if success.
 * @return int 1 if move or copy were selected but the destination directory does not exist.
 */
int actsetup(const struct optstruct *opts);

extern unsigned int notremoved, notmoved;

#ifndef _WIN32
int action_setup_quarantine_lock_at(int directory_fd, const char *directory_path, char **lockname_out);
#endif

#endif

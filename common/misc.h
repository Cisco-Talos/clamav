/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
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

#ifndef __MISC_H
#define __MISC_H
#ifndef _WIN32
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#endif
#include <stdbool.h>

#include "clamav.h"
#include "platform.h"
#include "optparser.h"
/* Maximum filenames under various systems - njh */
#ifndef NAME_MAX  /* e.g. Linux */
#ifdef MAXNAMELEN /* e.g. Solaris */
#define NAME_MAX MAXNAMELEN
#else
#ifdef FILENAME_MAX /* e.g. SCO */
#define NAME_MAX FILENAME_MAX
#endif
#endif
#endif

#ifdef HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#else
#define sd_listen_fds(u) 0
#define SD_LISTEN_FDS_START 3
#define sd_is_socket(f, a, s, l) 1
#endif

#include <limits.h>

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

#ifndef ADDR_LEN
#define ADDR_LEN 13
#endif

char *freshdbdir(void);
void print_version(const char *dbdir);
int check_flevel(void);
const char *filelist(const struct optstruct *opts, int *err);
int filecopy(const char *src, const char *dest);

#ifndef _WIN32
/*Returns 0 on success (only the child process returns.*/
int daemonize(void);

/*closes stdin, stdout, stderr.  This is called by daemonize, but not
 * daemonize_all_return.  Users of daemonize_all_return should call this
 * when initialization is complete.*/
int close_std_descriptors(void);

/*Returns the return value of fork.  All processes return */
int daemonize_all_return(void);

/*Parent waits for a SIGINT or the child process to exit.  If
 * it receives a SIGINT, it exits with exit code 0.  If the child
 * exits (error), it exits with the child process's exit code.
 *
 * @param user If user is supplied and this function is being called
 * as root, daemonize_parent_wait will change the parent process
 * to user before calling wait so that the child process can signal
 * the parent when it is time to exit.  The child process will still
 * return as root.
 *
 * @param log_file If user AND log_file are both supplied and this
 * function is being called as root, the ownership of log_file will
 * be changed to user.
 */
int daemonize_parent_wait(const char *const user, const char *const log_file);

/*Sends a SIGINT to the parent process.  It also closes stdin, stdout,
 * and stderr.*/
void daemonize_signal_parent(pid_t parentPid);

int drop_privileges(const char *const user, const char *const log_file);
#endif /* _WIN32 */

const char *get_version(void);
int match_regex(const char *filename, const char *pattern);
int cli_is_abspath(const char *path);
unsigned int countlines(const char *filename);

/* Checks if a virus database file or directory is older than 'days'. */
cl_error_t check_if_cvd_outdated(const char *path, long long days);

#endif

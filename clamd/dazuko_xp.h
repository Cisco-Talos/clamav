#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifdef CLAMUKO
/* DazukoXP. Allow cross platform file access control for 3rd-party applications.
   Written by John Ogness <jogness@antivir.de>

   Copyright (c) 2002, 2003, 2004 H+BEDV Datentechnik GmbH
   All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:

   1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

   3. Neither the name of Dazuko nor the names of its contributors may be used
   to endorse or promote products derived from this software without specific
   prior written permission.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
   ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
   LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
   CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
   SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
   ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
   POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef DAZUKO_XP_H
#define DAZUKO_XP_H

#define VERSION	"2.0.4-pre3"

#include "dazukoio_xp.h"

/* various requests */
#define SET_ACCESS_MASK		0
#define ADD_INCLUDE_PATH	1
#define ADD_EXCLUDE_PATH	2
#define REGISTER		3
#define REMOVE_ALL_PATHS	4
#define UNREGISTER		5
#define GET_AN_ACCESS		6
#define RETURN_AN_ACCESS	7

/* slot states */
#define	DAZUKO_FREE	0	/* the daemon is not ready */
#define	DAZUKO_READY	1	/* a daemon waits for something to do */
#define	DAZUKO_WAITING	2	/* a request is waiting to be served */
#define	DAZUKO_WORKING	3	/* daemon is currently in action */
#define	DAZUKO_DONE	4	/* daemon response is available */
#define	DAZUKO_BROKEN	5	/* invalid state (interrupt from ready,waiting) */

/* file types */
#define DAZUKO_NONE		0
#define DAZUKO_REGULAR		1
#define DAZUKO_DIRECTORY	2
#define DAZUKO_LINK		3


/*********************************************************
 * structures that MUST be implemented by platform-layer *
 *********************************************************/

/*
struct xp_file;
struct xp_mutex;
struct xp_atomic;
struct xp_file_struct;
struct xp_queue;
struct xp_rwlock;
struct xp_daemon_id;
*/


/******************************************
 * structures available to platform-layer *
 ******************************************/

struct event_properties
{
	int	thrown;

	int	flags;
	char	set_flags;
	int	mode;
	char	set_mode;
	int	uid;
	char	set_uid;
	int	pid;
	char	set_pid;
};

struct file_properties
{
	unsigned long	size;
	char		set_size;
	int		uid;
	char		set_uid;
	int		gid;
	char		set_gid;
	int		mode;
	char		set_mode;
	int		device_type;
	char		set_device_type;
	int		type;
	char		set_type;
};

struct dazuko_file_listnode
{
	char				*filename;
	int				filename_length;
	struct dazuko_file_listnode	*next;
};

struct dazuko_file_struct
{
	/* A structure designed for simple and
	 * intelligent memory management when
	 * doing filename lookups in the kernel. */

	int				should_scan;		/* already know we need to scan? */
	char				*filename;		/* filename to report (pointer in alias list) */
	int				filename_length;	/* length of filename reported */
	struct dazuko_file_listnode	*aliases;		/* list of file names (alias names) */
	struct file_properties		file_p;			/* properties of file */
	struct xp_file_struct		*extra_data;		/* extra platform-dependant data */
};


/********************************************************
 * functions that MUST be implemented by platform-layer *
 ********************************************************/

/* mutex */
int xp_init_mutex(struct xp_mutex *mutex);
int xp_down(struct xp_mutex *mutex);
int xp_up(struct xp_mutex *mutex);
int xp_destroy_mutex(struct xp_mutex *mutex);

/* read-write lock */
int xp_init_rwlock(struct xp_rwlock *rwlock);
int xp_write_lock(struct xp_rwlock *rwlock);
int xp_write_unlock(struct xp_rwlock *rwlock);
int xp_read_lock(struct xp_rwlock *rlock);
int xp_read_unlock(struct xp_rwlock *rlock);
int xp_destroy_rwlock(struct xp_rwlock *rwlock);

/* wait-notify queue */
int xp_init_queue(struct xp_queue *queue);
int xp_wait_until_condition(struct xp_queue *queue, int (*cfunction)(void *), void *cparam, int allow_interrupt);
int xp_notify(struct xp_queue *queue);
int xp_destroy_queue(struct xp_queue *queue);

/* memory */
void* xp_malloc(size_t size);
int xp_free(void *ptr);
int xp_copyin(const void *user_src, void *kernel_dest, size_t size);
int xp_copyout(const void *kernel_src, void *user_dest, size_t size);
int xp_verify_user_writable(const void *user_ptr, size_t size);
int xp_verify_user_readable(const void *user_ptr, size_t size);

/* path attribute */
int xp_is_absolute_path(const char *path);

/* atomic */
int xp_atomic_set(struct xp_atomic *atomic, int value);
int xp_atomic_inc(struct xp_atomic *atomic);
int xp_atomic_dec(struct xp_atomic *atomic);
int xp_atomic_read(struct xp_atomic *atomic);

/* file descriptor */
int xp_copy_file(struct xp_file *dest, struct xp_file *src);
int xp_compare_file(struct xp_file *file1, struct xp_file *file2);

/* system hook */
int xp_sys_hook(void);
int xp_sys_unhook(void);

/* file structure */
int xp_file_struct_check(struct dazuko_file_struct *dfs);
int xp_file_struct_check_cleanup(struct dazuko_file_struct *dfs);

/* daemon id */
int xp_id_compare(struct xp_daemon_id *id1, struct xp_daemon_id *id2);
int xp_id_free(struct xp_daemon_id *id);
struct xp_daemon_id* xp_id_copy(struct xp_daemon_id *id);

/* output */
int xp_print(const char *fmt, ...);

/* debug */
#ifdef DEBUG
#define DPRINT(fmt) xp_print fmt
#else
#define DPRINT(fmt)
#endif


/*****************************************
 * functions available to platform-layer *
 *****************************************/

int dazuko_vsnprintf(char *str, size_t size, const char *format, va_list ap);
int dazuko_snprintf(char *str, size_t size, const char *format, ...);
int dazuko_is_our_daemon(struct xp_daemon_id *xp_id);
int dazuko_get_value(const char *key, const char *string, char **value);
int dazuko_unregister_daemon(struct xp_daemon_id *xp_id);
int dazuko_handle_user_request(struct dazuko_request *user_request, struct xp_daemon_id *xp_id);
int dazuko_handle_user_request_compat12(void *ptr, int cmd, struct xp_daemon_id *xp_id);
int dazuko_get_filename_length(char *filename);
void dazuko_bzero(void *p, int len);
int dazuko_sys_check(unsigned long event, int daemon_is_allowed, struct xp_daemon_id *xp_id);
int dazuko_sys_pre(unsigned long event, struct dazuko_file_struct *kfs, struct xp_file *file, struct event_properties *event_p);
int dazuko_sys_post(unsigned long event, struct dazuko_file_struct *kfs, struct xp_file *file, struct event_properties *event_p);
int dazuko_init(void);
int dazuko_exit(void);

#endif
#endif

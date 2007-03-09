/*
 *  Copyright (C) 2006 Mark Pizzolato <clamav-devel@subscriptions.pizzolato.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
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

/*
 * This is a problem, which from a purist point of view, best wants an 
 * RW locking mechanism.
 * On Posix platforms, we leverage advisory locks provided by fcntl().
 * Windows doesn't have a native interprocess RW exclusion mechanism, 
 * one could be constructed from the services available, but it is somewhat
 * complicated.  Meanwhile, we observe that in ClamAV, it is extremely rare 
 * that there will ever be an occasion when multiple processes will be 
 * reading the ClamAV database from a given directory at the same, and in 
 * none of those possible cases would it matter if they serialized their 
 * accesses.  So, a simple mutual exclusion mechanism will suffice for both 
 * the reader and writer locks on Windows.
 */
#ifdef	_MSC_VER
#include <windows.h>
#endif

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef	HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#include <fcntl.h>
#include <errno.h>

#include "clamav.h"
#include "others.h"
#include "lockdb.h"

#ifdef CL_THREAD_SAFE
#include <pthread.h>
pthread_mutex_t lock_mutex = PTHREAD_MUTEX_INITIALIZER;
#else
#define pthread_mutex_lock(arg)
#define pthread_mutex_unlock(arg)
#endif

#ifdef C_WINDOWS /* FIXME */
#define DONT_LOCK_DBDIRS
#endif

struct dblock {
	struct dblock *lock_link;
	char lock_file[NAME_MAX];
#ifndef C_WINDOWS
	int lock_fd;
#else
	HANDLE lock_fd;
#endif
	int lock_type;
};

static struct dblock *dblocks = NULL;

static void cli_lockname(char *lock_file, size_t lock_file_size, const char *dbdirpath);
static int cli_lockdb(const char *dbdirpath, int wait, int writelock);

#ifdef DONT_LOCK_DBDIRS

int cli_readlockdb(const char *dbdirpath, int wait)
{
    return CL_SUCCESS;
}

int cli_writelockdb(const char *dbdirpath, int wait)
{
    return CL_SUCCESS;
}

int cli_unlockdb(const char *dbdirpath)
{
    return CL_SUCCESS;
}

int cli_freelocks(void)
{
	return CL_SUCCESS;
}

#else /* !DONT_LOCK_DBDIRS */

int cli_readlockdb(const char *dbdirpath, int wait)
{
    return cli_lockdb(dbdirpath, wait, 0);
}

int cli_writelockdb(const char *dbdirpath, int wait)
{
    return cli_lockdb(dbdirpath, wait, 1);
}

int cli_freelocks(void)
{
	struct dblock * lock, *nextlock, *usedlocks = NULL;

	pthread_mutex_lock(&lock_mutex);
	for(lock = dblocks; lock; lock = nextlock) {
		/* there might be some locks in use, eg: during a db reload, a failure can lead 
		 * to cl_free being called */
		nextlock = lock->lock_link;
		if(lock->lock_type != -1 && lock->lock_fd != -1) {
			lock->lock_link = usedlocks;
			usedlocks = lock;
		}
		else {
			free(lock);
		}
	}
	dblocks = usedlocks;
	pthread_mutex_unlock(&lock_mutex);
	return CL_SUCCESS;
}


int cli_unlockdb(const char *dbdirpath)
{
	char lock_file[NAME_MAX];
	struct dblock *lock;
#ifndef C_WINDOWS
	struct flock fl;
#endif

    cli_lockname(lock_file, sizeof(lock_file), dbdirpath);
    pthread_mutex_lock(&lock_mutex);
    for(lock=dblocks; lock; lock=lock->lock_link)
	if(!strcmp(lock_file, lock->lock_file))
	    break;
    if((!lock) || (lock->lock_type == -1)) {
	cli_errmsg("Database Directory: %s not locked\n", dbdirpath);
	pthread_mutex_unlock(&lock_mutex);
	return CL_ELOCKDB;
    }
#ifndef C_WINDOWS
    memset(&fl, 0, sizeof(fl));
    fl.l_type = F_UNLCK;
    if(fcntl(lock->lock_fd, F_SETLK, &fl) == -1) {
#else
    if(!ReleaseMutex(lock->lock_fd)) {
#endif
	cli_errmsg("Error Unlocking Database Directory %s\n", dbdirpath);
	pthread_mutex_unlock(&lock_mutex);
#ifndef C_WINDOWS
	close(lock->lock_fd);
	lock->lock_fd=-1;
	unlink(lock->lock_file);
#endif
	return CL_ELOCKDB;
    }
    lock->lock_type = -1;
#ifndef C_WINDOWS
    close(lock->lock_fd);
    lock->lock_fd=-1;
    unlink(lock->lock_file);
#endif
    pthread_mutex_unlock(&lock_mutex);

    return CL_SUCCESS;
}

static int cli_lockdb(const char *dbdirpath, int wait, int writelock)
{
	char lock_file[NAME_MAX];
	struct dblock *lock;
#ifndef C_WINDOWS
	struct flock fl;
	mode_t old_mask;
	unsigned int existing = 0;
#else
	DWORD LastError;
	SECURITY_ATTRIBUTES saAttr;
	SECURITY_DESCRIPTOR sdDesc;
#endif

    cli_lockname(lock_file, sizeof(lock_file), dbdirpath);
    pthread_mutex_lock(&lock_mutex);
    for(lock=dblocks; lock; lock=lock->lock_link)
	if(!strcmp(lock_file, lock->lock_file))
	    break;
    if(!lock) {
	lock = cli_calloc(1, sizeof(*lock));
	if(!lock) {
	    cli_errmsg("cli_lockdb(): Can't allocate lock structure to lock Database Directory: %s\n", dbdirpath);
	    pthread_mutex_unlock(&lock_mutex);
	    return CL_EMEM;
	}
	lock->lock_link = dblocks;
	strcpy(lock->lock_file, lock_file);
	lock->lock_fd = -1;
	lock->lock_type = -1;
	dblocks = lock;
    }
    if(lock->lock_type != -1) {
	cli_dbgmsg("Database Directory: %s already %s locked\n", dbdirpath, (lock->lock_type? "write" : "read"));
	pthread_mutex_unlock(&lock_mutex);
	return CL_ELOCKDB;
    }
#ifndef C_WINDOWS
    if(lock->lock_fd == -1) {
	old_mask = umask(0);
	if(-1 == (lock->lock_fd = open(lock->lock_file, O_RDWR|O_CREAT|O_TRUNC, S_IRWXU|S_IRWXG|S_IROTH))) {
	    if((writelock) ||
	       (-1 == (lock->lock_fd = open(lock->lock_file, O_RDONLY)))) {
		cli_dbgmsg("Can't %s Lock file for Database Directory: %s\n", (writelock ? "create" : "open"), dbdirpath);
		umask(old_mask);
		pthread_mutex_unlock(&lock_mutex);
		return CL_EIO; /* or CL_EACCESS */
	    } else {
		existing = 1;
	    }
	}
	umask(old_mask);
    }
#else
    if(lock->lock_fd == -1) {
	/* Create a security descriptor which allows any process to acquire the Mutex */
	InitializeSecurityDescriptor(&sdDesc, SECURITY_DESCRIPTOR_REVISION);
	SetSecurityDescriptorDacl(&sdDesc, TRUE, NULL, FALSE);
	saAttr.nLength = sizeof(saAttr);
	saAttr.bInheritHandle = FALSE;
	saAttr.lpSecurityDescriptor = &sdDesc;
	if(!(lock->lock_fd = CreateMutexA(&saAttr, TRUE, lock->lock_file))) {
	    if((GetLastError() != ERROR_ACCESS_DENIED) || 
	       (!(lock->lock_fd = OpenMutexA(MUTEX_MODIFY_STATE, FALSE, lock->lock_file)))) {
		cli_dbgmsg("Can't Create Mutex Lock for Database Directory: %s\n", dbdirpath);
		pthread_mutex_unlock(&lock_mutex);
		return CL_EIO;
	    }
	    LastError = ERROR_ALREADY_EXISTS;
	}
	LastError = GetLastError();
    } else {
	LastError = ERROR_ALREADY_EXISTS;
    }
#endif
    pthread_mutex_unlock(&lock_mutex);

#ifndef C_WINDOWS
    memset(&fl, 0, sizeof(fl));
    fl.l_type = (writelock ? F_WRLCK : F_RDLCK);
    if(fcntl(lock->lock_fd, ((wait) ? F_SETLKW : F_SETLK), &fl) == -1) {
#ifndef C_WINDOWS
	close(lock->lock_fd);
	lock->lock_fd = -1;
	if(errno != EACCES && errno != EAGAIN) {
	    if(!existing)
		unlink(lock->lock_file);
	    cli_errmsg("Can't acquire %s lock: %s\n", writelock ? "write" : "read", strerror(errno));
	    return CL_EIO;
	}
#endif
	return CL_ELOCKDB;
    }
#else
    if(LastError == ERROR_ALREADY_EXISTS) {
	if(WAIT_TIMEOUT == WaitForSingleObject(lock->lock_fd, ((wait) ? INFINITE : 0))) {
	    lock->lock_type = -1;
	    return CL_ELOCKDB;
	}
    }
#endif
    lock->lock_type = writelock;

    return CL_SUCCESS;
}

static void cli_lockname(char *lock_file, size_t lock_file_size, const char *dbdirpath)
{
	char *c;

    lock_file[lock_file_size-1] = '\0';
#ifndef C_WINDOWS
    snprintf(lock_file, lock_file_size-1, "%s/.dbLock", dbdirpath);
    for (c=lock_file; *c; ++c) {
#else
    snprintf(lock_file, lock_file_size-1, "Global\\ClamAVDB-%s", dbdirpath);
    for (c=lock_file+16; *c; ++c) {
#endif
	switch (*c) {
#ifdef C_WINDOWS
	case '\\':
	    *c = '/';
#endif
	case '/':
	    if(c!=lock_file && *(c-1) == '/') { /* compress imbedded // */
		--c;
		memmove(c, c+1,strlen(c+1)+1);
            } else if(c > lock_file+1 && (*(c-2) == '/') && (*(c-1) == '.')) { /* compress imbedded /./ */
		c -= 2;
		memmove(c, c+2,strlen(c+2)+1);
            }
	    break;
#ifdef C_WINDOWS
	default:
	    if(islower(*c)) /* Normalize to upper case */
		*c = toupper(*c);
	    break;
#endif
	}
    }
#ifdef C_WINDOWS
    if('/' == lock_file[strlen(lock_file)-1]) /* Remove trailing / */
	lock_file[strlen(lock_file)-1] = '\0';
#endif
}

#endif /* DONT_LOCK_DBDIRS */

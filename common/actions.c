/*
 *  Copyright (C) 2013-2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2009-2013 Sourcefire, Inc.
 *
 *  Author: aCaB, Micah Snyder
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

#ifdef _WIN32
#include <windows.h>
#include <aclapi.h>
#include <winternl.h>
#include <io.h>

#ifndef STATUS_OBJECT_NAME_EXISTS
#define STATUS_OBJECT_NAME_EXISTS ((NTSTATUS)0x40000000L)
#endif
#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#endif
#ifndef STATUS_OBJECT_NAME_COLLISION
#define STATUS_OBJECT_NAME_COLLISION ((NTSTATUS)0xC0000035L)
#endif
#endif

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#ifdef C_DARWIN
#include <copyfile.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if defined(C_LINUX) && !defined(_WIN32)
#include <sys/syscall.h>
#include <sys/xattr.h>
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1U << 0)
#endif
#endif
#include <stdbool.h>
#include <fcntl.h>
#include <errno.h>
#include <libgen.h>

// libclamav
#include "clamav.h"
#include "str.h"
#include "others.h"
#include "optparser.h"
#include "output.h"
#include "misc.h"
#include "actions.h"

void (*action)(const action_source_t *) = NULL;
unsigned int notmoved = 0, notremoved = 0;

static char *actarget;
static int targlen;
#ifndef _WIN32
static int actarget_fd = -1;
static char *actarget_lockname = NULL;
static int action_unlinkat_nointr(int dirfd, const char *path, int flags);
static int traverse_to(const char *directory, bool want_directory_handle, int *out_handle);
#else
static HANDLE actarget_handle = NULL;
static char *actarget_normalized = NULL;
static int traverse_to(const char *directory, bool want_directory_handle, HANDLE *out_handle);
static size_t win32_path_root_length(const char *path, size_t path_len);
static int win32_open_existing_path(const char *path, bool is_directory, ACCESS_MASK desired_access, HANDLE *out_handle);
static int win32_delete_handle(HANDLE file_handle);
static int win32_delete_dest_name(const char *dest_name);
#endif
static bool action_cleanup_registered = false;
static void action_move(const action_source_t *source);
static void action_copy(const action_source_t *source);
static void action_remove(const action_source_t *source);

static int action_fstat_nointr(int fd, STATBUF *st)
{
    int rc;

    do {
        rc = FSTAT(fd, st);
    } while ((rc < 0) && (EINTR == errno));

    return rc;
}

static void action_cleanup(void)
{
#ifndef _WIN32
    if ((-1 != actarget_fd) && (NULL != actarget_lockname)) {
        if ((0 != action_unlinkat_nointr(actarget_fd, actarget_lockname, 0)) && (ENOENT != errno)) {
            logg(LOGG_DEBUG, "action_cleanup: Failed to unlink quarantine lock '%s': %s\n",
                 actarget_lockname,
                 strerror(errno));
        }
    }

    if (NULL != actarget_lockname) {
        free(actarget_lockname);
        actarget_lockname = NULL;
    }

    if (-1 != actarget_fd) {
        close(actarget_fd);
        actarget_fd = -1;
    }
#else
    if ((NULL != actarget_handle) && (INVALID_HANDLE_VALUE != actarget_handle)) {
        CloseHandle(actarget_handle);
        actarget_handle = NULL;
    }
    if (NULL != actarget_normalized) {
        free(actarget_normalized);
        actarget_normalized = NULL;
        actarget            = NULL;
    }
#endif
}

static int action_close_dest_fd(int *fd)
{
    int close_fd;

    if ((NULL == fd) || (*fd < 0)) {
        errno = EBADF;
        return -1;
    }

    close_fd = *fd;
    *fd      = -1;

    return close(close_fd);
}

#ifndef _WIN32
static int action_open_nointr(const char *path, int flags)
{
    int fd;

    do {
        fd = open(path, flags);
    } while ((fd < 0) && (EINTR == errno));

    return fd;
}

static int action_openat_nointr(int dirfd, const char *path, int flags, mode_t mode)
{
    int fd;

    do {
        fd = openat(dirfd, path, flags, mode);
    } while ((fd < 0) && (EINTR == errno));

    return fd;
}

static int action_open_flags_with_largefile(int flags)
{
#ifdef O_LARGEFILE
    flags |= O_LARGEFILE;
#endif
    return flags;
}

static int action_directory_open_flags(void)
{
    int flags = O_NOFOLLOW;

#ifdef O_SEARCH
    flags |= O_SEARCH;
#elif defined(O_PATH)
    flags |= O_PATH;
#else
    flags |= O_RDONLY;
#endif
#ifdef O_DIRECTORY
    flags |= O_DIRECTORY;
#endif
#ifdef O_NONBLOCK
    flags |= O_NONBLOCK;
#endif

    return flags;
}

static int action_source_open_flags(void)
{
    int flags = O_RDONLY | O_NOFOLLOW | O_BINARY;

#ifdef O_NONBLOCK
    flags |= O_NONBLOCK;
#endif

    return action_open_flags_with_largefile(flags);
}

static int action_verify_directory_fd(int fd)
{
    STATBUF statbuf;

    if (0 != FSTAT(fd, &statbuf)) {
        return -1;
    }

    if (!S_ISDIR(statbuf.st_mode)) {
        errno = ENOTDIR;
        return -1;
    }

    return 0;
}

static int action_open_directory_nointr(const char *path)
{
    int fd = action_open_nointr(path, action_directory_open_flags());

    if (fd >= 0 && 0 != action_verify_directory_fd(fd)) {
        close(fd);
        fd = -1;
    }

    return fd;
}

static int action_openat_directory_nointr(int dirfd, const char *path)
{
    int fd = action_openat_nointr(dirfd, path, action_directory_open_flags(), 0);

    if (fd >= 0 && 0 != action_verify_directory_fd(fd)) {
        close(fd);
        fd = -1;
    }

    return fd;
}

static int action_openat_source_nointr(int dirfd, const char *path)
{
    return action_openat_nointr(dirfd, path, action_source_open_flags(), 0);
}

static int action_mkdirat_nointr(int dirfd, const char *path, mode_t mode)
{
    int rc;

    do {
        rc = mkdirat(dirfd, path, mode);
    } while ((rc < 0) && (EINTR == errno));

    return rc;
}

static int action_renameat_nointr(int olddirfd, const char *oldpath, int newdirfd, const char *newpath)
{
    int rc;

    do {
        rc = renameat(olddirfd, oldpath, newdirfd, newpath);
    } while ((rc < 0) && (EINTR == errno));

    return rc;
}

static int action_renameat_noreplace_nointr(int olddirfd, const char *oldpath, int newdirfd, const char *newpath)
{
    int rc;

#if defined(C_DARWIN)
    do {
        rc = renameatx_np(olddirfd, oldpath, newdirfd, newpath, RENAME_EXCL);
    } while ((rc < 0) && (EINTR == errno));
#elif defined(C_LINUX) && defined(SYS_renameat2)
    do {
        rc = (int)syscall(
            SYS_renameat2,
            olddirfd,
            oldpath,
            newdirfd,
            newpath,
            RENAME_NOREPLACE);
    } while ((rc < 0) && (EINTR == errno));
#else
    UNUSEDPARAM(olddirfd);
    UNUSEDPARAM(oldpath);
    UNUSEDPARAM(newdirfd);
    UNUSEDPARAM(newpath);
    errno = ENOTSUP;
    rc    = -1;
#endif

    return rc;
}

/**
 * @brief Test whether no-replace rename works inside a private directory.
 *
 * Directory restore after a mismatched private capture depends on an atomic
 * rename operation that refuses to overwrite the original basename. The
 * expected-stat unlink path probes this before capture because a writable
 * directory race can replace the checked regular file with a directory between
 * restat and private capture; without no-replace restore, a refused action
 * could still hide that directory in the private unlink directory.
 *
 * @param private_directory_fd Empty private directory fd used for this unlink.
 * @return true               No-replace rename failed with EEXIST as expected.
 * @return false              No-replace rename is unavailable or misbehaved.
 */
static bool action_private_dir_supports_noreplace_rename(int private_directory_fd)
{
    const char src_name[] = ".rename-noreplace-src";
    const char dst_name[] = ".rename-noreplace-dst";
    bool supported        = false;

    if (private_directory_fd < 0) {
        errno = EINVAL;
        return false;
    }

    if (0 != action_mkdirat_nointr(private_directory_fd, src_name, 0700)) {
        return false;
    }

    if (0 != action_mkdirat_nointr(private_directory_fd, dst_name, 0700)) {
        (void)action_unlinkat_nointr(private_directory_fd, src_name, AT_REMOVEDIR);
        return false;
    }

    if (0 != action_renameat_noreplace_nointr(
                 private_directory_fd,
                 src_name,
                 private_directory_fd,
                 dst_name)) {
        supported = (EEXIST == errno);
    }

    (void)action_unlinkat_nointr(private_directory_fd, src_name, AT_REMOVEDIR);
    (void)action_unlinkat_nointr(private_directory_fd, dst_name, AT_REMOVEDIR);

    if (!supported) {
        errno = ENOTSUP;
    }

    return supported;
}

static int traverse_to(const char *directory, bool want_directory_handle, int *out_handle);

#ifndef C_DARWIN
static ssize_t action_read_nointr(int fd, void *buf, size_t count)
{
    ssize_t rc;

    do {
        rc = read(fd, buf, count);
    } while ((rc < 0) && (EINTR == errno));

    return rc;
}

static ssize_t action_write_nointr(int fd, const void *buf, size_t count)
{
    ssize_t rc;

    do {
        rc = write(fd, buf, count);
    } while ((rc < 0) && (EINTR == errno));

    return rc;
}
#endif

static off_t action_lseek_nointr(int fd, off_t offset, int whence)
{
    off_t rc;

    do {
        rc = lseek(fd, offset, whence);
    } while (((off_t)-1 == rc) && (EINTR == errno));

    return rc;
}

#ifndef C_DARWIN
static int action_ftruncate_nointr(int fd, off_t length)
{
    int rc;

    do {
        rc = ftruncate(fd, length);
    } while ((rc < 0) && (EINTR == errno));

    return rc;
}
#endif

static int action_unlinkat_nointr(int dirfd, const char *path, int flags)
{
    int rc;

    do {
        rc = unlinkat(dirfd, path, flags);
    } while ((rc < 0) && (EINTR == errno));

    return rc;
}

#ifndef _WIN32
static int action_fstatat_nointr(int dirfd, const char *path, STATBUF *st, int flags)
{
    int rc;

    do {
#if defined(HAVE_STAT64) && STAT64_OK
        rc = fstatat64(dirfd, path, st, flags);
#else
        rc = fstatat(dirfd, path, st, flags);
#endif
    } while ((rc < 0) && (EINTR == errno));

    return rc;
}

static int action_validate_actarget_path(void)
{
    STATBUF fd_stat;
    STATBUF path_stat;

    /*
     * Destination entries are created through actarget_fd, but users see
     * actarget/name. Refuse success if actarget no longer names that fd.
     */
    if ((-1 == actarget_fd) || (NULL == actarget)) {
        errno = EINVAL;
        return -1;
    }

    if (0 != action_fstat_nointr(actarget_fd, &fd_stat)) {
        return -1;
    }

    if (0 != CLAMSTAT(actarget, &path_stat)) {
        return -1;
    }

    if (!S_ISDIR(path_stat.st_mode) ||
        (path_stat.st_dev != fd_stat.st_dev) ||
        (path_stat.st_ino != fd_stat.st_ino)) {
        errno = EAGAIN;
        return -1;
    }

    return 0;
}
#endif

static int action_fchmod_nointr(int fd, mode_t mode)
{
    int rc;

    do {
        rc = fchmod(fd, mode);
    } while ((rc < 0) && (EINTR == errno));

    return rc;
}

#ifdef C_LINUX
static int action_futimens_nointr(int fd, const struct timespec times[2])
{
    int rc;

    do {
        rc = futimens(fd, times);
    } while ((rc < 0) && (EINTR == errno));

    return rc;
}
#endif

static char *action_gen_quarantine_lockname(unsigned int attempt)
{
    int needed;
    char *lockname = NULL;

    needed = snprintf(NULL, 0, ".clamav-quarantine-lock.%lu.%u",
                      (unsigned long)getpid(),
                      attempt);
    if (needed < 0) {
        return NULL;
    }

    lockname = malloc((size_t)needed + 1);
    if (NULL == lockname) {
        return NULL;
    }

    if (snprintf(lockname, (size_t)needed + 1, ".clamav-quarantine-lock.%lu.%u",
                 (unsigned long)getpid(),
                 attempt) != needed) {
        free(lockname);
        return NULL;
    }

    return lockname;
}

int action_setup_quarantine_lock_at(int directory_fd, const char *directory_path, char **lockname_out)
{
    char *lockname = NULL;
    int fd        = -1;
    unsigned int i;

    if (directory_fd < 0 || NULL == lockname_out) {
        return -1;
    }

    *lockname_out = NULL;

    /*
     * Create the lock relative to the validated directory handle so the lock
     * stays bound to the directory we already traversed without following
     * symlinks.
     */
    for (i = 0; i < 100; i++) {
        lockname = action_gen_quarantine_lockname(i);
        if (NULL == lockname) {
            return -1;
        }

        fd = action_openat_nointr(directory_fd, lockname, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_BINARY, 0600);
        if (fd >= 0) {
            if (0 != close(fd)) {
                (void)action_unlinkat_nointr(directory_fd, lockname, 0);
                free(lockname);
                return -1;
            }

            *lockname_out = lockname;
            return 0;
        }

        if (EEXIST != errno) {
            logg(LOGG_INFO, "action_setup: Failed to create quarantine lock file in %s: %s\n",
                 (NULL != directory_path) ? directory_path : "(unknown)",
                 strerror(errno));
            free(lockname);
            return -1;
        }

        free(lockname);
        lockname = NULL;
    }

    logg(LOGG_INFO, "action_setup: Failed to create quarantine lock file in %s after repeated name collisions.\n",
         (NULL != directory_path) ? directory_path : "(unknown)");
    return -1;
}

static int action_setup_quarantine_lock(void)
{
    return action_setup_quarantine_lock_at(actarget_fd, actarget, &actarget_lockname);
}
#endif

#ifndef _WIN32
#ifdef C_LINUX
static ssize_t action_flistxattr_nointr(int fd, char *list, size_t size)
{
    ssize_t rc;

    do {
        rc = flistxattr(fd, list, size);
    } while ((rc < 0) && (EINTR == errno));

    return rc;
}

static ssize_t action_fgetxattr_nointr(int fd, const char *name, void *value, size_t size)
{
    ssize_t rc;

    do {
        rc = fgetxattr(fd, name, value, size);
    } while ((rc < 0) && (EINTR == errno));

    return rc;
}

static int action_fsetxattr_nointr(int fd, const char *name, const void *value, size_t size, int flags)
{
    int rc;

    do {
        rc = fsetxattr(fd, name, value, size, flags);
    } while ((rc < 0) && (EINTR == errno));

    return rc;
}

static int linux_copy_xattrs(int src_fd, int dest_fd)
{
    ssize_t list_size;
    char *names = NULL;
    char *name  = NULL;
    int status  = -1;

    list_size = action_flistxattr_nointr(src_fd, NULL, 0);
    if (list_size < 0) {
        if ((ENOTSUP == errno) || (EOPNOTSUPP == errno)) {
            return 0;
        }
        return -1;
    }

    if (0 == list_size) {
        return 0;
    }

    names = malloc((size_t)list_size);
    if (NULL == names) {
        return -1;
    }

    list_size = action_flistxattr_nointr(src_fd, names, (size_t)list_size);
    if (list_size < 0) {
        if ((ENOTSUP == errno) || (EOPNOTSUPP == errno)) {
            status = 0;
            goto done;
        }
        goto done;
    }

    for (name = names; name < names + list_size; name += strlen(name) + 1) {
        ssize_t value_size;
        void *value = NULL;

        value_size = action_fgetxattr_nointr(src_fd, name, NULL, 0);
        if (value_size < 0) {
            if (ENODATA == errno) {
                continue;
            }
            goto done;
        }

        if (value_size > 0) {
            value = malloc((size_t)value_size);
            if (NULL == value) {
                goto done;
            }

            value_size = action_fgetxattr_nointr(src_fd, name, value, (size_t)value_size);
            if (value_size < 0) {
                free(value);
                if (ENODATA == errno) {
                    continue;
                }
                goto done;
            }
        }

        if (0 != action_fsetxattr_nointr(dest_fd, name, value, (size_t)((value_size < 0) ? 0 : value_size), 0)) {
            int xattr_errno = errno;

            free(value);

            if ((EPERM == xattr_errno) || (EACCES == xattr_errno) ||
                (ENOTSUP == xattr_errno) || (EOPNOTSUPP == xattr_errno)) {
                continue;
            }

            errno = xattr_errno;
            goto done;
        }

        free(value);
    }

    status = 0;

done:
    if (NULL != names) {
        free(names);
    }

    return status;
}

static int linux_copy_file_metadata(int src_fd, int dest_fd)
{
    STATBUF src_stat;
    struct timespec times[2];

    if (0 != action_fstat_nointr(src_fd, &src_stat)) {
        return -1;
    }

    times[0] = src_stat.st_atim;
    times[1] = src_stat.st_mtim;
    if (0 != action_futimens_nointr(dest_fd, times)) {
        return -1;
    }

    if (0 != linux_copy_xattrs(src_fd, dest_fd)) {
        int xattr_errno = errno;
        logg(LOGG_DEBUG, "action: Failed to preserve extended attributes: %s\n",
             strerror(xattr_errno));
    }

    return 0;
}
#endif

static int filecopy_to_fd(const action_source_t *source, int dest_fd, STATBUF *src_stat_out)
{
    int src_fd;
#ifdef C_DARWIN
#else
    char buf[8192];
    ssize_t got;
#endif

    if ((NULL == source) || (dest_fd < 0) || (source->scan_fd < 0) || (false == source->has_stat)) {
        return -1;
    }

    src_fd = source->scan_fd;

    if (!S_ISREG(source->statbuf.st_mode)) {
        errno = EINVAL;
        return -1;
    }

    if (action_lseek_nointr(src_fd, 0, SEEK_SET) == (off_t)-1 ||
        action_lseek_nointr(dest_fd, 0, SEEK_SET) == (off_t)-1) {
        return -1;
    }

#ifdef C_DARWIN
    if (0 != fcopyfile(src_fd, dest_fd, NULL, COPYFILE_DATA | COPYFILE_XATTR)) {
        return -1;
    }
#else
    while ((got = action_read_nointr(src_fd, buf, sizeof(buf))) > 0) {
        size_t off = 0;

        while (off < (size_t)got) {
            ssize_t wrote = action_write_nointr(dest_fd, buf + off, (size_t)got - off);
            if (wrote <= 0) {
                return -1;
            }
            off += (size_t)wrote;
        }
    }

    if (got < 0 ||
        action_ftruncate_nointr(dest_fd, action_lseek_nointr(dest_fd, 0, SEEK_CUR)) != 0 ||
        action_lseek_nointr(dest_fd, 0, SEEK_SET) == (off_t)-1) {
        return -1;
    }
#endif

#ifdef C_LINUX
    if (0 != linux_copy_file_metadata(src_fd, dest_fd)) {
        return -1;
    }
#endif

    if (0 != action_fchmod_nointr(dest_fd, S_IRUSR | S_IWUSR)) {
        return -1;
    }

    if (NULL != src_stat_out) {
        *src_stat_out = source->statbuf;
    }

    return 0;
}
#else
typedef NTSTATUS(NTAPI *PNTCF)(
    PHANDLE FileHandle, // OUT
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock, // OUT
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength);

typedef VOID(NTAPI *PRIUS)(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString);

static ACCESS_MASK win32_directory_anchor_access(void)
{
    /*
     * Directory handles are used as validated anchors for later relative
     * opens/creates. They need traversal and attributes for validation, but
     * not FILE_LIST_DIRECTORY, so drop-box ACLs that deny listing can work.
     */
    return SYNCHRONIZE | FILE_TRAVERSE | FILE_READ_ATTRIBUTES;
}

static HANDLE win32_openat(
    HANDLE current_handle,
    const char *filename,
    PNTCF pNtCreateFile,
    PRIUS pRtlInitUnicodeString,
    ACCESS_MASK desiredAccess,
    ULONG fileAttributes,
    ULONG createDisposition,
    ULONG createOptions,
    ULONG shareAccess);

static WCHAR *win32_utf8_to_utf16(const char *value)
{
    int value_wchars;
    WCHAR *value_w = NULL;

    if (NULL == value) {
        return NULL;
    }

    value_wchars = MultiByteToWideChar(CP_UTF8, 0, value, -1, NULL, 0);
    if (0 == value_wchars) {
        return NULL;
    }

    value_w = malloc((size_t)value_wchars * sizeof(WCHAR));
    if (NULL == value_w) {
        return NULL;
    }

    if (0 == MultiByteToWideChar(CP_UTF8, 0, value, -1, value_w, value_wchars)) {
        free(value_w);
        return NULL;
    }

    return value_w;
}

static bool win32_is_extended_path_w(const WCHAR *path)
{
    if (NULL == path) {
        return false;
    }

    return ((0 == wcsncmp(path, L"\\\\?\\", 4)) ||
            (0 == wcsncmp(path, L"\\\\.\\", 4)));
}

static bool win32_is_drive_absolute_path_w(const WCHAR *path, size_t path_len)
{
    return (path_len >= 3) &&
           (((L'A' <= path[0]) && (L'Z' >= path[0])) || ((L'a' <= path[0]) && (L'z' >= path[0]))) &&
           (L':' == path[1]) &&
           ((L'\\' == path[2]) || (L'/' == path[2]));
}

static WCHAR *win32_dup_extended_path_w(const WCHAR *path_w)
{
    size_t path_len;
    size_t prefix_len;
    size_t result_len;
    const WCHAR *prefix = L"\\\\?\\";
    WCHAR *result       = NULL;

    if (NULL == path_w) {
        return NULL;
    }

    if (true == win32_is_extended_path_w(path_w)) {
        return _wcsdup(path_w);
    }

    path_len = wcslen(path_w);
    if (path_len < 2) {
        return _wcsdup(path_w);
    }

    if ((L'\\' == path_w[0]) && (L'\\' == path_w[1])) {
        prefix     = L"\\\\?\\UNC\\";
        prefix_len = wcslen(prefix);
        result_len = prefix_len + path_len - 2;
        result     = malloc((result_len + 1) * sizeof(WCHAR));
        if (NULL == result) {
            return NULL;
        }

        memcpy(result, prefix, prefix_len * sizeof(WCHAR));
        memcpy(result + prefix_len, path_w + 2, (path_len - 1) * sizeof(WCHAR));
        return result;
    }

    if (!win32_is_drive_absolute_path_w(path_w, path_len)) {
        return _wcsdup(path_w);
    }

    prefix_len = wcslen(prefix);
    result_len = prefix_len + path_len;
    result     = malloc((result_len + 1) * sizeof(WCHAR));
    if (NULL == result) {
        return NULL;
    }

    memcpy(result, prefix, prefix_len * sizeof(WCHAR));
    memcpy(result + prefix_len, path_w, (path_len + 1) * sizeof(WCHAR));
    return result;
}

static WCHAR *win32_dup_nonextended_path_w(const WCHAR *path_w)
{
    const WCHAR *body = path_w;

    if (NULL == path_w) {
        return NULL;
    }

    if (0 == wcsncmp(path_w, L"\\\\?\\UNC\\", 8)) {
        size_t body_len = wcslen(path_w + 8);
        WCHAR *result   = malloc((body_len + 3) * sizeof(WCHAR));
        if (NULL == result) {
            return NULL;
        }

        result[0] = L'\\';
        result[1] = L'\\';
        memcpy(result + 2, path_w + 8, (body_len + 1) * sizeof(WCHAR));
        return result;
    }

    if ((0 == wcsncmp(path_w, L"\\\\?\\", 4)) || (0 == wcsncmp(path_w, L"\\\\.\\", 4))) {
        body = path_w + 4;
    }

    return _wcsdup(body);
}

static char *win32_utf16_to_utf8(const WCHAR *value)
{
    int value_bytes;
    char *value_utf8 = NULL;

    if (NULL == value) {
        return NULL;
    }

    value_bytes = WideCharToMultiByte(CP_UTF8, 0, value, -1, NULL, 0, NULL, NULL);
    if (0 == value_bytes) {
        return NULL;
    }

    value_utf8 = malloc((size_t)value_bytes);
    if (NULL == value_utf8) {
        return NULL;
    }

    if (0 == WideCharToMultiByte(CP_UTF8, 0, value, -1, value_utf8, value_bytes, NULL, NULL)) {
        free(value_utf8);
        return NULL;
    }

    return value_utf8;
}

static int win32_copy_handle_data(HANDLE src_handle, HANDLE dest_handle)
{
    BYTE buf[8192];
    DWORD got   = 0;
    DWORD wrote = 0;
    LARGE_INTEGER zero;

    zero.QuadPart = 0;
    if (FALSE == SetFilePointerEx(src_handle, zero, NULL, FILE_BEGIN)) {
        logg(LOGG_INFO, "win32_copy_handle_data: SetFilePointerEx failed for source handle. Error: %lu\n", GetLastError());
        return -1;
    }
    if (FALSE == SetFilePointerEx(dest_handle, zero, NULL, FILE_BEGIN)) {
        logg(LOGG_INFO, "win32_copy_handle_data: SetFilePointerEx failed for destination handle. Error: %lu\n", GetLastError());
        return -1;
    }

    while (TRUE) {
        if (FALSE == ReadFile(src_handle, buf, (DWORD)sizeof(buf), &got, NULL)) {
            logg(LOGG_INFO, "win32_copy_handle_data: ReadFile failed. Error: %lu\n", GetLastError());
            return -1;
        }

        if (0 == got) {
            break;
        }

        wrote = 0;
        if ((FALSE == WriteFile(dest_handle, buf, got, &wrote, NULL)) || (wrote != got)) {
            logg(LOGG_INFO, "win32_copy_handle_data: WriteFile failed. Error: %lu, wrote: %lu, expected: %lu\n", GetLastError(), wrote, got);
            return -1;
        }
    }

    return 0;
}

static int win32_copy_basic_info(HANDLE src_handle, HANDLE dest_handle)
{
    FILE_BASIC_INFO basic_info;

    if (FALSE == GetFileInformationByHandleEx(
                     src_handle,
                     FileBasicInfo,
                     &basic_info,
                     sizeof(FILE_BASIC_INFO))) {
        return -1;
    }

    if (FALSE == SetFileInformationByHandle(
                     dest_handle,
                     FileBasicInfo,
                     &basic_info,
                     sizeof(FILE_BASIC_INFO))) {
        return -1;
    }

    return 0;
}

static int win32_open_existing_directory_at(HANDLE current_handle, const char *dirname, HANDLE *out_handle)
{
    HMODULE ntdll               = NULL;
    PNTCF pNtCreateFile         = NULL;
    PRIUS pRtlInitUnicodeString = NULL;
    HANDLE directory_handle     = NULL;
    int status                  = -1;

    if ((NULL == dirname) || (NULL == out_handle)) {
        return -1;
    }

    ntdll = LoadLibraryA("ntdll.dll");
    if (NULL == ntdll) {
        return -1;
    }

    pNtCreateFile         = (PNTCF)GetProcAddress(ntdll, "NtCreateFile");
    pRtlInitUnicodeString = (PRIUS)GetProcAddress(ntdll, "RtlInitUnicodeString");
    if ((NULL == pNtCreateFile) || (NULL == pRtlInitUnicodeString)) {
        goto done;
    }

    directory_handle = win32_openat(
        current_handle,
        dirname,
        pNtCreateFile,
        pRtlInitUnicodeString,
        win32_directory_anchor_access(),
        FILE_ATTRIBUTE_DIRECTORY,
        FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_OPEN_FOR_BACKUP_INTENT,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    if ((NULL == directory_handle) || (INVALID_HANDLE_VALUE == directory_handle)) {
        goto done;
    }

    *out_handle = directory_handle;
    directory_handle = NULL;
    status           = 0;

done:
    if ((NULL != directory_handle) && (INVALID_HANDLE_VALUE != directory_handle)) {
        CloseHandle(directory_handle);
    }
    if (NULL != ntdll) {
        FreeLibrary(ntdll);
    }
    return status;
}

static int win32_backup_read_exact(HANDLE src_handle, BYTE *buffer, DWORD bytes_to_read, LPVOID *backup_context)
{
    DWORD offset = 0;

    while (offset < bytes_to_read) {
        DWORD bytes_read = 0;

        if (FALSE == BackupRead(src_handle, buffer + offset, bytes_to_read - offset, &bytes_read, FALSE, FALSE, backup_context)) {
            return -1;
        }
        if (0 == bytes_read) {
            return -1;
        }

        offset += bytes_read;
    }

    return 0;
}

static int win32_backup_skip_stream(HANDLE src_handle, LARGE_INTEGER stream_size, LPVOID *backup_context)
{
    BYTE discard[8192];

    while (stream_size.QuadPart > 0) {
        DWORD want;
        DWORD skipped_low  = 0;
        DWORD skipped_high = 0;

        if (stream_size.QuadPart > UINT32_MAX) {
            want = UINT32_MAX;
        } else {
            want = (DWORD)stream_size.QuadPart;
        }

        if (BackupSeek(src_handle, want, 0, &skipped_low, &skipped_high, backup_context)) {
            ULARGE_INTEGER skipped;

            skipped.LowPart  = skipped_low;
            skipped.HighPart = skipped_high;
            if (0 == skipped.QuadPart) {
                return -1;
            }

            stream_size.QuadPart -= (LONGLONG)skipped.QuadPart;
            continue;
        }

        want = (stream_size.QuadPart > (LONGLONG)sizeof(discard)) ? (DWORD)sizeof(discard) : (DWORD)stream_size.QuadPart;
        if (0 != win32_backup_read_exact(src_handle, discard, want, backup_context)) {
            return -1;
        }
        stream_size.QuadPart -= want;
    }

    return 0;
}

static int win32_copy_backup_stream_data(HANDLE src_handle, HANDLE dest_handle, LARGE_INTEGER stream_size, LPVOID *backup_context)
{
    BYTE buf[8192];

    while (stream_size.QuadPart > 0) {
        DWORD want = (stream_size.QuadPart > (LONGLONG)sizeof(buf)) ? (DWORD)sizeof(buf) : (DWORD)stream_size.QuadPart;
        DWORD got  = 0;
        DWORD wrote;

        if (FALSE == BackupRead(src_handle, buf, want, &got, FALSE, FALSE, backup_context)) {
            return -1;
        }
        if (0 == got) {
            return -1;
        }

        wrote = 0;
        if ((FALSE == WriteFile(dest_handle, buf, got, &wrote, NULL)) || (wrote != got)) {
            return -1;
        }

        stream_size.QuadPart -= got;
    }

    return 0;
}

/**
 * @brief Create an alternate data stream relative to an opened destination.
 *
 * Opening the stream from the destination handle keeps ADS copies bound to the
 * quarantine file that getdest() already created, instead of reopening a
 * basename that another process could replace in the quarantine directory.
 *
 * @param dest_handle Open handle for the quarantine destination file.
 * @param stream_name Name returned by BackupRead(), such as ":ads:$DATA".
 * @param[out] out_handle Open handle for the destination stream.
 * @return 0 Stream was created.
 * @return -1 Stream creation failed.
 */
static int win32_create_dest_stream_handle(HANDLE dest_handle, const char *stream_name, HANDLE *out_handle)
{
    HMODULE ntdll               = NULL;
    PNTCF pNtCreateFile         = NULL;
    PRIUS pRtlInitUnicodeString = NULL;
    HANDLE stream_handle        = NULL;
    int status                  = -1;

    if ((NULL == dest_handle) || (INVALID_HANDLE_VALUE == dest_handle) ||
        (NULL == stream_name) || (NULL == out_handle)) {
        return -1;
    }

    ntdll = LoadLibraryA("ntdll.dll");
    if (NULL == ntdll) {
        return -1;
    }

    pNtCreateFile         = (PNTCF)GetProcAddress(ntdll, "NtCreateFile");
    pRtlInitUnicodeString = (PRIUS)GetProcAddress(ntdll, "RtlInitUnicodeString");
    if ((NULL == pNtCreateFile) || (NULL == pRtlInitUnicodeString)) {
        goto done;
    }

    stream_handle = win32_openat(
        dest_handle,
        stream_name,
        pNtCreateFile,
        pRtlInitUnicodeString,
        FILE_WRITE_DATA | SYNCHRONIZE,
        FILE_ATTRIBUTE_NORMAL,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    if ((NULL == stream_handle) || (INVALID_HANDLE_VALUE == stream_handle)) {
        goto done;
    }

    *out_handle   = stream_handle;
    stream_handle = NULL;
    status        = 0;

done:
    if ((NULL != stream_handle) && (INVALID_HANDLE_VALUE != stream_handle)) {
        CloseHandle(stream_handle);
    }
    if (NULL != ntdll) {
        FreeLibrary(ntdll);
    }
    return status;
}

static int win32_copy_alternate_streams(HANDLE src_handle, HANDLE dest_handle)
{
    LPVOID backup_context       = NULL;
    const DWORD stream_id_size  = (DWORD)offsetof(WIN32_STREAM_ID, cStreamName);
    WIN32_STREAM_ID stream_id;
    LARGE_INTEGER zero;
    int status = -1;

    if ((NULL == src_handle) || (INVALID_HANDLE_VALUE == src_handle) ||
        (NULL == dest_handle) || (INVALID_HANDLE_VALUE == dest_handle)) {
        return -1;
    }

    zero.QuadPart = 0;
    if (FALSE == SetFilePointerEx(src_handle, zero, NULL, FILE_BEGIN)) {
        return -1;
    }

    while (TRUE) {
        WCHAR *stream_name_w        = NULL;
        char *stream_name_utf8      = NULL;
        HANDLE dest_stream_handle   = INVALID_HANDLE_VALUE;
        DWORD bytes_read            = 0;

        if (FALSE == BackupRead(src_handle, (BYTE *)&stream_id, stream_id_size, &bytes_read, FALSE, FALSE, &backup_context)) {
            goto done;
        }

        if (0 == bytes_read) {
            status = 0;
            goto done;
        }

        if (bytes_read != stream_id_size) {
            goto done;
        }

        if (0 != stream_id.dwStreamNameSize) {
            size_t stream_name_chars;

            if (0 != (stream_id.dwStreamNameSize % sizeof(WCHAR))) {
                goto done;
            }

            stream_name_chars = stream_id.dwStreamNameSize / sizeof(WCHAR);
            if (stream_name_chars > (SIZE_MAX / sizeof(WCHAR)) - 1) {
                goto done;
            }

            stream_name_w = malloc((stream_name_chars + 1) * sizeof(WCHAR));
            if (NULL == stream_name_w) {
                goto done;
            }

            if (0 != win32_backup_read_exact(src_handle, (BYTE *)stream_name_w, stream_id.dwStreamNameSize, &backup_context)) {
                free(stream_name_w);
                goto done;
            }
            stream_name_w[stream_name_chars] = L'\0';
        }

        if ((BACKUP_ALTERNATE_DATA == stream_id.dwStreamId) &&
            (NULL != stream_name_w) &&
            (L'\0' != stream_name_w[0])) {
            stream_name_utf8 = win32_utf16_to_utf8(stream_name_w);
            if (NULL == stream_name_utf8) {
                free(stream_name_w);
                goto done;
            }

            if (0 != win32_create_dest_stream_handle(dest_handle, stream_name_utf8, &dest_stream_handle) ||
                0 != win32_copy_backup_stream_data(src_handle, dest_stream_handle, stream_id.Size, &backup_context)) {
                if ((NULL != dest_stream_handle) && (INVALID_HANDLE_VALUE != dest_stream_handle)) {
                    CloseHandle(dest_stream_handle);
                }
                free(stream_name_utf8);
                free(stream_name_w);
                goto done;
            }

            CloseHandle(dest_stream_handle);
            free(stream_name_utf8);
        } else if (0 != win32_backup_skip_stream(src_handle, stream_id.Size, &backup_context)) {
            free(stream_name_w);
            goto done;
        }

        free(stream_name_w);
    }

done:
    if (NULL != backup_context) {
        DWORD bytes_read = 0;
        (void)BackupRead(src_handle, NULL, 0, &bytes_read, TRUE, FALSE, &backup_context);
    }

    return status;
}

static int filecopy_to_fd(const action_source_t *source, const char *dest_path, int dest_fd)
{
    const char *src                  = NULL;
    HANDLE src_handle                = INVALID_HANDLE_VALUE;
    HANDLE dest_handle               = INVALID_HANDLE_VALUE;
    int status                       = -1;

    if ((NULL == source) || (NULL == dest_path) || (dest_fd < 0)) {
        return -1;
    }

    src        = (NULL != source->action_path) ? source->action_path : source->display_path;
    src_handle = (HANDLE)source->handle;
    if ((NULL == src) || (NULL == src_handle) || (INVALID_HANDLE_VALUE == src_handle)) {
        return -1;
    }

    dest_handle = (HANDLE)_get_osfhandle(dest_fd);
    if ((NULL == dest_handle) || (INVALID_HANDLE_VALUE == dest_handle)) {
        logg(LOGG_INFO, "filecopy_to_fd: Failed to get destination handle for '%s'.\n", dest_path);
        goto done;
    }

    if (0 != win32_copy_handle_data(src_handle, dest_handle)) {
        logg(LOGG_INFO, "filecopy_to_fd: Failed copying unnamed stream for '%s'. Error: %lu\n", src, GetLastError());
        goto done;
    }

    if (0 != win32_copy_alternate_streams(src_handle, dest_handle)) {
        logg(LOGG_INFO, "filecopy_to_fd: Failed copying alternate data streams for '%s'. Error: %lu\n", src, GetLastError());
        goto done;
    }

    if (0 != win32_copy_basic_info(src_handle, dest_handle)) {
        logg(LOGG_INFO, "filecopy_to_fd: Failed copying basic file info for '%s'. Error: %lu\n", src, GetLastError());
        goto done;
    }

    status = 0;

done:
    return status;
}

static int win32_delete_handle(HANDLE file_handle)
{
    FILE_DISPOSITION_INFO file_info = {0};

    if ((NULL == file_handle) || (INVALID_HANDLE_VALUE == file_handle)) {
        return -1;
    }

    file_info.DeleteFile = TRUE;
    if (FALSE == SetFileInformationByHandle(
                     file_handle,
                     FileDispositionInfo,
                     &file_info,
                     sizeof(FILE_DISPOSITION_INFO))) {
        return -1;
    }

    return 0;
}

static ACCESS_MASK win32_source_scan_desired_access(void)
{
    return FILE_GENERIC_READ | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
}

/**
 * @brief Check whether the selected action will remove the source file.
 *
 * @return true  The source file must be deleted after a detection.
 * @return false The source file is only copied or inspected.
 */
static bool win32_source_action_needs_delete_access(void)
{
    return (action == action_move) || (action == action_remove);
}

static int win32_same_file_handle(HANDLE first_handle, HANDLE second_handle)
{
    BY_HANDLE_FILE_INFORMATION first_info;
    BY_HANDLE_FILE_INFORMATION second_info;

    if ((NULL == first_handle) || (INVALID_HANDLE_VALUE == first_handle) ||
        (NULL == second_handle) || (INVALID_HANDLE_VALUE == second_handle)) {
        SetLastError(ERROR_INVALID_HANDLE);
        return -1;
    }

    if (FALSE == GetFileInformationByHandle(first_handle, &first_info)) {
        return -1;
    }
    if (FALSE == GetFileInformationByHandle(second_handle, &second_info)) {
        return -1;
    }

    if ((first_info.dwVolumeSerialNumber != second_info.dwVolumeSerialNumber) ||
        (first_info.nFileIndexHigh != second_info.nFileIndexHigh) ||
        (first_info.nFileIndexLow != second_info.nFileIndexLow)) {
        SetLastError(ERROR_FILE_NOT_FOUND);
        return -1;
    }

    return 0;
}

static int win32_open_delete_handle_for_source(
    const char *target,
    HANDLE source_handle,
    HANDLE *out_handle)
{
    HANDLE delete_handle = INVALID_HANDLE_VALUE;
    int status           = -1;

    if ((NULL == target) || (NULL == out_handle)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return -1;
    }

    if (0 != win32_open_existing_path(
                 target,
                 false,
                 DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                 &delete_handle)) {
        goto done;
    }

    if ((NULL != source_handle) && (INVALID_HANDLE_VALUE != source_handle) &&
        (0 != win32_same_file_handle(source_handle, delete_handle))) {
        goto done;
    }

    *out_handle  = delete_handle;
    delete_handle = INVALID_HANDLE_VALUE;
    status        = 0;

done:
    if (INVALID_HANDLE_VALUE != delete_handle) {
        CloseHandle(delete_handle);
    }
    return status;
}

static int win32_delete_dest_name(const char *dest_name)
{
    HMODULE ntdll               = NULL;
    PNTCF pNtCreateFile         = NULL;
    PRIUS pRtlInitUnicodeString = NULL;
    HANDLE delete_handle        = NULL;
    int status                  = -1;

    if ((NULL == dest_name) || (NULL == actarget_handle)) {
        return -1;
    }

    ntdll = LoadLibraryA("ntdll.dll");
    if (NULL == ntdll) {
        return -1;
    }

    pNtCreateFile         = (PNTCF)GetProcAddress(ntdll, "NtCreateFile");
    pRtlInitUnicodeString = (PRIUS)GetProcAddress(ntdll, "RtlInitUnicodeString");
    if ((NULL == pNtCreateFile) || (NULL == pRtlInitUnicodeString)) {
        goto done;
    }

    delete_handle = win32_openat(
        actarget_handle,
        dest_name,
        pNtCreateFile,
        pRtlInitUnicodeString,
        DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_ATTRIBUTE_NORMAL,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_OPEN_FOR_BACKUP_INTENT | FILE_SYNCHRONOUS_IO_NONALERT,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    if ((NULL == delete_handle) || (INVALID_HANDLE_VALUE == delete_handle)) {
        goto done;
    }

    status = win32_delete_handle(delete_handle);

done:
    if ((NULL != delete_handle) && (INVALID_HANDLE_VALUE != delete_handle)) {
        CloseHandle(delete_handle);
    }
    if (NULL != ntdll) {
        FreeLibrary(ntdll);
    }
    return status;
}

static int win32_delete_dest_path(const char *dest_path)
{
    const char *slash;
    const char *backslash;
    const char *dest_name;

    if (NULL == dest_path) {
        return -1;
    }

    slash     = strrchr(dest_path, '/');
    backslash = strrchr(dest_path, '\\');
    if ((NULL != slash) && ((NULL == backslash) || (slash > backslash))) {
        dest_name = slash + 1;
    } else if (NULL != backslash) {
        dest_name = backslash + 1;
    } else {
        dest_name = dest_path;
    }

    return win32_delete_dest_name(dest_name);
}

static char *win32_parent_path_dup(const char *path)
{
    char *copy      = NULL;
    char *slash     = NULL;
    char *backslash = NULL;
    char *last_sep  = NULL;
    size_t path_len = 0;
    size_t root_len = 0;

    if (NULL == path) {
        return NULL;
    }

    copy = strdup(path);
    if (NULL == copy) {
        return NULL;
    }

    path_len = strlen(copy);
    root_len = win32_path_root_length(copy, path_len);

    slash     = strrchr(copy, '/');
    backslash = strrchr(copy, '\\');
    last_sep  = (slash > backslash) ? slash : backslash;
    if (NULL == last_sep) {
        free(copy);
        return strdup(".");
    }

    if ((0 != root_len) && ((size_t)(last_sep - copy) < root_len)) {
        copy[root_len] = '\0';
    } else {
        *last_sep = '\0';
    }

    return copy;
}

static bool win32_path_is_separator(char c)
{
    return ('/' == c) || ('\\' == c);
}

static bool win32_path_is_drive_letter(char c)
{
    return (('A' <= c) && ('Z' >= c)) || (('a' <= c) && ('z' >= c));
}

static bool win32_path_ascii_equal_ignore_case(char lhs, char rhs)
{
    if (('A' <= lhs) && ('Z' >= lhs)) {
        lhs = (char)(lhs - 'A' + 'a');
    }
    if (('A' <= rhs) && ('Z' >= rhs)) {
        rhs = (char)(rhs - 'A' + 'a');
    }

    return lhs == rhs;
}

static bool win32_path_match_ignore_case(const char *path, size_t path_len, size_t pos, const char *expected)
{
    size_t i = 0;

    if ((NULL == path) || (NULL == expected)) {
        return false;
    }

    while ('\0' != expected[i]) {
        if ((pos + i >= path_len) ||
            !win32_path_ascii_equal_ignore_case(path[pos + i], expected[i])) {
            return false;
        }
        i++;
    }

    return true;
}

static bool win32_path_has_extended_prefix(const char *path, size_t path_len)
{
    return (path_len >= 4) &&
           win32_path_is_separator(path[0]) &&
           win32_path_is_separator(path[1]) &&
           ('?' == path[2]) &&
           win32_path_is_separator(path[3]);
}

static bool win32_path_has_extended_unc_prefix(const char *path, size_t path_len)
{
    return (path_len >= 8) &&
           win32_path_has_extended_prefix(path, path_len) &&
           (('U' == path[4]) || ('u' == path[4])) &&
           (('N' == path[5]) || ('n' == path[5])) &&
           (('C' == path[6]) || ('c' == path[6])) &&
           win32_path_is_separator(path[7]);
}

static size_t win32_path_extended_volume_root_length(const char *path, size_t path_len)
{
    size_t pos = 4;

    if (!win32_path_has_extended_prefix(path, path_len) ||
        !win32_path_match_ignore_case(path, path_len, pos, "Volume{")) {
        return 0;
    }
    pos += sizeof("Volume{") - 1;

    while ((pos < path_len) &&
           ('}' != path[pos]) &&
           !win32_path_is_separator(path[pos])) {
        pos++;
    }

    if ((pos >= path_len) || ('}' != path[pos])) {
        return 0;
    }
    pos++;

    if ((pos < path_len) && win32_path_is_separator(path[pos])) {
        return pos + 1;
    }

    return path_len;
}

static size_t win32_path_root_length(const char *path, size_t path_len)
{
    size_t pos             = 0;
    size_t volume_root_len = 0;

    if ((NULL == path) || (0 == path_len)) {
        return 0;
    }

    /* Extended drive root, such as "\\?\C:\". */
    if ((path_len >= 7) &&
        win32_path_is_separator(path[0]) &&
        win32_path_is_separator(path[1]) &&
        ('?' == path[2]) &&
        win32_path_is_separator(path[3]) &&
        win32_path_is_drive_letter(path[4]) &&
        (':' == path[5]) &&
        win32_path_is_separator(path[6])) {
        return 7;
    }

    /* Normal drive root, such as "C:\". */
    if ((path_len >= 3) &&
        win32_path_is_drive_letter(path[0]) &&
        (':' == path[1]) &&
        win32_path_is_separator(path[2])) {
        return 3;
    }

    /*
     * Drive-qualified paths, such as "C:" or "C:dir". The root prefix is
     * only the drive designator, but trimming must not remove it.
     */
    if ((path_len >= 2) &&
        win32_path_is_drive_letter(path[0]) &&
        (':' == path[1])) {
        return 2;
    }

    volume_root_len = win32_path_extended_volume_root_length(path, path_len);
    if (0 != volume_root_len) {
        return volume_root_len;
    }

    if ((path_len >= 2) &&
        win32_path_is_separator(path[0]) &&
        win32_path_is_separator(path[1])) {
        pos = 2;
        if (win32_path_has_extended_unc_prefix(path, path_len)) {
            /* Extended UNC root, such as "\\?\UNC\server\share\". */
            pos = 8;
        } else if ((path_len >= 4) &&
                   win32_path_has_extended_prefix(path, path_len)) {
            /* Generic extended namespace prefix, such as "\\?\". */
            return 4;
        }

        /* Skip leading separators, including repeated slashes. */
        while ((pos < path_len) && win32_path_is_separator(path[pos])) {
            pos++;
        }
        /* Skip the UNC server name in "\\server\share\". */
        while ((pos < path_len) && !win32_path_is_separator(path[pos])) {
            pos++;
        }
        if (pos >= path_len) {
            return path_len;
        }
        /* Skip separators between the server and share names. */
        while ((pos < path_len) && win32_path_is_separator(path[pos])) {
            pos++;
        }
        /* Skip the UNC share name. */
        while ((pos < path_len) && !win32_path_is_separator(path[pos])) {
            pos++;
        }
        if ((pos < path_len) && win32_path_is_separator(path[pos])) {
            /* Preserve the separator that terminates "\\server\share\". */
            return pos + 1;
        }
        return path_len;
    }

    /* Current-drive absolute root, such as "\Windows". */
    if (win32_path_is_separator(path[0])) {
        return 1;
    }

    return 0;
}

static char *win32_trim_trailing_path_separators_dup(const char *path)
{
    char *trimmed     = NULL;
    size_t path_len   = 0;
    size_t root_len   = 0;
    size_t trim_len   = 0;

    if (NULL == path) {
        return NULL;
    }

    path_len = strlen(path);
    root_len = win32_path_root_length(path, path_len);
    trim_len = path_len;

    while ((trim_len > root_len) && win32_path_is_separator(path[trim_len - 1])) {
        trim_len--;
    }

    trimmed = malloc(trim_len + 1);
    if (NULL == trimmed) {
        return NULL;
    }

    memcpy(trimmed, path, trim_len);
    trimmed[trim_len] = '\0';

    return trimmed;
}

static WCHAR *win32_normalize_full_path_w(const char *path)
{
    WCHAR *path_w        = NULL;
    WCHAR *extended_w    = NULL;
    WCHAR *normalized_w  = NULL;
    DWORD normalized_len = 0;

    path_w = win32_utf8_to_utf16(path);
    if (NULL == path_w) {
        return NULL;
    }

    extended_w = win32_dup_extended_path_w(path_w);
    free(path_w);
    if (NULL == extended_w) {
        return NULL;
    }

    normalized_len = GetFullPathNameW(extended_w, 0, NULL, NULL);
    if (0 == normalized_len) {
        free(extended_w);
        return NULL;
    }

    normalized_w = malloc((size_t)normalized_len * sizeof(WCHAR));
    if (NULL == normalized_w) {
        free(extended_w);
        return NULL;
    }

    if (0 == GetFullPathNameW(extended_w, normalized_len, normalized_w, NULL)) {
        free(normalized_w);
        free(extended_w);
        return NULL;
    }

    free(extended_w);
    extended_w = win32_dup_nonextended_path_w(normalized_w);
    free(normalized_w);
    return extended_w;
}

static WCHAR *win32_get_final_path_no_prefix_w(HANDLE handle)
{
    WCHAR *final_w    = NULL;
    WCHAR *trimmed_w  = NULL;
    DWORD final_len   = 0;
    DWORD copied_len  = 0;
    DWORD buffer_len  = 0;
    const WCHAR *body = NULL;

    final_len = GetFinalPathNameByHandleW(handle, NULL, 0, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (0 == final_len) {
        return NULL;
    }
    buffer_len = final_len + 1;
    if (buffer_len <= final_len) {
        return NULL;
    }

    final_w = malloc((size_t)buffer_len * sizeof(WCHAR));
    if (NULL == final_w) {
        return NULL;
    }

    copied_len = GetFinalPathNameByHandleW(handle, final_w, buffer_len, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if ((0 == copied_len) || (copied_len >= buffer_len)) {
        free(final_w);
        return NULL;
    }
    final_w[copied_len] = L'\0';

    trimmed_w = win32_dup_nonextended_path_w(final_w);
    free(final_w);
    return trimmed_w;
}

static int win32_reject_reparse_handle(HANDLE handle)
{
    FILE_ATTRIBUTE_TAG_INFO tag_info = {0};

    if (0 == GetFileInformationByHandleEx(
                 handle,
                 FileAttributeTagInfo,
                 &tag_info,
                 sizeof(FILE_ATTRIBUTE_TAG_INFO))) {
        return -1;
    }

    if (0 != (tag_info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        return -1;
    }

    return 0;
}

static int win32_validate_opened_path(HANDLE handle, const char *expected_path)
{
    WCHAR *expected_w = NULL;
    WCHAR *actual_w   = NULL;
    int status        = -1;

    expected_w = win32_normalize_full_path_w(expected_path);
    if (NULL == expected_w) {
        goto done;
    }

    actual_w = win32_get_final_path_no_prefix_w(handle);
    if (NULL == actual_w) {
        goto done;
    }

    /*
     * Keep this validation conservative. GetFullPathNameW() may preserve an
     * 8.3 alias while GetFinalPathNameByHandleW() reports the long path, so
     * valid short-name aliases can be rejected. Failing quarantine setup is
     * preferable to accepting a path spelling we cannot prove still names the
     * opened object.
     */
    if (0 != _wcsicmp(expected_w, actual_w)) {
        goto done;
    }

    if (0 != win32_reject_reparse_handle(handle)) {
        goto done;
    }

    status = 0;

done:
    if (NULL != expected_w) {
        free(expected_w);
    }
    if (NULL != actual_w) {
        free(actual_w);
    }
    return status;
}

static int action_validate_actarget_path(void)
{
    /*
     * Destination entries are created through actarget_handle, but users see
     * actarget/name. Refuse success if actarget no longer names that handle.
     */
    if ((NULL == actarget) || (NULL == actarget_handle) ||
        (INVALID_HANDLE_VALUE == actarget_handle)) {
        errno = EINVAL;
        SetLastError(ERROR_INVALID_PARAMETER);
        return -1;
    }

    if (0 != win32_validate_opened_path(actarget_handle, actarget)) {
        errno = EAGAIN;
        SetLastError(ERROR_FILE_NOT_FOUND);
        return -1;
    }

    return 0;
}

static int win32_open_existing_path(const char *path, bool is_directory, ACCESS_MASK desired_access, HANDLE *out_handle)
{
    WCHAR *path_w         = NULL;
    WCHAR *extended_path_w = NULL;
    HANDLE handle         = INVALID_HANDLE_VALUE;
    DWORD flags           = FILE_FLAG_OPEN_REPARSE_POINT;
    int status            = -1;

    if ((NULL == path) || (NULL == out_handle)) {
        return -1;
    }

    path_w = win32_utf8_to_utf16(path);
    if (NULL == path_w) {
        return -1;
    }

    extended_path_w = win32_dup_extended_path_w(path_w);
    if (NULL == extended_path_w) {
        goto done;
    }

    if (true == is_directory) {
        flags |= FILE_FLAG_BACKUP_SEMANTICS;
    }

    handle = CreateFileW(
        extended_path_w,
        desired_access,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        flags,
        NULL);
    if (INVALID_HANDLE_VALUE == handle) {
        goto done;
    }

    if (0 != win32_validate_opened_path(handle, path)) {
        SetLastError(ERROR_ACCESS_DENIED);
        CloseHandle(handle);
        handle = INVALID_HANDLE_VALUE;
        goto done;
    }

    *out_handle = handle;
    handle      = INVALID_HANDLE_VALUE;
    status      = 0;

done:
    if (INVALID_HANDLE_VALUE != handle) {
        CloseHandle(handle);
    }
    if (NULL != path_w) {
        free(path_w);
    }
    if (NULL != extended_path_w) {
        free(extended_path_w);
    }
    return status;
}

/**
 * @brief Open the Windows quarantine source with the requested access mask.
 *
 * @param path                  Source path to open.
 * @param require_resolved_path Whether to validate the opened path.
 * @param desired_access        Windows access mask requested for the handle.
 * @param out_handle            Opened source handle on success.
 * @return 0                    Source handle opened.
 * @return -1                   Source handle could not be opened.
 */
static int win32_open_source_handle_with_access(
    const char *path,
    bool require_resolved_path,
    ACCESS_MASK desired_access,
    HANDLE *out_handle)
{
    WCHAR *path_w          = NULL;
    WCHAR *extended_path_w = NULL;
    HANDLE handle          = INVALID_HANDLE_VALUE;
    int status             = -1;

    if ((NULL == path) || (NULL == out_handle)) {
        return -1;
    }

    if (require_resolved_path) {
        return win32_open_existing_path(path, false, desired_access, out_handle);
    }

    path_w = win32_utf8_to_utf16(path);
    if (NULL == path_w) {
        return -1;
    }

    extended_path_w = win32_dup_extended_path_w(path_w);
    if (NULL == extended_path_w) {
        goto done;
    }

    handle = CreateFileW(
        extended_path_w,
        desired_access,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (INVALID_HANDLE_VALUE == handle) {
        goto done;
    }

    *out_handle = handle;
    handle      = INVALID_HANDLE_VALUE;
    status      = 0;

done:
    if (INVALID_HANDLE_VALUE != handle) {
        CloseHandle(handle);
    }
    if (NULL != path_w) {
        free(path_w);
    }
    if (NULL != extended_path_w) {
        free(extended_path_w);
    }
    return status;
}

/**
 * @brief Open a Windows quarantine source for scanning.
 *
 * Move/remove actions first try to retain DELETE access on the scan source.
 * If that fails, fall back to a read-only scan handle so quarantine-action
 * permission failures do not suppress detection.
 *
 * @param path                  Source path to open.
 * @param require_resolved_path Whether to validate the opened path.
 * @param out_handle            Opened source handle on success.
 * @param out_handle_can_delete Whether the opened handle has DELETE access.
 * @return 0                    Source handle opened.
 * @return -1                   Source handle could not be opened.
 */
static int win32_open_source_handle(
    const char *path,
    bool require_resolved_path,
    HANDLE *out_handle,
    bool *out_handle_can_delete)
{
    ACCESS_MASK desired_access = win32_source_scan_desired_access();

    if ((NULL == out_handle) || (NULL == out_handle_can_delete)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return -1;
    }

    *out_handle            = INVALID_HANDLE_VALUE;
    *out_handle_can_delete = false;

    if (win32_source_action_needs_delete_access() &&
        (0 == win32_open_source_handle_with_access(
                  path,
                  require_resolved_path,
                  desired_access | DELETE,
                  out_handle))) {
        *out_handle_can_delete = true;
        return 0;
    }

    return win32_open_source_handle_with_access(
        path,
        require_resolved_path,
        desired_access,
        out_handle);
}

/**
 * @brief An openat equivalent for Win32 with a check to NOFOLLOW soft-links.
 *
 * The caller is responsible for closing the HANDLE.
 *
 * For the desiredAccess, fileAttributes, createOptions, and shareAccess parameters
 * see https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile
 *
 * @param current_handle        The current handle. If set to NULL, then filename should be a drive letter.
 * @param filename              The directory to open. If current_handle is valid, should be a directory found in the current directory.
 * @param pNtCreateFile         A function pointer to the NtCreateFile Win32 Native API.
 * @param pRtlInitUnicodeString A function pointer to the RtlInitUnicodeString Win32 Native API.
 * @param desiredAccess         The DesiredAccess option for NtCreateFile
 * @param fileAttributes        The FileAttributes option for NtCreateFile
 * @param createDisposition     The CreateDisposition option for NtCreateFile
 * @param createOptions         The CreateOptions option for NtCreateFile
 * @param shareAccess           The ShareAccess option for NtCreateFile
 * @return HANDLE               A handle on success, NULL on failure.
 */
static HANDLE win32_openat(
    HANDLE current_handle,
    const char *filename,
    PNTCF pNtCreateFile,
    PRIUS pRtlInitUnicodeString,
    ACCESS_MASK desiredAccess,
    ULONG fileAttributes,
    ULONG createDisposition,
    ULONG createOptions,
    ULONG shareAccess)
{
    HANDLE next_handle = NULL;

    LONG ntStatus;
    WCHAR *filenameW = NULL;
    UNICODE_STRING filenameU;
    int cchNextDirectoryName        = 0;
    IO_STATUS_BLOCK ioStatusBlock   = {0};
    OBJECT_ATTRIBUTES objAttributes = {0};
    FILE_ATTRIBUTE_TAG_INFO tagInfo = {0};

    /* Convert filename to a UNICODE_STRING, required by the native API NtCreateFile() */
    cchNextDirectoryName = MultiByteToWideChar(CP_UTF8, 0, filename, -1, NULL, 0);
    filenameW            = malloc(cchNextDirectoryName * sizeof(WCHAR));
    if (NULL == filenameW) {
        logg(LOGG_INFO, "win32_openat: failed to allocate memory for next directory name UTF16LE string\n");
        goto done;
    }
    if (0 == MultiByteToWideChar(CP_UTF8, 0, filename, -1, filenameW, cchNextDirectoryName)) {
        logg(LOGG_INFO, "win32_openat: failed to allocate buffer for unicode version of intermediate directory name.\n");
        goto done;
    }
    pRtlInitUnicodeString(&filenameU, filenameW);

    InitializeObjectAttributes(
        &objAttributes,       // ObjectAttributes
        &filenameU,           // ObjectName
        OBJ_CASE_INSENSITIVE, // Attributes
        current_handle,       // Root directory
        NULL);                // SecurityDescriptor

    ntStatus = pNtCreateFile(
        &next_handle,   // FileHandle
        desiredAccess,  // DesiredAccess
        &objAttributes, // ObjectAttributes
        &ioStatusBlock, // [out] status
        0,              // AllocationSize
        fileAttributes, // FileAttributes
        shareAccess,    // ShareAccess
        createDisposition,
        createOptions, // CreateOptions
        NULL,          // EaBuffer
        0);            // EaLength
    if (!NT_SUCCESS(ntStatus) || (NULL == next_handle)) {
        switch (ntStatus) {
            case STATUS_OBJECT_NAME_COLLISION:
            case STATUS_OBJECT_NAME_EXISTS:
                errno = EEXIST;
                break;
            case STATUS_ACCESS_DENIED:
                errno = EACCES;
                break;
            default:
                errno = EIO;
                break;
        }
        logg(LOGG_INFO, "win32_openat: Failed to open file '%s'. \nError: 0x%x \nioStatusBlock: 0x%x\n", filename, ntStatus, ioStatusBlock.Information);
        goto done;
    }
    logg(LOGG_DEBUG, "win32_openat: Opened file \"%s\"\n", filename);

    if (FILE_CREATE == createDisposition) {
        goto done;
    }

    if (0 == GetFileInformationByHandleEx(
                 next_handle,                        // hFile,
                 FileAttributeTagInfo,               // FileInformationClass
                 &tagInfo,                           // lpFileInformation
                 sizeof(FILE_ATTRIBUTE_TAG_INFO))) { // dwBufferSize
        logg(LOGG_INFO, "win32_openat: Failed to get file information by handle '%s'.  Error: %d.\n", filename, GetLastError());

        CloseHandle(next_handle);
        next_handle = NULL;
        goto done;
    }
    logg(LOGG_DEBUG, "win32_openat: tagInfo.FileAttributes: 0x%0x\n", tagInfo.FileAttributes);
    logg(LOGG_DEBUG, "win32_openat: tagInfo.ReparseTag:     0x%0x\n", tagInfo.ReparseTag);
    if (0 != (tagInfo.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        logg(LOGG_INFO, "win32_openat: File is a soft link: '%s' Aborting path traversal.\n\n", filename);

        CloseHandle(next_handle);
        next_handle = NULL;
        goto done;
    }
    logg(LOGG_DEBUG, "win32_openat: File or directory is not a soft link.\n\n");

done:
    if (NULL != filenameW) {
        free(filenameW);
    }

    return next_handle;
}

static int win32_create_dest_file(const char *dest_basename)
{
    HMODULE ntdll               = NULL;
    PNTCF pNtCreateFile         = NULL;
    PRIUS pRtlInitUnicodeString = NULL;
    HANDLE dest_handle          = NULL;
    int fd                      = -1;

    if ((NULL == dest_basename) || (NULL == actarget_handle)) {
        return -1;
    }

    ntdll = LoadLibraryA("ntdll.dll");
    if (NULL == ntdll) {
        return -1;
    }

    pNtCreateFile         = (PNTCF)GetProcAddress(ntdll, "NtCreateFile");
    pRtlInitUnicodeString = (PRIUS)GetProcAddress(ntdll, "RtlInitUnicodeString");
    if ((NULL == pNtCreateFile) || (NULL == pRtlInitUnicodeString)) {
        FreeLibrary(ntdll);
        return -1;
    }

    dest_handle = win32_openat(
        actarget_handle,
        dest_basename,
        pNtCreateFile,
        pRtlInitUnicodeString,
        FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_ATTRIBUTE_NORMAL,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE | FILE_OPEN_FOR_BACKUP_INTENT | FILE_SYNCHRONOUS_IO_NONALERT,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    if ((NULL == dest_handle) || (INVALID_HANDLE_VALUE == dest_handle)) {
        FreeLibrary(ntdll);
        return -1;
    }

    fd = _open_osfhandle((intptr_t)dest_handle, _O_WRONLY | _O_BINARY);
    if (fd < 0) {
        CloseHandle(dest_handle);
        (void)win32_delete_dest_name(dest_basename);
    }

    FreeLibrary(ntdll);
    return fd;
}
#endif

void action_source_init(action_source_t *source)
{
    if (NULL == source) {
        return;
    }

    memset(source, 0, sizeof(*source));
    source->scan_fd = -1;
#ifdef _WIN32
    source->handle = INVALID_HANDLE_VALUE;
#endif
}

static cl_error_t action_source_set_display_path(action_source_t *source, const char *display_path)
{
    source->display_path = strdup(display_path);
    if (NULL == source->display_path) {
        return CL_EMEM;
    }

    return CL_SUCCESS;
}

#ifndef _WIN32
static cl_error_t action_source_absolute_path_dup(const char *path, char **absolute_path)
{
    char cwd[PATH_MAX + 1];

    if ((NULL == path) || (NULL == absolute_path)) {
        return CL_EARG;
    }

    *absolute_path = NULL;

    if (cli_is_abspath(path)) {
        *absolute_path = strdup(path);
    } else {
        if (NULL == getcwd(cwd, sizeof(cwd))) {
            return CL_EOPEN;
        }

        *absolute_path = cli_newfilepath(cwd, path);
    }

    return (NULL == *absolute_path) ? CL_EMEM : CL_SUCCESS;
}

static cl_error_t action_source_fallback_action_path_dup(const char *path, char **action_path)
{
    cl_error_t status;

    if ((NULL == path) || (NULL == action_path)) {
        return CL_EARG;
    }

    *action_path = NULL;

    status = cli_realpath(path, action_path);
    if ((CL_SUCCESS == status) && (NULL != *action_path)) {
        return CL_SUCCESS;
    }

    if (NULL != *action_path) {
        free(*action_path);
        *action_path = NULL;
    }

    if ((action == action_move) || (action == action_remove)) {
        return (CL_SUCCESS == status) ? CL_EOPEN : status;
    }

    return action_source_absolute_path_dup(path, action_path);
}

static cl_error_t action_source_populate_posix(action_source_t *source, int fd, const char *open_path)
{
    cl_error_t status = CL_EOPEN;

    if (0 != action_fstat_nointr(fd, &source->statbuf)) {
        goto done;
    }
    source->has_stat = true;

    if (!S_ISREG(source->statbuf.st_mode)) {
        errno  = EINVAL;
        status = CL_EOPEN;
        goto done;
    }

    status = cli_get_filepath_from_filedesc(fd, &source->action_path);
    if (CL_SUCCESS != status) {
        /*
         * Some supported POSIX targets cannot derive a path from an open fd,
         * and Linux can also fail here when /proc/self/fd is unavailable. Fall
         * back to an absolute version of the submitted display path only for
         * those path-resolution failures. The opened fd remains the source for
         * scan/copy bytes, and move/remove still verify the path against the
         * recorded stat before unlinking.
         */
        if ((CL_BREAK != status) && (CL_EOPEN != status)) {
            goto done;
        }

        status = action_source_fallback_action_path_dup(open_path, &source->action_path);
        if (CL_SUCCESS != status) {
            goto done;
        }
    }

    status = CL_SUCCESS;

done:
    return status;
}

static cl_error_t action_source_open_posix_path(const char *open_path, bool require_resolved_path, int *fd)
{
    if ((NULL == open_path) || (NULL == fd)) {
        return CL_EARG;
    }

    *fd = -1;

    if (require_resolved_path) {
        if (!cli_is_abspath(open_path)) {
            return CL_EOPEN;
        }

        if (0 != traverse_to(open_path, false, fd)) {
            return CL_EOPEN;
        }
    } else {
        *fd = safe_open(open_path, action_source_open_flags());
        if (*fd < 0) {
            return CL_EOPEN;
        }
    }

    return CL_SUCCESS;
}
#else
static cl_error_t action_source_populate_win32(
    action_source_t *source,
    HANDLE source_handle,
    bool source_handle_can_delete)
{
    HANDLE scan_handle = INVALID_HANDLE_VALUE;
    cl_error_t status  = CL_EOPEN;

    if (FALSE == DuplicateHandle(
                     GetCurrentProcess(),
                     source_handle,
                     GetCurrentProcess(),
                     &scan_handle,
                     0,
                     FALSE,
                     DUPLICATE_SAME_ACCESS)) {
        goto done;
    }

    source->scan_fd = _open_osfhandle((intptr_t)scan_handle, _O_RDONLY | _O_BINARY);
    if (source->scan_fd < 0) {
        CloseHandle(scan_handle);
        goto done;
    }
    scan_handle = INVALID_HANDLE_VALUE;

    if (0 != action_fstat_nointr(source->scan_fd, &source->statbuf)) {
        goto done;
    }
    source->has_stat = true;

    if (!S_ISREG(source->statbuf.st_mode)) {
        errno  = EINVAL;
        status = CL_EOPEN;
        goto done;
    }

    status = cli_get_filepath_from_handle(source_handle, &source->action_path);
    if (CL_SUCCESS != status) {
        goto done;
    }

    source->handle            = source_handle;
    source->handle_can_delete = source_handle_can_delete;
    status                    = CL_SUCCESS;

done:
    if (INVALID_HANDLE_VALUE != scan_handle) {
        CloseHandle(scan_handle);
    }
    return status;
}
#endif

static cl_error_t action_source_open_path_impl(const char *display_path, const char *open_path, action_source_t *source, bool require_resolved_path)
{
    cl_error_t status = CL_EARG;
#ifndef _WIN32
    int fd = -1;
#else
    HANDLE source_handle          = INVALID_HANDLE_VALUE;
    bool source_handle_can_delete = false;
#endif

    if ((NULL == display_path) || (NULL == open_path) || (NULL == source)) {
        return CL_EARG;
    }

    action_source_init(source);

    status = action_source_set_display_path(source, display_path);
    if (CL_SUCCESS != status) {
        goto done;
    }

#ifndef _WIN32
    status = action_source_open_posix_path(open_path, require_resolved_path, &fd);
    if (CL_SUCCESS != status) {
        goto done;
    }

    status = action_source_populate_posix(source, fd, open_path);
    if (CL_SUCCESS != status) {
        goto done;
    }

    source->scan_fd = fd;
    fd              = -1;
#else
    if (0 != win32_open_source_handle(
                 open_path,
                 require_resolved_path,
                 &source_handle,
                 &source_handle_can_delete)) {
        status = CL_EOPEN;
        goto done;
    }

    status = action_source_populate_win32(source, source_handle, source_handle_can_delete);
    if (CL_SUCCESS != status) {
        goto done;
    }
    source_handle = INVALID_HANDLE_VALUE;
#endif

done:
#ifndef _WIN32
    if (-1 != fd) {
        close(fd);
    }
#else
    if (INVALID_HANDLE_VALUE != source_handle) {
        CloseHandle(source_handle);
    }
#endif
    if (CL_SUCCESS != status) {
        action_source_close(source);
    }
    return status;
}

cl_error_t action_source_open_path(const char *display_path, const char *open_path, action_source_t *source)
{
    return action_source_open_path_impl(display_path, open_path, source, true);
}

cl_error_t action_source_open(const char *display_path, action_source_t *source)
{
    return action_source_open_path_impl(display_path, display_path, source, false);
}

cl_error_t action_source_from_fd(const char *display_path, int fd, action_source_t *source)
{
    cl_error_t status = CL_EARG;
#ifndef _WIN32
    int dup_fd = -1;
#else
    intptr_t source_osfhandle = -1;
    HANDLE source_handle      = INVALID_HANDLE_VALUE;
    HANDLE dup_handle         = INVALID_HANDLE_VALUE;
#endif

    if ((NULL == display_path) || (fd < 0) || (NULL == source)) {
        return CL_EARG;
    }

    action_source_init(source);

    status = action_source_set_display_path(source, display_path);
    if (CL_SUCCESS != status) {
        goto done;
    }

#ifndef _WIN32
    do {
        dup_fd = dup(fd);
    } while ((dup_fd < 0) && (EINTR == errno));
    if (dup_fd < 0) {
        status = CL_EOPEN;
        goto done;
    }

    status = action_source_populate_posix(source, dup_fd, display_path);
    if (CL_SUCCESS != status) {
        goto done;
    }

    source->scan_fd = dup_fd;
    dup_fd          = -1;
#else
    source_osfhandle = _get_osfhandle(fd);
    if (-1 == source_osfhandle) {
        status = CL_EOPEN;
        goto done;
    }
    source_handle = (HANDLE)source_osfhandle;

    if (FALSE == DuplicateHandle(
                     GetCurrentProcess(),
                     source_handle,
                     GetCurrentProcess(),
                     &dup_handle,
                     0,
                     FALSE,
                     DUPLICATE_SAME_ACCESS)) {
        status = CL_EOPEN;
        goto done;
    }

    status = action_source_populate_win32(source, dup_handle, false);
    if (CL_SUCCESS != status) {
        goto done;
    }
    dup_handle = INVALID_HANDLE_VALUE;
#endif

done:
#ifndef _WIN32
    if (-1 != dup_fd) {
        close(dup_fd);
    }
#else
    if (INVALID_HANDLE_VALUE != dup_handle) {
        CloseHandle(dup_handle);
    }
#endif
    if (CL_SUCCESS != status) {
        action_source_close(source);
    }
    return status;
}

void action_source_close(action_source_t *source)
{
    if (NULL == source) {
        return;
    }

    if (-1 != source->scan_fd) {
        close(source->scan_fd);
    }
#ifdef _WIN32
    if ((NULL != source->handle) && (INVALID_HANDLE_VALUE != source->handle)) {
        CloseHandle((HANDLE)source->handle);
    }
#endif
    if (NULL != source->display_path) {
        free(source->display_path);
    }
    if (NULL != source->action_path) {
        free(source->action_path);
    }

    action_source_init(source);
}

static int getdest(const char *fullpath, char **newname)
{
    char *tmps, *filename;
    const char *dest_basename;
    int fd, i;

    tmps = strdup(fullpath);
    if (!tmps) {
        *newname = NULL;
        return -1;
    }
    filename = basename(tmps);

    if (!(*newname = (char *)malloc(targlen + strlen(filename) + 6))) {
        free(tmps);
        return -1;
    }
    dest_basename = filename;
    sprintf(*newname, "%s" PATHSEP "%s", actarget, dest_basename);
    for (i = 1; i < 1000; i++) {
#ifndef _WIN32
        fd = action_openat_nointr(actarget_fd, dest_basename, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_BINARY, 0600);
#else
        fd = win32_create_dest_file(dest_basename);
#endif
        if (fd >= 0) {
            if (0 != action_validate_actarget_path()) {
                int validate_errno = errno;

                (void)action_close_dest_fd(&fd);
#ifndef _WIN32
                (void)action_unlinkat_nointr(actarget_fd, dest_basename, 0);
#else
                (void)win32_delete_dest_name(dest_basename);
#endif
                errno = validate_errno;
                break;
            }
            free(tmps);
            return fd;
        }
        if (errno != EEXIST) break;
        sprintf(*newname, "%s" PATHSEP "%s.%03u", actarget, filename, i);
        dest_basename = strrchr(*newname, *PATHSEP);
        dest_basename = (NULL == dest_basename) ? *newname : dest_basename + 1;
    }
    free(tmps);
    free(*newname);
    *newname = NULL;
    return -1;
}

#ifndef _WIN32
static int action_unlink_dest_at(const char *dest_path)
{
    const char *dest_basename;

    if ((NULL == dest_path) || (-1 == actarget_fd)) {
        errno = EINVAL;
        return -1;
    }

    dest_basename = strrchr(dest_path, *PATHSEP);
    dest_basename = (NULL == dest_basename) ? dest_path : dest_basename + 1;

    return action_unlinkat_nointr(actarget_fd, dest_basename, 0);
}

static int action_link_source_to_dest(const action_source_t *source, char **newname, STATBUF *source_stat_out)
{
    char *tmps = NULL;
    char *dest_path = NULL;
    char *filename;
    const char *dest_basename;
    STATBUF dest_stat;
    int status = -1;
    int i;

    if ((NULL == source) || (NULL == source->action_path) ||
        (NULL == newname) || (-1 == actarget_fd) ||
        (false == source->has_stat) || !S_ISREG(source->statbuf.st_mode)) {
        errno = EINVAL;
        return -1;
    }

    *newname = NULL;

    tmps = strdup(source->action_path);
    if (NULL == tmps) {
        return -1;
    }
    filename = basename(tmps);

    dest_path = (char *)malloc(targlen + strlen(filename) + 6);
    if (NULL == dest_path) {
        goto done;
    }

    dest_basename = filename;
    sprintf(dest_path, "%s" PATHSEP "%s", actarget, dest_basename);
    for (i = 1; i < 1000; i++) {
        if (0 == linkat(AT_FDCWD, source->action_path, actarget_fd, dest_basename, 0)) {
            if (0 != action_fstatat_nointr(actarget_fd, dest_basename, &dest_stat, AT_SYMLINK_NOFOLLOW)) {
                (void)action_unlink_dest_at(dest_path);
                goto done;
            }

            if (!S_ISREG(dest_stat.st_mode) ||
                dest_stat.st_dev != source->statbuf.st_dev ||
                dest_stat.st_ino != source->statbuf.st_ino) {
                (void)action_unlink_dest_at(dest_path);
                errno = EAGAIN;
                goto done;
            }

            if (0 != action_validate_actarget_path()) {
                int validate_errno = errno;

                (void)action_unlink_dest_at(dest_path);
                errno = validate_errno;
                goto done;
            }

            if (NULL != source_stat_out) {
                *source_stat_out = source->statbuf;
            }
            *newname = dest_path;
            dest_path = NULL;
            status = 0;
            goto done;
        }

        if (EEXIST != errno) {
            goto done;
        }

        sprintf(dest_path, "%s" PATHSEP "%s.%03u", actarget, filename, i);
        dest_basename = strrchr(dest_path, *PATHSEP);
        dest_basename = (NULL == dest_basename) ? dest_path : dest_basename + 1;
    }

done:
    if (NULL != dest_path) {
        free(dest_path);
    }
    if (NULL != tmps) {
        free(tmps);
    }

    return status;
}
#endif

/**
 * @brief Traverse from root to the specified directory without following symlinks.
 *
 * The intention is so you can use `unlinkat` or `rename_at` to safely move or
 * delete the target directory.
 *
 * The caller is responsible for closing the output file descriptor if the
 * traversal succeeded.
 *
 * @param directory             The directory to traverse to (must be NULL terminated).
 * @param want_directory_handle Set to true to get the directory handle containing the file, false to get the file handle.
 * @param[out] out_handle       An open file descriptor or HANDLE (win32) for the directory.
 * @return 0                    Traverse succeeded.
 * @return -1                   Traverse failed.
 */
#ifndef _WIN32
static int traverse_to(const char *directory, bool want_directory_handle, int *out_handle)
#else
static int traverse_to(const char *directory, bool want_directory_handle, HANDLE *out_handle)
#endif
{
    int status = -1;
    size_t tokens_count;
    const char *tokens[PATH_MAX / 2];
    size_t i;
    char *tokenized_directory = NULL;
#ifndef _WIN32
    int current_handle = -1;
    int next_handle    = -1;
#else
    HANDLE current_handle = NULL;
    char *path_to_open    = NULL;
    bool is_directory     = want_directory_handle;
#endif

    if (NULL == directory || NULL == out_handle) {
        logg(LOGG_INFO, "traverse_to: Invalid arguments!\n");
        goto done;
    }

    tokenized_directory = strdup(directory);
    if (NULL == tokenized_directory) {
        logg(LOGG_INFO, "traverse_to: Failed to get copy of directory path to be tokenized!\n");
        goto done;
    }

    tokens_count = cli_strtokenize(tokenized_directory, *PATHSEP, PATH_MAX / 2, tokens);
    if (0 == tokens_count) {
        logg(LOGG_INFO, "traverse_to: tokenize of target directory returned 0 tokens!\n");
        goto done;
    }

#ifndef _WIN32
    /*
     * Open the root(/) directory, because it won't be the first token like a
     * drive letter (i.e. "C:") would be on Windows.
     */
    current_handle = action_open_directory_nointr("/");
    if (-1 == current_handle) {
        logg(LOGG_INFO, "traverse_to: Failed to open file descriptor for '/' directory.\n");
        goto done;
    }
#endif

    if (true == want_directory_handle) {
        tokens_count -= 1;
    }

#ifndef _WIN32
    if (0 == tokens_count) {
        status         = 0;
        *out_handle    = current_handle;
        current_handle = -1;
        goto done;
    }
#endif

    for (i = 0; i < tokens_count; i++) {
        if (0 == strlen(tokens[i])) {
            /* Empty token, likely first / or double // */
            continue;
        }

#ifndef _WIN32
        bool is_final_component;

        is_final_component = (false == want_directory_handle) && (i + 1 == tokens_count);
        next_handle        = is_final_component
                                 ? action_openat_source_nointr(current_handle, tokens[i])
                                 : action_openat_directory_nointr(current_handle, tokens[i]);
        if (-1 == next_handle) {
            logg(LOGG_INFO, "traverse_to: Failed open %s\n", tokens[i]);
            goto done;
        }
        close(current_handle);
        current_handle = next_handle;
        next_handle    = -1;

#else
        (void)i;
        break;
#endif

        logg(LOGG_DEBUG, "traverse_to: Handle opened for '%s' directory.\n", tokens[i]);
    }

#ifdef _WIN32
    if (true == want_directory_handle) {
        path_to_open = win32_parent_path_dup(directory);
        if (NULL == path_to_open) {
            logg(LOGG_INFO, "traverse_to: Failed to determine parent directory for '%s'\n", directory);
            goto done;
        }
    } else {
        path_to_open = strdup(directory);
        if (NULL == path_to_open) {
            logg(LOGG_INFO, "traverse_to: Failed to copy path '%s'\n", directory);
            goto done;
        }
    }

    if (0 != (is_directory
                  ? win32_open_existing_path(
                        path_to_open,
                        true,
                        win32_directory_anchor_access(),
                        &current_handle)
                  : win32_open_existing_path(
                        path_to_open,
                        false,
                        FILE_GENERIC_READ | READ_CONTROL | DELETE,
                        &current_handle))) {
        logg(LOGG_INFO, "traverse_to: Failed open %s\n", path_to_open);
        goto done;
    }
#endif

    status      = 0;
    *out_handle = current_handle;

done:
#ifndef _WIN32
    if ((-1 == status) && (-1 != current_handle)) {
        close(current_handle);
    }
#else
    if ((-1 == status) && (NULL != current_handle)) {
        CloseHandle(current_handle);
    }
    if (NULL != path_to_open) {
        free(path_to_open);
    }
#endif
    if (NULL != tokenized_directory) {
        free(tokenized_directory);
    }

    return status;
}

#ifndef _WIN32
#define ACTION_PRIVATE_UNLINK_NAME_SIZE 96

/**
 * @brief Compare two stat results to determine whether they name the same file.
 */
static bool action_stat_same_file(const STATBUF *first, const STATBUF *second)
{
    return (first->st_dev == second->st_dev) && (first->st_ino == second->st_ino);
}

/**
 * @brief Check whether a stat result describes a private unlink directory.
 */
static bool action_stat_is_private_unlink_dir(const STATBUF *statbuf)
{
    return S_ISDIR(statbuf->st_mode) &&
           (statbuf->st_uid == geteuid()) &&
           (0 == (statbuf->st_mode & (S_IRWXG | S_IRWXO)));
}

/**
 * @brief Stat an opened private directory and the parent-relative name for it.
 */
static int action_stat_open_private_dir(int parent_fd, const char *name, int private_fd, STATBUF *fd_stat, STATBUF *path_stat)
{
    if ((parent_fd < 0) || (NULL == name) || (private_fd < 0) || (NULL == fd_stat) || (NULL == path_stat)) {
        errno = EINVAL;
        return -1;
    }

    if (0 != action_fstat_nointr(private_fd, fd_stat)) {
        return -1;
    }

    if (0 != action_fstatat_nointr(parent_fd, name, path_stat, AT_SYMLINK_NOFOLLOW)) {
        return -1;
    }

    if (!action_stat_same_file(fd_stat, path_stat)) {
        errno = EAGAIN;
        return -1;
    }

    return 0;
}

/**
 * @brief Verify that an opened private unlink directory is still safely named.
 */
static int action_verify_private_unlink_dir(int parent_fd, const char *name, int private_fd, const STATBUF *created_stat)
{
    STATBUF fd_stat;
    STATBUF path_stat;

    if (NULL == created_stat) {
        errno = EINVAL;
        return -1;
    }

    if (0 != action_stat_open_private_dir(parent_fd, name, private_fd, &fd_stat, &path_stat)) {
        return -1;
    }

    if (!action_stat_same_file(&fd_stat, created_stat) ||
        !action_stat_same_file(&path_stat, created_stat)) {
        errno = EAGAIN;
        return -1;
    }

    /*
     * mkdirat() returns no fd, so a hostile writable parent can rename the new
     * directory before openat(). Refuse a replacement that was not created by
     * this effective user or is accessible by group/other users.
     */
    if (!action_stat_is_private_unlink_dir(&fd_stat) ||
        !action_stat_is_private_unlink_dir(&path_stat)) {
        errno = EACCES;
        return -1;
    }

    return 0;
}

/**
 * @brief Remove a private unlink directory only if its name still matches its fd.
 */
static int action_unlink_private_unlink_dir(int parent_fd, const char *name, int private_fd)
{
    STATBUF fd_stat;
    STATBUF path_stat;

    if (0 != action_stat_open_private_dir(parent_fd, name, private_fd, &fd_stat, &path_stat)) {
        return -1;
    }

    if (!action_stat_is_private_unlink_dir(&fd_stat) ||
        !action_stat_is_private_unlink_dir(&path_stat)) {
        errno = EACCES;
        return -1;
    }

    return action_unlinkat_nointr(parent_fd, name, AT_REMOVEDIR);
}

/**
 * @brief Remove a just-created private unlink directory before its fd is open.
 */
static int action_unlink_created_private_unlink_dir(int parent_fd, const char *name, const STATBUF *created_stat)
{
    STATBUF path_stat;

    if ((parent_fd < 0) || (NULL == name) || (NULL == created_stat)) {
        errno = EINVAL;
        return -1;
    }

    if (0 != action_fstatat_nointr(parent_fd, name, &path_stat, AT_SYMLINK_NOFOLLOW)) {
        return -1;
    }

    if (!action_stat_same_file(&path_stat, created_stat) ||
        !action_stat_is_private_unlink_dir(&path_stat)) {
        errno = EAGAIN;
        return -1;
    }

    return action_unlinkat_nointr(parent_fd, name, AT_REMOVEDIR);
}

/**
 * @brief Create and open a private directory under an already validated parent.
 *
 * The private directory is used to capture a source basename with renameat()
 * before verifying and unlinking it. Holding the directory fd keeps later
 * verification and deletion bound to the directory object even if the private
 * directory name is renamed by another process.
 *
 * @param parent_fd       Validated parent directory fd.
 * @param[out] name       Buffer that receives the private directory basename.
 * @param name_size       Size of the name buffer.
 * @param[out] private_fd Open fd for the private directory.
 * @return 0             Directory was created and opened.
 * @return -1            Directory creation/open failed.
 */
static int action_create_private_unlink_dir(int parent_fd, char *name, size_t name_size, int *private_fd)
{
    unsigned int i;

    if ((parent_fd < 0) || (NULL == name) || (0 == name_size) || (NULL == private_fd)) {
        errno = EINVAL;
        return -1;
    }

    *private_fd = -1;
    name[0]     = '\0';

    for (i = 0; i < 1000; i++) {
        STATBUF created_stat;
        int rc;

        rc = snprintf(
            name,
            name_size,
            ".clamav-unlink-%ld-%u-%u",
            (long)getpid(),
            cli_rndnum(0xffffff),
            i);
        if ((rc < 0) || ((size_t)rc >= name_size)) {
            errno = ENAMETOOLONG;
            return -1;
        }

        if (0 == action_mkdirat_nointr(parent_fd, name, 0700)) {
            if (0 != action_fstatat_nointr(parent_fd, name, &created_stat, AT_SYMLINK_NOFOLLOW)) {
                return -1;
            }
            if (!action_stat_is_private_unlink_dir(&created_stat)) {
                errno = EACCES;
                return -1;
            }

            *private_fd = action_openat_directory_nointr(parent_fd, name);
            if (*private_fd < 0) {
                int saved_errno = errno;

                (void)action_unlink_created_private_unlink_dir(parent_fd, name, &created_stat);
                errno = saved_errno;
                return -1;
            }
            if (0 != action_verify_private_unlink_dir(parent_fd, name, *private_fd, &created_stat)) {
                int saved_errno = errno;

                (void)action_unlink_private_unlink_dir(parent_fd, name, *private_fd);
                close(*private_fd);
                *private_fd = -1;
                errno       = saved_errno;
                return -1;
            }
            return 0;
        }

        if (EEXIST != errno) {
            return -1;
        }
    }

    errno = EEXIST;
    return -1;
}

/**
 * @brief Restore a captured replacement that should not be unlinked.
 *
 * The capture directory contains a basename that did not match the scanned
 * source after renameat(). Restore without overwriting anything that may have
 * appeared at the original basename while the action was deciding whether to
 * unlink the captured entry.
 *
 * @param target_directory_fd  Validated directory fd for the original basename.
 * @param private_directory_fd Private capture directory fd.
 * @param target_basename      Basename shared by the original and captured path.
 * @param captured_stat        stat() result for the captured basename.
 * @param supports_noreplace_restore Whether no-replace rename is available.
 * @return 0                  Captured entry was restored and removed from the
 *                            private directory.
 * @return -1                 Restore failed or cannot be done safely.
 */
static int action_restore_captured_unlink_target(
    int target_directory_fd,
    int private_directory_fd,
    const char *target_basename,
    const STATBUF *captured_stat,
    bool supports_noreplace_restore)
{
    int link_errno;

    if ((target_directory_fd < 0) || (private_directory_fd < 0) ||
        (NULL == target_basename) || (NULL == captured_stat)) {
        errno = EINVAL;
        return -1;
    }

    /*
     * linkat() restores regular files, symlinks, FIFOs, and other linkable
     * non-directory entries without overwriting a new entry that may have
     * appeared at the original basename.
     */
    if (0 == linkat(
                 private_directory_fd,
                 target_basename,
                 target_directory_fd,
                 target_basename,
                 0)) {
        return action_unlinkat_nointr(private_directory_fd, target_basename, 0);
    }
    link_errno = errno;

    if (EEXIST == link_errno) {
        errno = link_errno;
        return -1;
    }

    /*
     * Directories cannot be hard-linked, and non-directory hard-link restores
     * can be denied by policy such as Linux protected_hardlinks. Only use a
     * no-replace rename fallback where the platform provides one; plain
     * renameat() could overwrite a new entry that raced into the original
     * basename.
     */
    if (supports_noreplace_restore) {
        return action_renameat_noreplace_nointr(
            private_directory_fd,
            target_basename,
            target_directory_fd,
            target_basename);
    }

    errno = S_ISDIR(captured_stat->st_mode) ? ENOTSUP : link_errno;
    return -1;
}
#endif

/**
 * @brief Unlink (delete) a target file without following symlinks.
 *
 * This approach mitigates the possibility that one of the directories
 * in the path has been replaced with a malicious symlink.
 *
 * @param target    A file to be deleted.
 * @return 0        Unlink succeeded.
 * @return -1       Unlink failed.
 */
#ifndef _WIN32
static int traverse_unlink(const char *target, const STATBUF *expected_stat)
#else
static int traverse_unlink(
    const char *target,
    HANDLE target_file_handle,
    bool target_file_handle_can_delete)
#endif
{
    int status = -1;
    cl_error_t ret;
#ifndef _WIN32
    int target_directory_fd = -1;
    int private_directory_fd = -1;
    char private_directory_name[ACTION_PRIVATE_UNLINK_NAME_SIZE] = {0};
    STATBUF current_stat;
    STATBUF captured_stat;
    int rc;
    bool supports_noreplace_restore = false;
#else
    HANDLE delete_handle = INVALID_HANDLE_VALUE;
    bool close_delete_handle = true;
#endif
    char *target_basename = NULL;

    if (NULL == target) {
        logg(LOGG_INFO, "traverse_unlink: Invalid arguments!\n");
        goto done;
    }

#ifndef _WIN32
    /* On posix, we want a file descriptor for the directory */
    if (0 != traverse_to(target, true, &target_directory_fd)) {
        goto done;
    }
#else
    if (target_file_handle_can_delete) {
        delete_handle       = target_file_handle;
        close_delete_handle = false;
    } else {
        if (0 != win32_open_delete_handle_for_source(target, target_file_handle, &delete_handle)) {
            logg(LOGG_INFO, "traverse_unlink: Failed to open '%s' for delete. Error: %lu\n", target, GetLastError());
            goto done;
        }
    }

    if (0 != win32_delete_handle(delete_handle)) {
        logg(LOGG_INFO, "traverse_unlink: Failed to delete '%s'. Error: %lu\n", target, GetLastError());
        goto done;
    }
#endif

#ifndef _WIN32
    ret = cli_basename(target, strlen(target), &target_basename);
    if (CL_SUCCESS != ret) {
        logg(LOGG_INFO, "traverse_unlink: Failed to get basename of target path: %s\n\tError: %d\n", target, (int)ret);
        goto done;
    }

    if (NULL == expected_stat) {
        if (0 != action_unlinkat_nointr(target_directory_fd, target_basename, 0)) {
            logg(LOGG_INFO, "traverse_unlink: Failed to unlink: %s\nError:%s\n", target, strerror(errno));
            goto done;
        }
    } else {
        if (0 != action_create_private_unlink_dir(
                     target_directory_fd,
                     private_directory_name,
                     sizeof(private_directory_name),
                     &private_directory_fd)) {
            logg(LOGG_INFO, "traverse_unlink: Failed to create private unlink directory for '%s': %s\n", target, strerror(errno));
            goto done;
        }

        supports_noreplace_restore = action_private_dir_supports_noreplace_rename(private_directory_fd);
        if (!supports_noreplace_restore) {
            /*
             * This is intentionally conservative. Regular captured entries can
             * usually be restored with linkat(), but the basename can still
             * race from the checked regular file to a directory before the
             * private rename. Without an atomic no-replace directory restore,
             * refusing the action preserves the CLAM-2959 guarantee that a
             * failed quarantine action does not remove or hide a replacement.
             */
            logg(LOGG_INFO, "traverse_unlink: Refusing to capture '%s' because no-replace restore is unavailable.\n", target);
            errno = ENOTSUP;
            goto done;
        }

        do {
            rc = action_fstatat_nointr(target_directory_fd, target_basename, &current_stat, AT_SYMLINK_NOFOLLOW);
        } while ((rc < 0) && (EINTR == errno));

        if (0 != rc) {
            logg(LOGG_INFO, "traverse_unlink: Failed to restat '%s' before capture: %s\n", target, strerror(errno));
            goto done;
        }

        if (!S_ISREG(current_stat.st_mode) ||
            current_stat.st_dev != expected_stat->st_dev ||
            current_stat.st_ino != expected_stat->st_ino) {
            errno = EAGAIN;
            logg(LOGG_INFO, "traverse_unlink: Refusing to capture '%s' because the source changed after validation.\n", target);
            goto done;
        }

        if (0 != action_renameat_nointr(target_directory_fd, target_basename, private_directory_fd, target_basename)) {
            logg(LOGG_INFO, "traverse_unlink: Failed to capture '%s' before unlink: %s\n", target, strerror(errno));
            goto done;
        }

        do {
            rc = action_fstatat_nointr(private_directory_fd, target_basename, &captured_stat, AT_SYMLINK_NOFOLLOW);
        } while ((rc < 0) && (EINTR == errno));

        if (0 != rc) {
            logg(LOGG_INFO, "traverse_unlink: Failed to restat captured '%s' before unlink: %s\n", target, strerror(errno));
            goto done;
        }

        if (!S_ISREG(captured_stat.st_mode) ||
            captured_stat.st_dev != expected_stat->st_dev ||
            captured_stat.st_ino != expected_stat->st_ino) {
            if (0 != action_restore_captured_unlink_target(
                         target_directory_fd,
                         private_directory_fd,
                         target_basename,
                         &captured_stat,
                         supports_noreplace_restore)) {
                logg(LOGG_INFO, "traverse_unlink: Failed to restore captured replacement for '%s': %s\n", target, strerror(errno));
            }
            errno = EAGAIN;
            logg(LOGG_INFO, "traverse_unlink: Refusing to unlink '%s' because the captured source does not match the scanned file.\n", target);
            goto done;
        }

        if (0 != action_unlinkat_nointr(private_directory_fd, target_basename, 0)) {
            logg(LOGG_INFO, "traverse_unlink: Failed to unlink captured source for %s\nError:%s\n", target, strerror(errno));
            goto done;
        }
    }
#endif

    status = 0;

done:

    if (NULL != target_basename) {
        free(target_basename);
    }

#ifndef _WIN32
    if (-1 != private_directory_fd) {
        if (('\0' != private_directory_name[0]) &&
            (0 != action_unlink_private_unlink_dir(target_directory_fd, private_directory_name, private_directory_fd)) &&
            (ENOENT != errno)) {
            logg(LOGG_DEBUG, "traverse_unlink: Failed to remove private unlink directory '%s': %s\n",
                 private_directory_name,
                 strerror(errno));
        }
        close(private_directory_fd);
    }
    if (-1 != target_directory_fd) {
        close(target_directory_fd);
    }
#else
    if (close_delete_handle && (INVALID_HANDLE_VALUE != delete_handle)) {
        CloseHandle(delete_handle);
    }
#endif
    return status;
}

static const char *action_source_display_path(const action_source_t *source)
{
    return ((NULL != source) && (NULL != source->display_path)) ? source->display_path : "(null)";
}

static const char *action_source_action_path(const action_source_t *source)
{
    return ((NULL != source) && (NULL != source->action_path)) ? source->action_path : NULL;
}

static bool action_source_show_action_path(const action_source_t *source)
{
    const char *display_path = action_source_display_path(source);
    const char *action_path  = action_source_action_path(source);

    return (NULL != action_path) && (0 != strcmp(display_path, action_path));
}

static void action_move(const action_source_t *source)
{
    char *nuname = NULL;
    int fd       = -1;
    const char *filename;
    const char *action_filename;
    bool show_action_path;
#ifndef _WIN32
    STATBUF source_stat;
#endif

    filename          = action_source_display_path(source);
    action_filename   = action_source_action_path(source);
    show_action_path  = action_source_show_action_path(source);

    if ((NULL == source) || (NULL == action_filename)) {
        logg(LOGG_ERROR, "Can't move file '%s'\n", filename);
        notmoved++;
        goto done;
    }

#ifndef _WIN32
    if (0 == action_link_source_to_dest(source, &nuname, &source_stat)) {
        if (0 != action_validate_actarget_path()) {
            if (show_action_path) {
                logg(LOGG_ERROR, "Can't move file '%s' (real path: '%s'): quarantine destination '%s' is unavailable\n", filename, action_filename, actarget);
            } else {
                logg(LOGG_ERROR, "Can't move file '%s': quarantine destination '%s' is unavailable\n", filename, actarget);
            }
            (void)action_unlink_dest_at(nuname);
            notmoved++;
            goto done;
        }
        if (0 != traverse_unlink(action_filename, &source_stat)) {
            int unlink_errno = errno;
            if (show_action_path) {
                logg(LOGG_ERROR, "Can't unlink '%s' (real path: '%s') after linking into quarantine: %s\n", filename, action_filename, strerror(unlink_errno));
            } else {
                logg(LOGG_ERROR, "Can't unlink '%s' after linking into quarantine: %s\n", filename, strerror(unlink_errno));
            }
            if (EAGAIN != unlink_errno) {
                (void)action_unlink_dest_at(nuname);
            }
            notmoved++;
        } else if (show_action_path) {
            logg(LOGG_INFO, "%s (real path: '%s'): moved to '%s'\n", filename, action_filename, nuname);
        } else {
            logg(LOGG_INFO, "%s: moved to '%s'\n", filename, nuname);
        }
        goto done;
    }
#endif

    fd = getdest(action_filename, &nuname);

#ifndef _WIN32
    if (fd < 0 || filecopy_to_fd(source, fd, &source_stat) || action_close_dest_fd(&fd)) {
#else
    if (fd < 0 || filecopy_to_fd(source, nuname, fd) || action_close_dest_fd(&fd)) {
#endif
        if (NULL != nuname) {
            if (show_action_path) {
                logg(LOGG_ERROR, "Can't move file '%s' (real path: '%s') to '%s'\n", filename, action_filename, nuname);
            } else {
                logg(LOGG_ERROR, "Can't move file '%s' to '%s'\n", filename, nuname);
            }
        } else {
            if (show_action_path) {
                logg(LOGG_ERROR, "Can't move file '%s' (real path: '%s'): quarantine destination '%s' is unavailable\n", filename, action_filename, actarget);
            } else {
                logg(LOGG_ERROR, "Can't move file '%s': quarantine destination '%s' is unavailable\n", filename, actarget);
            }
        }
        notmoved++;
        if (nuname) {
#ifndef _WIN32
            action_unlink_dest_at(nuname);
#else
            if (fd >= 0) {
                close(fd);
                fd = -1;
            }
            (void)win32_delete_dest_path(nuname);
#endif
        }
    } else {
        if (0 != action_validate_actarget_path()) {
            if (show_action_path) {
                logg(LOGG_ERROR, "Can't move file '%s' (real path: '%s'): quarantine destination '%s' is unavailable\n", filename, action_filename, actarget);
            } else {
                logg(LOGG_ERROR, "Can't move file '%s': quarantine destination '%s' is unavailable\n", filename, actarget);
            }
            notmoved++;
#ifndef _WIN32
            action_unlink_dest_at(nuname);
#else
            if (fd >= 0) {
                close(fd);
                fd = -1;
            }
            (void)win32_delete_dest_path(nuname);
#endif
            goto done;
        }
#ifndef _WIN32
        if (0 != traverse_unlink(action_filename, &source_stat)) {
            if (show_action_path) {
                logg(LOGG_ERROR, "Can't unlink '%s' (real path: '%s') after copy: %s\n", filename, action_filename, strerror(errno));
            } else {
                logg(LOGG_ERROR, "Can't unlink '%s' after copy: %s\n", filename, strerror(errno));
            }
#else
        if (0 != traverse_unlink(
                     action_filename,
                     (HANDLE)source->handle,
                     source->handle_can_delete)) {
            DWORD delete_error = GetLastError();
            if (show_action_path) {
                logg(LOGG_ERROR, "Can't unlink '%s' (real path: '%s') after copy. Error: %lu\n", filename, action_filename, delete_error);
            } else {
                logg(LOGG_ERROR, "Can't unlink '%s' after copy. Error: %lu\n", filename, delete_error);
            }
#endif
            notmoved++;
        } else {
            if (show_action_path) {
                logg(LOGG_INFO, "%s (real path: '%s'): moved to '%s'\n", filename, action_filename, nuname);
            } else {
                logg(LOGG_INFO, "%s: moved to '%s'\n", filename, nuname);
            }
        }
    }

done:
    if (fd >= 0) close(fd);
    if (NULL != nuname) free(nuname);
    return;
}

static void action_copy(const action_source_t *source)
{
    char *nuname = NULL;
    int fd       = -1;
    const char *filename;
    const char *action_filename;
    bool show_action_path;

    filename          = action_source_display_path(source);
    action_filename   = action_source_action_path(source);
    show_action_path  = action_source_show_action_path(source);

    if ((NULL == source) || (NULL == action_filename)) {
        logg(LOGG_ERROR, "Can't copy file '%s'\n", filename);
        notmoved++;
        return;
    }

    fd = getdest(action_filename, &nuname);

#ifndef _WIN32
    if (fd < 0 || filecopy_to_fd(source, fd, NULL) || action_close_dest_fd(&fd)) {
#else
    if (fd < 0 || filecopy_to_fd(source, nuname, fd) || action_close_dest_fd(&fd)) {
#endif
        if (NULL != nuname) {
            if (show_action_path) {
                logg(LOGG_ERROR, "Can't copy file '%s' (real path: '%s') to '%s'\n", filename, action_filename, nuname);
            } else {
                logg(LOGG_ERROR, "Can't copy file '%s' to '%s'\n", filename, nuname);
            }
        } else {
            if (show_action_path) {
                logg(LOGG_ERROR, "Can't copy file '%s' (real path: '%s'): quarantine destination '%s' is unavailable\n", filename, action_filename, actarget);
            } else {
                logg(LOGG_ERROR, "Can't copy file '%s': quarantine destination '%s' is unavailable\n", filename, actarget);
            }
        }
        notmoved++;
        if (nuname) {
#ifndef _WIN32
            action_unlink_dest_at(nuname);
#else
            if (fd >= 0) {
                close(fd);
                fd = -1;
            }
            (void)win32_delete_dest_path(nuname);
#endif
        }
    } else if (0 != action_validate_actarget_path()) {
        if (show_action_path) {
            logg(LOGG_ERROR, "Can't copy file '%s' (real path: '%s'): quarantine destination '%s' is unavailable\n", filename, action_filename, actarget);
        } else {
            logg(LOGG_ERROR, "Can't copy file '%s': quarantine destination '%s' is unavailable\n", filename, actarget);
        }
        notmoved++;
#ifndef _WIN32
        action_unlink_dest_at(nuname);
#else
        if (fd >= 0) {
            close(fd);
            fd = -1;
        }
        (void)win32_delete_dest_path(nuname);
#endif
    } else if (show_action_path) {
        logg(LOGG_INFO, "%s (real path: '%s'): copied to '%s'\n", filename, action_filename, nuname);
    } else {
        logg(LOGG_INFO, "%s: copied to '%s'\n", filename, nuname);
    }

    if (fd >= 0) close(fd);
    if (nuname) free(nuname);
}

static void action_remove(const action_source_t *source)
{
    const char *filename;
    const char *action_filename;
    bool show_action_path;

    filename          = action_source_display_path(source);
    action_filename   = action_source_action_path(source);
    show_action_path  = action_source_show_action_path(source);

    if ((NULL == source) || (NULL == action_filename)) {
        logg(LOGG_ERROR, "Can't remove file '%s'\n", filename);
        notremoved++;
        goto done;
    }

#ifndef _WIN32
    if ((false == source->has_stat) ||
        !S_ISREG(source->statbuf.st_mode) ||
        (0 != traverse_unlink(action_filename, &source->statbuf))) {
#else
    if (0 != traverse_unlink(
                 action_filename,
                 (HANDLE)source->handle,
                 source->handle_can_delete)) {
#endif
        if (show_action_path) {
            logg(LOGG_ERROR, "Can't remove file '%s' (real path: '%s')\n", filename, action_filename);
        } else {
            logg(LOGG_ERROR, "Can't remove file '%s'\n", filename);
        }
        notremoved++;
    } else {
        if (show_action_path) {
            logg(LOGG_INFO, "%s (real path: '%s'): Removed.\n", filename, action_filename);
        } else {
            logg(LOGG_INFO, "%s: Removed.\n", filename);
        }
    }

done:
    return;
}

static int isdir(void)
{
    STATBUF sb;
    if (CLAMSTAT(actarget, &sb) || !S_ISDIR(sb.st_mode)) {
        logg(LOGG_ERROR, "'%s' doesn't exist or is not a directory\n", actarget);
        return 0;
    }
    return 1;
}

/*
 * Call this function at the beginning to configure the user preference.
 * Later, call the "action" callback function to perform the selection action.
 */
int actsetup(const struct optstruct *opts)
{
    int move = optget(opts, "move")->enabled;

    action_cleanup();
    if (false == action_cleanup_registered) {
        if (0 != atexit(action_cleanup)) {
            logg(LOGG_INFO, "action_setup: Failed to register cleanup handler.\n");
            return 1;
        }
        action_cleanup_registered = true;
    }

    if (move || optget(opts, "copy")->enabled) {
        const char *requested_actarget = optget(opts, move ? "move" : "copy")->strarg;
#ifndef _WIN32
        cl_error_t ret;
        int actarget_parent_fd = -1;
        char *actarget_basename = NULL;
        char *resolved_actarget = NULL;

        ret = cli_realpath(requested_actarget, &resolved_actarget);
        if (CL_SUCCESS != ret || NULL == resolved_actarget) {
            logg(LOGG_INFO, "action_setup: Failed to get realpath of %s\n", requested_actarget);
            if (NULL != resolved_actarget) {
                free(resolved_actarget);
            }
            return 1;
        }
        actarget = resolved_actarget;
#else
        actarget_normalized = win32_trim_trailing_path_separators_dup(requested_actarget);
        if (NULL == actarget_normalized) {
            logg(LOGG_INFO, "action_setup: Failed to normalize quarantine directory path %s\n", requested_actarget);
            return 1;
        }
        actarget = actarget_normalized;
#endif
        if (!isdir()) return 1;
        targlen = strlen(actarget);
#ifndef _WIN32
        ret = cli_basename(actarget, strlen(actarget), &actarget_basename);
        if ((CL_SUCCESS != ret) ||
            (0 != traverse_to(actarget, true, &actarget_parent_fd)) ||
            (-1 == (actarget_fd = action_openat_directory_nointr(actarget_parent_fd, actarget_basename)))) {
            if (-1 != actarget_parent_fd) {
                close(actarget_parent_fd);
            }
            if (NULL != actarget_basename) {
                free(actarget_basename);
            }
            logg(LOGG_INFO, "action_setup: Failed to open quarantine directory handle for %s\n", actarget);
            return 1;
        }
        close(actarget_parent_fd);
        free(actarget_basename);
        if (0 != action_setup_quarantine_lock()) {
            action_cleanup();
            return 1;
        }
#else
        HANDLE actarget_parent_handle = NULL;
        char *actarget_basename       = NULL;
        cl_error_t ret                = CL_EARG;
        size_t actarget_root_len      = win32_path_root_length(actarget, strlen(actarget));

        if ((0 != actarget_root_len) && (actarget_root_len == strlen(actarget))) {
            if (0 != win32_open_existing_path(
                         actarget,
                         true,
                         win32_directory_anchor_access(),
                         &actarget_handle)) {
                actarget_handle = INVALID_HANDLE_VALUE;
            }
        } else if (0 == traverse_to(actarget, true, &actarget_parent_handle)) {
            ret = cli_basename(actarget, strlen(actarget), &actarget_basename);
            if ((CL_SUCCESS == ret) &&
                (0 == win32_open_existing_directory_at(actarget_parent_handle, actarget_basename, &actarget_handle))) {
                CloseHandle(actarget_parent_handle);
                free(actarget_basename);
            } else {
                CloseHandle(actarget_parent_handle);
                if (NULL != actarget_basename) {
                    free(actarget_basename);
                }
                actarget_handle = INVALID_HANDLE_VALUE;
            }
        } else {
            actarget_handle = INVALID_HANDLE_VALUE;
        }

        if ((NULL == actarget_handle) || (INVALID_HANDLE_VALUE == actarget_handle)) {
            logg(LOGG_INFO, "action_setup: Failed to open quarantine directory handle for %s\n", actarget);
            return 1;
        }
#endif
        action  = move ? action_move : action_copy;
    } else if (optget(opts, "remove")->enabled)
        action = action_remove;
    return 0;
}

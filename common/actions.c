/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
#include <winternl.h>
#endif

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#if HAVE_UNISTD_H
#include <unistd.h>
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

void (*action)(const char *) = NULL;
unsigned int notmoved = 0, notremoved = 0;

static char *actarget;
static int targlen;

static int getdest(const char *fullpath, char **newname)
{
    char *tmps, *filename;
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
    sprintf(*newname, "%s" PATHSEP "%s", actarget, filename);
    for (i = 1; i < 1000; i++) {
        fd = open(*newname, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd >= 0) {
            free(tmps);
            return fd;
        }
        if (errno != EEXIST) break;
        sprintf(*newname, "%s" PATHSEP "%s.%03u", actarget, filename, i);
    }
    free(tmps);
    free(*newname);
    *newname = NULL;
    return -1;
}

#ifdef _WIN32

typedef LONG (*PNTCF)(
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

typedef void (*PRIUS)(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString);

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
        FILE_OPEN,      // CreateDisposition
        createOptions,  // CreateOptions
        NULL,           // EaBuffer
        0);             // EaLength
    if (!NT_SUCCESS(ntStatus) || (NULL == next_handle)) {
        logg(LOGG_INFO, "win32_openat: Failed to open file '%s'. \nError: 0x%x \nioStatusBlock: 0x%x\n", filename, ntStatus, ioStatusBlock.Information);
        goto done;
    }
    logg(LOGG_DEBUG, "win32_openat: Opened file \"%s\"\n", filename);

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
    bool bNeedDeleteFileAccess = false;

    HMODULE ntdll               = NULL;
    PNTCF pNtCreateFile         = NULL;
    PRIUS pRtlInitUnicodeString = NULL;

    PHANDLE current_handle = NULL;
    PHANDLE next_handle    = NULL;

    ACCESS_MASK desiredAccess = STANDARD_RIGHTS_READ | STANDARD_RIGHTS_WRITE | SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_READ_EA;
    ULONG fileAttributes      = FILE_ATTRIBUTE_DIRECTORY;
    ULONG createOptions       = FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT;
    ULONG shareAccess         = FILE_SHARE_READ;
#endif

    if (NULL == directory || NULL == out_handle) {
        logg(LOGG_INFO, "traverse_to: Invalid arguments!\n");
        goto done;
    }

#ifdef _WIN32
    ntdll = LoadLibraryA("ntdll.dll");
    if (NULL == ntdll) {
        logg(LOGG_INFO, "traverse_to: failed to load ntdll!\n");
        goto done;
    }
    pNtCreateFile = (PNTCF)GetProcAddress(ntdll, "NtCreateFile");
    if (NULL == pNtCreateFile) {
        logg(LOGG_INFO, "traverse_to: failed to get NtCreateFile proc address!\n");
        goto done;
    }
    pRtlInitUnicodeString = (PRIUS)GetProcAddress(ntdll, "RtlInitUnicodeString");
    if (NULL == pRtlInitUnicodeString) {
        logg(LOGG_INFO, "traverse_to: failed to get pRtlInitUnicodeString proc address!\n");
        goto done;
    }
#endif

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
    current_handle = open("/", O_RDONLY | O_NOFOLLOW);
    if (-1 == current_handle) {
        logg(LOGG_INFO, "traverse_to: Failed to open file descriptor for '/' directory.\n");
        goto done;
    }
#endif

    if (true == want_directory_handle) {
        tokens_count -= 1;
    }

    if (0 == tokens_count) {
        logg(LOGG_INFO, "traverse_to: Failed to get copy of directory path to be tokenized!\n");
        goto done;
    }

    for (i = 0; i < tokens_count; i++) {
        if (0 == strlen(tokens[i])) {
            /* Empty token, likely first / or double // */
            continue;
        }

#ifndef _WIN32

        next_handle = openat(current_handle, tokens[i], O_RDONLY | O_NOFOLLOW);
        if (-1 == next_handle) {
            logg(LOGG_INFO, "traverse_to: Failed open %s\n", tokens[i]);
            goto done;
        }
        close(current_handle);
        current_handle = next_handle;
        next_handle    = -1;

#else

        if (true != want_directory_handle) {
            if (i == tokens_count - 1) {
                /* Change createfile options for our target file instead of an intermediate directory. */
                desiredAccess  = FILE_GENERIC_READ | DELETE;
                fileAttributes = FILE_ATTRIBUTE_NORMAL;
                createOptions  = FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT;
                shareAccess    = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
            }
        }
        if (i == 0) {
            /* NtCreateFile requires the \???\ prefix on drive letters. Eg: \???\C:\ */
            size_t driveroot_len = strlen("\\??\\\\") + strlen(tokens[0]) + 1;
            char *driveroot      = malloc(driveroot_len);
            snprintf(driveroot, driveroot_len + 1, "\\??\\%s\\", tokens[0]);
            next_handle = win32_openat(current_handle,
                                       driveroot,
                                       pNtCreateFile,
                                       pRtlInitUnicodeString,
                                       desiredAccess,
                                       fileAttributes,
                                       createOptions,
                                       shareAccess);
            free(driveroot);
        } else {
            next_handle = win32_openat(current_handle,
                                       tokens[i],
                                       pNtCreateFile,
                                       pRtlInitUnicodeString,
                                       desiredAccess,
                                       fileAttributes,
                                       createOptions,
                                       shareAccess);
        }
        if (NULL == next_handle) {
            logg(LOGG_INFO, "traverse_to: Failed open %s\n", tokens[i]);
            goto done;
        }
        CloseHandle(current_handle);
        current_handle = next_handle;
        next_handle    = NULL;
#endif

        logg(LOGG_DEBUG, "traverse_to: Handle opened for '%s' directory.\n", tokens[i]);
    }

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
#endif
    if (NULL != tokenized_directory) {
        free(tokenized_directory);
    }

    return status;
}

/**
 * @brief Rename (move) a file from Source to Destination without following symlinks.
 *
 * This approach mitigates the possibility that one of the directories
 * in the path has been replaced with a malicious symlink.
 *
 * @param source        Source pathname.
 * @param destination   Destination pathname (including file name)
 * @return 0            Rename succeeded.
 * @return -1           Rename failed.
 */
static int traverse_rename(const char *source, const char *destination)
{
    int status = -1;
#ifndef _WIN32
    cl_error_t ret;
    int source_directory_fd = -1;
    char *source_basename   = NULL;
#else
    FILE_RENAME_INFO *fileInfo    = NULL;
    HANDLE source_file_handle     = NULL;
    HANDLE destination_dir_handle = NULL;
    WCHAR *destFilepathW          = NULL;
    int cchDestFilepath           = 0;
#endif

    if (NULL == source || NULL == destination) {
        logg(LOGG_INFO, "traverse_rename: Invalid arguments!\n");
        goto done;
    }

#ifndef _WIN32
    if (0 != traverse_to(source, true, &source_directory_fd)) {
        logg(LOGG_INFO, "traverse_rename: Failed to open file descriptor for source directory!\n");
        goto done;
    }
#else
    if (0 != traverse_to(source, false, &source_file_handle)) {
        logg(LOGG_INFO, "traverse_rename: Failed to open file descriptor for source file!\n");
        goto done;
    }
    if (0 != traverse_to(destination, true, &destination_dir_handle)) {
        logg(LOGG_INFO, "traverse_rename: Failed to open file descriptor for destination directory!\n");
        goto done;
    }
#endif

#ifndef _WIN32
    ret = cli_basename(source, strlen(source), &source_basename, false /* posix_support_backslash_pathsep */);
    if (CL_SUCCESS != ret) {
        logg(LOGG_INFO, "traverse_rename: Failed to get basename of source path:%s\n\tError: %d\n", source, (int)ret);
        goto done;
    }

    if (0 != renameat(source_directory_fd, source_basename, -1, destination)) {
        logg(LOGG_INFO, "traverse_rename: Failed to rename: %s\n\tto: %s\nError:%s\n", source, destination, strerror(errno));
        goto done;
    }
#else
    /* Convert destination filepath to a PWCHAR */
    cchDestFilepath = MultiByteToWideChar(CP_UTF8, 0, destination, strlen(destination), NULL, 0);
    destFilepathW   = calloc(cchDestFilepath * sizeof(WCHAR), 1);
    if (NULL == destFilepathW) {
        logg(LOGG_INFO, "traverse_rename: failed to allocate memory for destination basename UTF16LE string\n");
        goto done;
    }
    if (0 == MultiByteToWideChar(CP_UTF8, 0, destination, strlen(destination), destFilepathW, cchDestFilepath)) {
        logg(LOGG_INFO, "traverse_rename: failed to allocate buffer for UTF16LE version of destination file basename.\n");
        goto done;
    }

    fileInfo = calloc(1, sizeof(FILE_RENAME_INFO) + cchDestFilepath * sizeof(WCHAR));
    if (NULL == fileInfo) {
        logg(LOGG_INFO, "traverse_rename: failed to allocate memory for fileInfo struct\n");
        goto done;
    }

    fileInfo->ReplaceIfExists = TRUE;
    fileInfo->RootDirectory   = NULL;
    memcpy(fileInfo->FileName, destFilepathW, cchDestFilepath * sizeof(WCHAR));
    fileInfo->FileNameLength = cchDestFilepath;
    if (FALSE == SetFileInformationByHandle(
                     source_file_handle,                                            // FileHandle
                     FileRenameInfo,                                                // FileInformationClass
                     fileInfo,                                                      // FileInformation
                     sizeof(FILE_RENAME_INFO) + cchDestFilepath * sizeof(WCHAR))) { // Length

        logg(LOGG_INFO, "traverse_rename: Failed to set file rename info for '%s' to '%s'.\nError: %d\n", source, destination, GetLastError());
        goto done;
    }
#endif

    status = 0;

done:

#ifndef _WIN32
    if (NULL != source_basename) {
        free(source_basename);
    }

    if (-1 != source_directory_fd) {
        close(source_directory_fd);
    }
#else
    if (NULL != fileInfo) {
        free(fileInfo);
    }
    if (NULL != destFilepathW) {
        free(destFilepathW);
    }
    if (NULL != source_file_handle) {
        CloseHandle(source_file_handle);
    }
    if (NULL != destination_dir_handle) {
        CloseHandle(destination_dir_handle);
    }
#endif

    return status;
}

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
static int traverse_unlink(const char *target)
{
    int status = -1;
    cl_error_t ret;
#ifndef _WIN32
    int target_directory_fd = -1;
#else
    FILE_DISPOSITION_INFO fileInfo = {0};
    HANDLE target_file_handle      = NULL;
#endif
    char *target_basename = NULL;

    if (NULL == target) {
        logg(LOGG_INFO, "traverse_unlink: Invalid arguments!\n");
        goto done;
    }

#ifndef _WIN32
    /* On posix, we want a file descriptor for the directory */
    if (0 != traverse_to(target, true, &target_directory_fd)) {
#else
    /* On Windows, we want a handle to the file, not the directory */
    if (0 != traverse_to(target, false, &target_file_handle)) {
#endif
        logg(LOGG_INFO, "traverse_unlink: Failed to open file descriptor for target directory!\n");
        goto done;
    }

    ret = cli_basename(target, strlen(target), &target_basename, false /* posix_support_backslash_pathsep */);
    if (CL_SUCCESS != ret) {
        logg(LOGG_INFO, "traverse_unlink: Failed to get basename of target path: %s\n\tError: %d\n", target, (int)ret);
        goto done;
    }

#ifndef _WIN32
    if (0 != unlinkat(target_directory_fd, target_basename, 0)) {
        logg(LOGG_INFO, "traverse_unlink: Failed to unlink: %s\nError:%s\n", target, strerror(errno));
        goto done;
    }
#else
    fileInfo.DeleteFileA = TRUE;
    if (FALSE == SetFileInformationByHandle(
                     target_file_handle,               // FileHandle
                     FileDispositionInfo,              // FileInformationClass
                     &fileInfo,                        // FileInformation
                     sizeof(FILE_DISPOSITION_INFO))) { // Length

        logg(LOGG_INFO, "traverse_unlink: Failed to set file disposition to 'DELETE' for '%s'.\n", target);
        goto done;
    }
    if (FALSE == CloseHandle(target_file_handle)) {
        logg(LOGG_INFO, "traverse_unlink: Failed to set close & delete file '%s'.\n", target);
        goto done;
    }
    target_file_handle = NULL;
#endif

    status = 0;

done:

    if (NULL != target_basename) {
        free(target_basename);
    }

#ifndef _WIN32
    if (-1 != target_directory_fd) {
        close(target_directory_fd);
    }
#else
    if (NULL != target_file_handle) {
        CloseHandle(target_file_handle);
    }
#endif
    return status;
}

static void action_move(const char *filename)
{
    char *nuname        = NULL;
    char *real_filename = NULL;
    int fd              = -1;
    int copied          = 0;

    if (NULL == filename) {
        goto done;
    }

    fd = getdest(filename, &nuname);

#ifndef _WIN32
    if (fd < 0 || (0 != traverse_rename(filename, nuname) && ((copied = 1)) && filecopy(filename, nuname))) {
#else
    if (fd < 0 || (((copied = 1)) && filecopy(filename, nuname))) {
#endif
        logg(LOGG_ERROR, "Can't move file %s to %s\n", filename, nuname);
        notmoved++;
        if (nuname) traverse_unlink(nuname);
    } else {
        if (copied && (0 != traverse_unlink(filename)))
            logg(LOGG_ERROR, "Can't unlink '%s' after copy: %s\n", filename, strerror(errno));
        else
            logg(LOGG_INFO, "%s: moved to '%s'\n", filename, nuname);
    }

done:
    if (NULL != real_filename) free(real_filename);
    if (fd >= 0) close(fd);
    if (NULL != nuname) free(nuname);
    return;
}

static void action_copy(const char *filename)
{
    char *nuname;
    int fd = getdest(filename, &nuname);

    if (fd < 0 || filecopy(filename, nuname)) {
        logg(LOGG_ERROR, "Can't copy file '%s'\n", filename);
        notmoved++;
        if (nuname) traverse_unlink(nuname);
    } else
        logg(LOGG_INFO, "%s: copied to '%s'\n", filename, nuname);

    if (fd >= 0) close(fd);
    if (nuname) free(nuname);
}

static void action_remove(const char *filename)
{
    char *real_filename = NULL;

    if (NULL == filename) {
        goto done;
    }

    if (0 != traverse_unlink(filename)) {
        logg(LOGG_ERROR, "Can't remove file '%s'\n", filename);
        notremoved++;
    } else {
        logg(LOGG_INFO, "%s: Removed.\n", filename);
    }

done:
    if (NULL != real_filename) free(real_filename);
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
    if (move || optget(opts, "copy")->enabled) {
#ifndef _WIN32
        cl_error_t ret;
#endif
        actarget = optget(opts, move ? "move" : "copy")->strarg;
#ifndef _WIN32
        ret = cli_realpath((const char *)actarget, &actarget);
        if (CL_SUCCESS != ret || NULL == actarget) {
            logg(LOGG_INFO, "action_setup: Failed to get realpath of %s\n", actarget);
            return 0;
        }
#endif
        if (!isdir()) return 1;
        action  = move ? action_move : action_copy;
        targlen = strlen(actarget);
    } else if (optget(opts, "remove")->enabled)
        action = action_remove;
    return 0;
}

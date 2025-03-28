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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifndef _WIN32
#include <sys/socket.h>
#include <pwd.h>
#include <grp.h>
#include <sys/types.h>
#endif
#include <dirent.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>

// libclamav
#include "cvd.h"
#include "others.h" /* for cli_rmdirs() */
#include "regex/regex.h"
#include "version.h"

#include "optparser.h"
#include "output.h"
#include "misc.h"

#include <signal.h>

#ifndef WIN32
#include <sys/wait.h>
#endif

#ifndef REPO_VERSION
#define REPO_VERSION "exported"
#endif

const char *get_version(void)
{
    if (!strncmp("devel-", VERSION, 6) && strcmp("exported", REPO_VERSION)) {
        return REPO_VERSION "" VERSION_SUFFIX;
    }
    /* it is a release, or we have nothing better */
    return VERSION "" VERSION_SUFFIX;
}

char *freshdbdir(void)
{
    struct cl_cvd *d1, *d2;
    struct optstruct *opts;
    const struct optstruct *opt;
    const char *dbdir;
    char *retdir;

    /* try to find the most up-to-date db directory */
    dbdir = cl_retdbdir();
    if ((opts = optparse(OPT_CONFDIR_FRESHCLAM, 0, NULL, 0, OPT_FRESHCLAM, 0, NULL))) {
        if ((opt = optget(opts, "DatabaseDirectory"))->enabled) {
            if (strcmp(dbdir, opt->strarg)) {
                char *daily = (char *)malloc(strlen(opt->strarg) + strlen(dbdir) + 30);
                if (daily == NULL) {
                    fprintf(stderr, "Unable to allocate memory for db directory...\n");
                    return NULL;
                }
                sprintf(daily, "%s" PATHSEP "daily.cvd", opt->strarg);
                if (access(daily, R_OK))
                    sprintf(daily, "%s" PATHSEP "daily.cld", opt->strarg);

                if (!access(daily, R_OK) && (d1 = cl_cvdhead(daily))) {
                    sprintf(daily, "%s" PATHSEP "daily.cvd", dbdir);
                    if (access(daily, R_OK))
                        sprintf(daily, "%s" PATHSEP "daily.cld", dbdir);

                    if (!access(daily, R_OK) && (d2 = cl_cvdhead(daily))) {
                        free(daily);
                        if (d1->version > d2->version)
                            dbdir = opt->strarg;
                        cl_cvdfree(d2);
                    } else {
                        free(daily);
                        dbdir = opt->strarg;
                    }
                    cl_cvdfree(d1);
                } else {
                    free(daily);
                }
            }
        }
    }

    retdir = strdup(dbdir);

    if (opts)
        optfree(opts);

    return retdir;
}

void print_version(const char *dbdir)
{
    char *fdbdir = NULL, *path;
    const char *pt;
    struct cl_cvd *daily;
    time_t db_time;
    unsigned int db_version = 0;

    if (dbdir)
        pt = dbdir;
    else
        pt = fdbdir = freshdbdir();

    if (!pt) {
        printf("ClamAV %s\n", get_version());
        return;
    }

    if (!(path = malloc(strlen(pt) + 11))) {
        if (!dbdir)
            free(fdbdir);
        return;
    }

    sprintf(path, "%s" PATHSEP "daily.cvd", pt);
    if (!access(path, R_OK)) {
        daily = cl_cvdhead(path);
        if (daily) {
            db_version = daily->version;
            db_time    = daily->stime;
            cl_cvdfree(daily);
        }
    }

    sprintf(path, "%s" PATHSEP "daily.cld", pt);
    if (!access(path, R_OK)) {
        daily = cl_cvdhead(path);
        if (daily) {
            if (daily->version > db_version) {
                db_version = daily->version;
                db_time    = daily->stime;
            }
            cl_cvdfree(daily);
        }
    }

    if (!dbdir)
        free(fdbdir);

    if (db_version) {
        printf("ClamAV %s/%u/%s", get_version(), db_version, ctime(&db_time));
    } else {
        printf("ClamAV %s\n", get_version());
    }

    free(path);
}

int check_flevel(void)
{
    if (cl_retflevel() < CL_FLEVEL) {
        fprintf(stderr, "ERROR: This tool requires libclamav with functionality level %u or higher (current f-level: %u)\n", CL_FLEVEL, cl_retflevel());
        return 1;
    }
    return 0;
}

const char *filelist(const struct optstruct *opts, int *err)
{
    static char buff[1025];
    static unsigned int cnt = 0;
    const struct optstruct *opt;
    static FILE *fs = NULL;
    size_t len;

    if (!cnt && (opt = optget(opts, "file-list"))->enabled) {
        if (!fs) {
            fs = fopen(opt->strarg, "r");
            if (!fs) {
                fprintf(stderr, "ERROR: --file-list: Can't open file %s\n", opt->strarg);
                if (err)
                    *err = 54;
                return NULL;
            }
        }

        if (fgets(buff, 1024, fs)) {
            buff[1024] = 0;
            len        = strlen(buff);
            if (!len) {
                fclose(fs);
                return NULL;
            }
            len--;
            while (len && ((buff[len] == '\n') || (buff[len] == '\r')))
                buff[len--] = '\0';
            return buff;
        } else {
            fclose(fs);
            return NULL;
        }
    }

    return opts->filename ? opts->filename[cnt++] : NULL;
}

int filecopy(const char *src, const char *dest)
{
#ifdef _WIN32
    return (!CopyFileA(src, dest, 0));
#elif defined(C_DARWIN)
    pid_t pid;

    /* On Mac OS X use ditto and copy resource fork, too. */
    switch (pid = fork()) {
        case -1:
            return -1;
        case 0:
            execl("/usr/bin/ditto", "ditto", src, dest, NULL);
            perror("execl(ditto)");
            break;
        default:
            wait(NULL);
            return 0;
    }

    return -1;

#else /* C_DARWIN */
    return cli_filecopy(src, dest);
#endif
}

#ifndef _WIN32
int close_std_descriptors()
{
    int fds[3], i;

    fds[0] = open("/dev/null", O_RDONLY);
    fds[1] = open("/dev/null", O_WRONLY);
    fds[2] = open("/dev/null", O_WRONLY);
    if (fds[0] == -1 || fds[1] == -1 || fds[2] == -1) {
        fputs("Can't open /dev/null\n", stderr);
        for (i = 0; i <= 2; i++)
            if (fds[i] != -1)
                close(fds[i]);
        return -1;
    }

    for (i = 0; i <= 2; i++) {
        if (dup2(fds[i], i) == -1) {
            fprintf(stderr, "dup2(%d, %d) failed\n", fds[i], i); /* may not be printed */
            for (i = 0; i <= 2; i++)
                if (fds[i] != -1)
                    close(fds[i]);
            return -1;
        }
    }

    for (i = 0; i <= 2; i++)
        if (fds[i] > 2)
            close(fds[i]);

    return 0;
}

int daemonize_all_return(void)
{
    pid_t pid;

    pid = fork();

    if (0 == pid) {
        setsid();
    }
    return pid;
}

int daemonize(void)
{
    int ret = 0;

    ret = close_std_descriptors();
    if (ret) {
        return ret;
    }

    ret       = daemonize_all_return();
    pid_t pid = (pid_t)ret;
    /*parent process.*/
    if (pid > 0) {
        exit(0);
    }

    return pid;
}

static void daemonize_child_initialized_handler(int sig)
{
    (void)(sig);
    exit(0);
}

int daemonize_parent_wait(const char *const user, const char *const log_file)
{
    int daemonizePid = daemonize_all_return();
    if (daemonizePid == -1) {
        return -1;
    } else if (daemonizePid) { // parent
        /* The parent will wait until either the child process
         * exits, or signals the parent that its initialization is
         * complete.  If it exits, it is due to an error condition,
         * so the parent should exit with the same error code as the child.
         * If the child signals the parent that initialization is complete, it
         * the parent will exit from the signal handler (initDoneSignalHandler)
         * with exit code 0.
         */
        struct sigaction sig;
        memset(&sig, 0, sizeof(sig));
        sigemptyset(&(sig.sa_mask));
        sig.sa_handler = daemonize_child_initialized_handler;

        if (0 != sigaction(SIGINT, &sig, NULL)) {
            perror("sigaction");
            return -1;
        }

        if (NULL != user) {
            if (drop_privileges(user, log_file)) {
                return -1;
            }
        }

        int exitStatus;
        wait(&exitStatus);
        if (WIFEXITED(exitStatus)) { // error
            exitStatus = WEXITSTATUS(exitStatus);
            exit(exitStatus);
        }
    }
    return 0;
}

void daemonize_signal_parent(pid_t parentPid)
{
    close_std_descriptors();
    kill(parentPid, SIGINT);
}

int drop_privileges(const char *const user_name, const char *const log_file)
{
    int ret = 1;

    /*This function is called in a bunch of places, and rather than change the error checking
     * in every function, we are just going to return success if there is no work to do.
     */
    if ((0 == geteuid()) && (NULL != user_name)) {
        struct passwd *user = NULL;

        if ((user = getpwnam(user_name)) == NULL) {
            logg(LOGG_WARNING, "Can't get information about user %s.\n", user_name);
            fprintf(stderr, "ERROR: Can't get information about user %s.\n", user_name);
            goto done;
        }

#ifdef HAVE_INITGROUPS
        if (initgroups(user_name, user->pw_gid)) {
            fprintf(stderr, "ERROR: initgroups() failed.\n");
            logg(LOGG_WARNING, "initgroups() failed.\n");
            goto done;
        }
#elif HAVE_SETGROUPS
        if (setgroups(1, &user->pw_gid)) {
            fprintf(stderr, "ERROR: setgroups() failed.\n");
            logg(LOGG_WARNING, "setgroups() failed.\n");
            goto done;
        }
#endif

        /*Change ownership of the log file to the user we are going to switch to.*/
        if (NULL != log_file) {
            int ret = lchown(log_file, user->pw_uid, user->pw_gid);
            if (ret) {
                fprintf(stderr, "ERROR: lchown to user '%s' failed on\n", user->pw_name);
                fprintf(stderr, "log file '%s'.\n", log_file);
                fprintf(stderr, "Error was '%s'\n", strerror(errno));
                logg(LOGG_WARNING, "lchown to user '%s' failed on log file '%s'.  Error was '%s'\n",
                     user->pw_name, log_file, strerror(errno));
                goto done;
            }
        }

        if (setgid(user->pw_gid)) {
            fprintf(stderr, "ERROR: setgid(%d) failed.\n", (int)user->pw_gid);
            logg(LOGG_WARNING, "setgid(%d) failed.\n", (int)user->pw_gid);
            goto done;
        }

        if (setuid(user->pw_uid)) {
            fprintf(stderr, "ERROR: setuid(%d) failed.\n", (int)user->pw_uid);
            logg(LOGG_WARNING, "setuid(%d) failed.\n", (int)user->pw_uid);
            goto done;
        }
    }
    ret = 0;

done:
    return ret;
}
#endif /*_WIN32*/

int match_regex(const char *filename, const char *pattern)
{
    regex_t reg;
    int match, flags = REG_EXTENDED | REG_NOSUB;
    char fname[513];
#ifdef _WIN32
    flags |= REG_ICASE; /* case insensitive on Windows */
#endif
    if (cli_regcomp(&reg, pattern, flags) != 0)
        return 2;

    if (pattern[strlen(pattern) - 1] == *PATHSEP) {
        snprintf(fname, 511, "%s" PATHSEP, filename);
        fname[512] = 0;
    } else {
        strncpy(fname, filename, 513);
        fname[512] = '\0';
    }

    match = (cli_regexec(&reg, fname, 0, NULL, 0) == REG_NOMATCH) ? 0 : 1;
    cli_regfree(&reg);
    return match;
}

int cli_is_abspath(const char *path)
{
#ifdef _WIN32
    int len = strlen(path);
    return (len > 2 && path[0] == '\\' && path[1] == '\\') || (len >= 2 && ((*path >= 'a' && *path <= 'z') || (*path >= 'A' && *path <= 'Z')) && path[1] == ':');
#else
    return *path == '/';
#endif
}

unsigned int countlines(const char *filename)
{
    FILE *fh;
    char buff[1024];
    unsigned int lines = 0;

    if ((fh = fopen(filename, "r")) == NULL)
        return 0;

    while (fgets(buff, sizeof(buff), fh)) {
        // ignore comments
        if (buff[0] == '#') continue;

        // ignore empty lines in CR/LF format
        if (buff[0] == '\r' && buff[1] == '\n') continue;

        // ignore empty lines in LF format
        if (buff[0] == '\n') continue;

        lines++;
    }

    fclose(fh);
    return lines;
}

cl_error_t check_if_cvd_outdated(const char *path, long long days)
{
    cl_error_t status;
    time_t cvd_age;

    if ((status = cl_cvdgetage(path, &cvd_age)) != CL_SUCCESS) {
        logg(LOGG_ERROR, "%s\n", cl_strerror(status));
        return status;
    }

    if (days * 86400 < cvd_age) {
        logg(LOGG_ERROR, "Virus database is older than %lld days!\n", days);
        return CL_ECVD;
    }

    return CL_SUCCESS;
}

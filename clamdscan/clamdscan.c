/*
 *  Copyright (C) 2013-2025 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2007-2013 Sourcefire, Inc.
 *
 *  Authors: Tomasz Kojm, aCaB
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
#include <string.h>
#include <stdlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifndef _WIN32
#include <sys/time.h>
#endif
#include <time.h>
#include <signal.h>

// libclamav
#include "clamav.h"

// common
#include "output.h"
#include "misc.h"
#include "optparser.h"
#include "actions.h"

#include "client.h"

void help(void);

extern int printinfected;
struct optstruct *clamdopts = NULL;

static void print_server_version(const struct optstruct *opt)
{
    if (get_clamd_version(opt)) {
        /* can't get version from server, fallback */
        printf("ClamAV %s\n", get_version());
    }
}

int main(int argc, char **argv)
{
    int ds, dms, ret, infected = 0, err = 0;
    struct timeval t1, t2;
    time_t date_start, date_end;

    struct optstruct *opts;
    const struct optstruct *opt;
    char buffer[26];
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#else /* !_WIN32 */
    struct sigaction sigact;
#endif

    if ((opts = optparse(NULL, argc, argv, 1, OPT_CLAMDSCAN, OPT_CLAMSCAN, NULL)) == NULL) {
        mprintf(LOGG_ERROR, "Can't parse command line options\n");
        exit(2);
    }

    if (optget(opts, "help")->enabled) {
        optfree(opts);
        help();
    }

    if ((clamdopts = optparse(optget(opts, "config-file")->strarg, 0, NULL, 1, OPT_CLAMD, 0, NULL)) == NULL) {
        logg(LOGG_ERROR, "Can't parse clamd configuration file %s\n", optget(opts, "config-file")->strarg);
        optfree(opts);
        exit(2);
    }

    if (optget(opts, "verbose")->enabled) {
        mprintf_verbose = 1;
        logg_verbose    = 1;
    }

    if (optget(opts, "quiet")->enabled)
        mprintf_quiet = 1;

    if (optget(opts, "stdout")->enabled)
        mprintf_stdout = 1;

    if (optget(opts, "version")->enabled) {
        print_server_version(opts);
        optfree(opts);
        optfree(clamdopts);
        exit(0);
    }

    if (optget(opts, "ping")->enabled && !optget(opts, "wait")->enabled) {
        int16_t ping_result = ping_clamd(opts);
        switch (ping_result) {
            case 0:
                ret = 0;
                break;
            case 1:
                ret = (int)CL_ETIMEOUT;
                break;
            default:
                ret = (int)CL_ERROR;
                break;
        }
        optfree(opts);
        optfree(clamdopts);
        exit(ret);
    }

    if (optget(opts, "infected")->enabled)
        printinfected = 1;

    /* initialize logger */

    if ((opt = optget(opts, "log"))->enabled) {
        logg_file = opt->strarg;
        if (logg(LOGG_INFO, "--------------------------------------\n")) {
            mprintf(LOGG_ERROR, "Problem with internal logger.\n");
            optfree(opts);
            optfree(clamdopts);
            exit(2);
        }
    } else
        logg_file = NULL;

    if (optget(opts, "reload")->enabled) {
        ret = reload_clamd_database(opts);
        optfree(opts);
        optfree(clamdopts);
        logg_close();
        exit(ret);
    }

    if (actsetup(opts)) {
        optfree(opts);
        optfree(clamdopts);
        logg_close();
        exit(2);
    }

#ifndef _WIN32
    memset(&sigact, 0, sizeof(struct sigaction));
    sigact.sa_handler = SIG_IGN;
    sigemptyset(&sigact.sa_mask);
    sigaddset(&sigact.sa_mask, SIGPIPE);
    sigaction(SIGPIPE, &sigact, NULL);
#endif

    date_start = time(NULL);
    gettimeofday(&t1, NULL);

    ret = client(opts, &infected, &err);
    optfree(clamdopts);

    /* TODO: Implement STATUS in clamd */
    if (!optget(opts, "no-summary")->enabled) {
        struct tm tmp;

        date_end = time(NULL);
        gettimeofday(&t2, NULL);
        ds  = t2.tv_sec - t1.tv_sec;
        dms = t2.tv_usec - t1.tv_usec;
        ds -= (dms < 0) ? (1) : (0);
        dms += (dms < 0) ? (1000000) : (0);
        logg(LOGG_INFO, "\n----------- SCAN SUMMARY -----------\n");
        logg(LOGG_INFO, "Infected files: %d\n", infected);
        if (err)
            logg(LOGG_INFO, "Total errors: %d\n", err);
        if (notremoved) {
            logg(LOGG_INFO, "Not removed: %d\n", notremoved);
        }
        if (notmoved) {
            logg(LOGG_INFO, "Not moved: %d\n", notmoved);
        }
        logg(LOGG_INFO, "Time: %d.%3.3d sec (%d m %d s)\n", ds, dms / 1000, ds / 60, ds % 60);

#ifdef _WIN32
        if (0 != localtime_s(&tmp, &date_start)) {
#else
        if (!localtime_r(&date_start, &tmp)) {
#endif
            logg(LOGG_ERROR, "Failed to get local time for Start Date.\n");
        }
        strftime(buffer, sizeof(buffer), "%Y:%m:%d %H:%M:%S", &tmp);
        logg(LOGG_INFO, "Start Date: %s\n", buffer);

#ifdef _WIN32
        if (0 != localtime_s(&tmp, &date_end)) {
#else
        if (!localtime_r(&date_end, &tmp)) {
#endif
            logg(LOGG_ERROR, "Failed to get local time for End Date.\n");
        }
        strftime(buffer, sizeof(buffer), "%Y:%m:%d %H:%M:%S", &tmp);
        logg(LOGG_INFO, "End Date:   %s\n", buffer);
    }

    logg_close();
    optfree(opts);

    exit(ret);
}

void help(void)
{
    mprintf_stdout = 1;

    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "                      Clam AntiVirus: Daemon Client %s\n", get_version());
    mprintf(LOGG_INFO, "           By The ClamAV Team: https://www.clamav.net/about.html#credits\n");
    mprintf(LOGG_INFO, "           (C) 2025 Cisco Systems, Inc.\n");
    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "    clamdscan [options] [file/directory/-]\n");
    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "    --help              -h             Show this help\n");
    mprintf(LOGG_INFO, "    --version           -V             Print version number and exit\n");
    mprintf(LOGG_INFO, "    --verbose           -v             Be verbose\n");
    mprintf(LOGG_INFO, "    --quiet                            Be quiet, only output error messages\n");
    mprintf(LOGG_INFO, "    --stdout                           Write to stdout instead of stderr. Does not affect 'debug' messages.\n");
    mprintf(LOGG_INFO, "                                       (this help is always written to stdout)\n");
    mprintf(LOGG_INFO, "    --log=FILE          -l FILE        Save scan report in FILE\n");
    mprintf(LOGG_INFO, "    --file-list=FILE    -f FILE        Scan files from FILE\n");
    mprintf(LOGG_INFO, "    --ping              -p A[:I]       Ping clamd up to [A] times at optional interval [I] until it responds.\n");
    mprintf(LOGG_INFO, "    --wait              -w             Wait up to 30 seconds for clamd to start. Optionally use alongside --ping to set attempts [A] and interval [I] to check clamd.\n");
    mprintf(LOGG_INFO, "    --remove                           Remove infected files. Be careful!\n");
    mprintf(LOGG_INFO, "    --move=DIRECTORY                   Move infected files into DIRECTORY\n");
    mprintf(LOGG_INFO, "    --copy=DIRECTORY                   Copy infected files into DIRECTORY\n");
    mprintf(LOGG_INFO, "    --config-file=FILE    -c           Read configuration from FILE.\n");
#ifdef _WIN32
    mprintf(LOGG_INFO, "    --memory                           Scan loaded executable modules\n");
    mprintf(LOGG_INFO, "    --kill                             Kill/Unload infected loaded modules\n");
    mprintf(LOGG_INFO, "    --unload                           Unload infected modules from processes\n");
#endif
    mprintf(LOGG_INFO, "    --allmatch            -z           Continue scanning within file after finding a match.\n");
    mprintf(LOGG_INFO, "    --multiscan           -m           Force MULTISCAN mode\n");
    mprintf(LOGG_INFO, "    --infected            -i           Only print infected files\n");
    mprintf(LOGG_INFO, "    --no-summary                       Disable summary at end of scanning\n");
    mprintf(LOGG_INFO, "    --reload                           Request clamd to reload virus database\n");
    mprintf(LOGG_INFO, "    --fdpass                           Pass filedescriptor to clamd (useful if clamd is running as a different user)\n");
    mprintf(LOGG_INFO, "    --stream                           Force streaming files to clamd (for debugging and unit testing)\n");
    mprintf(LOGG_INFO, "\n");

    exit(0);
}

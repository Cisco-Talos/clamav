/*
 *  Copyright (C) 2013-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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
#include <string.h>
#include <signal.h>
#include <locale.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifndef _WIN32
#include <sys/time.h>
#endif
#include <time.h>
#ifdef C_LINUX
#include <sys/resource.h>
#endif

// libclamav
#include "clamav.h"
#include "others.h"
#include "str.h"

// common
#include "misc.h"
#include "output.h"
#include "actions.h"
#include "optparser.h"

#include "global.h"
#include "manager.h"

void help(void);

struct s_info info;
short recursion = 0, bell = 0;
short printinfected = 0, printclean = 1;

int main(int argc, char **argv)
{
    int ds, dms, ret;
    double mb, rmb;
    struct timeval t1, t2;
    time_t date_start, date_end;

    char buffer[26];
#ifndef _WIN32
    sigset_t sigset;
#endif
    struct optstruct *opts;
    const struct optstruct *opt;

    if (check_flevel())
        exit(2);

#if !defined(_WIN32)
    if (!setlocale(LC_CTYPE, "")) {
        mprintf(WARNING, "Failed to set locale\n");
    }
#if !defined(C_BEOS)
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGXFSZ);
    sigprocmask(SIG_SETMASK, &sigset, NULL);
#endif /* !C_BEOS */
#endif /* !_WIN32 */

    cl_initialize_crypto();

    if ((opts = optparse(NULL, argc, argv, 1, OPT_CLAMSCAN, 0, NULL)) == NULL) {
        mprintf(ERROR, "Can't parse command line options\n");
        return 2;
    }

    if (optget(opts, "verbose")->enabled) {
        mprintf_verbose = 1;
        logg_verbose    = 1;
    }

    if (optget(opts, "quiet")->enabled)
        mprintf_quiet = 1;

    if (optget(opts, "stdout")->enabled)
        mprintf_stdout = 1;

    if (optget(opts, "debug")->enabled) {
#if defined(C_LINUX)
        /* njh@bandsman.co.uk: create a dump if needed */
        struct rlimit rlim;

        rlim.rlim_cur = rlim.rlim_max = RLIM_INFINITY;
        if (setrlimit(RLIMIT_CORE, &rlim) < 0)
            perror("setrlimit");
#endif
        cl_debug(); /* enable debug messages */
    }

    if (optget(opts, "gen-mdb")->enabled) {
        cl_always_gen_section_hash();
    }

    if (optget(opts, "version")->enabled) {
        print_version(optget(opts, "database")->strarg);
        optfree(opts);
        return 0;
    }

    if (optget(opts, "help")->enabled) {
        optfree(opts);
        help();
        return 0;
    }

    if (optget(opts, "recursive")->enabled)
        recursion = 1;

    if (optget(opts, "infected")->enabled)
        printinfected = 1;

    if (optget(opts, "suppress-ok-results")->enabled)
        printclean = 0;

    if (optget(opts, "bell")->enabled)
        bell = 1;

    /* initialize logger */
    if ((opt = optget(opts, "log"))->enabled) {
        logg_file = opt->strarg;
        if (logg(INFO_NF, "\n-------------------------------------------------------------------------------\n\n")) {
            mprintf(ERROR, "Problem with internal logger.\n");
            optfree(opts);
            return 2;
        }
    } else
        logg_file = NULL;

    if (actsetup(opts)) {
        optfree(opts);
        logg_close();
        exit(2);
    }

    memset(&info, 0, sizeof(struct s_info));

    date_start = time(NULL);
    gettimeofday(&t1, NULL);

    ret = scanmanager(opts);

    if (!optget(opts, "no-summary")->enabled) {
        struct tm tmp;

        date_end = time(NULL);
        gettimeofday(&t2, NULL);
        ds  = t2.tv_sec - t1.tv_sec;
        dms = t2.tv_usec - t1.tv_usec;
        ds -= (dms < 0) ? (1) : (0);
        dms += (dms < 0) ? (1000000) : (0);
        logg(INFO, "\n----------- SCAN SUMMARY -----------\n");
        logg(INFO, "Known viruses: %u\n", info.sigs);
        logg(INFO, "Engine version: %s\n", get_version());
        logg(INFO, "Scanned directories: %u\n", info.dirs);
        logg(INFO, "Scanned files: %u\n", info.files);
        logg(INFO, "Infected files: %u\n", info.ifiles);
        if (info.errors)
            logg(INFO, "Total errors: %u\n", info.errors);
        if (notremoved) {
            logg(INFO, "Not removed: %u\n", notremoved);
        }
        if (notmoved) {
            logg(INFO, "Not %s: %u\n", optget(opts, "copy")->enabled ? "moved" : "copied", notmoved);
        }
        mb = info.blocks * (CL_COUNT_PRECISION / 1024) / 1024.0;
        logg(INFO, "Data scanned: %2.2lf MB\n", mb);
        rmb = info.rblocks * (CL_COUNT_PRECISION / 1024) / 1024.0;
        logg(INFO, "Data read: %2.2lf MB (ratio %.2f:1)\n", rmb, info.rblocks ? (double)info.blocks / (double)info.rblocks : 0);
        logg(INFO, "Time: %u.%3.3u sec (%u m %u s)\n", ds, dms / 1000, ds / 60, ds % 60);

#ifdef _WIN32
        if (0 != localtime_s(&tmp, &date_start)) {
#else
        if (!localtime_r(&date_start, &tmp)) {
#endif
            logg(ERROR, "Failed to get local time for Start Date.\n");
        }
        strftime(buffer, sizeof(buffer), "%Y:%m:%d %H:%M:%S", &tmp);
        logg(INFO, "Start Date: %s\n", buffer);

#ifdef _WIN32
        if (0 != localtime_s(&tmp, &date_end)) {
#else
        if (!localtime_r(&date_end, &tmp)) {
#endif
            logg(ERROR, "Failed to get local time for End Date.\n");
        }
        strftime(buffer, sizeof(buffer), "%Y:%m:%d %H:%M:%S", &tmp);
        logg(INFO, "End Date:   %s\n", buffer);
    }

    optfree(opts);

    return ret;
}

void help(void)
{
    mprintf_stdout = 1;

    mprintf(INFO, "\n");
    mprintf(INFO, "                       Clam AntiVirus: Scanner %s\n", get_version());
    mprintf(INFO, "           By The ClamAV Team: https://www.clamav.net/about.html#credits\n");
    mprintf(INFO, "           (C) 2022 Cisco Systems, Inc.\n");
    mprintf(INFO, "\n");
    mprintf(INFO, "    clamscan [options] [file/directory/-]\n");
    mprintf(INFO, "\n");
    mprintf(INFO, "    --help                -h             Show this help\n");
    mprintf(INFO, "    --version             -V             Print version number\n");
    mprintf(INFO, "    --verbose             -v             Be verbose\n");
    mprintf(INFO, "    --archive-verbose     -a             Show filenames inside scanned archives\n");
    mprintf(INFO, "    --debug                              Enable libclamav's debug messages\n");
    mprintf(INFO, "    --quiet                              Only output error messages\n");
    mprintf(INFO, "    --stdout                             Write to stdout instead of stderr. Does not affect 'debug' messages.\n");
    mprintf(INFO, "    --no-summary                         Disable summary at end of scanning\n");
    mprintf(INFO, "    --infected            -i             Only print infected files\n");
    mprintf(INFO, "    --suppress-ok-results -o             Skip printing OK files\n");
    mprintf(INFO, "    --bell                               Sound bell on virus detection\n");
    mprintf(INFO, "\n");
    mprintf(INFO, "    --tempdir=DIRECTORY                  Create temporary files in DIRECTORY\n");
    mprintf(INFO, "    --leave-temps[=yes/no(*)]            Do not remove temporary files\n");
    mprintf(INFO, "    --gen-json[=yes/no(*)]               Generate JSON metadata for the scanned file(s). For testing & development use ONLY.\n");
    mprintf(INFO, "                                         JSON will be printed if --debug is enabled.\n");
    mprintf(INFO, "                                         A JSON file will dropped to the temp directory if --leave-temps is enabled.\n");
    mprintf(INFO, "    --database=FILE/DIR   -d FILE/DIR    Load virus database from FILE or load all supported db files from DIR\n");
    mprintf(INFO, "    --official-db-only[=yes/no(*)]       Only load official signatures\n");
    mprintf(INFO, "    --log=FILE            -l FILE        Save scan report to FILE\n");
    mprintf(INFO, "    --recursive[=yes/no(*)]  -r          Scan subdirectories recursively\n");
    mprintf(INFO, "    --allmatch[=yes/no(*)]   -z          Continue scanning within file after finding a match\n");
    mprintf(INFO, "    --cross-fs[=yes(*)/no]               Scan files and directories on other filesystems\n");
    mprintf(INFO, "    --follow-dir-symlinks[=0/1(*)/2]     Follow directory symlinks (0 = never, 1 = direct, 2 = always)\n");
    mprintf(INFO, "    --follow-file-symlinks[=0/1(*)/2]    Follow file symlinks (0 = never, 1 = direct, 2 = always)\n");
    mprintf(INFO, "    --file-list=FILE      -f FILE        Scan files from FILE\n");
    mprintf(INFO, "    --remove[=yes/no(*)]                 Remove infected files. Be careful!\n");
    mprintf(INFO, "    --move=DIRECTORY                     Move infected files into DIRECTORY\n");
    mprintf(INFO, "    --copy=DIRECTORY                     Copy infected files into DIRECTORY\n");
    mprintf(INFO, "    --exclude=REGEX                      Don't scan file names matching REGEX\n");
    mprintf(INFO, "    --exclude-dir=REGEX                  Don't scan directories matching REGEX\n");
    mprintf(INFO, "    --include=REGEX                      Only scan file names matching REGEX\n");
    mprintf(INFO, "    --include-dir=REGEX                  Only scan directories matching REGEX\n");
#ifdef _WIN32
    mprintf(INFO, "    --memory                             Scan loaded executable modules\n");
    mprintf(INFO, "    --kill                               Kill/Unload infected loaded modules\n");
    mprintf(INFO, "    --unload                             Unload infected modules from processes\n");
#endif
    mprintf(INFO, "\n");
    mprintf(INFO, "    --bytecode[=yes(*)/no]               Load bytecode from the database\n");
    mprintf(INFO, "    --bytecode-unsigned[=yes/no(*)]      Load unsigned bytecode\n");
    mprintf(INFO, "                                         **Caution**: You should NEVER run bytecode signatures from untrusted sources.\n");
    mprintf(INFO, "                                         Doing so may result in arbitrary code execution.\n");
    mprintf(INFO, "    --bytecode-timeout=N                 Set bytecode timeout (in milliseconds)\n");
    mprintf(INFO, "    --statistics[=none(*)/bytecode/pcre] Collect and print execution statistics\n");
    mprintf(INFO, "    --detect-pua[=yes/no(*)]             Detect Possibly Unwanted Applications\n");
    mprintf(INFO, "    --exclude-pua=CAT                    Skip PUA sigs of category CAT\n");
    mprintf(INFO, "    --include-pua=CAT                    Load PUA sigs of category CAT\n");
    mprintf(INFO, "    --detect-structured[=yes/no(*)]      Detect structured data (SSN, Credit Card)\n");
    mprintf(INFO, "    --structured-ssn-format=X            SSN format (0=normal,1=stripped,2=both)\n");
    mprintf(INFO, "    --structured-ssn-count=N             Min SSN count to generate a detect\n");
    mprintf(INFO, "    --structured-cc-count=N              Min CC count to generate a detect\n");
    mprintf(INFO, "    --structured-cc-mode=X               CC mode (0=credit debit and private label, 1=credit cards only\n");
    mprintf(INFO, "    --scan-mail[=yes(*)/no]              Scan mail files\n");
    mprintf(INFO, "    --phishing-sigs[=yes(*)/no]          Enable email signature-based phishing detection\n");
    mprintf(INFO, "    --phishing-scan-urls[=yes(*)/no]     Enable URL signature-based phishing detection\n");
    mprintf(INFO, "    --heuristic-alerts[=yes(*)/no]       Heuristic alerts\n");
    mprintf(INFO, "    --heuristic-scan-precedence[=yes/no(*)] Stop scanning as soon as a heuristic match is found\n");
    mprintf(INFO, "    --normalize[=yes(*)/no]              Normalize html, script, and text files. Use normalize=no for yara compatibility\n");
    mprintf(INFO, "    --scan-pe[=yes(*)/no]                Scan PE files\n");
    mprintf(INFO, "    --scan-elf[=yes(*)/no]               Scan ELF files\n");
    mprintf(INFO, "    --scan-ole2[=yes(*)/no]              Scan OLE2 containers\n");
    mprintf(INFO, "    --scan-pdf[=yes(*)/no]               Scan PDF files\n");
    mprintf(INFO, "    --scan-swf[=yes(*)/no]               Scan SWF files\n");
    mprintf(INFO, "    --scan-html[=yes(*)/no]              Scan HTML files\n");
    mprintf(INFO, "    --scan-xmldocs[=yes(*)/no]           Scan xml-based document files\n");
    mprintf(INFO, "    --scan-hwp3[=yes(*)/no]              Scan HWP3 files\n");
    mprintf(INFO, "    --scan-archive[=yes(*)/no]           Scan archive files (supported by libclamav)\n");
    mprintf(INFO, "    --alert-broken[=yes/no(*)]           Alert on broken executable files (PE & ELF)\n");
    mprintf(INFO, "    --alert-broken-media[=yes/no(*)]     Alert on broken graphics files (JPEG, TIFF, PNG, GIF)\n");
    mprintf(INFO, "    --alert-encrypted[=yes/no(*)]        Alert on encrypted archives and documents\n");
    mprintf(INFO, "    --alert-encrypted-archive[=yes/no(*)] Alert on encrypted archives\n");
    mprintf(INFO, "    --alert-encrypted-doc[=yes/no(*)]    Alert on encrypted documents\n");
    mprintf(INFO, "    --alert-macros[=yes/no(*)]           Alert on OLE2 files containing VBA macros\n");
    mprintf(INFO, "    --alert-exceeds-max[=yes/no(*)]      Alert on files that exceed max file size, max scan size, or max recursion limit\n");
    mprintf(INFO, "    --alert-phishing-ssl[=yes/no(*)]     Alert on emails containing SSL mismatches in URLs\n");
    mprintf(INFO, "    --alert-phishing-cloak[=yes/no(*)]   Alert on emails containing cloaked URLs\n");
    mprintf(INFO, "    --alert-partition-intersection[=yes/no(*)] Alert on raw DMG image files containing partition intersections\n");
    mprintf(INFO, "    --nocerts                            Disable authenticode certificate chain verification in PE files\n");
    mprintf(INFO, "    --dumpcerts                          Dump authenticode certificate chain in PE files\n");
    mprintf(INFO, "\n");
    mprintf(INFO, "    --max-scantime=#n                    Scan time longer than this will be skipped and assumed clean (milliseconds)\n");
    mprintf(INFO, "    --max-filesize=#n                    Files larger than this will be skipped and assumed clean\n");
    mprintf(INFO, "    --max-scansize=#n                    The maximum amount of data to scan for each container file (**)\n");
    mprintf(INFO, "    --max-files=#n                       The maximum number of files to scan for each container file (**)\n");
    mprintf(INFO, "    --max-recursion=#n                   Maximum archive recursion level for container file (**)\n");
    mprintf(INFO, "    --max-dir-recursion=#n               Maximum directory recursion level\n");
    mprintf(INFO, "    --max-embeddedpe=#n                  Maximum size file to check for embedded PE\n");
    mprintf(INFO, "    --max-htmlnormalize=#n               Maximum size of HTML file to normalize\n");
    mprintf(INFO, "    --max-htmlnotags=#n                  Maximum size of normalized HTML file to scan\n");
    mprintf(INFO, "    --max-scriptnormalize=#n             Maximum size of script file to normalize\n");
    mprintf(INFO, "    --max-ziptypercg=#n                  Maximum size zip to type reanalyze\n");
    mprintf(INFO, "    --max-partitions=#n                  Maximum number of partitions in disk image to be scanned\n");
    mprintf(INFO, "    --max-iconspe=#n                     Maximum number of icons in PE file to be scanned\n");
    mprintf(INFO, "    --max-rechwp3=#n                     Maximum recursive calls to HWP3 parsing function\n");
#if HAVE_PCRE
    mprintf(INFO, "    --pcre-match-limit=#n                Maximum calls to the PCRE match function.\n");
    mprintf(INFO, "    --pcre-recmatch-limit=#n             Maximum recursive calls to the PCRE match function.\n");
    mprintf(INFO, "    --pcre-max-filesize=#n               Maximum size file to perform PCRE subsig matching.\n");
#endif /* HAVE_PCRE */
    mprintf(INFO, "    --disable-cache                      Disable caching and cache checks for hash sums of scanned files.\n");
    mprintf(INFO, "\n");
    mprintf(INFO, "Pass in - as the filename for stdin.\n");
    mprintf(INFO, "\n");
    mprintf(INFO, "(*) Default scan settings\n");
    mprintf(INFO, "(**) Certain files (e.g. documents, archives, etc.) may in turn contain other\n");
    mprintf(INFO, "   files inside. The above options ensure safe processing of this kind of data.\n\n");
}

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

static void loggBytes(uint64_t bytes)
{
    if (bytes >= (1024 * 1024 * 1024)) {
        logg(LOGG_INFO, "%.02f GiB", bytes / (double)(1024 * 1024 * 1024));
    } else if (bytes >= (1024 * 1024)) {
        logg(LOGG_INFO, "%.02f MiB", bytes / (double)(1024 * 1024));
    } else if (bytes >= 1024) {
        logg(LOGG_INFO, "%.02f KiB", bytes / (double)(1024));
    } else {
        logg(LOGG_INFO, "%" PRIu64 " B", bytes);
    }
}

int main(int argc, char **argv)
{
    int ds, dms, ret;
    struct timeval t1, t2;
    time_t date_start, date_end;

    char buffer[26];
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#else /* !_WIN32 */
    sigset_t sigset;
#endif
    struct optstruct *opts;
    const struct optstruct *opt;

    if (check_flevel())
        exit(2);

#if !defined(_WIN32)
    if (!setlocale(LC_CTYPE, "")) {
        mprintf(LOGG_WARNING, "Failed to set locale\n");
    }
#if !defined(C_BEOS)
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGXFSZ);
    sigprocmask(SIG_SETMASK, &sigset, NULL);
#endif /* !C_BEOS */
#endif /* !_WIN32 */

    cl_initialize_crypto();

    if ((opts = optparse(NULL, argc, argv, 1, OPT_CLAMSCAN, 0, NULL)) == NULL) {
        mprintf(LOGG_ERROR, "Can't parse command line options\n");
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
        if (logg(LOGG_INFO_NF, "\n-------------------------------------------------------------------------------\n\n")) {
            mprintf(LOGG_ERROR, "Problem with internal logger.\n");
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
        logg(LOGG_INFO, "\n----------- SCAN SUMMARY -----------\n");
        logg(LOGG_INFO, "Known viruses: %u\n", info.sigs);
        logg(LOGG_INFO, "Engine version: %s\n", get_version());
        logg(LOGG_INFO, "Scanned directories: %u\n", info.dirs);
        logg(LOGG_INFO, "Scanned files: %u\n", info.files);
        logg(LOGG_INFO, "Infected files: %u\n", info.ifiles);
        if (info.errors)
            logg(LOGG_INFO, "Total errors: %u\n", info.errors);
        if (notremoved) {
            logg(LOGG_INFO, "Not removed: %u\n", notremoved);
        }
        if (notmoved) {
            logg(LOGG_INFO, "Not %s: %u\n", optget(opts, "copy")->enabled ? "moved" : "copied", notmoved);
        }

        logg(LOGG_INFO, "Data scanned: ");
        loggBytes(info.bytes_scanned);
        logg(LOGG_INFO, "\n");

        logg(LOGG_INFO, "Data read: ");
        loggBytes(info.bytes_read);
        logg(LOGG_INFO, " (ratio %.2f:1)\n", info.bytes_read ? (double)info.bytes_scanned / (double)info.bytes_read : 0);

        logg(LOGG_INFO, "Time: %u.%3.3u sec (%u m %u s)\n", ds, dms / 1000, ds / 60, ds % 60);

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

    optfree(opts);

    return ret;
}

void help(void)
{
    mprintf_stdout = 1;

    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "                       Clam AntiVirus: Scanner %s\n", get_version());
    mprintf(LOGG_INFO, "           By The ClamAV Team: https://www.clamav.net/about.html#credits\n");
    mprintf(LOGG_INFO, "           (C) 2025 Cisco Systems, Inc.\n");
    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "    clamscan [options] [file/directory/-]\n");
    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "    --help                -h             Show this help.\n");
    mprintf(LOGG_INFO, "    --version             -V             Print version number.\n");
    mprintf(LOGG_INFO, "    --verbose             -v             Be verbose.\n");
    mprintf(LOGG_INFO, "    --archive-verbose     -a             Show filenames inside scanned archives.\n");
    mprintf(LOGG_INFO, "    --debug                              Enable libclamav's debug messages.\n");
    mprintf(LOGG_INFO, "    --quiet                              Only output error messages.\n");
    mprintf(LOGG_INFO, "    --stdout                             Write to stdout instead of stderr. Does not affect 'debug' messages.\n");
    mprintf(LOGG_INFO, "    --no-summary                         Disable summary at end of scanning.\n");
    mprintf(LOGG_INFO, "    --infected            -i             Only print infected files.\n");
    mprintf(LOGG_INFO, "    --suppress-ok-results -o             Skip printing OK files.\n");
    mprintf(LOGG_INFO, "    --bell                               Sound bell on virus detection.\n");
    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "    --tempdir=DIRECTORY                  Create temporary files in DIRECTORY.\n");
    mprintf(LOGG_INFO, "    --leave-temps[=yes/no(*)]            Do not remove temporary files.\n");
    mprintf(LOGG_INFO, "    --force-to-disk[=yes/no(*)]          Create temporary files for nested file scans that would otherwise be in-memory only.\n");
    mprintf(LOGG_INFO, "    --gen-json[=yes/no(*)]               Generate JSON metadata for the scanned file(s). For testing & development use ONLY.\n");
    mprintf(LOGG_INFO, "                                         JSON will be printed if --debug is enabled.\n");
    mprintf(LOGG_INFO, "                                         A JSON file will dropped to the temp directory if --leave-temps is enabled.\n");
    mprintf(LOGG_INFO, "    --json-store-html-uris[=yes(*)/no]   Store html URIs in metadata.\n");
    mprintf(LOGG_INFO, "                                         URIs will be written to the metadata.json file in an array called 'URIs'.\n");
    mprintf(LOGG_INFO, "    --json-store-pdf-uris[=yes(*)/no]    Store pdf URIs in metadata.\n");
    mprintf(LOGG_INFO, "                                         URIs will be written to the metadata.json file in an array called 'URIs'.\n");
    mprintf(LOGG_INFO, "    --json-store-extra-hashes[=yes(*)/no] Store md5 and sha1 in addition to sha2-256 in metadata.\n");
    mprintf(LOGG_INFO, "    --database=FILE/DIR   -d FILE/DIR    Load virus database from FILE or load all supported db files from DIR.\n");
    mprintf(LOGG_INFO, "    --official-db-only[=yes/no(*)]       Only load official signatures.\n");
    mprintf(LOGG_INFO, "    --fail-if-cvd-older-than=days        Return with a nonzero error code if virus database outdated.\n");
    mprintf(LOGG_INFO, "    --log=FILE            -l FILE        Save scan report to FILE.\n");
    mprintf(LOGG_INFO, "    --recursive[=yes/no(*)]  -r          Scan subdirectories recursively.\n");
    mprintf(LOGG_INFO, "    --allmatch[=yes/no(*)]   -z          Continue scanning within file after finding a match.\n");
    mprintf(LOGG_INFO, "    --cross-fs[=yes(*)/no]               Scan files and directories on other filesystems.\n");
    mprintf(LOGG_INFO, "    --follow-dir-symlinks[=0/1(*)/2]     Follow directory symlinks (0 = never, 1 = direct, 2 = always).\n");
    mprintf(LOGG_INFO, "    --follow-file-symlinks[=0/1(*)/2]    Follow file symlinks (0 = never, 1 = direct, 2 = always).\n");
    mprintf(LOGG_INFO, "    --file-list=FILE      -f FILE        Scan files from FILE.\n");
    mprintf(LOGG_INFO, "    --remove[=yes/no(*)]                 Remove infected files. Be careful!\n");
    mprintf(LOGG_INFO, "    --move=DIRECTORY                     Move infected files into DIRECTORY.\n");
    mprintf(LOGG_INFO, "    --copy=DIRECTORY                     Copy infected files into DIRECTORY.\n");
    mprintf(LOGG_INFO, "    --exclude=REGEX                      Don't scan file names matching REGEX.\n");
    mprintf(LOGG_INFO, "    --exclude-dir=REGEX                  Don't scan directories matching REGEX.\n");
    mprintf(LOGG_INFO, "    --include=REGEX                      Only scan file names matching REGEX.\n");
    mprintf(LOGG_INFO, "    --include-dir=REGEX                  Only scan directories matching REGEX.\n");
#ifdef _WIN32
    mprintf(LOGG_INFO, "    --memory                             Scan loaded executable modules.\n");
    mprintf(LOGG_INFO, "    --kill                               Kill/Unload infected loaded modules.\n");
    mprintf(LOGG_INFO, "    --unload                             Unload infected modules from processes.\n");
#endif
    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "    --bytecode[=yes(*)/no]               Load bytecode from the database.\n");
    mprintf(LOGG_INFO, "    --bytecode-unsigned[=yes/no(*)]      Load unsigned bytecode.\n");
    mprintf(LOGG_INFO, "                                         **Caution**: You should NEVER run bytecode signatures from untrusted sources.\n");
    mprintf(LOGG_INFO, "                                         Doing so may result in arbitrary code execution.\n");
    mprintf(LOGG_INFO, "    --bytecode-timeout=N                 Set bytecode timeout (in milliseconds).\n");
    mprintf(LOGG_INFO, "    --statistics[=none(*)/bytecode/pcre] Collect and print execution statistics.\n");
    mprintf(LOGG_INFO, "    --detect-pua[=yes/no(*)]             Detect Possibly Unwanted Applications.\n");
    mprintf(LOGG_INFO, "    --exclude-pua=CAT                    Skip PUA sigs of category CAT.\n");
    mprintf(LOGG_INFO, "    --include-pua=CAT                    Load PUA sigs of category CAT.\n");
    mprintf(LOGG_INFO, "    --detect-structured[=yes/no(*)]      Detect structured data (SSN, Credit Card).\n");
    mprintf(LOGG_INFO, "    --structured-ssn-format=X            SSN format (0=normal,1=stripped,2=both).\n");
    mprintf(LOGG_INFO, "    --structured-ssn-count=N             Min SSN count to generate a detect.\n");
    mprintf(LOGG_INFO, "    --structured-cc-count=N              Min CC count to generate a detect.\n");
    mprintf(LOGG_INFO, "    --structured-cc-mode=X               CC mode (0=credit debit and private label, 1=credit cards only.\n");
    mprintf(LOGG_INFO, "    --scan-mail[=yes(*)/no]              Scan mail files.\n");
    mprintf(LOGG_INFO, "    --phishing-sigs[=yes(*)/no]          Enable email signature-based phishing detection.\n");
    mprintf(LOGG_INFO, "    --phishing-scan-urls[=yes(*)/no]     Enable URL signature-based phishing detection.\n");
    mprintf(LOGG_INFO, "    --heuristic-alerts[=yes(*)/no]       Heuristic alerts.\n");
    mprintf(LOGG_INFO, "    --heuristic-scan-precedence[=yes/no(*)] Stop scanning as soon as a heuristic match is found.\n");
    mprintf(LOGG_INFO, "    --normalize[=yes(*)/no]              Normalize html, script, and text files. Use normalize=no for yara compatibility.\n");
    mprintf(LOGG_INFO, "    --scan-pe[=yes(*)/no]                Scan PE files.\n");
    mprintf(LOGG_INFO, "    --scan-elf[=yes(*)/no]               Scan ELF files.\n");
    mprintf(LOGG_INFO, "    --scan-ole2[=yes(*)/no]              Scan OLE2 containers.\n");
    mprintf(LOGG_INFO, "    --scan-pdf[=yes(*)/no]               Scan PDF files.\n");
    mprintf(LOGG_INFO, "    --scan-swf[=yes(*)/no]               Scan SWF files.\n");
    mprintf(LOGG_INFO, "    --scan-html[=yes(*)/no]              Scan HTML files.\n");
    mprintf(LOGG_INFO, "    --scan-xmldocs[=yes(*)/no]           Scan xml-based document files.\n");
    mprintf(LOGG_INFO, "    --scan-hwp3[=yes(*)/no]              Scan HWP3 files.\n");
    mprintf(LOGG_INFO, "    --scan-onenote[=yes(*)/no]           Scan OneNote files.\n");
    mprintf(LOGG_INFO, "    --scan-archive[=yes(*)/no]           Scan archive files (supported by libclamav).\n");
    mprintf(LOGG_INFO, "    --scan-image[=yes(*)/no]             Scan image (graphics) files.\n");
    mprintf(LOGG_INFO, "    --scan-image-fuzzy-hash[=yes(*)/no]  Detect files by calculating image (graphics) fuzzy hashes.\n");
    mprintf(LOGG_INFO, "    --alert-broken[=yes/no(*)]           Alert on broken executable files (PE & ELF).\n");
    mprintf(LOGG_INFO, "    --alert-broken-media[=yes/no(*)]     Alert on broken graphics files (JPEG, TIFF, PNG, GIF).\n");
    mprintf(LOGG_INFO, "    --alert-encrypted[=yes/no(*)]        Alert on encrypted archives and documents.\n");
    mprintf(LOGG_INFO, "    --alert-encrypted-archive[=yes/no(*)] Alert on encrypted archives.\n");
    mprintf(LOGG_INFO, "    --alert-encrypted-doc[=yes/no(*)]    Alert on encrypted documents.\n");
    mprintf(LOGG_INFO, "    --alert-macros[=yes/no(*)]           Alert on OLE2 files containing VBA macros.\n");
    mprintf(LOGG_INFO, "    --alert-exceeds-max[=yes/no(*)]      Alert on files that exceed max file size, max scan size, or max recursion limit.\n");
    mprintf(LOGG_INFO, "    --alert-phishing-ssl[=yes/no(*)]     Alert on emails containing SSL mismatches in URLs.\n");
    mprintf(LOGG_INFO, "    --alert-phishing-cloak[=yes/no(*)]   Alert on emails containing cloaked URLs.\n");
    mprintf(LOGG_INFO, "    --alert-partition-intersection[=yes/no(*)] Alert on raw DMG image files containing partition intersections.\n");
    mprintf(LOGG_INFO, "    --nocerts                            Disable authenticode certificate chain verification in PE files.\n");
    mprintf(LOGG_INFO, "    --dumpcerts                          Dump authenticode certificate chain in PE files.\n");
    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "    --max-scantime=#n                    Scan time longer than this will be skipped and assumed clean (milliseconds).\n");
    mprintf(LOGG_INFO, "    --max-filesize=#n                    Files larger than this will be skipped and assumed clean.\n");
    mprintf(LOGG_INFO, "    --max-scansize=#n                    The maximum amount of data to scan for each container file (**).\n");
    mprintf(LOGG_INFO, "    --max-files=#n                       The maximum number of files to scan for each container file (**).\n");
    mprintf(LOGG_INFO, "    --max-recursion=#n                   Maximum archive recursion level for container file (**).\n");
    mprintf(LOGG_INFO, "    --max-dir-recursion=#n               Maximum directory recursion level.\n");
    mprintf(LOGG_INFO, "    --max-embeddedpe=#n                  Maximum size file to check for embedded PE.\n");
    mprintf(LOGG_INFO, "    --max-htmlnormalize=#n               Maximum size of HTML file to normalize.\n");
    mprintf(LOGG_INFO, "    --max-htmlnotags=#n                  Maximum size of normalized HTML file to scan.\n");
    mprintf(LOGG_INFO, "    --max-scriptnormalize=#n             Maximum size of script file to normalize.\n");
    mprintf(LOGG_INFO, "    --max-ziptypercg=#n                  Maximum size zip to type reanalyze.\n");
    mprintf(LOGG_INFO, "    --max-partitions=#n                  Maximum number of partitions in disk image to be scanned.\n");
    mprintf(LOGG_INFO, "    --max-iconspe=#n                     Maximum number of icons in PE file to be scanned.\n");
    mprintf(LOGG_INFO, "    --max-rechwp3=#n                     Maximum recursive calls to HWP3 parsing function.\n");
    mprintf(LOGG_INFO, "    --pcre-match-limit=#n                Maximum calls to the PCRE match function.\n");
    mprintf(LOGG_INFO, "    --pcre-recmatch-limit=#n             Maximum recursive calls to the PCRE match function.\n");
    mprintf(LOGG_INFO, "    --pcre-max-filesize=#n               Maximum size file to perform PCRE subsig matching.\n");
    mprintf(LOGG_INFO, "    --disable-cache                      Disable caching and cache checks for hash sums of scanned files.\n");
    mprintf(LOGG_INFO, "    --hash-hint                          The file hash so that libclamav does not need to calculate it.\n");
    mprintf(LOGG_INFO, "                                         The type of hash must match the '--hash-alg'.\n");
    mprintf(LOGG_INFO, "    --log-hash                           Print the file hash after each file scanned.\n");
    mprintf(LOGG_INFO, "                                         The type of hash printed will match the '--hash-alg'.\n");
    mprintf(LOGG_INFO, "    --hash-alg                           The hashing algorithm used for either '--hash-hint' or '--log-hash'.\n");
    mprintf(LOGG_INFO, "                                         Supported algorithms are 'md5', 'sha1', 'sha2-256'.\n");
    mprintf(LOGG_INFO, "                                         If not specified, the default is 'sha2-256'.\n");
    mprintf(LOGG_INFO, "    --file-type-hint                     The file type hint so that libclamav can optimize scanning.\n");
    mprintf(LOGG_INFO, "                                         E.g. 'pe', 'elf', 'zip', etc.\n");
    mprintf(LOGG_INFO, "                                         You may also use ClamAV type names such as 'CL_TYPE_PE'.\n");
    mprintf(LOGG_INFO, "                                         ClamAV will ignore the hint if it is not familiar with the specified type.\n");
    mprintf(LOGG_INFO, "                                         See also: https://docs.clamav.net/appendix/FileTypes.html#file-types\n");
    mprintf(LOGG_INFO, "    --log-file-type                      Print the file type after each file scanned.\n");
    mprintf(LOGG_INFO, "    --cvdcertsdir=DIRECTORY              Specify a directory containing the root\n");
    mprintf(LOGG_INFO, "                                         CA cert needed to verify detached CVD digital signatures.\n");
    mprintf(LOGG_INFO, "                                         If not provided, then clamscan will look in the default directory.\n");
    mprintf(LOGG_INFO, "    --fips-limits                        Enforce FIPS-like limits on using hash algorithms for\n");
    mprintf(LOGG_INFO, "                                         cryptographic purposes. Will disable MD5 & SHA1.\n");
    mprintf(LOGG_INFO, "                                         FP sigs and will require '.sign' files to verify CVD\n");
    mprintf(LOGG_INFO, "                                         authenticity.\n");
    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "Environment Variables:\n");
    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "    LD_LIBRARY_PATH                      May be used on startup to find the libclamunrar_iface\n");
    mprintf(LOGG_INFO, "                                         shared library module to enable RAR archive support.\n");
    mprintf(LOGG_INFO, "    CVD_CERTS_DIR                        Specify a directory containing the root CA cert needed\n");
    mprintf(LOGG_INFO, "                                         to verify detached CVD digital signatures.\n");
    mprintf(LOGG_INFO, "                                         If not provided, then clamscan will look in the default directory.\n");
    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "Pass in - as the filename for stdin.\n");
    mprintf(LOGG_INFO, "\n");
    mprintf(LOGG_INFO, "(*) Default scan settings\n");
    mprintf(LOGG_INFO, "(**) Certain files (e.g. documents, archives, etc.) may in turn contain other\n");
    mprintf(LOGG_INFO, "   files inside. The above options ensure safe processing of this kind of data.\n\n");
}

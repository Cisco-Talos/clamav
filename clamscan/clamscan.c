/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
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

#ifdef	HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifndef _WIN32
#include <sys/time.h>
#endif
#include <time.h>
#ifdef C_LINUX
#include <sys/resource.h>
#endif

#include "others.h"
#include "global.h"
#include "manager.h"

#include "shared/misc.h"
#include "shared/output.h"
#include "shared/actions.h"
#include "shared/optparser.h"

#include "libclamav/str.h"
#include "libclamav/clamav.h"

void help(void);

struct s_info info;
short recursion = 0, bell = 0;
short printinfected = 0, printclean = 1;

int main(int argc, char **argv)
{
	int ds, dms, ret;
	double mb, rmb;
	struct timeval t1, t2;
#ifndef _WIN32
	sigset_t sigset;
#endif
	struct optstruct *opts;
	const struct optstruct *opt;

    if (check_flevel())
	    exit(2);

#if !defined(_WIN32) && !defined(C_BEOS)
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGXFSZ);
    sigprocmask(SIG_SETMASK, &sigset, NULL);
#endif

    cl_initialize_crypto();


    if((opts = optparse(NULL, argc, argv, 1, OPT_CLAMSCAN, 0, NULL)) == NULL) {
	mprintf("!Can't parse command line options\n");
	return 2;
    }

    if(optget(opts, "verbose")->enabled) {
	mprintf_verbose = 1;
	logg_verbose = 1;
    }

    if(optget(opts, "quiet")->enabled)
	mprintf_quiet = 1;

    if(optget(opts, "stdout")->enabled)
	mprintf_stdout = 1;


    if(optget(opts, "debug")->enabled) {
#if defined(C_LINUX)
	    /* njh@bandsman.co.uk: create a dump if needed */
	    struct rlimit rlim;

	rlim.rlim_cur = rlim.rlim_max = RLIM_INFINITY;
	if(setrlimit(RLIMIT_CORE, &rlim) < 0)
	    perror("setrlimit");
#endif
	cl_debug(); /* enable debug messages */
    }

    if (optget(opts, "gen-mdb")->enabled) {
        cl_always_gen_section_hash();
    }

    if(optget(opts, "version")->enabled) {
	print_version(optget(opts, "database")->strarg);
	optfree(opts);
	return 0;
    }

    if(optget(opts, "help")->enabled) {
	optfree(opts);
    	help();
	return 0;
    }

    if(optget(opts, "recursive")->enabled)
	recursion = 1;

    if(optget(opts, "infected")->enabled)
	printinfected = 1;

    if(optget(opts, "suppress-ok-results")->enabled)
	printclean = 0;

    if(optget(opts, "bell")->enabled)
	bell = 1;

    /* initialize logger */
    if((opt = optget(opts, "log"))->enabled) {
	logg_file = opt->strarg;
	if(logg("#\n-------------------------------------------------------------------------------\n\n")) {
	    mprintf("!Problem with internal logger.\n");
	    optfree(opts);
	    return 2;
	}
    } else
	logg_file = NULL;

    if(actsetup(opts)) {
	optfree(opts);
	logg_close();
	exit(2);
    }

    memset(&info, 0, sizeof(struct s_info));

    gettimeofday(&t1, NULL);

    ret = scanmanager(opts);

    if(!optget(opts, "no-summary")->enabled) {
	gettimeofday(&t2, NULL);

    ds = t2.tv_sec - t1.tv_sec;
	dms = t2.tv_usec - t1.tv_usec;
	ds -= (dms < 0) ? (1):(0);
	dms += (dms < 0) ? (1000000):(0);
	logg("\n----------- SCAN SUMMARY -----------\n");
	logg("Known viruses: %u\n", info.sigs);
	logg("Engine version: %s\n", get_version());
	logg("Scanned directories: %u\n", info.dirs);
	logg("Scanned files: %u\n", info.files);
	logg("Infected files: %u\n", info.ifiles);
	if(info.errors)
	    logg("Total errors: %u\n", info.errors);
	if(notremoved) {
	    logg("Not removed: %u\n", notremoved);
	}
	if(notmoved) {
	    logg("Not %s: %u\n", optget(opts, "copy")->enabled ? "moved" : "copied", notmoved);
	}
	mb = info.blocks * (CL_COUNT_PRECISION / 1024) / 1024.0;
	logg("Data scanned: %2.2lf MB\n", mb);
	rmb = info.rblocks * (CL_COUNT_PRECISION / 1024) / 1024.0;
	logg("Data read: %2.2lf MB (ratio %.2f:1)\n", rmb, info.rblocks ? (double)info.blocks/(double)info.rblocks : 0);
	logg("Time: %u.%3.3u sec (%u m %u s)\n", ds, dms/1000, ds/60, ds%60);
    }

    optfree(opts);

    cl_cleanup_crypto();

    return ret;
}

void help(void)
{
    mprintf_stdout = 1;

    mprintf("\n");
    mprintf("                       Clam AntiVirus: Scanner %s\n", get_version());
    printf("           By The ClamAV Team: https://www.clamav.net/about.html#credits\n");
    printf("           (C) 2019 Cisco Systems, Inc.\n");
    mprintf("\n");
    mprintf("    clamscan [options] [file/directory/-]\n");
    mprintf("\n");
    mprintf("    --help                -h             Show this help\n");
    mprintf("    --version             -V             Print version number\n");
    mprintf("    --verbose             -v             Be verbose\n");
    mprintf("    --archive-verbose     -a             Show filenames inside scanned archives\n");
    mprintf("    --debug                              Enable libclamav's debug messages\n");
    mprintf("    --quiet                              Only output error messages\n");
    mprintf("    --stdout                             Write to stdout instead of stderr\n");
    mprintf("    --no-summary                         Disable summary at end of scanning\n");
    mprintf("    --infected            -i             Only print infected files\n");
    mprintf("    --suppress-ok-results -o             Skip printing OK files\n");
    mprintf("    --bell                               Sound bell on virus detection\n");
    mprintf("\n");
    mprintf("    --tempdir=DIRECTORY                  Create temporary files in DIRECTORY\n");
    mprintf("    --leave-temps[=yes/no(*)]            Do not remove temporary files\n");
    mprintf("    --gen-json[=yes/no(*)]               Generate JSON description of scanned file(s). JSON will be printed and also-\n");
    mprintf("                                         dropped to the temp directory if --leave-temps is enabled.\n");
    mprintf("    --database=FILE/DIR   -d FILE/DIR    Load virus database from FILE or load all supported db files from DIR\n");
    mprintf("    --official-db-only[=yes/no(*)]       Only load official signatures\n");
    mprintf("    --log=FILE            -l FILE        Save scan report to FILE\n");
    mprintf("    --recursive[=yes/no(*)]  -r          Scan subdirectories recursively\n");
    mprintf("    --allmatch[=yes/no(*)]   -z          Continue scanning within file after finding a match\n");
    mprintf("    --cross-fs[=yes(*)/no]               Scan files and directories on other filesystems\n");
    mprintf("    --follow-dir-symlinks[=0/1(*)/2]     Follow directory symlinks (0 = never, 1 = direct, 2 = always)\n");
    mprintf("    --follow-file-symlinks[=0/1(*)/2]    Follow file symlinks (0 = never, 1 = direct, 2 = always)\n");
    mprintf("    --file-list=FILE      -f FILE        Scan files from FILE\n");
    mprintf("    --remove[=yes/no(*)]                 Remove infected files. Be careful!\n");
    mprintf("    --move=DIRECTORY                     Move infected files into DIRECTORY\n");
    mprintf("    --copy=DIRECTORY                     Copy infected files into DIRECTORY\n");
    mprintf("    --exclude=REGEX                      Don't scan file names matching REGEX\n");
    mprintf("    --exclude-dir=REGEX                  Don't scan directories matching REGEX\n");
    mprintf("    --include=REGEX                      Only scan file names matching REGEX\n");
    mprintf("    --include-dir=REGEX                  Only scan directories matching REGEX\n");
    mprintf("\n");
    mprintf("    --bytecode[=yes(*)/no]               Load bytecode from the database\n");
    mprintf("    --bytecode-unsigned[=yes/no(*)]      Load unsigned bytecode\n");
    mprintf("    --bytecode-timeout=N                 Set bytecode timeout (in milliseconds)\n");
    mprintf("    --statistics[=none(*)/bytecode/pcre] Collect and print execution statistics\n");
    mprintf("    --detect-pua[=yes/no(*)]             Detect Possibly Unwanted Applications\n");
    mprintf("    --exclude-pua=CAT                    Skip PUA sigs of category CAT\n");
    mprintf("    --include-pua=CAT                    Load PUA sigs of category CAT\n");
    mprintf("    --detect-structured[=yes/no(*)]      Detect structured data (SSN, Credit Card)\n");
    mprintf("    --structured-ssn-format=X            SSN format (0=normal,1=stripped,2=both)\n");
    mprintf("    --structured-ssn-count=N             Min SSN count to generate a detect\n");
    mprintf("    --structured-cc-count=N              Min CC count to generate a detect\n");
    mprintf("    --scan-mail[=yes(*)/no]              Scan mail files\n");
    mprintf("    --phishing-sigs[=yes(*)/no]          Enable email signature-based phishing detection\n");
    mprintf("    --phishing-scan-urls[=yes(*)/no]     Enable URL signature-based phishing detection\n");
    mprintf("    --heuristic-alerts[=yes(*)/no]       Heuristic alerts\n");
    mprintf("    --heuristic-scan-precedence[=yes/no(*)] Stop scanning as soon as a heuristic match is found\n");
    mprintf("    --normalize[=yes(*)/no]              Normalize html, script, and text files. Use normalize=no for yara compatibility\n");
    mprintf("    --scan-pe[=yes(*)/no]                Scan PE files\n");
    mprintf("    --scan-elf[=yes(*)/no]               Scan ELF files\n");
    mprintf("    --scan-ole2[=yes(*)/no]              Scan OLE2 containers\n");
    mprintf("    --scan-pdf[=yes(*)/no]               Scan PDF files\n");
    mprintf("    --scan-swf[=yes(*)/no]               Scan SWF files\n");
    mprintf("    --scan-html[=yes(*)/no]              Scan HTML files\n");
    mprintf("    --scan-xmldocs[=yes(*)/no]           Scan xml-based document files\n");
    mprintf("    --scan-hwp3[=yes(*)/no]              Scan HWP3 files\n");
    mprintf("    --scan-archive[=yes(*)/no]           Scan archive files (supported by libclamav)\n");
    mprintf("    --alert-broken[=yes/no(*)]           Alert on broken executable files (PE & ELF)\n");
    mprintf("    --alert-encrypted[=yes/no(*)]        Alert on encrypted archives and documents\n");
    mprintf("    --alert-encrypted-archive[=yes/no(*)] Alert on encrypted archives\n");
    mprintf("    --alert-encrypted-doc[=yes/no(*)]    Alert on encrypted documents\n");
    mprintf("    --alert-macros[=yes/no(*)]           Alert on OLE2 files containing VBA macros\n");
    mprintf("    --alert-exceeds-max[=yes/no(*)]      Alert on files that exceed max file size, max scan size, or max recursion limit\n");
    mprintf("    --alert-phishing-ssl[=yes/no(*)]     Alert on emails containing SSL mismatches in URLs\n");
    mprintf("    --alert-phishing-cloak[=yes/no(*)]   Alert on emails containing cloaked URLs\n");
    mprintf("    --alert-partition-intersection[=yes/no(*)] Alert on raw DMG image files containing partition intersections\n");
    mprintf("    --nocerts                            Disable authenticode certificate chain verification in PE files\n");
    mprintf("    --dumpcerts                          Dump authenticode certificate chain in PE files\n");
    mprintf("\n");
    mprintf("    --max-scantime=#n                    Scan time longer than this will be skipped and assumed clean\n");
    mprintf("    --max-filesize=#n                    Files larger than this will be skipped and assumed clean\n");
    mprintf("    --max-scansize=#n                    The maximum amount of data to scan for each container file (**)\n");
    mprintf("    --max-files=#n                       The maximum number of files to scan for each container file (**)\n");
    mprintf("    --max-recursion=#n                   Maximum archive recursion level for container file (**)\n");
    mprintf("    --max-dir-recursion=#n               Maximum directory recursion level\n");
    mprintf("    --max-embeddedpe=#n                  Maximum size file to check for embedded PE\n");
    mprintf("    --max-htmlnormalize=#n               Maximum size of HTML file to normalize\n");
    mprintf("    --max-htmlnotags=#n                  Maximum size of normalized HTML file to scan\n");
    mprintf("    --max-scriptnormalize=#n             Maximum size of script file to normalize\n");
    mprintf("    --max-ziptypercg=#n                  Maximum size zip to type reanalyze\n");
    mprintf("    --max-partitions=#n                  Maximum number of partitions in disk image to be scanned\n");
    mprintf("    --max-iconspe=#n                     Maximum number of icons in PE file to be scanned\n");
    mprintf("    --max-rechwp3=#n                     Maximum recursive calls to HWP3 parsing function\n");
#if HAVE_PCRE
    mprintf("    --pcre-match-limit=#n                Maximum calls to the PCRE match function.\n");
    mprintf("    --pcre-recmatch-limit=#n             Maximum recursive calls to the PCRE match function.\n");
    mprintf("    --pcre-max-filesize=#n               Maximum size file to perform PCRE subsig matching.\n");
#endif /* HAVE_PCRE */
    mprintf("    --disable-cache                      Disable caching and cache checks for hash sums of scanned files.\n");
    mprintf("\n");
    mprintf("Pass in - as the filename for stdin.\n");
    mprintf("\n");
    mprintf("(*) Default scan settings\n");
    mprintf("(**) Certain files (e.g. documents, archives, etc.) may in turn contain other\n");
    mprintf("   files inside. The above options ensure safe processing of this kind of data.\n\n");
}

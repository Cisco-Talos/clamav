/*
 *  Copyright (C) 2002 - 2006 Tomasz Kojm <tkojm@clamav.net>
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

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>

#include "clamscan_opt.h"
#include "others.h"
#include "shared.h"
#include "manager.h"
#include "defaults.h"
#include "treewalk.h"
#include "misc.h"

#include "output.h"
#include "options.h"

#ifdef C_LINUX
#include <sys/resource.h>
#endif

void help(void);

struct s_info claminfo;
short recursion = 0, printinfected = 0, bell = 0;

int main(int argc, char **argv)
{
	int ds, dms, ret;
	double mb;
	struct timeval t1, t2;
	struct timezone tz;
	struct optstruct *opt;
	const char *pt;


    opt = opt_parse(argc, argv, clamscan_shortopt, clamscan_longopt, NULL);
    if(!opt) {
	mprintf("!Can't parse the command line\n");
	return 40;
    }

    if(opt_check(opt, "verbose")) {
	mprintf_verbose = 1;
	logg_verbose = 1;
    }

    if(opt_check(opt, "quiet"))
	mprintf_quiet = 1;

    if(opt_check(opt, "stdout"))
	mprintf_stdout = 1;


    if(opt_check(opt, "debug")) {
#if defined(C_LINUX)
	    /* njh@bandsman.co.uk: create a dump if needed */
	    struct rlimit rlim;

	rlim.rlim_cur = rlim.rlim_max = RLIM_INFINITY;
	if(setrlimit(RLIMIT_CORE, &rlim) < 0)
	    perror("setrlimit");
#endif
	cl_debug(); /* enable debug messages */
    }

    if(opt_check(opt, "version")) {
	opt_free(opt);
	print_version();
	return 0;
    }

    if(opt_check(opt, "help")) {
	opt_free(opt);
    	help();
	return 0;
    }

    if(opt_check(opt, "recursive"))
	recursion = 1;

    if(opt_check(opt, "infected"))
	printinfected = 1;

    if(opt_check(opt, "bell"))
	bell = 1;

    if(opt_check(opt, "tempdir"))
	cl_settempdir(opt_arg(opt, "tempdir"), 0);

    if(opt_check(opt, "leave-temps"))
	cl_settempdir(NULL, 1);

    /* initialize logger */
    if(opt_check(opt, "log")) {
	logg_file = opt_arg(opt, "log");
	if(logg("#\n-------------------------------------------------------------------------------\n\n")) {
	    mprintf("!Problem with internal logger.\n");
	    opt_free(opt);
	    return 62;
	}
    } else 
	logg_file = NULL;


    /* validate some numerical options */

    if(opt_check(opt, "max-space")) {
	pt = opt_arg(opt, "max-space");
	if(!strchr(pt, 'M') && !strchr(pt, 'm')) {
	    if(!isnumb(pt)) {
		logg("!--max-space requires a natural number\n");
		opt_free(opt);
		return 40;
	    }
	}
    }

    if(opt_check(opt, "max-files")) {
	if(!isnumb(opt_arg(opt, "max-files"))) {
	    logg("!--max-files requires a natural number\n");
	    opt_free(opt);
	    return 40;
	}
    }

    if(opt_check(opt, "max-recursion")) {
	if(!isnumb(opt_arg(opt, "max-recursion"))) {
	    logg("!--max-recursion requires a natural number\n");
	    opt_free(opt);
	    return 40;
	}
    }

    if(opt_check(opt, "max-dir-recursion")) {
	if(!isnumb(opt_arg(opt, "max-dir-recursion"))) {
	    logg("!--max-dir-recursion requires a natural number\n");
	    opt_free(opt);
	    return 40;
	}
    }

    if(opt_check(opt, "max-ratio")) {
	if(!isnumb(opt_arg(opt, "max-ratio"))) {
	    logg("!--max-ratio requires a natural number\n");
	    opt_free(opt);
	    return 40;
	}
    }

    memset(&claminfo, 0, sizeof(struct s_info));

    gettimeofday(&t1, &tz);
    ret = scanmanager(opt);

    if(!opt_check(opt, "disable-summary") && !opt_check(opt, "no-summary")) {
	gettimeofday(&t2, &tz);
	ds = t2.tv_sec - t1.tv_sec;
	dms = t2.tv_usec - t1.tv_usec;
	ds -= (dms < 0) ? (1):(0);
	dms += (dms < 0) ? (1000000):(0);
	logg("\n----------- SCAN SUMMARY -----------\n");
	logg("Known viruses: %d\n", claminfo.signs);
	if(opt_check(opt, "ncore"))
	    logg("Engine version: %s [ncore]\n", cl_retver());
	else
	    logg("Engine version: %s\n", cl_retver());
	logg("Scanned directories: %d\n", claminfo.dirs);
	logg("Scanned files: %d\n", claminfo.files);
	logg("Infected files: %d\n", claminfo.ifiles);
	if(claminfo.notremoved) {
	    logg("Not removed: %d\n", claminfo.notremoved);
	}
	if(claminfo.notmoved) {
	    logg("Not moved: %d\n", claminfo.notmoved);
	}
	mb = claminfo.blocks * (CL_COUNT_PRECISION / 1024) / 1024.0;
	logg("Data scanned: %2.2lf MB\n", mb);
	logg("Time: %d.%3.3d sec (%d m %d s)\n", ds, dms/1000, ds/60, ds%60);
    }

    opt_free(opt);
    return ret;
}

void help(void)
{

    mprintf_stdout = 1;

    mprintf("\n");
    mprintf("                       Clam AntiVirus Scanner "VERSION"\n");
    mprintf("    (C) 2002 - 2005 ClamAV Team - http://www.clamav.net/team.html\n\n");

    mprintf("    --help                -h             Print this help screen\n");
    mprintf("    --version             -V             Print version number\n");
    mprintf("    --verbose             -v             Be verbose\n");
    mprintf("    --debug                              Enable libclamav's debug messages\n");
    mprintf("    --quiet                              Only output error messages\n");
    mprintf("    --stdout                             Write to stdout instead of stderr\n");
    mprintf("    --no-summary                         Disable summary at end of scanning\n");
    mprintf("    --infected            -i             Only print infected files\n");
    mprintf("    --bell                               Sound bell on virus detection\n");

    mprintf("\n");
    mprintf("    --tempdir=DIRECTORY                  Create temporary files in DIRECTORY\n");
    mprintf("    --leave-temps                        Do not remove temporary files\n");
    mprintf("    --database=FILE/DIR   -d FILE/DIR    Load virus database from FILE or load\n");
    mprintf("                                         all .cvd and .db[2] files from DIR\n");
    mprintf("    --log=FILE            -l FILE        Save scan report to FILE\n");
    mprintf("    --recursive           -r             Scan subdirectories recursively\n");
    mprintf("    --remove                             Remove infected files. Be careful!\n");
    mprintf("    --move=DIRECTORY                     Move infected files into DIRECTORY\n");
#ifdef HAVE_REGEX_H
    mprintf("    --exclude=REGEX                      Don't scan file names matching REGEX\n");
    mprintf("    --exclude-dir=REGEX                  Don't scan directories matching REGEX\n");
    mprintf("    --include=REGEX                      Only scan file names matching REGEX\n");
    mprintf("    --include-dir=REGEX                  Only scan directories matching REGEX\n");
#else
    mprintf("    --exclude=PATT                       Don't scan file names containing PATT\n");
    mprintf("    --exclude-dir=PATT                   Don't scan directories containing PATT\n");
    mprintf("    --include=PATT                       Only scan file names containing PATT\n");
    mprintf("    --include-dir=PATT                   Only scan directories containing PATT\n");
#endif
#ifdef HAVE_NCORE
    mprintf("\n    --ncore                            Use hardware acceleration\n");
#endif
    mprintf("\n");
    mprintf("    --no-mail                            Disable mail file support\n");
    mprintf("    --no-phishing                        Disable phishing detection\n");
#ifdef CL_EXPERIMENTAL
    mprintf("    --no-phishing-scan-urls              Disable url-based phishing detection\n");
    mprintf("    --phishing-strict-url-check          Enable phishing detection for all domains (might lead to false positives!)\n");
#endif
    mprintf("    --no-algorithmic                     Disable algorithmic detection\n");
    mprintf("    --no-pe                              Disable PE analysis\n");
    mprintf("    --no-ole2                            Disable OLE2 support\n");
    mprintf("    --no-html                            Disable HTML support\n");
    mprintf("    --no-archive                         Disable libclamav archive support\n");
    mprintf("    --detect-broken                      Try to detect broken executable files\n");
    mprintf("    --block-encrypted                    Block encrypted archives\n");
    mprintf("    --block-max                          Block archives that exceed limits\n");
#ifdef WITH_CURL
    mprintf("    --mail-follow-urls                   Download and scan URLs\n");
#endif

    mprintf("\n");
    mprintf("    --max-space=#n                       Only extract first #n kilobytes from\n");
    mprintf("                                         archived files\n");
    mprintf("    --max-files=#n                       Only extract first #n files from\n");
    mprintf("                                         archives\n");
    mprintf("    --max-recursion=#n                   Maximum archive recursion level\n");
    mprintf("    --max-ratio=#n                       Maximum compression ratio limit\n");
    mprintf("    --max-dir-recursion=#n               Maximum directory recursion level\n");
    mprintf("    --unzip[=FULLPATH]                   Enable support for .zip files\n");
    mprintf("    --unrar[=FULLPATH]                   Enable support for .rar files\n");
    mprintf("    --arj[=FULLPATH]                     Enable support for .arj files\n");
    mprintf("    --unzoo[=FULLPATH]                   Enable support for .zoo files\n");
    mprintf("    --lha[=FULLPATH]                     Enable support for .lha files\n");
    mprintf("    --jar[=FULLPATH]                     Enable support for .jar files\n");
    mprintf("    --tar[=FULLPATH]                     Enable support for .tar files\n");
    mprintf("    --deb[=FULLPATH to ar]               Enable support for .deb files\n");
    mprintf("    --tgz[=FULLPATH]                     Enable support for .tar.gz, .tgz files\n\n");
}

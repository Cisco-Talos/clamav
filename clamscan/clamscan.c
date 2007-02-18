/*
 *  Copyright (C) 2002 - 2005 Tomasz Kojm <tkojm@clamav.net>
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
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
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

#include "options.h"
#include "others.h"
#include "shared.h"
#include "manager.h"
#include "defaults.h"
#include "treewalk.h"
#include "misc.h"

#include "output.h"

#ifdef C_LINUX
#include <sys/resource.h>
#endif

void help(void);

struct s_info claminfo;
short recursion = 0, printinfected = 0, bell = 0;

int clamscan(struct optstruct *opt)
{
	int ds, dms, ret;
	double mb;
	struct timeval t1, t2;
	struct timezone tz;
	time_t starttime;

    /* initialize some important variables */

    if(optc(opt, 'v')) {
	mprintf_verbose = 1;
	logg_verbose = 1;
    }

    if(optl(opt, "quiet"))
	mprintf_quiet = 1;

    if(optl(opt, "stdout"))
	mprintf_stdout = 1;

    if(optl(opt, "debug")) {
#if defined(C_LINUX)
	    /* njh@bandsman.co.uk: create a dump if needed */
	    struct rlimit rlim;

	rlim.rlim_cur = rlim.rlim_max = RLIM_INFINITY;
	if(setrlimit(RLIMIT_CORE, &rlim) < 0)
	    perror("setrlimit");
#endif
	cl_debug(); /* enable debug messages */
    }

    if(optc(opt, 'V')) {
	print_version();
	return 0;
    }

    if(optc(opt, 'h')) {
	free_opt(opt);
    	help();
    }

    if(strcmp(VERSION, cl_retver())) {
	mprintf("WARNING: Version mismatch (clamscan: "VERSION", libclamav: %s)\n", cl_retver());
	mprintf("See the FAQ at http://www.clamav.net/faq.html\n");
    }

    /* check other options */

    if(optc(opt, 'r'))
	recursion = 1;

    if(optc(opt, 'i'))
	printinfected = 1;

    if(optl(opt, "bell"))
	bell = 1;

    if(optl(opt, "tempdir"))
	cl_settempdir(getargl(opt, "tempdir"), 0);

    if(optl(opt, "leave-temps"))
	cl_settempdir(NULL, 1);

    /* initialize logger */

    if(optc(opt, 'l')) {
	logg_file = getargc(opt, 'l');
	if(logg("--------------------------------------\n")) {
	    mprintf("!Problem with internal logger.\n");
	    return 62;
	}
    } else 
	logg_file = NULL;

    /* we need some pre-checks */
    if(optl(opt, "max-space"))
	if(!strchr(getargl(opt, "max-space"), 'M') && !strchr(getargl(opt, "max-space"), 'm'))
	    if(!isnumb(getargl(opt, "max-space"))) {
		mprintf("!--max-space requires natural number.\n");
		return 40;
	    }

    if(optl(opt, "max-files"))
	if(!isnumb(getargl(opt, "max-files"))) {
	    mprintf("!--max-files requires natural number.\n");
	    return 40;
	}

    if(optl(opt, "max-recursion"))
	if(!isnumb(getargl(opt, "max-recursion"))) {
	    mprintf("!--max-recursion requires natural number.\n");
	    return 40;
	}

    if(optl(opt, "max-dir-recursion"))
	if(!isnumb(getargl(opt, "max-dir-recursion"))) {
	    logg("!--max-dir-recursion requires natural number.\n");
	    return 40;
	}

    if(optl(opt, "max-ratio"))
	if(!isnumb(getargl(opt, "max-ratio"))) {
	    logg("!--max-ratio requires natural number.\n");
	    return 40;
	}

    time(&starttime);
    /* ctime() does \n, but I need it once more */
    logg("Scan started: %s\n", ctime(&starttime));

    memset(&claminfo, 0, sizeof(struct s_info));

    gettimeofday(&t1, &tz);
    ret = scanmanager(opt);

    if(!optl(opt, "disable-summary") && !optl(opt, "no-summary")) {
	gettimeofday(&t2, &tz);
	ds = t2.tv_sec - t1.tv_sec;
	dms = t2.tv_usec - t1.tv_usec;
	ds -= (dms < 0) ? (1):(0);
	dms += (dms < 0) ? (1000000):(0);
	mprintf("\n----------- SCAN SUMMARY -----------\n");
	    logg("\n-- summary --\n");
	mprintf("Known viruses: %d\n", claminfo.sigs);
	    logg("Known viruses: %d\n", claminfo.sigs);
	mprintf("Engine version: %s\n", cl_retver());
	    logg("Engine version: %s\n", cl_retver());
	mprintf("Scanned directories: %d\n", claminfo.dirs);
	    logg("Scanned directories: %d\n", claminfo.dirs);
	mprintf("Scanned files: %d\n", claminfo.files);
	    logg("Scanned files: %d\n", claminfo.files);
	mprintf("Infected files: %d\n", claminfo.ifiles);
	    logg("Infected files: %d\n", claminfo.ifiles);
	if(claminfo.notremoved) {
	    mprintf("Not removed: %d\n", claminfo.notremoved);
		logg("Not removed: %d\n", claminfo.notremoved);
	}
	if(claminfo.notmoved) {
	    mprintf("Not moved: %d\n", claminfo.notmoved);
		logg("Not moved: %d\n", claminfo.notmoved);
	}
	mb = claminfo.blocks * (CL_COUNT_PRECISION / 1024) / 1024.0;
	mprintf("Data scanned: %2.2lf MB\n", mb);
	    logg("Data scanned: %2.2lf MB\n", mb);
/*
	mprintf("I/O buffer size: %d bytes\n", SCANBUFF);
	    logg("I/O buffer size: %d bytes\n", SCANBUFF);
*/

	mprintf("Time: %d.%3.3d sec (%d m %d s)\n", ds, dms/1000, ds/60, ds%60);
	    logg("Time: %d.%3.3d sec (%d m %d s)\n", ds, dms/1000, ds/60, ds%60);
    }

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

    mprintf("\n");
    mprintf("    --no-mail                            Disable mail file support\n");
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
    mprintf("    --tgz[=FULLPATH]                     enable support for .tar.gz, .tgz files\n\n");

    exit(0);
}

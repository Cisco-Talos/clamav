/*
 *  Copyright (C) 2002, 2003 Tomasz Kojm <zolw@konarski.edu.pl>
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

void help(void);

/* this local macro takes care about freeing memory at exit */
/*
#define mexit(i)    if(opt) free_opt(opt);			    \
		    mprintf("*Memory freed. Exit code: %d\n", i);   \
		    exit(i);
*/
#define mexit(i)    exit(i)

void clamscan(struct optstruct *opt)
{
	int ds, dms, ret;
	double mb;
	struct timeval t1, t2;
	struct timezone tz;
	time_t starttime;


    /* initialize some important variables */

    mprintf_disabled = 0;

    if(optc(opt, 'v')) mprintf_verbose = 1;
    else mprintf_verbose = 0;

    if(optl(opt, "quiet")) mprintf_quiet = 1;
    else mprintf_quiet = 0;

    if(optl(opt, "stdout")) mprintf_stdout = 1;
    else mprintf_stdout = 0;

    if(optc(opt, 'V')) {
	mprintf("clamscan / ClamAV version "VERSION"\n");
	mexit(0);
    }

    if(optc(opt, 'h')) {
	free_opt(opt);
    	help();
    }

    /* check other options */

    if(optc(opt, 'r')) recursion = 1;
    else recursion = 0;

    if(optc(opt, 'i')) printinfected = 1;
    else printinfected = 0;

    /* initialize logger */

    if(optl(opt, "log-verbose")) logverbose = 1;
    else logverbose = 0;

    if(optc(opt, 'l')) {
	logfile = getargc(opt, 'l');
	if(logg("--------------------------------------\n")) {
	    mprintf("!Problem with internal logger.\n");
	    mexit(1);
	}
    } else 
	logfile = NULL;

    /* we need some pre-checks */
    if(optl(opt, "max-space"))
	if(!strchr(getargl(opt, "max-space"), 'M') && !strchr(getargl(opt, "max-space"), 'm'))
	    if(!isnumb(getargl(opt, "max-space"))) {
		mprintf("!--max-space requires natural number.\n");
		exit(40);
	    }

    if(optl(opt, "max-files"))
	if(!isnumb(getargl(opt, "max-files"))) {
	    mprintf("!--max-files requires natural number.\n");
	    exit(40);
	}

    if(optl(opt, "max-recursion"))
	if(!isnumb(getargl(opt, "max-recursion"))) {
	    mprintf("!--max-recursion requires natural number.\n");
	    exit(40);
	}


    time(&starttime);
    /* ctime() does \n, but I need it once more */
    logg("Scan started: %s\n", ctime(&starttime));

    memset(&claminfo, 0, sizeof(struct s_info));

    gettimeofday(&t1, &tz);
    ret = scanmanager(opt);

    if(!optl(opt, "disable-summary")) {
	gettimeofday(&t2, &tz);
	ds = t2.tv_sec - t1.tv_sec;
	dms = t2.tv_usec - t1.tv_usec;
	ds -= (dms < 0) ? (1):(0);
	dms += (dms < 0) ? (1000000):(0);
	mprintf("\n----------- SCAN SUMMARY -----------\n");
	    logg("\n-- summary --\n");
	mprintf("Known viruses: %d\n", claminfo.signs);
	    logg("Known viruses: %d\n", claminfo.signs);
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

	mprintf("I/O buffer size: %d bytes\n", BUFFSIZE);
	    logg("I/O buffer size: %d bytes\n", BUFFSIZE);
	mprintf("Time: %d.%3.3d sec (%d m %d s)\n", ds, dms/1000, ds/60, ds%60);
	    logg("Time: %d.%3.3d sec (%d m %d s)\n", ds, dms/1000, ds/60, ds%60);
    }

    mexit(ret);
}

void help(void)
{

    mprintf_stdout = 1;

    mprintf("\n");
    mprintf("		   Clam AntiVirus Scanner "VERSION"\n");
    mprintf("		   (c) 2002 Tomasz Kojm <zolw@konarski.edu.pl>\n");
    mprintf("	  \n");
    mprintf("    --help		    -h		Show help\n");
    mprintf("    --version		    -V		Print version number and exit\n");
    mprintf("    --verbose		    -v		Be verbose\n");
    mprintf("    --quiet				Be quiet, output only error messages\n");
    mprintf("    --stdout				Write to stdout instead of stderr\n");
    mprintf("					(this help is always written to stdout)\n");
    mprintf("    --force				Try to ignore some errors\n");
    mprintf("\n");
    mprintf("    --tempdir=DIRECTORY			create temporary files in DIRECTORY\n");
    mprintf("    --database=FILE/DIR    -d FILE/DIR	Load virus database from FILE or load\n");
    mprintf("					all .db and .db2 files from DIR\n");
    mprintf("    --log=FILE		    -l FILE	Save scan report in FILE\n");
    mprintf("    --log-verbose			Save additional informations\n");
    mprintf("    --recursive    	    -r	    	Scan directories recursively\n");
    mprintf("    --infected		    -i		Print infected files only\n");
    mprintf("    --remove				Remove infected files. Be careful.\n");
    mprintf("    --move=DIRECTORY			Move infected files into DIRECTORY\n");
    mprintf("    --exclude=PATT			Don't scan file names containing PATT\n");
    mprintf("    --include=PATT			Only scan file names containing PATT\n");
    mprintf("    --disable-summary			Disable summary at end of scanning\n");
    mprintf("    --mbox		    -m		Treat stdin as a mailbox\n");
    mprintf("\n");
    mprintf("    --disable-archive			Disable libclamav archive support\n");
    mprintf("    --max-space=#n			Extract first #n kilobytes only\n");
    mprintf("    --max-files=#n			Extract first #n files only\n");
    mprintf("    --max-recursion=#n			Maximal recursion level\n");
    mprintf("    --unzip[=FULLPATH]			Enable support for .zip files\n");
    mprintf("    --unrar[=FULLPATH]			Enable support for .rar files\n");
    mprintf("    --unace[=FULLPATH]			Enable support for .ace files\n");
    mprintf("    --arj[=FULLPATH]			Enable support for .arj files\n");
    mprintf("    --unzoo[=FULLPATH]			Enable support for .zoo files\n");
    mprintf("    --lha[=FULLPATH]			Enable support for .lha files\n");
    mprintf("    --jar[=FULLPATH]			Enable support for .jar files\n");
    mprintf("    --tar[=FULLPATH]			Enable support for .tar files\n");
    mprintf("    --deb[=FULLPATH to ar]    		Enable support for .deb files,\n");
    mprintf("					implies --tgz , but doesn't conflict\n");
    mprintf("					with --tgz=FULLPATH.\n");
    mprintf("    --tgz[=FULLPATH]			enable support for .tar.gz, .tgz files\n\n");

    exit(0);
}

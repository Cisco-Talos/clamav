/*
 *  Copyright (C) 2006 Sensory Networks, Inc.
 *	      (C) 2007 Tomasz Kojm <tkojm@clamav.net>
 *	      Written by Tomasz Kojm
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
#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <time.h>

#include "shared/misc.h"
#include "libclamav/clamav.h"
#include "libclamav/version.h"

#include "cfgparser.h"
#define _GNU_SOURCE
#include "getopt.h"

static void printopt(const struct cfgoption *opt, const struct cfgstruct *cpt, int nondef)
{

    if(!cpt->enabled && opt->numarg == -1) {
	if(!nondef || (opt->numarg != cpt->numarg))
	    printf("%s not set\n", opt->name);
	return;
    }

    while(cpt) {
	switch(opt->argtype) {
	    case OPT_STR:
	    case OPT_FULLSTR:
	    case OPT_QUOTESTR:
		if(!nondef || !opt->strarg || strcmp(opt->strarg, cpt->strarg))
		    printf("%s = \"%s\"\n", opt->name, cpt->strarg);
		break;
	    case OPT_NUM:
	    case OPT_COMPSIZE:
		if(!nondef || (opt->numarg != cpt->numarg))
		    printf("%s = %u\n", opt->name, cpt->numarg);
		break;
	    case OPT_BOOL:
		if(!nondef || (opt->numarg != cpt->numarg))
		    printf("%s = %s\n", opt->name, cpt->enabled ? "yes" : "no");
		break;
	    default:
		printf("%s: UNKNOWN ARGUMENT TYPE\n", opt->name);
	}
	cpt = cpt->nextarg;
    }
}

static void printcfg(const char *cfgfile, int nondef)
{
	const struct cfgoption *opt;
	const struct cfgstruct *cpt;
	struct cfgstruct *cfg;
	int i;
	unsigned short cfgowner = 0;


    if(!(cfg = getcfg(cfgfile, 1))) {
	printf("Can't parse %s\n", cfgfile);
	return;
    }

    /* pre loop to detect merged config */
    for(i = 0; ; i++) {
	opt = &cfg_options[i];

	if(!opt->name)
	    break;

	cpt = cfgopt(cfg, opt->name);

	if((cpt->numarg != opt->numarg) || (cpt->strarg && opt->strarg && strcmp(cpt->strarg, opt->strarg))) {
	    if((opt->owner & OPT_CLAMD) && !(opt->owner & OPT_FRESHCLAM))
		cfgowner |= OPT_CLAMD;
	    else if((opt->owner & OPT_FRESHCLAM) && !(opt->owner & OPT_CLAMD))
		cfgowner |= OPT_FRESHCLAM;
	}
    }

    if((cfgowner & OPT_CLAMD) && (cfgowner & OPT_FRESHCLAM)) { /* merged cfg */
	printf("%s: clamd and freshclam directives\n", cfgfile);
	printf("------------------------------\n");

	printf("\n[common]\n");
	for(i = 0; ; i++) {
	    opt = &cfg_options[i];
	    if(!opt->name)
		break;
	    if((opt->owner & OPT_CLAMD) && (opt->owner & OPT_FRESHCLAM)) {
		cpt = cfgopt(cfg, opt->name);
		printopt(opt, cpt, nondef);
	    }
	}

	printf("\n[clamd]\n");
	for(i = 0; ; i++) {
	    opt = &cfg_options[i];
	    if(!opt->name)
		break;
	    if((opt->owner & OPT_CLAMD) && !(opt->owner & OPT_FRESHCLAM)) {
		cpt = cfgopt(cfg, opt->name);
		printopt(opt, cpt, nondef);
	    }
	}

	printf("\n[freshclam]\n");
	for(i = 0; ; i++) {
	    opt = &cfg_options[i];
	    if(!opt->name)
		break;
	    if((opt->owner & OPT_FRESHCLAM) && !(opt->owner & OPT_CLAMD)) {
		cpt = cfgopt(cfg, opt->name);
		printopt(opt, cpt, nondef);
	    }
	}

    } else { /* separate cfg */

	if(cfgowner & OPT_CLAMD) {
	    printf("%s: clamd directives\n", cfgfile);
	    printf("------------------------------\n");

	    for(i = 0; ; i++) {
		opt = &cfg_options[i];
		if(!opt->name)
		    break;
		if(opt->owner & OPT_CLAMD) {
		    cpt = cfgopt(cfg, opt->name);
		    printopt(opt, cpt, nondef);
		}
	    }
	} else {
	    printf("%s: freshclam directives\n", cfgfile);
	    printf("------------------------------\n");

	    for(i = 0; ; i++) {
		opt = &cfg_options[i];
		if(!opt->name)
		    break;
		if(opt->owner & OPT_FRESHCLAM) {
		    cpt = cfgopt(cfg, opt->name);
		    printopt(opt, cpt, nondef);
		}
	    }
	}
    }
    freecfg(cfg);

}

static void printdb(const char *dir, const char *db)
{
	struct cl_cvd *cvd;
	char path[256];
	unsigned int cld = 0;
	time_t t;


    snprintf(path, sizeof(path), "%s/%s.cvd", dir, db);
    if(access(path, R_OK) == -1) {
	snprintf(path, sizeof(path), "%s/%s.cld", dir, db);
	cld = 1;
	if(access(path, R_OK) == -1) {
	    printf("%s db: Not found\n", db);
	    return;
	}
    }

    if((cvd = cl_cvdhead(path))) {
	t = (time_t) cvd->stime;
	printf("%s db: Format: %s, Version: %u, Build time: %s", db, cld ? ".cld" : ".cvd", cvd->version, ctime(&t));
	cl_cvdfree(cvd);
    }
}

static void version(void)
{
    printf("Clam AntiVirus Configuration Tool %s\n", get_version());
}

static void help(void)
{
    printf("\n");
    printf("             Clam AntiVirus: Configuration Tool %s\n", get_version());
    printf("         (C) 2006 - 2007 ClamAV Team - http://www.clamav.net/team\n\n");

    printf("    --help                 -h              show help\n");
    printf("    --version              -v              show version\n");
    printf("    --config-dir DIR       -c DIR          search for config files in DIR\n");
    printf("    --non-default          -n              only print non-default settings\n");
    printf("\n");
}


#ifndef REPO_VERSION
#define REPO_VERSION VERSION
#endif

int main(int argc, char **argv)
{
	char path[1024];
	struct stat sb;
	int ret, opt_index, nondef = 0;
	const char *getopt_parameters = "hVc:n";
	static struct option long_options[] = {
	    {"help", 0, 0, 'h'},
	    {"version", 0, 0, 'V'},
	    {"config-dir", 1, 0, 'c'},
	    {"non-default", 0, 0, 'n'},
	    {0, 0, 0, 0}
    	};
	char *confdir = strdup(CONFDIR), *dbdir;
	int found = 0;


    while(1) {
	opt_index = 0;
	ret = getopt_long(argc, argv, getopt_parameters, long_options, &opt_index);

	if (ret == -1)
	    break;

	switch (ret) {
	    case 0:
		break;

	    case 'c':
		free(confdir);
		confdir = strdup(optarg);
		break;

	    case 'h':
		help();
		free(confdir);
		exit(0);

	    case 'n':
		nondef = 1;
		break;

	    case 'V':
		version();
		free(confdir);
		exit(0);

    	    default:
		printf("ERROR: Unknown option passed\n");
		free(confdir);
		exit(1);
        }
    }

    snprintf(path, sizeof(path), "%s/clamd.conf", confdir);
    if(stat(path, &sb) != -1) {
	printcfg(path, nondef);
	found = 1;
	printf("\n");
    }

    snprintf(path, sizeof(path), "%s/freshclam.conf", confdir);
    if(stat(path, &sb) != -1) {
	printcfg(path, nondef);
	found = 1;
    }

    if(!found) {
	printf("No config files found in %s\n", confdir);
	free(confdir);
	return 1;
    }
    free(confdir);

    printf("\nEngine and signature databases\n");
    printf("------------------------------\n");

#ifdef CL_EXPERIMENTAL
    printf("Engine version: %s (with experimental code)\n", get_version());
#else
    printf("Engine version: %s\n", get_version());
#endif

    if(strcmp(REPO_VERSION, cl_retver()))
	printf("WARNING: Version mismatch: clamconf: "REPO_VERSION", libclamav: %s\n", cl_retver());

    printf("Database directory: ");
    dbdir = freshdbdir();
    if(!dbdir) {
	printf("Failed to retrieve\n");
	return 1;
    } else printf("%s\n", dbdir);

    if(dbdir) {
	printdb(dbdir, "main");
	printdb(dbdir, "daily");
	free(dbdir);
    }
    return 0;
}

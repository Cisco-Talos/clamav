/*
 *  Copyright (C) 2006 Tomasz Kojm <tkojm@clamav.net>
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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cfgparser.h"
#define _GNU_SOURCE
#include "getopt.h"

void printopt(const struct cfgoption *opt, const struct cfgstruct *cpt)
{
    if(!cpt->enabled) {
	printf("%s not set\n", opt->name);
	return;
    }

    /*
    printf("opt: %s, %d, %d, %s, %d, %d\n", opt->name, opt->argtype, opt->numarg, opt->strarg, opt->multiple, opt->owner);
    printf("cpt: %s, %s, %d, %d, %d\n", cpt->optname, cpt->strarg, cpt->numarg, cpt->enabled, cpt->multiple);
    */

    switch(opt->argtype) {
	case OPT_STR:
	case OPT_FULLSTR:
	    printf("%s = \"%s\"\n", opt->name, cpt->strarg);
	    break;
	case OPT_NUM:
	case OPT_COMPSIZE:
	    printf("%s = %d\n", opt->name, cpt->numarg);
	    break;
	case OPT_BOOL:
	    if(cpt->enabled)
		printf("%s = yes\n", opt->name);
	    else
		printf("%s = no\n", opt->name);
	    break;
	default:
	    printf("%s: UNKNOWN ARGUMENT TYPE\n, opt->name");
    }
}

void printcfg(const char *cfgfile)
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
	printf("-----------------\n");

	printf("\n[common]\n");
	for(i = 0; ; i++) {
	    opt = &cfg_options[i];
	    if(!opt->name)
		break;
	    if((opt->owner & OPT_CLAMD) && (opt->owner & OPT_FRESHCLAM)) {
		cpt = cfgopt(cfg, opt->name);
		printopt(opt, cpt);
	    }
	}

	printf("\n[clamd]\n");
	for(i = 0; ; i++) {
	    opt = &cfg_options[i];
	    if(!opt->name)
		break;
	    if((opt->owner & OPT_CLAMD) && !(opt->owner & OPT_FRESHCLAM)) {
		cpt = cfgopt(cfg, opt->name);
		printopt(opt, cpt);
	    }
	}

	printf("\n[freshclam]\n");
	for(i = 0; ; i++) {
	    opt = &cfg_options[i];
	    if(!opt->name)
		break;
	    if((opt->owner & OPT_FRESHCLAM) && !(opt->owner & OPT_CLAMD)) {
		cpt = cfgopt(cfg, opt->name);
		printopt(opt, cpt);
	    }
	}

    } else { /* separate cfg */

	if(cfgowner & OPT_CLAMD) {
	    printf("%s: clamd directives\n", cfgfile);
	    printf("-----------------\n");

	    for(i = 0; ; i++) {
		opt = &cfg_options[i];
		if(!opt->name)
		    break;
		if(opt->owner & OPT_CLAMD) {
		    cpt = cfgopt(cfg, opt->name);
		    printopt(opt, cpt);
		}
	    }
	} else {
	    printf("%s: freshclam directives\n", cfgfile);
	    printf("-----------------\n");

	    for(i = 0; ; i++) {
		opt = &cfg_options[i];
		if(!opt->name)
		    break;
		if(opt->owner & OPT_FRESHCLAM) {
		    cpt = cfgopt(cfg, opt->name);
		    printopt(opt, cpt);
		}
	    }
	}
    }

    freecfg(cfg);
}

void help(void)
{
    printf("\n");
    printf("             Clam AntiVirus: Configuration Tool "VERSION"\n");
    printf("      (C) 2006 ClamAV Team - http://www.clamav.net/team.html\n\n");

    printf("    --help                 -h              show help\n");
    printf("    --config-dir DIR       -c DIR          search for config files in DIR\n");
    printf("\n");
}

int main(int argc, char **argv)
{
	char path[1024];
	struct stat sb;
	int ret, opt_index;
	const char *getopt_parameters = "hc:";
	static struct option long_options[] = {
	    {"help", 0, 0, 'h'},
	    {"config-dir", 1, 0, 'c'},
	    {0, 0, 0, 0}
    	};
	char *confdir = strdup(CONFDIR);
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
		confdir = optarg;
		break;

	    case 'h':
		help();
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
	printcfg(path);
	found = 1;
	printf("\n");
    }

    snprintf(path, sizeof(path), "%s/freshclam.conf", confdir);
    if(stat(path, &sb) != -1) {
	printcfg(path);
	found = 1;
    }

    if(!found) {
	printf("No config files found in %s\n", confdir);
	free(confdir);
	return 1;
    }

    return 0;
}

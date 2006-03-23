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
#include <ctype.h>

#include "options.h"
#include "cfgparser.h"
#include "defaults.h"
#include "str.h"
#include "memory.h"
#include "misc.h"

static int regcfg(struct cfgstruct **copt, char *optname, char *strarg, int numarg, short multiple);

struct cfgstruct *getcfg(const char *cfgfile, int verbose)
{
	char buff[LINE_LENGTH], *name, *arg, *c;
	FILE *fs;
	int line = 0, i, found, ctype, calc, val;
	struct cfgstruct *copt = NULL;
	struct cfgoption *pt;

	struct cfgoption cfg_options[] = {
	    {"LogFile",	OPT_FULLSTR, -1, NULL, 0},
	    {"LogFileUnlock", OPT_BOOL, 0, NULL, 0},
	    {"LogFileMaxSize", OPT_COMPSIZE, 1048576, NULL, 0},
	    {"LogTime", OPT_BOOL, 0, NULL, 0},
	    {"LogClean", OPT_BOOL, 0, NULL, 0},
	    {"LogVerbose", OPT_BOOL, 0, NULL, 0}, /* clamd + freshclam */
	    {"LogSyslog", OPT_BOOL, 0, NULL, 0},
	    {"LogFacility", OPT_STR, -1, "LOG_LOCAL6", 0},
	    {"PidFile", OPT_FULLSTR, -1, NULL, 0},
	    {"TemporaryDirectory", OPT_FULLSTR, -1, NULL, 0},
	    {"ScanPE", OPT_BOOL, 1, NULL, 0},
	    {"DetectBrokenExecutables", OPT_BOOL, 0, NULL, 0},
	    {"ScanMail", OPT_BOOL, 1, NULL, 0},
	    {"MailFollowURLs", OPT_BOOL, 0, NULL, 0},
	    {"DetectPhishing", OPT_BOOL, 1, NULL, 0},
	    {"ScanAlgo", OPT_BOOL, 1, NULL, 0},
	    {"ScanHTML", OPT_BOOL, 1, NULL, 0},
	    {"ScanOLE2", OPT_BOOL, 1, NULL, 0},
	    {"ScanArchive", OPT_BOOL, 1, NULL, 0},
	    {"ArchiveMaxFileSize", OPT_COMPSIZE, 10485760, NULL, 0},
	    {"ArchiveMaxRecursion", OPT_NUM, 8, NULL, 0},
	    {"ArchiveMaxFiles", OPT_NUM, 1000, NULL, 0},
	    {"ArchiveMaxCompressionRatio", OPT_NUM, 250, NULL, 0},
	    {"ArchiveLimitMemoryUsage", OPT_BOOL, 0, NULL, 0},
	    {"ArchiveBlockEncrypted", OPT_BOOL, 0, NULL, 0},
	    {"ArchiveBlockMax", OPT_BOOL, 0, NULL, 0},
	    {"DatabaseDirectory", OPT_FULLSTR, -1, DATADIR, 0}, /* clamd + freshclam */
	    {"TCPAddr", OPT_STR, -1, NULL, 0},
	    {"TCPSocket", OPT_NUM, -1, NULL, 0},
	    {"LocalSocket", OPT_FULLSTR, -1, NULL, 0},
	    {"MaxConnectionQueueLength", OPT_NUM, 15, NULL, 0},
	    {"StreamMaxLength", OPT_COMPSIZE, 10485760, NULL, 0},
	    {"StreamMinPort", OPT_NUM, 1024, NULL, 0},
	    {"StreamMaxPort", OPT_NUM, 2048, NULL, 0},
	    {"MaxThreads", OPT_NUM, 10, NULL, 0},
	    {"ReadTimeout", OPT_NUM, 120, NULL, 0},
	    {"IdleTimeout", OPT_NUM, 30, NULL, 0},
	    {"MaxDirectoryRecursion", OPT_NUM, 15, NULL, 0},
	    {"FollowDirectorySymlinks", OPT_BOOL, 0, NULL, 0},
	    {"FollowFileSymlinks", OPT_BOOL, 0, NULL, 0},
	    {"ExitOnOOM", OPT_BOOL, 0, NULL, 0},
	    {"Foreground", OPT_BOOL, 0, NULL, 0}, /* clamd + freshclam */
	    {"Debug", OPT_BOOL, 0, NULL, 0},
	    {"LeaveTemporaryFiles", OPT_BOOL, 0, NULL, 0},
	    {"FixStaleSocket", OPT_BOOL, 0, NULL, 0},
	    {"User", OPT_STR, -1, NULL, 0},
	    {"AllowSupplementaryGroups", OPT_BOOL, 0, NULL, 0},
	    {"SelfCheck", OPT_NUM, 1800, NULL, 0},
	    {"VirusEvent", OPT_FULLSTR, -1, NULL, 0},
	    {"ClamukoScanOnAccess", OPT_BOOL, 0, NULL, 0},
	    {"ClamukoScanOnOpen", OPT_BOOL, 0, NULL, 0},
	    {"ClamukoScanOnClose", OPT_BOOL, 0, NULL, 0},
	    {"ClamukoScanOnExec", OPT_BOOL, 0, NULL, 0},
	    {"ClamukoIncludePath", OPT_STR, 0, NULL, 0},
	    {"ClamukoExcludePath", OPT_STR, 0, NULL, 0},
	    {"ClamukoMaxFileSize", OPT_COMPSIZE, 5242880, NULL, 0},
	    {"ClamukoScanArchive", OPT_BOOL, 0, NULL, 0},
	    {"DatabaseOwner", OPT_STR, -1, NULL, 0}, /* freshclam */
	    {"Checks", OPT_NUM, 12, NULL, 0}, /* freshclam */
	    {"UpdateLogFile", OPT_FULLSTR, -1, NULL, 0}, /* freshclam */
	    {"DNSDatabaseInfo", OPT_STR, -1, "current.cvd.clamav.net", 0}, /* freshclam */
	    {"DatabaseMirror", OPT_STR, -1, NULL, 1}, /* freshclam */
	    {"MaxAttempts", OPT_NUM, 3, NULL, 0}, /* freshclam */
	    {"HTTPProxyServer", OPT_STR, -1, NULL, 0}, /* freshclam */
	    {"HTTPProxyPort", OPT_NUM, -1, NULL, 0}, /* freshclam */
	    {"HTTPProxyUsername", OPT_STR, -1, NULL, 0}, /* freshclam */
	    {"HTTPProxyPassword", OPT_STR, -1, NULL, 0}, /* freshclam */
	    {"HTTPUserAgent", OPT_FULLSTR, -1, NULL, 0}, /* freshclam */
	    {"NotifyClamd", OPT_STR, -1, NULL, 0}, /* freshclam */
	    {"OnUpdateExecute", OPT_FULLSTR, -1, NULL, 0}, /* freshclam */
	    {"OnErrorExecute", OPT_FULLSTR, -1, NULL, 0}, /* freshclam */
	    {"OnOutdatedExecute", OPT_FULLSTR, -1, NULL, 0}, /* freshclam */
	    {"LocalIPAddress", OPT_STR, -1, NULL, 0}, /* freshclam */
	    {0, 0, 0, 0, 0}
	};


    for(i = 0; ; i++) {
	pt = &cfg_options[i];
	if(!pt->name)
	    break;

	if(regcfg(&copt, strdup(pt->name), pt->strarg ? strdup(pt->strarg) : NULL, pt->numarg, pt->multiple) < 0) {
	    fprintf(stderr, "ERROR: Can't register new options (not enough memory)\n");
	    freecfg(copt);
	    return NULL;
	}
    }

    if((fs = fopen(cfgfile, "r")) == NULL) {
	/* do not print error message here! */
	freecfg(copt);
	return NULL;
    }

    while(fgets(buff, LINE_LENGTH, fs)) {
	line++;

	if(buff[0] == '#')
	    continue;

	if(!strncmp("Example", buff, 7)) {
	    if(verbose)
		fprintf(stderr, "ERROR: Please edit the example config file %s.\n", cfgfile);
	    fclose(fs);
	    freecfg(copt);
	    return NULL;
	}

	if((name = cli_strtok(buff, 0, " \r\n"))) {
	    arg = cli_strtok(buff, 1, " \r\n");
	    found = 0;
	    for(i = 0; ; i++) {
		pt = &cfg_options[i];
		if(pt->name) {
		    if(!strcmp(name, pt->name)) {
			found = 1;
			switch(pt->argtype) {
			    case OPT_STR:
				if(!arg) {
				    if(verbose)
					fprintf(stderr, "ERROR: Parse error at line %d: Option %s requires string argument.\n", line, name);
				    fclose(fs);
				    freecfg(copt);
				    return NULL;
				}
				if(regcfg(&copt, name, arg, -1, pt->multiple) < 0) {
				    fprintf(stderr, "ERROR: Can't register new options (not enough memory)\n");
				    fclose(fs);
				    freecfg(copt);
				    return NULL;
				}
				break;
			    case OPT_FULLSTR:
				/* an ugly hack of the above case */
				if(!arg) {
				    if(verbose)
					fprintf(stderr, "ERROR: Parse error at line %d: Option %s requires string argument.\n", line, name);
				    fclose(fs);
				    freecfg(copt);
				    return NULL;
				}
				free(arg);
				arg = strstr(buff, " ");
				arg = strdup(++arg);
				if((c = strpbrk(arg, "\n\r")))
				    *c = '\0';
				if(regcfg(&copt, name, arg, -1, pt->multiple) < 0) {
				    fprintf(stderr, "ERROR: Can't register new options (not enough memory)\n");
				    fclose(fs);
				    freecfg(copt);
				    return NULL;
				}
				break;
			    case OPT_NUM:
				if(!arg || !isnumb(arg)) {
				    if(verbose)
					fprintf(stderr, "ERROR: Parse error at line %d: Option %s requires numerical argument.\n", line, name);
				    fclose(fs);
				    freecfg(copt);
				    return NULL;
				}
				if(regcfg(&copt, name, NULL, atoi(arg), pt->multiple) < 0) {
				    fprintf(stderr, "ERROR: Can't register new options (not enough memory)\n");
				    fclose(fs);
				    freecfg(copt);
				    free(arg);
				    return NULL;
				}
				free(arg);
				break;
			    case OPT_COMPSIZE:
				if(!arg) {
				    if(verbose)
					fprintf(stderr, "ERROR: Parse error at line %d: Option %s requires argument.\n", line, name);
				    fclose(fs);
				    freecfg(copt);
				    return NULL;
				}
				ctype = tolower(arg[strlen(arg) - 1]);
				if(ctype == 'm' || ctype == 'k') {
				    char *cpy = (char *) mcalloc(strlen(arg), sizeof(char));
				    strncpy(cpy, arg, strlen(arg) - 1);
				    if(!isnumb(cpy)) {
					if(verbose)
					    fprintf(stderr, "ERROR: Parse error at line %d: Option %s requires numerical (raw/K/M) argument.\n", line, name);
					fclose(fs);
					freecfg(copt);
					return NULL;
				    }
				    if(ctype == 'm')
					calc = atoi(cpy) * 1024 * 1024;
				    else
					calc = atoi(cpy) * 1024;
				    free(cpy);
				} else {
				    if(!isnumb(arg)) {
					if(verbose)
					    fprintf(stderr, "ERROR: Parse error at line %d: Option %s requires numerical (raw/K/M) argument.\n", line, name);
					fclose(fs);
					freecfg(copt);
					return NULL;
				    }
				    calc = atoi(arg);
				}
				free(arg);
				if(regcfg(&copt, name, NULL, calc, pt->multiple) < 0) {
				    fprintf(stderr, "ERROR: Can't register new options (not enough memory)\n");
				    fclose(fs);
				    freecfg(copt);
				    return NULL;
				}
				break;
			    case OPT_BOOL:

				if(!arg) {
				    if(verbose)
					fprintf(stderr, "ERROR: Parse error at line %d: Option %s requires boolean argument.\n", line, name);
				    fclose(fs);
				    freecfg(copt);
				    return NULL;
				}

				if(!strcasecmp(arg, "yes") || !strcmp(arg, "1") || !strcasecmp(arg, "true")) {
				    val = 1;
				} else if(!strcasecmp(arg, "no") || !strcmp(arg, "0") || !strcasecmp(arg, "false")) {
				    val = 0;
				} else {
				    if(verbose)
					fprintf(stderr, "ERROR: Parse error at line %d: Option %s requires boolean argument.\n", line, name);
				    fclose(fs);
				    freecfg(copt);
				    return NULL;
				}
				free(arg);
				if(regcfg(&copt, name, NULL, val, pt->multiple) < 0) {
				    fprintf(stderr, "ERROR: Can't register new options (not enough memory)\n");
				    fclose(fs);
				    freecfg(copt);
				    return NULL;
				}
				break;
			    default:
				if(verbose)
				    fprintf(stderr, "ERROR: Parse error at line %d: Option %s is of unknown type %d\n", line, name, pt->argtype);
				free(name);
				free(arg);
				freecfg(copt);
				return NULL;
			}
		    }
		} else
		    break;
	    }

	    if(!found) {
		if(verbose)
		    fprintf(stderr, "ERROR: Parse error at line %d: Unknown option %s.\n", line, name);
		fclose(fs);
		freecfg(copt);
		return NULL;
	    }
	}
    }

    fclose(fs);
    return copt;
}

void freecfg(struct cfgstruct *copt)
{
    	struct cfgstruct *handler;
    	struct cfgstruct *arg;

    while(copt) {
	arg = copt->nextarg;
	while(arg) {
	    if(arg->strarg) {
		free(arg->optname);
		free(arg->strarg);
		handler = arg;
		arg = arg->nextarg;
		free(handler);
	    } else
		arg = arg->nextarg;
	}
	if(copt->optname)
	    free(copt->optname);

	if(copt->strarg)
	    free(copt->strarg);

	handler = copt;
	copt = copt->next;
	free(handler);
    }
    return;
}

struct cfgstruct *cfgopt(const struct cfgstruct *copt, const char *optname)
{
	struct cfgstruct *handler;

    handler = (struct cfgstruct *) copt;

    while(1) {
	if(handler) {
	    if(handler->optname)
		if(!strcmp(handler->optname, optname))
		    return handler;
	} else break;
	handler = handler->next;
    }

    return NULL;
}

static int regcfg(struct cfgstruct **copt, char *optname, char *strarg, int numarg, short multiple)
{
	struct cfgstruct *newnode, *pt;


    newnode = (struct cfgstruct *) mmalloc(sizeof(struct cfgstruct));

    if(!newnode)
	return -1;

    newnode->optname = optname;
    newnode->nextarg = NULL;
    newnode->next = NULL;
    newnode->enabled = 0;
    newnode->multiple = multiple;

    if(strarg) {
	newnode->strarg = strarg;
	newnode->enabled = 1;
    } else {
	newnode->strarg = NULL;
    }

    newnode->numarg = numarg;
    if(numarg != -1 && numarg != 0)
	newnode->enabled = 1;

    if((pt = cfgopt(*copt, optname))) {
	if(pt->multiple) {

	    if(pt->enabled) {
		while(pt->nextarg)
		    pt = pt->nextarg;

		pt->nextarg = newnode;
	    } else {
		pt->strarg = newnode->strarg;
		pt->numarg = newnode->numarg;
		pt->enabled = newnode->enabled;
		free(newnode);
	    }
	    return 3; /* registered additional argument */

	} else {
	    pt->strarg = newnode->strarg;
	    pt->numarg = newnode->numarg;
	    pt->enabled = newnode->enabled;
	    free(newnode);
	    return 2;
	}

    } else {
	newnode->next = *copt;
	*copt = newnode;
	return 1;
    }
}


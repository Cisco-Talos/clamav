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
#include <ctype.h>

#include "options.h"
#include "cfgfile.h"
#include "others.h"
#include "defaults.h"


struct cfgstruct *parsecfg(const char *cfgfile)
{
	char buff[LINE_LENGTH], *name, *arg;
	FILE *fs;
	int line = 0, i, found, ctype, calc;
	struct cfgstruct *copt = NULL;
	struct cfgoption *pt;

	struct cfgoption cfg_options[] = {
	    {"LogFile", OPT_STR},
	    {"LogFileUnlock", OPT_NOARG},
	    {"LogFileMaxSize", OPT_COMPSIZE},
	    {"LogTime", OPT_NOARG},
	    {"LogVerbose", OPT_NOARG},
	    {"LogSyslog", OPT_NOARG},
	    {"PidFile", OPT_STR},
	    {"MaxFileSize", OPT_COMPSIZE},
	    {"ScanMail", OPT_NOARG},
	    {"ScanArchive", OPT_NOARG},
	    {"ScanRAR", OPT_NOARG},
	    {"ArchiveMaxFileSize", OPT_COMPSIZE},
	    {"ArchiveMaxRecursion", OPT_NUM},
	    {"ArchiveMaxFiles", OPT_NUM},
	    {"ArchiveLimitMemoryUsage", OPT_NOARG},
	    {"DataDirectory", OPT_STR},
	    {"TCPAddr", OPT_STR},
	    {"TCPSocket", OPT_NUM},
	    {"LocalSocket", OPT_STR},
	    {"MaxConnectionQueueLength", OPT_NUM},
	    {"StreamSaveToDisk", OPT_NOARG},
	    {"StreamMaxLength", OPT_COMPSIZE},
	    {"UseProcesses", OPT_NOARG},
	    {"MaxThreads", OPT_NUM},
	    {"ThreadTimeout", OPT_NUM},
	    {"MaxDirectoryRecursion", OPT_NUM},
	    {"FollowDirectorySymlinks", OPT_NOARG},
	    {"FollowFileSymlinks", OPT_NOARG},
	    {"Foreground", OPT_NOARG},
	    {"Debug", OPT_NOARG},
	    {"FixStaleSocket", OPT_NOARG},
	    {"User", OPT_STR},
	    {"AllowSupplementaryGroups", OPT_NOARG},
	    {"SelfCheck", OPT_NUM},
	    {"VirusEvent", OPT_FULLSTR},
	    {"ClamukoScanOnLine", OPT_NOARG},
	    {"ClamukoScanOnOpen", OPT_NOARG},
	    {"ClamukoScanOnClose", OPT_NOARG},
	    {"ClamukoScanOnExec", OPT_NOARG},
	    {"ClamukoIncludePath", OPT_STR},
	    {"ClamukoExcludePath", OPT_STR},
	    {"ClamukoMaxFileSize", OPT_COMPSIZE},
	    {"ClamukoScanArchive", OPT_NOARG},
	    {0, 0}
	};


    if((fs = fopen(cfgfile, "r")) == NULL) {
	fprintf(stderr, "ERROR: Can't open config file %s !\n", cfgfile);
	return NULL;
    }


    while(fgets(buff, LINE_LENGTH, fs)) {

	line++;

	if(buff[0] == '#')
	    continue;

	if(!strncmp("Example", buff, 7)) {
	    fprintf(stderr, "ERROR: Please edit the example config file %s.\n", cfgfile);
	    return NULL;
	}


	if((name = tok(buff, 1))) {
	    arg = tok(buff, 2);
	    found = 0;
	    for(i = 0; ; i++) {
		pt = &cfg_options[i];
		if(pt->name) {
		    if(!strcmp(name, pt->name)) {
			found = 1;
			switch(pt->argtype) {
			    case OPT_STR:
				if(!arg) {
				    fprintf(stderr, "ERROR: Parse error at line %d: Option %s requires string as argument.\n", line, name);
				    return NULL;
				}
				copt = regcfg(copt, name, arg, 0);
				break;
			    case OPT_FULLSTR:
				if(!arg) {
				    fprintf(stderr, "ERROR: Parse error at line %d: Option %s requires string as argument.\n", line, name);
				    return NULL;
				}
				// FIXME: this one is an ugly hack of the above
				// case
				free(arg);
				arg = strstr(buff, " ");
				arg = strdup(++arg);
				copt = regcfg(copt, name, arg, 0);
				break;
			    case OPT_NUM:
				if(!isnumb(arg)) {
				    fprintf(stderr, "ERROR: Parse error at line %d: Option %s requires numerical argument.\n", line, name);
				    return NULL;
				}
				copt = regcfg(copt, name, NULL, atoi(arg));
				break;
			    case OPT_COMPSIZE:
				if(!arg) {
				    fprintf(stderr, "ERROR: Parse error at line %d: Option %s requires argument.\n", line, name);
				    return NULL;
				}
				ctype = tolower(arg[strlen(arg) - 1]);
				if(ctype == 'm' || ctype == 'k') {
				    char *cpy = mcalloc(strlen(arg), sizeof(char));
				    strncpy(cpy, arg, strlen(arg) - 1);
				    if(!isnumb(cpy)) {
					fprintf(stderr, "ERROR: Parse error at line %d: Option %s requires numerical (raw/K/M) argument.\n", line, name);
					return NULL;
				    }
				    if(ctype == 'm')
					calc = atoi(cpy) * 1024 * 1024;
				    else
					calc = atoi(cpy) * 1024;
				    free(cpy);
				} else {
				    if(!isnumb(arg)) {
					fprintf(stderr, "ERROR: Parse error at line %d: Option %s requires numerical (raw/K/M) argument.\n", line, name);
					return NULL;
				    }
				    calc = atoi(arg);
				}
				copt = regcfg(copt, name, NULL, calc);
				break;
			    case OPT_NOARG:
				if(arg) {
				    fprintf(stderr, "ERROR: Parse error at line %d: Option %s doesn't support arguments.\n", line, name);
				    return NULL;
				}
				copt = regcfg(copt, name, NULL, 0);
				break;
			    case OPT_OPTARG:
				copt = regcfg(copt, name, arg, 0);
				break;
			}
		    }
		} else
		    break;
	    } 

	    if(!found) {
		fprintf(stderr, "ERROR: Parse error at line %d: Unknown option %s.\n", line, name);
		return NULL;
	    }
	}
    }

    fclose(fs);
    return copt;
}

char *tok(const char *line, int field)
{
        int length, counter = 0, i, j = 0, k;
        char *buffer;


    length = strlen(line);
    buffer = (char *) mcalloc(length, sizeof(char));

    for(i = 0; i < length; i++) {
        if(line[i] == ' ' || line[i] == '\n') {
            counter++;
            if(counter == field)
		break;

            for(k = 0; k < length; k++)
		buffer[k] = 0;

            j = 0;
	    while((line[i+1] == ' ' || line[i+1] == '\n') && i < length)
		i++;
        } else {
	    if(line[i] != ' ') {
		buffer[j]=line[i];
		j++;
	    }
	}
    }

    chomp(buffer); /* preventive */

    if(strlen(buffer) == 0) {
	free(buffer);
	return NULL;
    } else
	return realloc(buffer, strlen(buffer) + 1);
}

struct cfgstruct *regcfg(struct cfgstruct *copt, const char *optname, const char *strarg, int numarg)
{
	struct cfgstruct *newnode, *pt;

    newnode = (struct cfgstruct *) mmalloc(sizeof(struct cfgstruct));
    newnode->optname = optname;
    newnode->nextarg = NULL;
    newnode->next = NULL;

    if(strarg)
	newnode->strarg = strarg;
    else {
	newnode->strarg = NULL;
	newnode->numarg = numarg;
    }

    if((pt = cfgopt(copt, optname))) {
	while(pt->nextarg)
	    pt = pt->nextarg;

	pt->nextarg = newnode;
	return copt;
    } else {
	newnode->next = copt;
	return newnode;
    }
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

/*
 *  Copyright (C) 2002 - 2004 Tomasz Kojm <tkojm@clamav.net>
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

static int isnumb(const char *str)
{
	int i;

    for(i = 0; i < strlen(str); i++)
	if(!isdigit(str[i]))
	    return 0;

    return 1;
}

struct cfgstruct *parsecfg(const char *cfgfile, int messages)
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
	    {"LogClean", OPT_NOARG},
	    {"LogVerbose", OPT_NOARG}, /* clamd + freshclam */
	    {"LogSyslog", OPT_NOARG},
	    {"LogFacility", OPT_STR},
	    {"PidFile", OPT_STR},
	    {"TemporaryDirectory", OPT_STR},
	    {"DisableDefaultScanOptions", OPT_NOARG},
	    {"ScanPE", OPT_NOARG},
	    {"DetectBrokenExecutables", OPT_NOARG},
	    {"ScanMail", OPT_NOARG},
	    {"MailFollowURLs", OPT_NOARG},
	    {"ScanHTML", OPT_NOARG},
	    {"ScanOLE2", OPT_NOARG},
	    {"ScanArchive", OPT_NOARG},
	    {"ScanRAR", OPT_NOARG},
	    {"ArchiveMaxFileSize", OPT_COMPSIZE},
	    {"ArchiveMaxRecursion", OPT_NUM},
	    {"ArchiveMaxFiles", OPT_NUM},
	    {"ArchiveMaxCompressionRatio", OPT_NUM},
	    {"ArchiveLimitMemoryUsage", OPT_NOARG},
	    {"ArchiveBlockEncrypted", OPT_NOARG},
	    {"ArchiveBlockMax", OPT_NOARG},
	    {"DataDirectory", OPT_STR}, /* obsolete */
	    {"DatabaseDirectory", OPT_STR}, /* clamd + freshclam */
	    {"TCPAddr", OPT_STR},
	    {"TCPSocket", OPT_NUM},
	    {"LocalSocket", OPT_STR},
	    {"MaxConnectionQueueLength", OPT_NUM},
	    {"StreamMaxLength", OPT_COMPSIZE},
	    {"MaxThreads", OPT_NUM},
	    {"ReadTimeout", OPT_NUM},
	    {"IdleTimeout", OPT_NUM},
	    {"MaxDirectoryRecursion", OPT_NUM},
	    {"FollowDirectorySymlinks", OPT_NOARG},
	    {"FollowFileSymlinks", OPT_NOARG},
	    {"Foreground", OPT_NOARG},
	    {"Debug", OPT_NOARG},
	    {"LeaveTemporaryFiles", OPT_NOARG},
	    {"FixStaleSocket", OPT_NOARG},
	    {"User", OPT_STR},
	    {"AllowSupplementaryGroups", OPT_NOARG},
	    {"SelfCheck", OPT_NUM},
	    {"VirusEvent", OPT_FULLSTR},
	    {"ClamukoScanOnLine", OPT_NOARG}, /* old name */
	    {"ClamukoScanOnAccess", OPT_NOARG},
	    {"ClamukoScanOnOpen", OPT_NOARG},
	    {"ClamukoScanOnClose", OPT_NOARG},
	    {"ClamukoScanOnExec", OPT_NOARG},
	    {"ClamukoIncludePath", OPT_STR},
	    {"ClamukoExcludePath", OPT_STR},
	    {"ClamukoMaxFileSize", OPT_COMPSIZE},
	    {"ClamukoScanArchive", OPT_NOARG},
	    {"DatabaseOwner", OPT_STR}, /* freshclam */
	    {"Checks", OPT_NUM}, /* freshclam */
	    {"UpdateLogFile", OPT_STR}, /* freshclam */
	    {"DNSDatabaseInfo", OPT_STR}, /* freshclam */
	    {"DatabaseMirror", OPT_STR}, /* freshclam */
	    {"MaxAttempts", OPT_NUM}, /* freshclam */
	    {"HTTPProxyServer", OPT_STR}, /* freshclam */
	    {"HTTPProxyPort", OPT_NUM}, /* freshclam */
	    {"HTTPProxyUsername", OPT_STR}, /* freshclam */
	    {"HTTPProxyPassword", OPT_STR}, /* freshclam */
	    {"NotifyClamd", OPT_OPTARG}, /* freshclam */
	    {"OnUpdateExecute", OPT_FULLSTR}, /* freshclam */
	    {"OnErrorExecute", OPT_FULLSTR}, /* freshclam */
	    {0, 0}
	};


    if((fs = fopen(cfgfile, "r")) == NULL)
	return NULL;

    while(fgets(buff, LINE_LENGTH, fs)) {

	line++;

	if(buff[0] == '#')
	    continue;

	if(!strncmp("Example", buff, 7)) {
	    if(messages)
		fprintf(stderr, "ERROR: Please edit the example config file %s.\n", cfgfile);
	    fclose(fs);
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
				    if(messages)
					fprintf(stderr, "ERROR: Parse error at line %d: Option %s requires string as argument.\n", line, name);
				    fclose(fs);
				    return NULL;
				}
				copt = regcfg(copt, name, arg, 0);
				break;
			    case OPT_FULLSTR:
				if(!arg) {
				    if(messages)
					fprintf(stderr, "ERROR: Parse error at line %d: Option %s requires string as argument.\n", line, name);
				    fclose(fs);
				    return NULL;
				}
				/* FIXME: this one is an ugly hack of the above case */
				free(arg);
				arg = strstr(buff, " ");
				arg = strdup(++arg);
				copt = regcfg(copt, name, arg, 0);
				break;
			    case OPT_NUM:
				if(!arg || !isnumb(arg)) {
				    if(messages)
					fprintf(stderr, "ERROR: Parse error at line %d: Option %s requires numerical argument.\n", line, name);
				    fclose(fs);
				    return NULL;
				}
				copt = regcfg(copt, name, NULL, atoi(arg));
				free(arg);
				break;
			    case OPT_COMPSIZE:
				if(!arg) {
				    if(messages)
					fprintf(stderr, "ERROR: Parse error at line %d: Option %s requires argument.\n", line, name);
				    fclose(fs);
				    return NULL;
				}
				ctype = tolower(arg[strlen(arg) - 1]);
				if(ctype == 'm' || ctype == 'k') {
				    char *cpy = (char *) mcalloc(strlen(arg), sizeof(char));
				    strncpy(cpy, arg, strlen(arg) - 1);
				    if(!isnumb(cpy)) {
					if(messages)
					    fprintf(stderr, "ERROR: Parse error at line %d: Option %s requires numerical (raw/K/M) argument.\n", line, name);
					fclose(fs);
					return NULL;
				    }
				    if(ctype == 'm')
					calc = atoi(cpy) * 1024 * 1024;
				    else
					calc = atoi(cpy) * 1024;
				    free(cpy);
				} else {
				    if(!isnumb(arg)) {
					if(messages)
					    fprintf(stderr, "ERROR: Parse error at line %d: Option %s requires numerical (raw/K/M) argument.\n", line, name);
					fclose(fs);
					return NULL;
				    }
				    calc = atoi(arg);
				}
				copt = regcfg(copt, name, NULL, calc);
				free(arg);
				break;
			    case OPT_NOARG:
				if(arg) {
				    if(messages)
					fprintf(stderr, "ERROR: Parse error at line %d: Option %s doesn't support arguments (got '%s').\n", line, name, arg);
				    fclose(fs);
				    return NULL;
				}
				copt = regcfg(copt, name, NULL, 0);
				break;
			    case OPT_OPTARG:
				copt = regcfg(copt, name, arg, 0);
				break;
			    default:
				if(messages)
				    fprintf(stderr, "ERROR: Parse error at line %d: Option %s is of unknown type %d\n", line, name, pt->argtype);
				free(name);
				free(arg);
				break;
			}
		    }
		} else
		    break;
	    } 

	    if(!found) {
		if(messages)
		    fprintf(stderr, "ERROR: Parse error at line %d: Unknown option %s.\n", line, name);
		fclose(fs);
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

    while (copt) {
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
	if(copt->optname) {
	    free(copt->optname);
	}
	if(copt->strarg) {
	    free(copt->strarg);
	}
	handler = copt;
	copt = copt->next;
	free(handler);
    }
    return;
}

struct cfgstruct *regcfg(struct cfgstruct *copt, char *optname, char *strarg, int numarg)
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

/*
 *  Copyright (C) 2002 - 2007 Tomasz Kojm <tkojm@clamav.net>
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
#include <ctype.h>

#include "shared/cfgparser.h"
#include "shared/misc.h"

#include "libclamav/str.h"

struct cfgoption cfg_options[] = {
    {"LogFile",	OPT_QUOTESTR, -1, NULL, 0, OPT_CLAMD},
    {"LogFileUnlock", OPT_BOOL, 0, NULL, 0, OPT_CLAMD},
    {"LogFileMaxSize", OPT_COMPSIZE, 1048576, NULL, 0, OPT_CLAMD | OPT_FRESHCLAM},
    {"LogTime", OPT_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_FRESHCLAM},
    {"LogClean", OPT_BOOL, 0, NULL, 0, OPT_CLAMD},
    {"LogVerbose", OPT_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_FRESHCLAM},
    {"LogSyslog", OPT_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_FRESHCLAM},
    {"LogFacility", OPT_QUOTESTR, -1, "LOG_LOCAL6", 0, OPT_CLAMD | OPT_FRESHCLAM},
    {"PidFile", OPT_QUOTESTR, -1, NULL, 0, OPT_CLAMD | OPT_FRESHCLAM},
    {"TemporaryDirectory", OPT_QUOTESTR, -1, NULL, 0, OPT_CLAMD},
    {"ScanPE", OPT_BOOL, 1, NULL, 0, OPT_CLAMD},
    {"ScanELF", OPT_BOOL, 1, NULL, 0, OPT_CLAMD},
    {"DetectBrokenExecutables", OPT_BOOL, 0, NULL, 0, OPT_CLAMD},
    {"ScanMail", OPT_BOOL, 1, NULL, 0, OPT_CLAMD},
    {"MailFollowURLs", OPT_BOOL, 0, NULL, 0, OPT_CLAMD},
    {"ScanPartialMessages", OPT_BOOL, 0, NULL, 0, OPT_CLAMD},
    {"PhishingSignatures", OPT_BOOL, 1, NULL, 0, OPT_CLAMD},
    {"PhishingScanURLs",OPT_BOOL, 1, NULL, 0, OPT_CLAMD},
    /* these are FP prone options, if default isn't used */
    {"PhishingAlwaysBlockCloak", OPT_BOOL, 0, NULL, 0, OPT_CLAMD},
    {"PhishingAlwaysBlockSSLMismatch", OPT_BOOL, 0, NULL, 0, OPT_CLAMD},
    {"HeuristicScanPrecedence", OPT_BOOL, 0, NULL, 0, OPT_CLAMD},
    /* end of FP prone options */
    {"DetectPUA", OPT_BOOL, 0, NULL, 0, OPT_CLAMD},
    {"ExcludePUA", OPT_QUOTESTR, -1, NULL, 1, OPT_CLAMD},
    {"IncludePUA", OPT_QUOTESTR, -1, NULL, 1, OPT_CLAMD},
    {"StructuredDataDetection", OPT_BOOL, 0, NULL, 0, OPT_CLAMD},
    {"StructuredMinCreditCardCount", OPT_NUM, 3, NULL, 0, OPT_CLAMD},
    {"StructuredMinSSNCount", OPT_NUM, 3, NULL, 0, OPT_CLAMD},
    {"StructuredSSNFormatNormal", OPT_BOOL, 1, NULL, 0, OPT_CLAMD},
    {"StructuredSSNFormatStripped", OPT_BOOL, 0, NULL, 0, OPT_CLAMD},
    {"AlgorithmicDetection", OPT_BOOL, 1, NULL, 0, OPT_CLAMD},
    {"ScanHTML", OPT_BOOL, 1, NULL, 0, OPT_CLAMD},
    {"ScanOLE2", OPT_BOOL, 1, NULL, 0, OPT_CLAMD},
    {"ScanPDF", OPT_BOOL, 0, NULL, 0, OPT_CLAMD},
    {"ScanArchive", OPT_BOOL, 1, NULL, 0, OPT_CLAMD},
    {"MaxScanSize", OPT_COMPSIZE, 104857600, NULL, 0, OPT_CLAMD},
    {"MaxFileSize", OPT_COMPSIZE, 26214400, NULL, 0, OPT_CLAMD},
    {"MaxRecursion", OPT_NUM, 16, NULL, 0, OPT_CLAMD},
    {"MaxFiles", OPT_NUM, 10000, NULL, 0, OPT_CLAMD},
    {"ArchiveLimitMemoryUsage", OPT_BOOL, 0, NULL, 0, OPT_CLAMD},
    {"ArchiveBlockEncrypted", OPT_BOOL, 0, NULL, 0, OPT_CLAMD},
    {"DatabaseDirectory", OPT_QUOTESTR, -1, DATADIR, 0, OPT_CLAMD | OPT_FRESHCLAM},
    {"TCPAddr", OPT_QUOTESTR, -1, NULL, 0, OPT_CLAMD},
    {"TCPSocket", OPT_NUM, -1, NULL, 0, OPT_CLAMD},
    {"LocalSocket", OPT_QUOTESTR, -1, NULL, 0, OPT_CLAMD},
    {"MaxConnectionQueueLength", OPT_NUM, 15, NULL, 0, OPT_CLAMD},
    {"StreamMaxLength", OPT_COMPSIZE, 10485760, NULL, 0, OPT_CLAMD},
    {"StreamMinPort", OPT_NUM, 1024, NULL, 0, OPT_CLAMD},
    {"StreamMaxPort", OPT_NUM, 2048, NULL, 0, OPT_CLAMD},
    {"MaxThreads", OPT_NUM, 10, NULL, 0, OPT_CLAMD},
    {"ReadTimeout", OPT_NUM, 120, NULL, 0, OPT_CLAMD},
    {"IdleTimeout", OPT_NUM, 30, NULL, 0, OPT_CLAMD},
    {"MaxDirectoryRecursion", OPT_NUM, 15, NULL, 0, OPT_CLAMD},
    {"ExcludePath", OPT_QUOTESTR, -1, NULL, 1, OPT_CLAMD},
    {"FollowDirectorySymlinks", OPT_BOOL, 0, NULL, 0, OPT_CLAMD},
    {"FollowFileSymlinks", OPT_BOOL, 0, NULL, 0, OPT_CLAMD},
    {"ExitOnOOM", OPT_BOOL, 0, NULL, 0, OPT_CLAMD},
    {"Foreground", OPT_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_FRESHCLAM},
    {"Debug", OPT_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_FRESHCLAM},
    {"LeaveTemporaryFiles", OPT_BOOL, 0, NULL, 0, OPT_CLAMD},
    {"FixStaleSocket", OPT_BOOL, 1, NULL, 0, OPT_CLAMD},
    {"User", OPT_QUOTESTR, -1, NULL, 0, OPT_CLAMD},
    {"AllowSupplementaryGroups", OPT_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_FRESHCLAM},
    {"SelfCheck", OPT_NUM, 1800, NULL, 0, OPT_CLAMD},
    {"VirusEvent", OPT_FULLSTR, -1, NULL, 0, OPT_CLAMD},
    {"ClamukoScanOnAccess", OPT_BOOL, -1, NULL, 0, OPT_CLAMD},
    {"ClamukoScanOnOpen", OPT_BOOL, -1, NULL, 0, OPT_CLAMD},
    {"ClamukoScanOnClose", OPT_BOOL, -1, NULL, 0, OPT_CLAMD},
    {"ClamukoScanOnExec", OPT_BOOL, -1, NULL, 0, OPT_CLAMD},
    {"ClamukoIncludePath", OPT_QUOTESTR, -1, NULL, 1, OPT_CLAMD},
    {"ClamukoExcludePath", OPT_QUOTESTR, -1, NULL, 1, OPT_CLAMD},
    {"ClamukoMaxFileSize", OPT_COMPSIZE, 5242880, NULL, 0, OPT_CLAMD},
    {"DatabaseOwner", OPT_QUOTESTR, -1, CLAMAVUSER, 0, OPT_FRESHCLAM},
    {"Checks", OPT_NUM, 12, NULL, 0, OPT_FRESHCLAM},
    {"UpdateLogFile", OPT_QUOTESTR, -1, NULL, 0, OPT_FRESHCLAM},
    {"DNSDatabaseInfo", OPT_QUOTESTR, -1, "current.cvd.clamav.net", 0, OPT_FRESHCLAM},
    {"DatabaseMirror", OPT_QUOTESTR, -1, NULL, 1, OPT_FRESHCLAM},
    {"MaxAttempts", OPT_NUM, 3, NULL, 0, OPT_FRESHCLAM},
    {"ScriptedUpdates", OPT_BOOL, 1, NULL, 0, OPT_FRESHCLAM},
    {"CompressLocalDatabase", OPT_BOOL, 0, NULL, 0, OPT_FRESHCLAM},
    {"HTTPProxyServer", OPT_QUOTESTR, -1, NULL, 0, OPT_FRESHCLAM},
    {"HTTPProxyPort", OPT_NUM, -1, NULL, 0, OPT_FRESHCLAM},
    {"HTTPProxyUsername", OPT_QUOTESTR, -1, NULL, 0, OPT_FRESHCLAM},
    {"HTTPProxyPassword", OPT_QUOTESTR, -1, NULL, 0, OPT_FRESHCLAM},
    {"HTTPUserAgent", OPT_FULLSTR, -1, NULL, 0, OPT_FRESHCLAM},
    {"NotifyClamd", OPT_QUOTESTR, -1, NULL, 0, OPT_FRESHCLAM},
    {"OnUpdateExecute", OPT_FULLSTR, -1, NULL, 0, OPT_FRESHCLAM},
    {"OnErrorExecute", OPT_FULLSTR, -1, NULL, 0, OPT_FRESHCLAM},
    {"OnOutdatedExecute", OPT_FULLSTR, -1, NULL, 0, OPT_FRESHCLAM},
    {"LocalIPAddress", OPT_QUOTESTR, -1, NULL, 0, OPT_FRESHCLAM},
    {"ConnectTimeout", OPT_NUM, 30, NULL, 0, OPT_FRESHCLAM},
    {"ReceiveTimeout", OPT_NUM, 30, NULL, 0, OPT_FRESHCLAM},

    {"DevACOnly", OPT_BOOL, -1, NULL, 0, OPT_CLAMD},
    {"DevACDepth", OPT_NUM, -1, NULL, 0, OPT_CLAMD},

    {NULL, 0, 0, NULL, 0, 0}
};

static int regcfg(struct cfgstruct **copt, const char *optname, char *strarg, int numarg, short multiple);

struct cfgstruct *getcfg(const char *cfgfile, int verbose)
{
	char buff[LINE_LENGTH], *name, *arg, *c;
	FILE *fs;
	int line = 0, i, found, ctype, calc, val;
	struct cfgstruct *copt = NULL;
	struct cfgoption *pt;


    for(i = 0; ; i++) {
	pt = &cfg_options[i];
	if(!pt->name)
	    break;

	if(regcfg(&copt, pt->name, pt->strarg ? strdup(pt->strarg) : NULL, pt->numarg, pt->multiple) < 0) {
	    fprintf(stderr, "ERROR: Can't register new options (not enough memory)\n");
	    freecfg(copt);
	    return NULL;
	}
    }

    if((fs = fopen(cfgfile, "rb")) == NULL) {
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
			    	/* deprecated.  Use OPT_QUOTESTR instead since it behaves like this, but supports quotes to allow values to contain whitespace */
				if(!arg) {
				    if(verbose)
					fprintf(stderr, "ERROR: Parse error at line %d: Option %s requires string argument.\n", line, name);
				    fclose(fs);
				    free(name);
				    freecfg(copt);
				    return NULL;
				}
				if(regcfg(&copt, name, arg, -1, pt->multiple) < 0) {
				    fprintf(stderr, "ERROR: Can't register new options (not enough memory)\n");
				    fclose(fs);
				    free(name);
				    free(arg);
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
				    free(name);
				    freecfg(copt);
				    return NULL;
				}
				free(arg);
				arg = strstr(buff, " ");
				arg = strdup(++arg);
				if((arg) && (c = strpbrk(arg, "\n\r")))
				    *c = '\0';
				if((!arg) || (regcfg(&copt, name, arg, -1, pt->multiple) < 0)) {
				    fprintf(stderr, "ERROR: Can't register new options (not enough memory)\n");
				    fclose(fs);
				    free(name);
				    free(arg);
				    freecfg(copt);
				    return NULL;
				}
				break;
			    case OPT_QUOTESTR:
				/* an ugly hack of the above case */
				if(!arg) {
				    if(verbose)
					fprintf(stderr, "ERROR: Parse error at line %d: Option %s requires string argument.\n", line, name);
				    fclose(fs);
				    free(name);
				    freecfg(copt);
				    return NULL;
				}
				if((*arg == '\'') || (*arg == '"')) {
				    free(arg);
				    c = strstr(buff, " ");
				    arg = strdup(c+2);
				    if(arg) {
					if((c = strchr(arg, c[1])))
					    *c = '\0';
					else {
					    if(verbose)
						fprintf(stderr, "ERROR: Parse error at line %d: Option %s missing closing quote.\n", line, name);
					    fclose(fs);
					    free(name);
					    free(arg);
					    freecfg(copt);
					    return NULL;
					}
				    }
				}
				if((!arg) || (regcfg(&copt, name, arg, -1, pt->multiple) < 0)) {
				    fprintf(stderr, "ERROR: Can't register new options (not enough memory)\n");
				    fclose(fs);
				    free(name);
				    free(arg);
				    freecfg(copt);
				    return NULL;
				}
				break;
			    case OPT_NUM:
				if(!arg || !cli_isnumber(arg)) {
				    if(verbose)
					fprintf(stderr, "ERROR: Parse error at line %d: Option %s requires numerical argument.\n", line, name);
				    fclose(fs);
				    free(name);
				    free(arg);
				    freecfg(copt);
				    return NULL;
				}
				if(regcfg(&copt, name, NULL, atoi(arg), pt->multiple) < 0) {
				    fprintf(stderr, "ERROR: Can't register new options (not enough memory)\n");
				    fclose(fs);
				    free(name);
				    free(arg);
				    freecfg(copt);
				    return NULL;
				}
				free(arg);
				break;
			    case OPT_COMPSIZE:
				if(!arg) {
				    if(verbose)
					fprintf(stderr, "ERROR: Parse error at line %d: Option %s requires argument.\n", line, name);
				    fclose(fs);
				    free(name);
				    freecfg(copt);
				    return NULL;
				}
				ctype = tolower(arg[strlen(arg) - 1]);
				if(ctype == 'm' || ctype == 'k') {
				    char *cpy = strdup(arg);
				    if(!cpy) {
					fprintf(stderr, "ERROR: Can't register new options (not enough memory)\n");
					fclose(fs);
					free(name);
					freecfg(copt);
					return NULL;
				    }
				    cpy[strlen(arg) - 1] = '\0';
				    if(!cli_isnumber(cpy)) {
					if(verbose)
					    fprintf(stderr, "ERROR: Parse error at line %d: Option %s requires numerical (raw/K/M) argument.\n", line, name);
					fclose(fs);
					free(name);
					free(arg);
					freecfg(copt);
					return NULL;
				    }
				    if(ctype == 'm')
					calc = atoi(cpy) * 1024 * 1024;
				    else
					calc = atoi(cpy) * 1024;
				    free(cpy);
				} else {
				    if(!cli_isnumber(arg)) {
					if(verbose)
					    fprintf(stderr, "ERROR: Parse error at line %d: Option %s requires numerical (raw/K/M) argument.\n", line, name);
					fclose(fs);
					free(name);
					free(arg);
					freecfg(copt);
					return NULL;
				    }
				    calc = atoi(arg);
				}
				free(arg);
				if(regcfg(&copt, name, NULL, calc, pt->multiple) < 0) {
				    fprintf(stderr, "ERROR: Can't register new options (not enough memory)\n");
				    fclose(fs);
				    free(name);
				    free(arg);
				    freecfg(copt);
				    return NULL;
				}
				break;
			    case OPT_BOOL:

				if(!arg) {
				    if(verbose)
					fprintf(stderr, "ERROR: Parse error at line %d: Option %s requires boolean argument.\n", line, name);
				    fclose(fs);
				    free(name);
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
				    free(name);
				    free(arg);
				    freecfg(copt);
				    return NULL;
				}
				free(arg);
				if(regcfg(&copt, name, NULL, val, pt->multiple) < 0) {
				    fprintf(stderr, "ERROR: Can't register new options (not enough memory)\n");
				    fclose(fs);
				    free(name);
				    free(arg);
				    freecfg(copt);
				    return NULL;
				}
				break;
			    default:
				if(verbose)
				    fprintf(stderr, "ERROR: Parse error at line %d: Option %s is of unknown type %d\n", line, name, pt->argtype);
				fclose(fs);
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
		free(name);
		fclose(fs);
		freecfg(copt);
		return NULL;
	    }
	    free(name);
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

const struct cfgstruct *cfgopt(const struct cfgstruct *copt, const char *optname)
{
    while(copt) {
	if(copt->optname && !strcmp(copt->optname, optname))
	    return copt;

	copt = copt->next;
    }

    return NULL;
}

static struct cfgstruct *cfgopt_i(struct cfgstruct *copt, const char *optname)
{
    while(copt) {
	if(copt->optname && !strcmp(copt->optname, optname))
	    return copt;

	copt = copt->next;
    }

    return NULL;
}

static int regcfg(struct cfgstruct **copt, const char *optname, char *strarg, int numarg, short multiple)
{
	struct cfgstruct *newnode, *pt;


    newnode = (struct cfgstruct *) malloc(sizeof(struct cfgstruct));

    if(!newnode)
	return -1;

    newnode->optname = optname ? strdup(optname) : NULL;
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

    if((pt = cfgopt_i(*copt, optname))) {
	if(pt->multiple) {

	    if(pt->enabled) {
		while(pt->nextarg)
		    pt = pt->nextarg;

		pt->nextarg = newnode;
	    } else {
		if(pt->strarg)
		    free(pt->strarg);
		pt->strarg = newnode->strarg;
		pt->numarg = newnode->numarg;
		pt->enabled = newnode->enabled;
		if(newnode->optname)
		    free(newnode->optname);
		free(newnode);
	    }
	    return 3; /* registered additional argument */

	} else {
	    if(pt->strarg)
		free(pt->strarg);
	    pt->strarg = newnode->strarg;
	    pt->numarg = newnode->numarg;
	    pt->enabled = newnode->enabled;
	    if(newnode->optname)
		free(newnode->optname);
	    free(newnode);
	    return 2;
	}

    } else {
	newnode->next = *copt;
	*copt = newnode;
	return 1;
    }
}


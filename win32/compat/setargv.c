/*
 *  Copyright (C) 2009 Sourcefire, Inc.
 *
 *  Authors: aCaB <acab@clamav.net>
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

#include "dirent.h"
#include "libgen.h"

/* THIS IS A HACK ! */
/* _setargv is the designed way to customize command line parsing which we use here
   for globbing reasons (incidentally the globbing in setargv.obj is badly broken)
   
   The crt first calls OUR _setargv from pre_c_init but later, from within pre_cpp_init,
   it also calls ITS OWN BUILTIN NATIVE CRAP, which re-parses the command line and 
   eventually overrides our override.

   So, we additionally replace the command line global pointer _acmdln with a
   crafted set of arguments in order to fool buggy CRT's.
*/
#define _MY_CRT_INSISTS_ON_PARSING_THE_COMMAND_LINE_TWICE_FOR_NO_REASONS_
#ifdef _MY_CRT_INSISTS_ON_PARSING_THE_COMMAND_LINE_TWICE_FOR_NO_REASONS_
extern char ** __p__acmdln(void);
#endif

int glob_add(const char *path, int *argc, char ***argv);

int _setargv() {
    char *cur = GetCommandLineA(), *begparm = NULL, *endparm = NULL;
    char **argv = NULL, c;
    int argc = 0, i, in_sq = 0, in_dq = 0, need_glob = 0, allarglen = 0;
    int *g_argc = __p___argc();
    char ***g_argv = __p___argv();

    do {
	c = *cur;
	switch(c) {
	    case '\0':
		endparm = cur;
		break;
	    case ' ':
		if(begparm && !(in_sq | in_dq))
		    endparm = cur;
		break;
	    case '\'':
		if(!in_dq) {
		    in_sq = !in_sq;
		    if(!in_sq)
			endparm = cur;
		}
		break;
	    case '"':
		if(!in_sq) {
		    in_dq = !in_dq;
		    if(!in_dq)
			endparm = cur;
		}
		break;
	    case '*':
	    case '?':
		if(!in_sq)
		    need_glob = 1;
	    default:
		if(!begparm) {
		    begparm = cur;
		    endparm = NULL;
		}
	}
	if (begparm && endparm) {
	    if(begparm < endparm) {
		char *path = malloc(endparm - begparm + 1);
		int arglen = 0;

		memcpy(path, begparm, endparm - begparm);
		path[endparm - begparm] = '\0';
		if(argc && need_glob) {
		    arglen = glob_add(path, &argc, &argv);
		    if(!arglen) {
			path = malloc(endparm - begparm + 1);
			memcpy(path, begparm, endparm - begparm);
			path[endparm - begparm] = '\0';
		    }
		}
		if(!arglen) {
		    argv = realloc(argv, sizeof(*argv) * (argc + 1));
		    argv[argc] = path;
		    argc++;
		    arglen = endparm - begparm;
		}
		allarglen += arglen;
	    }
	    need_glob = 0;
	    in_sq = 0;
	    in_dq = 0;
	    begparm = NULL;
	    endparm = NULL;
	}
	cur++;
    } while (c);

    if(argc) {
	int i, argvlen = sizeof(*argv) * (argc + 1), argclen = 0;
	argv = realloc(argv, argvlen + allarglen + argc);
	argv[argc] = NULL;
	for(i=0; i<argc; i++) {
	    int curlen = strlen(argv[i]) + 1;
	    char *curarg = (char *)argv + argvlen + argclen;
	    memcpy(curarg, argv[i], curlen);
	    argclen += curlen;
	    free(argv[i]);
	    argv[i] = curarg;
	}
#ifdef _MY_CRT_INSISTS_ON_PARSING_THE_COMMAND_LINE_TWICE_FOR_NO_REASONS_
        {
	    char *fake_cmdl = malloc(argclen + 1 + 2*argc);
	    char *curarg = fake_cmdl;
	    char **g_cmdl = __p__acmdln();
	    for(i=0; i<argc; i++)
		curarg += sprintf(curarg, "\"%s\" ", argv[i]);
	    curarg--;
	    *curarg = '\0';
	    *g_cmdl = fake_cmdl;
	}
#endif
	*g_argc = argc;
	*g_argv = argv;
    }
    return 0;
}

int glob_add(const char *path, int *argc, char ***argv) {
    char *tail = strchr(path, '*'), *tailqmark;
    char *dup1, *dup2, *dir, *base, *taildirsep, *tailwldsep;
    struct dirent *de;
    int baselen, taillen, dirlen, mergedir = 0, outlen = 0;
    int qmarklen = 0;
    DIR *d;

    if(strlen(path) > 4 && !memcmp(path, "\\\\?\\", 4))
	tailqmark = strchr(&path[4], '?');
    else
	tailqmark = strchr(path, '?');

    if(tailqmark && (!tail || tailqmark < tail))
	tail = tailqmark;

    if(!tail) {
	*argv = realloc(*argv, sizeof(**argv) * (*argc + 1));
	(*argv)[*argc] = path;
	(*argc)++;
	return strlen(path);
    }

    if(tail!=path && tail[-1] == '\\') {
	tail[-1] = '\0';
	mergedir = 1;
    }
    while(*tail) {
	if(*tail == '?') {
	    if(tail == tailqmark || qmarklen) 
		qmarklen++;
	    *tail = 0;
	} else if(*tail == '*') {
	    *tail = '\0';
	    qmarklen = 0;
	} else 
	    break;
	tail++;
    }
    taillen = strlen(tail);
    taildirsep = strchr(tail, '\\');
    if(taildirsep && taildirsep - tail == taillen - 1) {
	*taildirsep = '\0';
	taildirsep = NULL;
	taillen--;
    }
    if(!taildirsep)
	taildirsep = tail + taillen;

    tailwldsep = strchr(tail, '*');
    tailqmark = strchr(tail, '?');
    if(tailqmark && (!tailwldsep || tailqmark < tailwldsep))
	tailwldsep = tailqmark;
    if(!tailwldsep)
	tailwldsep = tail + taillen;

    dup1 = strdup(path);
    dup2 = strdup(path);

    if(!mergedir) {
	dir = dirname(dup1);
	base = basename(dup2);
    } else {
	dir = dup1;
	base = dup2;
	*dup2 = '\0';
    }

    dirlen = strlen(dir);
    baselen = strlen(base);

    d = opendir(dir);
    while(d && (de = readdir(d))) {
	int namelen = strlen(de->d_name);
	char *newpath;

	if(!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) continue;
	if(namelen < baselen) continue;
	if(strncasecmp(base, de->d_name, baselen)) continue;
	if(de->d_type == DT_DIR && taildirsep < tailwldsep) {
	    int d_taillen = taildirsep - tail;
	    if(namelen < baselen + d_taillen) continue;
	    if(strncasecmp(tail, &de->d_name[namelen - d_taillen], d_taillen)) continue;
	    newpath = malloc(dirlen + namelen + taillen - d_taillen + 3);
	    sprintf(newpath, "%s\\%s\\%s", dir, de->d_name, &tail[d_taillen+1]);
	    outlen += glob_add(newpath, argc, argv);
	} else {
	    int d_taillen = tailwldsep - tail;
	    char *start;
	    if(namelen < baselen + d_taillen) continue;
	    if(qmarklen && baselen + qmarklen + d_taillen != namelen)	continue;
	    if(d_taillen == taillen) {
		start = &de->d_name[namelen - d_taillen];
		namelen = d_taillen;
	    } else {
		start = &de->d_name[baselen];
		namelen -= baselen;
	    }

	    for(; namelen >= d_taillen; start++, namelen--) {
		if(strncasecmp(start, tail, d_taillen)) continue;
		newpath = malloc(dirlen + (start - de->d_name) +  taillen + 2);
		sprintf(newpath, "%s\\", dir);
		memcpy(&newpath[dirlen + 1], de->d_name, start - de->d_name);
		strcpy(&newpath[dirlen + 1 + start - de->d_name], tail);
		outlen += glob_add(newpath, argc, argv);
	    }
	}
    }
    if(d) closedir(d);
    free(dup1);
    free(dup2);
    free(path);
    return outlen;
}

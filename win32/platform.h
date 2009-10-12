#ifndef __PLATFORM_H
#define __PLATFORM_H

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <io.h>
#include <direct.h>

#include "snprintf.h"

typedef int ssize_t;
#define strcasecmp lstrcmpi
#define strncasecmp strnicmp
#define mkdir(path, mode) mkdir(path)
#define lstat stat

#define PATH_MAX 32767

#define S_IRUSR S_IREAD
#define S_IWUSR S_IWRITE
#define S_IRWXU (S_IRUSR|S_IWUSR)
#define S_ISDIR(mode) ((_S_IFDIR & mode)!=0)
#define S_ISREG(mode) ((_S_IFREG & mode)!=0)
#define S_ISLNK(mode) (0)
#define F_OK 0
#define W_OK 2
#define R_OK 4
#define X_OK R_OK

#define SEARCH_LIBDIR ""

#ifndef MIN
#define MIN(a, b)	(((a) < (b)) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a,b)	(((a) > (b)) ? (a) : (b))
#endif

#ifndef HAVE_IN_PORT_T
typedef	unsigned	short	in_port_t;
#endif

#ifndef HAVE_IN_ADDR_T
typedef	unsigned	int	in_addr_t;
#endif

#define PATHSEP "\\"

#endif /* __PLATFORM_H */
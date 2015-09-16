#ifndef __PLATFORM_H
#define __PLATFORM_H

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <io.h>
#include <fcntl.h>
#include <direct.h>
#include <Ws2tcpip.h>
#include <process.h>

#ifdef __cplusplus
extern "C"
{
#endif

#include "gettimeofday.h"
#include "snprintf.h"
#include "net.h"
#include "w32_errno.h"
#include "w32_stat.h"
#include "random.h"
#include "utf8_util.h"

#ifdef __cplusplus
}
#else
typedef unsigned short mode_t;
#endif

#ifdef _WIN64
#define SIZEOF_VOID_P 8
#else
#define SIZEOF_VOID_P 4
#endif

#define strcasecmp lstrcmpi
#define strncasecmp strnicmp
#define mkdir(path, mode) mkdir(path)
#define sleep(sex) Sleep(1000*(sex))
#define getuid() 0
#define getgid() 0

char *strptime(const char *s, const char *format, struct tm *tm);

#define srand w32_srand
#define rand w32_rand
#define socket w32_socket
#define getsockopt w32_getsockopt
#define setsockopt w32_setsockopt
#define bind w32_bind
#define listen w32_listen
#define accept w32_accept
#define connect w32_connect
#define shutdown w32_shutdown
#define send w32_send
#define recv w32_recv
#define closesocket w32_closesocket
#define getservbyname w32_getservbyname
#define getaddrinfo w32_getaddrinfo
#ifdef gai_strerror
#undef gai_strerror
#endif
#define gai_strerror w32_strerror
#define freeaddrinfo w32_freeaddrinfo
#define inet_ntop w32_inet_ntop
#define inet_ntoa w32_inet_ntoa
#define getpeername w32_getpeername
#define select w32_select
#define poll w32_poll
#define strerror w32_strerror
#define strerror_r w32_strerror_r
#define ftruncate _chsize
#define getpid GetCurrentProcessId

#define PATH_MAX 32767
#define SEARCH_LIBDIR ""
#define WORDS_BIGENDIAN 0
#define EAI_SYSTEM 0

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

void w32_glob(int *argc_ptr, char ***argv_ptr);

#undef DATADIR
#undef CONFDIR
#if !defined(THIS_IS_LIBCLAMAV) && defined(_MSC_VER)
#define LIBCLAMAV_EXPORT __declspec(dllimport)
#else
#define LIBCLAMAV_EXPORT
#endif
LIBCLAMAV_EXPORT extern const char *DATADIR;
LIBCLAMAV_EXPORT extern const char *CONFDIR;
LIBCLAMAV_EXPORT extern const char *CONFDIR_CLAMD;
LIBCLAMAV_EXPORT extern const char *CONFDIR_FRESHCLAM;
LIBCLAMAV_EXPORT extern const char *CONFDIR_MILTER;
#undef HAVE_CONFIG_H

#ifdef OUT
#undef OUT
#endif

int real_main(int, char**);
#define main main(int argc, char **argv) { _setmode(_fileno(stdin), _O_BINARY); w32_glob(&argc, &argv); return real_main(argc, argv); }; int real_main

#endif /* __PLATFORM_H */


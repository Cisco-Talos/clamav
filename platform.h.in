#ifndef _WIN32
#define closesocket(s) close(s)
#endif

#ifndef O_BINARY
#define O_BINARY 0
#endif

#ifndef	FALSE
#define FALSE (0)
#endif
#ifndef	TRUE
#define TRUE (1)
#endif

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

#ifdef _WIN32
#define PATHSEP "\\"
#else
#define PATHSEP "/"
#endif

#define CONFDIR_CLAMD CONFDIR PATHSEP "clamd.conf"
#define CONFDIR_FRESHCLAM CONFDIR PATHSEP "freshclam.conf"
#define CONFDIR_MILTER CONFDIR PATHSEP "clamav-milter.conf"

#define cli_to_utf8_maybe_alloc(x) (x)
#define cli_strdup_to_utf8(x) strdup(x)
#ifndef WORDS_BIGENDIAN
#define WORDS_BIGENDIAN 0
#endif

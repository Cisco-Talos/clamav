#ifndef FDPASSING_H
#define FDPASSING_H

#ifdef HAVE_FD_PASSING

#ifdef FDPASS_NEED_XOPEN
/* to expose BSD 4.4/Unix98 semantics instead of BSD 4.3 semantics */
#define _XOPEN_SOURCE 500
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>

#endif
#endif


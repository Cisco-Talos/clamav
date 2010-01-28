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

#include <winsock2.h>
#include <Ws2tcpip.h>
/* #define W2K_DNSAAPI_COMPAT */
#ifdef W2K_DNSAAPI_COMPAT
#include <Wspiapi.h>
#endif
#include "net.h"
#include "w32_errno.h"

static void wsock2errno() {
    switch(WSAGetLastError()) {
	case WSA_INVALID_HANDLE:
	case WSA_INVALID_PARAMETER: 
	case WSAVERNOTSUPPORTED: 
	case WSANOTINITIALISED: 
	case WSAEINVALIDPROCTABLE: 
	case WSAEINVALIDPROVIDER: 
	case WSAEPROVIDERFAILEDINIT:
	case WSASYSCALLFAILURE:
	case WSASERVICE_NOT_FOUND:
	case WSATYPE_NOT_FOUND:
	    errno = EINVAL;
	    break;
	case WSA_OPERATION_ABORTED: 
	case WSAENOMORE: 
	case WSAECANCELLED: 
	case WSA_E_NO_MORE: 
	case WSA_E_CANCELLED: 
	case WSA_IO_INCOMPLETE: 
	case WSA_IO_PENDING: 
	case WSAEREFUSED: 
	case WSA_QOS_RECEIVERS: 
	case WSA_QOS_SENDERS: 
	case WSA_QOS_NO_SENDERS: 
	case WSA_QOS_NO_RECEIVERS: 
	case WSA_QOS_REQUEST_CONFIRMED: 
	case WSA_QOS_ADMISSION_FAILURE: 
	case WSA_QOS_POLICY_FAILURE: 
	case WSA_QOS_BAD_STYLE: 
	case WSA_QOS_BAD_OBJECT: 
	case WSA_QOS_TRAFFIC_CTRL_ERROR: 
	case WSA_QOS_GENERIC_ERROR: 
	case WSA_QOS_ESERVICETYPE: 
	case WSA_QOS_EFLOWSPEC: 
	case WSA_QOS_EPROVSPECBUF: 
	case WSA_QOS_EFILTERSTYLE: 
	case WSA_QOS_EFILTERTYPE: 
	case WSA_QOS_EFILTERCOUNT: 
	case WSA_QOS_EOBJLENGTH: 
	case WSA_QOS_EFLOWCOUNT: 
	case WSA_QOS_EUNKOWNPSOBJ: 
	case WSA_QOS_EPOLICYOBJ: 
	case WSA_QOS_EFLOWDESC: 
	case WSA_QOS_EPSFLOWSPEC: 
	case WSA_QOS_EPSFILTERSPEC: 
	case WSA_QOS_ESDMODEOBJ: 
	case WSA_QOS_ESHAPERATEOBJ: 
	case WSA_QOS_RESERVED_PETYPE: 
	    errno = EBOGUSWSOCK;
	    break;
	case WSA_NOT_ENOUGH_MEMORY: 
	    errno = ENOMEM;
	    break;
	case WSAEINTR: 
	    errno = EINTR;
	    break;
	case WSAEBADF: 
	    errno = EBADF;
	    break;
	case WSAEACCES: 
	    errno = EACCES;
	    break;
	case WSAEFAULT: 
	    errno = EFAULT;
	    break;
	case WSAEINVAL: 
	    errno = EINVAL;
	    break;
	case WSAEMFILE: 
	    errno = EMFILE;
	    break;
	case WSAEWOULDBLOCK: 
	    errno = EAGAIN;
	    break;
	case WSAEINPROGRESS: 
	    errno = EINPROGRESS;
	    break;
	case WSAEALREADY: 
	    errno = EALREADY;
	    break;
	case WSAENOTSOCK: 
	    errno = ENOTSOCK;
	    break;
	case WSAEDESTADDRREQ: 
	    errno = EDESTADDRREQ;
	    break;
	case WSAEMSGSIZE: 
	    errno = EMSGSIZE;
	    break;
	case WSAEPROTOTYPE: 
	    errno = EPROTOTYPE;
	    break;
	case WSAENOPROTOOPT: 
	    errno = ENOPROTOOPT;
	    break;
	case WSAEPROTONOSUPPORT: 
	    errno = EPROTONOSUPPORT;
	    break;
	case WSAESOCKTNOSUPPORT: 
	    errno = ESOCKTNOSUPPORT;
	    break;
	case WSAEOPNOTSUPP: 
	    errno = EOPNOTSUPP;
	    break;
	case WSAEPFNOSUPPORT: 
	    errno = EPFNOSUPPORT;
	    break;
	case WSAEAFNOSUPPORT: 
	    errno = EAFNOSUPPORT;
	    break;
	case WSAEADDRINUSE: 
	    errno = EADDRINUSE;
	    break;
	case WSAEADDRNOTAVAIL: 
	    errno = EADDRNOTAVAIL;
	    break;
	case WSASYSNOTREADY:
	case WSAENETDOWN: 
	    errno = ENETDOWN;
	    break;
	case WSAENETUNREACH: 
	    errno = ENETUNREACH;
	    break;
	case WSAENETRESET: 
	    errno = ENETRESET;
	    break;
	case WSAECONNABORTED: 
	    errno = ECONNABORTED;
	    break;
	case WSAECONNRESET:
	case WSAEDISCON:
	    errno = ECONNRESET;
	    break;
	case WSAENOBUFS: 
	    errno = ENOBUFS;
	    break;
	case WSAEISCONN: 
	    errno = EISCONN;
	    break;
	case WSAENOTCONN: 
	    errno = ENOTCONN;
	    break;
	case WSAESHUTDOWN: 
	    errno = ESHUTDOWN;
	    break;
	case WSAETOOMANYREFS: 
	    errno = ETOOMANYREFS;
	    break;
	case WSAETIMEDOUT: 
	    errno = ETIMEDOUT;
	    break;
	case WSAECONNREFUSED: 
	    errno = ECONNREFUSED;
	    break;
	case WSAELOOP: 
	    errno = ELOOP;
	    break;
	case WSAENAMETOOLONG: 
	    errno = ENAMETOOLONG;
	    break;
	case WSAEHOSTDOWN: 
	    errno = EHOSTDOWN;
	    break;
	case WSAEHOSTUNREACH: 
	    errno = EHOSTUNREACH;
	    break;
	case WSAENOTEMPTY: 
	    errno = ENOTEMPTY;
	    break;
	case WSAEPROCLIM: 
	case WSAEUSERS: 
	    errno = EUSERS;
	    break;
	case WSAEDQUOT: 
	    errno = EDQUOT;
	    break;
	case WSAESTALE: 
	    errno = ESTALE;
	    break;
	case WSAEREMOTE: 
	    errno = EREMOTE;
	    break;
    }
}

int w32_socket(int domain, int type, int protocol) {
    SOCKET s = socket(domain, type, protocol);
    if(s == INVALID_SOCKET) {
	wsock2errno();
	return -1;
    }
    return (int)s;
}

int w32_getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen) {
    if(getsockopt((SOCKET)sockfd, level, optname, (char *)optval, optlen) == SOCKET_ERROR) {
	wsock2errno();
	return -1;
    }
    return 0;
}

int w32_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) {
    if(setsockopt((SOCKET)sockfd, level, optname, (const char*)optval, optlen) == SOCKET_ERROR) {
	wsock2errno();
	return -1;
    }
    return 0;
}

int w32_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if(bind((SOCKET)sockfd, addr, addrlen) == SOCKET_ERROR) {
	wsock2errno();
	return -1;
    }
    return 0;
}

int w32_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if(connect((SOCKET)sockfd, addr, addrlen)) {
	wsock2errno();
	return -1;
    }
    return 0;
}

ssize_t w32_send(int sockfd, const void *buf, size_t len, int flags) {
    int ret = send((SOCKET)sockfd, (const char *)buf, (int)len, flags);
    if(ret == SOCKET_ERROR) {
	wsock2errno();
	return -1;
    }
    return (ssize_t)ret;
}

ssize_t w32_recv(int sockfd, void *buf, size_t len, int flags) {
    int ret = recv((SOCKET)sockfd, (char *)buf, len, flags);
    if(ret == SOCKET_ERROR) {
	wsock2errno();
	return -1;
    }
    return (ssize_t)ret;
}

int w32_closesocket(int sockfd) {
    if(closesocket((SOCKET)sockfd) == SOCKET_ERROR) {
	wsock2errno();
	return -1;
    }
    return 0;
}

struct servent *w32_getservbyname(const char *name, const char *proto) {
    return getservbyname(name, proto);
}

int w32_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
    return getaddrinfo(node, service, hints, res);
}

void w32_freeaddrinfo(struct addrinfo *res) {
    freeaddrinfo(res);
}

const char *w32_inet_ntop(int af, const void *src, char *dst, socklen_t size) {
    const char *ret;

    if(af != AF_INET) {
	errno = EAFNOSUPPORT;
	return NULL;
    }
    ret = inet_ntoa(*(struct in_addr *)src);
    if(!ret) {
	wsock2errno();
	return NULL;
    }
    if(strlen(ret) >= size) {
	errno = ENOSPC;
	return NULL;
    }
    strcpy(dst, ret);
    return ret;
}

struct hostent *w32_gethostbyname(const char *name) {
    return gethostbyname(name);
}

int w32_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) {
    int ret = select(nfds, readfds, writefds, exceptfds, timeout);
    if(ret == SOCKET_ERROR) {
	wsock2errno();
	return -1;
    }
    return ret;
}

int w32_accept(int sockfd, const struct sockaddr *addr, socklen_t *addrlen) {
    if(accept((SOCKET)sockfd, addr, addrlen)) {
	wsock2errno();
	return -1;
    }
    return 0;
}

int w32_listen(int sockfd, int backlog) {
    if(listen((SOCKET)sockfd, backlog)) {
	wsock2errno();
	return -1;
    }
    return 0;
}

int w32_shutdown(int sockfd, int how) {
    if(shutdown((SOCKET)sockfd, how)) {
	wsock2errno();
	return -1;
    }
    return 0;
}

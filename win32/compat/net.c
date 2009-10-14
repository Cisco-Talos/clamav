#include <winsock2.h>
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

int w32_send(int sockfd, const void *buf, size_t len, int flags) {
    int ret;
    if(WSASend((SOCKET)sockfd, (LPWSABUF)buf, (DWORD)len, (LPDWORD)&ret, (DWORD)flags, NULL, NULL)) {
	wsock2errno();
	return -1;
    }
    return ret;
}

/*
int w32_gethostbyname(const char *name) {
    struct hostent *h = gethostbyname(name);
    h_errno = 0;
    if(!h) {
	switch(WSAGetLastError()) {
	    case WSAHOST_NOT_FOUND:
		*h_errno = HOST_NOT_FOUND;
		break;
	    case WSATRY_AGAIN:
		*h_errno = TRY_AGAIN;
		break;
	    case WSANO_RECOVERY:
		*h_errno = NO_RECOVERY;
		break;
	    case WSANO_DATA:
		*h_errno = NO_DATA;
		break;
	}
    }
    return h;
}

*/
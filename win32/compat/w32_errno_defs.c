/* Automatically generated on Thu Jan 28 23:51:23 CET 2010 */

#include <errno.h>

static const struct errno_struct {
	int err;
	const char *strerr;
} w32_errnos[] = {
#ifndef EPERM
#define EPERM 1001
#endif
{ EPERM, "Operation not permitted" },
#ifndef ENOENT
#define ENOENT 1002
#endif
{ ENOENT, "No such file or directory" },
#ifndef ESRCH
#define ESRCH 1003
#endif
{ ESRCH, "No such process" },
#ifndef EINTR
#define EINTR 1004
#endif
{ EINTR, "Interrupted function call" },
#ifndef EIO
#define EIO 1005
#endif
{ EIO, "Input/output error" },
#ifndef ENXIO
#define ENXIO 1006
#endif
{ ENXIO, "No such device or address" },
#ifndef E2BIG
#define E2BIG 1007
#endif
{ E2BIG, "Argument list too long" },
#ifndef ENOEXEC
#define ENOEXEC 1008
#endif
{ ENOEXEC, "Executable file format error" },
#ifndef EBADF
#define EBADF 1009
#endif
{ EBADF, "Bad file descriptor" },
#ifndef ECHILD
#define ECHILD 1010
#endif
{ ECHILD, "No child process" },
#ifndef EAGAIN
#define EAGAIN 1011
#endif
{ EAGAIN, "Resource temporarily unavailable, try again" },
#ifndef ENOMEM
#define ENOMEM 1012
#endif
{ ENOMEM, "Not enough space" },
#ifndef EACCES
#define EACCES 1013
#endif
{ EACCES, "Permission denied" },
#ifndef EFAULT
#define EFAULT 1014
#endif
{ EFAULT, "Bad address" },
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef ENOTBLK
#define ENOTBLK 1015
#endif
{ ENOTBLK, "Block device required" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifndef EBUSY
#define EBUSY 1016
#endif
{ EBUSY, "Device or resource busy" },
#ifndef EEXIST
#define EEXIST 1017
#endif
{ EEXIST, "File exists" },
#ifndef EXDEV
#define EXDEV 1018
#endif
{ EXDEV, "Improper link" },
#ifndef ENODEV
#define ENODEV 1019
#endif
{ ENODEV, "No such device" },
#ifndef ENOTDIR
#define ENOTDIR 1020
#endif
{ ENOTDIR, "Not a directory" },
#ifndef EISDIR
#define EISDIR 1021
#endif
{ EISDIR, "Is a directory" },
#ifndef EINVAL
#define EINVAL 1022
#endif
{ EINVAL, "Invalid argument" },
#ifndef ENFILE
#define ENFILE 1023
#endif
{ ENFILE, "Too many files open in system" },
#ifndef EMFILE
#define EMFILE 1024
#endif
{ EMFILE, "Too many open files" },
#ifndef ENOTTY
#define ENOTTY 1025
#endif
{ ENOTTY, "Inappropriate I/O control operation" },
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef ETXTBSY
#define ETXTBSY 1026
#endif
{ ETXTBSY, "Text file busy" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifndef EFBIG
#define EFBIG 1027
#endif
{ EFBIG, "File too large" },
#ifndef ENOSPC
#define ENOSPC 1028
#endif
{ ENOSPC, "No space left on a device" },
#ifndef ESPIPE
#define ESPIPE 1029
#endif
{ ESPIPE, "Invalid seek" },
#ifndef EROFS
#define EROFS 1030
#endif
{ EROFS, "Read-only file system" },
#ifndef EMLINK
#define EMLINK 1031
#endif
{ EMLINK, "Too many links" },
#ifndef EPIPE
#define EPIPE 1032
#endif
{ EPIPE, "Broken pipe" },
#ifndef EDOM
#define EDOM 1033
#endif
{ EDOM, "Mathematics argument out of domain of function" },
#ifndef ERANGE
#define ERANGE 1034
#endif
{ ERANGE, "Result too large or too small" },
#ifndef EDEADLK
#define EDEADLK 1035
#endif
{ EDEADLK, "Resource deadlock would occur" },
#ifndef ENAMETOOLONG
#define ENAMETOOLONG 1036
#endif
{ ENAMETOOLONG, "Filename too long" },
#ifndef ENOLCK
#define ENOLCK 1037
#endif
{ ENOLCK, "No locks available" },
#ifndef ENOSYS
#define ENOSYS 1038
#endif
{ ENOSYS, "Function not implemented" },
#ifndef ENOTEMPTY
#define ENOTEMPTY 1039
#endif
{ ENOTEMPTY, "Directory not empty" },
#ifndef ELOOP
#define ELOOP 1040
#endif
{ ELOOP, "Too many levels of symbolic links" },
#ifndef EWOULDBLOCK
#define EWOULDBLOCK 1041
#endif
{ EWOULDBLOCK, "Operation would block" },
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef ENOMSG
#define ENOMSG 1042
#endif
{ ENOMSG, "No message of the desired type" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef EIDRM
#define EIDRM 1043
#endif
{ EIDRM, "Identifier removed" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef ECHRNG
#define ECHRNG 1044
#endif
{ ECHRNG, "Channel number out of range" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef EL2NSYNC
#define EL2NSYNC 1045
#endif
{ EL2NSYNC, "Level 2 not synchronized" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef EL3HLT
#define EL3HLT 1046
#endif
{ EL3HLT, "Level 3 halted" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef EL3RST
#define EL3RST 1047
#endif
{ EL3RST, "Level 3 reset" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef ELNRNG
#define ELNRNG 1048
#endif
{ ELNRNG, "Link number out of range" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef EUNATCH
#define EUNATCH 1049
#endif
{ EUNATCH, "Protocol driver not attached" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef ENOCSI
#define ENOCSI 1050
#endif
{ ENOCSI, "No CSI structure available" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef EL2HLT
#define EL2HLT 1051
#endif
{ EL2HLT, "Level 2 halted" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef EBADE
#define EBADE 1052
#endif
{ EBADE, "Invalid exchange" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef EBADR
#define EBADR 1053
#endif
{ EBADR, "Invalid request descriptor" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef EXFULL
#define EXFULL 1054
#endif
{ EXFULL, "Exchange full" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef ENOANO
#define ENOANO 1055
#endif
{ ENOANO, "No anode" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef EBADRQC
#define EBADRQC 1056
#endif
{ EBADRQC, "Invalid request code" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef EBADSLT
#define EBADSLT 1057
#endif
{ EBADSLT, "Invalid slot" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifndef EDEADLOCK
#define EDEADLOCK 1058
#endif
{ EDEADLOCK, "Resource deadlock" },
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef EBFONT
#define EBFONT 1059
#endif
{ EBFONT, "Bad font file format" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef ENOSTR
#define ENOSTR 1060
#endif
{ ENOSTR, "Not a STREAM" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef ENODATA
#define ENODATA 1061
#endif
{ ENODATA, "No message available" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifndef ETIME
#define ETIME 1062
#endif
{ ETIME, "STREAM ioctl() timeout" },
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef ENOSR
#define ENOSR 1063
#endif
{ ENOSR, "No STREAM resources" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef ENONET
#define ENONET 1064
#endif
{ ENONET, "Machine is not on the network" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef ENOPKG
#define ENOPKG 1065
#endif
{ ENOPKG, "Package not installed" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifndef EREMOTE
#define EREMOTE 1066
#endif
{ EREMOTE, "Object is remote" },
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef ENOLINK
#define ENOLINK 1067
#endif
{ ENOLINK, "Reserved" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef EADV
#define EADV 1068
#endif
{ EADV, "Advertise error" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef ESRMNT
#define ESRMNT 1069
#endif
{ ESRMNT, "Srmount error" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifndef ECOMM
#define ECOMM 1070
#endif
{ ECOMM, "Communication error on send" },
#ifndef EPROTO
#define EPROTO 1071
#endif
{ EPROTO, "Protocol error" },
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef EMULTIHOP
#define EMULTIHOP 1072
#endif
{ EMULTIHOP, "Reserved" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef EDOTDOT
#define EDOTDOT 1073
#endif
{ EDOTDOT, "RFS specific error" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef EBADMSG
#define EBADMSG 1074
#endif
{ EBADMSG, "Bad Message" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef EOVERFLOW
#define EOVERFLOW 1075
#endif
{ EOVERFLOW, "Value too large to be stored in data type" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef ENOTUNIQ
#define ENOTUNIQ 1076
#endif
{ ENOTUNIQ, "Name not unique on network" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef EBADFD
#define EBADFD 1077
#endif
{ EBADFD, "File descriptor in bad state" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef EREMCHG
#define EREMCHG 1078
#endif
{ EREMCHG, "Remote address changed" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef ELIBACC
#define ELIBACC 1079
#endif
{ ELIBACC, "Can not access a needed shared library" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef ELIBBAD
#define ELIBBAD 1080
#endif
{ ELIBBAD, "Accessing a corrupted shared library" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef ELIBSCN
#define ELIBSCN 1081
#endif
{ ELIBSCN, ".lib section in a.out corrupted" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef ELIBMAX
#define ELIBMAX 1082
#endif
{ ELIBMAX, "Attempting to link in too many shared libraries" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef ELIBEXEC
#define ELIBEXEC 1083
#endif
{ ELIBEXEC, "Cannot exec a shared library directly" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifndef EILSEQ
#define EILSEQ 1084
#endif
{ EILSEQ, "Illegal byte sequence" },
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef ERESTART
#define ERESTART 1085
#endif
{ ERESTART, "Interrupted system call should be restarted" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef ESTRPIPE
#define ESTRPIPE 1086
#endif
{ ESTRPIPE, "Streams pipe error" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifndef EUSERS
#define EUSERS 1087
#endif
{ EUSERS, "Too many users" },
#ifndef ENOTSOCK
#define ENOTSOCK 1088
#endif
{ ENOTSOCK, "Not a socket" },
#ifndef EDESTADDRREQ
#define EDESTADDRREQ 1089
#endif
{ EDESTADDRREQ, "Destination address required" },
#ifndef EMSGSIZE
#define EMSGSIZE 1090
#endif
{ EMSGSIZE, "Message too large" },
#ifndef EPROTOTYPE
#define EPROTOTYPE 1091
#endif
{ EPROTOTYPE, "Socket type not supported" },
#ifndef ENOPROTOOPT
#define ENOPROTOOPT 1092
#endif
{ ENOPROTOOPT, "Protocol not available" },
#ifndef EPROTONOSUPPORT
#define EPROTONOSUPPORT 1093
#endif
{ EPROTONOSUPPORT, "Protocol not supported" },
#ifndef ESOCKTNOSUPPORT
#define ESOCKTNOSUPPORT 1094
#endif
{ ESOCKTNOSUPPORT, "Socket type not supported" },
#ifndef EOPNOTSUPP
#define EOPNOTSUPP 1095
#endif
{ EOPNOTSUPP, "Operation not supported on socket" },
#ifndef EPFNOSUPPORT
#define EPFNOSUPPORT 1096
#endif
{ EPFNOSUPPORT, "Protocol family not supported" },
#ifndef EAFNOSUPPORT
#define EAFNOSUPPORT 1097
#endif
{ EAFNOSUPPORT, "Address family not supported" },
#ifndef EADDRINUSE
#define EADDRINUSE 1098
#endif
{ EADDRINUSE, "Address in use" },
#ifndef EADDRNOTAVAIL
#define EADDRNOTAVAIL 1099
#endif
{ EADDRNOTAVAIL, "Address not available" },
#ifndef ENETDOWN
#define ENETDOWN 1100
#endif
{ ENETDOWN, "Network is down" },
#ifndef ENETUNREACH
#define ENETUNREACH 1101
#endif
{ ENETUNREACH, "Network unreachable" },
#ifndef ENETRESET
#define ENETRESET 1102
#endif
{ ENETRESET, "Network dropped connection because of reset" },
#ifndef ECONNABORTED
#define ECONNABORTED 1103
#endif
{ ECONNABORTED, "Connection aborted" },
#ifndef ECONNRESET
#define ECONNRESET 1104
#endif
{ ECONNRESET, "Connection reset" },
#ifndef ENOBUFS
#define ENOBUFS 1105
#endif
{ ENOBUFS, "No buffer space available" },
#ifndef EISCONN
#define EISCONN 1106
#endif
{ EISCONN, "Socket is connected" },
#ifndef ENOTCONN
#define ENOTCONN 1107
#endif
{ ENOTCONN, "Socket not connected" },
#ifndef ESHUTDOWN
#define ESHUTDOWN 1108
#endif
{ ESHUTDOWN, "Cannot send after transport endpoint shutdown" },
#ifndef ETOOMANYREFS
#define ETOOMANYREFS 1109
#endif
{ ETOOMANYREFS, "Too many references: cannot splice" },
#ifndef ETIMEDOUT
#define ETIMEDOUT 1110
#endif
{ ETIMEDOUT, "Connection timed out" },
#ifndef ECONNREFUSED
#define ECONNREFUSED 1111
#endif
{ ECONNREFUSED, "Connection refused" },
#ifndef EHOSTDOWN
#define EHOSTDOWN 1112
#endif
{ EHOSTDOWN, "Host is down" },
#ifndef EHOSTUNREACH
#define EHOSTUNREACH 1113
#endif
{ EHOSTUNREACH, "Host is unreachable" },
#ifndef EALREADY
#define EALREADY 1114
#endif
{ EALREADY, "Connection already in progress" },
#ifndef EINPROGRESS
#define EINPROGRESS 1115
#endif
{ EINPROGRESS, "Operation in progress" },
#ifndef ESTALE
#define ESTALE 1116
#endif
{ ESTALE, "Reserved" },
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef EUCLEAN
#define EUCLEAN 1117
#endif
{ EUCLEAN, "Structure needs cleaning" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef ENOTNAM
#define ENOTNAM 1118
#endif
{ ENOTNAM, "Not a XENIX named type file" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef ENAVAIL
#define ENAVAIL 1119
#endif
{ ENAVAIL, "No XENIX semaphores available" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef EISNAM
#define EISNAM 1120
#endif
{ EISNAM, "Is a named type file" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef EREMOTEIO
#define EREMOTEIO 1121
#endif
{ EREMOTEIO, "Remote I/O error" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifndef EDQUOT
#define EDQUOT 1122
#endif
{ EDQUOT, "Reserved" },
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef ENOMEDIUM
#define ENOMEDIUM 1123
#endif
{ ENOMEDIUM, "No medium found" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef EMEDIUMTYPE
#define EMEDIUMTYPE 1124
#endif
{ EMEDIUMTYPE, "Wrong medium type" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef ECANCELED
#define ECANCELED 1125
#endif
{ ECANCELED, "Operation canceled" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef ENOKEY
#define ENOKEY 1126
#endif
{ ENOKEY, "Required key not available" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef EKEYEXPIRED
#define EKEYEXPIRED 1127
#endif
{ EKEYEXPIRED, "Key has expired" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef EKEYREVOKED
#define EKEYREVOKED 1128
#endif
{ EKEYREVOKED, "Key has been revoked" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef EKEYREJECTED
#define EKEYREJECTED 1129
#endif
{ EKEYREJECTED, "Key was rejected by service" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef EOWNERDEAD
#define EOWNERDEAD 1130
#endif
{ EOWNERDEAD, "Owner died" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifdef __ERRNO_INCLUDE_UNUSED
#ifndef ENOTRECOVERABLE
#define ENOTRECOVERABLE 1131
#endif
{ ENOTRECOVERABLE, "State not recoverable" },
#endif /* __ERRNO_INCLUDE_UNUSED */
#ifndef EBOGUSWSOCK
#define EBOGUSWSOCK 1132
#endif
{ EBOGUSWSOCK, "WinSock error"}
};

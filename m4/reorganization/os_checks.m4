case "$target_os" in
linux*)
    AC_DEFINE([C_LINUX],1,[target is linux])
    have_fanotify="no"
    if test "$have_pthreads" = "yes"; then
	THREAD_LIBS="-lpthread"
	TH_SAFE="-thread-safe"
	if test "$want_fanotify" = "yes"; then
	    AC_CHECK_HEADER([sys/fanotify.h],
               [AC_DEFINE([FANOTIFY],1,[use fanotify])
                have_fanotify="yes"],)
	fi
    fi
    ;;
kfreebsd*-gnu)
    AC_DEFINE([C_KFREEBSD_GNU],1,[target is kfreebsd-gnu])
    if test "$have_pthreads" = "yes"; then
       THREAD_LIBS="-lpthread"
       TH_SAFE="-thread-safe"
    fi
    ;;
solaris*)
    CLAMDSCAN_LIBS="$CLAMDSCAN_LIBS -lresolv"
    FRESHCLAM_LIBS="$FRESHCLAM_LIBS -lresolv"
    if test "$have_pthreads" = "yes"; then
	THREAD_LIBS="-lpthread"
	CLAMD_LIBS="$CLAMD_LIBS -lresolv"
	CLAMAV_MILTER_LIBS="$CLAMAV_MILTER_LIBS -lresolv"
	TH_SAFE="-thread-safe"
    fi
    AC_DEFINE([C_SOLARIS],1,[os is solaris])
    ;;
freebsd[[45]]*)
    if test "$have_pthreads" = "yes"; then
	THREAD_LIBS="-pthread -lc_r"
	TH_SAFE="-thread-safe"
    fi
    AC_DEFINE([C_BSD],1,[os is freebsd 4 or 5])
    ;;
freebsd*)
    if test "$have_pthreads" = "yes"; then
	THREAD_LIBS="-lthr"
	TH_SAFE="-thread-safe"
    fi
    AC_DEFINE([C_BSD],1,[os is freebsd 6])
    ;;
dragonfly*)
    if test "$have_pthreads" = "yes"; then
	THREAD_LIBS="-pthread"
	TH_SAFE="-thread-safe"
    fi
    AC_DEFINE([C_BSD],1,[os is dragonfly])
    ;;
openbsd*)
    if test "$have_pthreads" = "yes"; then
	THREAD_LIBS="-pthread"
	CLAMD_LIBS="$CLAMD_LIBS -pthread"
	CLAMAV_MILTER_LIBS="$CLAMAV_MILTER_LIBS -pthread"
	TH_SAFE="-thread-safe"
    fi
    AC_DEFINE([C_BSD],1,[os is OpenBSD])
    ;;
bsdi*)
    if test "$have_pthreads" = "yes"; then
	THREAD_LIBS="-pthread"
	TH_SAFE="-thread-safe"
    fi
    AC_DEFINE([C_BSD],1,[os is BSDI BSD/OS])
    ;;
netbsd*)
     if test "$have_pthreads" = "yes"; then
	THREAD_LIBS="-lpthread"
     fi
    AC_DEFINE([C_BSD],1,[os is NetBSD])
    ;;
bsd*)
    AC_MSG_RESULT([Unknown BSD detected. Disabling thread support.])
    have_pthreads="no"
    AC_DEFINE([C_BSD],1,[os is bsd flavor])
    ;;
beos*)
    AC_MSG_RESULT([BeOS detected. Disabling thread support.])
    have_pthreads="no"
    AC_DEFINE([C_BEOS],1,[os is beos])
    ;;
x86:Interix*)
    AC_DEFINE([C_INTERIX],1,[os is Interix])
    ;;
darwin*)
    AC_DEFINE([C_BSD],1,[os is bsd flavor])
    AC_DEFINE([C_DARWIN],1,[os is darwin])
    AC_DEFINE([BIND_8_COMPAT],1,[enable bind8 compatibility])
    AC_DEFINE([CLAMAUTH],1,[use ClamAuth])
    use_netinfo="yes"
    ;;
os2*)
    CLAMDSCAN_LIBS="$CLAMDSCAN_LIBS -lsyslog"
    FRESHCLAM_LIBS="$FRESHCLAM_LIBS -lsyslog"
    CLAMD_LIBS="$CLAMD_LIBS -lsyslog"
    CLAMAV_MILTER_LIBS="$CLAMAV_MILTER_LIBS -lsyslog"
    if test "$have_pthreads" = "yes"; then
	THREAD_LIBS="-lpthread"
	TH_SAFE="-thread-safe"
    fi
    AC_DEFINE([C_OS2],1,[os is OS/2])
    ;;
sco*)
    dnl njh@bandsman.sco.uk: SCO Unix port
    dnl FRESHCLAM_LIBS="-lsocket"
    dnl CLAMD_LIBS="-lsocket"
    dnl CLAMAV_MILTER_LIBS="$CLAMAV_MILTER_LIBS -lsocket"
    ;;
hpux*)
    if test "$have_pthreads" = "yes"; then
	THREAD_LIBS="-lpthread"
	TH_SAFE="-thread-safe"
    fi
    AC_DEFINE([C_HPUX],1,[os is hpux])
    if test "$have_mempool" = "yes"; then
	LDFLAGS="$LDFLAGS -Wl,+pd,1M"
    fi
    ;;
aix*)
    if test "$have_pthreads" = "yes"; then
	THREAD_LIBS="-lpthread"
	TH_SAFE="-thread-safe"
	AC_DEFINE([_THREAD_SAFE],1,[thread safe])
    fi
    AC_DEFINE([C_AIX],1,[os is aix])
    ;;
*-*-osf*)
    if test "$have_pthreads" = "yes"; then
	THREAD_LIBS="-pthread"
	TH_SAFE="-thread-safe"
	AC_DEFINE([_POSIX_PII_SOCKET],1,[POSIX compatibility])
    fi
    AC_DEFINE([C_OSF],1,[os is osf/tru64])
    ;;
nto-qnx*)
    AC_DEFINE([C_QNX6],1,[os is QNX 6.x.x])
    ;;
irix*)
    if test "$have_pthreads" = "yes"; then
	THREAD_LIBS="-lpthread"
	TH_SAFE="-thread-safe"
    fi
    LIBS="$LIBS -lgen"
    AC_DEFINE([C_IRIX],1,[os is irix])
    ;;
interix*)
    AC_DEFINE([C_INTERIX],1,[os is interix])
    if test "$test_clamav" = "yes"; then
	if test ! -r /etc/passwd; then
	   test_clamav="no"
	fi
    fi
    if test "$have_pthreads" = "yes"; then
	THREAD_LIBS="-lpthread"
	TH_SAFE="-thread-safe"
    fi
    ;;
gnu*)
    AC_DEFINE([C_GNU_HURD],1,[target is gnu-hurd])
    if test "$have_pthreads" = "yes"; then
       THREAD_LIBS="-lpthread"
       TH_SAFE="-thread-safe"
    fi
    ;;
*)
    ;;
esac

dnl AC_C_DNS
dnl Checks resolv.h presence and usability
dnl Checks for specific lresolv exports
dnl Checks for lresolve reentrance
dnl
dnl Note using AC_LINK_IFELSE instead of AC_CHECK_LIB
dnl as symbols are often redefined in resolv.h

AC_DEFUN([AC_C_DNS], [

AC_ARG_ENABLE([dns],
    [AC_HELP_STRING([--disable-dns], [do not include support for database verification through DNS])],
    [want_dns=$enableval], [want_dns=yes]
)
if test $want_dns = yes; then
    ac_cv_have_lresolv=no
    AC_CHECK_HEADER([resolv.h],
	[
	    AC_CACHE_CHECK([for dn_expand in std libs], [ac_cv_have_lresolv_std], [
	    	ac_cv_have_lresolv_std='no'
	        AC_LINK_IFELSE([AC_LANG_SOURCE([
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
int main() { return (long)dn_expand; }
		])],
		[
		    ac_cv_have_lresolv_std='yes'
		    ac_cv_have_lresolv=''
		])
	    ])
	    if test "x$ac_cv_have_lresolv" = "xno"; then
	    bklibs=$LIBS
	    LIBS=-lresolv
	    AC_CACHE_CHECK([for dn_expand in -lresolv], [ac_cv_have_lresolv_lresolv], [
		ac_cv_have_lresolv_lresolv='yes'
		AC_LINK_IFELSE([AC_LANG_SOURCE([
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
int main() { return (long)dn_expand; }
    	     	])],
		[
		    ac_cv_have_lresolv_lresolv='yes'
		    ac_cv_have_lresolv=' -lresolv'
		])
	    ])
	    LIBS=$bklibs;
	    fi
	],
	[ ac_cv_have_lresolv=no ],
	[
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
    ])
    if test "x$ac_cv_have_lresolv" != "xno"; then
    	FRESHCLAM_LIBS="$FRESHCLAM_LIBS$ac_cv_have_lresolv"
	AC_DEFINE([HAVE_RESOLV_H],1,[have resolv.h])
    else
	AC_MSG_WARN([****** DNS support disabled])
    fi
fi

])


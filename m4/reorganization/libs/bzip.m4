
AC_ARG_ENABLE([bzip2],
[AS_HELP_STRING([--disable-bzip2], [do not include bzip2 support])],
want_bzip2=$enableval, want_bzip2="yes")

bzip_check="ok"
if test "$want_bzip2" = "yes"
then
    AC_LIB_LINKFLAGS([bz2])
    save_LDFLAGS="$LDFLAGS"
    # Only add -L if prefix is not empty
    test -z "$LIBBZ2_PREFIX" || LDFLAGS="$LDFLAGS -L$LIBBZ2_PREFIX/$acl_libdirstem";

    have_bzprefix="no"
    AC_CHECK_LIB([bz2], [BZ2_bzDecompressInit], [have_bzprefix="yes"])
    if test "x$have_bzprefix" = "xno"; then
        AC_DEFINE([NOBZ2PREFIX],1,[bzip funtions do not have bz2 prefix])
    fi
    LDFLAGS="$save_LDFLAGS"
    if test "$HAVE_LIBBZ2" = "yes"; then
	AC_CHECK_HEADER([bzlib.h],
			[AC_C_CVE_2008_1372],
			[ac_cv_c_cve_2008_1372="no"])
	if test "$ac_cv_c_cve_2008_1372" = "bugged"; then
		AC_MSG_WARN([****** bzip2 libraries are affected by the CVE-2008-1372 bug])
		AC_MSG_WARN([****** We strongly suggest you to update to bzip2 1.0.5.])
		AC_MSG_WARN([****** Please do not report stability problems to the ClamAV developers!])
		bzip_check="bugged (CVE-2008-1372)"
	fi
	if test "$ac_cv_c_cve_2008_1372" = "linkfailed"; then
		dnl This shouldn't happen
		dnl We failed to link but libtool may still be able to link, so don't disable bzip2 just yet
		AC_MSG_WARN([****** Unable to link bzip2 testcase])
		AC_MSG_WARN([****** You may be affected by CVE-2008-1372 bug, but I need to be able to link a testcase to verify])
		AC_MSG_WARN([****** It is recommended to fix your build environment so that we can run the testcase!])
		AC_MSG_WARN([****** Please do not report stability problems to the ClamAV developers!])
		bzip_check="link failed (CVE-2008-1372)"
	fi

	case "$ac_cv_c_cve_2008_1372" in
	ok|bugged|linkfailed)
		;;
	*)
		HAVE_LIBBZ2=no
		;;
	esac
    fi

    if test "$HAVE_LIBBZ2" = "yes"; then
	AC_C_CVE_2010_0405
	if test "$ac_cv_c_cve_2010_0405" = "bugged"; then
		AC_MSG_WARN([****** bzip2 libraries are affected by the CVE-2010-0405 bug])
		AC_MSG_WARN([****** We strongly suggest you to update bzip2])
		AC_MSG_WARN([****** Please do not report stability problems to the ClamAV developers!])
		bzip_check="bugged (CVE-2010-0405)"
	fi
	if test "$ac_cv_c_cve_2010_0405" = "linkfailed"; then
		dnl This shouldn't happen
		dnl We failed to link but libtool may still be able to link, so don't disable bzip2 just yet
		AC_MSG_WARN([****** Unable to link bzip2 testcase])
		AC_MSG_WARN([****** You may be affected by CVE-2010-0405 bug, but I need to be able to link a testcase to verify])
		AC_MSG_WARN([****** It is recommended to fix your build environment so that we can run the testcase!])
		AC_MSG_WARN([****** Please do not report stability problems to the ClamAV developers!])
		bzip_check="link failed (CVE-2010-0405)"
	fi

	case "$ac_cv_c_cve_2010_0405" in
	ok|bugged|linkfailed)
		LIBCLAMAV_LIBS="$LIBCLAMAV_LIBS $LTLIBBZ2"
		AC_DEFINE([HAVE_BZLIB_H],1,[have bzip2])
		;;
	*)
		AC_MSG_WARN([****** bzip2 support disabled])
		;;
	esac

    else
	AC_MSG_WARN([****** bzip2 support disabled])
    fi
fi

AM_CONDITIONAL([HAVE_LIBBZ2], test "x$HAVE_LIBBZ2" = "xyes")

dnl change this on a release
dnl VERSION="devel-`date +%Y%m%d`"
VERSION="0.102.0-devel-`date +%Y%m%d`"

dnl libclamav version info
LC_CURRENT=9
LC_REVISION=1
LC_AGE=0
LIBCLAMAV_VERSION="$LC_CURRENT":"$LC_REVISION":"$LC_AGE"
AC_SUBST([LIBCLAMAV_VERSION])

LC_MAJOR=`expr $LC_CURRENT - $LC_AGE`
AC_DEFINE_UNQUOTED([LIBCLAMAV_FULLVER], "$LC_MAJOR.$LC_AGE.$LC_REVISION", ["Full clamav library version number"])
AC_DEFINE_UNQUOTED([LIBCLAMAV_MAJORVER], $LC_MAJOR, ["Major clamav library version number"])

dnl libfreshclam version info
LFC_CURRENT=2
LFC_REVISION=0
LFC_AGE=0
LIBFRESHCLAM_VERSION="$LFC_CURRENT":"$LFC_REVISION":"$LFC_AGE"
AC_SUBST([LIBFRESHCLAM_VERSION])

LFC_MAJOR=`expr $LFC_CURRENT - $LFC_AGE`
AC_DEFINE_UNQUOTED([LIBFRESHCLAM_FULLVER], "$LFC_MAJOR.$LFC_AGE.$LFC_REVISION", ["Full freshclam library version number"])
AC_DEFINE_UNQUOTED([LIBFRESHCLAM_MAJORVER], $LFC_MAJOR, ["Major freshclam library version number"])

AC_DEFINE_UNQUOTED([VERSION],"$VERSION",[Version number of package])
AC_DEFINE_UNQUOTED([VERSION_SUFFIX],"$VERSION_SUFFIX",[Version suffix for package])

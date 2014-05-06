dnl change this on a release
dnl VERSION="devel-`date +%Y%m%d`"
VERSION="0.98.3"

LC_CURRENT=7
LC_REVISION=22
LC_AGE=1
LIBCLAMAV_VERSION="$LC_CURRENT":"$LC_REVISION":"$LC_AGE"
AC_SUBST([LIBCLAMAV_VERSION])

AC_DEFINE_UNQUOTED([LIBCLAMAV_FULLVER], "$major.$LC_AGE.$LC_REVISION",
        ["Full library version number"])

AC_DEFINE_UNQUOTED([LIBCLAMAV_MAJORVER], $major, ["Major library version number"])

AC_DEFINE_UNQUOTED([VERSION],"$VERSION",[Version number of package])
AC_DEFINE_UNQUOTED([VERSION_SUFFIX],"$VERSION_SUFFIX",[Version suffix for package])

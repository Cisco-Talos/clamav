dnl change this on a release
dnl During active development, set: VERSION="<version>-devel-`date +%Y%m%d`"
dnl For beta,                  set: VERSION="<version>-beta"
dnl For release candidate,     set: VERSION="<version>-rc"
dnl For release,               set: VERSION="<version>"
VERSION="0.103.9"

major=`echo $PACKAGE_VERSION |cut -d. -f1 | sed -e "s/[^0-9]//g"`
minor=`echo $PACKAGE_VERSION |cut -d. -f2 | sed -e "s/[^0-9]//g"`
patch=`echo $PACKAGE_VERSION |cut -d. -f3 | cut -d- -f1 | sed -e "s/[^0-9]//g"`

PACKAGE_VERSION_NUM=`printf "0x%02x%02x%02x" "$major" "$minor" "$patch"`
AC_SUBST(PACKAGE_VERSION_NUM)

dnl libclamav version info
LC_CURRENT=9
LC_REVISION=5
LC_AGE=0
LIBCLAMAV_VERSION="$LC_CURRENT":"$LC_REVISION":"$LC_AGE"
AC_SUBST([LIBCLAMAV_VERSION])

LIBCLAMAV_VERSION_NUM=`printf "0x%02x%02x%02x" "$LC_CURRENT" "$LC_REVISION" "$LC_AGE"`
AC_SUBST(LIBCLAMAV_VERSION_NUM)

LC_MAJOR=`expr $LC_CURRENT - $LC_AGE`
AC_DEFINE_UNQUOTED([LIBCLAMAV_FULLVER], "$LC_MAJOR.$LC_AGE.$LC_REVISION", ["Full clamav library version number"])
AC_DEFINE_UNQUOTED([LIBCLAMAV_MAJORVER], $LC_MAJOR, ["Major clamav library version number"])

dnl libfreshclam version info
LFC_CURRENT=2
LFC_REVISION=1
LFC_AGE=0
LIBFRESHCLAM_VERSION="$LFC_CURRENT":"$LFC_REVISION":"$LFC_AGE"
AC_SUBST([LIBFRESHCLAM_VERSION])

LIBFRESHCLAM_VERSION_NUM=`printf "0x%02x%02x%02x" "$LFC_CURRENT" "$LFC_REVISION" "$LFC_AGE"`
AC_SUBST(LIBFRESHCLAM_VERSION_NUM)

LFC_MAJOR=`expr $LFC_CURRENT - $LFC_AGE`
AC_DEFINE_UNQUOTED([LIBFRESHCLAM_FULLVER], "$LFC_MAJOR.$LFC_AGE.$LFC_REVISION", ["Full freshclam library version number"])
AC_DEFINE_UNQUOTED([LIBFRESHCLAM_MAJORVER], $LFC_MAJOR, ["Major freshclam library version number"])

AC_DEFINE_UNQUOTED([VERSION],"$VERSION",[Version number of package])
AC_DEFINE_UNQUOTED([VERSION_SUFFIX],"$VERSION_SUFFIX",[Version suffix for package])

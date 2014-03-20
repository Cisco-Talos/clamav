
want_xml="auto"
AC_ARG_ENABLE([xml],
[  --disable-xml	  disable DMG and XAR support],
want_xml=$enableval, want_xml="auto")

XML_HOME=""
if test "X$want_xml" != "Xno"; then
  AC_MSG_CHECKING([for libxml2 installation])
  AC_ARG_WITH([xml],
  [  --with-xml=DIR	  path to directory containing libxml2 library (default=
			  /usr/local or /usr if not found in /usr/local)],
  [
  if test "$withval"
  then
    XML_HOME="$withval"
    AC_MSG_RESULT([using $XML_HOME])
  else
    AC_MSG_ERROR([cannot assign blank value to --with-xml])
  fi
  ], [
  XML_HOME=/usr/local
  if test ! -x "$XML_HOME/bin/xml2-config"
  then
    XML_HOME=/usr
    if test ! -x "$XML_HOME/bin/xml2-config"
    then
      XML_HOME=""
    fi
  fi
  if test "x$XML_HOME" != "x"; then
    AC_MSG_RESULT([$XML_HOME])
  else
    AC_MSG_RESULT([not found])
  fi
  ])
fi

found_xml="no"
XMLCONF_VERSION=""
XML_CPPFLAGS=""
XML_LIBS=""
if test "x$XML_HOME" != "x"; then
  AC_MSG_CHECKING([xml2-config version])
  XMLCONF_VERSION="`$XML_HOME/bin/xml2-config --version`"
  if test "x%XMLCONF_VERSION" != "x"; then
    AC_MSG_RESULT([$XMLCONF_VERSION])
    found_xml="yes"
    XML_CPPFLAGS="`$XML_HOME/bin/xml2-config --cflags`"
    XML_LIBS="`$XML_HOME/bin/xml2-config --libs`"
  else
    AC_MSG_ERROR([xml2-config failed])
  fi
fi

working_xml="no"
if test "X$found_xml" != "Xno"; then
  AC_MSG_CHECKING([for xmlreader.h in $XML_HOME])

  if test ! -f "$XML_HOME/include/libxml2/libxml/xmlreader.h"; then
    AC_MSG_RESULT([not found])
  else
    AC_MSG_RESULT([found])
    save_LIBS="$LIBS"
    save_CPPFLAGS="$CPPFLAGS"
    CPPFLAGS="$CPPFLAGS $XML_CPPFLAGS"
    save_LDFLAGS="$LDFLAGS"
    LDFLAGS="$LDFLAGS $XML_LIBS"

    AC_CHECK_LIB([xml2], [xmlTextReaderRead], [working_xml="yes"], [working_xml="no"])

    CPPFLAGS="$save_CPPFLAGS"
    LDFLAGS="$save_LDFLAGS"
    LIBS="$save_LIBS"
  fi
fi

if test "$working_xml" = "yes"; then
  AC_DEFINE([HAVE_LIBXML2],1,[Define to 1 if you have the 'libxml2' library (-lxml2).])
  AC_SUBST(XML_CPPFLAGS)
  AC_SUBST(XML_LIBS)
  AC_MSG_NOTICE([Compiling and linking with libxml2 from $XML_HOME])
else
  if test "$want_xml" = "yes"; then
     AC_MSG_ERROR([****** Please install libxml2 packages!])
  else
    if test "$want_xml" != "no"; then
      AC_MSG_NOTICE([****** libxml2 support unavailable])
    fi
  fi
  XML_CPPFLAGS=""
  XML_LIBS=""
  AC_SUBST(XML_CPPFLAGS)
  AC_SUBST(XML_LIBS)
fi

AM_CONDITIONAL([HAVE_LIBXML2], test "x$HAVE_LIBXML2" = "xyes")

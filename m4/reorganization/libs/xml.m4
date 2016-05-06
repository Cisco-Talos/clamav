
want_xml="auto"
AC_ARG_ENABLE([xml],
[AS_HELP_STRING([--disable-xml], [do not include DMG and XAR support])],
    [want_xml=$enableval], [want_xml="auto"])

XML_HOME=""
xmlconfig=""
if test "X$want_xml" != "Xno"; then
  AC_MSG_CHECKING([for libxml2 installation])
  AC_ARG_WITH([xml],
  [AS_HELP_STRING([--with-xml@<:@=DIR@:>@], [path to directory containing libxml2 library
                  @<:@default=/usr/local or /usr if not found in /usr/local@:>@])],
  [if test "x$withval" = x ; then
      AC_MSG_ERROR([cannot assign blank value to --with-xml])
   fi
   with_xml="$withval"
  ],[with_xml="yes"])

  case "$with_xml" in
    yes) AC_PATH_PROG([xmlconfig], [xml2-config])
        if test "x$xmlconfig" = x ; then
            AC_MSG_NOTICE([can not locate xml2-config in PATH, will search default XML_HOME variants])

            AC_MSG_CHECKING([for xml2-config in default XML_HOME locations])
            XML_HOME=/usr/local
            if test ! -x "$XML_HOME/bin/xml2-config"
            then
              XML_HOME=/usr
              if test ! -x "$XML_HOME/bin/xml2-config"
              then
                XML_HOME=""
                AC_MSG_ERROR([not found])
              fi
            fi
        else
            AC_MSG_RESULT(using $xmlconfig as the xml2-config program)
        fi
        ;;
    no) want_xml=no
        AC_MSG_RESULT(not wanted by caller)
        ;;
    *-config)
        xmlconfig="$withval"
        AC_MSG_RESULT(considering $xmlconfig as the xml2-config program)
        ;;
    *) # Path to XML_HOME
        XML_HOME="$withval"
        AC_MSG_RESULT([using XML_HOME=$XML_HOME to look for xml2-config program])
        ;;
  esac
  if test "x$want_xml" != xno ; then
    if test "x$xmlconfig" = "x"; then
      if test "x$XML_HOME" != "x" && test -x "$XML_HOME/bin/xml2-config" ; then
        xmlconfig="$XML_HOME/bin/xml2-config"
        AC_MSG_NOTICE([found xml2-config under $XML_HOME])
      fi
    fi

    if test "x$xmlconfig" != "x" && test -x "$xmlconfig" -a -s "$xmlconfig"; then
      AC_MSG_NOTICE([will use $xmlconfig])
    else
      AC_MSG_ERROR([cannot use '$xmlconfig' value as the xml2-config program])
    fi
  fi
fi

found_xml="no"
XMLCONF_VERSION=""
XML_CPPFLAGS=""
XML_LIBS=""
if test "x$xmlconfig" != "x"; then
  AC_MSG_CHECKING([xml2-config version with $xmlconfig])
  XMLCONF_VERSION="`$xmlconfig --version`"
  if test "x$XMLCONF_VERSION" != "x"; then
    AC_MSG_RESULT([$XMLCONF_VERSION])
    found_xml="yes"
    XML_CPPFLAGS="`$xmlconfig --cflags`"
    XML_LIBS="`$xmlconfig --libs`"
    if test x"$XML_HOME" = x ; then
      XML_HOME="`$xmlconfig --prefix`"
    fi
    if test x"$XML_HOME" = x ; then
      AC_MSG_ERROR([xml2-config failed])
    fi
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

    AC_CHECK_LIB([xml2], [xmlTextReaderRead], [working_xml="yes"], [working_xml="no"], [$XML_LIBS])

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

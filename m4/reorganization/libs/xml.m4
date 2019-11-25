with_xml_val="yes"
want_xml="auto"
AC_ARG_ENABLE([xml],
[AS_HELP_STRING([--disable-xml], [do not include DMG and XAR support])],
want_xml=$enableval, want_xml="auto")

if test "X$want_xml" != "Xno"; then
    PKG_CHECK_MODULES([XML], [libxml-2.0],
	[found_xml=yes],
	[
	    found_xml=no
	    AS_IF([test "x$want_xml" = xyes],
		[AC_MSG_ERROR([--enable-xml set but cannot find libxml2])]
	    )
	]
    )

  working_xml="no"
  if test "X$found_xml" != "Xno"; then
    XML_HOME=$(${PKG_CONFIG} --variable prefix libxml-2.0)
    AC_MSG_CHECKING([for xmlreader.h in $readerresult])

    if test ! -f "$XML_HOME/include/libxml2/libxml/xmlreader.h"; then
      AC_MSG_RESULT([not found])
    else
      AC_MSG_RESULT([found])
      save_LIBS="$LIBS"
      save_CPPFLAGS="$CPPFLAGS"
      XML_CPPFLAGS="$XML_CFLAGS"
      CPPFLAGS="$CPPFLAGS $XML_CPPFLAGS"
      save_LDFLAGS="$LDFLAGS"
      LDFLAGS="$LDFLAGS $XML_LIBS"

      AS_ECHO("CPPFLAGS: $CPPFLAGS")
      AS_ECHO("LD_FLAGS: $LDFLAGS")

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
      AC_MSG_NOTICE([****** libxml2 support unavailable])
    fi
    XML_CPPFLAGS=""
    XML_LIBS=""
    AC_SUBST(XML_CPPFLAGS)
    AC_SUBST(XML_LIBS)
  fi
fi

AM_CONDITIONAL([HAVE_LIBXML2], test "x$HAVE_LIBXML2" = "xyes")

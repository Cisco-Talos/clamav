AC_ARG_ENABLE([milter],
[AS_HELP_STRING([--enable-milter], [build clamav-milter])],
have_milter=$enableval, have_milter="no")

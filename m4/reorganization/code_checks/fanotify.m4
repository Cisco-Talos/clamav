AC_ARG_ENABLE([fanotify],
[AS_HELP_STRING([--disable-fanotify], [do not add fanotify support (Linux only)])],
want_fanotify=$enableval, want_fanotify="yes")
have_fanotify="no"

dnl Check for OpenSSL
AC_MSG_CHECKING([for OpenSSL installation])

AC_ARG_WITH([openssl],
[  --with-openssl=DIR   path to directory containing openssl (default=
    /usr/local or /usr if not found in /usr/local)],
[
if test "$withval"; then
    LIBSSL_HOME="$withval"
fi
], [
LIBSSL_HOME=/usr/local
if test ! -f "$LIBSSL_HOME/include/openssl/ssl.h"
then
    LIBSSL_HOME=/usr
fi
AC_MSG_RESULT([$LIBSSL_HOME])
])

if test ! -f "$LIBSSL_HOME/include/openssl/ssl.h"
then
    AC_MSG_ERROR([OpenSSL not found.])
fi

SSL_LDFLAGS="-L$LIBSSL_HOME/lib -lssl -lcrypto"
SSL_CPPFLAGS="-I$LIBSSL_HOME/include"

save_LDFLAGS="$LDFLAGS"
LDFLAGS="-L$LIBSSL_HOME/lib -lssl -lcrypto"

have_ssl="no"
have_crypto="no"

AC_CHECK_LIB([ssl], [SSL_library_init], [have_ssl="yes"], [AC_MSG_ERROR([Your OpenSSL installation is misconfigured or missing])])

AC_CHECK_LIB([crypto], [EVP_EncryptInit], [have_crypto="yes"], [AC_MSG_ERROR([Your OpenSSL installation is misconfigured or missing])])

if test "x$have_ssl" = "xyes"; then
    LIBCLAMAV_LIBS="$SSL_LDFLAGS $LIBCLAMAV_LIBS"
    CLAMSCAN_LIBS="$SSL_LDFLAGS $CLAMSCAN_LIBS"
    FRESHCLAM_LIBS="$SSL_LDFLAGS $FRESHCLAM_LIBS"
    CLAMD_LIBS="$SSL_LDFLAGS $CLAMD_LIBS"
    CLAMDSCAN_LIBS="$SSL_LDFLAGS $CLAMDSCAN_LIBS"
    SIGTOOL_LIBS="$SSL_LDFLAGS $SIGTOOL_LIBS"

    LIBCLAMAV_CPPFLAGS="$SSL_CPPFLAGS $LIBCLAMAV_CPPFLAGS"
    CLAMSCAN_CPPFLAGS="$SSL_CPPFLAGS $CLAMSCAN_CPPFLAGS"
    FRESHCLAM_CPPFLAGS="$SSL_CPPFLAGS $FRESHCLAM_CPPFLAGS"
    CLAMD_CPPFLAGS="$SSL_CPPFLAGS $CLAMD_CPPFLAGS"
    CLAMDSCAN_CPPFLAGS="$SSL_CPPFLAGS $CLAMDSCAN_CPPFLAGS"
    SIGTOOL_CPPFLAGS="$SSL_CPPFLAGS $SIGTOOL_CPPFLAGS"
fi

LDFLAGS="$save_LDFLAGS"

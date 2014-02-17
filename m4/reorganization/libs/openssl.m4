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

SSL_LDFLAGS="-L$LIBSSL_HOME/lib -lssl"
SSL_CPPFLAGS="-I$LIBSSL_HOME/include"

save_LDFLAGS="$LDFLAGS"
LDFLAGS="-L$LIBSSL_HOME/lib -lssl"
AC_CHECK_LIB([ssl], [SSL_library_init], [LIBCLAMAV_LIBS="$LIBCLAMAV_LIBS $SSL_LDFLAGS"],
        [AC_MSG_ERROR([Your OpenSSL is misconfigured])])

LDFLAGS="-L$LIBSSL_HOME/lib -lcrypto"
AC_CHECK_LIB([crypto], [EVP_EncryptInit], [LIBCLAMAV_LIBS="$LIBCLAMAV_LIBS -lcrypto"],
        [AC_MSG_ERROR([Your OpenSSL installation is misconfigured])])

LDFLAGS="$save_LDFLAGS"

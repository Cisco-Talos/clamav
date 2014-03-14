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

SSL_LDFLAGS="-L$LIBSSL_HOME/lib"
SSL_LIBS="-lssl -lcrypto"
SSL_CPPFLAGS="-I$LIBSSL_HOME/include"

save_LDFLAGS="$LDFLAGS"
LDFLAGS="-L$LIBSSL_HOME/lib $SSL_LIBS"

save_CFLAGS="$CFLAGS"
CFLAGS="$SSL_CPPFLAGS"

have_ssl="no"
have_crypto="no"

AC_CHECK_LIB([ssl], [SSL_library_init], [have_ssl="yes"], [AC_MSG_ERROR([Your OpenSSL installation is misconfigured or missing])])

AC_CHECK_LIB([crypto], [EVP_EncryptInit], [have_crypto="yes"], [AC_MSG_ERROR([Your OpenSSL installation is misconfigured or missing])])

LDFLAGS="$save_LDFLAGS"
CFLAGS="$save_CFLAGS"

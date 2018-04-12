dnl Check for OpenSSL
AC_MSG_CHECKING([for OpenSSL installation])

AC_ARG_WITH([openssl],
[AS_HELP_STRING([--with-openssl@<:@=DIR@:>@], [path to directory containing openssl
                @<:@default=/usr/local or /usr if not found in /usr/local@:>@])],
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

save_LDFLAGS="$LDFLAGS"
save_CFLAGS="$CFLAGS"
save_LIBS="$LIBS"

SSL_LIBS="$LIBS -lssl -lcrypto -lz"
LIBS="$LIBS $SSL_LIBS"

if test "$LIBSSL_HOME" != "/usr"; then
    SSL_LDFLAGS="-L$LIBSSL_HOME/lib"
    SSL_CPPFLAGS="-I$LIBSSL_HOME/include"
    LDFLAGS="-L$LIBSSL_HOME/lib"
    CFLAGS="$SSL_CPPFLAGS"
else
    SSL_LDFLAGS=""
    SSL_CPPFLAGS=""
fi

have_ssl="no"
have_crypto="no"

AC_LINK_IFELSE(
	       [AC_LANG_PROGRAM([[#include <openssl/bn.h>]],
				[[BN_CTX_new();]])],
	       [have_ssl="yes";],
	       [AC_MSG_ERROR([Your OpenSSL installation is misconfigured or missing])])


AC_CHECK_LIB([crypto], [CRYPTO_free], [have_crypto="yes"], [AC_MSG_ERROR([Your OpenSSL installation is misconfigured or missing])], [-lcrypto -lz])

dnl OpenSSL 0.9.8 is the minimum required version due to X509_VERIFY_PARAM
AC_CHECK_LIB([ssl], [X509_VERIFY_PARAM_new], [], [AC_MSG_ERROR([Your OpenSSL installation is missing the X509_VERIFY_PARAM function. Please upgrade to a more recent version of OpenSSL.])], [-lcrypto -lz])

LDFLAGS="$save_LDFLAGS"
CFLAGS="$save_CFLAGS"
LIBS="$save_LIBS"

AC_DEFUN([AC_C_OPENSSL],[
	dnl Checking for openssl libs and headers
	AC_CHECK_LIB([ssl], [BIO_new], [LIBS="$LIBS -lssl"], [AC_MSG_ERROR([Please install openssl-dev])])
	AC_CHECK_HEADER([openssl/x509.h], [], [AC_MSG_ERROR([Please install openssl-dev]) ])
	]
)


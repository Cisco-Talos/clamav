AC_DEFUN([AC_C_MYSQL],[
	dnl Checking for mysql libs and headers
	AC_CHECK_LIB([mysqlclient], [mysql_query], [LIBS="$LIBS -lmysqlclient"], [AC_MSG_ERROR([Please install libmysqlclient-dev])])
	AC_CHECK_HEADER([mysql/mysql.h], [AC_DEFINE([HAVE_MYSQL_MYSQL_H], 1, [mysql/mysql.h])], [AC_CHECK_HEADER([mysql.h], [AC_DEFINE([HAVE_MYSQL_H], 1, [mysql.h])], [AC_MSG_ERROR([Please install libmysqlclient-dev])]) ])
	]
)


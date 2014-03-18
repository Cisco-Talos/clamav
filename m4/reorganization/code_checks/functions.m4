AX_CHECK_UNAME_SYSCALL
AC_CHECK_LIB([socket], [bind], [LIBS="$LIBS -lsocket"; CLAMAV_MILTER_LIBS="$CLAMAV_MILTER_LIBS -lsocket"; FRESHCLAM_LIBS="$FRESHCLAM_LIBS -lsocket"; CLAMD_LIBS="$CLAMD_LIBS -lsocket"])
AC_SEARCH_LIBS([gethostent],[nsl], [(LIBS="$LIBS -lnsl"; CLAMAV_MILTER_LIBS="$CLAMAV_MILTER_LIBS -lnsl"; FRESHCLAM_LIBS="$FRESHCLAM_LIBS -lnsl"; CLAMD_LIBS="$CLAMD_LIBS -lnsl")])

AC_CHECK_FUNCS([poll setsid memcpy snprintf vsnprintf strerror_r strlcpy strlcat strcasestr inet_ntop setgroups initgroups ctime_r mkstemp mallinfo madvise])
AC_FUNC_FSEEKO

dnl Check if anon maps are available, check if we can determine the page size
AC_C_FUNC_MMAP_PRIVATE
AC_C_FUNC_PAGESIZE
AC_C_FUNC_MMAP_ANONYMOUS

AC_CHECK_FUNCS([enable_extended_FILE_stdio])

AC_CHECK_FUNCS([timegm])
AC_CHECK_FUNCS([sysctlbyname])

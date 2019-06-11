AC_ARG_ENABLE(clamonacc,
	     [AC_HELP_STRING([--enable-clamonacc], [build clamonacc tool @<:@default=auto@:>@])],
[enable_clamonacc=$enableval], [enable_clamonacc="auto"])

if test "$enable_clamonacc" != "no"; then
	AC_CANONICAL_HOST

        case "${host_os}" in

        	linux*)
			LIBCURL_CHECK_CONFIG(
			[],
			[7.40.0],
			[$enable_clamonacc="yes"], 
			[AC_MSG_ERROR([Your libcurl (e.g. libcurl-devel) is too old. ClamAV requires libcurl 7.40 or higher.]])
			)
			dnl AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <curl/curl.h>]],[[
			dnl	int x;
			dnl	curl_easy_setopt(NULL,CURLOPT_URL,NULL);
			dnl	x=CURLOPT_UNIX_SOCKET_PATH;
			dnl	if (x) {;}]])],$enable_clamonacc="yes", AC_MSG_ERROR([Your libcurl (e.g. libcurl-devel) is too old. ClamAV requires libcurl 7.40 or higher.]))
			;;
		*)
			if test "$enable_clamonacc" == "yes"; then
				AC_MSG_ERROR([Clamonacc was explicitly requested, but the platform ($host_os) you are trying to build on is not currently supported for this tool.])
			fi
                        ;;
	esac
fi


AM_CONDITIONAL([BUILD_CLAMONACC], [test x$enable_clamonacc == xyes])

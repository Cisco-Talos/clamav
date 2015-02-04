AC_ARG_ENABLE([mempool],[AS_HELP_STRING([--disable-mempool], [do not use memory pools])], enable_mempool=$enableval, enable_mempool="yes")
have_mempool="no"
if test "$enable_mempool" = "yes"; then
	if test "$ac_cv_c_mmap_private" != "yes"; then
		AC_MSG_NOTICE([****** mempool support disabled (mmap not available or not usable)])
	else
		if test "$ac_cv_c_can_get_pagesize" != "yes"; then
			AC_MSG_NOTICE([****** mempool support disabled (pagesize cannot be determined)])
		else
			if test "$ac_cv_c_mmap_anonymous" = "no"; then
				AC_MSG_NOTICE([****** mempool support disabled (anonymous mmap not available)])
			else
				AC_DEFINE([USE_MPOOL],1,[enable memory pools])
				have_mempool="yes"
			fi
		fi
	fi
fi

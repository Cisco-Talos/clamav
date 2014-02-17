dnl Linker feature checks
dnl check for version script support in the linker (GNU ld, or Solaris ld style)
AC_CACHE_CHECK([for ld --version-script], [ac_cv_ld_version_script], [dnl
  cat > conftest.c <<EOF
void cl_symbol1(void) {}
void cli_symbol2(void) {}
EOF
  cat > conftest.map <<EOF
RELEASE
{
	global:
		cl_*;
	local:
		*;
};
PRIVATE
{
	global:
		cli_*;
	local:
		*;
};
EOF
  dnl check for GNU ld style linker version script
  if AC_TRY_COMMAND([${CC-cc} $CFLAGS $pic_flag $LDFLAGS -shared
				-o conftest.so conftest.c
				-Wl,--version-script,conftest.map
		       1>&AS_MESSAGE_LOG_FD]);
  then
      VERSIONSCRIPTFLAG=--version-script
      ac_cv_ld_version_script=yes
  else
	dnl check for Solaris ld style linker version script
	if AC_TRY_COMMAND([${CC-cc} $CFLAGS $pic_flag $LDFLAGS -shared
				-o conftest.so conftest.c
				-Wl,-M,conftest.map
			1>&AS_MESSAGE_LOG_FD]);
	then
		VERSIONSCRIPTFLAG=-M
		ac_cv_ld_version_script=yes;
	else
		ac_cv_ld_version_script=no
	fi
  fi
 rm -f conftest*])
AC_SUBST([VERSIONSCRIPTFLAG])
AM_CONDITIONAL([VERSIONSCRIPT], test "x$ac_cv_ld_version_script" = "xyes")

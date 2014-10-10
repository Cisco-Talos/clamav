AC_ARG_WITH([system-llvm], AC_HELP_STRING([--with-system-llvm],
[Use system llvm instead of built-in, uses full path to llvm-config (default=
/usr/local or /usr if not found in /usr/local)]),
[case "$withval" in
  yes)
    system_llvm="default"
    ;;
  no)
    system_llvm="built-in"
    ;;
  *)
    system_llvm=$withval
 esac
], [system_llvm="built-in"])

AC_ARG_ENABLE([llvm],AC_HELP_STRING([--enable-llvm],
[Enable 'llvm' JIT/verifier support @<:@default=auto@:>@]),
[enable_llvm=$enableval],
[
if test "x$system_llvm" != "xbuilt-in"; then
    enable_llvm="yes"
else
    enable_llvm="auto"
fi
])

if test "$enable_llvm" != "no"; then
    dnl Try to configure subdir, optionally
    AC_CONFIG_SUBDIRS_OPTIONAL([libclamav/c++])
else
    system_llvm="none"
fi

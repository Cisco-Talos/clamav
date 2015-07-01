AC_ARG_WITH([system-llvm], [AC_HELP_STRING([--with-system-llvm],
[use system llvm instead of built-in, uses full path to llvm-config
@<:@default=/usr/local or /usr if not found in /usr/local@:>@])],
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

AC_ARG_WITH([llvm-linking], [AC_HELP_STRING([--with-llvm-linking],
[specifies method to linking llvm @<:@static|dynamic@:>@, only valid with --with-system-llvm])],
[
if test "x$system_llvm" = "xbuilt-in"; then
   AC_MSG_ERROR([Failed to configure LLVM, and LLVM linking was specified without specifying system-llvm])  
else
case "$withval" in
  static)
    llvm_linking="static"
    ;;
  dynamic)
    llvm_linking="dynamic"
    ;;
  *)
    AC_MSG_ERROR([Invalid argument to --with-llvm-linking])
esac
fi
], [
if test "x$system_llvm" = "xbuilt-in"; then
   llvm_linking=""
else
   llvm_linking="auto"
fi
])

AC_ARG_ENABLE([llvm],AC_HELP_STRING([--enable-llvm],
[enable 'llvm' JIT/verifier support @<:@default=auto@:>@]),
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
    llvm_linking=""
fi

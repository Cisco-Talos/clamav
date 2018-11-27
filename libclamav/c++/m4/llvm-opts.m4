dnl Act as a single handler point for LLVM options
dnl Assigns enable_llvm, system_llvm, llvm_linking, and llvmver variables
dnl Assigns llvmoptserrmsg variable on error

dnl Determine if LLVM is requested (or auto, reassigned if system-llvm specified)
dnl Overrides "auto" with "yes" if a system-llvm is specified
AC_ARG_ENABLE([llvm],AC_HELP_STRING([--enable-llvm],
[enable 'llvm' JIT/verifier support @<:@default=auto@:>@]),
[enable_llvm=$enableval], [enable_llvm="auto"])

if test "$enable_llvm" != "no"; then

dnl Determine whether to user built in LLVM or to use system-specified LLVM
dnl locate the llvmconfig program
AC_ARG_WITH([system-llvm], AC_HELP_STRING([--with-system-llvm],
[Specify system llvm location or to use old package, uses full path to llvm-config or bin directory
     (default=search PATH environment variable)]),
[system_llvm=$withval; if test "$enable_llvm" = "auto"; then enable_llvm="yes"; fi], [system_llvm="yes"])

case "$system_llvm" in
  yes)
     AC_PATH_PROG([llvmconfig], [llvm-config])
     if test "x$llvmconfig" = "x"; then
         llvmoptserrmsg="llvm-config cannot be found within PATH"
     fi
     ;;
  no) ;;
  *)
     if test -d "$withval"; then
         AC_PATH_PROG([llvmconfig], [llvm-config], [], [$withval/bin])
     else
         llvmconfig=$withval
         if test ! -x "$llvmconfig"; then
             llvmconfig=""
         fi
     fi

     if test "x$llvmconfig" = "x"; then
         llvmoptserrmsg="llvm-config does not exist at $withval"
     fi
     ;;
esac

if test "x$llvmconfig" != "x"; then

dnl Determine linking method to external LLVM, built-in only does static linking
AC_ARG_WITH([llvm-linking], [AC_HELP_STRING([--with-llvm-linking],
[specifies method to linking llvm @<:@static|dynamic@:>@, only valid with --with-system-llvm])],
[if test "x$llvmconfig" = "x"; then
   AC_MSG_ERROR([Failed to configure LLVM, and LLVM linking was specified without valid llvm-config])
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
], [llvm_linking="dynamic"])

llvmver=`$llvmconfig --version`

else dnl test "x$llvmconfig" != "x"

llvmver="2.8"
system_llvm="internal"

fi dnl test "x$llvmconfig" != "x"

fi dnl test "enable_llvm" != "no

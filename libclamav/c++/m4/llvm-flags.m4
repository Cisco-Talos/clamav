dnl Act as a single handler point for LLVM options
dnl Compile a set of compile and linker flags for LLVM
dnl Populates LLVMCONFIG_CXXFLAGS, LLVMCONFIG_LDFLAGS, LLVMCONFIG_LIBS, and LLVMCONFIG_LIBFILES macros
dnl Assigns llvmver_int, system_llvm, llvm_linking, and enable_llvm variables (for tracking in features summary)

dnl Determine if LLVM is requested (or auto, reassigned if system-llvm specified)
AC_ARG_ENABLE([llvm],AC_HELP_STRING([--enable-llvm],
[enable 'llvm' JIT/verifier support @<:@default=auto@:>@]),
[enable_llvm=$enableval], [enable_llvm="auto"])

dnl Determine whether to user built in LLVM or to use system-specified LLVM
dnl locate the llvmconfig program
AC_ARG_WITH([system-llvm], AC_HELP_STRING([--with-system-llvm],
[Use system llvm instead of built-in, uses full path to llvm-config or bin directory
     (default=search PATH environment variable)]),
[case "$withval" in
  yes)
     AC_PATH_PROG([llvmconfig], [llvm-config])
     if test "x$llvmconfig" = "x"; then
         AC_MSG_ERROR([llvm-config cannot be found within PATH])
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
         AC_MSG_ERROR([llvm-config does not exist at $withval])
     fi
     ;;
  esac
])

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
], [llvm_linking=""])

dnl Version number check
if test "x$llvmconfig" != "x"; then
    llvmver=`$llvmconfig --version`
    AC_MSG_NOTICE([Using external LLVM])
else
    llvmver="2.8"
    packaged_llvm="yes"
fi

llvmver_val=`echo "$llvmver" | sed -e 's/svn//g'`
AC_CANONICAL_HOST
case $host_os in
  darwin* )
    llvmver_sval=`echo "$llvmver_val" | sed -Ee 's/[[0-9]]+//' | sed -e 's/^\.//'`
    llvmver_major=`echo "$llvmver_val"  | sed -Ee 's/([[0-9]]+).*/\1/'`
    llvmver_minor=`echo "$llvmver_sval" | sed -Ee 's/([[0-9]]+).*/\1/'`
    llvmver_patch=`echo "$llvmver_sval" | sed -Ee 's/[[0-9]]+//' | sed -e 's/^\.//' | sed -Ee 's/([[0-9]]+).*/\1/'`
    ;;
  *)
    llvmver_sval=`echo "$llvmver_val" | sed -re 's/[[0-9]]+//' | sed -e 's/^\.//'`
    llvmver_major=`echo "$llvmver_val"  | sed -re 's/([[0-9]]+).*/\1/'`
    llvmver_minor=`echo "$llvmver_sval" | sed -re 's/([[0-9]]+).*/\1/'`
    llvmver_patch=`echo "$llvmver_sval" | sed -re 's/[[0-9]]+//' | sed -e 's/^\.//' | sed -re 's/([[0-9]]+).*/\1/'`
    ;;
esac
dnl suffix unused as of LLVM 3.4.1
llvmver_suffix=
if test "x$llvmver_patch" = "x"; then
    llvmver_patch=0
fi

AC_MSG_CHECKING([for supported LLVM version])
llvmver_test=${llvmver_major}${llvmver_minor}${llvmver_patch}
if test "x$packaged_llvm" = "xyes"; then
    AC_MSG_RESULT([ok ($llvmver)])
elif test $llvmver_test -lt 290; then
    AC_MSG_RESULT([no ($llvmver)])
    AC_MSG_ERROR([LLVM >= 2.9 required, but "$llvmver"($llvmver_test) found])
elif test $llvmver_test -lt 360; then
    llvmcomp="jit nativecodegen scalaropts ipo"
    AC_MSG_RESULT([ok ($llvmver)])
elif test $llvmver_test -lt 370; then
    dnl LLVM 3.6.0 removed jit, so we have to use mcjit
    dnl and we're using InitializeNativeTargetAsmParser, so we need the architecture specific parsers
    llvmcomp="mcjit nativecodegen scalaropts ipo x86asmparser powerpcasmparser"
    AC_MSG_RESULT([ok ($llvmver)])
else
    AC_MSG_RESULT([no ($llvmver)])
    AC_MSG_ERROR([LLVM < 3.7 required, but "$llvmver"($llvmver_test) found])
fi

dnl aquire the required flags to properly link in external LLVM
if test "x$llvmconfig" != "x"; then
    AC_SUBST(LLVMCONFIG_CXXFLAGS, [`$llvmconfig --cxxflags`])

    if test "x$llvm_linking" = "xdynamic"; then
        AC_SUBST(LLVMCONFIG_LDFLAGS, [`$llvmconfig --ldflags`])
        AC_SUBST(LLVMCONFIG_LIBS, [-lLLVM-$llvmver])
        AC_SUBST(LLVMCONFIG_LIBFILES, [])
    else
        if test $llvmver_test -ge 350; then
           dnl LLVM 3.5.0 and after splits linker flags into two sets
           ldflags=`$llvmconfig --ldflags`
           syslibs=`$llvmconfig --system-libs`
           AC_SUBST(LLVMCONFIG_LDFLAGS, ["$ldflags $syslibs"])
        else
           AC_SUBST(LLVMCONFIG_LDFLAGS, [`$llvmconfig --ldflags`])
        fi
        AC_SUBST(LLVMCONFIG_LIBS, [`$llvmconfig --libs $llvmcomp`])
        AC_SUBST(LLVMCONFIG_LIBFILES, [`$llvmconfig --libfiles $llvmcomp`])
    fi

    AC_MSG_NOTICE([CXXFLAGS from llvm-config: $LLVMCONFIG_CXXFLAGS])
    AC_MSG_NOTICE([LDFLAGS from llvm-config: $LLVMCONFIG_LDFLAGS])
    AC_MSG_NOTICE([LIBS from llvm-config: $LLVMCONFIG_LIBS])
fi
dnl patch does not affect clamav source (yet)
llvmver_int=${llvmver_major}${llvmver_minor}

dnl @synopsis AC_CREATE_TARGET_H [(HEADER-FILE [,PREFIX)]
dnl
dnl create the header-file and let it contain '#defines'
dnl for the target platform. This macro is used for libraries
dnl that have platform-specific quirks. Instead of inventing a
dnl target-specific target.h.in files, just let it create a
dnl header file from the definitions of AC_CANONICAL_SYSTEM
dnl and put only ifdef's in the installed header-files.
dnl
dnl if the HEADER-FILE is absent, [target.h] is used.
dnl if the PREFIX is absent, [TARGET] is used. 
dnl the prefix can be the packagename. (y:a-z-:A-Z_:)
dnl
dnl the defines look like...
dnl
dnl #ifndef TARGET_CPU_M68K
dnl #define TARGET_CPU_M68K "m68k"
dnl #endif
dnl
dnl #ifndef TARGET_OS_LINUX
dnl #define TARGET_OS_LINUX "linux-gnu"
dnl #endif
dnl
dnl #ifndef TARGET_OS_TYPE                     /* the string itself */
dnl #define TARGET_OS_TYPE "linux-gnu"
dnl #endif
dnl 
dnl detail:  in the case of hppa1.1, the three idents "hppa1_1" "hppa1" 
dnl and "hppa"  are derived, for an m68k it just two, "m68k" and "m"
dnl
dnl the CREATE_TARGET_H__ variant is almost the same function, but everything 
dnl is lowercased instead of uppercased, and there is a "__" in front of
dnl each prefix, so it looks like...
dnl 
dnl #ifndef __target_os_linux
dnl #define __target_os_linux "linux-gnulibc2"
dnl #endif
dnl
dnl #ifndef __target_os__                     /* the string itself */
dnl #define __target_os__ "linux-gnulibc2"
dnl #endif
dnl
dnl #ifndef __target_cpu_i586
dnl #define __target_cpu_i586 "i586"
dnl #endif
dnl
dnl #ifndef __target_arch_i386                
dnl #define __target_arch_i386 "i386"
dnl #endif
dnl
dnl #ifndef __target_arch__                   /* cpu family arch */
dnl #define __target_arch__ "i386"
dnl #endif
dnl
dnl other differences: the default string-define is "__" insteadof "_TYPE" 
dnl
dnl personally I prefer the second variant (which had been the first in
dnl the devprocess of this file but I assume people will often fallback
dnl to the primary variant presented herein).
dnl
dnl NOTE: CREATE_TARGET_H does also fill HOST_OS-defines
dnl functionality has been split over functions called CREATE_TARGET_H_UPPER 
dnl CREATE_TARGET_H_LOWER CREATE_TARGET_HOST_UPPER CREATE_TARGET_HOST_LOWER
dnl CREATE_TARGET_H  uses CREATE_TARGET_H_UPPER    CREATE_TARGET_HOST_UPPER
dnl CREATE_TARGET_H_ uses CREATE_TARGET_H_LOWER    CREATE_TARGET_HOST_LOWER
dnl
dnl there is now a CREATE_PREFIX_TARGET_H in this file as a shorthand for
dnl PREFIX_CONFIG_H from a target.h file, however w/o the target.h ever created
dnl (the prefix is a bit different, since we add an extra -target- and -host-)
dnl 
dnl @version: $Id: acinclude.m4,v 1.8 2006/12/22 19:45:32 acab Exp $
dnl @author Guido Draheim <guidod@gmx.de>                 STATUS: used often

AC_DEFUN([AC_CREATE_TARGET_H],
[AC_REQUIRE([AC_CANONICAL_CPU_ARCH])
AC_CREATE_TARGET_H_UPPER($1,$2)
AC_CREATE_TARGET_HOST_UPPER($1,$2)
])

AC_DEFUN([AC_CREATE_TARGET_OS_H],
[AC_REQUIRE([AC_CANONICAL_CPU_ARCH])
AC_CREATE_TARGET_H_LOWER($1,$2)
AC_CREATE_TARGET_HOST_LOWER($1,$2)
])

AC_DEFUN([AC_CREATE_TARGET_H__],
[AC_REQUIRE([AC_CANONICAL_CPU_ARCH])
AC_CREATE_TARGET_H_LOWER($1,$2)
AC_CREATE_TARGET_HOST_LOWER($1,$2)
])

dnl [(OUT-FILE [, PREFIX])]  defaults: PREFIX=$PACKAGE OUTFILE=$PREFIX-target.h
AC_DEFUN([AC_CREATE_PREFIX_TARGET_H],[dnl
ac_prefix_conf_PKG=`echo ifelse($2, , $PACKAGE, $2)`
ac_prefix_conf_OUT=`echo ifelse($1, , $ac_prefix_conf_PKG-target.h, $1)`
ac_prefix_conf_PRE=`echo $ac_prefix_conf_PKG-target | sed -e 'y:abcdefghijklmnopqrstuvwxyz-:ABCDEFGHIJKLMNOPQRSTUVWXYZ_:'`
AC_CREATE_TARGET_H_UPPER($ac_prefix_conf_PRE,$ac_perfix_conf_OUT)
ac_prefix_conf_PRE=`echo __$ac_prefix_conf_PKG-host | sed -e 'y:abcdefghijklmnopqrstuvwxyz-:ABCDEFGHIJKLMNOPQRSTUVWXYZ_:'`
AC_CREATE_TARGET_HOST_UPPER($ac_prefix_conf_PRE,$ac_perfix_conf_OUT)
])

dnl [(OUT-FILE[, PREFIX])]  defaults: PREFIX=$PACKAGE OUTFILE=$PREFIX-target.h
AC_DEFUN([AC_CREATE_PREFIX_TARGET_H_],[dnl
ac_prefix_conf_PKG=`echo ifelse($2, , $PACKAGE, $2)`
ac_prefix_conf_OUT=`echo ifelse($1, , $ac_prefix_conf_PKG-target.h, $1)`
ac_prefix_conf_PRE=`echo __$ac_prefix_conf_PKG-target | sed -e 'y:ABCDEFGHIJKLMNOPQRSTUVWXYZ-:abcdefghijklmnopqrstuvwxyz_:'`
AC_CREATE_TARGET_H_LOWER($ac_prefix_conf_PRE,$ac_perfix_conf_OUT)
ac_prefix_conf_PRE=`echo __$ac_prefix_conf_PKG-host | sed -e 'y:ABCDEFGHIJKLMNOPQRSTUVWXYZ-:abcdefghijklmnopqrstuvwxyz_:'`
AC_CREATE_TARGET_HOST_LOWER($ac_prefix_conf_PRE,$ac_perfix_conf_OUT)
])

AC_DEFUN([AC_CREATE_TARGET_H_FILE],[dnl
ac_need_target_h_file_new=true
])

AC_DEFUN([AC_CREATE_TARGET_H_UPPER],
[AC_REQUIRE([AC_CANONICAL_CPU_ARCH])
AC_REQUIRE([AC_CREATE_TARGET_H_FILE])
changequote({, })dnl
ac_need_target_h_file=ifelse($1, , target.h, $1)
ac_need_target_h_prefix=`echo ifelse($2, , target, $2) | sed -e 'y:abcdefghijklmnopqrstuvwxyz-:ABCDEFGHIJKLMNOPQRSTUVWXYZ_:' -e 's:[^A-Z0-9_]::g'`
#
target_os0=`echo "$target_os"  | sed -e 'y:abcdefghijklmnopqrstuvwxyz.-:ABCDEFGHIJKLMNOPQRSTUVWXYZ__:' -e 's:[^A-Z0-9_]::g'`
target_os1=`echo "$target_os0" | sed -e 's:\([^0-9]*\).*:\1:' `
target_os2=`echo "$target_os0" | sed -e 's:\([^_]*\).*:\1:' `
target_os3=`echo "$target_os2" | sed -e 's:\([^0-9]*\).*:\1:' `
#
target_cpu0=`echo "$target_cpu"  | sed -e 'y:abcdefghijklmnopqrstuvwxyz.-:ABCDEFGHIJKLMNOPQRSTUVWXYZ__:' -e 's:[^A-Z0-9_]::g'`
target_cpu1=`echo "$target_cpu0" | sed -e 's:\([^0-9]*\).*:\1:' `
target_cpu2=`echo "$target_cpu0" | sed -e 's:\([^_]*\).*:\1:' `
target_cpu3=`echo "$target_cpu2" | sed -e 's:\([^0-9]*\).*:\1:' `
#
target_cpu_arch0=`echo "$target_cpu_arch" | sed -e 'y:abcdefghijklmnopqrstuvwxyz:ABCDEFGHIJKLMNOPQRSTUVWXYZ:'`
#
changequote([, ])dnl
#
if $ac_need_target_h_file_new ; then
AC_MSG_RESULT(creating $ac_need_target_h_file - canonical system defines)
echo /'*' automatically generated by $PACKAGE configure '*'/ >$ac_need_target_h_file
echo /'*' on `date` '*'/ >>$ac_need_target_h_file
ac_need_target_h_file_new=false
fi
echo /'*' target uppercase defines '*'/ >>$ac_need_target_h_file
dnl
old1=""
old2=""
for i in $target_os0 $target_os1 $target_os2 $target_os3 "TYPE"
do
  if test "$old1" != "$i"; then
  if test "$old2" != "$i"; then
   echo " " >>$ac_need_target_h_file
   echo "#ifndef "$ac_need_target_h_prefix"_OS_"$i >>$ac_need_target_h_file
   echo "#define "$ac_need_target_h_prefix"_OS_"$i '"'"$target_os"'"' >>$ac_need_target_h_file
   echo "#endif" >>$ac_need_target_h_file
  fi
  fi
  old2="$old1"
  old1="$i"
done
#
old1=""
old2=""
for i in $target_cpu0 $target_cpu1 $target_cpu2 $target_cpu3 "TYPE" 
do
  if test "$old1" != "$i"; then
  if test "$old2" != "$i"; then
   echo " " >>$ac_need_target_h_file
   echo "#ifndef "$ac_need_target_h_prefix"_CPU_"$i >>$ac_need_target_h_file
   echo "#define "$ac_need_target_h_prefix"_CPU_"$i '"'"$target_cpu"'"' >>$ac_need_target_h_file
   echo "#endif" >>$ac_need_target_h_file
  fi
  fi
  old2="$old1"
  old1="$i"
done
#
old1=""
old2=""
for i in $target_cpu_arch0 "TYPE" 
do
  if test "$old1" != "$i"; then
  if test "$old2" != "$i"; then
   echo " " >>$ac_need_target_h_file
   echo "#ifndef "$ac_need_target_h_prefix"_ARCH_"$i >>$ac_need_target_h_file
   echo "#define "$ac_need_target_h_prefix"_ARCH_"$i '"'"$target_cpu_arch"'"' >>$ac_need_target_h_file
   echo "#endif" >>$ac_need_target_h_file
  fi
  fi
  old2="$old1"
  old1="$i"
done
])

dnl
dnl ... the lowercase variant ...
dnl
AC_DEFUN([AC_CREATE_TARGET_H_LOWER],
[AC_REQUIRE([AC_CANONICAL_CPU_ARCH])
AC_REQUIRE([AC_CREATE_TARGET_H_FILE])
changequote({, })dnl
ac_need_target_h_file=`echo ifelse($1, , target-os.h, $1)`
ac_need_target_h_prefix=`echo ifelse($2, , target, $2) | sed -e 'y:ABCDEFGHIJKLMNOPQRSTUVWXYZ-:abcdefghijklmnopqrstuvwxyz_:' -e 's:[^a-z0-9_]::g'`
#
target_os0=`echo "$target_os"  | sed -e 'y:ABCDEFGHIJKLMNOPQRSTUVWXYZ.-:abcdefghijklmnopqrstuvwxyz__:' -e 's:[^a-z0-9_]::g'`
target_os1=`echo "$target_os0" | sed -e 's:\([^0-9]*\).*:\1:' `
target_os2=`echo "$target_os0" | sed -e 's:\([^_]*\).*:\1:' `
target_os3=`echo "$target_os2" | sed -e 's:\([^0-9]*\).*:\1:' `
#
target_cpu0=`echo "$target_cpu"  | sed -e 'y:ABCDEFGHIJKLMNOPQRSTUVWXYZ.-:abcdefghijklmnopqrstuvwxyz__:' -e 's:[^a-z0-9_]::g'`
target_cpu1=`echo "$target_cpu0" | sed -e 's:\([^0-9]*\).*:\1:' `
target_cpu2=`echo "$target_cpu0" | sed -e 's:\([^_]*\).*:\1:' `
target_cpu3=`echo "$target_cpu2" | sed -e 's:\([^0-9]*\).*:\1:' `
#
target_cpu_arch0=`echo "$target_cpu_arch" | sed -e 'y:ABCDEFGHIJKLMNOPQRSTUVWXYZ:abcdefghijklmnopqrstuvwxyz:'`
#
changequote([, ])dnl
#
if $ac_need_target_h_file_new ; then
AC_MSG_RESULT(creating $ac_need_target_h_file - canonical system defines)
echo /'*' automatically generated by $PACKAGE configure '*'/ >$ac_need_target_h_file
echo /'*' on `date` '*'/ >>$ac_need_target_h_file
ac_need_target_h_file_new=false
fi
echo /'*' target lowercase defines '*'/ >>$ac_need_target_h_file
dnl
old1=""
old2=""
for i in $target_os0 $target_os1 $target_os2 $target_os3 "_"; 
do
  if test "$old1" != "$i"; then
  if test "$old2" != "$i"; then
   echo " " >>$ac_need_target_h_file
   echo "#ifndef __"$ac_need_target_h_prefix"_os_"$i >>$ac_need_target_h_file
   echo "#define __"$ac_need_target_h_prefix"_os_"$i '"'"$target_os"'"' >>$ac_need_target_h_file
   echo "#endif" >>$ac_need_target_h_file
  fi
  fi
  old2="$old1"
  old1="$i"
done
#
old1=""
old2=""
for i in $target_cpu0 $target_cpu1 $target_cpu2 $target_cpu3 "_" 
do
  if test "$old1" != "$i"; then
  if test "$old2" != "$i"; then
   echo " " >>$ac_need_target_h_file
   echo "#ifndef __"$ac_need_target_h_prefix"_cpu_"$i >>$ac_need_target_h_file
   echo "#define __"$ac_need_target_h_prefix"_cpu_"$i '"'"$target_cpu"'"' >>$ac_need_target_h_file
   echo "#endif" >>$ac_need_target_h_file
  fi
  fi
  old2="$old1"
  old1="$i"
done
#
old1=""
old2=""
for i in $target_cpu_arch0 "_" 
do
  if test "$old1" != "$i"; then
  if test "$old2" != "$i"; then
   echo " " >>$ac_need_target_h_file
   echo "#ifndef __"$ac_need_target_h_prefix"_arch_"$i >>$ac_need_target_h_file
   echo "#define __"$ac_need_target_h_prefix"_arch_"$i '"'"$target_cpu_arch"'"' >>$ac_need_target_h_file
   echo "#endif" >>$ac_need_target_h_file
  fi
  fi
  old2="$old1"
  old1="$i"
done
])

dnl -------------------------------------------------------------------
dnl
dnl ... the uppercase variant for the host ...
dnl
AC_DEFUN([AC_CREATE_TARGET_HOST_UPPER],
[AC_REQUIRE([AC_CANONICAL_CPU_ARCH])
AC_REQUIRE([AC_CREATE_TARGET_H_FILE])
changequote({, })dnl
ac_need_target_h_file=`echo ifelse($1, , target.h, $1)`
ac_need_target_h_prefix=`echo ifelse($2, , host, $2) | sed -e 'y:abcdefghijklmnopqrstuvwxyz-:ABCDEFGHIJKLMNOPQRSTUVWXYZ_:' -e 's:[^A-Z0-9_]::g'`
#
host_os0=`echo "$host_os"  | sed -e 'y:abcdefghijklmnopqrstuvwxyz.-:ABCDEFGHIJKLMNOPQRSTUVWXYZ__:' -e 's:[^A-Z0-9_]::g'`
host_os1=`echo "$host_os0" | sed -e 's:\([^0-9]*\).*:\1:' `
host_os2=`echo "$host_os0" | sed -e 's:\([^_]*\).*:\1:' `
host_os3=`echo "$host_os2" | sed -e 's:\([^0-9]*\).*:\1:' `
#
host_cpu0=`echo "$host_cpu"  | sed -e 'y:abcdefghijklmnopqrstuvwxyz.-:ABCDEFGHIJKLMNOPQRSTUVWXYZ__:' -e 's:[^A-Z0-9]::g'`
host_cpu1=`echo "$host_cpu0" | sed -e 's:\([^0-9]*\).*:\1:' `
host_cpu2=`echo "$host_cpu0" | sed -e 's:\([^_]*\).*:\1:' `
host_cpu3=`echo "$host_cpu2" | sed -e 's:\([^0-9]*\).*:\1:' `
#
host_cpu_arch0=`echo "$host_cpu_arch" | sed -e 'y:abcdefghijklmnopqrstuvwxyz:ABCDEFGHIJKLMNOPQRSTUVWXYZ:'`
#
changequote([, ])dnl
#
if $ac_need_target_h_file_new ; then
AC_MSG_RESULT(creating $ac_need_target_h_file - canonical system defines)
echo /'*' automatically generated by $PACKAGE configure '*'/ >$ac_need_target_h_file
echo /'*' on `date` '*'/ >>$ac_need_target_h_file
ac_need_target_h_file_new=false
fi
echo /'*' host uppercase defines '*'/ >>$ac_need_target_h_file
dnl
old1=""
old2=""
for i in $host_os0 $host_os1 $host_os2 $host_os3 "TYPE"
do
  if test "$old1" != "$i"; then
  if test "$old2" != "$i"; then
   echo " " >>$ac_need_target_h_file
   echo "#ifndef "$ac_need_target_h_prefix"_OS_"$i >>$ac_need_target_h_file
   echo "#define "$ac_need_target_h_prefix"_OS_"$i '"'"$host_os"'"' >>$ac_need_target_h_file
   echo "#endif" >>$ac_need_target_h_file
  fi
  fi
  old2="$old1"
  old1="$i"
done
#
old1=""
old2=""
for i in $host_cpu0 $host_cpu1 $host_cpu2 $host_cpu3 "TYPE" 
do
  if test "$old1" != "$i"; then
  if test "$old2" != "$i"; then
   echo " " >>$ac_need_target_h_file
   echo "#ifndef "$ac_need_target_h_prefix"_CPU_"$i >>$ac_need_target_h_file
   echo "#define "$ac_need_target_h_prefix"_CPU_"$i '"'"$host_cpu"'"' >>$ac_need_target_h_file
   echo "#endif" >>$ac_need_target_h_file
  fi
  fi
  old2="$old1"
  old1="$i"
done
#
old1=""
old2=""
for i in $host_cpu_arch0 "TYPE" 
do
  if test "$old1" != "$i"; then
  if test "$old2" != "$i"; then
   echo " " >>$ac_need_target_h_file
   echo "#ifndef "$ac_need_target_h_prefix"_ARCH_"$i >>$ac_need_target_h_file
   echo "#define "$ac_need_target_h_prefix"_ARCH_"$i '"'"$host_cpu_arch"'"' >>$ac_need_target_h_file
   echo "#endif" >>$ac_need_target_h_file
  fi
  fi
  old2="$old1"
  old1="$i"
done
])

dnl ---------------------------------------------------------------------
dnl
dnl ... the lowercase variant for the host ...
dnl
AC_DEFUN([AC_CREATE_TARGET_HOST_LOWER],
[AC_REQUIRE([AC_CANONICAL_CPU_ARCH])
AC_REQUIRE([AC_CREATE_TARGET_H_FILE])
changequote({, })dnl
ac_need_target_h_file=`echo ifelse($1, , target.h, $1)`
ac_need_target_h_prefix=`echo ifelse($2, , host, $2) | sed -e 'y:ABCDEFGHIJKLMNOPQRSTUVWXYZ-:abcdefghijklmnopqrstuvwxyz_:' -e 's:[^a-z0-9_]::g'`
#
host_os0=`echo "$host_os"  | sed -e 'y:ABCDEFGHIJKLMNOPQRSTUVWXYZ.-:abcdefghijklmnopqrstuvwxyz__:' -e 's:[^a-z0-9_]::g'`
host_os1=`echo "$host_os0" | sed -e 's:\([^0-9]*\).*:\1:' `
host_os2=`echo "$host_os0" | sed -e 's:\([^_]*\).*:\1:' `
host_os3=`echo "$host_os2" | sed -e 's:\([^0-9]*\).*:\1:' `
#
host_cpu0=`echo "$host_cpu"  | sed -e 'y:ABCDEFGHIJKLMNOPQRSTUVWXYZ.-:abcdefghijklmnopqrstuvwxyz__:' -e 's:[^a-z0-9_]::g'`
host_cpu1=`echo "$host_cpu0" | sed -e 's:\([^0-9]*\).*:\1:' `
host_cpu2=`echo "$host_cpu0" | sed -e 's:\([^_]*\).*:\1:' `
host_cpu3=`echo "$host_cpu2" | sed -e 's:\([^0-9]*\).*:\1:' `
#
host_cpu_arch0=`echo "$host_cpu_arch" | sed -e 'y:ABCDEFGHIJKLMNOPQRSTUVWXYZ:abcdefghijklmnopqrstuvwxyz:'`
#
changequote([, ])dnl
#
if $ac_need_target_h_file_new ; then
AC_MSG_RESULT(creating $ac_need_target_h_file - canonical system defines)
echo /'*' automatically generated by $PACKAGE configure '*'/ >$ac_need_target_h_file
echo /'*' on `date` '*'/ >>$ac_need_target_h_file
ac_need_target_h_file_new=false
fi
echo /'*' host lowercase defines '*'/ >>$ac_need_target_h_file
dnl
old1=""
old2=""
for i in $host_os0 $host_os1 $host_os2 $host_os3 "_"; 
do
  if test "$old1" != "$i"; then
  if test "$old2" != "$i"; then
   echo " " >>$ac_need_target_h_file
   echo "#ifndef __"$ac_need_target_h_prefix"_os_"$i >>$ac_need_target_h_file
   echo "#define __"$ac_need_target_h_prefix"_os_"$i '"'"$host_os"'"' >>$ac_need_target_h_file
   echo "#endif" >>$ac_need_target_h_file
  fi
  fi
  old2="$old1"
  old1="$i"
done
#
old1=""
old2=""
for i in $host_cpu0 $host_cpu1 $host_cpu2 $host_cpu3 "_" 
do
  if test "$old1" != "$i"; then
  if test "$old2" != "$i"; then
   echo " " >>$ac_need_target_h_file
   echo "#ifndef __"$ac_need_target_h_prefix"_cpu_"$i >>$ac_need_target_h_file
   echo "#define __"$ac_need_target_h_prefix"_cpu_"$i '"'"$host_cpu"'"' >>$ac_need_target_h_file
   echo "#endif" >>$ac_need_target_h_file
  fi
  fi
  old2="$old1"
  old1="$i"
done
#
old1=""
old2=""
for i in $host_cpu_arch0 "_" 
do
  if test "$old1" != "$i"; then
  if test "$old2" != "$i"; then
   echo " " >>$ac_need_target_h_file
   echo "#ifndef __"$ac_need_target_h_prefix"_arch_"$i >>$ac_need_target_h_file
   echo "#define __"$ac_need_target_h_prefix"_arch_"$i '"'"$host_cpu_arch"'"' >>$ac_need_target_h_file
   echo "#endif" >>$ac_need_target_h_file
  fi
  fi
  old2="$old1"
  old1="$i"
done
])

dnl -------------------------------------------------------------------

dnl
dnl the instruction set architecture (ISA) has evolved for a small set
dnl of cpu types. So they often have specific names, e.g. sparclite,
dnl yet they share quite a few similarities. This macro will set the
dnl shell-var $target_cpu_arch to the basic type. Note that these
dnl names are often in conflict with their original 32-bit type name
dnl of these processors, just use them for directory-handling or add
dnl a prefix/suffix to distinguish them from $target_cpu
dnl
dnl this macros has been invented since config.guess is sometimes
dnl too specific about the cpu-type. I chose the names along the lines
dnl of linux/arch/ which is modelled after widespread arch-naming, IMHO.
dnl
AC_DEFUN([AC_CANONICAL_CPU_ARCH],
[AC_REQUIRE([AC_CANONICAL_SYSTEM])
target_cpu_arch="unknown"
case $target_cpu in
 i386*|i486*|i586*|i686*|i786*) target_cpu_arch=i386 ;;
 power*)   target_cpu_arch=ppc ;;
 arm*)     target_cpu_arch=arm ;;
 sparc64*) target_cpu_arch=sparc64 ;;
 sparc*)   target_cpu_arch=sparc ;;
 mips64*)  target_cpu_arch=mips64 ;;
 mips*)    target_cpu_arch=mips ;;
 alpha*)   target_cpu_arch=alpha ;;
 hppa1*)   target_cpu_arch=hppa1 ;;
 hppa2*)   target_cpu_arch=hppa2 ;;
 arm*)     target_cpu_arch=arm ;;
 m68???|mcf54??) target_cpu_arch=m68k ;;
 *)        target_cpu_arch="$target_cpu" ;;
esac

host_cpu_arch="unknown"
case $host_cpu in
 i386*|i486*|i586*|i686*|i786*) host_cpu_arch=i386 ;;
 power*)   host_cpu_arch=ppc ;;
 arm*)     host_cpu_arch=arm ;;
 sparc64*) host_cpu_arch=sparc64 ;;
 sparc*)   host_cpu_arch=sparc ;;
 mips64*)  host_cpu_arch=mips64 ;;
 mips*)    host_cpu_arch=mips ;;
 alpha*)   host_cpu_arch=alpha ;;
 hppa1*)   host_cpu_arch=hppa1 ;;
 hppa2*)   host_cpu_arch=hppa2 ;;
 arm*)     host_cpu_arch=arm ;;
 m68???|mcf54??) host_cpu_arch=m68k ;;
 *)        host_cpu_arch="$target_cpu" ;;
esac
])

dnl @synopsis AC_COMPILE_CHECK_SIZEOF(TYPE [, HEADERS [, EXTRA_SIZES...]])
dnl
dnl This macro checks for the size of TYPE using compile checks, not
dnl run checks. You can supply extra HEADERS to look into. the check
dnl will cycle through 1 2 4 8 16 and any EXTRA_SIZES the user
dnl supplies. If a match is found, it will #define SIZEOF_`TYPE' to
dnl that value. Otherwise it will emit a configure time error
dnl indicating the size of the type could not be determined.
dnl
dnl The trick is that C will not allow duplicate case labels. While
dnl this is valid C code:
dnl
dnl      switch (0) case 0: case 1:;
dnl
dnl The following is not:
dnl
dnl      switch (0) case 0: case 0:;
dnl
dnl Thus, the AC_TRY_COMPILE will fail if the currently tried size
dnl does not match.
dnl
dnl Here is an example skeleton configure.in script, demonstrating the
dnl macro's usage:
dnl
dnl      AC_PROG_CC
dnl      AC_CHECK_HEADERS(stddef.h unistd.h)
dnl      AC_TYPE_SIZE_T
dnl      AC_CHECK_TYPE(ssize_t, int)
dnl
dnl      headers='#ifdef HAVE_STDDEF_H
dnl      #include <stddef.h>
dnl      #endif
dnl      #ifdef HAVE_UNISTD_H
dnl      #include <unistd.h>
dnl      #endif
dnl      '
dnl
dnl      AC_COMPILE_CHECK_SIZEOF(char)
dnl      AC_COMPILE_CHECK_SIZEOF(short)
dnl      AC_COMPILE_CHECK_SIZEOF(int)
dnl      AC_COMPILE_CHECK_SIZEOF(long)
dnl      AC_COMPILE_CHECK_SIZEOF(unsigned char *)
dnl      AC_COMPILE_CHECK_SIZEOF(void *)
dnl      AC_COMPILE_CHECK_SIZEOF(size_t, $headers)
dnl      AC_COMPILE_CHECK_SIZEOF(ssize_t, $headers)
dnl      AC_COMPILE_CHECK_SIZEOF(ptrdiff_t, $headers)
dnl      AC_COMPILE_CHECK_SIZEOF(off_t, $headers)
dnl
dnl @author Kaveh Ghazi <ghazi@caip.rutgers.edu>
dnl @version $Id: acinclude.m4,v 1.8 2006/12/22 19:45:32 acab Exp $
dnl
AC_DEFUN([AC_COMPILE_CHECK_SIZEOF],
[changequote(<<, >>)dnl
dnl The name to #define.
define(<<AC_TYPE_NAME>>, translit(sizeof_$1, [a-z *], [A-Z_P]))dnl
dnl The cache variable name.
define(<<AC_CV_NAME>>, translit(ac_cv_sizeof_$1, [ *], [_p]))dnl
changequote([, ])dnl
AC_MSG_CHECKING(size of $1)
AC_CACHE_VAL(AC_CV_NAME,
[for ac_size in 4 8 1 2 16 $2 ; do # List sizes in rough order of prevalence.
  AC_TRY_COMPILE([#include "confdefs.h"
#include <sys/types.h>
$2
], [switch (0) case 0: case (sizeof ($1) == $ac_size):;], AC_CV_NAME=$ac_size)
  if test x$AC_CV_NAME != x ; then break; fi
done
])
if test x$AC_CV_NAME = x ; then
  AC_MSG_ERROR([cannot determine a size for $1])
fi
AC_MSG_RESULT($AC_CV_NAME)
AC_DEFINE_UNQUOTED(AC_TYPE_NAME, $AC_CV_NAME, [The number of bytes in type $1])
undefine([AC_TYPE_NAME])dnl
undefine([AC_CV_NAME])dnl
])
dnl Add --enable-maintainer-mode option to configure.
dnl From Jim Meyering

dnl serial 1

AC_DEFUN([AM_MAINTAINER_MODE],
[AC_MSG_CHECKING([whether to enable maintainer-specific portions of Makefiles])
  dnl maintainer-mode is disabled by default
  AC_ARG_ENABLE(maintainer-mode,
[AS_HELP_STRING([--enable-maintainer-mode], [make rules and dependencies not useful
                                            (and sometimes confusing) to the casual installer])],
      USE_MAINTAINER_MODE=$enableval,
      USE_MAINTAINER_MODE=no)
  AC_MSG_RESULT($USE_MAINTAINER_MODE)
  AM_CONDITIONAL(MAINTAINER_MODE, test $USE_MAINTAINER_MODE = yes)
  MAINT=$MAINTAINER_MODE_TRUE
  AC_SUBST(MAINT)dnl
]
)

dnl AC_C_CVE_2008_1372
dnl Checks DoS in bzlib 
AC_DEFUN([AC_C_CVE_2008_1372],
[AC_CACHE_CHECK([for CVE-2008-1372], [ac_cv_c_cve_2008_1372],
[
save_LIBS="$LIBS"
LIBS="$LIBCLAMAV_LIBS $LIBBZ2"
AC_TRY_RUN([
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <bzlib.h>

#ifdef NOBZ2PREFIX
#define BZ2_bzReadOpen bzReadOpen
#define BZ2_bzReadClose bzReadClose
#define BZ2_bzRead bzRead
#define BZ2_bzDecompressInit bzDecompressInit
#define BZ2_bzDecompress bzDecompress
#define BZ2_bzDecompressEnd bzDecompressEnd
#endif

const unsigned char poc[] = {
  0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0x20, 0x0c,
  0xa6, 0x9c, 0x00, 0x00, 0xc2, 0xfb, 0x90, 0xca, 0x10, 0x04, 0x00, 0x40,
  0x03, 0x77, 0x80, 0x06, 0x00, 0x7a, 0x2f, 0xde, 0x40, 0x04, 0x00, 0x40,
  0x08, 0x30, 0x00, 0xb9, 0xb0, 0x4a, 0x89, 0xa3, 0x43, 0x4d, 0x00, 0x00,
  0x01, 0xb5, 0x04, 0xa4, 0x6a, 0x19, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x91,
  0x00, 0x00, 0x00, 0x00, 0x2a, 0x91, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x00,
  0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00,
  0x00, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x2a,
  0x91, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x91, 0x00, 0x00, 0x00, 0x00, 0x2a,
  0x91, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x91, 0x2a, 0xad, 0x2a, 0x91, 0x32,
  0x9a, 0x32, 0x0d, 0x06, 0x8d, 0x00, 0x03, 0xf7, 0x13, 0xd2, 0xf5, 0x54,
  0x5b, 0x20, 0x4b, 0x34, 0x40, 0x8a, 0x6b, 0xaa, 0x64, 0xd8, 0x30, 0x9d,
  0x8a, 0x9a, 0x52, 0x44, 0x13, 0x46, 0x37, 0xd9, 0x0a, 0x3c, 0xa6, 0xee,
  0xe9, 0xee, 0xec, 0x6d, 0x4a, 0x65, 0xc2, 0x32, 0xcb, 0x43, 0x82, 0x48,
  0xa1, 0x26, 0xc3, 0x43, 0x11, 0x47, 0x0a, 0x5e, 0xc1, 0x30, 0x55, 0x84,
  0xb1, 0x25, 0x7a, 0x2b, 0x86, 0x0e, 0xc8, 0x1a, 0x45, 0x10, 0xf1, 0xa9,
  0x19, 0x00, 0x30, 0x3c, 0x2a, 0xeb, 0x16, 0x6a, 0x75, 0x86, 0x60, 0xd0,
  0xc7, 0xd0, 0x94, 0x34, 0xf1, 0x6b, 0x49, 0x9f, 0x30, 0x4e, 0x0f, 0x70,
  0xbe, 0x12, 0x28, 0xe9, 0x7d, 0x10, 0x80, 0x35, 0x53, 0xaf, 0x72, 0xe1,
  0x83, 0x90, 0xb8, 0xf8, 0x4b, 0x1a, 0xa4, 0x29, 0x1b, 0x90, 0xe1, 0x4a,
  0x0f, 0xc5, 0xdc, 0x91, 0x4e, 0x14, 0x24, 0x08, 0x03, 0x29, 0xa7, 0x00
};
const unsigned int poc_len = 252;

int main (int argc, char **argv) {
        bz_stream bz;
        char buf[1024];

        memset(&bz, 0, sizeof(bz));
        bz.next_in = (char *)&poc;
        bz.avail_in = poc_len;
        bz.next_out = buf;
        bz.avail_out = sizeof(buf);
        if(BZ2_bzDecompressInit(&bz, 0, 0)!=BZ_OK)
                return 1;

        while((BZ2_bzDecompress(&bz))==BZ_OK) {
                bz.next_out = buf;
                bz.avail_out = sizeof(buf);
        }
        BZ2_bzDecompressEnd(&bz);
        return 0;
}
], [ac_cv_c_cve_2008_1372=ok], [
if test $? -gt 127; then 
	ac_cv_c_cve_2008_1372=bugged
else
	ac_cv_c_cve_2008_1372=linkfailed
fi
], [ac_cv_c_cve_2008_1372=ok])
LIBS="$save_LIBS"
])
])

dnl AC_C_CVE_2010_0405
dnl Checks DoS in bzlib 
AC_DEFUN([AC_C_CVE_2010_0405],
[AC_CACHE_CHECK([for CVE-2010-0405], [ac_cv_c_cve_2010_0405],
[
save_LIBS="$LIBS"
LIBS="$LIBCLAMAV_LIBS $LIBBZ2"
AC_TRY_RUN([
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <bzlib.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef NOBZ2PREFIX
#define BZ2_bzReadOpen bzReadOpen
#define BZ2_bzReadClose bzReadClose
#define BZ2_bzRead bzRead
#define BZ2_bzDecompressInit bzDecompressInit
#define BZ2_bzDecompress bzDecompress
#define BZ2_bzDecompressEnd bzDecompressEnd
#endif

const unsigned char poc[] = {
0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xfe, 0x20, 0x2c, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01,
0x00, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x02, 0x02, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
0x01, 0x00, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01,
0x00, 0x01, 0x01, 0x01, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01,
0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0xff
};
const unsigned int poc_len = 280;

int main (int argc, char **argv) {
        bz_stream bz;
        char buf[1024];

        memset(&bz, 0, sizeof(bz));
        bz.next_in = (char *)&poc;
        bz.avail_in = poc_len;
        bz.next_out = buf;
        bz.avail_out = sizeof(buf);

	alarm(10);

        if(BZ2_bzDecompressInit(&bz, 0, 0)!=BZ_OK)
                return 1;

        while((BZ2_bzDecompress(&bz))==BZ_OK) {
                bz.next_out = buf;
                bz.avail_out = sizeof(buf);
        }
        BZ2_bzDecompressEnd(&bz);
        return 0;
}
], [ac_cv_c_cve_2010_0405=ok], [
if test $? -gt 127; then 
	ac_cv_c_cve_2010_0405=bugged
else
	ac_cv_c_cve_2010_0405=linkfailed
fi
], [ac_cv_c_cve_2010_0405=ok])
LIBS="$save_LIBS"
])
])

dnl AC_LIB_FIND(LIBNAME, HEADER, LINKTESTCODE, ACTION-IF-FOUND, ACTION-IF-NOT-FOUND)
dnl Checks for flags needed to link with LIBNAME, for the existence of HEADER,
dnl and the ability to link with LINKTESTCODE.
dnl If successful sets LIB${LIBNAME}, LTLIB${LIBNAME}, INC${LIBNAME} variables,
dnl AC_DEFINEs HAVE_LIB${LIBNAME} to 1, defines HAVE_LIB${LIBNAME} to yes,
dnl and evaluates ACTION-IF-FOUND.
dnl Otherwise evaluates ACTION-IF-NOT-FOUND.
dnl --------------------------------------------------------------------------------
AC_DEFUN([AC_LIB_FIND],
[
	dnl Prerequisites of AC_LIB_LINKFLAGS_BODY
  	AC_REQUIRE([AC_LIB_PREPARE_PREFIX])
	AC_REQUIRE([AC_LIB_RPATH])
	m4_if($#,5,,[m4_fatal([$0: invalid number of arguments: $#])])
  	define([NAME],[translit([$1],[abcdefghijklmnopqrstuvwxyz./-],
                               [ABCDEFGHIJKLMNOPQRSTUVWXYZ___])])
		save_CPPFLAGS="$CPPFLAGS"
		save_LIBS="$LIBS"
		AC_LIB_LINKFLAGS_BODY([$1])
		CPPFLAGS="$CPPFLAGS $INC[]NAME"
		AC_CHECK_HEADER([$2], [have_header=yes],[have_header=no])
		ac_cv_findlib_[]NAME[]_libs=
		ac_cv_findlib_[]NAME[]_ltlibs=
		ac_cv_findlib_[]NAME[]_inc=
		AS_IF([test "$have_header" = "yes"],[
				LIBS="$LIBS $LIB[]NAME"
				AC_MSG_CHECKING([linking with $1])
				AC_LINK_IFELSE([AC_LANG_SOURCE([$3])],[
					ac_cv_findlib_[]NAME[]_libs="$LIB[]NAME"
					ac_cv_findlib_[]NAME[]_ltlibs="$LTLIB[]NAME"
					ac_cv_findlib_[]NAME[]_inc="$INC[]NAME"
					AC_MSG_RESULT([ok])
				])
		])
		CPPFLAGS="$save_CPPFLAGS"
		LIBS="$save_LIBS"
	AS_IF([test "X$ac_cv_findlib_[]NAME[]_libs" = "X"],[
			AC_MSG_NOTICE([unable to compile/link with $1])
			HAVE_LIB[]NAME=no
			$5
		],[
			AC_MSG_NOTICE([Compiling and linking with $1 by using $ac_cv_findlib_[]NAME[]_inc $ac_cv_findlib_[]NAME[]_libs])
			AC_DEFINE([HAVE_LIB]NAME,1,[Define to '1' if you have the $2 library])
			HAVE_LIB[]NAME=yes
			LIB[]NAME="$ac_cv_findlib_[]NAME[]_libs"
			LTLIB[]NAME="$ac_cv_findlib_[]NAME[]_ltlibs"
			INC[]NAME="$ac_cv_findlib_[]NAME[]_inc"
			$4
	])
	undefine([NAME])	
])

dnl Try to set a correct default libdir for multiarch systems
AC_DEFUN([AC_LIB_MULTILIB_GUESS],
[
	# Only modify libdir if user has not overridden it
	default_libdir='${exec_prefix}/lib'
	if test "$libdir" = "$default_libdir"; then
		AC_MSG_CHECKING([for multiarch libdir])
		# Based on http://lists.gnu.org/archive/html/autoconf/2008-09/msg00072.html
		if test "$GCC" = yes; then
			ac_multilibdir=`$CC -print-multi-os-directory $CFLAGS $CPPFLAGS $LDFLAGS` || ac_multilibdir=.
		else
			ac_multilibdir=.
		fi
		case "$ac_multilibdir" in
			 # I don't know if the first two cases can happen, but it would be a
			 # bad idea to override $exec_prefix
			 /* | ../../* | .) acl_libdirstem=lib ;;
			 ../*)             acl_libdirstem=`echo $ac_multilibdir | sed 's/^...//' ` ;;
			*)                 acl_libdirstem=lib/$ac_multilibdir ;;
		esac
		libdir='${exec_prefix}/'$acl_libdirstem
		AC_MSG_RESULT([$libdir])
	else
		acl_libdirstem=lib
		if test -d "$libdir"; then
			case "$libdir" in
				*/lib64/ | */lib64 ) acl_libdirstem=lib64 ;;
				*) searchdir=`cd "$libdir" && pwd`
				   case "$searchdir" in
					*/lib64 ) acl_libdirstem=lib64 ;;
				   esac
			esac
		fi
	fi
])

dnl CL_MSG_STATUS([featurename],[have_feature], [enable_feature])
AC_DEFUN([CL_MSG_STATUS],
[
   m4_if($#,3,,[m4_fatal([$0: invalid number of arguments: $#])])
   AS_ECHO_N(["              $1: "])
   AS_IF([test "x$3" = "xno"], [AS_ECHO(["$2 (disabled)"])],
	 [test "x$3" = "xyes"], [AS_ECHO(["$2"])],
	 [test "x$3" = "x"], [AS_ECHO(["$2"])],
	 [AS_ECHO(["$2 ($3)"])])
])

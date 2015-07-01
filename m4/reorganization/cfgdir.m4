dnl configure config directory
cfg_dir=`echo $sysconfdir | grep prefix`

if test -n "$cfg_dir"; then
    if test "$prefix" = "NONE"
    then
	cfg_dir="$ac_default_prefix/etc"
    else
	cfg_dir="$prefix/etc"
    fi
else
    cfg_dir="$sysconfdir"
fi

CFGDIR=$cfg_dir
AC_SUBST([CFGDIR])
AC_DEFINE_UNQUOTED([CONFDIR],"$cfg_dir",[where to look for the config file])

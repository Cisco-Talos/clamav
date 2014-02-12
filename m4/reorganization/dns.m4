AC_ARG_ENABLE([dns-fix],
[  --enable-dns-fix	  enable workaround for broken DNS servers (as in SpeedTouch 510)],
enable_dnsfix=$enableval, enable_dnsfix="no")

if test "$enable_dnsfix" = "yes"; then
  AC_DEFINE([FRESHCLAM_DNS_FIX],1,[enable workaround for broken DNS servers])
fi

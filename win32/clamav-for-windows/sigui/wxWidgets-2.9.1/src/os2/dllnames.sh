#!/bin/sh
#
# dllnames - a tool to form short DLL names for wxWindows
#
# This script will accept an import library name and create
# a short(er) DLL name from it.

dllFile="$1"
dirName=`echo $dllFile | sed 's-\(.*[/\\]\)[^/\\]*$-\1-'`
dllFile=`echo $dllFile | sed 's-.*[/\\]\([^/\\]*\)$-\1-'`
case $dllFile in
*wx_base_*)
    dllFile=`echo $dllFile | sed 's/base_\(...\)/b\1/'`
    ;;
*wx_based_*)
    dllFile=`echo $dllFile | sed 's/based_\(...\)/d\1/'`
    ;;
*wx_based-*)
    dllFile=`echo $dllFile | sed 's/based/basd/'`
    ;;
*wx_*d_*)
    dllFile=`echo $dllFile | sed 's/_\(.\)[^_]*_\(..\)[^-]*-/\1d\2/'`
    ;;
*wx_*_*)
    dllFile=`echo $dllFile | sed 's/_\(..\)[^_]*_\(..\)[^-]*-/\1\2/'`
    ;;
*)
    ;;
esac
dllFile="`echo $dllFile | sed 's/\.//' | sed 's/_//' | sed 's/-//'`"
echo $dirName$dllFile
exit 0
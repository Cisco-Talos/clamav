#!/bin/sh
if test ! `basename $CLAM_VIRUSEVENT_FILENAME` = "clam.exe"; then
	echo "VirusEvent incorrect: $CLAM_VIRUSEVENT_FILENAME" >$1/test-clamd.log
	exit 1
fi
if test ! "x$CLAM_VIRUSEVENT_VIRUSNAME" = "xClamAV-Test-File.UNOFFICIAL"; then
	echo "VirusName incorrect: $CLAM_VIRUSEVENT_VIRUSNAME" >$1/test-clamd.log
	exit 2
fi
echo $2 >$1/test-clamd.log

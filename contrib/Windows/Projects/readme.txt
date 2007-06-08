This directory contains the files needed to build ClamAV under Windows
using Visual Studio 2005, thus avoiding emulation layers such as Cygwin.

Some patches are needed against the rest of CVS for the code to
compile (most of them are trivial), see clamAV/patches.

You will need to get hold of w32-pthreads version 2.6 from
http://sourceware.org/pthreads-win32/.

Thanks to acab@clamav.net for adding libclamav.dll support

TODO:	Support GMP
	virusaction is not supported
	A plugin to MS Exchange
	On access scanning
	Investigation of .NET dependencies
	Scan when a screensaver kicks in
	zlib and pthreads should be DLL, not bundled into libclamav.dll

-Nigel Horne

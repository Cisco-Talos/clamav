This directory contains the files needed to build ClamAV under Windows
using Visual Studio 2005, thus avoiding emulation layers such as Cygwin.

Some patches are needed against the rest of CVS for the code to
compile (most of them are trivial), see clamAV/patches.

You will need to get hold of w32-pthreads.

TODO:	Support GMP
	libclamav should be a DLL
	virusaction is not supported
	A plugin to MS Exchange
	On access scanning
	Changing libclamav to be a DLL
	Investigation of .NET dependencies

-Nigel Horne 2006

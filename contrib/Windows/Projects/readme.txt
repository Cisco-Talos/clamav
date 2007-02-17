This directory contains the files needed to build ClamAV under Windows
using Visual Studio 2005, thus avoiding emulation layers such as Cygwin.

Some patches are needed against the rest of CVS for the code to
compile (most of them are trivial), see clamAV/patches.

The project files will be uploaded here in due course.

TODO:	Support GMP
	libclamav should be a DLL
	virusaction is not supported
FIXME:	Only one concurrent mmap is allowed
	In MSVC debug mode, a trap for closing a file that isn't open is
		raised when scaning a cabinet file

-Nigel Horne 2006

This directory will contain the files needed to build ClamAV under Windows
using Visual Studio 2005, thus avoiding emulation layers such as Cygwin.

libclamav and clamscan are now available, execpt for routines that
require memory mapped I/O.

Some patches are needed against the rest of CVS for the code to
compile (mostly these are trivial), email me for the latest patches.

-Nigel Horne 2006

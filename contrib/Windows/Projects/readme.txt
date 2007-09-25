This directory contains the files needed to build ClamAV under Windows
using Visual Studio 2005, thus avoiding emulation layers such as Cygwin.

Some patches are needed against the rest of SVN for the code to
compile (most of them are trivial), see clamAV/patches.

You will need to get hold of w32-pthreads version 2.6, or later, from
http://sourceware.org/pthreads-win32/ and install pthreadVC2.dll into a
location that CLamAV can find, such as c:\Program Files\ClamAV\pthreadVC2.dll.
You will need to create a folder "libclamav\pthread" and these files into
there: config.h, pthread.h, pthreadVC2.dll, pthreadVC2.lib, sched.h,
semaphore.h.

You will need to download the zlib source from http://www.zlib.net/
and install the .c and .h files into .../libclamav/zlib.

Thanks to acab@clamav.net for adding libclamav.dll support, and to
edwin@clamav.net for testing it all and for pthreads support as a DLL.

TODO:	Support GMP
	virusaction is not supported
	A plugin to MS Exchange
	On access scanning
	Scan when a screensaver kicks in
	zlib should be DLL, not bundled into libclamav.dll (needs thought
		on the C runtime library)

-Nigel Horne

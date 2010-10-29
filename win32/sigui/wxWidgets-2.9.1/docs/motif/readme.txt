
  Welcome to wxWidgets/Motif

You have downloaded the Motif port of the wxWidgets GUI library.

More information about the wxWidgets project as a whole
can be found at:

  http://www.wxwidgets.org/
  
Information on how to install can be found in the file 
install.txt, but if you cannot wait, this should work on
many systems:

./configure --with-motif
make
su <type root password>
make install
ldconfig
exit

Alternatively, a script (makewxmotif) for running configure can
be found in this directory.

When you run into problems, please read the install.txt and
follow those instructions. If you still don't have any success,
please send a bug report to one of our mailing lists (see
the wxWidgets homepage) INCLUDING A DESCRIPTION OF YOUR SYSTEM AND
YOUR PROBLEM, SUCH AS YOUR VERSION OF MOTIF, WXMOTIF, WHAT
DISTRIBUTION YOU USE AND WHAT ERROR WAS REPORTED.
Alternatively, you may also use the bug reporting system
linked from the wxWidgets web page.

The library produced by the install process will be called 
libwx_motif.a (static) and libwx_motif-2.6.so.0.0.0 (shared) so that
once a binary incompatible version of wxWidgets/Motif comes out 
we'll augment the library version number to avoid linking problems.

Please send problems concerning installation, feature requests, 
bug reports or comments to the wxWidgets users list. Information 
on how to subscribe is available from www.wxwidgets.org.

wxWidgets/Motif doesn't come with any guarantee whatsoever. It might 
crash your hard disk or destroy your monitor. It doesn't claim to be
suitable for any special or general purpose.

  Regards,

  The wxWidgets team


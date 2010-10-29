
  Welcome to wxWidgets/X11

You have downloaded the X11 port of the wxWidgets GUI library.
This runs on X11 with no Motif, Xt, GTK+ or any other standard
widget set -- instead it uses the wxUniversal widgets. The
intention is to have it run on NanoX as well as desktop X11.

More information about the wxWidgets project as a whole
can be found at:

  http://www.wxwidgets.org
  
Information on how to install can be found in the file 
install.txt, but if you cannot wait, this should work on
many systems:

./configure --with-x11 --disable-shared --enable-log --enable-debug -without-odbc --enable-debug_cntxt

make
su <type root password>
make install
ldconfig
exit

When you run into problems, please read the install.txt and
follow those instructions. If you still don't have any success,
please send a bug report to one of our mailing lists (see
the wxWidgets homepage) INCLUDING A DESCRIPTION OF YOUR SYSTEM AND
YOUR PROBLEM, SUCH AS YOUR VERSION OF X, WHAT DISTRIBUTION YOU USE
AND WHAT ERROR WAS REPORTED. Alternatively, you may also use the bug
reporting system linked from the wxWidgets web page.

The library produced by the install process will be called 
libwx_x11univ[d].a (static) and libwx_x11univ[d]-2.3.so.0.0.0
(shared) so that once a binary incompatible version of
wxWidgets/X11 comes out we'll augment the library version number
to avoid linking problems.

Please send problems concerning installation, feature requests, 
bug reports or comments to the wxWidgets users list. Information 
on how to subscribe is available from www.wxwidgets.org.

wxWidgets/X11 doesn't come with any guarantee whatsoever. It might 
crash your hard disk or destroy your monitor. It doesn't claim to be
suitable for any special or general purpose.

Status
======

Many of the samples are running.

Some remaining issues:

- some refresh efficiency issues
- clipboard implementation missing
- drag and drop implementation missing
- wxX11's wxTextCtrl (separate from wxUniv version)
  needs some work, for example to remove vertical scrollbar,
  and to provide wordwrap
- wxToggleButton implementation missing
- wxSpinCtrl implementation missing
- tooltips implementation missing
- code common to the Motif and X11 ports needs to be merged
- need thread safety in event loop

  Regards,

  The wxWidgets team


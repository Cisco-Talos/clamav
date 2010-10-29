   Welcome to wxWidgets for GTK+
   -----------------------------

You have downloaded the GTK+ port of the wxWidgets GUI library.

It is required to use at least GTK+ 2.4 and some features are 
only available when using GTK+ 2.8 or higher. Note that if you
compile wxWidgets against GTK+ 2.8 your app will still work
with older GTK+ version down to version 2.4 as wxWidgets
tests for the presence of newer features at run-time and it
will fall back to a generic implementation if these features
are not present in the GTK+ version used.

wxWidgets 2.8 still supports GTK+ 1.2, but no developement
is done on that port anymore and support for GTK+ 1.2 will
probably be dropped entirely. Indeed, one of the major steps
in the developement cycle leading up to wxWidgets 2.8 was
that the codebase for GTK+ 1.2 and GTK+ 2.0 were separated
so that improvements and clean-ups to the GTK+ 2.0 port 
could be done without caring for GTK+ 1.2.

More info about the wxWidgets project (including all the
other ports and version of wxWidgets) can be found at the
main wxWidgets homepage at:

                  http://www.wxwidgets.org/
  
Information on how to install can be found in the file 
INSTALL.txt, but if you cannot wait, this should work on
many systems:

    mkdir build_gtk
    cd build_gtk
    ../configure
    make
    su <type root password>
    make install
    ldconfig

In order to use wxGTK with GTK 1.2 you need to use --with-gtk=1
configure option. To build the library in Unicode mode (all
strings will be wide strings and so on) you need to configure
with GTK 2.0 and add --enable-unicode.

Please note that it is strongly advised to build the library in
a separate directory, as shown above, as it allows you to have
different builds of it (for example with and without debug) in
parallel. If you build in the source directory, don't forget to
do "make clean" before changing the configuration!

When you run into problems, please read the INSTALL.txt and 
follow those instructions. If you still don't have any success,
please send a bug report to one of our mailing list, INCLUDING 
A DESCRIPTION OF YOUR SYSTEM AND YOUR PROBLEM, SUCH AS YOUR 
VERSION OF GTK, WXGTK, WHAT DISTRIBUTION YOU USE AND WHAT ERROR 
WAS REPORTED. I know this has no effect, but I tried...

Please send problems concerning installation, feature requests, 
bug reports or comments to the wxWidgets users list. These can
be found at http://www.wxwidgets.org and more specifically at 
http://lists.wxwidgets.org.

wxWidgets doesn't come with any guarantee whatsoever. It 
might crash your harddisk or destroy your monitor. It doesn't 
claim to be suitable for any special or general purpose.

  Regards,

    Robert Roebling


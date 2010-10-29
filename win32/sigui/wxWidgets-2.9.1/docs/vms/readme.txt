This distribution contains makefiles for VMS. It is a very preliminary release
and many tests have still to be done.

The compilation was tested with
    -OpenVMS Alpha 7.2-1
    -DECC 6.2
    -Compaq C++ 6.2
    -DECWindows 1.2-5
    -GTK1.2.8 (for wxGTK)
    
To get everything compiled you'll need to have installed prior to compiling
wxWidgets:
    -Bison
      get it from http://www.openvms.digital.com/freeware/
      You'll have to fix the following bug:
        add the following 3 lines in BISON.SIMPLE
	  #elif __VMS
	  #include <stdlib.h>
	  #define alloca malloc
        before
	  #endif /* __hpux */
        
    -Flex
      get it from http://www.openvms.digital.com/freeware/

    -Sed
      get it from http://www.openvms.digital.com/freeware/

    -sys$library:libjpeg.olb  (from ftp://ftp.uu.net/graphics/jpeg/ )
        add /name=(as_is,short) to CFLAGS in the descrip.mms file
        don't forget to mms/descrip=Makefile/macro="ALPHA=1"

    -sys$library:libpng.olb & sys$library:libz.olb (from
          http://www.cdrom.com/pub/png/pngcode.html )
        add /name=(as_is,short) to CFLAGS in the descrip.mms of both png and
        zlib

    -sys$library:libtiff.olb (from: ftp://ftp.sgi.com/graphics/tiff/ )
       - add /name=(as_is,short) to the C_COMPILE variable in MAKVMS.COM
       - the following patch is needed in the tiff3.4 distribution:
polka-jj) diff TIFFCOMP.H;3 TIFFCOMP.H;1
************
File $DISK2:[JOUKJ.PUBLIC.TIFF.TIFF.LIBTIFF]TIFFCOMP.H;3
   97   #ifndef HAVE_UNISTD_H
   98   #define HAVE_UNISTD_H   1
   99   #endif
  100   #endif
******
File $DISK2:[JOUKJ.PUBLIC.TIFF.TIFF.LIBTIFF]TIFFCOMP.H;1
   97   #define HAVE_UNISTD_H   1
   98   #endif
************
************
File $DISK2:[JOUKJ.PUBLIC.TIFF.TIFF.LIBTIFF]TIFFCOMP.H;3
  108   #if !defined(SEEK_SET) && defined( HAVE_UNISTD_H )
  109   #include <unistd.h>
******
File $DISK2:[JOUKJ.PUBLIC.TIFF.TIFF.LIBTIFF]TIFFCOMP.H;1
  106   #if !defined(SEEK_SET) && HAVE_UNISTD_H
  107   #include <unistd.h>
************

    -X11:libxpm.olb ( from ftp://koala.inria.fr/pub/xpm/ )
        add /name=(as_is,short) to cc_defs in the descrip.mms file

    -GTK & VMS Porting library (only needed for wxGTK)
       ( from http://www.openvms.digital.com/openvms/products/ips/gtk.html )

    -Redefine the logical SYS$LIBRARY in such a way that it also points
     to the includefile/library directories of the above packages:
     i.e.
$ define sys$library sys$sysroot:[syslib],-
     $disk2:[joukj.public.xpm.xpm.lib],-
     $disk2:[joukj.public.jpeg.jpeg],-
     $disk2:[joukj.public.png.libpng],-
     $disk2:[joukj.public.tiff.tiff.libtiff],-
     $disk2:[joukj.public.png.zlib],-
     $disk2:[joukj.public.gtk.gtk.glib],-
     $disk2:[joukj.public.gtk.gtk.glib.gthread],-
     $disk2:[joukj.compaq.porting_library.dist.include]

    -redefine the logical X11 in such a way that also points to the
      xpm-distribution.
      i.e.
$  define/nolog X11 $disk2:[joukj.public.xpm.xpm.lib],decw$include

    -for wxGTK you'll have to redefine SYS$SHARE to compile and run the
         applications.
     i.e.
$  ass $disk2:[joukj.public.gtk.gtk.glib],-
       $disk2:[joukj.public.gtk.gtk.glib.gmodule],-
       $disk2:[joukj.public.gtk.gtk.gtk.gdk],-
       $disk2:[joukj.public.gtk.gtk.gtk.gtk],-
       $disk2:[joukj.compaq.porting_library.dist.lib],-
       sys$sysroot:[syslib] sys$share

    -At the moment you'll have to hack the [.src.common]descrip.mms file
       to include the right location of bison/flex and sed, but i intend to
       make this better in future.

    -The following is a work-around a include file bug which occurs on some
      versions of VMS. If you get lib$get_current_invo_context undefined
      while linking you'll have to add
         "lib$get_current_invo_context"="LIB$GET_CURR_INVO_CONTEXT"
      in [.src.unix]descrip.mms to CXX_DEFINE. and recompile wxWidgets.

    -Some versions of the CC compiler give warnings like
       %CC-W-CXXKEYWORD, "bool" is a keyword in C++ .... when compiling
       if You encounter these, replace mms by mms/ignore=warning in the
       following

  -Now build everything using one of the following
      mms
      mms gtk
      mms motif
    in the main directory of the distribution. Without an argument both wxGTK
    and wxMOTIF are built. The libraries are built in the [.lib] directory.
    All the samples I tried are built automatically.

  -I think in general wxGTK is better maintained, so that version is my
    first choice.
  
  -Note that only a few people have used wxWidgets on VMS so many problems are
   to be expected.


 -Many thanks for testing and reporting problems to:
    -Walter Braeu


 -Known problems :
   wxMOTIF :
       -The calendar sample puts the boxes of the month and year selection on
        top of each other.
       -The caret sample: sometimes a non blinking caret remains in the
        window.
       -checklist sample: There is no way to check/uncheck since this box is
        missing
       -conftest sample: The boxes in the window are too small to display
        texts with the fonts specified.
       -controls sample: radiobox does not appear on the screen
       -Some samples crash due to colour allocation problems
        i.e. -drawing,image

   wxGTK :
       -In the calendar sample options can only be switched on and not off
        again.
       -image sample: after clicking "about" the colourmap is permanently
        changed resulting in strange images
     
Finally :
 I like the idea of Robert Roebling that CD's with classical music should be
send to the authors.


>-----------------------------------------------------------------------------<

  Jouk Jansen
		 
  joukj@hrem.stm.tudelft.nl


  Technische Universiteit Delft        tttttttttt  uu     uu  ddddddd
  Nationaal centrum voor HREM          tttttttttt  uu     uu  dd    dd
  Rotterdamseweg 137                       tt      uu     uu  dd     dd
  2628 AL Delft                            tt      uu     uu  dd     dd
  Nederland                                tt      uu     uu  dd    dd
  tel. 31-15-2781536                       tt       uuuuuuu   ddddddd

>-----------------------------------------------------------------------------<

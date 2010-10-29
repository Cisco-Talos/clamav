
  =================================================
  Welcome to wxWidgets/CE
  =================================================

You have downloaded the Windows CE port of the wxWidgets GUI library.
This runs on Pocket PC 2002/2003, Smartphone 2002/2003,
Windows CE .NET 4.x, and Windows Mobile 5.

More information about the wxWidgets project as a whole
can be found at:

  http://www.wxwidgets.org

Information about the Windows CE port in particular can be found in
the wxWinCE topic in the wxWidgets reference manual.

Supported platforms
===================

These are the supported platforms at the moment:

- x86 emulator build in eVC 3 and eVC 4.x
- Pocket PC (StrongARM)
- Smartphone (StrongARM)
- Windows Mobile 5

You can test the library and applications using the Pocket PC emulator 
and/or Compaq iPAQ or other PDAs using Pocket PC.

Compiler installation
=====================

1. Embedded Visual C++
----------------------

Get the Visual C++ embedded (FREE) from Microsoft website
 http://msdn.microsoft.com/vstudio/device/embedded/download.asp
 
You must use Embedded Visual C++ 3.0 or Embedded Visual C++ 4.x.

You can download the Smartphone 2002/3 and Pocket PC 2002/3
SDKs separately.

2. Visual Studio 2005
---------------------

VS 2005 Professional is required to write Windows Mobile 5 applications, although Pocket PC
2003 applications should also run on Mobile 5. VS 2005 must
be purchased, and you can then download the Mobile 5 2005 SDK
from Microsoft's site.
 
wxWidgets/CE Configuration
================================

You may wish to customize the following file
before compiling wxWinCE:

include/wx/msw/wince/setup.h

wxWidgets/CE Compilation
================================

NOTE: to generate targets not in the standard project files,
you should rebuild the project files using Bakefile.
Also, if you are building from a SVN version of wxWidgets,
you need to create eVC++ project files or get them from
somewhere, such as the daily makefile builds here:

http://biolpc22.york.ac.uk/pub/Daily_Makefiles/

See technote docs/tech/tn0016.txt for details on using Bakefile,
and you can get Bakefile from:

http://bakefile.sf.net

Open build/wince/wx.vcw, select an ARM or x86 target (or emulator
target for eVC++ 4), and compile.

Then open samples/minimal/minimal.vcw, select an ARM, x86 or emulator
target, and compile. You can use the emulator or real hardware to run
the sample.

There may be long delays while eVC++ computes dependencies, and expect
to wait a long time for loading and saving workspaces. Do not attempt to
save the wxWidgets library project file: it will take forever and generate
a huge file, so make alterations either using Bakefile or by editing the
project file with a text editor, and reloading. Sample project files are OK
to save.

To compile using the emulator on eVC++3:

- Open build/wince/wx.vcw, select the
  WIN32 (WCE x86) Debug Unicode configuration, close the dialog,
  then select Pocket PC 2002 and Pocket PC 2002 Emulation on the toolbar,
  and compile.

- Open samples/minimal/minimal.vcw, select the
  WIN32 (WCE x86 Debug) configuration, and select Pocket PC 2002 and
  Pocket PC 2002 Emulation as before.

To compile using the emulator on eVC++4:

- Open build/wince/wx.vcw, select the
  WIN32 (WCE Emulator) Debug configuration, and compile.

- Open samples/minimal/minimal.vcw with eVC++, select the
  WIN32 (WCE emulator) Debug configuration, and compile.

Note: builds for the different SDKs (Smartphone, PPC, .Net)
use the same directory and library names, so for the moment
these builds cannot co-exist simultaneously.

To use Visual Studio 2005, you need to allow VS to convert the projects
first (but install all the SDKs you need to _before_ converting), and then
you need to adjust the library settings of each wxWidgets and sample project.

Edit the configuration properties for each configuration and in the Librarian,
add a relative path ..\..\lib to each library path. For example:

..\..\lib\$(PlatformName)\$(ConfigurationName)\wx_mono.lib

Then, for a sample you want to compile, edit the configuration properties
and make sure ..\..\lib\$(PlatformName)\$(ConfigurationName) is in the Linker/General/Additional
Library Directories property. Also change the Linker/Input/Additional Dependencies
property to something like:

coredll.lib wx_mono.lib wx_wxjpeg.lib wx_wxpng.lib wx_wxzlib.lib wx_wxexpat.lib commctrl.lib winsock.lib wininet.lib

since the library names in the wxWidgets workspace were changed
by VS 2005.

Status
======

It's possible to create working Pocket PC or Smartphone
applications with this port. For further information
about how to use wxWidgets with Windows CE, and further
work that needs to be done, see the wxWinCE topic in the
reference manual, and also:

http://wiki.wxwidgets.org/Developers_Notebook/WxWinCE

The "Life!" demo in demos/life has some adaptations for
wxWinCE, and also demonstrates how to make an installer for
a Pocket PC application.

Disclaimer
==========

All product names are used for identification purposes and are trademarks 
or registered trademarks owned by their respective companies.


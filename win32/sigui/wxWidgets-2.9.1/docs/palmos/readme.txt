                              wxPalm README
                              =============

NB: wxPalm is currently in pre-alpha stage -- but it's already fun!

I. Building wxPalm under Windows
--------------------------------

First, you need the freely distributable Palm OS Developer Studio available at

                http://www.palmos.com/dev/tools/dev_suite.html

Beware, its installation takes about 500Mb (+ 150 Mb of cygwin if not installed
yet), so make sure you have enough disk space for it and for wxWidgets build
tree (another 50Mb). Last tested set: PODS 1.2, SDK 6.1, wxWidgets 2.7.0.

The Developer Studio is Eclipse-based and so is a GUI environment, however it
is also possible to build Palm applications from the command line using the
usual GNU tools. Both methods are covered below, choose one which you prefer.

a) Using command line tools:
    - If you have installed Developer Studio in a non default location (e.g.
      d:\PalmOS), you will need to set the environment variables:

                set TOOLS_DIR=D:/PalmOS/PalmOSTools/
                set SDK_LOCATION=D:/PalmOS/sdk-6/

      Don't use backslashes and don't forget the trailing slash. On the bright
      side, spaces don't need to be escaped in any way.

    - create a lib/gcc_lib/palmos/wx directory
    - copy include/wx/palmos/setup0.h to lib/gcc_lib/palmos/wx/setup.h
        TODO: modify Makefile to do it automatically

    - ensure that the directories d:\PalmOS\PalmOSTools and the one containing
      GNU tools (i.e. cygwin bin directory) are in your PATH

    - go to build/palmos and run make

    - you should end up with DebugSim/wxWidgets.prc: this is the Palm database
      which you can load into the emulator

    - to test it, run the emulator (you need PalmOS 6 one!) after seting
      another env var:

                set PALMSOURCE_SIM_PATH=wxWindows\build\palmos\DebugSim

      wait until the emulator finishes to boot, right click it and choose
      "Install" in the menu, select wxWindows.prc in the file open dialog.
      You should see "Minimal App" with a familiar icon appear in the list,
      click it and it should start.


b) Using IDE:
    TODO: write this after checking that the instructions below work




Original note from William Osborne follows:

wxWidgets 2.5.3 CVS 10-18-2004
------------------------------

This is a Palm OS 6 port of the wxWidgets toolkit.  Included in the source 
package is the complete source necessary to build the Palm OS port using the 
Palm OS Developer Studio.  Also included is the diff showing the changes that 
need to be incorporated into the wxWidgets 2.5.3 CVS source tree before the 
Palm OS port can be integrated.

I am releasing this port to the wxWidgets team under the terms of the wxWindows 
license.  A copy of the wxWindows license is included in the source package.

No third party libraries or code were used in making this port.  The port consists 
entirely of code I personally wrote combined with code that was included in the 
wxWidgets 2.5.3 CSV source tree.  Whenever possible, I have used the Palm OS 6 API, 
in places where the API was not practical to use, I wrote my own functions.

I am submitting this source package as an entry in the wxWidgets Palm OS 6 port 
challenge.  Details on this challenge are available at:
http://www.wxwidgets.org/about/news/palmos.htm

Please note that this port is in a very early state.  Currently the port 
provides limited functionality for the wxFrame, wxMenu, wxStatusBar, 
wxTopLevelWindow, and wxWindow classes.  The other classes in the wxWidgets 
toolkit still need to be ported.  In it's current state, the Palm OS 6 port 
is capable of running the minimal wxWidgets sample

The easiest way to see the port in action is to build the source package with 
the Palm OS Developer Studio available at http://www.palmos.com/dev/dl/dl_tools/dl_pods/  
Here are the steps that you need to follow to build the package:

1) Unpack the ZIP file into a directory located within the Palm OS Developer 
   Studio workspace directory.  The path to the folder should look something 
   like this: "C:\Program Files\PalmSource\Palm OS Developer Suite\workspace\wxWidgets"

2) Open Palm OS Developer Studio and click on File->Import.

3) Select "Existing Project into Workspace" as the import source and click Next.

4) On the next screen click the Browse button next to Project contents and select
   the folder you unpacked the source package into.  Click on Finish to continue.

5) You should now see the project listed in the Project pane on the right side of the 
   window.  Click on the name of the project.  Now click on the Project menu and select
   "Rebuild Project"

6) After the build is complete, click on the Run menu and select ""  The Palm OS 6 simulator
   should start.  If this is the first time you have used the simulator, you will be prompted  
   to choose a ROM file.  You can find the ROM files in a folder like "C:\Program 
   Files\PalmSource\Palm OS Developer Suite\sdk-6\tools\Simulator\6.0.1\ROM"  It doesn't 
   really matter whether you choose a Release or a Debug ROM (the debug ROM generates extra 
   reports when an application crashes.)

7) You should see the Palm logo appear in the simulator window.  You may get a dialog box 
   asking you to choose a language.  Click OK to continue.  You should see the simulator 
   initialize the built-in Palm applications.  After a few moments, the wxWidgets minimal 
   sample should start.  Have fun!

Since this source package was based on the wxWidgets 2.5.3 CVS source tree dated October 18, 
2004 I don't anticipate any problems with merging the sources into the 2.5.3 source tree.

If you have any questions or comments about the port, please feel free to send an email to 
the wxWidgets developer list or directly to me at wbo@freeshell.org

Enjoy!
William Osborne
wbo@freeshell.org

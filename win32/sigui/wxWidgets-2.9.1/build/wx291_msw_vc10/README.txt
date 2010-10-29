===============================
===     wxWidgets 2.9.1     ===
=== MSVC 2010 Project Files ===
=== by Sami Hamlaoui (2010) ===
===============================

=========================================================================
=== 1. What?
=========================================================================

Microsoft.CppCommon.targets(151,5): error MSB6001: Invalid command line switch for "cmd.exe". The path is not of a legal form.

=========================================================================
=== 2. Why?
=========================================================================

The convertor in MSVC 2010 to load MSVC 2008 projects works fine. However, the custom build tool has changed in the latest release, and has issues with commands that have quotations and/or spaces in them. As wxWidgets relies on the custom build tool to copy the "Setup.h" file to the right directories, this caused a number of compile errors, rendering it impossible to build wxWidgets with this new compiler.

These project files have been modified to work around these limitations.

=========================================================================
=== 3. How?
=========================================================================

By removing all usage of the custom build tool. Instead, each project has a Pre-Build Event which copies the "Setup.h" file to the right location. The file and location differ depending on the project configuration (DLL/LIB, Standard/Universal) as before. The commands used are:

	xcopy ..\..\include\wx\XXX\setup.h ..\..\lib\vc_YYY\ZZZ\wx\ /Y

	XXX - "msw" or "univ", depending on the project configuration
	YYY - "lib" or "dll", depending on the project configuration
	ZZZ - "mswu", "mswud", "mswunivu" or "mswunivud" depending on the project configuration

"xcopy" is used over "copy" as it will automatically build the directory structure if needed ("copy" will generate errors on a clean install with no dictories created). The /Y switch tells it to override the destination file if one exists.

=========================================================================
=== 4. Where?
=========================================================================

The project files must be located in a subfolder under "build". You can place them in the "msw" folder along with the project files for older MSVC versions, or create a new folder. The name of the folder you put them in doesn't matter, provided it is located in the "build" folder.

=========================================================================
=== 5. When?
=========================================================================

These project files were released on 25th August 2010 by Sami Hamlaoui. They are provided as is. No support, no promise of updates (I can probably promise you that I won't update them), no responsibility if it somehow reformats your machine. Do with them what you will - I don't mind and I don't care :).

Also, I've only tested this with Visual C++ 2010 Express Edition, although it should compile fine on any version. The only 2 projects that it refused to compile are DLL Universal Debug/Release, due to missing wxActiveXEvent symbols. Seeing as MSVC 2008 gives me the exact same errors on the exact same configurations, I'm not going to pull my hair out trying to fix it.

Finally, I've enabled multi-processor compilation on all builds and projects to give it a nice speedup when building (especially handy when building all 8 versions of the 21 libraries!).

Enjoy!
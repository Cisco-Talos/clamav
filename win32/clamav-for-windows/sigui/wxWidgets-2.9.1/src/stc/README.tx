This contrib is the wxStyledTextCtrl, which is a wrapper around the
Scintilla edit control.  (See www.scintilla.org)

There is still VERY MUCH to be done, most notable of which is a more
advanced sample that exercises more of the code.  (I havn't tested
AutoComplete or CallTips, or most of the event types at all yet.)  And
also documentation, adding wrappers for some new scintilla
functionality, building and testing on wxGTK, etc.  Be patient, it all
will get there soon.



Let me describe a bit about the architecture I am implementing...
Obviously there is the Platform layer which implements the varioius
platform classes by using wxWindows classes and filling in where
needed.  Then there is a ScintillaWX class that is derived from
ScintillaBase and implements the necessary virtual methods that
Scintilla needs to fully funciton.  This class however is not meant to
ever be used directly by wx programmers.  I call it one end of the
bridge between the wx and Scintilla worlds.  The other end of the
bridge is a class called wxStyledTextCtrl that looks, feels and acts
like other classes in wxWindows.  Here is a diagram:


 +------------------+          +-------------------+
 | wxStyledTextCtrl |--bridge--|    ScintillaWX    |
 +------------------+          +-------------------+
                               |   ScintillaBase   |
                               +-------------------+
                               |       Editor      |
                               +-------------------+
                               |     PlatWX        |
                               +-------------------+


wxStyledTextCtrl derives from wxControl so it has a window that can be
drawn upon.  When a wxStyledTextCtrl is constructed it constructs a
ScintillaWX for itself and passes itself to the scintilla object to be
set as the wMain and wDraw attributes.  All method calls on the STC
are sent over the bridge in the form of calls to ScintiallWX::WndProc.
All notifications are sent back over the bridge and turned into
wxEvents.


Robin

[SOLARIS NOTE - ellers@iinet.net.au - June 2002]

On sunos5 (sparc) the stc code breaks if optimisation is turned on (the
default). If your release build breaks but the debug build is fine, 
try reconfiguring with --disable-optimise and rebuilding. If you are using
wxPython you will also need to disable optimised compiling. To do this I
had to hand modify the python makefile in (prefix)/lib/python2.2/config/Makefile
to remove optimisation flags.


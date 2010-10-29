wxMicroWindows port
===================

Warning: As of 2007-07-17 this port probably doesn't build any more.
         Please don't expect it to work out of the box currently.


Julian Smart 2001-12-08

This is a port of wxWidgets to MicroWindows, under Linux.
Widgets are supplied by the wxUniversal project, while the
underlying port uses the Windows ports with small modifications
for the MicroWindows API.

=== NOTE: ===

  Current efforts are being concentrated on a port to Nano-X,
  which potentially offers greater flexibility than the WIN32
  API of MicroWindows, such as the ability to run multiple
  Nano-X processes simultaneously. Please see
  ../docs/x11/readme-nanox.txt for information.

There are many things missing from MicroWindows that will
make the port quite limited for the time being.
In particular, only one WIN32 app may be run at a time.

Note that you can gain confidence in the WIN32/wxUniversal
combination by compiling wxUniversal under Windows using VC++,
using src/wxUniv.dsp. You can compile the minimal
and widgets samples in wxUniversal mode using the
UnivDebug and UnivRelease targets. Most of the code is shared
between this combination, and the wxMicroWindows port.

Installation
============

MicroWindows:

- unarchive MicroWindows 0.89pre8

- change 'config' to use X11 and any other options you feel fit.
  Suggestions for changes to the defaults:

  ERASEMOVE=N (otherwise moving windows will look messy)
  X11=Y
  OPTIMIZE=N
  DEBUG=Y
  VERBOSE=Y

  Note: these are already applied by the patch below.

- apply microwindows.patches (from wxWidgets:
  docs/microwin/microwindows.patches) to fix PeekMessage
  and other issues. If the patch doesn't apply automatically,
  you may need to apply it by hand, and the relevant changed
  functions are given at the end of this file for convenience.

  Example patch command:

  % cd microwindows-0.89pre8.orig
  % patch -p0 < ~/wx2/docs/microwin/microwindows.patches

- compile by typing 'make' from within the MicroWindows src directory

wxMicroWindows:

- Download wxMSW 2.3.4 or greater, or get it from CVS

- Many settings in include/wx/setup.h have to be disabled. As contents
  of this file keeps changing, it's impossible to say what exactly should be
  disabled but it probably makes sense to disable as much as possible
  initially, make sure that the build works and then add features as needed.

- EITHER:

  o set the MICROWINDOWS environment variable, e.g.:

    % export MICROWINDOWS=/home/julians/local/microwindows/microwindows-0.89pre8/src

  OR:

  o change the TOP variable at the top of src/msw/makefile.mic
    to reflect where MicroWindows is installed

- type 'make -f makefile.mic all' from src/msw. To clean, use
  cleanwx and NOT clean since that will clean MicroWindows itself

- to make the sample, cd into samples/minimal, edit the TOP variable
  (or set MICROWINDOWS) as before, and type 'make -f makefile.mic all'

Running 'minimal' runs the virtual MicroWindows desktop
and the minimal sample, since in a MicroWindows WIN32 application
they are one and the same binary.

Status
======

The minimal sample is almost fully-functional, apart from some
presentation issues (no menu borders and status bar in the wrong
place.

The widgets sample is crashing in DeleteObject (see notes below).


Implementation Notes
====================

wxMicroWindows is essentially the wxMSW port + wxUniversal
widgets. Lots of things in include/wx/univ/setup.h are switched
off to allow the port to compile. There are also #ifdefs
switching off further functionality, such as most wxBitmap
functions, pending proper implementation.

There are some WIN32 API functions not implemented by MicroWindows
that are instead stubbed out in include/wx/msw/microwin.c,
and 'implemented' in src/msw/microwin.c. Some of these functions
are important, some less so. They will need to be implemented
in due course. But implementing missing functionality in this way
is preferably to proliferating many #ifdefs in the
wxMSW/wxMicroWindows port itself.


Errors/warnings
===============

In file ../../src/msw/window.cpp at line 1294: 'UpdateWindow' failed with error 0x00000000 (Success).

  - caused because there are no paint messages pending. Presumed
    harmless.

In file ../../src/msw/dc.cpp at line 1838: 'BitBlt' failed with error 0x00000000 (Success).

  - caused because the window isn't mapped, and MwPrepareDC in wingdi.c
    fails (hwnd->unmapcount is non-zero). Presumed harmless.

Recursive paint problem, e.g. when clicking the 'Press Me!'
button in the widgets sample a few times, until the text control
is full.

  - possibly the scrollbar is causing the text control to be
    updated, which somehow effects the scrollbar, which causes
    a window update, etc.

Sluggish updates.

  - probably because many image to bitmap conversions are being
    done on update, and bitmaps should probably be cached.


Things missing from MicroWindows that need to be worked around
==============================================================

wxImage/inline XPM/::CreateBitmap support
-----------------------------------------

This is the main obstacle to getting a good range
of widgets working, since wxUniversal uses inline XPMs
to implement most of the widgets.

See src/engine/devimage.c for routines for loading JPEGs,
XPMs etc. Unfortunately the XPM routines are also #ifdefed
for FILE_IO, even though for inline XPMs we don't need file I/O.
(Embedded systems tend not to have file I/O, anyway.)

Now, wxWidgets has its own XPM decoder, src/common/xpmdecod.cpp,
so in theory we don't need to use MicroWindows' code there.
wxImage can load an inline XPM, _but_ we need to convert to
a wxBitmap since this is what the widgets need.

There is no ::CreateBitmap or BITMAPINFO. (BMPs can be converted
to C using convbmp, then need to use Gr... functions.)

So how can we convert from wxImage to wxBitmap in MicroWindows?

Well, a simple-minded way would be to use CreateCompatibleBitmap
which returns an HBITMAP, select it into an HDC, and draw
the pixels from the wxImage to the HDC one by one with SetPixel.
This is now implemented, but there are problems with masks.
(a) masks have to be created at screen depth because BitBlt/GrDraw
can't cope with differing depths, and (b) masked blitting
is still not working (try enabling mask creation in
wxBitmap::CreateFromImage by setting USE_MASKS to 1).


Other missing features
----------------------

No ::GetKeyState (see include/wx/msw/private.h). Should probably use
GdOpenKeyboard/GdCloseKeyboard/GdReadKeyboard. Could perhaps emulate
GetKeyState this way.

No ::DestroyIcon, ::DestroyCursor - use ::DestroyObject instead?
Also no LoadCursor, LoadImage. So how do we make cursors? No ::SetCursor.

wxDC: no ::GetTextColor, ::GetBkColor, ::IntersectClipRect,
::GetClipBox

No ::SetMenu, so no menus or menubars (now implemented by
wxUniversal).

No ::GetObject so we can't get LOGFONT from an HFONT
in wxSystemSettings (worked around by passing HFONT to
the wxFont constructor).


Applying patches by hand
========================

The full altered functions are given below in case you have
to apply them by hand.

src/mwin/winevent.c
-------------------

A second test has been added to this line:

	if(hittest == HTCLIENT || hwnd == GetCapture()) {

in MwTranslateMouseMessage below. This corrects a mouse message
bug.

/*
 * Translate and deliver hardware mouse message to proper window.
 */
void
MwTranslateMouseMessage(HWND hwnd,UINT msg,int hittest)
{
	POINT		pt;
	DWORD		tick;
	static UINT	lastmsg = 0;
	static HWND	lasthwnd;
	static DWORD	lasttick;
	static int	lastx, lasty;

	/* determine double click eligibility*/
	if(msg == WM_LBUTTONDOWN || msg == WM_RBUTTONDOWN) {
		tick = GetTickCount();
		if((hwnd->pClass->style & CS_DBLCLKS) &&
		    msg == lastmsg && hwnd == lasthwnd &&
		    tick - lasttick < DBLCLICKSPEED &&
		    abs(cursorx-lastx) < mwSYSMETRICS_CXDOUBLECLK &&
		    abs(cursory-lasty) < mwSYSMETRICS_CYDOUBLECLK)
			msg += (WM_LBUTTONDBLCLK - WM_LBUTTONDOWN);
		lastmsg = msg;
		lasthwnd = hwnd;
		lasttick = tick;
		lastx = cursorx;
		lasty = cursory;
	}

	/*
	 * We always send nc mouse message
	 * unlike Windows, for HTCLIENT default processing
	 */
	PostMessage(hwnd, msg + (WM_NCMOUSEMOVE-WM_MOUSEMOVE), hittest,
		MAKELONG(cursorx, cursory));

	/* then possibly send user mouse message*/
	if(hittest == HTCLIENT || hwnd == GetCapture()) {
		pt.x = cursorx;
		pt.y = cursory;
		ScreenToClient(hwnd, &pt);
		PostMessage(hwnd, msg, 0, MAKELONG(pt.x, pt.y));
	}
}

winuser.c
---------

Part of PeekMessage has been factored out into PeekMessageHelper,
and used in PeekMessage and GetMessage. The three relevant functions
are:

/*
 * A helper function for sharing code between PeekMessage and GetMessage
 */

BOOL WINAPI
PeekMessageHelper(LPMSG lpMsg, HWND hwnd, UINT uMsgFilterMin, UINT uMsgFilterMax,
	UINT wRemoveMsg, BOOL returnIfEmptyQueue)
{
	HWND	wp;
	PMSG	pNxtMsg;

	/* check if no messages in queue*/
	if(mwMsgHead.head == NULL) {
                /* Added by JACS so it doesn't reach MwSelect */
                if (returnIfEmptyQueue)
                    return FALSE;

#if PAINTONCE
		/* check all windows for pending paint messages*/
		for(wp=listwp; wp; wp=wp->next) {
			if(!(wp->style & WS_CHILD)) {
				if(chkPaintMsg(wp, lpMsg))
					return TRUE;
			}
		}
		for(wp=listwp; wp; wp=wp->next) {
			if(wp->style & WS_CHILD) {
				if(chkPaintMsg(wp, lpMsg))
					return TRUE;
			}
		}
#endif
		MwSelect();
	}

	if(mwMsgHead.head == NULL)
		return FALSE;

	pNxtMsg = (PMSG)mwMsgHead.head;
	if(wRemoveMsg & PM_REMOVE)
		GdListRemove(&mwMsgHead, &pNxtMsg->link);
	*lpMsg = *pNxtMsg;
	if(wRemoveMsg & PM_REMOVE)
		GdItemFree(pNxtMsg);
	return TRUE;
}

BOOL WINAPI
PeekMessage(LPMSG lpMsg, HWND hwnd, UINT uMsgFilterMin, UINT uMsgFilterMax,
	UINT wRemoveMsg)
{
        /* Never wait in MwSelect: pass TRUE */
        return PeekMessageHelper(lpMsg, hwnd, uMsgFilterMin, uMsgFilterMax, wRemoveMsg, TRUE);
}

BOOL WINAPI
GetMessage(LPMSG lpMsg,HWND hwnd,UINT wMsgFilterMin,UINT wMsgFilterMax)
{
	/*
	 * currently MwSelect() must poll for VT switch reasons,
	 * so this code will work
	 */
        /* Always wait in MwSelect if there are messages: pass FALSE */
	while(!PeekMessageHelper(lpMsg, hwnd, wMsgFilterMin, wMsgFilterMax,PM_REMOVE, FALSE))
		continue;
	return lpMsg->message != WM_QUIT;
}

/////////////////////////////////////////////////////////////////////////////
// Name:        wx/uiaction.h
// Purpose:     wxUIActionSimulator interface
// Author:      Kevin Ollivier
// Modified by:
// Created:     2010-03-06
// RCS-ID:      $Id: menu.cpp 54129 2008-06-11 19:30:52Z SC $
// Copyright:   (c) Kevin Ollivier
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_UIACTIONSIMULATOR_H_
#define _WX_UIACTIONSIMULATOR_H_

#include "wx/defs.h"

#if wxUSE_UIACTIONSIMULATOR

#include "wx/event.h"
#include "wx/dynarray.h"

class WXDLLIMPEXP_CORE wxUIActionSimulator
{
public:
    wxUIActionSimulator();
    ~wxUIActionSimulator();

    // Mouse related
    bool        MouseMove(long x, long y);
    bool        MouseDown(int button = wxMOUSE_BTN_LEFT);
    bool        MouseUp(int button = wxMOUSE_BTN_LEFT);
    bool        MouseClick(int button = wxMOUSE_BTN_LEFT);
    bool        MouseDblClick(int button = wxMOUSE_BTN_LEFT);
    bool        MouseDragDrop(long x1, long y1, long x2, long y2, int button = wxMOUSE_BTN_LEFT);

    // Keyboard related:

    bool        KeyDown(int keycode, bool shiftDown=false, bool cmdDown=false, bool altDown=false)
                    { return Key(keycode, true, shiftDown, cmdDown, altDown); }

    bool        KeyUp(int keycode, bool shiftDown=false, bool cmdDown=false, bool altDown=false)
                    { return Key(keycode, false, shiftDown, cmdDown, altDown); }

    bool        Char(int keycode, bool shiftDown=false, bool cmdDown=false, bool altDown=false);

protected:
    // Implementation-wise, since key events take more code to set up on GTK and Mac, it makes
    // sense to handle both key down and key up in one method. However, I wanted the API for pressing
    // and releasing the mouse and keyboard to be consistent, and I don't really like using a bool
    // for pressed state, so I'm leaving this as an implementation detail.
    bool        Key(int keycode, bool isDown=true, bool shiftDown=false, bool cmdDown=false, bool altDown=false);
};

#endif // wxUSE_UIACTIONSIMULATOR

#endif // _WX_UIACTIONSIMULATOR_H_

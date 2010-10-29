/////////////////////////////////////////////////////////////////////////////
// Name:        src/common/uiactioncmn.cpp
// Purpose:     wxUIActionSimulator common implementation
// Author:      Kevin Ollivier
// Modified by:
// Created:     2010-03-06
// RCS-ID:      $Id: menu.cpp 54129 2008-06-11 19:30:52Z SC $
// Copyright:   (c) Kevin Ollivier
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#if wxUSE_UIACTIONSIMULATOR

#include "wx/uiaction.h"

wxUIActionSimulator::wxUIActionSimulator()
{
}

wxUIActionSimulator::~wxUIActionSimulator()
{
}


bool wxUIActionSimulator::MouseClick(int button)
{
    MouseDown(button);
    MouseUp(button);

    return true;
}

bool wxUIActionSimulator::MouseDblClick(int button)
{
    MouseDown(button);
    MouseUp(button);
    MouseDown(button);
    MouseUp(button);

    return true;
}

bool wxUIActionSimulator::MouseDragDrop(long x1, long y1, long x2, long y2, int button)
{
    MouseMove(x1, y1);
    MouseDown(button);
    MouseMove(x2, y2);
    MouseUp(button);

    return true;
}

bool  wxUIActionSimulator::Char(int keycode, bool shiftDown, bool cmdDown, bool altDown)
{
    Key(keycode, false, shiftDown, cmdDown, altDown);
    Key(keycode, true, shiftDown, cmdDown, altDown);

    return true;
}

#endif // wxUSE_UIACTIONSIMULATOR

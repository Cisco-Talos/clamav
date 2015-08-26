/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/main.cpp
// Purpose:     Entry point
// Author:      David Elliott
// Modified by:
// Created:     2002/11/11
// RCS-ID:      $Id$
// Copyright:   (c) 2002 David Elliott
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////
/* DFE: ^^^^^ Was that really necessary :-) */

#include "wx/wxprec.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
#endif // WX_PRECOMP

WXDLLEXPORT int main(int argc, char* argv[])
{
    return wxEntry(argc, argv);
}

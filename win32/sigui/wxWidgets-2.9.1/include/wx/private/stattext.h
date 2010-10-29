/////////////////////////////////////////////////////////////////////////////
// Name:        wx/private/stattext.h
// Purpose:     Internal declarations for dlgcmn.cpp and stattextcmn.cpp
// Author:      Francesco Montorsi
// Created:     2007-01-07 (extracted from dlgcmn.cpp)
// RCS-ID:      $Id$
// Copyright:   (c) 1999 Vadim Zeitlin
//              (c) 2007 wxWidgets team
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_PRIVATE_STATTEXT_H_
#define _WX_PRIVATE_STATTEXT_H_

#include "wx/window.h"

enum
{
    wxMARKUP_ENTITY_AMP,
    wxMARKUP_ENTITY_LT,
    wxMARKUP_ENTITY_GT,
    wxMARKUP_ENTITY_APOS,
    wxMARKUP_ENTITY_QUOT,
    wxMARKUP_ENTITY_MAX
};

enum
{
    wxMARKUP_ELEMENT_NAME,
    wxMARKUP_ELEMENT_VALUE,
    wxMARKUP_ELEMENT_MAX
};

// these are the only entities treated in a special way by wxStaticText::SetLabel()
// when the wxST_MARKUP style is used; use as:
//
//    wxMarkupEntities[wxMARKUP_ELEMENT_NAME][wxMARKUP_ENTITY_GT]  == "&gt;"
//    wxMarkupEntities[wxMARKUP_ELEMENT_VALUE][wxMARKUP_ENTITY_GT] == ">"
//
extern const wxChar *wxMarkupEntities[wxMARKUP_ELEMENT_MAX][wxMARKUP_ENTITY_MAX];

#endif // _WX_PRIVATE_STATTEXT_H_

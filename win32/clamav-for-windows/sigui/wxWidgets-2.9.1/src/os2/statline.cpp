/////////////////////////////////////////////////////////////////////////////
// Name:        src/os2/statline.cpp
// Purpose:     OS2 version of wxStaticLine class
// Author:      David Webster
// Created:     10/23/99
// Version:     $Id$
// Copyright:   (c) 1999 David Webster
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_STATLINE

#include "wx/statline.h"

#ifndef WX_PRECOMP
    #include "wx/log.h"
#endif

#include "wx/os2/private.h"

// ============================================================================
// implementation
// ============================================================================

IMPLEMENT_DYNAMIC_CLASS(wxStaticLine, wxControl)

// ----------------------------------------------------------------------------
// wxStaticLine
// ----------------------------------------------------------------------------

bool wxStaticLine::Create(
  wxWindow*                         pParent
, wxWindowID                        vId
, const wxPoint&                    rPos
, const wxSize&                     rSize
, long                              lStyle
, const wxString&                   rsName
)
{
    wxSize                          vSize = AdjustSize(rSize);

    if ( !CreateControl( pParent
                        ,vId
                        ,rPos
                        ,vSize
                        ,lStyle
                        ,wxDefaultValidator
                        ,rsName
                       ))
        return FALSE;
    if (!OS2CreateControl( wxT("STATIC")
                          ,SS_FGNDFRAME
                          ,rPos
                          ,rSize
                          ,rsName
                         ))
        return FALSE;

    wxColour                        vColour;

    vColour.Set(wxString(wxT("GREY")));

    LONG                            lColor = (LONG)vColour.GetPixel();

    ::WinSetPresParam( m_hWnd
                      ,PP_FOREGROUNDCOLOR
                      ,sizeof(LONG)
                      ,(PVOID)&lColor
                     );
    return TRUE;
} // end of wxStaticLine::Create

WXDWORD wxStaticLine::OS2GetStyle(
  long                              lStyle
, WXDWORD*                          pdwExstyle
) const
{
    //
    // We never have border
    //
    lStyle &= ~wxBORDER_MASK;
    lStyle |= wxBORDER_NONE;

    WXDWORD                         dwStyle = wxControl::OS2GetStyle( lStyle
                                                                     ,pdwExstyle
                                                                    );
    //
    // Add our default styles
    //
    return dwStyle | WS_CLIPSIBLINGS;
}
#endif // wxUSE_STATLINE

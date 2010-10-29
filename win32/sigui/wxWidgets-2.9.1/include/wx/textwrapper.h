///////////////////////////////////////////////////////////////////////////////
// Name:        wx/textwrapper.h
// Purpose:     declaration of wxTextWrapper class
// Author:      Vadim Zeitlin
// Created:     2009-05-31 (extracted from dlgcmn.cpp via wx/private/stattext.h)
// RCS-ID:      $Id$
// Copyright:   (c) 1999, 2009 Vadim Zeitlin <vadim@wxwidgets.org>
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

#ifndef _WX_TEXTWRAPPER_H_
#define _WX_TEXTWRAPPER_H_

#include "wx/window.h"

// ----------------------------------------------------------------------------
// wxTextWrapper
// ----------------------------------------------------------------------------

// this class is used to wrap the text on word boundary: wrapping is done by
// calling OnStartLine() and OnOutputLine() functions
class WXDLLIMPEXP_CORE wxTextWrapper
{
public:
    wxTextWrapper() { m_eol = false; }

    // win is used for getting the font, text is the text to wrap, width is the
    // max line width or -1 to disable wrapping
    void Wrap(wxWindow *win, const wxString& text, int widthMax);

    // we don't need it, but just to avoid compiler warnings
    virtual ~wxTextWrapper() { }

protected:
    // line may be empty
    virtual void OnOutputLine(const wxString& line) = 0;

    // called at the start of every new line (except the very first one)
    virtual void OnNewLine() { }

private:
    // call OnOutputLine() and set m_eol to true
    void DoOutputLine(const wxString& line)
    {
        OnOutputLine(line);

        m_eol = true;
    }

    // this function is a destructive inspector: when it returns true it also
    // resets the flag to false so calling it again wouldn't return true any
    // more
    bool IsStartOfNewLine()
    {
        if ( !m_eol )
            return false;

        m_eol = false;

        return true;
    }


    bool m_eol;

    wxDECLARE_NO_COPY_CLASS(wxTextWrapper);
};

#endif // _WX_TEXTWRAPPER_H_


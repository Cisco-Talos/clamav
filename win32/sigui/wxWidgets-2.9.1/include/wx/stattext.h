/////////////////////////////////////////////////////////////////////////////
// Name:        stattext.h
// Purpose:     wxStaticText base header
// Author:      Julian Smart
// Modified by:
// Created:
// Copyright:   (c) Julian Smart
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_STATTEXT_H_BASE_
#define _WX_STATTEXT_H_BASE_

#include "wx/defs.h"

#if wxUSE_STATTEXT

#include "wx/control.h"

/*
 * wxStaticText flags
 */
#define wxST_NO_AUTORESIZE         0x0001
#define wxST_MARKUP                0x0002
#define wxST_ELLIPSIZE_START       0x0004
#define wxST_ELLIPSIZE_MIDDLE      0x0008
#define wxST_ELLIPSIZE_END         0x0010

extern WXDLLIMPEXP_DATA_CORE(const char) wxStaticTextNameStr[];

class WXDLLIMPEXP_CORE wxStaticTextBase : public wxControl
{
public:
    wxStaticTextBase() { }

    // wrap the text of the control so that no line is longer than the given
    // width (if possible: this function won't break words)
    // This function will modify the value returned by GetLabel()!
    void Wrap(int width);

    // overriden base virtuals
    virtual bool AcceptsFocus() const { return false; }
    virtual bool HasTransparentBackground() { return true; }

    bool IsEllipsized() const
    {
        return HasFlag(wxST_ELLIPSIZE_START) ||
               HasFlag(wxST_ELLIPSIZE_MIDDLE) ||
               HasFlag(wxST_ELLIPSIZE_END);
    }

    // get the string without mnemonic characters ('&') and without markup
    // (if the wxST_MARKUP style is set)
    virtual wxString GetLabelText() const;

    // set label text (mnemonics and markup, if the wxST_MARKUP style is set,
    // will be escaped)
    virtual void SetLabelText(const wxString& text);


    // static utilities for markup handling
    // (symmetric to those in wxControl about mnemonics)
    // -------------------------------------------------

    // get the string without mnemonic characters ('&') and without markup
    // (note that markup is always removed; this function is static and cannot
    //  check for wxST_MARKUP style presence/absence!)
    static wxString GetLabelText(const wxString& label);

    // removes the markup recognized by wxStaticText and returns the cleaned string
    static wxString RemoveMarkup(const wxString& str);

    // escapes all special symbols (<>"'&) present in the given string
    // using the corresponding entities (&lt; &gt; &quot; &apos; &amp;)
    static wxString EscapeMarkup(const wxString& str);

protected:      // functions required for wxST_ELLIPSIZE_* support

    // choose the default border for this window
    virtual wxBorder GetDefaultBorder() const { return wxBORDER_NONE; }

    // calls only RemoveMarkup() on the original label 
    // if the wxST_MARKUP style is set
    // (but unlike GetLabelText won't remove mnemonics)
    virtual wxString GetLabelWithoutMarkup() const;

    // just calls RemoveMarkup() & Ellipsize() on the original label 
    // if the wxST_MARKUP & wxST_ELLIPSIZE_* styles are set
    // (but unlike GetLabelText won't remove mnemonics)
    virtual wxString GetEllipsizedLabelWithoutMarkup() const;

    // replaces parts of the string with ellipsis if needed
    wxString Ellipsize(const wxString& label) const;

    // to be called when updating the size of the static text:
    // updates the label redoing ellipsization calculations
    void UpdateLabel();

    // These functions are platform-specific and must be overridden in ports
    // which do not natively support ellipsization and they must be implemented
    // in a way so that the m_labelOrig member of wxControl is not touched:

    // returns the real label currently displayed inside the control.
    virtual wxString DoGetLabel() const { return wxEmptyString; }

    // sets the real label currently displayed inside the control,
    // _without_ invalidating the size. The text passed is always markup-free
    // but may contain the mnemonic characters.
    virtual void DoSetLabel(const wxString& WXUNUSED(str)) { }

private:
    wxDECLARE_NO_COPY_CLASS(wxStaticTextBase);
};

// see wx/generic/stattextg.h for the explanation
#ifndef wxNO_PORT_STATTEXT_INCLUDE

#if defined(__WXUNIVERSAL__)
    #include "wx/univ/stattext.h"
#elif defined(__WXMSW__)
    #include "wx/msw/stattext.h"
#elif defined(__WXMOTIF__)
    #include "wx/motif/stattext.h"
#elif defined(__WXGTK20__)
    #include "wx/gtk/stattext.h"
#elif defined(__WXGTK__)
    #include "wx/gtk1/stattext.h"
#elif defined(__WXMAC__)
    #include "wx/osx/stattext.h"
#elif defined(__WXCOCOA__)
    #include "wx/cocoa/stattext.h"
#elif defined(__WXPM__)
    #include "wx/os2/stattext.h"
#elif defined(__WXPALMOS__)
    #include "wx/palmos/stattext.h"
#endif

#endif // !wxNO_PORT_STATTEXT_INCLUDE

#endif // wxUSE_STATTEXT

#endif // _WX_STATTEXT_H_BASE_

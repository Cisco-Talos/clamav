/////////////////////////////////////////////////////////////////////////////
// Name:        src/common/ctrlcmn.cpp
// Purpose:     wxControl common interface
// Author:      Vadim Zeitlin
// Modified by:
// Created:     26.07.99
// RCS-ID:      $Id$
// Copyright:   (c) wxWidgets team
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

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_CONTROLS

#include "wx/control.h"

#ifndef WX_PRECOMP
    #include "wx/dc.h"
    #include "wx/log.h"
    #include "wx/radiobut.h"
    #include "wx/statbmp.h"
    #include "wx/bitmap.h"
    #include "wx/utils.h"       // for wxStripMenuCodes()
    #include "wx/settings.h"
#endif

const char wxControlNameStr[] = "control";

// ============================================================================
// implementation
// ============================================================================

wxControlBase::~wxControlBase()
{
    // this destructor is required for Darwin
}

bool wxControlBase::Create(wxWindow *parent,
                           wxWindowID id,
                           const wxPoint &pos,
                           const wxSize &size,
                           long style,
                           const wxValidator& wxVALIDATOR_PARAM(validator),
                           const wxString &name)
{
    bool ret = wxWindow::Create(parent, id, pos, size, style, name);

#if wxUSE_VALIDATORS
    if ( ret )
        SetValidator(validator);
#endif // wxUSE_VALIDATORS

    return ret;
}

bool wxControlBase::CreateControl(wxWindowBase *parent,
                                  wxWindowID id,
                                  const wxPoint& pos,
                                  const wxSize& size,
                                  long style,
                                  const wxValidator& validator,
                                  const wxString& name)
{
    // even if it's possible to create controls without parents in some port,
    // it should surely be discouraged because it doesn't work at all under
    // Windows
    wxCHECK_MSG( parent, false, wxT("all controls must have parents") );

    if ( !CreateBase(parent, id, pos, size, style, validator, name) )
        return false;

    parent->AddChild(this);

    return true;
}

void wxControlBase::Command(wxCommandEvent& event)
{
    (void)GetEventHandler()->ProcessEvent(event);
}

void wxControlBase::InitCommandEvent(wxCommandEvent& event) const
{
    event.SetEventObject((wxControlBase *)this);    // const_cast

    // event.SetId(GetId()); -- this is usuall done in the event ctor

    switch ( m_clientDataType )
    {
        case wxClientData_Void:
            event.SetClientData(GetClientData());
            break;

        case wxClientData_Object:
            event.SetClientObject(GetClientObject());
            break;

        case wxClientData_None:
            // nothing to do
            ;
    }
}

bool wxControlBase::SetFont(const wxFont& font)
{
    InvalidateBestSize();
    return wxWindow::SetFont(font);
}

// wxControl-specific processing after processing the update event
void wxControlBase::DoUpdateWindowUI(wxUpdateUIEvent& event)
{
    // call inherited
    wxWindowBase::DoUpdateWindowUI(event);

    // update label
    if ( event.GetSetText() )
    {
        if ( event.GetText() != GetLabel() )
            SetLabel(event.GetText());
    }

    // Unfortunately we don't yet have common base class for
    // wxRadioButton, so we handle updates of radiobuttons here.
    // TODO: If once wxRadioButtonBase will exist, move this code there.
#if wxUSE_RADIOBTN
    if ( event.GetSetChecked() )
    {
        wxRadioButton *radiobtn = wxDynamicCastThis(wxRadioButton);
        if ( radiobtn )
            radiobtn->SetValue(event.GetChecked());
    }
#endif // wxUSE_RADIOBTN
}

/* static */
wxString wxControlBase::GetLabelText(const wxString& label)
{
    // we don't want strip the TABs here, just the mnemonics
    return wxStripMenuCodes(label, wxStrip_Mnemonics);
}

/* static */
wxString wxControlBase::RemoveMnemonics(const wxString& str)
{
    // we don't want strip the TABs here, just the mnemonics
    return wxStripMenuCodes(str, wxStrip_Mnemonics);
}

/* static */
wxString wxControlBase::EscapeMnemonics(const wxString& text)
{
    wxString label(text);
    label.Replace("&", "&&");
    return label;
}

/* static */
int wxControlBase::FindAccelIndex(const wxString& label, wxString *labelOnly)
{
    // the character following MNEMONIC_PREFIX is the accelerator for this
    // control unless it is MNEMONIC_PREFIX too - this allows to insert
    // literal MNEMONIC_PREFIX chars into the label
    static const wxChar MNEMONIC_PREFIX = wxT('&');

    if ( labelOnly )
    {
        labelOnly->Empty();
        labelOnly->Alloc(label.length());
    }

    int indexAccel = -1;
    for ( wxString::const_iterator pc = label.begin(); pc != label.end(); ++pc )
    {
        if ( *pc == MNEMONIC_PREFIX )
        {
            ++pc; // skip it
            if ( pc == label.end() )
                break;
            else if ( *pc != MNEMONIC_PREFIX )
            {
                if ( indexAccel == -1 )
                {
                    // remember it (-1 is for MNEMONIC_PREFIX itself
                    indexAccel = pc - label.begin() - 1;
                }
                else
                {
                    wxFAIL_MSG(wxT("duplicate accel char in control label"));
                }
            }
        }

        if ( labelOnly )
        {
            *labelOnly += *pc;
        }
    }

    return indexAccel;
}

wxBorder wxControlBase::GetDefaultBorder() const
{
    return wxBORDER_THEME;
}

/* static */ wxVisualAttributes
wxControlBase::GetCompositeControlsDefaultAttributes(wxWindowVariant WXUNUSED(variant))
{
    wxVisualAttributes attrs;
    attrs.font = wxSystemSettings::GetFont(wxSYS_DEFAULT_GUI_FONT);
    attrs.colFg = wxSystemSettings::GetColour(wxSYS_COLOUR_WINDOWTEXT);
    attrs.colBg = wxSystemSettings::GetColour(wxSYS_COLOUR_WINDOW);

    return attrs;
}

// ----------------------------------------------------------------------------
// wxControlBase - ellipsization code
// ----------------------------------------------------------------------------

#define wxELLIPSE_REPLACEMENT       wxS("...")

/* static and protected */
wxString wxControlBase::DoEllipsizeSingleLine(const wxString& curLine, const wxDC& dc,
                                              wxEllipsizeMode mode, int maxFinalWidthPx,
                                              int replacementWidthPx, int marginWidthPx)
{
    wxASSERT_MSG(replacementWidthPx > 0 && marginWidthPx > 0,
                 "Invalid parameters");
    wxASSERT_LEVEL_2_MSG(!curLine.Contains('\n'),
                         "Use Ellipsize() instead!");

    wxASSERT_MSG( mode != wxELLIPSIZE_NONE, "shouldn't be called at all then" );

    // NOTE: this function assumes that any mnemonic/tab character has already
    //       been handled if it was necessary to handle them (see Ellipsize())

    if (maxFinalWidthPx <= 0)
        return wxEmptyString;

    wxArrayInt charOffsetsPx;
    size_t len = curLine.length();
    if (len == 0 ||
        !dc.GetPartialTextExtents(curLine, charOffsetsPx))
        return curLine;

    wxASSERT(charOffsetsPx.GetCount() == len);

    // NOTE: charOffsetsPx[n] is the width in pixels of the first n characters (with the last one INCLUDED)
    //       thus charOffsetsPx[len-1] is the total width of the string
    size_t totalWidthPx = charOffsetsPx.Last();
    if ( totalWidthPx <= (size_t)maxFinalWidthPx )
        return curLine;     // we don't need to do any ellipsization!

    int excessPx = wxMin(totalWidthPx - maxFinalWidthPx +
                         replacementWidthPx +
                         marginWidthPx,     // security margin
                         totalWidthPx);
    wxASSERT(excessPx>0);       // excessPx should be in the [1;totalWidthPx] range

    // REMEMBER: indexes inside the string have a valid range of [0;len-1] if not otherwise constrained
    //           lengths/counts of characters (e.g. nCharsToRemove) have a valid range of [0;len] if not otherwise constrained
    // NOTE: since this point we know we have for sure a non-empty string from which we need
    //       to remove _at least_ one character (thus nCharsToRemove below is constrained to be >= 1)

    size_t initialCharToRemove,     // index of first character to erase, valid range is [0;len-1]
           nCharsToRemove;          // how many chars do we need to erase? valid range is [1;len-initialCharToRemove]

    // let's compute the range of characters to remove depending on the ellipsization mode:
    switch (mode)
    {
        case wxELLIPSIZE_START:
            initialCharToRemove = 0;
            for ( nCharsToRemove = 1;
                  nCharsToRemove < len && charOffsetsPx[nCharsToRemove-1] < excessPx;
                  nCharsToRemove++ )
                ;
            break;

        case wxELLIPSIZE_MIDDLE:
            {
                // NOTE: the following piece of code works also when len == 1

                // start the removal process from the middle of the string
                // i.e. separe the string in three parts: 
                // - the first one to preserve, valid range [0;initialCharToRemove-1] or the empty range if initialCharToRemove==0
                // - the second one to remove, valid range [initialCharToRemove;endCharToRemove]
                // - the third one to preserve, valid range [endCharToRemove+1;len-1] or the empty range if endCharToRemove==len-1
                // NOTE: empty range != range [0;0] since the range [0;0] contains 1 character (the zero-th one)!
                initialCharToRemove = len/2;
                size_t endCharToRemove = len/2;     // index of the last character to remove; valid range is [0;len-1]

                int removedPx = 0;
                for ( ; removedPx < excessPx; )
                {
                    // try to remove the last character of the first part of the string
                    if (initialCharToRemove > 0)
                    {
                        // width of the (initialCharToRemove-1)-th character
                        int widthPx;
                        if (initialCharToRemove >= 2)
                            widthPx = charOffsetsPx[initialCharToRemove-1] - charOffsetsPx[initialCharToRemove-2];
                        else
                            widthPx = charOffsetsPx[initialCharToRemove-1];     
                                // the (initialCharToRemove-1)-th character is the first char of the string
                        
                        wxASSERT(widthPx >= 0);     // widthPx is zero for e.g. tab characters

                        // mark the (initialCharToRemove-1)-th character as removable
                        initialCharToRemove--;
                        removedPx += widthPx;
                    }

                    // try to remove the first character of the last part of the string
                    if (endCharToRemove < len - 1 &&
                        removedPx < excessPx)
                    {
                        // width of the (endCharToRemove+1)-th character
                        int widthPx = charOffsetsPx[endCharToRemove+1] -
                                      charOffsetsPx[endCharToRemove];

                        wxASSERT(widthPx >= 0);     // widthPx is zero for e.g. tab characters

                        // mark the (endCharToRemove+1)-th character as removable
                        endCharToRemove++;
                        removedPx += widthPx;
                    }

                    if (initialCharToRemove == 0 && endCharToRemove == len-1)
                    {
                        // we need to remove all the characters of the string!
                        break;
                    }
                }

                nCharsToRemove = endCharToRemove - initialCharToRemove + 1;
            }
            break;

        case wxELLIPSIZE_END:
            {
                int maxWidthPx = totalWidthPx - excessPx;

                // go backward from the end of the string toward the start
                for ( initialCharToRemove = len-1;
                      initialCharToRemove > 0 && charOffsetsPx[initialCharToRemove-1] > maxWidthPx;
                      initialCharToRemove-- )
                    ;
                nCharsToRemove = len - initialCharToRemove;
            }
            break;

        case wxELLIPSIZE_NONE:
        default:
            wxFAIL_MSG("invalid ellipsize mode");
            return curLine;
    }

#ifdef __VMS
#pragma message disable unscomzer
   // suppress warnings on comparison of unsigned numbers
#endif
   wxASSERT(initialCharToRemove >= 0 && initialCharToRemove <= len-1);  // see valid range for initialCharToRemove above
#ifdef __VMS
#pragma message enable unscomzer
   // suppress warnings on comparison of unsigned numbers
#endif
    wxASSERT(nCharsToRemove >= 1 && nCharsToRemove <= len-initialCharToRemove);  // see valid range for nCharsToRemove above

    // erase nCharsToRemove characters after initialCharToRemove (included);
    // e.g. if we have the string "foobar" (len = 6)
    //                               ^
    //                               \--- initialCharToRemove = 2
    //      and nCharsToRemove = 2, then we get "foar"
    wxString ret(curLine);
    ret.erase(initialCharToRemove, nCharsToRemove);

    int removedPx;
    if (initialCharToRemove >= 1)
        removedPx = charOffsetsPx[initialCharToRemove+nCharsToRemove-1] - charOffsetsPx[initialCharToRemove-1];
    else 
        removedPx = charOffsetsPx[initialCharToRemove+nCharsToRemove-1];
    wxASSERT(removedPx >= excessPx);

    // if there is space for the replacement dots, add them
    if ((int)totalWidthPx-removedPx+replacementWidthPx < maxFinalWidthPx)
        ret.insert(initialCharToRemove, wxELLIPSE_REPLACEMENT);

    // if everything was ok, we should have shortened this line
    // enough to make it fit in maxFinalWidthPx:
    wxASSERT_LEVEL_2(dc.GetTextExtent(ret).GetWidth() <= maxFinalWidthPx);

    return ret;
}

/* static */
wxString wxControlBase::Ellipsize(const wxString& label, const wxDC& dc,
                                  wxEllipsizeMode mode, int maxFinalWidth,
                                  int flags)
{
    wxString ret;

    // these cannot be cached between different Ellipsize() calls as they can
    // change because of e.g. a font change; however we calculate them only once
    // when ellipsizing multiline labels:
    int replacementWidth = dc.GetTextExtent(wxELLIPSE_REPLACEMENT).GetWidth();
    int marginWidth = dc.GetCharWidth();

    // NB: we must handle correctly labels with newlines:
    wxString curLine;
    for ( wxString::const_iterator pc = label.begin(); ; ++pc )
    {
        if ( pc == label.end() || *pc == wxS('\n') )
        {
            curLine = DoEllipsizeSingleLine(curLine, dc, mode, maxFinalWidth,
                                            replacementWidth, marginWidth);

            // add this (ellipsized) row to the rest of the label
            ret << curLine;
            if ( pc == label.end() )
            {
                // NOTE: this is the return which always exits the function
                return ret;
            }
            else
            {
                ret << *pc;
                curLine.clear();
            }
        }
        // we need to remove mnemonics from the label for correct calculations
        else if ( *pc == wxS('&') && (flags & wxELLIPSIZE_FLAGS_PROCESS_MNEMONICS) )
        {
            // pc+1 is safe: at worst we'll be at end()
            wxString::const_iterator next = pc + 1;
            if ( next != label.end() && *next == wxS('&') )
                curLine += wxS('&');          // && becomes &
            //else: remove this ampersand
        }
        // we need also to expand tabs to properly calc their size
        else if ( *pc == wxS('\t') && (flags & wxELLIPSIZE_FLAGS_EXPAND_TABS) )
        {
            // Windows natively expands the TABs to 6 spaces. Do the same:
            curLine += wxS("      ");
        }
        else
        {
            curLine += *pc;
        }
    }

    // this return would generate a
    //  warning C4702: unreachable code
    // with MSVC since the function always exits from inside the loop
    //return ret;
}



// ----------------------------------------------------------------------------
// wxStaticBitmap
// ----------------------------------------------------------------------------

#if wxUSE_STATBMP

wxStaticBitmapBase::~wxStaticBitmapBase()
{
    // this destructor is required for Darwin
}

wxSize wxStaticBitmapBase::DoGetBestSize() const
{
    wxSize best;
    wxBitmap bmp = GetBitmap();
    if ( bmp.Ok() )
        best = wxSize(bmp.GetWidth(), bmp.GetHeight());
    else
        // this is completely arbitrary
        best = wxSize(16, 16);
    CacheBestSize(best);
    return best;
}

#endif // wxUSE_STATBMP

#endif // wxUSE_CONTROLS

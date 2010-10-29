/////////////////////////////////////////////////////////////////////////////
// Name:        src/common/stattextcmn.cpp
// Purpose:     common (to all ports) wxStaticText functions
// Author:      Vadim Zeitlin, Francesco Montorsi
// Created:     2007-01-07 (extracted from dlgcmn.cpp)
// RCS-ID:      $Id$
// Copyright:   (c) 1999-2006 Vadim Zeitlin
//              (c) 2007 Francesco Montorsi
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

#include "wx/textwrapper.h"
#include "wx/private/stattext.h"

#ifndef WX_PRECOMP
    #include "wx/button.h"
    #include "wx/dcclient.h"
    #include "wx/intl.h"
    #include "wx/log.h"
    #include "wx/settings.h"
    #include "wx/stattext.h"
    #include "wx/sizer.h"
    #include "wx/containr.h"
#endif

const wxChar *wxMarkupEntities[][wxMARKUP_ENTITY_MAX] =
{
    // the entities handled by SetLabel() when wxST_MARKUP is used and their referenced string

    { wxT("&amp;"), wxT("&lt;"), wxT("&gt;"), wxT("&apos;"), wxT("&quot;") },
    { wxT("&"),     wxT("<"),    wxT(">"),    wxT("'"),      wxT("\"")     }
};

#if wxUSE_STATTEXT

// ----------------------------------------------------------------------------
// wxTextWrapper
// ----------------------------------------------------------------------------

void wxTextWrapper::Wrap(wxWindow *win, const wxString& text, int widthMax)
{
    wxString line;

    wxString::const_iterator lastSpace = text.end();
    wxString::const_iterator lineStart = text.begin();
    for ( wxString::const_iterator p = lineStart; ; ++p )
    {
        if ( IsStartOfNewLine() )
        {
            OnNewLine();

            lastSpace = text.end();
            line.clear();
            lineStart = p;
        }

        if ( p == text.end() || *p == wxT('\n') )
        {
            DoOutputLine(line);

            if ( p == text.end() )
                break;
        }
        else // not EOL
        {
            if ( *p == wxT(' ') )
                lastSpace = p;

            line += *p;

            if ( widthMax >= 0 && lastSpace != text.end() )
            {
                int width;
                win->GetTextExtent(line, &width, NULL);

                if ( width > widthMax )
                {
                    // remove the last word from this line
                    line.erase(lastSpace - lineStart, p + 1 - lineStart);
                    DoOutputLine(line);

                    // go back to the last word of this line which we didn't
                    // output yet
                    p = lastSpace;
                }
            }
            //else: no wrapping at all or impossible to wrap
        }
    }
}


// ----------------------------------------------------------------------------
// wxLabelWrapper: helper class for wxStaticTextBase::Wrap()
// ----------------------------------------------------------------------------

class wxLabelWrapper : public wxTextWrapper
{
public:
    void WrapLabel(wxWindow *text, int widthMax)
    {
        m_text.clear();
        Wrap(text, text->GetLabel(), widthMax);
        text->SetLabel(m_text);
    }

protected:
    virtual void OnOutputLine(const wxString& line)
    {
        m_text += line;
    }

    virtual void OnNewLine()
    {
        m_text += wxT('\n');
    }

private:
    wxString m_text;
};


// ----------------------------------------------------------------------------
// wxStaticTextBase
// ----------------------------------------------------------------------------

void wxStaticTextBase::Wrap(int width)
{
    wxLabelWrapper wrapper;
    wrapper.WrapLabel(this, width);
}

wxString wxStaticTextBase::GetLabelText() const
{
    wxString ret(GetLabel());

    if (HasFlag(wxST_MARKUP))
        ret = RemoveMarkup(ret);
    return RemoveMnemonics(ret);
}

void wxStaticTextBase::SetLabelText(const wxString& text)
{
    wxString str = text;

    if (HasFlag(wxST_MARKUP))
        str = EscapeMarkup(str);        // escapes markup and the & characters (which are also mnemonics)
    else
        str = EscapeMnemonics(text);    // escape only the mnemonics
    SetLabel(str);
}

/* static */
wxString wxStaticTextBase::GetLabelText(const wxString& label)
{
    wxString ret = RemoveMarkup(label);
        // always remove the markup (this function is static 
        // and cannot check for wxST_MARKUP presence/absence)

    return RemoveMnemonics(ret);
}

/* static */
wxString wxStaticTextBase::RemoveMarkup(const wxString& text)
{
    // strip out of "text" the markup for platforms which don't support it natively
    bool inside_tag = false;

    wxString label;
    for ( wxString::const_iterator source = text.begin();
          source != text.end(); ++source )
    {
        switch ( (*source).GetValue() )
        {
            case wxT('<'):
                if (inside_tag)
                {
                    wxLogDebug(wxT("Invalid markup !"));
                    return wxEmptyString;
                }
                inside_tag = true;
                break;

            case wxT('>'):
                if (!inside_tag)
                {
                    wxLogDebug(wxT("Invalid markup !"));
                    return wxEmptyString;
                }
                inside_tag = false;
                break;

            case wxT('&'):
                {
                    if ( source+1 == text.end() )
                    {
                        wxLogDebug(wxT("Cannot use & as last character of the string '%s'"),
                                   text.c_str());
                        return wxEmptyString;
                    }

                    // is this ampersand introducing a mnemonic or rather an entity?
                    bool isMnemonic = true;
                    size_t distanceFromEnd = text.end() - source;
                    for (size_t j=0; j < wxMARKUP_ENTITY_MAX; j++)
                    {
                        const wxChar *entity = wxMarkupEntities[wxMARKUP_ELEMENT_NAME][j];
                        size_t entityLen = wxStrlen(entity);

                        if (distanceFromEnd >= entityLen &&
                            wxString(source, source + entityLen) == entity)
                        {
                            // replace the &entity; string with the entity reference
                            label << wxMarkupEntities[wxMARKUP_ELEMENT_VALUE][j];
                            // little exception: when the entity reference is
                            // "&" (i.e. when entity is "&amp;"), substitute it
                            // with && instead of a single ampersand:
                            if (*wxMarkupEntities[wxMARKUP_ELEMENT_VALUE][j] == wxT('&'))
                                label << wxT('&');
                            // the -1 is because main for() loop already
                            // increments i:
                            source += entityLen - 1;
                            isMnemonic = false;
                            break;
                        }
                    }

                    if (isMnemonic)
                        label << *source;
                }
                break;


            default:
                if (!inside_tag)
                    label << *source;
        }
    }

    return label;
}

/* static */
wxString wxStaticTextBase::EscapeMarkup(const wxString& text)
{
    wxString ret;

    for (wxString::const_iterator source = text.begin();
         source != text.end(); ++source)
    {
        bool isEntity = false;

        // search in the list of the entities and eventually escape this character
        for (size_t j=0; j < wxMARKUP_ENTITY_MAX; j++)
        {
            if (*source == *wxMarkupEntities[wxMARKUP_ELEMENT_VALUE][j])
            {
                ret << wxMarkupEntities[wxMARKUP_ELEMENT_NAME][j];
                isEntity = true;
                break;
            }
        }

        if (!isEntity)
            ret << *source;     // this character does not need to be escaped
    }

    return ret;
}


// ----------------------------------------------------------------------------
// wxStaticTextBase - generic implementation for wxST_ELLIPSIZE_* support
// ----------------------------------------------------------------------------

void wxStaticTextBase::UpdateLabel()
{
    if (!IsEllipsized())
        return;

    wxString newlabel = GetEllipsizedLabelWithoutMarkup();

    // we need to touch the "real" label (i.e. the text set inside the control,
    // using port-specific functions) instead of the string returned by GetLabel().
    //
    // In fact, we must be careful not to touch the original label passed to
    // SetLabel() otherwise GetLabel() will behave in a strange way to the user
    // (e.g. returning a "Ver...ing" instead of "Very long string") !
    if (newlabel == DoGetLabel())
        return;
    DoSetLabel(newlabel);
}

wxString wxStaticTextBase::GetLabelWithoutMarkup() const
{
    wxString ret(m_labelOrig);

    if (HasFlag(wxST_MARKUP))
        ret = RemoveMarkup(ret);

    // unlike GetLabelText() we don't remove the mnemonics here!
    return ret;
}

wxString wxStaticTextBase::GetEllipsizedLabelWithoutMarkup() const
{
    // this function should be used only by ports which do not support
    // ellipsis in static texts: we first remove markup (which cannot
    // be handled safely by Ellipsize()) and then ellipsize the result.

    wxString ret(m_labelOrig);

    // the order of the following two blocks is important!

    if (HasFlag(wxST_MARKUP))
        ret = RemoveMarkup(ret);

    if (IsEllipsized())
        ret = Ellipsize(ret);

    return ret;
}

wxString wxStaticTextBase::Ellipsize(const wxString& label) const
{
    wxSize sz(GetSize());
    if (sz.GetWidth() < 2 || sz.GetHeight() < 2)
    {
        // the size of this window is not valid (yet)
        return label;
    }

    wxClientDC dc(const_cast<wxStaticTextBase*>(this));
    dc.SetFont(GetFont());

    wxEllipsizeMode mode;
    if ( HasFlag(wxST_ELLIPSIZE_START) )
        mode = wxELLIPSIZE_START;
    else if ( HasFlag(wxST_ELLIPSIZE_MIDDLE) )
        mode = wxELLIPSIZE_MIDDLE;
    else if ( HasFlag(wxST_ELLIPSIZE_END) )
        mode = wxELLIPSIZE_END;
    else
    {
        wxFAIL_MSG( "should only be called if have one of wxST_ELLIPSIZE_XXX" );

        return label;
    }

    return wxControl::Ellipsize(label, dc, mode, sz.GetWidth());
}

#endif // wxUSE_STATTEXT

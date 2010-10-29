/////////////////////////////////////////////////////////////////////////////
// Name:        src/motif/combobox.cpp
// Purpose:     wxComboBox class
// Author:      Julian Smart
// Modified by:
// Created:     17/09/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_COMBOBOX

#include "wx/combobox.h"

#ifndef WX_PRECOMP
    #include "wx/arrstr.h"
#endif

#ifdef __VMS__
#pragma message disable nosimpint
#endif
#include <Xm/Xm.h>
#ifdef __VMS__
#pragma message enable nosimpint
#endif

// use the old, GPL'd combobox
#if (XmVersion < 2000)

#include "xmcombo/xmcombo.h"

#include "wx/motif/private.h"

void  wxComboBoxCallback (Widget w, XtPointer clientData,
                          XmComboBoxSelectionCallbackStruct * cbs);

IMPLEMENT_DYNAMIC_CLASS(wxComboBox, wxControl)

bool wxComboBox::Create(wxWindow *parent, wxWindowID id,
                        const wxString& value,
                        const wxPoint& pos,
                        const wxSize& size,
                        int n, const wxString choices[],
                        long style,
                        const wxValidator& validator,
                        const wxString& name)
{
    if( !CreateControl( parent, id, pos, size, style, validator, name ) )
        return false;
    PreCreation();

    Widget parentWidget = (Widget) parent->GetClientWidget();

    Widget buttonWidget = XtVaCreateManagedWidget(name.c_str(),
        xmComboBoxWidgetClass, parentWidget,
        XmNmarginHeight, 0,
        XmNmarginWidth, 0,
        XmNshowLabel, False,
        XmNeditable, ((style & wxCB_READONLY) != wxCB_READONLY),
        XmNsorted, ((style & wxCB_SORT) == wxCB_SORT),
        XmNstaticList, ((style & wxCB_SIMPLE) == wxCB_SIMPLE),
        NULL);

    int i;
    for (i = 0; i < n; i++)
    {
        wxXmString str( choices[i] );
        XmComboBoxAddItem(buttonWidget, str(), 0);
        m_stringArray.Add(choices[i]);
    }

    m_mainWidget = (Widget) buttonWidget;

    XtManageChild (buttonWidget);

    SetValue(value);

    XtAddCallback (buttonWidget, XmNselectionCallback, (XtCallbackProc) wxComboBoxCallback,
        (XtPointer) this);
    XtAddCallback (buttonWidget, XmNvalueChangedCallback, (XtCallbackProc) wxComboBoxCallback,
        (XtPointer) this);

    PostCreation();
    AttachWidget (parent, m_mainWidget, (WXWidget) NULL, pos.x, pos.y, size.x, size.y);

    return true;
}

bool wxComboBox::Create(wxWindow *parent, wxWindowID id,
                        const wxString& value,
                        const wxPoint& pos,
                        const wxSize& size,
                        const wxArrayString& choices,
                        long style,
                        const wxValidator& validator,
                        const wxString& name)
{
    wxCArrayString chs(choices);
    return Create(parent, id, value, pos, size, chs.GetCount(),
                  chs.GetStrings(), style, validator, name);
}

wxComboBox::~wxComboBox()
{
    DetachWidget((Widget) m_mainWidget); // Removes event handlers
    XtDestroyWidget((Widget) m_mainWidget);
    m_mainWidget = (WXWidget) 0;
}

void wxComboBox::DoSetSize(int x, int y,
                           int width, int WXUNUSED(height),
                           int sizeFlags)
{
    // Necessary so it doesn't call wxChoice::SetSize
    wxWindow::DoSetSize(x, y, width, DoGetBestSize().y, sizeFlags);
}

#if 0
// Already defined in include/motif/combobox.h
wxString wxComboBox::GetValue() const
{
    char *s = XmComboBoxGetString ((Widget) m_mainWidget);
    if (s)
    {
        wxString str(s);
        XtFree (s);
        return str;
    }
    else
        return wxEmptyString;
}
#endif

void wxComboBox::SetValue(const wxString& value)
{
    if( !value.empty() )
    {
        m_inSetValue = true;
        XmComboBoxSetString((Widget)m_mainWidget, value.char_str());
        m_inSetValue = false;
    }
}

void wxComboBox::SetString(unsigned int WXUNUSED(n), const wxString& WXUNUSED(s))
{
    wxFAIL_MSG( wxT("wxComboBox::SetString only implemented for Motif 2.0") );
}

// TODO auto-sorting is not supported by the code
int wxComboBox::DoInsertItems(const wxArrayStringsAdapter& items,
                              unsigned int pos,
                              void **clientData,
                              wxClientDataType type)
{
    const unsigned int numItems = items.GetCount();

    AllocClientData(numItems);
    for( unsigned int i = 0; i < numItems; ++i, ++pos )
    {
        wxXmString str( items[i].c_str() );
        XmComboBoxAddItem((Widget) m_mainWidget, str(), GetMotifPosition(pos));
        m_stringArray.Insert(items[i], pos);
        InsertNewItemClientData(pos, clientData, i, type);
    }

    return pos - 1;
}

void wxComboBox::DoDeleteOneItem(unsigned int n)
{
    XmComboBoxDeletePos((Widget) m_mainWidget, n+1);
    m_stringArray.RemoveAt(n);
    wxControlWithItems::DoDeleteOneItem(n);
}

void wxComboBox::Clear()
{
    XmComboBoxDeleteAllItems((Widget) m_mainWidget);
    m_stringArray.Clear();

    wxControlWithItems::DoClear();
}

void wxComboBox::SetSelection (int n)
{
    XmComboBoxSelectPos((Widget) m_mainWidget, n+1, False);
}

int wxComboBox::GetSelection (void) const
{
    int sel = XmComboBoxGetSelectedPos((Widget) m_mainWidget);
    if (sel == 0)
        return -1;
    else
        return sel - 1;
}

wxString wxComboBox::GetString(unsigned int n) const
{
    return m_stringArray[n];
}

int wxComboBox::FindString(const wxString& s, bool WXUNUSED(bCase)) const
{
    // FIXME: back to base class for not supported value of bCase

    int *pos_list = NULL;
    int count = 0;
    wxXmString text( s );
    bool found = (XmComboBoxGetMatchPos((Widget) m_mainWidget,
        text(), &pos_list, &count) != 0);

    if (found && count > 0)
    {
        int pos = pos_list[0] - 1;
        free(pos_list);
        return pos;
    }

    return wxNOT_FOUND;
}

void  wxComboBoxCallback (Widget WXUNUSED(w), XtPointer clientData,
                          XmComboBoxSelectionCallbackStruct * cbs)
{
    wxComboBox *item = (wxComboBox *) clientData;

    switch (cbs->reason)
    {
    case XmCR_SINGLE_SELECT:
    case XmCR_BROWSE_SELECT:
        {
            wxCommandEvent event (wxEVT_COMMAND_COMBOBOX_SELECTED,
                                  item->GetId());
            event.SetInt(cbs->index - 1);
            event.SetString( item->GetString ( event.GetInt() ) );
            if ( item->HasClientObjectData() )
                event.SetClientObject( item->GetClientObject(cbs->index - 1) );
            else if ( item->HasClientUntypedData() )
                event.SetClientData( item->GetClientData(cbs->index - 1) );
            event.SetExtraLong(true);
            event.SetEventObject(item);
            item->ProcessCommand (event);
            break;
        }
    case XmCR_VALUE_CHANGED:
        {
            wxCommandEvent event (wxEVT_COMMAND_TEXT_UPDATED, item->GetId());
            event.SetInt(-1);
            event.SetString( item->GetValue() );
            event.SetExtraLong(true);
            event.SetEventObject(item);
            item->ProcessCommand (event);
            break;
        }
    default:
        break;
    }
}

void wxComboBox::ChangeFont(bool keepOriginalSize)
{
    // Don't use the base class wxChoice's ChangeFont
    wxWindow::ChangeFont(keepOriginalSize);
}

void wxComboBox::ChangeBackgroundColour()
{
    wxWindow::ChangeBackgroundColour();
}

void wxComboBox::ChangeForegroundColour()
{
    wxWindow::ChangeForegroundColour();
}

wxSize wxComboBox::DoGetBestSize() const
{
    if( (GetWindowStyle() & wxCB_DROPDOWN) == wxCB_DROPDOWN ||
        (GetWindowStyle() & wxCB_READONLY) == wxCB_READONLY )
    {
        wxSize items = GetItemsSize();
        // FIXME arbitrary constants
        return wxSize( ( items.x ? items.x + 50 : 120 ),
                         items.y + 10 );
    }
    else
        return wxWindow::DoGetBestSize();
}

WXWidget wxComboBox::GetTextWidget() const
{
    return (WXWidget)XmComboBoxGetEditWidget((Widget) m_mainWidget);
}

#endif // XmVersion < 2000

#endif // wxUSE_COMBOBOX

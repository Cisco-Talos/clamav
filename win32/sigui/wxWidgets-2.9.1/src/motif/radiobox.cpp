/////////////////////////////////////////////////////////////////////////////
// Name:        src/motif/radiobox.cpp
// Purpose:     wxRadioBox
// Author:      Julian Smart
// Modified by:
// Created:     17/09/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_RADIOBOX

#include "wx/radiobox.h"

#ifndef WX_PRECOMP
    #include "wx/utils.h"
    #include "wx/arrstr.h"
#endif

#ifdef __VMS__
#pragma message disable nosimpint
#endif
#include <Xm/Label.h>
#include <Xm/LabelG.h>
#include <Xm/ToggleB.h>
#include <Xm/ToggleBG.h>
#include <Xm/RowColumn.h>
#include <Xm/Frame.h>
#ifdef __VMS__
#pragma message enable nosimpint
#endif

#include "wx/motif/private.h"

void wxRadioBoxCallback (Widget w, XtPointer clientData,
                    XmToggleButtonCallbackStruct * cbs);

IMPLEMENT_DYNAMIC_CLASS(wxRadioBox, wxControl)

// Radio box item
void wxRadioBox::Init()
{
    m_selectedButton = -1;
    m_noItems = 0;
    m_noRowsOrCols = 0;
    m_labelWidget = (WXWidget) 0;
}

bool wxRadioBox::Create(wxWindow *parent, wxWindowID id, const wxString& title,
             const wxPoint& pos, const wxSize& size,
             int n, const wxString choices[],
             int majorDim, long style,
             const wxValidator& val, const wxString& name)
{
    if( !CreateControl( parent, id, pos, size, style, val, name ) )
        return false;
    PreCreation();

    m_noItems = (unsigned int)n;
    m_noRowsOrCols = majorDim;

    SetMajorDim(majorDim == 0 ? n : majorDim, style);

    Widget parentWidget = (Widget) parent->GetClientWidget();
    Display* dpy = XtDisplay(parentWidget);

    m_mainWidget = XtVaCreateWidget ("radioboxframe",
                                     xmFrameWidgetClass, parentWidget,
                                     XmNresizeHeight, True,
                                     XmNresizeWidth, True,
                                     NULL);

    wxString label1(GetLabelText(title));

    if (!label1.empty())
    {
        wxXmString text(label1);
        m_labelWidget = (WXWidget)
            XtVaCreateManagedWidget( label1.mb_str(),
#if wxUSE_GADGETS
                style & wxCOLOURED ? xmLabelWidgetClass
                                   : xmLabelGadgetClass,
                (Widget)m_mainWidget,
#else
                xmLabelWidgetClass, (Widget)m_mainWidget,
#endif
                wxFont::GetFontTag(), m_font.GetFontTypeC(dpy),
                XmNlabelString, text(),
// XmNframeChildType is not in Motif 1.2, nor in Lesstif,
// if it was compiled with 1.2 compatibility
// TODO: check this still looks OK for Motif 1.2.
#if (XmVersion > 1200)
                XmNframeChildType, XmFRAME_TITLE_CHILD,
#else
                XmNchildType, XmFRAME_TITLE_CHILD,
#endif
                XmNchildVerticalAlignment, XmALIGNMENT_CENTER,
                NULL);
    }

    Arg args[3];

    XtSetArg (args[0], XmNorientation, ((style & wxHORIZONTAL) == wxHORIZONTAL ?
                                          XmHORIZONTAL : XmVERTICAL));
    XtSetArg (args[1], XmNnumColumns, GetMajorDim());
    XtSetArg (args[2], XmNadjustLast, False);

    Widget radioBoxWidget =
        XmCreateRadioBox ((Widget)m_mainWidget, wxMOTIF_STR("radioBoxWidget"), args, 3);

    m_radioButtons.reserve(n);
    m_radioButtonLabels.reserve(n);

    int i;
    for (i = 0; i < n; i++)
    {
        wxString str(GetLabelText(choices[i]));
        m_radioButtonLabels.push_back(str);
        Widget radioItem =  XtVaCreateManagedWidget (
                                str.mb_str(),
#if wxUSE_GADGETS
                                xmToggleButtonGadgetClass, radioBoxWidget,
#else
                                xmToggleButtonWidgetClass, radioBoxWidget,
#endif
                                wxFont::GetFontTag(), m_font.GetFontTypeC(dpy),
                                NULL);
        m_radioButtons.push_back((WXWidget)radioItem);
        XtAddCallback (radioItem, XmNvalueChangedCallback,
                       (XtCallbackProc) wxRadioBoxCallback,
                       (XtPointer) this);
    }

    SetSelection (0);

    XtRealizeWidget((Widget)m_mainWidget);
    XtManageChild (radioBoxWidget);
    XtManageChild ((Widget)m_mainWidget);

    PostCreation();
    AttachWidget (parent, m_mainWidget, NULL, pos.x, pos.y, size.x, size.y);

    return true;
}

bool wxRadioBox::Create(wxWindow *parent, wxWindowID id, const wxString& title,
             const wxPoint& pos, const wxSize& size,
             const wxArrayString& choices,
             int majorDim, long style,
             const wxValidator& val, const wxString& name)
{
    wxCArrayString chs(choices);
    return Create(parent, id, title, pos, size, chs.GetCount(),
                  chs.GetStrings(), majorDim, style, val, name);
}

wxRadioBox::~wxRadioBox()
{
    DetachWidget(m_mainWidget);
    XtDestroyWidget((Widget) m_mainWidget);

    m_mainWidget = (WXWidget) 0;
}

void wxRadioBox::SetString(unsigned int item, const wxString& label)
{
    if (!IsValid(item))
        return;

    Widget widget = (Widget)m_radioButtons[item];
    if (!label.empty())
    {
        wxString label1(GetLabelText(label));
        wxXmString text( label1 );
        m_radioButtonLabels[item] = label1;
        XtVaSetValues (widget,
                        XmNlabelString, text(),
                        XmNlabelType, XmSTRING,
                        NULL);
    }
}

void wxRadioBox::SetSelection(int n)
{
    if (!IsValid(n))
        return;

    m_selectedButton = n;

    m_inSetValue = true;

    XmToggleButtonSetState ((Widget) m_radioButtons[n], True, False);

    for (unsigned int i = 0; i < m_noItems; i++)
        if (i != (unsigned int)n)
            XmToggleButtonSetState ((Widget) m_radioButtons[i], False, False);

    m_inSetValue = false;
}

// Get single selection, for single choice list items
int wxRadioBox::GetSelection() const
{
    return m_selectedButton;
}

// Find string for position
wxString wxRadioBox::GetString(unsigned int n) const
{
    if (!IsValid(n))
        return wxEmptyString;
    return m_radioButtonLabels[n];
}

void wxRadioBox::DoSetSize(int x, int y, int width, int height, int sizeFlags)
{
    bool managed = XtIsManaged((Widget) m_mainWidget);

    if (managed)
        XtUnmanageChild ((Widget) m_mainWidget);

    int xx = x; int yy = y;
    AdjustForParentClientOrigin(xx, yy, sizeFlags);

    if (x > -1 || (sizeFlags & wxSIZE_ALLOW_MINUS_ONE))
        XtVaSetValues ((Widget) m_mainWidget, XmNx, xx, NULL);
    if (y > -1 || (sizeFlags & wxSIZE_ALLOW_MINUS_ONE))
        XtVaSetValues ((Widget) m_mainWidget, XmNy, yy, NULL);

    if (width > 0)
        XtVaSetValues ((Widget) m_mainWidget, XmNwidth, width, NULL);
    if (height > 0)
        XtVaSetValues ((Widget) m_mainWidget, XmNheight, height, NULL);

    if (managed)
        XtManageChild ((Widget) m_mainWidget);
}

// Enable a specific button
bool wxRadioBox::Enable(unsigned int n, bool enable)
{
    if (!IsValid(n))
        return false;

    XtSetSensitive ((Widget) m_radioButtons[n], (Boolean) enable);
    return true;
}

// Enable all controls
bool wxRadioBox::Enable(bool enable)
{
    if ( !wxControl::Enable(enable) )
        return false;

    for (unsigned int i = 0; i < m_noItems; i++)
        XtSetSensitive ((Widget) m_radioButtons[i], (Boolean) enable);

    return true;
}

bool wxRadioBox::Show(bool show)
{
    // TODO: show/hide all children
    return wxControl::Show(show);
}

// Show a specific button
bool wxRadioBox::Show(unsigned int n, bool show)
{
  // This method isn't complete, and we try do do our best...
  // It's main purpose isn't for allowing Show/Unshow dynamically,
  // but rather to provide a way to design wxRadioBox such:
  //
  //        o Val1  o Val2   o Val3
  //        o Val4           o Val6
  //        o Val7  o Val8   o Val9
  //
  // In my case, this is a 'direction' box, and the Show(5,False) is
  // coupled with an Enable(5,False)
  //
    if (!IsValid(n))
        return false;

    XtVaSetValues ((Widget) m_radioButtons[n],
        XmNindicatorOn, (unsigned char) show,
        NULL);

    // Please note that this is all we can do: removing the label
    // if switching to unshow state. However, when switching
    // to the on state, it's the prog. resp. to call SetString(item,...)
    // after this call!!
    if (!show)
        wxRadioBox::SetString (n, " ");

    return true;
}

// For single selection items only
wxString wxRadioBox::GetStringSelection () const
{
    int sel = GetSelection ();
    if (sel != wxNOT_FOUND)
        return this->GetString((unsigned int)sel);
    else
        return wxEmptyString;
}

bool wxRadioBox::SetStringSelection (const wxString& s)
{
    int sel = FindString (s);
    if (sel > -1)
    {
        SetSelection (sel);
        return true;
    }
    else
        return false;
}

void wxRadioBox::Command (wxCommandEvent & event)
{
    SetSelection (event.GetInt());
    ProcessCommand (event);
}

void wxRadioBox::ChangeFont(bool keepOriginalSize)
{
    wxWindow::ChangeFont(keepOriginalSize);

    for (unsigned int i = 0; i < m_noItems; i++)
    {
        WXWidget radioButton = m_radioButtons[i];

        XtVaSetValues ((Widget) radioButton,
                       wxFont::GetFontTag(), m_font.GetFontTypeC(XtDisplay((Widget) GetTopWidget())),
                       NULL);
    }
}

void wxRadioBox::ChangeBackgroundColour()
{
    wxWindow::ChangeBackgroundColour();

    wxColour colour = *wxBLACK;
    WXPixel selectPixel = colour.AllocColour(XtDisplay((Widget)m_mainWidget));

    for (unsigned int i = 0; i < m_noItems; i++)
    {
        WXWidget radioButton = m_radioButtons[i];

        wxDoChangeBackgroundColour(radioButton, m_backgroundColour, true);

        XtVaSetValues ((Widget) radioButton,
          XmNselectColor, selectPixel,
          NULL);
    }
}

void wxRadioBox::ChangeForegroundColour()
{
    wxWindow::ChangeForegroundColour();

    for (unsigned int i = 0; i < m_noItems; i++)
    {
        WXWidget radioButton = m_radioButtons[i];

        wxDoChangeForegroundColour(radioButton, m_foregroundColour);
    }
}

void wxRadioBoxCallback (Widget w, XtPointer clientData,
                    XmToggleButtonCallbackStruct * cbs)
{
  if (!cbs->set)
    return;

  wxRadioBox *item = (wxRadioBox *) clientData;
  int sel = -1;
  unsigned int i;
  const wxWidgetArray& buttons = item->GetRadioButtons();
  for (i = 0; i < item->GetCount(); i++)
    if (((Widget)buttons[i]) == w)
      sel = (int)i;
  item->SetSel(sel);

  if (item->InSetValue())
    return;

  wxCommandEvent event (wxEVT_COMMAND_RADIOBOX_SELECTED, item->GetId());
  event.SetInt(sel);
  event.SetString(item->GetStringSelection());
  event.SetEventObject(item);
  item->ProcessCommand (event);
}

#endif // wxUSE_RADIOBOX

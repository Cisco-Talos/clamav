/////////////////////////////////////////////////////////////////////////////
// Name:        src/motif/choice.cpp
// Purpose:     wxChoice
// Author:      Julian Smart
// Modified by:
// Created:     17/09/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_CHOICE

#include "wx/choice.h"

#ifndef WX_PRECOMP
    #include "wx/utils.h"
    #include "wx/arrstr.h"
#endif

#ifdef __VMS__
#pragma message disable nosimpint
#endif
#include <Xm/Xm.h>
#include <Xm/PushBG.h>
#include <Xm/PushB.h>
#include <Xm/RowColumn.h>
#ifdef __VMS__
#pragma message enable nosimpint
#endif

#include "wx/motif/private.h"

#define WIDTH_OVERHEAD 48
#define WIDTH_OVERHEAD_SUBTRACT 40
#define HEIGHT_OVERHEAD 15

IMPLEMENT_DYNAMIC_CLASS(wxChoice, wxControlWithItems)

void wxChoiceCallback (Widget w, XtPointer clientData,
                       XtPointer ptr);

wxChoice::wxChoice()
{
    Init();
}

void wxChoice::Init()
{
    m_buttonWidget = (WXWidget) 0;
    m_menuWidget = (WXWidget) 0;
    m_formWidget = (WXWidget) 0;
}

bool wxChoice::Create(wxWindow *parent, wxWindowID id,
                      const wxPoint& pos,
                      const wxSize& size,
                      int n, const wxString choices[],
                      long style,
                      const wxValidator& validator,
                      const wxString& name)
{
    if ( !CreateControl(parent, id, pos, size, style, validator, name) )
        return false;
    PreCreation();

    Widget parentWidget = (Widget) parent->GetClientWidget();

    m_formWidget = (WXWidget) XtVaCreateManagedWidget(name.c_str(),
        xmRowColumnWidgetClass, parentWidget,
        XmNmarginHeight, 0,
        XmNmarginWidth, 0,
        XmNpacking, XmPACK_TIGHT,
        XmNorientation, XmHORIZONTAL,
        XmNresizeWidth, False,
        XmNresizeHeight, False,
        NULL);

    XtVaSetValues ((Widget) m_formWidget, XmNspacing, 0, NULL);

    /*
    * Create the popup menu
    */
    m_menuWidget = (WXWidget) XmCreatePulldownMenu ((Widget) m_formWidget,
                                                    wxMOTIF_STR("choiceMenu"),
                                                    NULL, 0);

    if (n > 0)
    {
        int i;
        for (i = 0; i < n; i++)
            Append (choices[i]);
    }

    /*
    * Create button
    */
    Arg args[10];
    Cardinal argcnt = 0;

    XtSetArg (args[argcnt], XmNsubMenuId, (Widget) m_menuWidget); ++argcnt;
    XtSetArg (args[argcnt], XmNmarginWidth, 0); ++argcnt;
    XtSetArg (args[argcnt], XmNmarginHeight, 0); ++argcnt;
    XtSetArg (args[argcnt], XmNpacking, XmPACK_TIGHT); ++argcnt;
    m_buttonWidget = (WXWidget) XmCreateOptionMenu ((Widget) m_formWidget,
                                                    wxMOTIF_STR("choiceButton"),
                                                    args, argcnt);

    m_mainWidget = m_buttonWidget;

    XtManageChild ((Widget) m_buttonWidget);

    // New code from Roland Haenel (roland_haenel@ac.cybercity.de)
    // Some time ago, I reported a problem with wxChoice-items under
    // Linux and Motif 2.0 (they caused sporadic GPFs). Now it seems
    // that I have found the code responsible for this behaviour.
#if XmVersion >= 1002
#if XmVersion <  2000
    // JACS, 24/1/99: this seems to cause a malloc crash later on, e.g.
    // in controls sample.
    //
    // Widget optionLabel = XmOptionLabelGadget ((Widget) m_buttonWidget);
    // XtUnmanageChild (optionLabel);
#endif
#endif

    wxSize bestSize = GetBestSize();
    if( size.x > 0 ) bestSize.x = size.x;
    if( size.y > 0 ) bestSize.y = size.y;

    XtVaSetValues((Widget) m_formWidget, XmNresizePolicy, XmRESIZE_NONE, NULL);

    PostCreation();
    AttachWidget (parent, m_buttonWidget, m_formWidget,
                  pos.x, pos.y, bestSize.x, bestSize.y);

    return true;
}

bool wxChoice::Create(wxWindow *parent, wxWindowID id,
                      const wxPoint& pos,
                      const wxSize& size,
                      const wxArrayString& choices,
                      long style,
                      const wxValidator& validator,
                      const wxString& name)
{
    wxCArrayString chs(choices);
    return Create(parent, id, pos, size, chs.GetCount(), chs.GetStrings(),
                  style, validator, name);
}

wxChoice::~wxChoice()
{
    // For some reason destroying the menuWidget
    // can cause crashes on some machines. It will
    // be deleted implicitly by deleting the parent form
    // anyway.
    //  XtDestroyWidget (menuWidget);

    if (GetMainWidget())
    {
        DetachWidget(GetMainWidget()); // Removes event handlers
        DetachWidget(m_formWidget);

        XtDestroyWidget((Widget) m_formWidget);
        m_formWidget = (WXWidget) 0;

        // Presumably the other widgets have been deleted now, via the form
        m_mainWidget = (WXWidget) 0;
        m_buttonWidget = (WXWidget) 0;
    }
}

static inline wxChar* MYcopystring(const wxChar* s)
{
    wxChar* copy = new wxChar[wxStrlen(s) + 1];
    return wxStrcpy(copy, s);
}

// TODO auto-sorting is not supported by the code
int wxChoice::DoInsertItems(const wxArrayStringsAdapter& items,
                            unsigned int pos,
                            void **clientData, wxClientDataType type)
{
#ifndef XmNpositionIndex
    wxCHECK_MSG( pos == GetCount(), -1, wxT("insert not implemented"));
#endif

    const unsigned int numItems = items.GetCount();
    AllocClientData(numItems);
    for( unsigned int i = 0; i < numItems; ++i, ++pos )
    {
        Widget w = XtVaCreateManagedWidget (GetLabelText(items[i]),
#if wxUSE_GADGETS
            xmPushButtonGadgetClass, (Widget) m_menuWidget,
#else
            xmPushButtonWidgetClass, (Widget) m_menuWidget,
#endif
#ifdef XmNpositionIndex
            XmNpositionIndex, pos,
#endif
            NULL);

        wxDoChangeBackgroundColour((WXWidget) w, m_backgroundColour);

        if( m_font.Ok() )
            wxDoChangeFont( w, m_font );

        m_widgetArray.Insert(w, pos);

        char mnem = wxFindMnemonic (items[i]);
        if (mnem != 0)
            XtVaSetValues (w, XmNmnemonic, mnem, NULL);

        XtAddCallback (w, XmNactivateCallback,
                       (XtCallbackProc) wxChoiceCallback,
                       (XtPointer) this);

        if (m_stringArray.GetCount() == 0 && m_buttonWidget)
        {
            XtVaSetValues ((Widget) m_buttonWidget, XmNmenuHistory, w, NULL);
            Widget label = XmOptionButtonGadget ((Widget) m_buttonWidget);
            wxXmString text( items[i] );
            XtVaSetValues (label,
                XmNlabelString, text(),
                NULL);
        }

        m_stringArray.Insert(items[i], pos);

        InsertNewItemClientData(pos, clientData, i, type);
    }

    return pos - 1;
}

void wxChoice::DoDeleteOneItem(unsigned int n)
{
    Widget w = (Widget)m_widgetArray[n];
    XtRemoveCallback(w, XmNactivateCallback, (XtCallbackProc)wxChoiceCallback,
                     (XtPointer)this);

    m_stringArray.RemoveAt(size_t(n));
    m_widgetArray.RemoveAt(size_t(n));
    wxChoiceBase::DoDeleteOneItem(n);

    XtDestroyWidget(w);
}

void wxChoice::DoClear()
{
    m_stringArray.Clear();

    unsigned int i;
    for (i = 0; i < m_stringArray.GetCount(); i++)
    {
        XtRemoveCallback((Widget) m_widgetArray[i],
                         XmNactivateCallback, (XtCallbackProc)wxChoiceCallback,
                         (XtPointer)this);
        XtUnmanageChild ((Widget) m_widgetArray[i]);
        XtDestroyWidget ((Widget) m_widgetArray[i]);
    }

    m_widgetArray.Clear();
    if (m_buttonWidget)
        XtVaSetValues ((Widget) m_buttonWidget,
                       XmNmenuHistory, (Widget) NULL,
                       NULL);

    wxChoiceBase::DoClear();
}

int wxChoice::GetSelection() const
{
    XmString text;
    Widget label = XmOptionButtonGadget ((Widget) m_buttonWidget);
    XtVaGetValues (label,
        XmNlabelString, &text,
        NULL);
    wxXmString freeMe(text);
    wxString s = wxXmStringToString( text );

    if (!s.empty())
    {
        for (size_t i=0; i<m_stringArray.GetCount(); i++)
            if (m_stringArray[i] == s)
                return i;

        return wxNOT_FOUND;
    }

    return wxNOT_FOUND;
}

void wxChoice::SetSelection(int n)
{
    m_inSetValue = true;

#if 0
    Dimension selectionWidth, selectionHeight;
#endif
    wxXmString text( m_stringArray[n] );
// MBN: this seems silly, at best, and causes wxChoices to be clipped:
//      will remove "soon"
#if 0
    XtVaGetValues ((Widget) m_widgetArray[n],
                    XmNwidth, &selectionWidth,
                    XmNheight, &selectionHeight,
                    NULL);
#endif
    Widget label = XmOptionButtonGadget ((Widget) m_buttonWidget);
    XtVaSetValues (label,
        XmNlabelString, text(),
        NULL);
#if 0
    XtVaSetValues ((Widget) m_buttonWidget,
        XmNwidth, selectionWidth, XmNheight, selectionHeight,
        XmNmenuHistory, (Widget) m_widgetArray[n], NULL);
#endif

    m_inSetValue = false;
}

wxString wxChoice::GetString(unsigned int n) const
{
    return m_stringArray[n];
}

void wxChoice::SetColumns(int n)
{
    if (n<1) n = 1 ;

    short numColumns = (short)n ;
    Arg args[3];

    XtSetArg(args[0], XmNnumColumns, numColumns);
    XtSetArg(args[1], XmNpacking, XmPACK_COLUMN);
    XtSetValues((Widget) m_menuWidget,args,2) ;
}

int wxChoice::GetColumns(void) const
{
    short numColumns ;

    XtVaGetValues((Widget) m_menuWidget,XmNnumColumns,&numColumns,NULL) ;
    return numColumns ;
}

void wxChoice::SetFocus()
{
    XmProcessTraversal(XtParent((Widget)m_mainWidget), XmTRAVERSE_CURRENT);
}

void wxChoice::DoSetSize(int x, int y, int width, int height, int sizeFlags)
{
    XtVaSetValues((Widget) m_formWidget, XmNresizePolicy, XmRESIZE_ANY, NULL);
    bool managed = XtIsManaged((Widget) m_formWidget);

    if (managed)
        XtUnmanageChild ((Widget) m_formWidget);

    int actualWidth = width - WIDTH_OVERHEAD_SUBTRACT,
        actualHeight = height - HEIGHT_OVERHEAD;

    if (width > -1)
    {
        unsigned int i;
        for (i = 0; i < m_stringArray.GetCount(); i++)
            XtVaSetValues ((Widget) m_widgetArray[i],
                           XmNwidth, actualWidth,
                           NULL);
        XtVaSetValues ((Widget) m_buttonWidget, XmNwidth, actualWidth,
            NULL);
    }
    if (height > -1)
    {
#if 0
        unsigned int i;
        for (i = 0; i < m_stringArray.GetCount(); i++)
            XtVaSetValues ((Widget) m_widgetArray[i],
                           XmNheight, actualHeight,
                           NULL);
#endif
        XtVaSetValues ((Widget) m_buttonWidget, XmNheight, actualHeight,
            NULL);
    }

    if (managed)
        XtManageChild ((Widget) m_formWidget);
    XtVaSetValues((Widget) m_formWidget, XmNresizePolicy, XmRESIZE_NONE, NULL);

    wxControl::DoSetSize (x, y, width, height, sizeFlags);
}

void wxChoice::Command(wxCommandEvent & event)
{
    SetSelection (event.GetInt());
    ProcessCommand (event);
}

void wxChoiceCallback (Widget w, XtPointer clientData, XtPointer WXUNUSED(ptr))
{
    wxChoice *item = (wxChoice *) clientData;
    if (item)
    {
        if (item->InSetValue())
            return;

        int n = item->GetWidgets().Index(w);
        if (n != wxNOT_FOUND)
        {
            wxCommandEvent event(wxEVT_COMMAND_CHOICE_SELECTED, item->GetId());
            event.SetEventObject(item);
            event.SetInt(n);
            event.SetString( item->GetStrings().Item(n) );
            if ( item->HasClientObjectData() )
                event.SetClientObject( item->GetClientObject(n) );
            else if ( item->HasClientUntypedData() )
                event.SetClientData( item->GetClientData(n) );
            item->ProcessCommand (event);
        }
    }
}

void wxChoice::ChangeFont(bool keepOriginalSize)
{
    // Note that this causes the widget to be resized back
    // to its original size! We therefore have to set the size
    // back again. TODO: a better way in Motif?
    if (m_mainWidget && m_font.Ok())
    {
        Display* dpy = XtDisplay((Widget) m_mainWidget);
        int width, height, width1, height1;
        GetSize(& width, & height);

        WXString fontTag = wxFont::GetFontTag();

        XtVaSetValues ((Widget) m_formWidget,
                       fontTag, m_font.GetFontTypeC(dpy),
                       NULL);
        XtVaSetValues ((Widget) m_buttonWidget,
                       fontTag, m_font.GetFontTypeC(dpy),
                       NULL);

        for( unsigned int i = 0; i < m_stringArray.GetCount(); ++i )
            XtVaSetValues( (Widget)m_widgetArray[i],
                           fontTag, m_font.GetFontTypeC(dpy),
                           NULL );

        GetSize(& width1, & height1);
        if (keepOriginalSize && (width != width1 || height != height1))
        {
            SetSize(wxDefaultCoord, wxDefaultCoord, width, height);
        }
    }
}

void wxChoice::ChangeBackgroundColour()
{
    wxDoChangeBackgroundColour(m_formWidget, m_backgroundColour);
    wxDoChangeBackgroundColour(m_buttonWidget, m_backgroundColour);
    wxDoChangeBackgroundColour(m_menuWidget, m_backgroundColour);
    unsigned int i;
    for (i = 0; i < m_stringArray.GetCount(); i++)
        wxDoChangeBackgroundColour(m_widgetArray[i], m_backgroundColour);
}

void wxChoice::ChangeForegroundColour()
{
    wxDoChangeForegroundColour(m_formWidget, m_foregroundColour);
    wxDoChangeForegroundColour(m_buttonWidget, m_foregroundColour);
    wxDoChangeForegroundColour(m_menuWidget, m_foregroundColour);
    unsigned int i;
    for (i = 0; i < m_stringArray.GetCount(); i++)
        wxDoChangeForegroundColour(m_widgetArray[i], m_foregroundColour);
}

unsigned int wxChoice::GetCount() const
{
    return m_stringArray.GetCount();
}

void wxChoice::SetString(unsigned int WXUNUSED(n), const wxString& WXUNUSED(s))
{
    wxFAIL_MSG( wxT("wxChoice::SetString not implemented") );
}

wxSize wxChoice::GetItemsSize() const
{
    int x, y, mx = 0, my = 0;

    // get my
    GetTextExtent( "|", &x, &my );

    for (size_t i=0; i<m_stringArray.GetCount(); i++)
    {
        GetTextExtent( m_stringArray[i], &x, &y );
        mx = wxMax( mx, x );
        my = wxMax( my, y );
    }

    return wxSize( mx, my );
}

wxSize wxChoice::DoGetBestSize() const
{
    wxSize items = GetItemsSize();
    // FIXME arbitrary constants
    return wxSize( ( items.x ? items.x + WIDTH_OVERHEAD : 120 ),
                     items.y + HEIGHT_OVERHEAD );
}

#endif // wxUSE_CHOICE

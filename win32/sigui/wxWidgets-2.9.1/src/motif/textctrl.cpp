/////////////////////////////////////////////////////////////////////////////
// Name:        src/motif/textctrl.cpp
// Purpose:     wxTextCtrl
// Author:      Julian Smart
// Modified by:
// Created:     17/09/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
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

#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>

#include "wx/textctrl.h"

#ifndef WX_PRECOMP
    #include "wx/utils.h"
    #include "wx/settings.h"
#endif

#include "wx/filefn.h"

#ifdef __VMS__
#pragma message disable nosimpint
#endif
#include <Xm/Text.h>
#ifdef __VMS__
#pragma message enable nosimpint
#endif

#include "wx/motif/private.h"

// ----------------------------------------------------------------------------
// private functions
// ----------------------------------------------------------------------------

// helper: inserts the new text in the value of the text ctrl and returns the
// result in place
static void MergeChangesIntoString(wxString& value,
                                   XmTextVerifyCallbackStruct *textStruct);

// callbacks
static void wxTextWindowChangedProc(Widget w, XtPointer clientData, XtPointer ptr);
static void wxTextWindowModifyProc(Widget w, XtPointer clientData, XmTextVerifyCallbackStruct *cbs);
static void wxTextWindowGainFocusProc(Widget w, XtPointer clientData, XmAnyCallbackStruct *cbs);
static void wxTextWindowLoseFocusProc(Widget w, XtPointer clientData, XmAnyCallbackStruct *cbs);
static void wxTextWindowActivateProc(Widget w, XtPointer clientData, XmAnyCallbackStruct *ptr);

    IMPLEMENT_DYNAMIC_CLASS(wxTextCtrl, wxTextCtrlBase)

    BEGIN_EVENT_TABLE(wxTextCtrl, wxTextCtrlBase)
        EVT_DROP_FILES(wxTextCtrl::OnDropFiles)
        EVT_CHAR(wxTextCtrl::OnChar)

    EVT_MENU(wxID_CUT, wxTextCtrl::OnCut)
    EVT_MENU(wxID_COPY, wxTextCtrl::OnCopy)
    EVT_MENU(wxID_PASTE, wxTextCtrl::OnPaste)
    EVT_MENU(wxID_UNDO, wxTextCtrl::OnUndo)
    EVT_MENU(wxID_REDO, wxTextCtrl::OnRedo)

    EVT_UPDATE_UI(wxID_CUT, wxTextCtrl::OnUpdateCut)
    EVT_UPDATE_UI(wxID_COPY, wxTextCtrl::OnUpdateCopy)
    EVT_UPDATE_UI(wxID_PASTE, wxTextCtrl::OnUpdatePaste)
    EVT_UPDATE_UI(wxID_UNDO, wxTextCtrl::OnUpdateUndo)
    EVT_UPDATE_UI(wxID_REDO, wxTextCtrl::OnUpdateRedo)

    END_EVENT_TABLE()

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxTextCtrl
// ----------------------------------------------------------------------------

// Text item
wxTextCtrl::wxTextCtrl()
{
    m_tempCallbackStruct = NULL;
    m_modified = false;
    m_processedDefault = false;
}

bool wxTextCtrl::Create(wxWindow *parent,
                        wxWindowID id,
                        const wxString& value,
                        const wxPoint& pos,
                        const wxSize& size,
                        long style,
                        const wxValidator& validator,
                        const wxString& name)
{
    if( !CreateControl( parent, id, pos, size, style, validator, name ) )
        return false;
    PreCreation();

    m_tempCallbackStruct = NULL;
    m_modified = false;
    m_processedDefault = false;

    Widget parentWidget = (Widget) parent->GetClientWidget();

    Bool wantHorizScroll = (m_windowStyle & wxHSCROLL) != 0 ? True : False;
    // If we don't have horizontal scrollbars, we want word wrap.
    // OpenMotif 2.1 crashes if wantWordWrap is True in Japanese
    // locale (and probably other multibyte locales). The check might be
    // more precise
#if wxCHECK_LESSTIF() || wxCHECK_MOTIF_VERSION( 2, 2 )
    Bool wantWordWrap = wantHorizScroll == True ? False : True;
#else
    Bool wantWordWrap = False;
#endif

    if (m_windowStyle & wxTE_MULTILINE)
    {
        Arg args[8];
        int count = 0;
        XtSetArg (args[count], XmNscrollHorizontal, wantHorizScroll); ++count;
        if( m_font.IsOk() )
            XtSetArg (args[count], (String) wxFont::GetFontTag(),
                      m_font.GetFontType( XtDisplay(parentWidget) ) ); ++count;
        XtSetArg (args[count], XmNwordWrap, wantWordWrap); ++count;
        XtSetArg (args[count], XmNvalue, (const char*)value.mb_str()); ++count;
        XtSetArg (args[count], XmNeditable,
                  style & wxTE_READONLY ? False : True); ++count;
        XtSetArg (args[count], XmNeditMode, XmMULTI_LINE_EDIT ); ++count;

        m_mainWidget =
            (WXWidget) XmCreateScrolledText(parentWidget,
                                            name.char_str(),
                                            args, count);

        XtManageChild ((Widget) m_mainWidget);
    }
    else
    {
        m_mainWidget = (WXWidget)XtVaCreateManagedWidget
                                 (
                                  name.mb_str(),
                                  xmTextWidgetClass,
                                  parentWidget,
                                  wxFont::GetFontTag(), m_font.GetFontType( XtDisplay(parentWidget) ),
                                  XmNvalue, (const char*)value.mb_str(),
                                  XmNeditable, (style & wxTE_READONLY) ?
                                      False : True,
                                  NULL
                                 );

#if 0
        // TODO: Is this relevant? What does it do?
        int noCols = 2;
        if (!value.IsNull() && (value.length() > (unsigned int) noCols))
            noCols = value.length();
        XtVaSetValues((Widget) m_mainWidget,
                      XmNcolumns, noCols,
                      NULL);
#endif
    }

    // remove border if asked for
    if ( style & wxNO_BORDER )
    {
        XtVaSetValues((Widget)m_mainWidget,
                      XmNshadowThickness, 0,
                      NULL);
    }

    // install callbacks
    XtAddCallback((Widget) m_mainWidget, XmNvalueChangedCallback, (XtCallbackProc)wxTextWindowChangedProc, (XtPointer)this);

    XtAddCallback((Widget) m_mainWidget, XmNmodifyVerifyCallback, (XtCallbackProc)wxTextWindowModifyProc, (XtPointer)this);

    XtAddCallback((Widget) m_mainWidget, XmNactivateCallback, (XtCallbackProc)wxTextWindowActivateProc, (XtPointer)this);

    XtAddCallback((Widget) m_mainWidget, XmNfocusCallback, (XtCallbackProc)wxTextWindowGainFocusProc, (XtPointer)this);

    XtAddCallback((Widget) m_mainWidget, XmNlosingFocusCallback, (XtCallbackProc)wxTextWindowLoseFocusProc, (XtPointer)this);

    PostCreation();
    AttachWidget (parent, m_mainWidget, (WXWidget) NULL,
                  pos.x, pos.y, size.x, size.y);

    return true;
}

WXWidget wxTextCtrl::GetTopWidget() const
{
    return IsMultiLine() ? (WXWidget)XtParent((Widget)m_mainWidget)
                         : m_mainWidget;
}

wxString wxTextCtrl::GetValue() const
{
    wxString str; // result

    if (m_windowStyle & wxTE_PASSWORD)
    {
        // the value is stored always in m_value because it can't be retrieved
        // from the text control
        str = m_value;
    }
    else
    {
        str = wxTextEntry::GetValue();

        if ( m_tempCallbackStruct )
        {
            // the string in the control isn't yet updated, can't use it as is
            MergeChangesIntoString(str, (XmTextVerifyCallbackStruct *)
                                   m_tempCallbackStruct);
        }
    }

    return str;
}

void wxTextCtrl::DoSetValue(const wxString& text, int flags)
{
    m_inSetValue = true;

    XmTextSetString ((Widget) m_mainWidget, text.char_str());
    XtVaSetValues ((Widget) m_mainWidget,
                   XmNcursorPosition, text.length(),
                   NULL);

    SetInsertionPoint(text.length());
    XmTextShowPosition ((Widget) m_mainWidget, text.length());
    m_modified = true;

    m_inSetValue = false;

    if ( flags & SetValue_SendEvent )
        SendTextUpdatedEvent();
}

bool wxTextCtrl::IsModified() const
{
    return m_modified;
}

// Makes modified or unmodified
void wxTextCtrl::MarkDirty()
{
    m_modified = true;
}

void wxTextCtrl::DiscardEdits()
{
    m_modified = false;
}

int wxTextCtrl::GetNumberOfLines() const
{
    // HIDEOUSLY inefficient, but we have no choice.
    char *s = XmTextGetString ((Widget) m_mainWidget);
    if (s)
    {
        long i = 0;
        int currentLine = 0;
        bool finished = false;
        while (!finished)
        {
            int ch = s[i];
            if (ch == '\n')
            {
                currentLine++;
                i++;
            }
            else if (ch == 0)
            {
                finished = true;
            }
            else
                i++;
        }

        XtFree (s);
        return currentLine;
    }
    return 0;
}

long wxTextCtrl::XYToPosition(long x, long y) const
{
/* It seems, that there is a bug in some versions of the Motif library,
    so the original wxWin-Code doesn't work. */
    /*
    Widget textWidget = (Widget) handle;
    return (long) XmTextXYToPos (textWidget, (Position) x, (Position) y);
    */
    /* Now a little workaround: */
    long r=0;
    for (int i=0; i<y; i++) r+=(GetLineLength(i)+1);
    return r+x;
}

bool wxTextCtrl::PositionToXY(long pos, long *x, long *y) const
{
    Position xx, yy;
    XmTextPosToXY((Widget) m_mainWidget, pos, &xx, &yy);
    if ( x )
        *x = xx;
    if ( y )
        *y = yy;

    return true;
}

void wxTextCtrl::ShowPosition(long pos)
{
    XmTextShowPosition ((Widget) m_mainWidget, (XmTextPosition) pos);
}

int wxTextCtrl::GetLineLength(long lineNo) const
{
    wxString str = GetLineText (lineNo);
    return (int) str.length();
}

wxString wxTextCtrl::GetLineText(long lineNo) const
{
    // HIDEOUSLY inefficient, but we have no choice.
    char *s = XmTextGetString ((Widget) m_mainWidget);

    if (s)
    {
        wxString buf;
        long i;
        int currentLine = 0;
        for (i = 0; currentLine != lineNo && s[i]; i++ )
            if (s[i] == '\n')
                currentLine++;
            // Now get the text
            int j;
            for (j = 0; s[i] && s[i] != '\n'; i++, j++ )
                buf += s[i];

            XtFree(s);
            return buf;
    }
    else
        return wxEmptyString;
}

/*
* Text item
*/

void wxTextCtrl::Command(wxCommandEvent & event)
{
    SetValue (event.GetString());
    ProcessCommand (event);
}

void wxTextCtrl::OnDropFiles(wxDropFilesEvent& event)
{
    // By default, load the first file into the text window.
    if (event.GetNumberOfFiles() > 0)
    {
        LoadFile(event.GetFiles()[0]);
    }
}

void wxTextCtrl::OnChar(wxKeyEvent& event)
{
    // Indicates that we should generate a normal command, because
    // we're letting default behaviour happen (otherwise it's vetoed
    // by virtue of overriding OnChar)
    m_processedDefault = true;

    if (m_tempCallbackStruct)
    {
        XmTextVerifyCallbackStruct *textStruct =
            (XmTextVerifyCallbackStruct *) m_tempCallbackStruct;
        textStruct->doit = True;
        if (wxIsascii(event.m_keyCode) && (textStruct->text->length == 1))
        {
            textStruct->text->ptr[0] = (char)((event.m_keyCode == WXK_RETURN) ? 10 : event.m_keyCode);
        }
    }
}

void wxTextCtrl::ChangeFont(bool keepOriginalSize)
{
    wxWindow::ChangeFont(keepOriginalSize);
}

void wxTextCtrl::ChangeBackgroundColour()
{
    wxWindow::ChangeBackgroundColour();

    /* TODO: should scrollbars be affected? Should probably have separate
    * function to change them (by default, taken from wxSystemSettings)
    */
    if (m_windowStyle & wxTE_MULTILINE)
    {
        Widget parent = XtParent ((Widget) m_mainWidget);
        Widget hsb, vsb;

        XtVaGetValues (parent,
            XmNhorizontalScrollBar, &hsb,
            XmNverticalScrollBar, &vsb,
            NULL);
        wxColour backgroundColour = wxSystemSettings::GetColour(wxSYS_COLOUR_3DFACE);
        if (hsb)
            wxDoChangeBackgroundColour((WXWidget) hsb, backgroundColour, true);
        if (vsb)
            wxDoChangeBackgroundColour((WXWidget) vsb, backgroundColour, true);

        // MBN: why change parent background?
        // DoChangeBackgroundColour((WXWidget) parent, m_backgroundColour, true);
    }
}

void wxTextCtrl::ChangeForegroundColour()
{
    wxWindow::ChangeForegroundColour();

    if (m_windowStyle & wxTE_MULTILINE)
    {
        Widget parent = XtParent ((Widget) m_mainWidget);
        Widget hsb, vsb;

        XtVaGetValues (parent,
            XmNhorizontalScrollBar, &hsb,
            XmNverticalScrollBar, &vsb,
            NULL);

            /* TODO: should scrollbars be affected? Should probably have separate
            * function to change them (by default, taken from wxSystemSettings)
            if (hsb)
            DoChangeForegroundColour((WXWidget) hsb, m_foregroundColour);
            if (vsb)
            DoChangeForegroundColour((WXWidget) vsb, m_foregroundColour);
        */
        wxDoChangeForegroundColour((WXWidget) parent, m_foregroundColour);
    }
}

void wxTextCtrl::DoSendEvents(void *wxcbs, long keycode)
{
    // we're in process of updating the text control
    m_tempCallbackStruct = wxcbs;

    XmTextVerifyCallbackStruct *cbs = (XmTextVerifyCallbackStruct *)wxcbs;

    wxKeyEvent event (wxEVT_CHAR);
    event.SetId(GetId());
    event.m_keyCode = keycode;
    event.SetEventObject(this);

    // Only if wxTextCtrl::OnChar is called will this be set to True (and
    // the character passed through)
    cbs->doit = False;

    HandleWindowEvent(event);

    if ( !InSetValue() && m_processedDefault )
    {
        // Can generate a command
        wxCommandEvent commandEvent(wxEVT_COMMAND_TEXT_UPDATED, GetId());
        commandEvent.SetEventObject(this);
        ProcessCommand(commandEvent);
    }

    // do it after the (user) event handlers processed the events because
    // otherwise GetValue() would return incorrect (not yet updated value)
    m_tempCallbackStruct = NULL;
}

wxSize wxDoGetSingleTextCtrlBestSize( Widget textWidget,
                                      const wxWindow* window )
{
    Dimension xmargin, ymargin, highlight, shadow;
    char* value;

    XtVaGetValues( textWidget,
                   XmNmarginWidth, &xmargin,
                   XmNmarginHeight, &ymargin,
                   XmNvalue, &value,
                   XmNhighlightThickness, &highlight,
                   XmNshadowThickness, &shadow,
                   NULL );

    if( !value )
        value = wxMOTIF_STR("|");

    int x, y;
    window->GetTextExtent( value, &x, &y );

    if( x < 90 )
        x = 90;

    return wxSize( x + 2 * xmargin + 2 * highlight + 2 * shadow,
                   // MBN: +2 necessary: Lesstif bug or mine?
                   y + 2 * ymargin + 2 * highlight + 2 * shadow + 2 );
}

wxSize wxTextCtrl::DoGetBestSize() const
{
    if( IsSingleLine() )
    {
        wxSize best = wxControl::DoGetBestSize();
#if wxCHECK_MOTIF_VERSION( 2, 3 )
        // OpenMotif 2.3 gives way too big X sizes
        wxSize other_best = wxDoGetSingleTextCtrlBestSize
                                ( (Widget) GetTopWidget(), this );
        return wxSize( other_best.x, best.y );
#else
        if( best.x < 90 ) best.x = 90;

        return best;
#endif
    }
    else
        return wxWindow::DoGetBestSize();
}

// ----------------------------------------------------------------------------
// helpers and Motif callbacks
// ----------------------------------------------------------------------------

static void MergeChangesIntoString(wxString& value,
                                   XmTextVerifyCallbackStruct *cbs)
{
    /* _sm_
     * At least on my system (SunOS 4.1.3 + Motif 1.2), you need to think of
     * every event as a replace event.  cbs->text->ptr gives the replacement
     * text, cbs->startPos gives the index of the first char affected by the
     * replace, and cbs->endPos gives the index one more than the last char
     * affected by the replace (startPos == endPos implies an empty range).
     * Hence, a deletion is represented by replacing all input text with a
     * blank string ("", *not* NULL!).  A simple insertion that does not
     * overwrite any text has startPos == endPos.
     */

    if ( !value )
    {
        // easy case: the ol value was empty
        value = cbs->text->ptr;
    }
    else
    {
        // merge the changes into the value
        const char * const passwd = value;
        int len = value.length();

        len += ( cbs->text->ptr ?
                 strlen(cbs->text->ptr) :
                 0 ) + 1;                      // + new text (if any) + NUL
        len -= cbs->endPos - cbs->startPos;    // - text from affected region.

        char * newS = new char [len];
        char * dest = newS,
             * insert = cbs->text->ptr;

        // Copy (old) text from passwd, up to the start posn of the change.
        int i;
        const char * p = passwd;
        for (i = 0; i < cbs->startPos; ++i)
            *dest++ = *p++;

        // Copy the text to be inserted).
        if (insert)
            while (*insert)
                *dest++ = *insert++;

        // Finally, copy into newS any remaining text from passwd[endPos] on.
        for (p = passwd + cbs->endPos; *p; )
            *dest++ = *p++;
        *dest = 0;

        value = newS;

        delete[] newS;
    }
}

static void
wxTextWindowChangedProc (Widget w, XtPointer clientData, XtPointer WXUNUSED(ptr))
{
    if (!wxGetWindowFromTable(w))
        // Widget has been deleted!
        return;

    wxTextCtrl *tw = (wxTextCtrl *) clientData;
    tw->SetModified(true);
}

static void
wxTextWindowModifyProc (Widget WXUNUSED(w), XtPointer clientData, XmTextVerifyCallbackStruct *cbs)
{
    wxTextCtrl *tw = (wxTextCtrl *) clientData;
    tw->m_processedDefault = false;

    // First, do some stuff if it's a password control: in this case, we need
    // to store the string inside the class because GetValue() can't retrieve
    // it from the text ctrl. We do *not* do it in other circumstances because
    // it would double the amount of memory needed.

    if ( tw->GetWindowStyleFlag() & wxTE_PASSWORD )
    {
        MergeChangesIntoString(tw->m_value, cbs);

        if ( cbs->text->length > 0 )
        {
            int i;
            for (i = 0; i < cbs->text->length; ++i)
                cbs->text->ptr[i] = '*';
            cbs->text->ptr[i] = '\0';
        }
    }

    if(tw->InSetValue())
        return;

    // If we're already within an OnChar, return: probably a programmatic
    // insertion.
    if (tw->m_tempCallbackStruct)
        return;

    // Check for a backspace
    if (cbs->startPos == (cbs->currInsert - 1))
    {
        tw->DoSendEvents((void *)cbs, WXK_DELETE);

        return;
    }

    // Pasting operation: let it through without calling OnChar
    if (cbs->text->length > 1)
        return;

    // Something other than text
    if (cbs->text->ptr == NULL)
        return;

    // normal key press
    char ch = cbs->text->ptr[0];
    tw->DoSendEvents((void *)cbs, ch == '\n' ? '\r' : ch);
}

static void
wxTextWindowGainFocusProc (Widget w, XtPointer clientData, XmAnyCallbackStruct *WXUNUSED(cbs))
{
    if (!wxGetWindowFromTable(w))
        return;

    wxTextCtrl *tw = (wxTextCtrl *) clientData;
    wxFocusEvent event(wxEVT_SET_FOCUS, tw->GetId());
    event.SetEventObject(tw);
    tw->HandleWindowEvent(event);
}

static void
wxTextWindowLoseFocusProc (Widget w, XtPointer clientData, XmAnyCallbackStruct *WXUNUSED(cbs))
{
    if (!wxGetWindowFromTable(w))
        return;

    wxTextCtrl *tw = (wxTextCtrl *) clientData;
    wxFocusEvent event(wxEVT_KILL_FOCUS, tw->GetId());
    event.SetEventObject(tw);
    tw->HandleWindowEvent(event);
}

static void wxTextWindowActivateProc(Widget w, XtPointer clientData,
                                     XmAnyCallbackStruct *WXUNUSED(ptr))
{
    if (!wxGetWindowFromTable(w))
        return;

    wxTextCtrl *tw = (wxTextCtrl *) clientData;

    if (tw->InSetValue())
        return;

    wxCommandEvent event(wxEVT_COMMAND_TEXT_ENTER);
    event.SetId(tw->GetId());
    event.SetEventObject(tw);
    tw->ProcessCommand(event);
}

void wxTextCtrl::OnCut(wxCommandEvent& WXUNUSED(event))
{
    Cut();
}

void wxTextCtrl::OnCopy(wxCommandEvent& WXUNUSED(event))
{
    Copy();
}

void wxTextCtrl::OnPaste(wxCommandEvent& WXUNUSED(event))
{
    Paste();
}

void wxTextCtrl::OnUndo(wxCommandEvent& WXUNUSED(event))
{
    Undo();
}

void wxTextCtrl::OnRedo(wxCommandEvent& WXUNUSED(event))
{
    Redo();
}

void wxTextCtrl::OnUpdateCut(wxUpdateUIEvent& event)
{
    event.Enable( CanCut() );
}

void wxTextCtrl::OnUpdateCopy(wxUpdateUIEvent& event)
{
    event.Enable( CanCopy() );
}

void wxTextCtrl::OnUpdatePaste(wxUpdateUIEvent& event)
{
    event.Enable( CanPaste() );
}

void wxTextCtrl::OnUpdateUndo(wxUpdateUIEvent& event)
{
    event.Enable( CanUndo() );
}

void wxTextCtrl::OnUpdateRedo(wxUpdateUIEvent& event)
{
    event.Enable( CanRedo() );
}

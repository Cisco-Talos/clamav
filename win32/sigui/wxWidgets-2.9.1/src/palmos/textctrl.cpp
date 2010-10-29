/////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/textctrl.cpp
// Purpose:     wxTextCtrl
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
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

#if wxUSE_TEXTCTRL

#include "wx/textctrl.h"

#ifndef WX_PRECOMP
    #include "wx/settings.h"
    #include "wx/brush.h"
    #include "wx/utils.h"
    #include "wx/intl.h"
    #include "wx/log.h"
    #include "wx/app.h"
    #include "wx/menu.h"
    #include "wx/module.h"
#endif

#if wxUSE_CLIPBOARD
    #include "wx/clipbrd.h"
#endif

#include "wx/textfile.h"

#include <string.h>

#if wxUSE_RICHEDIT

#include "wx/palmos/missing.h"

#endif // wxUSE_RICHEDIT

// ----------------------------------------------------------------------------
// private classes
// ----------------------------------------------------------------------------

#if wxUSE_RICHEDIT

// this module initializes RichEdit DLL(s) if needed
class wxRichEditModule : public wxModule
{
public:
    virtual bool OnInit();
    virtual void OnExit();

    // load the richedit DLL of at least of required version
    static bool Load(int version = 1);

private:
    // the handles to richedit 1.0 and 2.0 (or 3.0) DLLs
    static HINSTANCE ms_hRichEdit[2];

    DECLARE_DYNAMIC_CLASS(wxRichEditModule)
};

HINSTANCE wxRichEditModule::ms_hRichEdit[2] = { NULL, NULL };

IMPLEMENT_DYNAMIC_CLASS(wxRichEditModule, wxModule)

#endif // wxUSE_RICHEDIT

// ----------------------------------------------------------------------------
// event tables and other macros
// ----------------------------------------------------------------------------

#if wxUSE_EXTENDED_RTTI
WX_DEFINE_FLAGS( wxTextCtrlStyle )

wxBEGIN_FLAGS( wxTextCtrlStyle )
    // new style border flags, we put them first to
    // use them for streaming out
    wxFLAGS_MEMBER(wxBORDER_SIMPLE)
    wxFLAGS_MEMBER(wxBORDER_SUNKEN)
    wxFLAGS_MEMBER(wxBORDER_DOUBLE)
    wxFLAGS_MEMBER(wxBORDER_RAISED)
    wxFLAGS_MEMBER(wxBORDER_STATIC)
    wxFLAGS_MEMBER(wxBORDER_NONE)

    // old style border flags
    wxFLAGS_MEMBER(wxSIMPLE_BORDER)
    wxFLAGS_MEMBER(wxSUNKEN_BORDER)
    wxFLAGS_MEMBER(wxDOUBLE_BORDER)
    wxFLAGS_MEMBER(wxRAISED_BORDER)
    wxFLAGS_MEMBER(wxSTATIC_BORDER)
    wxFLAGS_MEMBER(wxBORDER)

    // standard window styles
    wxFLAGS_MEMBER(wxTAB_TRAVERSAL)
    wxFLAGS_MEMBER(wxCLIP_CHILDREN)
    wxFLAGS_MEMBER(wxTRANSPARENT_WINDOW)
    wxFLAGS_MEMBER(wxWANTS_CHARS)
    wxFLAGS_MEMBER(wxFULL_REPAINT_ON_RESIZE)
    wxFLAGS_MEMBER(wxALWAYS_SHOW_SB )
    wxFLAGS_MEMBER(wxVSCROLL)
    wxFLAGS_MEMBER(wxHSCROLL)

    wxFLAGS_MEMBER(wxTE_PROCESS_ENTER)
    wxFLAGS_MEMBER(wxTE_PROCESS_TAB)
    wxFLAGS_MEMBER(wxTE_MULTILINE)
    wxFLAGS_MEMBER(wxTE_PASSWORD)
    wxFLAGS_MEMBER(wxTE_READONLY)
    wxFLAGS_MEMBER(wxHSCROLL)
    wxFLAGS_MEMBER(wxTE_RICH)
    wxFLAGS_MEMBER(wxTE_RICH2)
    wxFLAGS_MEMBER(wxTE_AUTO_URL)
    wxFLAGS_MEMBER(wxTE_NOHIDESEL)
    wxFLAGS_MEMBER(wxTE_LEFT)
    wxFLAGS_MEMBER(wxTE_CENTRE)
    wxFLAGS_MEMBER(wxTE_RIGHT)
    wxFLAGS_MEMBER(wxTE_DONTWRAP)
    wxFLAGS_MEMBER(wxTE_CHARWRAP)
    wxFLAGS_MEMBER(wxTE_WORDWRAP)

wxEND_FLAGS( wxTextCtrlStyle )

IMPLEMENT_DYNAMIC_CLASS_XTI(wxTextCtrl, wxControl,"wx/textctrl.h")

wxBEGIN_PROPERTIES_TABLE(wxTextCtrl)
    wxEVENT_PROPERTY( TextUpdated , wxEVT_COMMAND_TEXT_UPDATED , wxCommandEvent )
    wxEVENT_PROPERTY( TextEnter , wxEVT_COMMAND_TEXT_ENTER , wxCommandEvent )

    wxPROPERTY( Font , wxFont , SetFont , GetFont  , EMPTY_MACROVALUE, 0 /*flags*/ , wxT("Helpstring") , wxT("group") )
    wxPROPERTY( Value , wxString , SetValue, GetValue, wxString() , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
    wxPROPERTY_FLAGS( WindowStyle , wxTextCtrlStyle , long , SetWindowStyleFlag , GetWindowStyleFlag , EMPTY_MACROVALUE , 0 /*flags*/ , wxT("Helpstring") , wxT("group")) // style
wxEND_PROPERTIES_TABLE()

wxBEGIN_HANDLERS_TABLE(wxTextCtrl)
wxEND_HANDLERS_TABLE()

wxCONSTRUCTOR_6( wxTextCtrl , wxWindow* , Parent , wxWindowID , Id , wxString , Value , wxPoint , Position , wxSize , Size , long , WindowStyle)
#else
IMPLEMENT_DYNAMIC_CLASS(wxTextCtrl, wxTextCtrlBase)
#endif


BEGIN_EVENT_TABLE(wxTextCtrl, wxTextCtrlBase)
    EVT_CHAR(wxTextCtrl::OnChar)
    EVT_DROP_FILES(wxTextCtrl::OnDropFiles)

#if wxUSE_RICHEDIT
    EVT_RIGHT_UP(wxTextCtrl::OnRightClick)
#endif

    EVT_MENU(wxID_CUT, wxTextCtrl::OnCut)
    EVT_MENU(wxID_COPY, wxTextCtrl::OnCopy)
    EVT_MENU(wxID_PASTE, wxTextCtrl::OnPaste)
    EVT_MENU(wxID_UNDO, wxTextCtrl::OnUndo)
    EVT_MENU(wxID_REDO, wxTextCtrl::OnRedo)
    EVT_MENU(wxID_CLEAR, wxTextCtrl::OnDelete)
    EVT_MENU(wxID_SELECTALL, wxTextCtrl::OnSelectAll)

    EVT_UPDATE_UI(wxID_CUT, wxTextCtrl::OnUpdateCut)
    EVT_UPDATE_UI(wxID_COPY, wxTextCtrl::OnUpdateCopy)
    EVT_UPDATE_UI(wxID_PASTE, wxTextCtrl::OnUpdatePaste)
    EVT_UPDATE_UI(wxID_UNDO, wxTextCtrl::OnUpdateUndo)
    EVT_UPDATE_UI(wxID_REDO, wxTextCtrl::OnUpdateRedo)
    EVT_UPDATE_UI(wxID_CLEAR, wxTextCtrl::OnUpdateDelete)
    EVT_UPDATE_UI(wxID_SELECTALL, wxTextCtrl::OnUpdateSelectAll)

    EVT_SET_FOCUS(wxTextCtrl::OnSetFocus)
END_EVENT_TABLE()

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// creation
// ----------------------------------------------------------------------------

void wxTextCtrl::Init()
{
}

wxTextCtrl::~wxTextCtrl()
{
}

bool wxTextCtrl::Create(wxWindow *parent, wxWindowID id,
                        const wxString& value,
                        const wxPoint& pos,
                        const wxSize& size,
                        long style,
                        const wxValidator& validator,
                        const wxString& name)
{
    return false;
}

// ----------------------------------------------------------------------------
// set/get the controls text
// ----------------------------------------------------------------------------

wxString wxTextCtrl::GetValue() const
{
    wxString res;
    return res;
}

wxString wxTextCtrl::GetRange(long from, long to) const
{
    wxString res;
    return res;
}

void wxTextCtrl::DoSetValue(const wxString& value, int flags)
{
}

void wxTextCtrl::WriteText(const wxString& value)
{
}

void wxTextCtrl::DoWriteText(const wxString& text, int flags)
{
}

void wxTextCtrl::AppendText(const wxString& text)
{
}

void wxTextCtrl::Clear()
{
}

// ----------------------------------------------------------------------------
// Clipboard operations
// ----------------------------------------------------------------------------

void wxTextCtrl::Copy()
{
}

void wxTextCtrl::Cut()
{
}

void wxTextCtrl::Paste()
{
}

bool wxTextCtrl::CanCopy() const
{
    return false;
}

bool wxTextCtrl::CanCut() const
{
    return false;
}

bool wxTextCtrl::CanPaste() const
{
    return false;
}

// ----------------------------------------------------------------------------
// Accessors
// ----------------------------------------------------------------------------

void wxTextCtrl::SetEditable(bool editable)
{
}

void wxTextCtrl::SetInsertionPoint(long pos)
{
}

void wxTextCtrl::SetInsertionPointEnd()
{
}

long wxTextCtrl::GetInsertionPoint() const
{
    return 0;
}

wxTextPos wxTextCtrl::GetLastPosition() const
{
    return 0;
}

// If the return values from and to are the same, there is no
// selection.
void wxTextCtrl::GetSelection(long* from, long* to) const
{
}

bool wxTextCtrl::IsEditable() const
{
    return false;
}

// ----------------------------------------------------------------------------
// selection
// ----------------------------------------------------------------------------

void wxTextCtrl::SetSelection(long from, long to)
{
}

void wxTextCtrl::DoSetSelection(long from, long to, int flags)
{
}

// ----------------------------------------------------------------------------
// Working with files
// ----------------------------------------------------------------------------

bool wxTextCtrl::DoLoadFile(const wxString& file, int fileType)
{
    return false;
}

// ----------------------------------------------------------------------------
// Editing
// ----------------------------------------------------------------------------

void wxTextCtrl::Replace(long from, long to, const wxString& value)
{
}

void wxTextCtrl::Remove(long from, long to)
{
}

bool wxTextCtrl::IsModified() const
{
    return false;
}

void wxTextCtrl::MarkDirty()
{
}

void wxTextCtrl::DiscardEdits()
{
}

int wxTextCtrl::GetNumberOfLines() const
{
    return 0;
}

// ----------------------------------------------------------------------------
// Positions <-> coords
// ----------------------------------------------------------------------------

long wxTextCtrl::XYToPosition(long x, long y) const
{
    return 0;
}

bool wxTextCtrl::PositionToXY(long pos, long *x, long *y) const
{
    return false;
}

wxTextCtrlHitTestResult
wxTextCtrl::HitTest(const wxPoint& pt, long *pos) const
{
    return wxTE_HT_UNKNOWN;
}

// ----------------------------------------------------------------------------
//
// ----------------------------------------------------------------------------

void wxTextCtrl::ShowPosition(long pos)
{
}

long wxTextCtrl::GetLengthOfLineContainingPos(long pos) const
{
    return 0;
}

int wxTextCtrl::GetLineLength(long lineNo) const
{
    return 0;
}

wxString wxTextCtrl::GetLineText(long lineNo) const
{
    wxString str;

    return str;
}

void wxTextCtrl::SetMaxLength(unsigned long len)
{
}

// ----------------------------------------------------------------------------
// Undo/redo
// ----------------------------------------------------------------------------

void wxTextCtrl::Undo()
{
}

void wxTextCtrl::Redo()
{
}

bool wxTextCtrl::CanUndo() const
{
    return false;
}

bool wxTextCtrl::CanRedo() const
{
    return false;
}

// ----------------------------------------------------------------------------
// caret handling (Windows only)
// ----------------------------------------------------------------------------

bool wxTextCtrl::ShowNativeCaret(bool show)
{
    return false;
}

// ----------------------------------------------------------------------------
// implemenation details
// ----------------------------------------------------------------------------

void wxTextCtrl::Command(wxCommandEvent & event)
{
}

void wxTextCtrl::OnDropFiles(wxDropFilesEvent& event)
{
}

// ----------------------------------------------------------------------------
// kbd input processing
// ----------------------------------------------------------------------------

void wxTextCtrl::OnChar(wxKeyEvent& event)
{
}

// ----------------------------------------------------------------------------
// text control event processing
// ----------------------------------------------------------------------------

bool wxTextCtrl::SendUpdateEvent()
{
    return false;
}

bool wxTextCtrl::AdjustSpaceLimit()
{
    return false;
}

wxSize wxTextCtrl::DoGetBestSize() const
{
    return wxSize(0,0);
}

// ----------------------------------------------------------------------------
// standard handlers for standard edit menu events
// ----------------------------------------------------------------------------

void wxTextCtrl::OnCut(wxCommandEvent& WXUNUSED(event))
{
}

void wxTextCtrl::OnCopy(wxCommandEvent& WXUNUSED(event))
{
}

void wxTextCtrl::OnPaste(wxCommandEvent& WXUNUSED(event))
{
}

void wxTextCtrl::OnUndo(wxCommandEvent& WXUNUSED(event))
{
}

void wxTextCtrl::OnRedo(wxCommandEvent& WXUNUSED(event))
{
}

void wxTextCtrl::OnDelete(wxCommandEvent& WXUNUSED(event))
{
}

void wxTextCtrl::OnSelectAll(wxCommandEvent& WXUNUSED(event))
{
}

void wxTextCtrl::OnUpdateCut(wxUpdateUIEvent& event)
{
}

void wxTextCtrl::OnUpdateCopy(wxUpdateUIEvent& event)
{
}

void wxTextCtrl::OnUpdatePaste(wxUpdateUIEvent& event)
{
}

void wxTextCtrl::OnUpdateUndo(wxUpdateUIEvent& event)
{
}

void wxTextCtrl::OnUpdateRedo(wxUpdateUIEvent& event)
{
}

void wxTextCtrl::OnUpdateDelete(wxUpdateUIEvent& event)
{
}

void wxTextCtrl::OnUpdateSelectAll(wxUpdateUIEvent& event)
{
}

void wxTextCtrl::OnSetFocus(wxFocusEvent& WXUNUSED(event))
{
}

wxVisualAttributes wxTextCtrl::GetDefaultAttributes() const
{
    wxVisualAttributes attrs;
    attrs.font = wxSystemSettings::GetFont(wxSYS_DEFAULT_GUI_FONT);
    attrs.colFg = wxSystemSettings::GetColour(wxSYS_COLOUR_WINDOWTEXT);
    attrs.colBg = wxSystemSettings::GetColour(wxSYS_COLOUR_WINDOW); //white
    return attrs;
}

bool wxTextCtrl::EmulateKeyPress(const wxKeyEvent& rEvent)
{
    return false;
}
bool wxTextCtrl::CanApplyThemeBorder() const
{
    return false;
}
bool wxTextCtrl::IsEmpty() const
{
    return false;
}
bool wxTextCtrl::AcceptsFocusFromKeyboard() const
{
    return false;
}
void wxTextCtrl::AdoptAttributesFromHWND()
{
}
void wxTextCtrl::SetWindowStyleFlag(long lStyle)
{
}

// the rest of the file only deals with the rich edit controls
#if wxUSE_RICHEDIT

// ----------------------------------------------------------------------------
// EN_LINK processing
// ----------------------------------------------------------------------------

bool wxTextCtrl::MSWOnNotify(int idCtrl, WXLPARAM lParam, WXLPARAM *result)
{
    return false;
}

// ----------------------------------------------------------------------------
// colour setting for the rich edit controls
// ----------------------------------------------------------------------------

bool wxTextCtrl::SetBackgroundColour(const wxColour& colour)
{
    return false;
}

bool wxTextCtrl::SetForegroundColour(const wxColour& colour)
{
    return false;
}

// ----------------------------------------------------------------------------
// wxRichEditModule
// ----------------------------------------------------------------------------

bool wxRichEditModule::OnInit()
{
    return false;
}

void wxRichEditModule::OnExit()
{
}

/* static */
bool wxRichEditModule::Load(int version)
{
    return false;
}

#endif // wxUSE_RICHEDIT

// ----------------------------------------------------------------------------
// styling support for rich edit controls
// ----------------------------------------------------------------------------

#if wxUSE_RICHEDIT

bool wxTextCtrl::SetStyle(long start, long end, const wxTextAttr& style)
{
    return false;
}

bool wxTextCtrl::SetDefaultStyle(const wxTextAttr& style)
{
    return false;
}

bool wxTextCtrl::GetStyle(long position, wxTextAttr& style)
{
    return false;
}

#endif // wxUSE_RICHEDIT

#endif // wxUSE_TEXTCTRL

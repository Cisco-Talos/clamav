/////////////////////////////////////////////////////////////////////////////
// Name:        src/x11/textctrl.cpp
// Purpose:
// Author:      Robert Roebling
// Id:          $Id$
// Copyright:   (c) 1998 Robert Roebling
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// for compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/textctrl.h"

#ifndef WX_PRECOMP
    #include "wx/intl.h"
    #include "wx/log.h"
    #include "wx/utils.h"
    #include "wx/panel.h"
    #include "wx/dcclient.h"
    #include "wx/settings.h"
#endif

#include "wx/clipbrd.h"
#include "wx/tokenzr.h"

#include "wx/univ/inphand.h"
#include "wx/univ/renderer.h"
#include "wx/univ/colschem.h"
#include "wx/univ/theme.h"

//-----------------------------------------------------------------------------
//  helpers
//-----------------------------------------------------------------------------

wxSourceUndoStep::wxSourceUndoStep( wxSourceUndo type, int y1, int y2, wxTextCtrl *owner )
{
    m_type = type;
    m_y1 = y1;
    m_y2 = y2;
    m_owner = owner;

    m_cursorX = m_owner->GetCursorX();
    m_cursorY = m_owner->GetCursorY();

    if (m_type == wxSOURCE_UNDO_LINE)
    {
        m_text = m_owner->m_lines[m_y1].m_text;
    } else
    if (m_type == wxSOURCE_UNDO_ENTER)
    {
        m_text = m_owner->m_lines[m_y1].m_text;
    } else
    if (m_type == wxSOURCE_UNDO_BACK)
    {
        for (int i = m_y1; i < m_y2+2; i++)
        {
            if (i >= (int)m_owner->m_lines.GetCount())
                m_lines.Add( wxEmptyString );
            else
                m_lines.Add( m_owner->m_lines[i].m_text );
        }
    } else
    if (m_type == wxSOURCE_UNDO_DELETE)
    {
        for (int i = m_y1; i < m_y2+1; i++)
        {
            m_lines.Add( m_owner->m_lines[i].m_text );
        }
    } else
    if (m_type == wxSOURCE_UNDO_PASTE)
    {
        m_text = m_owner->m_lines[m_y1].m_text;
    }
}

void wxSourceUndoStep::Undo()
{
    if (m_type == wxSOURCE_UNDO_LINE)
    {
        m_owner->m_lines[m_y1].m_text = m_text;
        m_owner->MoveCursor( m_cursorX, m_cursorY );
        m_owner->RefreshLine( m_y1 );
    } else
    if (m_type == wxSOURCE_UNDO_ENTER)
    {
        m_owner->m_lines[m_y1].m_text = m_text;
        m_owner->m_lines.RemoveAt( m_y1+1 );
        m_owner->MoveCursor( m_cursorX, m_cursorY );
        m_owner->RefreshDown( m_y1 );
    } else
    if (m_type == wxSOURCE_UNDO_BACK)
    {
        m_owner->m_lines[m_y1].m_text = m_lines[0];
        m_owner->m_lines.Insert( new wxSourceLine( m_lines[1] ), m_y1+1 );
        m_owner->MyAdjustScrollbars();
        m_owner->MoveCursor( m_cursorX, m_cursorY );
        m_owner->RefreshDown( m_y1 );
    } else
    if (m_type == wxSOURCE_UNDO_DELETE)
    {
        m_owner->m_lines[m_y1].m_text = m_lines[0];
        for (int i = 1; i < (int)m_lines.GetCount(); i++)
            m_owner->m_lines.Insert( new wxSourceLine( m_lines[i] ), m_y1+i );
        m_owner->MyAdjustScrollbars();
        m_owner->MoveCursor( m_cursorX, m_cursorY );
        m_owner->RefreshDown( m_y1 );
    } else
    if (m_type == wxSOURCE_UNDO_PASTE)
    {
        m_owner->m_lines[m_y1].m_text = m_text;
        for (int i = 0; i < m_y2-m_y1; i++)
            m_owner->m_lines.RemoveAt( m_y1+1 );
        m_owner->MyAdjustScrollbars();
        m_owner->MoveCursor( m_cursorX, m_cursorY );
        m_owner->RefreshDown( m_y1 );
    } else
    if (m_type == wxSOURCE_UNDO_INSERT_LINE)
    {
        m_owner->m_lines.RemoveAt( m_y1 );
        m_owner->MyAdjustScrollbars();
        m_owner->MoveCursor( 0, m_y1 );
        m_owner->RefreshDown( m_y1 );
    }
}

#include "wx/arrimpl.cpp"
WX_DEFINE_OBJARRAY(wxSourceLineArray);

//-----------------------------------------------------------------------------
//  wxTextCtrl
//-----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxTextCtrl, wxTextCtrlBase)

BEGIN_EVENT_TABLE(wxTextCtrl, wxTextCtrlBase)
    EVT_PAINT(wxTextCtrl::OnPaint)
    EVT_ERASE_BACKGROUND(wxTextCtrl::OnEraseBackground)
    EVT_CHAR(wxTextCtrl::OnChar)
    EVT_MOUSE_EVENTS(wxTextCtrl::OnMouse)
    EVT_KILL_FOCUS(wxTextCtrl::OnKillFocus)
    EVT_SET_FOCUS(wxTextCtrl::OnSetFocus)

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

void wxTextCtrl::Init()
{
    m_editable = true;
    m_modified = false;

    m_lang = wxSOURCE_LANG_NONE;

    m_capturing = false;

    m_cursorX = 0;
    m_cursorY = 0;

    m_longestLine = 0;

    m_bracketX = -1;
    m_bracketY = -1;

    m_overwrite = false;
    m_ignoreInput = false;

    ClearSelection();

    m_keywordColour = wxColour( 10, 140, 10 );

    m_defineColour = *wxRED;

    m_variableColour = wxColour( 50, 120, 150 );

    m_commentColour = wxColour( 130, 130, 130 );

    m_stringColour = wxColour( 10, 140, 10 );
}

wxTextCtrl::wxTextCtrl( wxWindow *parent,
                        wxWindowID id,
                        const wxString &value,
                        const wxPoint &pos,
                        const wxSize &size,
                        long style,
                        const wxValidator& validator,
                        const wxString &name )
    : wxScrollHelper(this)
{
    Init();

    Create( parent, id, value, pos, size, style, validator, name );
}

wxTextCtrl::~wxTextCtrl()
{
    WX_CLEAR_LIST(wxList, m_undos);
}

bool wxTextCtrl::Create( wxWindow *parent,
                         wxWindowID id,
                         const wxString &value,
                         const wxPoint &pos,
                         const wxSize &size,
                         long style,
                         const wxValidator& validator,
                         const wxString &name )
{
    if ((style & wxBORDER_MASK) == 0)
        style |= wxBORDER_SUNKEN;

    if ((style & wxTE_MULTILINE) != 0)
        style |= wxALWAYS_SHOW_SB;

    wxTextCtrlBase::Create( parent, id, pos /* wxDefaultPosition */, size,
                            style | wxVSCROLL | wxHSCROLL);

    SetBackgroundColour( *wxWHITE );

    SetCursor( wxCursor( wxCURSOR_IBEAM ) );

    m_editable = ((m_windowStyle & wxTE_READONLY) == 0);

    if (HasFlag(wxTE_PASSWORD))
        m_sourceFont = wxFont( 12, wxMODERN, wxNORMAL, wxNORMAL );
    else
        m_sourceFont = GetFont();

    wxClientDC dc(this);
    dc.SetFont( m_sourceFont );
    m_lineHeight = dc.GetCharHeight();
    m_charWidth = dc.GetCharWidth();

    SetValue( value );

    wxSize size_best( DoGetBestSize() );
    wxSize new_size( size );
    if (new_size.x == -1)
        new_size.x = size_best.x;
    if (new_size.y == -1)
        new_size.y = size_best.y;
    if ((new_size.x != size.x) || (new_size.y != size.y))
        SetSize( new_size.x, new_size.y );

    // We create an input handler since it might be useful
    CreateInputHandler(wxINP_HANDLER_TEXTCTRL);

    MyAdjustScrollbars();

    return true;
}

//-----------------------------------------------------------------------------
//  public methods
//-----------------------------------------------------------------------------

wxString wxTextCtrl::GetValue() const
{
    wxString ret;
    for (size_t i = 0; i < m_lines.GetCount(); i++)
    {
        ret += m_lines[i].m_text;
        if (i+1 < m_lines.GetCount())
            ret += wxT('\n');
    }

    return ret;
}

void wxTextCtrl::DoSetValue(const wxString& value, int flags)
{
    m_modified = false;

    wxString oldValue = GetValue();

    m_cursorX = 0;
    m_cursorY = 0;
    ClearSelection();
    m_lines.Clear();
    m_longestLine = 0;

    if (value.empty())
    {
        m_lines.Add( new wxSourceLine( wxEmptyString ) );
    }
    else
    {
        int begin = 0;
        int pos = 0;
        for (;;)
        {
            pos = value.find( wxT('\n'), begin );
            if (pos < 0)
            {
                wxSourceLine *sl = new wxSourceLine( value.Mid( begin, value.Len()-begin ) );
                m_lines.Add( sl );

                // if (sl->m_text.Len() > m_longestLine)
                //    m_longestLine = sl->m_text.Len();
                int ww = 0;
                GetTextExtent( sl->m_text, &ww, NULL, NULL, NULL );
                ww /= m_charWidth;
                if (ww > m_longestLine)
                    m_longestLine = ww;

                break;
            }
            else
            {
                wxSourceLine *sl = new wxSourceLine( value.Mid( begin, pos-begin ) );
                m_lines.Add( sl );

                // if (sl->m_text.Len() > m_longestLine)
                //      m_longestLine = sl->m_text.Len();
                int ww = 0;
                GetTextExtent( sl->m_text, &ww, NULL, NULL, NULL );
                ww /= m_charWidth;
                if (ww > m_longestLine)
                    m_longestLine = ww;

                begin = pos+1;
            }
        }
    }

    // Don't need to refresh if the value hasn't changed
    if ((GetWindowStyle() & wxTE_MULTILINE) == 0)
    {
        if (value == oldValue)
            return;
    }

    MyAdjustScrollbars();

    Refresh();

    if ( flags & SetValue_SendEvent )
        SendTextUpdatedEvent();
}

int wxTextCtrl::GetLineLength(long lineNo) const
{
    if (lineNo >= (long)m_lines.GetCount())
        return 0;

    return m_lines[lineNo].m_text.Len();
}

wxString wxTextCtrl::GetLineText(long lineNo) const
{
    if (lineNo >= (long)m_lines.GetCount())
        return wxEmptyString;

    return m_lines[lineNo].m_text;
}

int wxTextCtrl::GetNumberOfLines() const
{
    return  m_lines.GetCount();
}

bool wxTextCtrl::IsModified() const
{
    return m_modified;
}

bool wxTextCtrl::IsEditable() const
{
    return m_editable;
}

void wxTextCtrl::GetSelection(long* from, long* to) const
{
    if (m_selStartX == -1 || m_selStartY == -1 ||
        m_selEndX == -1 || m_selEndY == -1)
    {
        *from = GetInsertionPoint();
        *to = GetInsertionPoint();
    }
    else
    {
        *from = XYToPosition(m_selStartX, m_selStartY);
        *to = XYToPosition(m_selEndX, m_selEndY);
    }
}

void wxTextCtrl::Clear()
{
    m_modified = true;
    m_cursorX = 0;
    m_cursorY = 0;
    ClearSelection();

    m_lines.Clear();
    m_lines.Add( new wxSourceLine( wxEmptyString ) );

    SetScrollbars( m_charWidth, m_lineHeight, 0, 0, 0, 0 );
    Refresh();
    WX_CLEAR_LIST(wxList, m_undos);
}

void wxTextCtrl::Replace(long from, long to, const wxString& value)
{
}

void wxTextCtrl::Remove(long from, long to)
{
}

void wxTextCtrl::DiscardEdits()
{
    ClearSelection();
    Refresh();
}

void wxTextCtrl::SetMaxLength(unsigned long len)
{
}

int wxTextCtrl::PosToPixel( int line, int pos )
{
    // TODO add support for Tabs

    if (line >= (int)m_lines.GetCount()) return 0;
    if (pos < 0) return 0;

    wxString text = m_lines[line].m_text;

    if (text.empty()) return 0;

    if (pos < (int)text.Len())
        text.Remove( pos, text.Len()-pos );

    int w = 0;

    GetTextExtent( text, &w, NULL, NULL, NULL );

    return w;
}

int wxTextCtrl::PixelToPos( int line, int pixel )
{
    if (pixel < 2) return 0;

    if (line >= (int)m_lines.GetCount()) return 0;

    wxString text = m_lines[line].m_text;

    int w = 0;
    int res = text.Len();
    while (res > 0)
    {
        GetTextExtent( text, &w, NULL, NULL, NULL );

        if (w < pixel)
            return res;

        res--;
        text.Remove( res,1 );
    }

    return 0;
}

void wxTextCtrl::SetLanguage( wxSourceLanguage lang )
{
    m_lang = lang;

    m_keywords.Clear();
}

void wxTextCtrl::WriteText(const wxString& text2)
{
    if (text2.empty()) return;

    m_modified = true;

    wxString text( text2 );
    wxArrayString lines;
    int pos;
    while ( (pos = text.Find('\n')) != -1 )
    {
       lines.Add( text.Left( pos ) );
       text.Remove( 0, pos+1 );
    }
    lines.Add( text );
    int count = (int)lines.GetCount();

    wxString tmp1( m_lines[m_cursorY].m_text );
    wxString tmp2( tmp1 );
    int len = (int)tmp1.Len();

    if (len < m_cursorX)
    {
        wxString tmp;
        for (int i = 0; i < m_cursorX-len; i++)
            tmp.Append( ' ' );
        m_lines[m_cursorY].m_text.Append( tmp );
        tmp1.Append( tmp );
        tmp2.Append( tmp );
    }

    tmp1.Remove( m_cursorX );
    tmp2.Remove( 0, m_cursorX );
    tmp1.Append( lines[0] );

    if (count == 1)
    {
        m_undos.Append( new wxSourceUndoStep( wxSOURCE_UNDO_LINE, m_cursorY, m_cursorY, this ) );

        tmp1.Append( tmp2 );
        m_lines[m_cursorY].m_text = tmp1;
        RefreshLine( m_cursorY );
    }
    else
    {
        m_undos.Append( new wxSourceUndoStep( wxSOURCE_UNDO_PASTE, m_cursorY, m_cursorY+count-1, this ) );

        m_lines[m_cursorY].m_text = tmp1;
        int i;
        for (i = 1; i < count; i++)
            m_lines.Insert( new wxSourceLine( lines[i] ), m_cursorY+i );
        m_lines[m_cursorY+i-1].m_text.Append( tmp2 );

        MyAdjustScrollbars();
        RefreshDown( m_cursorY );
    }
}

void wxTextCtrl::AppendText(const wxString& text2)
{
    if (text2.empty()) return;

    m_modified = true;

    wxString text( text2 );
    wxArrayString lines;
    int pos;
    while ( (pos = text.Find('\n')) != -1 )
    {
       lines.Add( text.Left( pos ) );
       text.Remove( 0, pos+1 );
    }
    lines.Add( text );
    int count = (int)lines.GetCount();

    size_t y = m_lines.GetCount()-1;

    wxString tmp( m_lines[y].m_text );
    tmp.Append( lines[0] );

    if (count == 1)
    {
        m_undos.Append( new wxSourceUndoStep( wxSOURCE_UNDO_LINE, y, y, this ) );

        m_lines[y].m_text = tmp;
        RefreshLine( y );
    }
    else
    {
        m_undos.Append( new wxSourceUndoStep( wxSOURCE_UNDO_PASTE, y, y+count-1, this ) );

        m_lines[y].m_text = tmp;
        int i;
        for (i = 1; i < count; i++)
            m_lines.Insert( new wxSourceLine( lines[i] ), y+i );

        MyAdjustScrollbars();
        RefreshDown( y );
    }
}

bool wxTextCtrl::SetStyle(long start, long end, const wxTextAttr& style)
{
    return false;
}

long wxTextCtrl::XYToPosition(long x, long y) const
{
    long ret = 0;

    for (size_t i = 0; i < m_lines.GetCount(); i++)
    {
        if (i < (size_t)y)
        {
            // Add one for the end-of-line character
            ret += m_lines[i].m_text.Len() + 1;
            continue;
        }

        if ((size_t)x < (m_lines[i].m_text.Len()+1))
            return (ret + x);
        else
            return (ret + m_lines[i].m_text.Len() + 1);
    }

    return ret;
}

bool wxTextCtrl::PositionToXY(long pos, long *x, long *y) const
{
    if (m_lines.GetCount() == 0)
    {
        if (x) *x = 0;
        if (y) *y = 0;

        return (pos == 0);
    }

    long xx = 0;
    long yy = 0;

    for (size_t i = 0; i < m_lines.GetCount(); i++)
    {
        //pos -= m_lines[i].m_text.Len();
        //if (pos <= 0)

        // Add one for the end-of-line character. (In Windows,
        // there are _two_ positions for each end of line.)
        if (pos <= ((int)m_lines[i].m_text.Len()))
        {
            xx = pos;
            if (x) *x = xx;
            if (y) *y = yy;
            return true;
        }
        pos -= (m_lines[i].m_text.Len() + 1);
        yy++;
    }

    // Last pos
    //xx = m_lines[ m_lines.GetCount()-1 ].m_text.Len();
    xx = pos;
    if (x) *x = xx;
    if (y) *y = yy;

    return false;
}

void wxTextCtrl::ShowPosition(long pos)
{
}

void wxTextCtrl::Copy()
{
    if (!HasSelection()) return;

    wxString sel;

    int selStartY = m_selStartY;
    int selEndY = m_selEndY;
    int selStartX = m_selStartX;
    int selEndX = m_selEndX;

    if ((selStartY > selEndY) ||
        ((selStartY == selEndY) && (selStartX > selEndX)))
    {
        int tmp = selStartX;
        selStartX = selEndX;
        selEndX = tmp;
        tmp = selStartY;
        selStartY = selEndY;
        selEndY = tmp;
    }

    if (selStartY == selEndY)
    {
        sel = m_lines[selStartY].m_text;

        if (selStartX >= (int)sel.Len()) return;
        if (selEndX > (int)sel.Len())
            selEndX = sel.Len();

        sel.Remove( selEndX, sel.Len()-selEndX );
        sel.Remove( 0, selStartX );
    }
    else
    {
        wxString tmp( m_lines[selStartY].m_text );

        if (selStartX < (int)tmp.Len())
        {
            tmp.Remove( 0, selStartX );
            sel = tmp;
            sel.Append( wxT("\n") );
        }
        for (int i = selStartY+1; i < selEndY; i++)
        {
            sel.Append( m_lines[i].m_text );
            sel.Append( wxT("\n") );
        }
        tmp = m_lines[selEndY].m_text;
        if (selEndX > (int)tmp.Len())
            selEndX = tmp.Len();
        if (selEndX > 0)
        {
            tmp.Remove( selEndX, tmp.Len()-selEndX );
            sel.Append( tmp );
        }
    }

    if (wxTheClipboard->Open())
    {
        wxTheClipboard->SetData( new wxTextDataObject( sel ) );
        wxTheClipboard->Close();
    }
}

void wxTextCtrl::Cut()
{
    Copy();

    Delete();
}

void wxTextCtrl::Paste()
{
    Delete();

    if (!wxTheClipboard->Open()) return;

    if (!wxTheClipboard->IsSupported( wxDF_TEXT ))
    {
        wxTheClipboard->Close();

        return;
    }

    wxTextDataObject data;

    bool ret = wxTheClipboard->GetData( data );

    wxTheClipboard->Close();

    if (!ret) return;

    m_modified = true;

    wxString text( data.GetText() );
    wxArrayString lines;
    int pos;
    while ( (pos = text.Find('\n')) != -1 )
    {
       lines.Add( text.Left( pos ) );
       text.Remove( 0, pos+1 );
    }
    lines.Add( text );
    int count = (int)lines.GetCount();

    wxString tmp1( m_lines[m_cursorY].m_text );
    wxString tmp2( tmp1 );
    int len = (int)tmp1.Len();

    if (len < m_cursorX)
    {
        wxString tmp;
        for (int i = 0; i < m_cursorX-len; i++)
            tmp.Append( ' ' );
        m_lines[m_cursorY].m_text.Append( tmp );
        tmp1.Append( tmp );
        tmp2.Append( tmp );
    }

    tmp1.Remove( m_cursorX );
    tmp2.Remove( 0, m_cursorX );
    tmp1.Append( lines[0] );

    if (count == 1)
    {
        m_undos.Append( new wxSourceUndoStep( wxSOURCE_UNDO_LINE, m_cursorY, m_cursorY, this ) );

        tmp1.Append( tmp2 );
        m_lines[m_cursorY].m_text = tmp1;
        RefreshLine( m_cursorY );
    }
    else
    {
        m_undos.Append( new wxSourceUndoStep( wxSOURCE_UNDO_PASTE, m_cursorY, m_cursorY+count-1, this ) );

        m_lines[m_cursorY].m_text = tmp1;
        int i;
        for (i = 1; i < count; i++)
            m_lines.Insert( new wxSourceLine( lines[i] ), m_cursorY+i );
        m_lines[m_cursorY+i-1].m_text.Append( tmp2 );

        MyAdjustScrollbars();
        RefreshDown( m_cursorY );
    }
}

void wxTextCtrl::Undo()
{
    if (m_undos.GetCount() == 0) return;

    wxList::compatibility_iterator node = m_undos.Item( m_undos.GetCount()-1 );
    wxSourceUndoStep *undo = (wxSourceUndoStep*) node->GetData();

    undo->Undo();

    delete undo;
    m_undos.Erase( node );

    m_modified = true;
}

void wxTextCtrl::SetInsertionPoint(long pos)
{
    ClearSelection();
    long x, y;
    PositionToXY(pos, & x, & y);
    m_cursorX = x;
    m_cursorY = y;
    // TODO: scroll to this position if necessary
    Refresh();
}

void wxTextCtrl::SetInsertionPointEnd()
{
    SetInsertionPoint(GetLastPosition());
}

long wxTextCtrl::GetInsertionPoint() const
{
    return XYToPosition( m_cursorX, m_cursorY );
}

wxTextPos wxTextCtrl::GetLastPosition() const
{
    size_t lineCount = m_lines.GetCount() - 1;
    // It's the length of the line, not the length - 1,
    // because there's a position after the last character.
    return XYToPosition( m_lines[lineCount].m_text.Len(), lineCount );
}

void wxTextCtrl::SetSelection(long from, long to)
{
}

void wxTextCtrl::SetEditable(bool editable)
{
    m_editable = editable;
}

bool wxTextCtrl::Enable( bool enable )
{
    return false;
}

bool wxTextCtrl::SetFont(const wxFont& font)
{
    wxTextCtrlBase::SetFont( font );

    m_sourceFont = font;

    wxClientDC dc(this);
    dc.SetFont( m_sourceFont );
    m_lineHeight = dc.GetCharHeight();
    m_charWidth = dc.GetCharWidth();

    // TODO: recalc longest lines

    MyAdjustScrollbars();

    return true;
}

bool wxTextCtrl::SetForegroundColour(const wxColour& colour)
{
    return wxWindow::SetForegroundColour( colour );
}

bool wxTextCtrl::SetBackgroundColour(const wxColour& colour)
{
    return wxWindow::SetBackgroundColour( colour );
}

//-----------------------------------------------------------------------------
//  private code and handlers
//-----------------------------------------------------------------------------

void wxTextCtrl::SearchForBrackets()
{
    int oldBracketY = m_bracketY;
    int oldBracketX = m_bracketX;

    if (m_cursorY < 0 || m_cursorY >= (int)m_lines.GetCount()) return;

    wxString current = m_lines[m_cursorY].m_text;

    // reverse search first

    char bracket = ' ';

    if (m_cursorX > 0)
        bracket = current[(size_t) (m_cursorX-1)];

    if (bracket == ')' || bracket == ']' || bracket == '}')
    {
        char antibracket = '(';
        if (bracket == ']') antibracket = '[';
        if (bracket == '}') antibracket = '{';

        int count = 1;

        int endY = m_cursorY-60;
        if (endY < 0) endY = 0;
        for (int y = m_cursorY; y >= endY; y--)
        {
            current = m_lines[y].m_text;
            if (y == m_cursorY)
                current.erase(m_cursorX-1,current.Len()-m_cursorX+1);

            for (int n = current.Len()-1; n >= 0; n--)
            {
                // ignore chars
                if (current[(size_t) (n)] == '\'')
                {
                    for (int m = n-1; m >= 0; m--)
                    {
                        if (current[(size_t) (m)] == '\'')
                        {
                            if (m == 0 || current[(size_t) (m-1)] != '\\')
                                break;
                        }
                        n = m-1;
                    }
                    continue;
                }

                // ignore strings
                if (current[(size_t) (n)] == '\"')
                {
                    for (int m = n-1; m >= 0; m--)
                    {
                        if (current[(size_t) (m)] == '\"')
                        {
                            if (m == 0 || current[(size_t) (m-1)] != '\\')
                                break;
                        }
                        n = m-1;
                    }
                    continue;
                }

                if (current[(size_t) (n)] == antibracket)
                {
                    count--;
                    if (count == 0)
                    {
                        m_bracketY = y;
                        m_bracketX = n;
                        if (oldBracketY != m_bracketY && oldBracketY != -1)
                            RefreshLine( oldBracketY );
                        if (m_bracketY != oldBracketY || m_bracketX != oldBracketX)
                            RefreshLine( m_bracketY );
                        return;
                    }
                }
                else if (current[(size_t) (n)] == bracket)
                {
                    count++;
                }
            }
        }
    }

    // then forward

    bracket = ' ';
    if ((int)current.Len() > m_cursorX)
        bracket = current[(size_t) (m_cursorX)];
    if (bracket == '(' || bracket == '[' || bracket == '{')
    {
        char antibracket = ')';
        if (bracket == '[') antibracket = ']';
        if (bracket == '{') antibracket = '}';

        int count = 1;

        int endY = m_cursorY+60;
        if (endY > (int)(m_lines.GetCount()-1)) endY = m_lines.GetCount()-1;
        for (int y = m_cursorY; y <= endY; y++)
        {
            current = m_lines[y].m_text;
            int start = 0;
            if (y == m_cursorY)
                start = m_cursorX+1;

            for (int n = start; n < (int)current.Len(); n++)
            {
                // ignore chars
                if (current[(size_t) (n)] == '\'')
                {
                    for (int m = n+1; m < (int)current.Len(); m++)
                    {
                        if (current[(size_t) (m)] == '\'')
                        {
                            if (m == 0 || (current[(size_t) (m-1)] != '\\') || (m >= 2 && current[(size_t) (m-2)] == '\\'))
                                break;
                        }
                        n = m+1;
                    }
                    continue;
                }

                // ignore strings
                if (current[(size_t) (n)] == '\"')
                {
                    for (int m = n+1; m < (int)current.Len(); m++)
                    {
                        if (current[(size_t) (m)] == '\"')
                        {
                            if (m == 0 || (current[(size_t) (m-1)] != '\\') || (m >= 2 && current[(size_t) (m-2)] == '\\'))
                                break;
                        }
                        n = m+1;
                    }
                    continue;
                }

                if (current[(size_t) (n)] == antibracket)
                {
                    count--;
                    if (count == 0)
                    {
                        m_bracketY = y;
                        m_bracketX = n;
                        if (oldBracketY != m_bracketY && oldBracketY != -1)
                            RefreshLine( oldBracketY );
                        if (m_bracketY != oldBracketY || m_bracketX != oldBracketX)
                            RefreshLine( m_bracketY );
                        return;
                    }
                }
                else if (current[(size_t) (n)] == bracket)
                {
                    count++;
                }
            }
        }
    }

    if (oldBracketY != -1)
    {
        m_bracketY = -1;
        RefreshLine( oldBracketY );
    }
}

void wxTextCtrl::Delete()
{
    if (!HasSelection()) return;

    m_modified = true;

    int selStartY = m_selStartY;
    int selEndY = m_selEndY;
    int selStartX = m_selStartX;
    int selEndX = m_selEndX;

    if ((selStartY > selEndY) ||
        ((selStartY == selEndY) && (selStartX > selEndX)))
    {
        int tmp = selStartX;
        selStartX = selEndX;
        selEndX = tmp;
        tmp = selStartY;
        selStartY = selEndY;
        selEndY = tmp;
    }

    int len = (int)m_lines[selStartY].m_text.Len();

    if (selStartY == selEndY)
    {
        m_undos.Append( new wxSourceUndoStep( wxSOURCE_UNDO_LINE, selStartY, selStartY, this ) );

        wxString tmp( m_lines[selStartY].m_text );
        if (selStartX < len)
        {
            if (selEndX > len)
                selEndX = len;
            tmp.Remove( selStartX, selEndX-selStartX );
            m_lines[selStartY].m_text = tmp;
        }
        ClearSelection();
        m_cursorX = selStartX;
        RefreshLine( selStartY );
    }
    else
    {
        m_undos.Append( new wxSourceUndoStep( wxSOURCE_UNDO_DELETE, selStartY, selEndY, this ) );

        if (selStartX < len)
            m_lines[selStartY].m_text.Remove( selStartX );

        for (int i = 0; i < selEndY-selStartY-1; i++)
            m_lines.RemoveAt( selStartY+1 );

        if (selEndX < (int)m_lines[selStartY+1].m_text.Len())
            m_lines[selStartY+1].m_text.Remove( 0, selEndX );
        else
            m_lines[selStartY+1].m_text.Remove( 0 );

        m_lines[selStartY].m_text.Append( m_lines[selStartY+1].m_text );
        m_lines.RemoveAt( selStartY+1 );

        ClearSelection();
        MoveCursor( selStartX, selStartY );
        MyAdjustScrollbars();

        RefreshDown( selStartY );
    }
}

void wxTextCtrl::DeleteLine()
{
    if (HasSelection()) return;

    if (m_cursorY < 0 || m_cursorY >= (int)m_lines.GetCount()-1) return;  // TODO

    m_undos.Append( new wxSourceUndoStep( wxSOURCE_UNDO_DELETE, m_cursorY, m_cursorY+1, this ) );

    m_lines.RemoveAt( m_cursorY );
    m_cursorX = 0;
    if (m_cursorY >= (int)m_lines.GetCount()) m_cursorY--;

    MyAdjustScrollbars();
    RefreshDown( m_cursorY );
}

void wxTextCtrl::DoChar( char c )
{
    m_modified = true;

    m_undos.Append( new wxSourceUndoStep( wxSOURCE_UNDO_LINE, m_cursorY, m_cursorY, this ) );

    wxString tmp( m_lines[m_cursorY].m_text );
    tmp.Trim();
    if (m_cursorX >= (int)tmp.Len())
    {
        int len = tmp.Len();
        for (int i = 0; i < m_cursorX - len; i++)
            tmp.Append( ' ' );
        tmp.Append( c );
    }
    else
    {
        if (m_overwrite)
            tmp.SetChar( m_cursorX, c );
        else
            tmp.insert( m_cursorX, 1, c );
    }

    m_lines[m_cursorY].m_text = tmp;

//    if (tmp.Len() > m_longestLine)
//    {
//        m_longestLine = tmp.Len();
//        MyAdjustScrollbars();
//    }

    int ww = 0;
    GetTextExtent( tmp, &ww, NULL, NULL, NULL );
    ww /= m_charWidth;
    if (ww > m_longestLine)
    {
        m_longestLine = ww;
        MyAdjustScrollbars();
    }

    m_cursorX++;

    int y = m_cursorY*m_lineHeight;
    // int x = (m_cursorX-1)*m_charWidth;
    int x = PosToPixel( m_cursorY, m_cursorX-1 );
    CalcScrolledPosition( x, y, &x, &y );
    wxRect rect( x+2, y+2, 10000, m_lineHeight );
    Refresh( true, &rect );
    // refresh whole line for syntax colour highlighting
    rect.x = 0;
    Refresh( false, &rect );

    int size_x = 0;
    int size_y = 0;
    GetClientSize( &size_x, &size_y );
    size_x /= m_charWidth;

    int view_x = 0;
    int view_y = 0;
    GetViewStart( &view_x, &view_y );

    //int xx = m_cursorX;
    int xx = PosToPixel( m_cursorY, m_cursorX ) / m_charWidth;

    if (xx < view_x)
        Scroll( xx, -1 );
    else if (xx > view_x+size_x-1)
        Scroll( xx-size_x+1, -1 );
}

void wxTextCtrl::DoBack()
{
    m_modified = true;

    if (m_cursorX == 0)
    {
        if (m_cursorY == 0) return;

        m_undos.Append( new wxSourceUndoStep( wxSOURCE_UNDO_BACK, m_cursorY-1, m_cursorY, this ) );

        wxString tmp1( m_lines[m_cursorY-1].m_text );
        tmp1.Trim();
        wxString tmp2( m_lines[m_cursorY].m_text );
        tmp2.Trim();
        m_cursorX = tmp1.Len();
        m_cursorY--;
        tmp1.Append( tmp2 );
        m_lines[m_cursorY].m_text = tmp1;
        m_lines.RemoveAt( m_cursorY+1 );

        MyAdjustScrollbars();
        RefreshDown( m_cursorY-1 );
    }
    else
    {
        m_undos.Append( new wxSourceUndoStep( wxSOURCE_UNDO_LINE, m_cursorY, m_cursorY, this ) );

        if (m_cursorX <= (int)m_lines[m_cursorY].m_text.Len())
            m_lines[m_cursorY].m_text.Remove( m_cursorX-1, 1 );
        m_cursorX--;

        int y = m_cursorY*m_lineHeight;
        // int x = m_cursorX*m_charWidth;
        int x = PosToPixel( m_cursorY, m_cursorX );
        CalcScrolledPosition( x, y, &x, &y );
        wxRect rect( x+2, y+2, 10000, m_lineHeight );
        Refresh( true, &rect );
        // refresh whole line for syntax colour highlighting
        rect.x = 0;
        Refresh( false, &rect );
    }
}

void wxTextCtrl::DoDelete()
{
    m_modified = true;

    wxString tmp( m_lines[m_cursorY].m_text );
    tmp.Trim();
    int len = (int)tmp.Len();
    if (m_cursorX >= len)
    {
        if (m_cursorY == (int)m_lines.GetCount()-1) return;

        m_undos.Append( new wxSourceUndoStep( wxSOURCE_UNDO_DELETE, m_cursorY, m_cursorY+1, this ) );

        for (int i = 0; i < (m_cursorX-len); i++)
            tmp += ' ';

        tmp += m_lines[m_cursorY+1].m_text;

        m_lines[m_cursorY] = tmp;
        m_lines.RemoveAt( m_cursorY+1 );

        MyAdjustScrollbars();
        RefreshDown( m_cursorY );
    }
    else
    {
        m_undos.Append( new wxSourceUndoStep( wxSOURCE_UNDO_LINE, m_cursorY, m_cursorY, this ) );

        tmp.Remove( m_cursorX, 1 );
        m_lines[m_cursorY].m_text = tmp;

        int y = m_cursorY*m_lineHeight;
        // int x = m_cursorX*m_charWidth;
        int x = PosToPixel( m_cursorY, m_cursorX );
        CalcScrolledPosition( x, y, &x, &y );
        wxRect rect( x+2, y+2, 10000, m_lineHeight );
        Refresh( true, &rect );
        // refresh whole line for syntax colour highlighting
        rect.x = 0;
        Refresh( false, &rect );
    }
}

void wxTextCtrl::DoReturn()
{
    m_modified = true;

    m_undos.Append( new wxSourceUndoStep( wxSOURCE_UNDO_ENTER, m_cursorY, m_cursorY, this ) );

    wxString tmp( m_lines[m_cursorY].m_text );
    size_t indent = tmp.find_first_not_of( ' ' );
    if (indent == wxSTRING_MAXLEN) indent = 0;
    tmp.Trim();
    if (m_cursorX >= (int)tmp.Len())
    {
        int cursorX = indent;
        int cursorY = m_cursorY + 1;

        wxString new_tmp;
        for (size_t i = 0; i < indent; i++) new_tmp.Append( ' ' );
        m_lines.Insert( new wxSourceLine( new_tmp ), cursorY );

        MyAdjustScrollbars();
        MoveCursor( cursorX, cursorY );
        RefreshDown( m_cursorY );
    }
    else
    {
        wxString tmp1( tmp );
        tmp1.Remove( m_cursorX, tmp.Len()-m_cursorX );
        m_lines[m_cursorY].m_text = tmp1;

        wxString tmp2( tmp );
        tmp2.Remove( 0, m_cursorX );

        int cursorX = indent;
        int cursorY = m_cursorY + 1;

        wxString new_tmp;
        for (size_t i = 0; i < indent; i++) new_tmp.Append( ' ' );
        new_tmp.Append( tmp2 );
        m_lines.Insert( new wxSourceLine( new_tmp ), cursorY );

        MyAdjustScrollbars();
        MoveCursor( cursorX, cursorY );
        RefreshDown( m_cursorY-1 );
    }
}

void wxTextCtrl::DoDClick()
{
    wxString line( m_lines[ m_cursorY ].m_text );
    if (m_cursorX >= (int)line.Len()) return;
    int p = m_cursorX;
    char ch = line[(size_t) (p)];
    if (((ch >= 'a') && (ch <= 'z')) ||
        ((ch >= 'A') && (ch <= 'Z')) ||
        ((ch >= '0') && (ch <= '9')) ||
        (ch == '_'))
    {
        m_selStartY = m_cursorY;
        m_selEndY = m_cursorY;
        if (p > 0)
        {
            ch = line[(size_t) (p-1)];
            while (((ch >= 'a') && (ch <= 'z')) ||
                   ((ch >= 'A') && (ch <= 'Z')) ||
                   ((ch >= '0') && (ch <= '9')) ||
                   (ch == '_'))
            {
                p--;
                if (p == 0) break;
                ch = line[(size_t) (p-1)];
            }
        }
        m_selStartX = p;

        p = m_cursorX;
        if (p < (int)line.Len())
        {
            ch = line[(size_t) (p)];
            while (((ch >= 'a') && (ch <= 'z')) ||
                   ((ch >= 'A') && (ch <= 'Z')) ||
                   ((ch >= '0') && (ch <= '9')) ||
                   (ch == '_'))
            {
                if (p >= (int)line.Len()) break;
                p++;
                ch = line[(size_t) (p)];
            }
        }
        m_selEndX = p;
        RefreshLine( m_cursorY );
    }
}

wxString wxTextCtrl::GetNextToken( wxString &line, size_t &pos )
{
    wxString ret;
    size_t len = line.Len();
    for (size_t p = pos; p < len; p++)
    {
        if ((m_lang == wxSOURCE_LANG_PYTHON) || (m_lang == wxSOURCE_LANG_PERL))
        {
            if (line[p] == '#')
            {
                for (size_t q = p; q < len; q++)
                    ret.Append( line[q] );
                pos = p;
                return ret;
            }
        }
        else
        {
            if ((line[p] == '/') && (p+1 < len) && (line[(size_t) (p+1)] == '/'))
            {
                for (size_t q = p; q < len; q++)
                    ret.Append( line[q] );
                pos = p;
                return ret;
            }
        }

        if (line[p] == '"')
        {
            ret.Append( line[p] );
            for (size_t q = p+1; q < len; q++)
            {
                ret.Append( line[q] );
                if ((line[q] == '"') && ((line[(size_t) (q-1)] != '\\') || (q >= 2 && line[(size_t) (q-2)] == '\\')))
                   break;
            }
            pos = p;
            return ret;
        }

        if (line[p] == '\'')
        {
            ret.Append( line[p] );
            for (size_t q = p+1; q < len; q++)
            {
                ret.Append( line[q] );
                if ((line[q] == '\'') && ((line[(size_t) (q-1)] != '\\') || (q >= 2 && line[(size_t) (q-2)] == '\\')))
                   break;
            }
            pos = p;
            return ret;
        }

        if (((line[p] >= 'a') && (line[p] <= 'z')) ||
            ((line[p] >= 'A') && (line[p] <= 'Z')) ||
            (line[p] == '_') ||
            (line[p] == '#'))
        {
           ret.Append( line[p] );
           for (size_t q = p+1; q < len; q++)
           {
                if (((line[q] >= 'a') && (line[q] <= 'z')) ||
                   ((line[q] >= 'A') && (line[q] <= 'Z')) ||
                   ((line[q] >= '0') && (line[q] <= '9')) ||
                   (line[q] == '_'))
                {
                    ret.Append( line[q] );
                    continue;
                }
                else
                {
                    pos = p;
                    return ret;
                }
           }
           pos = p;
           return ret;
        }
    }

    return ret;
}

void wxTextCtrl::OnEraseBackground( wxEraseEvent &event )
{
    event.Skip();
}

void wxTextCtrl::DrawLinePart( wxDC &dc, int x, int y, const wxString &toDraw, const wxString &origin, const wxColour &colour )
{
    size_t pos = 0;
    size_t len = origin.Len();
    dc.SetTextForeground( colour );
    while (pos < len)
    {
        while (toDraw[pos] == wxT(' '))
        {
            pos++;
            if (pos == len) return;
        }

        size_t start = pos;

        wxString current;
        current += toDraw[pos];
        pos++;
        while ( (toDraw[pos] == origin[pos]) && (pos < len))
        {
            current += toDraw[pos];
            pos++;
        }

        int xx = 0;
        wxString tmp = origin.Left( start );
        GetTextExtent( tmp, &xx, NULL, NULL, NULL );
        xx += x;
        int yy = y;
        dc.DrawText( current, xx, yy );
    }
}

void wxTextCtrl::DrawLine( wxDC &dc, int x, int y, const wxString &line2, int lineNum )
{
    int selStartY = m_selStartY;
    int selEndY = m_selEndY;
    int selStartX = m_selStartX;
    int selEndX = m_selEndX;

    if ((selStartY > selEndY) ||
        ((selStartY == selEndY) && (selStartX > selEndX)))
    {
        int tmp = selStartX;
        selStartX = selEndX;
        selEndX = tmp;
        tmp = selStartY;
        selStartY = selEndY;
        selEndY = tmp;
    }

    wxString line( line2 );
    if (HasFlag(wxTE_PASSWORD))
    {
        size_t len = line.Len();
        line = wxString( wxT('*'), len );
    }

    wxString keyword( ' ', line.Len() );
    wxString define( ' ', line.Len() );
    wxString variable( ' ', line.Len() );
    wxString comment( ' ', line.Len() );
    wxString my_string( ' ', line.Len() );
    wxString selection( ' ', line.Len() );

    if (m_lang != wxSOURCE_LANG_NONE)
    {
        if (lineNum == m_bracketY)
        {
            wxString red( ' ', line.Len() );
            if (m_bracketX < (int)line.Len())
            {
                red.SetChar( m_bracketX, line[(size_t) (m_bracketX)] );
                line.SetChar( m_bracketX, ' ' );
                dc.SetTextForeground( *wxRED );
                dc.DrawText( red, x, y );
                dc.SetTextForeground( *wxBLACK );
            }
        }

        size_t pos = 0;
        wxString token( GetNextToken( line, pos ) );
        while (!token.IsNull())
        {
            if (m_keywords.Index( token ) != wxNOT_FOUND)
            {
                size_t end_pos = pos + token.Len();
                for (size_t i = pos; i < end_pos; i++)
                {
                    keyword[i] = line[i];
                    line[i] = ' ';
                }
            } else
            if (m_defines.Index( token ) != wxNOT_FOUND)
            {
                size_t end_pos = pos + token.Len();
                for (size_t i = pos; i < end_pos; i++)
                {
                    define[i] = line[i];
                    line[i] = ' ';
                }
            } else
            if ((m_variables.Index( token ) != wxNOT_FOUND) ||
                ((token.Len() > 2) && (token[(size_t) (0)] == 'w') && (token[(size_t) (1)] == 'x')))
            {
                size_t end_pos = pos + token.Len();
                for (size_t i = pos; i < end_pos; i++)
                {
                    variable[i] = line[i];
                    line[i] = ' ';
                }
            } else
            if ((token.Len() >= 2) && (token[(size_t) (0)] == '/') && (token[(size_t) (1)] == '/') && (m_lang == wxSOURCE_LANG_CPP))
            {
                size_t end_pos = pos + token.Len();
                for (size_t i = pos; i < end_pos; i++)
                {
                    comment[i] = line[i];
                    line[i] = ' ';
                }
            } else
            if ((token[(size_t) (0)] == '#') &&
                ((m_lang == wxSOURCE_LANG_PYTHON) || (m_lang == wxSOURCE_LANG_PERL)))
            {
                size_t end_pos = pos + token.Len();
                for (size_t i = pos; i < end_pos; i++)
                {
                    comment[i] = line[i];
                    line[i] = ' ';
                }
            } else
            if ((token[(size_t) (0)] == '"') || (token[(size_t) (0)] == '\''))
            {
                size_t end_pos = pos + token.Len();
                for (size_t i = pos; i < end_pos; i++)
                {
                    my_string[i] = line[i];
                    line[i] = ' ';
                }
            }
            pos += token.Len();
            token = GetNextToken( line, pos );
        }
    }

    if ((lineNum < selStartY) || (lineNum > selEndY))
    {
        DrawLinePart( dc, x, y, line, line2, *wxBLACK );
        DrawLinePart( dc, x, y, selection, line2, *wxWHITE );
        DrawLinePart( dc, x, y, keyword, line2, m_keywordColour );
        DrawLinePart( dc, x, y, define, line2, m_defineColour );
        DrawLinePart( dc, x, y, variable, line2, m_variableColour );
        DrawLinePart( dc, x, y, comment, line2, m_commentColour );
        DrawLinePart( dc, x, y, my_string, line2, m_stringColour );
        return;
    }

    if (selStartY == selEndY)
    {
        // int xx = selStartX*m_charWidth;
        int xx = PosToPixel( lineNum, selStartX );
        // int ww = (selEndX-selStartX)*m_charWidth;
        int ww = PosToPixel( lineNum, selEndX ) - xx;
        dc.DrawRectangle( xx+2, lineNum*m_lineHeight+2, ww, m_lineHeight );

        for (size_t i = (size_t)selStartX; i < (size_t)selEndX; i++)
        {
            selection[i] = line[i];
            line[i] = ' ';
        }
    } else
    if ((lineNum > selStartY) && (lineNum < selEndY))
    {
        dc.DrawRectangle( 0+2, lineNum*m_lineHeight+2, 10000, m_lineHeight );

        for (size_t i = 0; i < line.Len(); i++)
        {
            selection[i] = line[i];
            line[i] = ' ';
        }
    } else
    if (lineNum == selStartY)
    {
        // int xx = selStartX*m_charWidth;
        int xx = PosToPixel( lineNum, selStartX );
        dc.DrawRectangle( xx+2, lineNum*m_lineHeight+2, 10000, m_lineHeight );

        for (size_t i = (size_t)selStartX; i < line.Len(); i++)
        {
            selection[i] = line[i];
            line[i] = ' ';
        }
    } else
    if (lineNum == selEndY)
    {
        // int ww = selEndX*m_charWidth;
        int ww = PosToPixel( lineNum, selEndX );
        dc.DrawRectangle( 0+2, lineNum*m_lineHeight+2, ww, m_lineHeight );

        for (size_t i = 0; i < (size_t)selEndX; i++)
        {
            selection[i] = line[i];
            line[i] = ' ';
        }
    }

    DrawLinePart( dc, x, y, line, line2, *wxBLACK );
    DrawLinePart( dc, x, y, selection, line2, *wxWHITE );
    DrawLinePart( dc, x, y, keyword, line2, m_keywordColour );
    DrawLinePart( dc, x, y, define, line2, m_defineColour );
    DrawLinePart( dc, x, y, variable, line2, m_variableColour );
    DrawLinePart( dc, x, y, comment, line2, m_commentColour );
    DrawLinePart( dc, x, y, my_string, line2, m_stringColour );
}

void wxTextCtrl::OnPaint( wxPaintEvent &event )
{
    wxPaintDC dc(this);

    if (m_lines.GetCount() == 0) return;

    PrepareDC( dc );

    dc.SetFont( m_sourceFont );

    int scroll_y = 0;
    GetViewStart( NULL, &scroll_y );

    // We have a inner border of two pixels
    // around the text, so scroll units do
    // not correspond to lines.
    if (scroll_y > 0) scroll_y--;

    int size_x = 0;
    int size_y = 0;
    GetClientSize( &size_x, &size_y );

    dc.SetPen( *wxTRANSPARENT_PEN );
    dc.SetBrush( wxBrush( wxTHEME_COLOUR(HIGHLIGHT), wxSOLID ) );
    int upper = wxMin( (int)m_lines.GetCount(), scroll_y+(size_y/m_lineHeight)+2 );
    for (int i = scroll_y; i < upper; i++)
    {
        int x = 0+2;
        int y = i*m_lineHeight+2;
        int w = 10000;
        int h = m_lineHeight;
        CalcScrolledPosition( x,y,&x,&y );
        if (IsExposed(x,y,w,h))
            DrawLine( dc, 0+2, i*m_lineHeight+2, m_lines[i].m_text, i );
    }

    if (m_editable && (FindFocus() == this))
    {
        ///dc.SetBrush( *wxRED_BRUSH );
        dc.SetBrush( *wxBLACK_BRUSH );
        // int xx = m_cursorX*m_charWidth;
        int xx = PosToPixel( m_cursorY, m_cursorX );
        dc.DrawRectangle( xx+2, m_cursorY*m_lineHeight+2, 2, m_lineHeight );
    }
}

void wxTextCtrl::OnMouse( wxMouseEvent &event )
{
    if (m_lines.GetCount() == 0) return;


#if 0  // there is no middle button on iPAQs
    if (event.MiddleDown())
    {
        Paste( true );
        return;
    }
#endif

    if (event.LeftDClick())
    {
        DoDClick();
        return;
    }

    if (event.LeftDown())
    {
        m_capturing = true;
        CaptureMouse();
    }

    if (event.LeftUp())
    {
        m_capturing = false;
        ReleaseMouse();
    }

    if (event.LeftDown() ||
        (event.LeftIsDown() && m_capturing))
    {
        int x = event.GetX();
        int y = event.GetY();
        CalcUnscrolledPosition( x, y, &x, &y );
        y /= m_lineHeight;
        // x /= m_charWidth;
        x = PixelToPos( y, x );
        MoveCursor(
            wxMin( 1000, wxMax( 0, x ) ),
            wxMin( (int)m_lines.GetCount()-1, wxMax( 0, y ) ),
            event.ShiftDown() || !event.LeftDown() );
    }
}

void wxTextCtrl::OnChar( wxKeyEvent &event )
{
    if (m_lines.GetCount() == 0) return;

    if (!m_editable) return;

    int size_x = 0;
    int size_y = 0;
    GetClientSize( &size_x, &size_y );
    size_x /= m_charWidth;
    size_y /= m_lineHeight;
    size_y--;

    if (event.ShiftDown())
    {
        switch (event.GetKeyCode())
        {
            case '4': event.m_keyCode = WXK_LEFT;     break;
            case '8': event.m_keyCode = WXK_UP;       break;
            case '6': event.m_keyCode = WXK_RIGHT;    break;
            case '2': event.m_keyCode = WXK_DOWN;     break;
            case '9': event.m_keyCode = WXK_PAGEUP;   break;
            case '3': event.m_keyCode = WXK_PAGEDOWN; break;
            case '7': event.m_keyCode = WXK_HOME;     break;
            case '1': event.m_keyCode = WXK_END;      break;
            case '0': event.m_keyCode = WXK_INSERT;   break;
        }
    }

    switch (event.GetKeyCode())
    {
        case WXK_UP:
        {
            if (m_ignoreInput) return;
            if (m_cursorY > 0)
                MoveCursor( m_cursorX, m_cursorY-1, event.ShiftDown() );
            m_ignoreInput = true;
            return;
        }
        case WXK_DOWN:
        {
            if (m_ignoreInput) return;
            if (m_cursorY < (int)(m_lines.GetCount()-1))
                MoveCursor( m_cursorX, m_cursorY+1, event.ShiftDown() );
            m_ignoreInput = true;
            return;
        }
        case WXK_LEFT:
        {
            if (m_ignoreInput) return;
            if (m_cursorX > 0)
            {
                MoveCursor( m_cursorX-1, m_cursorY, event.ShiftDown() );
            }
            else
            {
                if (m_cursorY > 0)
                    MoveCursor( m_lines[m_cursorY-1].m_text.Len(), m_cursorY-1, event.ShiftDown() );
            }
            m_ignoreInput = true;
            return;
        }
        case WXK_RIGHT:
        {
            if (m_ignoreInput) return;
            if (m_cursorX < 1000)
                MoveCursor( m_cursorX+1, m_cursorY, event.ShiftDown() );
            m_ignoreInput = true;
            return;
        }
        case WXK_HOME:
        {
            if (event.ControlDown())
                MoveCursor( 0, 0, event.ShiftDown() );
            else
                MoveCursor( 0, m_cursorY, event.ShiftDown() );
            return;
        }
        case WXK_END:
        {
            if (event.ControlDown())
                MoveCursor( 0, m_lines.GetCount()-1, event.ShiftDown() );
            else
                MoveCursor( m_lines[m_cursorY].m_text.Len(), m_cursorY, event.ShiftDown() );
            return;
        }
        case WXK_NEXT:
        {
            if (m_ignoreInput) return;
            MoveCursor( m_cursorX, wxMin( (int)(m_lines.GetCount()-1), m_cursorY+size_y ), event.ShiftDown() );
            m_ignoreInput = true;
            return;
        }
        case WXK_PAGEUP:
        {
            if (m_ignoreInput) return;
            MoveCursor( m_cursorX, wxMax( 0, m_cursorY-size_y ), event.ShiftDown() );
            m_ignoreInput = true;
            return;
        }
        case WXK_INSERT:
        {
            if (event.ShiftDown())
                Paste();
            else if (event.ControlDown())
                Copy();
            else
                m_overwrite = !m_overwrite;
            return;
        }
        case WXK_RETURN:
        {
            if (m_windowStyle & wxTE_PROCESS_ENTER)
            {
                wxCommandEvent event(wxEVT_COMMAND_TEXT_ENTER, m_windowId);
                event.SetEventObject(this);
                event.SetString(GetValue());
                if (HandleWindowEvent(event)) return;
            }

            if (IsSingleLine())
            {
                event.Skip();
                return;
            }

            if (HasSelection())
                Delete();
            DoReturn();
            return;
        }
        case WXK_TAB:
        {
            if (HasSelection())
                Delete();
            bool save_overwrite = m_overwrite;
            m_overwrite = false;
            int i = 4-(m_cursorX % 4);
            if (i == 0) i = 4;
            for (int c = 0; c < i; c++)
                 DoChar( ' ' );
            m_overwrite = save_overwrite;
            return;
        }
        case WXK_BACK:
        {
            if (HasSelection())
                Delete();
            else
                DoBack();
            return;
        }
        case WXK_DELETE:
        {
            if (HasSelection())
                Delete();
            else
                DoDelete();
            return;
        }
        default:
        {
            if (  (event.GetKeyCode() >= 'a') &&
                  (event.GetKeyCode() <= 'z') &&
                  (event.AltDown()) )
            {
                // Alt-F etc.
                event.Skip();
                return;
            }

            if (  (event.GetKeyCode() >= 32) &&
                  (event.GetKeyCode() <= 255) &&
                 !(event.ControlDown() && !event.AltDown()) ) // filters out Ctrl-X but leaves Alt-Gr
            {
                if (HasSelection())
                    Delete();
                DoChar( (char) event.GetKeyCode() );
                return;
            }
        }
    }

    event.Skip();
}

void wxTextCtrl::OnInternalIdle()
{
    wxControl::OnInternalIdle();

    m_ignoreInput = false;

    if (m_lang != wxSOURCE_LANG_NONE)
        SearchForBrackets();
}

void wxTextCtrl::Indent()
{
    int startY = m_cursorY;
    int endY = m_cursorY;
    if (HasSelection())
    {
        startY = m_selStartY;
        endY = m_selEndY;
        if (endY < startY)
        {
            int tmp = startY;
            startY = endY;
            endY = tmp;
        }
    }

    m_undos.Append( new wxSourceUndoStep( wxSOURCE_UNDO_LINE, startY, endY, this ) );

    for (int i = startY; i <= endY; i++)
    {
        m_lines[i].m_text.insert( 0u, wxT("    ") );
        RefreshLine( i );
    }
}

void wxTextCtrl::Unindent()
{
    int startY = m_cursorY;
    int endY = m_cursorY;
    if (HasSelection())
    {
        startY = m_selStartY;
        endY = m_selEndY;
        if (endY < startY)
        {
            int tmp = startY;
            startY = endY;
            endY = tmp;
        }
    }

    m_undos.Append( new wxSourceUndoStep( wxSOURCE_UNDO_LINE, startY, endY, this ) );

    for (int i = startY; i <= endY; i++)
    {
        for (int n = 0; n < 4; n++)
        {
            if (m_lines[i].m_text[0u] == wxT(' '))
                m_lines[i].m_text.erase(0u,1u);
        }
        RefreshLine( i );
    }
}
bool wxTextCtrl::HasSelection()
{
    return ((m_selStartY != m_selEndY) || (m_selStartX != m_selEndX));
}

void wxTextCtrl::ClearSelection()
{
    m_selStartX = -1;
    m_selStartY = -1;
    m_selEndX = -1;
    m_selEndY = -1;
}

void wxTextCtrl::RefreshLine( int n )
{
    int y = n*m_lineHeight;
    int x = 0;
    CalcScrolledPosition( x, y, &x, &y );
    wxRect rect( 0+2, y+2, 10000, m_lineHeight );
    Refresh( true, &rect );
}

void wxTextCtrl::RefreshDown( int n )
{
    int size_x = 0;
    int size_y = 0;
    GetClientSize( &size_x, &size_y );

    int view_x = 0;
    int view_y = 0;
    GetViewStart( &view_x, &view_y );

    if (n < view_y)
    {
        Refresh();
    }
    else
    {
        int y = n*m_lineHeight;
        int x = 0;
        CalcScrolledPosition( x, y, &x, &y );

        wxRect rect( 0+2, y+2, 10000, size_y );
        Refresh( true, &rect );
    }
}

void wxTextCtrl::MoveCursor( int new_x, int new_y, bool shift, bool centre )
{
    if (!m_editable) return;

    // if (IsSingleLine() || (m_lang == wxSOURCE_LANG_NONE))
    {
        if (new_x > (int) (m_lines[new_y].m_text.Len()))
            new_x = m_lines[new_y].m_text.Len();
    }

    if ((new_x == m_cursorX) && (new_y == m_cursorY)) return;

    bool no_cursor_refresh = false;
    bool has_selection = HasSelection();

    if (shift)
    {
        int x,y,w,h;
        bool erase_background = true;

        if (!has_selection)
        {
            m_selStartX = m_cursorX;
            m_selStartY = m_cursorY;

            x = 0;
            w = 10000;
            if (new_y > m_selStartY)
            {
                y = m_selStartY*m_lineHeight;
                h = (new_y-m_selStartY+1)*m_lineHeight;
            }
            else if (new_y == m_selStartY)
            {
                x = PosToPixel( new_y, m_selStartX );
                w = PosToPixel( new_y, new_x ) - x;
                if (w < 0)
                {
                    x += w;
                    w = -w + 2; // +2 for the cursor
                }
                y = m_selStartY*m_lineHeight;
                h = m_lineHeight;
            }
            else
            {
                y = new_y*m_lineHeight;
                h = (-new_y+m_selStartY+1)*m_lineHeight;
            }

            no_cursor_refresh = true;
            m_cursorX = new_x;
            m_cursorY = new_y;
        }
        else
        {
            if (new_y == m_selEndY)
            {
                y = new_y *m_lineHeight;
                h = m_lineHeight;
                if (m_selEndX > new_x)
                {
                    // x = new_x*m_charWidth;
                    x = PosToPixel( new_y, new_x );
                    // w = (m_selEndX-new_x)*m_charWidth;
                    w = PosToPixel( new_y, m_selEndX ) - x;
                }
                else
                {
                    // x = m_selEndX*m_charWidth;
                    x = PosToPixel( new_y, m_selEndX );
                    // w = (-m_selEndX+new_x)*m_charWidth;
                    w = PosToPixel( new_y, new_x ) - x;
                }
            }
            else
            {
                x = 0;
                w = 10000;
                if (new_y > m_selEndY)
                {
                    y = m_selEndY*m_lineHeight;
                    h = (new_y-m_selEndY+1) * m_lineHeight;

                    erase_background = ((m_selEndY < m_selStartY) ||
                                        ((m_selEndY == m_selStartY) && (m_selEndX < m_selStartX)));
                }
                else
                {
                    y = new_y*m_lineHeight;
                    h = (-new_y+m_selEndY+1) * m_lineHeight;

                    erase_background = ((m_selEndY > m_selStartY) ||
                                        ((m_selEndY == m_selStartY) && (m_selEndX > m_selStartX)));
                }
                no_cursor_refresh = true;
                m_cursorX = new_x;
                m_cursorY = new_y;
            }
        }

        m_selEndX = new_x;
        m_selEndY = new_y;

        CalcScrolledPosition( x, y, &x, &y );
        wxRect rect( x+2, y+2, w, h );
        Refresh( erase_background, &rect );
    }
    else
    {
        if (has_selection)
        {
            int ry1 = m_selEndY;
            int ry2 = m_selStartY;
            m_selEndX = -1;
            m_selEndY = -1;
            m_selStartX = -1;
            m_selStartY = -1;

            if (ry1 > ry2)
            {
                int tmp = ry2;
                ry2 = ry1;
                ry1 = tmp;
            }

            int x = 0;
            int y = ry1*m_lineHeight;
            CalcScrolledPosition( x, y, &x, &y );
            wxRect rect( 0, y+2, 10000, (ry2-ry1+1)*m_lineHeight );

            Refresh( true, &rect );
        }
    }

/*
    printf( "startx %d starty %d endx %d endy %d\n",
            m_selStartX, m_selStartY, m_selEndX, m_selEndY );

    printf( "has %d\n", (int)HasSelection() );
*/

    if (!no_cursor_refresh)
    {
        // int x = m_cursorX*m_charWidth;
        int x = PosToPixel( m_cursorY, m_cursorX );
        int y = m_cursorY*m_lineHeight;
        CalcScrolledPosition( x, y, &x, &y );
        wxRect rect( x+2, y+2, 4, m_lineHeight+2 );

        m_cursorX = new_x;
        m_cursorY = new_y;

        Refresh( true, &rect );

        if (FindFocus() == this)
        {
            wxClientDC dc(this);
            PrepareDC( dc );
            dc.SetPen( *wxTRANSPARENT_PEN );
            //dc.SetBrush( *wxRED_BRUSH );
            dc.SetBrush( *wxBLACK_BRUSH );
            // int xx = m_cursorX*m_charWidth;
            int xx = PosToPixel( m_cursorY, m_cursorX );
            dc.DrawRectangle( xx+2, m_cursorY*m_lineHeight+2, 2, m_lineHeight );
        }
    }

    int size_x = 0;
    int size_y = 0;
    GetClientSize( &size_x, &size_y );
    size_x /= m_charWidth;
    size_y /= m_lineHeight;

    int view_x = 0;
    int view_y = 0;
    GetViewStart( &view_x, &view_y );

    if (centre)
    {
        int sy = m_cursorY - (size_y/2);
        if (sy < 0) sy = 0;
        Scroll( -1, sy );
    }
    else
    {
        if (m_cursorY < view_y)
            Scroll( -1, m_cursorY );
        else if (m_cursorY > view_y+size_y-1)
            Scroll( -1, m_cursorY-size_y+1 );
    }

    //int xx = m_cursorX;
    int xx = PosToPixel( m_cursorY, m_cursorX ) / m_charWidth;

    if (xx < view_x)
        Scroll( xx, -1 );
    else if (xx > view_x+size_x-1)
        Scroll( xx-size_x+1, -1 );
}

void wxTextCtrl::MyAdjustScrollbars()
{
    if (IsSingleLine())
        return;

    int y_range = m_lines.GetCount();

    int height = 0;
    GetClientSize( NULL, &height );
    height -= 4;
    if (height >= (int)m_lines.GetCount() *m_lineHeight)
        y_range = 0;

    int view_x = 0;
    int view_y = 0;
    GetViewStart( &view_x, &view_y );

    SetScrollbars( m_charWidth, m_lineHeight, m_longestLine+2, y_range, view_x, view_y );
}

//-----------------------------------------------------------------------------
//  clipboard handlers
//-----------------------------------------------------------------------------

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

wxSize wxTextCtrl::DoGetBestSize() const
{
    if (IsSingleLine())
    {
        wxSize ret(80, m_lineHeight + 4);

        if (HasFlag(wxBORDER_SUNKEN) || HasFlag(wxBORDER_RAISED))
            ret.y += 4;

        if (HasFlag(wxBORDER_SIMPLE))
            ret.y += 2;

        return ret;
    }
    else
    {
        return wxSize(80, 60);
    }
}

void wxTextCtrl::OnSetFocus( wxFocusEvent& event )
{
    // To hide or show caret, as appropriate
    Refresh();
}

void wxTextCtrl::OnKillFocus( wxFocusEvent& event )
{
    // To hide or show caret, as appropriate
    Refresh();
}

// ----------------------------------------------------------------------------
// text control scrolling
// ----------------------------------------------------------------------------

bool wxTextCtrl::ScrollLines(int lines)
{
    wxFAIL_MSG( "wxTextCtrl::ScrollLines not implemented");

    return false;
}

bool wxTextCtrl::ScrollPages(int pages)
{
    wxFAIL_MSG( "wxTextCtrl::ScrollPages not implemented");

    return false;
}

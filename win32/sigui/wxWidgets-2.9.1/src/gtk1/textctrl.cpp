/////////////////////////////////////////////////////////////////////////////
// Name:        src/gtk1/textctrl.cpp
// Purpose:
// Author:      Robert Roebling
// Id:          $Id$
// Copyright:   (c) 1998 Robert Roebling, Vadim Zeitlin
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/textctrl.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/intl.h"
    #include "wx/log.h"
    #include "wx/utils.h"
    #include "wx/panel.h"
    #include "wx/settings.h"
    #include "wx/math.h"
#endif

#include "wx/strconv.h"
#include "wx/fontutil.h"        // for wxNativeFontInfo (GetNativeFontInfo())
#include "wx/evtloop.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>

#include "wx/gtk1/private.h"
#include <gdk/gdkkeysyms.h>

//-----------------------------------------------------------------------------
// idle system
//-----------------------------------------------------------------------------

extern void wxapp_install_idle_handler();
extern bool g_isIdle;

//-----------------------------------------------------------------------------
// data
//-----------------------------------------------------------------------------

extern wxCursor   g_globalCursor;
extern wxWindowGTK *g_delayedFocus;

// ----------------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------------

extern "C" {
static void wxGtkTextInsert(GtkWidget *text,
                            const wxTextAttr& attr,
                            const char *txt,
                            size_t len)
{
    wxFont tmpFont;
    GdkFont *font;
    if (attr.HasFont())
    {
        tmpFont = attr.GetFont();

        // FIXME: if this crashes because tmpFont goes out of scope and the GdkFont is
        // deleted, then we need to call gdk_font_ref on font.
        // This is because attr.GetFont() now returns a temporary font since wxTextAttr
        // no longer stores a wxFont object, for efficiency.

        font = tmpFont.GetInternalFont();
    }
    else
        font  = NULL;

    GdkColor *colFg = attr.HasTextColour() ? attr.GetTextColour().GetColor()
                                           : NULL;

    GdkColor *colBg = attr.HasBackgroundColour()
                        ? attr.GetBackgroundColour().GetColor()
                        : NULL;

    gtk_text_insert( GTK_TEXT(text), font, colFg, colBg, txt, len );
}
}

// ----------------------------------------------------------------------------
// "insert_text" for GtkEntry
// ----------------------------------------------------------------------------

extern "C" {
static void
gtk_insert_text_callback(GtkEditable *editable,
                         const gchar *WXUNUSED(new_text),
                         gint WXUNUSED(new_text_length),
                         gint *WXUNUSED(position),
                         wxTextCtrl *win)
{
    if (g_isIdle)
        wxapp_install_idle_handler();

    // we should only be called if we have a max len limit at all
    GtkEntry *entry = GTK_ENTRY (editable);

    wxCHECK_RET( entry->text_max_length, wxT("shouldn't be called") );

    // check that we don't overflow the max length limit
    //
    // FIXME: this doesn't work when we paste a string which is going to be
    //        truncated
    if ( entry->text_length == entry->text_max_length )
    {
        // we don't need to run the base class version at all
        gtk_signal_emit_stop_by_name(GTK_OBJECT(editable), "insert_text");

        // remember that the next changed signal is to be ignored to avoid
        // generating a dummy wxEVT_COMMAND_TEXT_UPDATED event
        win->IgnoreNextTextUpdate();

        // and generate the correct one ourselves
        wxCommandEvent event(wxEVT_COMMAND_TEXT_MAXLEN, win->GetId());
        event.SetEventObject(win);
        event.SetString(win->GetValue());
        win->HandleWindowEvent( event );
    }
}
}

//-----------------------------------------------------------------------------
//  "changed"
//-----------------------------------------------------------------------------

extern "C" {
static void
gtk_text_changed_callback( GtkWidget *WXUNUSED(widget), wxTextCtrl *win )
{
    if ( win->IgnoreTextUpdate() )
        return;

    if (!win->m_hasVMT) return;

    if (g_isIdle)
        wxapp_install_idle_handler();

    win->SetModified();
    win->UpdateFontIfNeeded();

    wxCommandEvent event( wxEVT_COMMAND_TEXT_UPDATED, win->GetId() );
    event.SetEventObject( win );
    win->HandleWindowEvent( event );
}
}

//-----------------------------------------------------------------------------
// "changed" from vertical scrollbar
//-----------------------------------------------------------------------------

extern "C" {
static void
gtk_scrollbar_changed_callback( GtkWidget *WXUNUSED(widget), wxTextCtrl *win )
{
    if (!win->m_hasVMT) return;

    if (g_isIdle)
        wxapp_install_idle_handler();

    win->CalculateScrollbar();
}
}

// ----------------------------------------------------------------------------
// redraw callback for multiline text
// ----------------------------------------------------------------------------

// redrawing a GtkText from inside a wxYield() call results in crashes (the
// text sample shows it in its "Add lines" command which shows wxProgressDialog
// which implicitly calls wxYield()) so we override GtkText::draw() and simply
// don't do anything if we're inside wxYield()

extern "C" {
    typedef void (*GtkDrawCallback)(GtkWidget *widget, GdkRectangle *rect);
}

static GtkDrawCallback gs_gtk_text_draw = NULL;

extern "C" {
static void wxgtk_text_draw( GtkWidget *widget, GdkRectangle *rect)
{
    wxEventLoopBase* loop = wxEventLoopBase::GetActive();
    if ( loop && !loop->IsYielding() )
    {
        wxCHECK_RET( gs_gtk_text_draw != wxgtk_text_draw,
                     wxT("infinite recursion in wxgtk_text_draw aborted") );

        gs_gtk_text_draw(widget, rect);
    }
}
}

//-----------------------------------------------------------------------------
//  wxTextCtrl
//-----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxTextCtrl, wxTextCtrlBase)

BEGIN_EVENT_TABLE(wxTextCtrl, wxTextCtrlBase)
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

void wxTextCtrl::Init()
{
    m_ignoreNextUpdate =
    m_modified = false;
    SetUpdateFont(false);
    m_text =
    m_vScrollbar = NULL;
}

wxTextCtrl::~wxTextCtrl()
{
}

wxTextCtrl::wxTextCtrl( wxWindow *parent,
                        wxWindowID id,
                        const wxString &value,
                        const wxPoint &pos,
                        const wxSize &size,
                        long style,
                        const wxValidator& validator,
                        const wxString &name )
{
    Init();

    Create( parent, id, value, pos, size, style, validator, name );
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
    m_needParent = true;
    m_acceptsFocus = true;

    if (!PreCreation( parent, pos, size ) ||
        !CreateBase( parent, id, pos, size, style, validator, name ))
    {
        wxFAIL_MSG( wxT("wxTextCtrl creation failed") );
        return false;
    }


    m_vScrollbarVisible = false;

    bool multi_line = (style & wxTE_MULTILINE) != 0;

    if (multi_line)
    {
        // create our control ...
        m_text = gtk_text_new( NULL, NULL );

        // ... and put into the upper left hand corner of the table
        bool bHasHScrollbar = false;
        m_widget = gtk_table_new(bHasHScrollbar ? 2 : 1, 2, FALSE);
        GTK_WIDGET_UNSET_FLAGS( m_widget, GTK_CAN_FOCUS );
        gtk_table_attach( GTK_TABLE(m_widget), m_text, 0, 1, 0, 1,
                      (GtkAttachOptions)(GTK_FILL | GTK_EXPAND | GTK_SHRINK),
                      (GtkAttachOptions)(GTK_FILL | GTK_EXPAND | GTK_SHRINK),
                       0, 0);

        // always wrap words
        gtk_text_set_word_wrap( GTK_TEXT(m_text), TRUE );

        // finally, put the vertical scrollbar in the upper right corner
        m_vScrollbar = gtk_vscrollbar_new( GTK_TEXT(m_text)->vadj );
        GTK_WIDGET_UNSET_FLAGS( m_vScrollbar, GTK_CAN_FOCUS );
        gtk_table_attach(GTK_TABLE(m_widget), m_vScrollbar, 1, 2, 0, 1,
                     GTK_FILL,
                     (GtkAttachOptions)(GTK_EXPAND | GTK_FILL | GTK_SHRINK),
                     0, 0);
    }
    else
    {
        // a single-line text control: no need for scrollbars
        m_widget =
        m_text = gtk_entry_new();
    }

    m_parent->DoAddChild( this );

    m_focusWidget = m_text;

    PostCreation(size);

    if (multi_line)
        gtk_widget_show(m_text);

    if (multi_line)
    {
        gtk_signal_connect(GTK_OBJECT(GTK_TEXT(m_text)->vadj), "changed",
          (GtkSignalFunc) gtk_scrollbar_changed_callback, (gpointer) this );

        // only initialize gs_gtk_text_draw once, starting from the next the
        // klass::draw will already be wxgtk_text_draw
        if ( !gs_gtk_text_draw )
        {
            GtkDrawCallback&
                draw = GTK_WIDGET_CLASS(GTK_OBJECT(m_text)->klass)->draw;

            gs_gtk_text_draw = draw;

            draw = wxgtk_text_draw;
        }
    }

    if (!value.empty())
    {
#if !GTK_CHECK_VERSION(1, 2, 0)
        // if we don't realize it, GTK 1.0.6 dies with a SIGSEGV in
        // gtk_editable_insert_text()
        gtk_widget_realize(m_text);
#endif // GTK 1.0

        gint tmp = 0;
#if wxUSE_UNICODE
        wxWX2MBbuf val = value.mbc_str();
        gtk_editable_insert_text( GTK_EDITABLE(m_text), val, strlen(val), &tmp );
#else
        gtk_editable_insert_text( GTK_EDITABLE(m_text), value, value.length(), &tmp );
#endif

        if (multi_line)
        {
            // Bring editable's cursor uptodate. Bug in GTK.
            SET_EDITABLE_POS(m_text, gtk_text_get_point( GTK_TEXT(m_text) ));
        }
    }

    if (style & wxTE_PASSWORD)
    {
        if (!multi_line)
            gtk_entry_set_visibility( GTK_ENTRY(m_text), FALSE );
    }

    if (style & wxTE_READONLY)
    {
        if (!multi_line)
            gtk_entry_set_editable( GTK_ENTRY(m_text), FALSE );
    }
    else
    {
        if (multi_line)
            gtk_text_set_editable( GTK_TEXT(m_text), 1 );
    }

    // We want to be notified about text changes.
    gtk_signal_connect( GTK_OBJECT(m_text), "changed",
        GTK_SIGNAL_FUNC(gtk_text_changed_callback), (gpointer)this);

    m_cursor = wxCursor( wxCURSOR_IBEAM );

    wxTextAttr attrDef(GetForegroundColour(), GetBackgroundColour(), GetFont());
    SetDefaultStyle( attrDef );

    return true;
}


void wxTextCtrl::CalculateScrollbar()
{
    if ((m_windowStyle & wxTE_MULTILINE) == 0) return;

    GtkAdjustment *adj = GTK_TEXT(m_text)->vadj;

    if (adj->upper - adj->page_size < 0.8)
    {
        if (m_vScrollbarVisible)
        {
            gtk_widget_hide( m_vScrollbar );
            m_vScrollbarVisible = false;
        }
    }
    else
    {
        if (!m_vScrollbarVisible)
        {
            gtk_widget_show( m_vScrollbar );
            m_vScrollbarVisible = true;
        }
    }
}

wxString wxTextCtrl::DoGetValue() const
{
    wxCHECK_MSG( m_text != NULL, wxEmptyString, wxT("invalid text ctrl") );

    wxString tmp;
    if (m_windowStyle & wxTE_MULTILINE)
    {
        gint len = gtk_text_get_length( GTK_TEXT(m_text) );
        char *text = gtk_editable_get_chars( GTK_EDITABLE(m_text), 0, len );
        tmp = text;
        g_free( text );
    }
    else
    {
        tmp = wxGTK_CONV_BACK( gtk_entry_get_text( GTK_ENTRY(m_text) ) );
    }

    return tmp;
}

void wxTextCtrl::DoSetValue( const wxString &value, int flags )
{
    wxCHECK_RET( m_text != NULL, wxT("invalid text ctrl") );

    if ( !(flags & SetValue_SendEvent) )
    {
        // do not generate events
        IgnoreNextTextUpdate();
    }

    if (m_windowStyle & wxTE_MULTILINE)
    {
        gint len = gtk_text_get_length( GTK_TEXT(m_text) );
        gtk_editable_delete_text( GTK_EDITABLE(m_text), 0, len );
        len = 0;
        gtk_editable_insert_text( GTK_EDITABLE(m_text), value.mbc_str(), value.length(), &len );
    }
    else
    {
        gtk_entry_set_text( GTK_ENTRY(m_text), wxGTK_CONV( value ) );
    }

    // GRG, Jun/2000: Changed this after a lot of discussion in
    //   the lists. wxWidgets 2.2 will have a set of flags to
    //   customize this behaviour.
    SetInsertionPoint(0);

    m_modified = false;
}

void wxTextCtrl::WriteText( const wxString &text )
{
    wxCHECK_RET( m_text != NULL, wxT("invalid text ctrl") );

    if ( text.empty() )
        return;

    // gtk_text_changed_callback() will set m_modified to true but m_modified
    // shouldn't be changed by the program writing to the text control itself,
    // so save the old value and restore when we're done
    bool oldModified = m_modified;

    if ( m_windowStyle & wxTE_MULTILINE )
    {
        // After cursor movements, gtk_text_get_point() is wrong by one.
        gtk_text_set_point( GTK_TEXT(m_text), GET_EDITABLE_POS(m_text) );

        // always use m_defaultStyle, even if it is empty as otherwise
        // resetting the style and appending some more text wouldn't work: if
        // we don't specify the style explicitly, the old style would be used
        gtk_editable_delete_selection( GTK_EDITABLE(m_text) );
        wxGtkTextInsert(m_text, m_defaultStyle, text.c_str(), text.length());

        // we called wxGtkTextInsert with correct font, no need to do anything
        // in UpdateFontIfNeeded() any longer
        if ( !text.empty() )
        {
            SetUpdateFont(false);
        }

        // Bring editable's cursor back uptodate.
        SET_EDITABLE_POS(m_text, gtk_text_get_point( GTK_TEXT(m_text) ));
    }
    else // single line
    {
        // First remove the selection if there is one
        gtk_editable_delete_selection( GTK_EDITABLE(m_text) );

        // This moves the cursor pos to behind the inserted text.
        gint len = GET_EDITABLE_POS(m_text);

        gtk_editable_insert_text( GTK_EDITABLE(m_text), text.c_str(), text.length(), &len );

        // Bring entry's cursor uptodate.
        gtk_entry_set_position( GTK_ENTRY(m_text), len );
    }

    m_modified = oldModified;
}

void wxTextCtrl::AppendText( const wxString &text )
{
    SetInsertionPointEnd();
    WriteText( text );
}

wxString wxTextCtrl::GetLineText( long lineNo ) const
{
    if (m_windowStyle & wxTE_MULTILINE)
    {
        gint len = gtk_text_get_length( GTK_TEXT(m_text) );
        char *text = gtk_editable_get_chars( GTK_EDITABLE(m_text), 0, len );

        if (text)
        {
            wxString buf;
            long i;
            int currentLine = 0;
            for (i = 0; currentLine != lineNo && text[i]; i++ )
                if (text[i] == '\n')
            currentLine++;
            // Now get the text
            int j;
            for (j = 0; text[i] && text[i] != '\n'; i++, j++ )
                buf += text[i];

            g_free( text );
            return buf;
        }
        else
        {
            return wxEmptyString;
        }
    }
    else
    {
        if (lineNo == 0) return GetValue();
        return wxEmptyString;
    }
}

void wxTextCtrl::OnDropFiles( wxDropFilesEvent &WXUNUSED(event) )
{
  /* If you implement this, don't forget to update the documentation!
   * (file docs/latex/wx/text.tex) */
    wxFAIL_MSG( wxT("wxTextCtrl::OnDropFiles not implemented") );
}

bool wxTextCtrl::PositionToXY(long pos, long *x, long *y ) const
{
    if ( m_windowStyle & wxTE_MULTILINE )
    {
        wxString text = GetValue();

        // cast to prevent warning. But pos really should've been unsigned.
        if( (unsigned long)pos > text.length()  )
            return false;

        *x=0;   // First Col
        *y=0;   // First Line

        const wxChar* stop = text.c_str() + pos;
        for ( const wxChar *p = text.c_str(); p < stop; p++ )
        {
            if (*p == wxT('\n'))
            {
                (*y)++;
                *x=0;
            }
            else
                (*x)++;
        }
    }
    else // single line control
    {
        if ( pos <= GTK_ENTRY(m_text)->text_length )
        {
            *y = 0;
            *x = pos;
        }
        else
        {
            // index out of bounds
            return false;
        }
    }

    return true;
}

long wxTextCtrl::XYToPosition(long x, long y ) const
{
    if (!(m_windowStyle & wxTE_MULTILINE)) return 0;

    long pos=0;
    for( int i=0; i<y; i++ ) pos += GetLineLength(i) + 1; // one for '\n'

    pos += x;
    return pos;
}

int wxTextCtrl::GetLineLength(long lineNo) const
{
    wxString str = GetLineText (lineNo);
    return (int) str.length();
}

int wxTextCtrl::GetNumberOfLines() const
{
    if (m_windowStyle & wxTE_MULTILINE)
    {
        gint len = gtk_text_get_length( GTK_TEXT(m_text) );
        char *text = gtk_editable_get_chars( GTK_EDITABLE(m_text), 0, len );

        if (text)
        {
            int currentLine = 0;
            for (int i = 0; i < len; i++ )
            {
                if (text[i] == '\n')
                    currentLine++;
            }
            g_free( text );

            // currentLine is 0 based, add 1 to get number of lines
            return currentLine + 1;
        }
        else
        {
            return 0;
        }
    }
    else
    {
        return 1;
    }
}

void wxTextCtrl::SetInsertionPoint( long pos )
{
    wxCHECK_RET( m_text != NULL, wxT("invalid text ctrl") );

    if ( IsMultiLine() )
    {
        gtk_signal_disconnect_by_func( GTK_OBJECT(m_text),
          GTK_SIGNAL_FUNC(gtk_text_changed_callback), (gpointer)this);

        /* we fake a set_point by inserting and deleting. as the user
           isn't supposed to get to know about this non-sense, we
           disconnect so that no events are sent to the user program. */

        gint tmp = (gint)pos;
        gtk_editable_insert_text( GTK_EDITABLE(m_text), " ", 1, &tmp );
        gtk_editable_delete_text( GTK_EDITABLE(m_text), tmp-1, tmp );

        gtk_signal_connect( GTK_OBJECT(m_text), "changed",
          GTK_SIGNAL_FUNC(gtk_text_changed_callback), (gpointer)this);

        // bring editable's cursor uptodate. Bug in GTK.
        SET_EDITABLE_POS(m_text, gtk_text_get_point( GTK_TEXT(m_text) ));
    }
    else
    {
        gtk_entry_set_position( GTK_ENTRY(m_text), (int)pos );

        // Bring editable's cursor uptodate. Bug in GTK.
        SET_EDITABLE_POS(m_text, (guint32)pos);
    }
}

void wxTextCtrl::SetInsertionPointEnd()
{
    wxCHECK_RET( m_text != NULL, wxT("invalid text ctrl") );

    if (m_windowStyle & wxTE_MULTILINE)
    {
        SetInsertionPoint(gtk_text_get_length(GTK_TEXT(m_text)));
    }
    else
    {
        gtk_entry_set_position( GTK_ENTRY(m_text), -1 );
    }
}

void wxTextCtrl::SetEditable( bool editable )
{
    wxCHECK_RET( m_text != NULL, wxT("invalid text ctrl") );

    if (m_windowStyle & wxTE_MULTILINE)
    {
        gtk_text_set_editable( GTK_TEXT(m_text), editable );
    }
    else
    {
        gtk_entry_set_editable( GTK_ENTRY(m_text), editable );
    }
}

void wxTextCtrl::DoEnable( bool enable )
{
    if (m_windowStyle & wxTE_MULTILINE)
    {
        gtk_text_set_editable( GTK_TEXT(m_text), enable );
    }
    else
    {
        gtk_widget_set_sensitive( m_text, enable );
    }
}

// wxGTK-specific: called recursively by Enable,
// to give widgets an oppprtunity to correct their colours after they
// have been changed by Enable
void wxTextCtrl::OnEnabled( bool WXUNUSED(enable) )
{
    if ( IsSingleLine() )
        return;

    // If we have a custom background colour, we use this colour in both
    // disabled and enabled mode, or we end up with a different colour under the
    // text.
    wxColour oldColour = GetBackgroundColour();
    if (oldColour.Ok())
    {
        // Need to set twice or it'll optimize the useful stuff out
        if (oldColour == * wxWHITE)
            SetBackgroundColour(*wxBLACK);
        else
            SetBackgroundColour(*wxWHITE);
        SetBackgroundColour(oldColour);
    }
}

void wxTextCtrl::MarkDirty()
{
    m_modified = true;
}

void wxTextCtrl::DiscardEdits()
{
    m_modified = false;
}

// ----------------------------------------------------------------------------
// max text length support
// ----------------------------------------------------------------------------

void wxTextCtrl::IgnoreNextTextUpdate()
{
    m_ignoreNextUpdate = true;
}

bool wxTextCtrl::IgnoreTextUpdate()
{
    if ( m_ignoreNextUpdate )
    {
        m_ignoreNextUpdate = false;

        return true;
    }

    return false;
}

void wxTextCtrl::SetMaxLength(unsigned long len)
{
    if ( !HasFlag(wxTE_MULTILINE) )
    {
        gtk_entry_set_max_length(GTK_ENTRY(m_text), len);

        // there is a bug in GTK+ 1.2.x: "changed" signal is emitted even if
        // we had tried to enter more text than allowed by max text length and
        // the text wasn't really changed
        //
        // to detect this and generate TEXT_MAXLEN event instead of
        // TEXT_CHANGED one in this case we also catch "insert_text" signal
        //
        // when max len is set to 0 we disconnect our handler as it means that
        // we shouldn't check anything any more
        if ( len )
        {
            gtk_signal_connect( GTK_OBJECT(m_text),
                                "insert_text",
                                GTK_SIGNAL_FUNC(gtk_insert_text_callback),
                                (gpointer)this);
        }
        else // no checking
        {
            gtk_signal_disconnect_by_func
            (
                GTK_OBJECT(m_text),
                GTK_SIGNAL_FUNC(gtk_insert_text_callback),
                (gpointer)this
            );
        }
    }
}

void wxTextCtrl::SetSelection( long from, long to )
{
    wxCHECK_RET( m_text != NULL, wxT("invalid text ctrl") );

    if (from == -1 && to == -1)
    {
        from = 0;
        to = GetValue().length();
    }

    if ( (m_windowStyle & wxTE_MULTILINE) &&
         !GTK_TEXT(m_text)->line_start_cache )
    {
        // tell the programmer that it didn't work
        wxLogDebug(wxT("Can't call SetSelection() before realizing the control"));
        return;
    }

    if (m_windowStyle & wxTE_MULTILINE)
    {
        gtk_editable_select_region( GTK_EDITABLE(m_text), (gint)from, (gint)to );
    }
    else
    {
        gtk_editable_select_region( GTK_EDITABLE(m_text), (gint)from, (gint)to );
    }
}

void wxTextCtrl::ShowPosition( long pos )
{
    if (m_windowStyle & wxTE_MULTILINE)
    {
        GtkAdjustment *vp = GTK_TEXT(m_text)->vadj;
        float totalLines =  (float) GetNumberOfLines();
        long posX;
        long posY;
        PositionToXY(pos, &posX, &posY);
        float posLine = (float) posY;
        float p = (posLine/totalLines)*(vp->upper - vp->lower) + vp->lower;
        gtk_adjustment_set_value(GTK_TEXT(m_text)->vadj, p);
    }
}

long wxTextCtrl::GetInsertionPoint() const
{
    wxCHECK_MSG( m_text != NULL, 0, wxT("invalid text ctrl") );
    return (long) GET_EDITABLE_POS(m_text);
}

wxTextPos wxTextCtrl::GetLastPosition() const
{
    wxCHECK_MSG( m_text != NULL, 0, wxT("invalid text ctrl") );

    int pos = 0;

    if (m_windowStyle & wxTE_MULTILINE)
    {
        pos = gtk_text_get_length( GTK_TEXT(m_text) );
    }
    else
    {
        pos = GTK_ENTRY(m_text)->text_length;
    }

    return (long)pos;
}

void wxTextCtrl::Remove( long from, long to )
{
    wxCHECK_RET( m_text != NULL, wxT("invalid text ctrl") );
    gtk_editable_delete_text( GTK_EDITABLE(m_text), (gint)from, (gint)to );
}

void wxTextCtrl::Replace( long from, long to, const wxString &value )
{
    wxCHECK_RET( m_text != NULL, wxT("invalid text ctrl") );

    Remove( from, to );

    if (!value.empty())
    {
        gint pos = (gint)from;
#if wxUSE_UNICODE
        wxWX2MBbuf buf = value.mbc_str();
        gtk_editable_insert_text( GTK_EDITABLE(m_text), buf, strlen(buf), &pos );
#else
        gtk_editable_insert_text( GTK_EDITABLE(m_text), value, value.length(), &pos );
#endif // wxUSE_UNICODE
    }
}

void wxTextCtrl::Cut()
{
    wxCHECK_RET( m_text != NULL, wxT("invalid text ctrl") );
    gtk_editable_cut_clipboard(GTK_EDITABLE(m_text) DUMMY_CLIPBOARD_ARG);
}

void wxTextCtrl::Copy()
{
    wxCHECK_RET( m_text != NULL, wxT("invalid text ctrl") );
    gtk_editable_copy_clipboard(GTK_EDITABLE(m_text) DUMMY_CLIPBOARD_ARG);
}

void wxTextCtrl::Paste()
{
    wxCHECK_RET( m_text != NULL, wxT("invalid text ctrl") );
    gtk_editable_paste_clipboard(GTK_EDITABLE(m_text) DUMMY_CLIPBOARD_ARG);
}

// Undo/redo
void wxTextCtrl::Undo()
{
    // TODO
    wxFAIL_MSG( wxT("wxTextCtrl::Undo not implemented") );
}

void wxTextCtrl::Redo()
{
    // TODO
    wxFAIL_MSG( wxT("wxTextCtrl::Redo not implemented") );
}

bool wxTextCtrl::CanUndo() const
{
    // TODO
    //wxFAIL_MSG( wxT("wxTextCtrl::CanUndo not implemented") );
    return false;
}

bool wxTextCtrl::CanRedo() const
{
    // TODO
    //wxFAIL_MSG( wxT("wxTextCtrl::CanRedo not implemented") );
    return false;
}

// If the return values from and to are the same, there is no
// selection.
void wxTextCtrl::GetSelection(long* fromOut, long* toOut) const
{
    wxCHECK_RET( m_text != NULL, wxT("invalid text ctrl") );

    gint from = -1;
    gint to = -1;
    bool haveSelection = false;

     if ( (GTK_EDITABLE(m_text)->has_selection) )
     {
         haveSelection = true;
         from = (long) GTK_EDITABLE(m_text)->selection_start_pos;
         to = (long) GTK_EDITABLE(m_text)->selection_end_pos;
     }

     if (! haveSelection )
          from = to = GetInsertionPoint();

     if ( from > to )
     {
         // exchange them to be compatible with wxMSW
         gint tmp = from;
         from = to;
         to = tmp;
     }

    if ( fromOut )
        *fromOut = from;
    if ( toOut )
        *toOut = to;
}


bool wxTextCtrl::IsEditable() const
{
    wxCHECK_MSG( m_text != NULL, false, wxT("invalid text ctrl") );
    return GTK_EDITABLE(m_text)->editable;
}

bool wxTextCtrl::IsModified() const
{
    return m_modified;
}

void wxTextCtrl::Clear()
{
    SetValue( wxEmptyString );
}

void wxTextCtrl::OnChar( wxKeyEvent &key_event )
{
    wxCHECK_RET( m_text != NULL, wxT("invalid text ctrl") );

    if ((key_event.GetKeyCode() == WXK_RETURN) && (m_windowStyle & wxTE_PROCESS_ENTER))
    {
        wxCommandEvent event(wxEVT_COMMAND_TEXT_ENTER, m_windowId);
        event.SetEventObject(this);
        event.SetString(GetValue());
        if (HandleWindowEvent(event)) return;
    }

    if ((key_event.GetKeyCode() == WXK_RETURN) && !(m_windowStyle & wxTE_MULTILINE))
    {
        // This will invoke the dialog default action, such
        // as the clicking the default button.

        wxWindow *top_frame = m_parent;
        while (top_frame->GetParent() && !(top_frame->IsTopLevel()))
            top_frame = top_frame->GetParent();

        if (top_frame && GTK_IS_WINDOW(top_frame->m_widget))
        {
            GtkWindow *window = GTK_WINDOW(top_frame->m_widget);

            if (window->default_widget)
            {
                gtk_widget_activate (window->default_widget);
                return;
            }
        }
    }

    key_event.Skip();
}

GtkWidget* wxTextCtrl::GetConnectWidget()
{
    return GTK_WIDGET(m_text);
}

bool wxTextCtrl::IsOwnGtkWindow( GdkWindow *window )
{
    if (m_windowStyle & wxTE_MULTILINE)
    {
        return (window == GTK_TEXT(m_text)->text_area);
    }
    else
    {
        return (window == GTK_ENTRY(m_text)->text_area);
    }
}

// the font will change for subsequent text insertiongs
bool wxTextCtrl::SetFont( const wxFont &font )
{
    wxCHECK_MSG( m_text != NULL, false, wxT("invalid text ctrl") );

    if ( !wxTextCtrlBase::SetFont(font) )
    {
        // font didn't change, nothing to do
        return false;
    }

    if ( m_windowStyle & wxTE_MULTILINE )
    {
        SetUpdateFont(true);

        m_defaultStyle.SetFont(font);

        ChangeFontGlobally();
    }

    return true;
}

void wxTextCtrl::ChangeFontGlobally()
{
    // this method is very inefficient and hence should be called as rarely as
    // possible!
    wxASSERT_MSG( (m_windowStyle & wxTE_MULTILINE) && m_updateFont,

                  wxT("shouldn't be called for single line controls") );

    wxString value = GetValue();
    if ( !value.empty() )
    {
        SetUpdateFont(false);

        Clear();
        AppendText(value);
    }
}

void wxTextCtrl::UpdateFontIfNeeded()
{
    if ( m_updateFont )
        ChangeFontGlobally();
}

bool wxTextCtrl::SetForegroundColour(const wxColour& colour)
{
    if ( !wxControl::SetForegroundColour(colour) )
        return false;

    // update default fg colour too
    m_defaultStyle.SetTextColour(colour);

    return true;
}

bool wxTextCtrl::SetBackgroundColour( const wxColour &colour )
{
    wxCHECK_MSG( m_text != NULL, false, wxT("invalid text ctrl") );

    if ( !wxControl::SetBackgroundColour( colour ) )
        return false;

    if (!m_widget->window)
        return false;

    if (!m_backgroundColour.Ok())
        return false;

    if (m_windowStyle & wxTE_MULTILINE)
    {
        GdkWindow *window = GTK_TEXT(m_text)->text_area;
        if (!window)
            return false;
        m_backgroundColour.CalcPixel( gdk_window_get_colormap( window ) );
        gdk_window_set_background( window, m_backgroundColour.GetColor() );
        gdk_window_clear( window );
    }

    // change active background color too
    m_defaultStyle.SetBackgroundColour( colour );

    return true;
}

bool wxTextCtrl::SetStyle( long start, long end, const wxTextAttr& style )
{
    if ( m_windowStyle & wxTE_MULTILINE )
    {
        if ( style.IsDefault() )
        {
            // nothing to do
            return true;
        }

        // VERY dirty way to do that - removes the required text and re-adds it
        // with styling (FIXME)

        gint l = gtk_text_get_length( GTK_TEXT(m_text) );

        wxCHECK_MSG( start >= 0 && end <= l, false,
                     wxT("invalid range in wxTextCtrl::SetStyle") );

        gint old_pos = gtk_editable_get_position( GTK_EDITABLE(m_text) );
        char *text = gtk_editable_get_chars( GTK_EDITABLE(m_text), start, end );
        wxString tmp(text,*wxConvCurrent);
        g_free( text );

        gtk_editable_delete_text( GTK_EDITABLE(m_text), start, end );
        gtk_editable_set_position( GTK_EDITABLE(m_text), start );

    #if wxUSE_UNICODE
        wxWX2MBbuf buf = tmp.mbc_str();
        const char *txt = buf;
        size_t txtlen = strlen(buf);
    #else
        const char *txt = tmp;
        size_t txtlen = tmp.length();
    #endif

        // use the attributes from style which are set in it and fall back
        // first to the default style and then to the text control default
        // colours for the others
        wxGtkTextInsert(m_text,
                        wxTextAttr::Combine(style, m_defaultStyle, this),
                        txt,
                        txtlen);

        /* does not seem to help under GTK+ 1.2 !!!
        gtk_editable_set_position( GTK_EDITABLE(m_text), old_pos ); */
        SetInsertionPoint( old_pos );

        return true;
    }

    // else single line
    // cannot do this for GTK+'s Entry widget
    return false;
}

void wxTextCtrl::DoApplyWidgetStyle(GtkRcStyle *style)
{
    gtk_widget_modify_style(m_text, style);
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

void wxTextCtrl::OnInternalIdle()
{
    wxCursor cursor = m_cursor;
    if (g_globalCursor.Ok()) cursor = g_globalCursor;

    if (cursor.Ok())
    {
        GdkWindow *window = NULL;
        if (HasFlag(wxTE_MULTILINE))
            window = GTK_TEXT(m_text)->text_area;
        else
            window = GTK_ENTRY(m_text)->text_area;

        if (window)
            gdk_window_set_cursor( window, cursor.GetCursor() );

        if (!g_globalCursor.Ok())
            cursor = *wxSTANDARD_CURSOR;

        window = m_widget->window;
        if ((window) && !(GTK_WIDGET_NO_WINDOW(m_widget)))
            gdk_window_set_cursor( window, cursor.GetCursor() );
    }

    if (g_delayedFocus == this)
    {
        if (GTK_WIDGET_REALIZED(m_widget))
        {
            gtk_widget_grab_focus( m_widget );
            g_delayedFocus = NULL;
        }
    }

    if (wxUpdateUIEvent::CanUpdate(this))
        UpdateWindowUI(wxUPDATE_UI_FROMIDLE);
}

wxSize wxTextCtrl::DoGetBestSize() const
{
    // FIXME should be different for multi-line controls...
    wxSize ret( wxControl::DoGetBestSize() );
    wxSize best(80, ret.y);
    CacheBestSize(best);
    return best;
}

// ----------------------------------------------------------------------------
// freeze/thaw
// ----------------------------------------------------------------------------

void wxTextCtrl::DoFreeze()
{
    if ( HasFlag(wxTE_MULTILINE) )
    {
        gtk_text_freeze(GTK_TEXT(m_text));
    }
}

void wxTextCtrl::DoThaw()
{
    if ( HasFlag(wxTE_MULTILINE) )
    {
        GTK_TEXT(m_text)->vadj->value = 0.0;

        gtk_text_thaw(GTK_TEXT(m_text));
    }
}

// ----------------------------------------------------------------------------
// scrolling
// ----------------------------------------------------------------------------

GtkAdjustment *wxTextCtrl::GetVAdj() const
{
    if ( !IsMultiLine() )
        return NULL;

    return GTK_TEXT(m_text)->vadj;
}

bool wxTextCtrl::DoScroll(GtkAdjustment *adj, int diff)
{
    float value = adj->value + diff;

    if ( value < 0 )
        value = 0;

    float upper = adj->upper - adj->page_size;
    if ( value > upper )
        value = upper;

    // did we noticeably change the scroll position?
    if ( fabs(adj->value - value) < 0.2 )
    {
        // well, this is what Robert does in wxScrollBar, so it must be good...
        return false;
    }

    adj->value = value;
    gtk_signal_emit_by_name(GTK_OBJECT(adj), "value_changed");

    return true;
}

bool wxTextCtrl::ScrollLines(int lines)
{
    GtkAdjustment *adj = GetVAdj();
    if ( !adj )
        return false;

    // this is hardcoded to 10 in GTK+ 1.2 (great idea)
    int diff = 10*lines;

    return DoScroll(adj, diff);
}

bool wxTextCtrl::ScrollPages(int pages)
{
    GtkAdjustment *adj = GetVAdj();
    if ( !adj )
        return false;

    return DoScroll(adj, (int)ceil(pages*adj->page_increment));
}


// static
wxVisualAttributes
wxTextCtrl::GetClassDefaultAttributes(wxWindowVariant WXUNUSED(variant))
{
    return GetDefaultAttributesFromGTKWidget(gtk_entry_new, true);
}

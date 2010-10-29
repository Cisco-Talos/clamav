/////////////////////////////////////////////////////////////////////////////
// Name:        src/gtk1/bmpbuttn.cpp
// Purpose:
// Author:      Robert Roebling
// Id:          $Id$
// Copyright:   (c) 1998 Robert Roebling
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_BMPBUTTON

#include "wx/bmpbuttn.h"

#include "wx/gtk1/private.h"

//-----------------------------------------------------------------------------
// classes
//-----------------------------------------------------------------------------

class wxBitmapButton;

//-----------------------------------------------------------------------------
// idle system
//-----------------------------------------------------------------------------

extern void wxapp_install_idle_handler();
extern bool g_isIdle;

//-----------------------------------------------------------------------------
// data
//-----------------------------------------------------------------------------

extern bool   g_blockEventsOnDrag;

//-----------------------------------------------------------------------------
// "clicked"
//-----------------------------------------------------------------------------

extern "C" {
static void gtk_bmpbutton_clicked_callback( GtkWidget *WXUNUSED(widget), wxBitmapButton *button )
{
    if (g_isIdle)
        wxapp_install_idle_handler();

    if (!button->m_hasVMT) return;
    if (g_blockEventsOnDrag) return;

    wxCommandEvent event(wxEVT_COMMAND_BUTTON_CLICKED, button->GetId());
    event.SetEventObject(button);
    button->HandleWindowEvent(event);
}
}

//-----------------------------------------------------------------------------
// "enter"
//-----------------------------------------------------------------------------

extern "C" {
static void gtk_bmpbutton_enter_callback( GtkWidget *WXUNUSED(widget), wxBitmapButton *button )
{
    if (!button->m_hasVMT) return;
    if (g_blockEventsOnDrag) return;

    button->GTKSetHasFocus();
}
}

//-----------------------------------------------------------------------------
// "leave"
//-----------------------------------------------------------------------------

extern "C" {
static void gtk_bmpbutton_leave_callback( GtkWidget *WXUNUSED(widget), wxBitmapButton *button )
{
    if (!button->m_hasVMT) return;
    if (g_blockEventsOnDrag) return;

    button->GTKSetNotFocus();
}
}

//-----------------------------------------------------------------------------
// "pressed"
//-----------------------------------------------------------------------------

extern "C" {
static void gtk_bmpbutton_press_callback( GtkWidget *WXUNUSED(widget), wxBitmapButton *button )
{
    if (!button->m_hasVMT) return;
    if (g_blockEventsOnDrag) return;

    button->StartSelect();
}
}

//-----------------------------------------------------------------------------
// "released"
//-----------------------------------------------------------------------------

extern "C" {
static void gtk_bmpbutton_release_callback( GtkWidget *WXUNUSED(widget), wxBitmapButton *button )
{
    if (!button->m_hasVMT) return;
    if (g_blockEventsOnDrag) return;

    button->EndSelect();
}
}

//-----------------------------------------------------------------------------
// wxBitmapButton
//-----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxBitmapButton,wxButton)

void wxBitmapButton::Init()
{
    m_hasFocus =
    m_isSelected = false;
}

bool wxBitmapButton::Create( wxWindow *parent,
                             wxWindowID id,
                             const wxBitmap& bitmap,
                             const wxPoint& pos,
                             const wxSize& size,
                             long style,
                             const wxValidator& validator,
                             const wxString &name )
{
    m_needParent = true;
    m_acceptsFocus = true;

    if (!PreCreation( parent, pos, size ) ||
        !CreateBase( parent, id, pos, size, style, validator, name ))
    {
        wxFAIL_MSG( wxT("wxBitmapButton creation failed") );
        return false;
    }

    m_bitmaps[State_Normal] = bitmap;

    m_widget = gtk_button_new();

    if (style & wxNO_BORDER)
       gtk_button_set_relief( GTK_BUTTON(m_widget), GTK_RELIEF_NONE );

    if (bitmap.IsOk())
    {
        OnSetBitmap();
    }

    gtk_signal_connect_after( GTK_OBJECT(m_widget), "clicked",
      GTK_SIGNAL_FUNC(gtk_bmpbutton_clicked_callback), (gpointer*)this );

    gtk_signal_connect( GTK_OBJECT(m_widget), "enter",
      GTK_SIGNAL_FUNC(gtk_bmpbutton_enter_callback), (gpointer*)this );
    gtk_signal_connect( GTK_OBJECT(m_widget), "leave",
      GTK_SIGNAL_FUNC(gtk_bmpbutton_leave_callback), (gpointer*)this );
    gtk_signal_connect( GTK_OBJECT(m_widget), "pressed",
      GTK_SIGNAL_FUNC(gtk_bmpbutton_press_callback), (gpointer*)this );
    gtk_signal_connect( GTK_OBJECT(m_widget), "released",
      GTK_SIGNAL_FUNC(gtk_bmpbutton_release_callback), (gpointer*)this );

    m_parent->DoAddChild( this );

    PostCreation(size);

    return true;
}

void wxBitmapButton::SetLabel( const wxString &label )
{
    wxCHECK_RET( m_widget != NULL, wxT("invalid button") );

    wxControl::SetLabel( label );
}

void wxBitmapButton::DoApplyWidgetStyle(GtkRcStyle *style)
{
    if ( !BUTTON_CHILD(m_widget) )
        return;

    wxButton::DoApplyWidgetStyle(style);
}

void wxBitmapButton::OnSetBitmap()
{
    wxCHECK_RET( m_widget != NULL, wxT("invalid bitmap button") );

    InvalidateBestSize();

    wxBitmap the_one;
    if (!IsThisEnabled())
        the_one = GetBitmapDisabled();
   else if (m_isSelected)
     the_one = GetBitmapPressed();
   else if (HasFocus())
     the_one = GetBitmapFocus();

   if (!the_one.IsOk())
     {
         the_one = GetBitmapLabel();
         if (!the_one.IsOk())
             return;
     }

    GdkBitmap *mask = NULL;
    if (the_one.GetMask()) mask = the_one.GetMask()->GetBitmap();

    GtkWidget *child = BUTTON_CHILD(m_widget);
    if (child == NULL)
    {
        // initial bitmap
        GtkWidget *pixmap;
        pixmap = gtk_pixmap_new(the_one.GetPixmap(), mask);
        gtk_widget_show(pixmap);
        gtk_container_add(GTK_CONTAINER(m_widget), pixmap);
    }
    else
    {   // subsequent bitmaps
        GtkPixmap *pixmap = GTK_PIXMAP(child);
        gtk_pixmap_set(pixmap, the_one.GetPixmap(), mask);
    }
}

wxSize wxBitmapButton::DoGetBestSize() const
{
    return wxControl::DoGetBestSize();
}

bool wxBitmapButton::Enable( bool enable )
{
    if ( !wxWindow::Enable(enable) )
        return false;

    OnSetBitmap();

    return true;
}

void wxBitmapButton::GTKSetHasFocus()
{
    m_hasFocus = true;
    OnSetBitmap();
}

void wxBitmapButton::GTKSetNotFocus()
{
    m_hasFocus = false;
    OnSetBitmap();
}

void wxBitmapButton::StartSelect()
{
    m_isSelected = true;
    OnSetBitmap();
}

void wxBitmapButton::EndSelect()
{
    m_isSelected = false;
    OnSetBitmap();
}

#endif // wxUSE_BMPBUTTON

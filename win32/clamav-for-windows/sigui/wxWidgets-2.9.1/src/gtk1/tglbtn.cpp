/////////////////////////////////////////////////////////////////////////////
// Name:        src/gtk1/tglbtn.cpp
// Purpose:     Definition of the wxToggleButton class, which implements a
//              toggle button under wxGTK.
// Author:      John Norris, minor changes by Axel Schlueter
// Modified by:
// Created:     08.02.01
// RCS-ID:      $Id$
// Copyright:   (c) 2000 Johnny C. Norris II
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_TOGGLEBTN

#include "wx/tglbtn.h"

#ifndef WX_PRECOMP
    #include "wx/button.h"
#endif

#include "wx/gtk1/private.h"

extern void wxapp_install_idle_handler();
extern bool g_isIdle;
extern bool      g_blockEventsOnDrag;
extern wxCursor   g_globalCursor;

extern "C" {
static void gtk_togglebutton_clicked_callback(GtkWidget *WXUNUSED(widget), wxToggleButton *cb)
{
    if (g_isIdle)
        wxapp_install_idle_handler();

    if (!cb->m_hasVMT || g_blockEventsOnDrag)
        return;

    if (cb->m_blockEvent) return;

    // Generate a wx event.
    wxCommandEvent event(wxEVT_COMMAND_TOGGLEBUTTON_CLICKED, cb->GetId());
    event.SetInt(cb->GetValue());
    event.SetEventObject(cb);
    cb->HandleWindowEvent(event);
}
}

wxDEFINE_EVENT( wxEVT_COMMAND_TOGGLEBUTTON_CLICKED, wxCommandEvent );

// ------------------------------------------------------------------------
// wxToggleBitmapButton
// ------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxToggleBitmapButton, wxControl)

bool wxToggleBitmapButton::Create(wxWindow *parent, wxWindowID id,
                            const wxBitmap &label, const wxPoint &pos,
                            const wxSize &size, long style,
                            const wxValidator& validator,
                            const wxString &name)
{
    m_needParent = true;
    m_acceptsFocus = true;

    m_blockEvent = false;

    if (!PreCreation(parent, pos, size) ||
       !CreateBase(parent, id, pos, size, style, validator, name ))
    {
        wxFAIL_MSG(wxT("wxToggleBitmapButton creation failed"));
        return false;
    }

    m_bitmap = label;

    // Create the gtk widget.
    m_widget = gtk_toggle_button_new();

    if (style & wxNO_BORDER)
       gtk_button_set_relief( GTK_BUTTON(m_widget), GTK_RELIEF_NONE );

    if (m_bitmap.Ok())
    {
        OnSetBitmap();
    }

    gtk_signal_connect(GTK_OBJECT(m_widget), "clicked",
                      GTK_SIGNAL_FUNC(gtk_togglebutton_clicked_callback),
                      (gpointer *)this);

    m_parent->DoAddChild(this);

    PostCreation(size);

    return true;
}

// void SetValue(bool state)
// Set the value of the toggle button.
void wxToggleBitmapButton::SetValue(bool state)
{
    wxCHECK_RET(m_widget != NULL, wxT("invalid toggle button"));

    if (state == GetValue())
        return;

    m_blockEvent = true;

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(m_widget), state);

    m_blockEvent = false;
}

// bool GetValue() const
// Get the value of the toggle button.
bool wxToggleBitmapButton::GetValue() const
{
    wxCHECK_MSG(m_widget != NULL, false, wxT("invalid toggle button"));

    return GTK_TOGGLE_BUTTON(m_widget)->active;
}

void wxToggleBitmapButton::SetLabel(const wxBitmap& label)
{
    wxCHECK_RET(m_widget != NULL, wxT("invalid toggle button"));

    m_bitmap = label;
    InvalidateBestSize();

    OnSetBitmap();
}

void wxToggleBitmapButton::OnSetBitmap()
{
    if (!m_bitmap.Ok()) return;

    GdkBitmap *mask = NULL;
    if (m_bitmap.GetMask()) mask = m_bitmap.GetMask()->GetBitmap();

    GtkWidget *child = BUTTON_CHILD(m_widget);
    if (child == NULL)
    {
        // initial bitmap
        GtkWidget *pixmap = gtk_pixmap_new(m_bitmap.GetPixmap(), mask);
        gtk_widget_show(pixmap);
        gtk_container_add(GTK_CONTAINER(m_widget), pixmap);
    }
    else
    {   // subsequent bitmaps
        GtkPixmap *g_pixmap = GTK_PIXMAP(child);
        gtk_pixmap_set(g_pixmap, m_bitmap.GetPixmap(), mask);
    }
}

bool wxToggleBitmapButton::Enable(bool enable /*=true*/)
{
    if (!wxControl::Enable(enable))
        return false;

    gtk_widget_set_sensitive(BUTTON_CHILD(m_widget), enable);

    return true;
}

void wxToggleBitmapButton::DoApplyWidgetStyle(GtkRcStyle *style)
{
    gtk_widget_modify_style(m_widget, style);
    gtk_widget_modify_style(BUTTON_CHILD(m_widget), style);
}

bool wxToggleBitmapButton::IsOwnGtkWindow(GdkWindow *window)
{
    return window == TOGGLE_BUTTON_EVENT_WIN(m_widget);
}

void wxToggleBitmapButton::OnInternalIdle()
{
    wxCursor cursor = m_cursor;

    if (g_globalCursor.Ok())
        cursor = g_globalCursor;

    GdkWindow *win = TOGGLE_BUTTON_EVENT_WIN(m_widget);
    if ( win && cursor.Ok() )
    {
      /* I now set the cursor the anew in every OnInternalIdle call
         as setting the cursor in a parent window also effects the
         windows above so that checking for the current cursor is
         not possible. */

        gdk_window_set_cursor(win, cursor.GetCursor());
    }

    if (wxUpdateUIEvent::CanUpdate(this))
        UpdateWindowUI(wxUPDATE_UI_FROMIDLE);
}


// Get the "best" size for this control.
wxSize wxToggleBitmapButton::DoGetBestSize() const
{
    wxSize best;

    if (m_bitmap.Ok())
    {
        int border = HasFlag(wxNO_BORDER) ? 4 : 10;
        best.x = m_bitmap.GetWidth()+border;
        best.y = m_bitmap.GetHeight()+border;
    }
    CacheBestSize(best);
    return best;
}


// static
wxVisualAttributes
wxToggleBitmapButton::GetClassDefaultAttributes(wxWindowVariant WXUNUSED(variant))
{
    return GetDefaultAttributesFromGTKWidget(gtk_toggle_button_new);
}


// ------------------------------------------------------------------------
// wxToggleButton
// ------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxToggleButton, wxControl)

bool wxToggleButton::Create(wxWindow *parent, wxWindowID id,
                            const wxString &label, const wxPoint &pos,
                            const wxSize &size, long style,
                            const wxValidator& validator,
                            const wxString &name)
{
    m_needParent = true;
    m_acceptsFocus = true;

    m_blockEvent = false;

    if (!PreCreation(parent, pos, size) ||
        !CreateBase(parent, id, pos, size, style, validator, name )) {
        wxFAIL_MSG(wxT("wxToggleButton creation failed"));
        return false;
    }

    wxControl::SetLabel(label);

    // Create the gtk widget.
    m_widget = gtk_toggle_button_new_with_label( wxGTK_CONV( m_label ) );

    gtk_signal_connect(GTK_OBJECT(m_widget), "clicked",
                       GTK_SIGNAL_FUNC(gtk_togglebutton_clicked_callback),
                       (gpointer *)this);

    m_parent->DoAddChild(this);

    PostCreation(size);

    return true;
}

// void SetValue(bool state)
// Set the value of the toggle button.
void wxToggleButton::SetValue(bool state)
{
    wxCHECK_RET(m_widget != NULL, wxT("invalid toggle button"));

    if (state == GetValue())
        return;

    m_blockEvent = true;

    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(m_widget), state);

    m_blockEvent = false;
}

// bool GetValue() const
// Get the value of the toggle button.
bool wxToggleButton::GetValue() const
{
    wxCHECK_MSG(m_widget != NULL, false, wxT("invalid toggle button"));

    return GTK_TOGGLE_BUTTON(m_widget)->active;
}

void wxToggleButton::SetLabel(const wxString& label)
{
    wxCHECK_RET(m_widget != NULL, wxT("invalid toggle button"));

    wxControl::SetLabel(label);

    gtk_label_set(GTK_LABEL(BUTTON_CHILD(m_widget)), wxGTK_CONV( GetLabel() ) );
}

bool wxToggleButton::Enable(bool enable /*=true*/)
{
    if (!wxControl::Enable(enable))
        return false;

    gtk_widget_set_sensitive(BUTTON_CHILD(m_widget), enable);

    return true;
}

void wxToggleButton::DoApplyWidgetStyle(GtkRcStyle *style)
{
    gtk_widget_modify_style(m_widget, style);
    gtk_widget_modify_style(BUTTON_CHILD(m_widget), style);
}

bool wxToggleButton::IsOwnGtkWindow(GdkWindow *window)
{
    return window == TOGGLE_BUTTON_EVENT_WIN(m_widget);
}

void wxToggleButton::OnInternalIdle()
{
    wxCursor cursor = m_cursor;

    if (g_globalCursor.Ok())
        cursor = g_globalCursor;

    GdkWindow *win = TOGGLE_BUTTON_EVENT_WIN(m_widget);
    if ( win && cursor.Ok() )
    {
      /* I now set the cursor the anew in every OnInternalIdle call
         as setting the cursor in a parent window also effects the
         windows above so that checking for the current cursor is
         not possible. */

        gdk_window_set_cursor(win, cursor.GetCursor());
    }

    if (wxUpdateUIEvent::CanUpdate(this))
        UpdateWindowUI(wxUPDATE_UI_FROMIDLE);
}


// Get the "best" size for this control.
wxSize wxToggleButton::DoGetBestSize() const
{
    wxSize ret(wxControl::DoGetBestSize());

    if (!HasFlag(wxBU_EXACTFIT))
    {
        if (ret.x < 80) ret.x = 80;
    }

    CacheBestSize(ret);
    return ret;
}

// static
wxVisualAttributes
wxToggleButton::GetClassDefaultAttributes(wxWindowVariant WXUNUSED(variant))
{
    return GetDefaultAttributesFromGTKWidget(gtk_toggle_button_new);
}

#endif // wxUSE_TOGGLEBTN

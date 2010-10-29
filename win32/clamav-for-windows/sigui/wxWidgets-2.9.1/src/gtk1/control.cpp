/////////////////////////////////////////////////////////////////////////////
// Name:        src/gtk1/control.cpp
// Purpose:     wxControl implementation for wxGTK
// Author:      Robert Roebling
// Id:          $Id$
// Copyright:   (c) 1998 Robert Roebling, Julian Smart and Vadim Zeitlin
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_CONTROLS

#include "wx/control.h"

#ifndef WX_PRECOMP
    #include "wx/log.h"
    #include "wx/settings.h"
#endif

#include "wx/fontutil.h"
#include "wx/gtk1/private.h"

// ============================================================================
// wxControl implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxControl creation
// ----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxControl, wxWindow)

wxControl::wxControl()
{
    m_needParent = true;
}

bool wxControl::Create( wxWindow *parent,
                      wxWindowID id,
                      const wxPoint &pos,
                      const wxSize &size,
                      long style,
                      const wxValidator& validator,
                      const wxString &name )
{
    bool ret = wxWindow::Create(parent, id, pos, size, style, name);

#if wxUSE_VALIDATORS
    SetValidator(validator);
#endif

    return ret;
}

wxSize wxControl::DoGetBestSize() const
{
    // Do not return any arbitrary default value...
    wxASSERT_MSG( m_widget, wxT("DoGetBestSize called before creation") );

    GtkRequisition req;
    req.width = 2;
    req.height = 2;
    (* GTK_WIDGET_CLASS( GTK_OBJECT_GET_CLASS(m_widget) )->size_request )
        (m_widget, &req );

    wxSize best(req.width, req.height);
    CacheBestSize(best);
    return best;
}


void wxControl::PostCreation(const wxSize& size)
{
    wxWindow::PostCreation();

    // NB: GetBestSize needs to know the style, otherwise it will assume
    //     default font and if the user uses a different font, determined
    //     best size will be different (typically, smaller) than the desired
    //     size. This call ensure that a style is available at the time
    //     GetBestSize is called.
    gtk_widget_ensure_style(m_widget);

    ApplyWidgetStyle();
    SetInitialSize(size);
}

// ----------------------------------------------------------------------------
// wxControl dealing with labels
// ----------------------------------------------------------------------------

void wxControl::SetLabel( const wxString &label )
{
    // keep the original string internally to be able to return it later (for
    // consistency with the other ports)
    m_label = label;

    InvalidateBestSize();
}

wxString wxControl::GetLabel() const
{
    return m_label;
}

void wxControl::GTKSetLabelForLabel(GtkLabel *w, const wxString& label)
{
    // don't call the virtual function which might call this one back again
    wxControl::SetLabel(label);

    const wxString labelGTK = GTKRemoveMnemonics(label);

    gtk_label_set(w, wxGTK_CONV(labelGTK));
}

void wxControl::GTKSetLabelForFrame(GtkFrame *w, const wxString& label)
{
    wxControl::SetLabel(label);

    const wxString labelGTK = GTKRemoveMnemonics(label);

    gtk_frame_set_label(w, labelGTK.empty() ? (const char *)NULL
                                            : wxGTK_CONV(labelGTK));
}

/* static */
wxString wxControl::GTKRemoveMnemonics(const wxString& label)
{
    const size_t len = label.length();
    wxString labelGTK;
    labelGTK.reserve(len);
    for ( size_t i = 0; i < len; i++ )
    {
        wxChar ch = label[i];

        if ( ch == wxT('&') )
        {
            if ( i == len - 1 )
            {
                // "&" at the end of string is an error
                wxLogDebug(wxT("Invalid label \"%s\"."), label.c_str());
                break;
            }

            ch = label[++i]; // skip '&' itself
            if ( ch == wxT('&') )
            {
                // special case: "&&" is not a mnemonic at all but just an
                // escaped "&"
                labelGTK += wxT('&');
                continue;
            }
        }

        labelGTK += ch;
    }

    return labelGTK;
}

// ----------------------------------------------------------------------------
// wxControl styles (a.k.a. attributes)
// ----------------------------------------------------------------------------

wxVisualAttributes wxControl::GetDefaultAttributes() const
{
    return GetDefaultAttributesFromGTKWidget(m_widget,
                                             UseGTKStyleBase());
}


#define SHIFT (8*(sizeof(short int)-sizeof(char)))

// static
wxVisualAttributes
wxControl::GetDefaultAttributesFromGTKWidget(GtkWidget* widget,
                                             bool useBase,
                                             int state)
{
    GtkStyle* style;
    wxVisualAttributes attr;

    style = gtk_rc_get_style(widget);
    if (!style)
        style = gtk_widget_get_default_style();

    if (!style)
    {
        return wxWindow::GetClassDefaultAttributes(wxWINDOW_VARIANT_NORMAL);
    }

    if (state == -1)
        state = GTK_STATE_NORMAL;

    // get the style's colours
    attr.colFg = wxColour(style->fg[state].red   >> SHIFT,
                          style->fg[state].green >> SHIFT,
                          style->fg[state].blue  >> SHIFT);
    if (useBase)
        attr.colBg = wxColour(style->base[state].red   >> SHIFT,
                              style->base[state].green >> SHIFT,
                              style->base[state].blue  >> SHIFT);
    else
        attr.colBg = wxColour(style->bg[state].red   >> SHIFT,
                              style->bg[state].green >> SHIFT,
                              style->bg[state].blue  >> SHIFT);

    // get the style's font
    // TODO: isn't there a way to get a standard gtk 1.2 font?
    attr.font = wxFont( 12, wxSWISS, wxNORMAL, wxNORMAL );

    return attr;
}


//static
wxVisualAttributes
wxControl::GetDefaultAttributesFromGTKWidget(wxGtkWidgetNew_t widget_new,
                                             bool useBase,
                                             int state)
{
    wxVisualAttributes attr;
    // NB: we need toplevel window so that GTK+ can find the right style
    GtkWidget *wnd = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    GtkWidget* widget = widget_new();
    gtk_container_add(GTK_CONTAINER(wnd), widget);
    attr = GetDefaultAttributesFromGTKWidget(widget, useBase, state);
    gtk_widget_destroy(wnd);
    return attr;
}

//static
wxVisualAttributes
wxControl::GetDefaultAttributesFromGTKWidget(wxGtkWidgetNewFromStr_t widget_new,
                                             bool useBase,
                                             int state)
{
    wxVisualAttributes attr;
    // NB: we need toplevel window so that GTK+ can find the right style
    GtkWidget *wnd = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    GtkWidget* widget = widget_new("");
    gtk_container_add(GTK_CONTAINER(wnd), widget);
    attr = GetDefaultAttributesFromGTKWidget(widget, useBase, state);
    gtk_widget_destroy(wnd);
    return attr;
}


//static
wxVisualAttributes
wxControl::GetDefaultAttributesFromGTKWidget(wxGtkWidgetNewFromAdj_t widget_new,
                                             bool useBase,
                                             int state)
{
    wxVisualAttributes attr;
    // NB: we need toplevel window so that GTK+ can find the right style
    GtkWidget *wnd = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    GtkWidget* widget = widget_new(NULL);
    gtk_container_add(GTK_CONTAINER(wnd), widget);
    attr = GetDefaultAttributesFromGTKWidget(widget, useBase, state);
    gtk_widget_destroy(wnd);
    return attr;
}

#endif // wxUSE_CONTROLS

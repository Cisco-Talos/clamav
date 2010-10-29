/////////////////////////////////////////////////////////////////////////////
// Name:        stattext.cpp
// Purpose:
// Author:      Robert Roebling
// Id:          $Id$
// Copyright:   (c) 1998 Robert Roebling
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_STATTEXT

#include "wx/stattext.h"
#include "wx/gtk1/private.h"

#include "gdk/gdk.h"
#include "gtk/gtk.h"

extern "C"
void wxgtk_window_size_request_callback(GtkWidget *widget,
                                        GtkRequisition *requisition,
                                        wxWindow *win);

//-----------------------------------------------------------------------------
// wxStaticText
//-----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxStaticText,wxControl)

wxStaticText::wxStaticText()
{
}

wxStaticText::wxStaticText(wxWindow *parent,
                           wxWindowID id,
                           const wxString &label,
                           const wxPoint &pos,
                           const wxSize &size,
                           long style,
                           const wxString &name)
{
  Create( parent, id, label, pos, size, style, name );
}

bool wxStaticText::Create(wxWindow *parent,
                          wxWindowID id,
                          const wxString &label,
                          const wxPoint &pos,
                          const wxSize &size,
                          long style,
                          const wxString &name )
{
    m_needParent = TRUE;

    if (!PreCreation( parent, pos, size ) ||
        !CreateBase( parent, id, pos, size, style, wxDefaultValidator, name ))
    {
        wxFAIL_MSG( wxT("wxStaticText creation failed") );
        return FALSE;
    }

    m_label = label;
    m_widget = gtk_label_new( wxGTK_CONV( GTKRemoveMnemonics(label)) );

    GtkJustification justify;
    if ( style & wxALIGN_CENTER )
      justify = GTK_JUSTIFY_CENTER;
    else if ( style & wxALIGN_RIGHT )
      justify = GTK_JUSTIFY_RIGHT;
    else // wxALIGN_LEFT is 0
      justify = GTK_JUSTIFY_LEFT;
    gtk_label_set_justify(GTK_LABEL(m_widget), justify);

    // GTK_JUSTIFY_LEFT is 0, RIGHT 1 and CENTER 2
    static const float labelAlignments[] = { 0.0, 1.0, 0.5 };
    gtk_misc_set_alignment(GTK_MISC(m_widget), labelAlignments[justify], 0.0);

        gtk_label_set_line_wrap( GTK_LABEL(m_widget), TRUE );

    m_parent->DoAddChild( this );

    PostCreation(size);

    return TRUE;
}

wxString wxStaticText::GetLabel() const
{
    GtkLabel *label = GTK_LABEL(m_widget);
    wxString str = wxString( label->label );
    return wxString(str);
}

void wxStaticText::SetLabel( const wxString &label )
{
    wxCHECK_RET( m_widget != NULL, wxT("invalid static text") );

    GTKSetLabelForLabel(GTK_LABEL(m_widget), label);

    // adjust the label size to the new label unless disabled
    if (!HasFlag(wxST_NO_AUTORESIZE))
        SetSize( GetBestSize() );
}

bool wxStaticText::SetFont( const wxFont &font )
{
    bool ret = wxControl::SetFont(font);

    // adjust the label size to the new label unless disabled
    if (!HasFlag(wxST_NO_AUTORESIZE))
    {
        InvalidateBestSize();
        SetSize( GetBestSize() );
    }
    return ret;
}

void wxStaticText::DoSetSize(int x, int y,
                           int width, int height,
                           int sizeFlags )
{
    wxControl::DoSetSize( x, y, width, height, sizeFlags );
}

wxSize wxStaticText::DoGetBestSize() const
{
    // Do not return any arbitrary default value...
    wxASSERT_MSG( m_widget, wxT("wxStaticText::DoGetBestSize called before creation") );

    // This resets the internal GTK1 size calculation, which
    // otherwise would be cashed (incorrectly)
    gtk_label_set_pattern( GTK_LABEL(m_widget), NULL );

    // GetBestSize is supposed to return unwrapped size
    gtk_label_set_line_wrap( GTK_LABEL(m_widget), FALSE );

    GtkRequisition req;
    req.width = -1;
    req.height = -1;
    (* GTK_WIDGET_CLASS( GTK_OBJECT_GET_CLASS(m_widget) )->size_request )
        (m_widget, &req );

    gtk_label_set_line_wrap( GTK_LABEL(m_widget), TRUE );

    return wxSize (req.width, req.height);
}

bool wxStaticText::SetForegroundColour(const wxColour& colour)
{
    // First, we call the base class member
    wxControl::SetForegroundColour(colour);
    // Then, to force the color change, we set the label with the current label
    SetLabel(GetLabel());
    return true;
}

// static
wxVisualAttributes
wxStaticText::GetClassDefaultAttributes(wxWindowVariant WXUNUSED(variant))
{
    return GetDefaultAttributesFromGTKWidget(gtk_label_new);
}

#endif // wxUSE_STATTEXT

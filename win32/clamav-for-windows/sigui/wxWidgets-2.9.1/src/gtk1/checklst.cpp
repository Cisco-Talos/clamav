/////////////////////////////////////////////////////////////////////////////
// Name:        src/gtk1/checklst.cpp
// Purpose:
// Author:      Robert Roebling
// Id:          $Id$
// Copyright:   (c) 1998 Robert Roebling
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#if wxUSE_CHECKLISTBOX

#include "wx/checklst.h"
#include "wx/gtk1/private.h"

#include <gdk/gdk.h>
#include <gtk/gtk.h>

//-----------------------------------------------------------------------------
// wxCheckListBox
//-----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxCheckListBox,wxListBox)

wxCheckListBox::wxCheckListBox() : wxListBox()
{
    m_hasCheckBoxes = true;
}

wxCheckListBox::wxCheckListBox(wxWindow *parent, wxWindowID id,
                               const wxPoint& pos,
                               const wxSize& size,
                               int nStrings,
                               const wxString *choices,
                               long style,
                               const wxValidator& validator,
                               const wxString& name )
{
    m_hasCheckBoxes = true;
    wxListBox::Create( parent, id, pos, size, nStrings, choices, style, validator, name );
}

wxCheckListBox::wxCheckListBox(wxWindow *parent, wxWindowID id,
                               const wxPoint& pos,
                               const wxSize& size,
                               const wxArrayString& choices,
                               long style,
                               const wxValidator& validator,
                               const wxString& name )
{
    m_hasCheckBoxes = true;
    wxListBox::Create( parent, id, pos, size, choices,
                       style, validator, name );
}

bool wxCheckListBox::IsChecked(unsigned int index) const
{
    wxCHECK_MSG( m_list != NULL, false, wxT("invalid checklistbox") );

    GList *child = g_list_nth( m_list->children, index );
    if (child)
    {
        GtkBin *bin = GTK_BIN( child->data );
        GtkLabel *label = GTK_LABEL( bin->child );

        wxString str( wxGTK_CONV_BACK( label->label ) );

        return str.GetChar(1) == wxCHECKLBOX_CHECKED;
    }

    wxFAIL_MSG(wxT("wrong checklistbox index"));
    return false;
}

void wxCheckListBox::Check(unsigned int index, bool check )
{
    wxCHECK_RET( m_list != NULL, wxT("invalid checklistbox") );

    GList *child = g_list_nth( m_list->children, index );
    if (child)
    {
        GtkBin *bin = GTK_BIN( child->data );
        GtkLabel *label = GTK_LABEL( bin->child );

        wxString str( wxGTK_CONV_BACK( label->label ) );

        if (check == (str.GetChar(1) == wxCHECKLBOX_CHECKED))
            return;

        str.SetChar( 1, check ? wxCHECKLBOX_CHECKED : wxCHECKLBOX_UNCHECKED );

        gtk_label_set( label, wxGTK_CONV( str ) );

        return;
    }

    wxFAIL_MSG(wxT("wrong checklistbox index"));
}

int wxCheckListBox::GetItemHeight() const
{
    // FIXME
    return 22;
}

#endif

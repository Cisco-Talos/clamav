/////////////////////////////////////////////////////////////////////////////
// Name:        custom_combo.h
// Purpose:     Define some custom wxComboCtrls
// Author:      Utensil Candel (UtensilCandel@@gmail.com)
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef WX_CUSTOM_COMBO_H
#define WX_CUSTOM_COMBO_H

// ----------------------------------------------------------------------------
// class PenStyleComboBox
// This class is a modified version of the one from samples/combo.cpp
// ----------------------------------------------------------------------------

#include <wx/odcombo.h>

class PenStyleComboBox : public wxOwnerDrawnComboBox
{
public:
    virtual void OnDrawItem( wxDC& dc,
                             const wxRect& rect,
                             int item,
                             int flags ) const;


    virtual void OnDrawBackground( wxDC& dc, const wxRect& rect,
                                   int item, int flags ) const;

    virtual wxCoord OnMeasureItem( size_t item ) const;

    virtual wxCoord OnMeasureItemWidth( size_t WXUNUSED(item) ) const;

    static PenStyleComboBox* CreateSample(wxWindow* parent);
};


// ----------------------------------------------------------------------------
// wxListView Custom popup interface
// This class is a modified version of the one from samples/combo.cpp
// ----------------------------------------------------------------------------

#include <wx/listctrl.h>

class ListViewComboPopup : public wxListView, public wxComboPopup
{
public:

    virtual void Init()
    {
        m_value = -1;
        m_itemHere = -1; // hot item in list
    }

    virtual bool Create( wxWindow* parent )
    {
        return wxListView::Create(parent,1,
                                  wxPoint(0,0),wxDefaultSize,
                                  wxLC_LIST|wxLC_VRULES|wxBORDER_THEME);
    }

    virtual wxWindow *GetControl()
        { return this; }

    virtual void SetStringValue( const wxString& s )
    {
        int n = wxListView::FindItem(-1,s);
        if ( n >= 0 && n < GetItemCount() )
            wxListView::Select(n);
    }

    virtual wxString GetStringValue() const
    {
        if ( m_value >= 0 )
            return wxListView::GetItemText(m_value);
        return wxEmptyString;
    }

    //
    // Popup event handlers
    //

    // Mouse hot-tracking
    void OnMouseMove(wxMouseEvent& event)
    {
        // Move selection to cursor if it is inside the popup

        int resFlags;
        int itemHere = HitTest(event.GetPosition(),resFlags);
        if ( itemHere >= 0 )
        {
            wxListView::Select(itemHere,true);
            m_itemHere = itemHere;
        }
        event.Skip();
    }

    // On mouse left, set the value and close the popup
    void OnMouseClick(wxMouseEvent& WXUNUSED(event))
    {
        m_value = m_itemHere;
        // TODO: Send event
        Dismiss();
    }

    //
    // Utilies for item manipulation
    //

    void AddSelection( const wxString& selstr )
    {
        wxListView::InsertItem(GetItemCount(),selstr);
    }

protected:
    int             m_value;        // current item index
    int             m_itemHere;     // hot item in popup

private:
    DECLARE_EVENT_TABLE()
};


// ----------------------------------------------------------------------------
// wxTreeCtrl Custom popup interface
// This class is a modified version of the one from samples/combo.cpp
// ----------------------------------------------------------------------------

#include <wx/treectrl.h>

class TreeCtrlComboPopup : public wxTreeCtrl, public wxComboPopup
{
public:

    virtual void Init()
    {
    }

    virtual bool Create( wxWindow* parent )
    {
        return wxTreeCtrl::Create(parent,1,
                                  wxPoint(0,0),wxDefaultSize,
                                  wxTR_HAS_BUTTONS|wxTR_SINGLE|
                                  wxTR_LINES_AT_ROOT|wxBORDER_THEME);
    }

    virtual void OnShow()
    {
        // make sure selected item is visible
        if ( m_value.IsOk() )
            EnsureVisible(m_value);
    }

    virtual wxSize GetAdjustedSize( int minWidth,
                                    int WXUNUSED(prefHeight),
                                    int maxHeight )
    {
        return wxSize(minWidth, wxMin(80, maxHeight));
    }

    virtual wxWindow *GetControl()
        { return this; }

    // Needed by SetStringValue
    wxTreeItemId FindItemByText( wxTreeItemId parent, const wxString& text )
    {
        wxTreeItemIdValue cookie;
        wxTreeItemId child = GetFirstChild(parent,cookie);
        while ( child.IsOk() )
        {
            if ( GetItemText(child) == text )
            {
                return child;
            }
            if ( ItemHasChildren(child) )
            {
                wxTreeItemId found = FindItemByText(child,text);
                if ( found.IsOk() )
                    return found;
            }
            child = GetNextChild(parent,cookie);
        }
        return wxTreeItemId();
    }

    virtual void SetStringValue( const wxString& s )
    {
        wxTreeItemId root = GetRootItem();
        if ( !root.IsOk() )
            return;

        wxTreeItemId found = FindItemByText(root,s);
        if ( found.IsOk() )
        {
            m_value = m_itemHere = found;
            wxTreeCtrl::SelectItem(found);
        }
    }

    virtual wxString GetStringValue() const
    {
        if ( m_value.IsOk() )
            return wxTreeCtrl::GetItemText(m_value);
        return wxEmptyString;
    }

    //
    // Popup event handlers
    //

    // Mouse hot-tracking
    void OnMouseMove(wxMouseEvent& event)
    {
        int resFlags;
        wxTreeItemId itemHere = HitTest(event.GetPosition(),resFlags);
        if ( itemHere.IsOk() && (resFlags & wxTREE_HITTEST_ONITEMLABEL) )
        {
            wxTreeCtrl::SelectItem(itemHere,true);
            m_itemHere = itemHere;
        }
        event.Skip();
    }

    // On mouse left, set the value and close the popup
    void OnMouseClick(wxMouseEvent& event)
    {
        int resFlags;
        wxTreeItemId itemHere = HitTest(event.GetPosition(),resFlags);
        if ( itemHere.IsOk() && (resFlags & wxTREE_HITTEST_ONITEMLABEL) )
        {
            m_itemHere = itemHere;
            m_value = itemHere;
            Dismiss();
            // TODO: Send event
        }
        event.Skip();
    }

protected:
    wxTreeItemId        m_value;        // current item index
    wxTreeItemId        m_itemHere;     // hot item in popup

private:
    DECLARE_EVENT_TABLE()
};


#endif // WX_CUSTOM_COMBO_H

/////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/listbox.h
// Purpose:     wxListBox class
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_LISTBOX_H_
#define _WX_LISTBOX_H_

#if wxUSE_LISTBOX

// ----------------------------------------------------------------------------
// simple types
// ----------------------------------------------------------------------------

#if wxUSE_OWNER_DRAWN
  class WXDLLIMPEXP_FWD_CORE wxOwnerDrawn;

  // define the array of list box items
  #include  "wx/dynarray.h"

  WX_DEFINE_EXPORTED_ARRAY_PTR(wxOwnerDrawn *, wxListBoxItemsArray);
#endif // wxUSE_OWNER_DRAWN

// forward decl for GetSelections()
class wxArrayInt;

// ----------------------------------------------------------------------------
// List box control
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_CORE wxListBox : public wxListBoxBase
{
public:
    // ctors and such
    wxListBox();
    wxListBox(wxWindow *parent, wxWindowID id,
            const wxPoint& pos = wxDefaultPosition,
            const wxSize& size = wxDefaultSize,
            int n = 0, const wxString choices[] = NULL,
            long style = 0,
            const wxValidator& validator = wxDefaultValidator,
            const wxString& name = wxListBoxNameStr)
    {
        Create(parent, id, pos, size, n, choices, style, validator, name);
    }
    wxListBox(wxWindow *parent, wxWindowID id,
            const wxPoint& pos,
            const wxSize& size,
            const wxArrayString& choices,
            long style = 0,
            const wxValidator& validator = wxDefaultValidator,
            const wxString& name = wxListBoxNameStr)
    {
        Create(parent, id, pos, size, choices, style, validator, name);
    }

    bool Create(wxWindow *parent, wxWindowID id,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                int n = 0, const wxString choices[] = NULL,
                long style = 0,
                const wxValidator& validator = wxDefaultValidator,
                const wxString& name = wxListBoxNameStr);
    bool Create(wxWindow *parent, wxWindowID id,
                const wxPoint& pos,
                const wxSize& size,
                const wxArrayString& choices,
                long style = 0,
                const wxValidator& validator = wxDefaultValidator,
                const wxString& name = wxListBoxNameStr);

    virtual ~wxListBox();

    // implement base class pure virtuals
    virtual void DoClear();
    virtual void DoDeleteOneItem(unsigned int n);

    virtual unsigned int GetCount() const;
    virtual wxString GetString(unsigned int n) const;
    virtual void SetString(unsigned int n, const wxString& s);

    virtual bool IsSelected(int n) const;
    virtual void DoSetSelection(int n, bool select);
    virtual int GetSelection() const;
    virtual int GetSelections(wxArrayInt& aSelections) const;

    virtual int DoInsertItems(const wxArrayStringsAdapter& items,
                              unsigned int pos,
                              void **clientData, wxClientDataType type);

    virtual void DoSetFirstItem(int n);

    virtual void DoSetItemClientData(unsigned int n, void* clientData);
    virtual void* DoGetItemClientData(unsigned int n) const;

    // wxCheckListBox support
#if wxUSE_OWNER_DRAWN
    bool MSWOnMeasure(WXMEASUREITEMSTRUCT *item);
    bool MSWOnDraw(WXDRAWITEMSTRUCT *item);

    // plug-in for derived classes
    virtual wxOwnerDrawn *CreateLboxItem(size_t n);

    // allows to get the item and use SetXXX functions to set it's appearance
    wxOwnerDrawn *GetItem(size_t n) const { return m_aItems[n]; }

    // get the index of the given item
    int GetItemIndex(wxOwnerDrawn *item) const { return m_aItems.Index(item); }
#endif // wxUSE_OWNER_DRAWN

    // Windows-specific code to set the horizontal extent of the listbox, if
    // necessary. If s is non-NULL, it's used to calculate the horizontal
    // extent. Otherwise, all strings are used.
    virtual void SetHorizontalExtent(const wxString& s = wxEmptyString);

    // Windows callbacks
    bool MSWCommand(WXUINT param, WXWORD id);

    virtual wxVisualAttributes GetDefaultAttributes() const
    {
        return GetClassDefaultAttributes(GetWindowVariant());
    }

    static wxVisualAttributes
    GetClassDefaultAttributes(wxWindowVariant variant = wxWINDOW_VARIANT_NORMAL)
    {
        return GetCompositeControlsDefaultAttributes(variant);
    }

protected:
    WXDWORD MSWGetStyle(long style, WXDWORD *exstyle) const;

    // free memory (common part of Clear() and dtor)
    void Free();

    int m_selected;

    virtual wxSize DoGetBestSize() const;

#if wxUSE_OWNER_DRAWN
    // control items
    wxListBoxItemsArray m_aItems;
#endif

private:
    DECLARE_DYNAMIC_CLASS_NO_COPY(wxListBox)
};

#endif // wxUSE_LISTBOX

#endif
    // _WX_LISTBOX_H_

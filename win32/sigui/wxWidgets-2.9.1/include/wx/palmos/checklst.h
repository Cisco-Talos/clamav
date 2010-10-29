///////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/checklst.h
// Purpose:     wxCheckListBox class - a listbox with checkable items
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

#ifndef   __CHECKLST__H_
#define   __CHECKLST__H_

#if !wxUSE_OWNER_DRAWN
  #error  "wxCheckListBox class requires owner-drawn functionality."
#endif

class WXDLLIMPEXP_FWD_CORE wxOwnerDrawn;
class WXDLLIMPEXP_FWD_CORE wxCheckListBoxItem; // fwd decl, defined in checklst.cpp

class WXDLLIMPEXP_CORE wxCheckListBox : public wxCheckListBoxBase
{
public:
  // ctors
  wxCheckListBox();
  wxCheckListBox(wxWindow *parent, wxWindowID id,
                 const wxPoint& pos = wxDefaultPosition,
                 const wxSize& size = wxDefaultSize,
                 int nStrings = 0,
                 const wxString choices[] = NULL,
                 long style = 0,
                 const wxValidator& validator = wxDefaultValidator,
                 const wxString& name = wxListBoxNameStr);
  wxCheckListBox(wxWindow *parent, wxWindowID id,
                 const wxPoint& pos,
                 const wxSize& size,
                 const wxArrayString& choices,
                 long style = 0,
                 const wxValidator& validator = wxDefaultValidator,
                 const wxString& name = wxListBoxNameStr);

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

  // override base class virtuals
  virtual void Delete(unsigned int n);

  virtual bool SetFont( const wxFont &font );

  // items may be checked
  virtual bool IsChecked(unsigned int uiIndex) const;
  virtual void Check(unsigned int uiIndex, bool bCheck = true);

  // return the index of the item at this position or wxNOT_FOUND
  int HitTest(const wxPoint& pt) const { return DoHitTestItem(pt.x, pt.y); }
  int HitTest(wxCoord x, wxCoord y) const { return DoHitTestItem(x, y); }

  // accessors
  size_t GetItemHeight() const { return m_nItemHeight; }

protected:
  // we create our items ourselves and they have non-standard size,
  // so we need to override these functions
  virtual wxOwnerDrawn *CreateLboxItem(size_t n);
  virtual bool          MSWOnMeasure(WXMEASUREITEMSTRUCT *item);

  // this can't be called DoHitTest() because wxWindow already has this method
  int DoHitTestItem(wxCoord x, wxCoord y) const;

  // pressing space or clicking the check box toggles the item
  void OnKeyDown(wxKeyEvent& event);
  void OnLeftClick(wxMouseEvent& event);

private:
  size_t m_nItemHeight;  // height of checklistbox items (the same for all)

  DECLARE_EVENT_TABLE()
  DECLARE_DYNAMIC_CLASS_NO_COPY(wxCheckListBox)
};

#endif    //_CHECKLST_H

/////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/menu.h
// Purpose:     wxMenu, wxMenuBar classes
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_MENU_H_
#define _WX_MENU_H_

#if wxUSE_ACCEL
    #include "wx/accel.h"
    #include "wx/dynarray.h"

    WX_DEFINE_EXPORTED_ARRAY_PTR(wxAcceleratorEntry *, wxAcceleratorArray);
#endif // wxUSE_ACCEL

class WXDLLIMPEXP_FWD_CORE wxFrame;

#if defined(__WXWINCE__) && wxUSE_TOOLBAR
class WXDLLIMPEXP_FWD_CORE wxToolBar;
#endif

#include "wx/arrstr.h"

// ----------------------------------------------------------------------------
// Menu
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_CORE wxMenu : public wxMenuBase
{
public:
    // ctors & dtor
    wxMenu(const wxString& title, long style = 0)
        : wxMenuBase(title, style) { Init(); }

    wxMenu(long style = 0) : wxMenuBase(style) { Init(); }

    virtual ~wxMenu();

    // implement base class virtuals
    virtual wxMenuItem* DoAppend(wxMenuItem *item);
    virtual wxMenuItem* DoInsert(size_t pos, wxMenuItem *item);
    virtual wxMenuItem* DoRemove(wxMenuItem *item);

    virtual void Break();

    virtual void SetTitle(const wxString& title);

    // implementation only from now on
    // -------------------------------

    virtual void Attach(wxMenuBarBase *menubar);

    bool PalmCommand(WXUINT param, WXWORD id);

    // semi-private accessors
        // get the window which contains this menu
    wxWindow *GetWindow() const;

#if wxUSE_ACCEL
    // called by wxMenuBar to build its accel table from the accels of all menus
    bool HasAccels() const { return !m_accels.IsEmpty(); }
    size_t GetAccelCount() const { return m_accels.GetCount(); }
    size_t CopyAccels(wxAcceleratorEntry *accels) const;

    // called by wxMenuItem when its accels changes
    void UpdateAccel(wxMenuItem *item);

    // helper used by wxMenu itself (returns the index in m_accels)
    int FindAccel(int id) const;
#endif // wxUSE_ACCEL

private:
    // common part of all ctors
    void Init();

    // common part of Append/Insert (behaves as Append is pos == (size_t)-1)
    bool DoInsertOrAppend(wxMenuItem *item, size_t pos = (size_t)-1);

    // terminate the current radio group, if any
    void EndRadioGroup();

    // if true, insert a break before appending the next item
    bool m_doBreak;

    // the position of the first item in the current radio group or -1
    int m_startRadioGroup;

#if wxUSE_ACCEL
    // the accelerators for our menu items
    wxAcceleratorArray m_accels;
#endif // wxUSE_ACCEL

    DECLARE_DYNAMIC_CLASS_NO_COPY(wxMenu)
};

// ----------------------------------------------------------------------------
// Menu Bar (a la Windows)
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_CORE wxMenuInfo : public wxObject
{
public :
    wxMenuInfo() { m_menu = NULL ; }
    virtual ~wxMenuInfo() { }

    void Create( wxMenu *menu , const wxString &title )
    { m_menu = menu ; m_title = title ; }
    wxMenu* GetMenu() const { return m_menu ; }
    wxString GetTitle() const { return m_title ; }
private :
    wxMenu *m_menu ;
    wxString m_title ;

    DECLARE_DYNAMIC_CLASS(wxMenuInfo) ;
} ;

WX_DECLARE_EXPORTED_LIST(wxMenuInfo, wxMenuInfoList );

class WXDLLIMPEXP_CORE wxMenuBar : public wxMenuBarBase
{
public:
    // ctors & dtor
        // default constructor
    wxMenuBar();

    wxMenuBar(long style);
        // menubar takes ownership of the menus arrays but copies the titles
    wxMenuBar(size_t n, wxMenu *menus[], const wxString titles[], long style = 0);
    virtual ~wxMenuBar();

    // menubar construction
    bool Append( wxMenuInfo *info ) { return Append( info->GetMenu() , info->GetTitle() ) ; }
    const wxMenuInfoList& GetMenuInfos() const ;

    virtual bool Append( wxMenu *menu, const wxString &title );
    virtual bool Insert(size_t pos, wxMenu *menu, const wxString& title);
    virtual wxMenu *Replace(size_t pos, wxMenu *menu, const wxString& title);
    virtual wxMenu *Remove(size_t pos);

    virtual void EnableTop( size_t pos, bool flag );
    virtual void SetMenuLabel( size_t pos, const wxString& label );
    virtual wxString GetMenuLabel( size_t pos ) const;

    // implementation from now on
    WXHMENU Create();
    virtual void Detach();
    virtual void Attach(wxFrame *frame);

    void LoadMenu();
    int ProcessCommand(int ItemID);

#if wxUSE_ACCEL
    // get the accel table for all the menus
    const wxAcceleratorTable& GetAccelTable() const { return m_accelTable; }

    // update the accel table (must be called after adding/deleting a menu)
    void RebuildAccelTable();
#endif // wxUSE_ACCEL

    // if the menubar is modified, the display is not updated automatically,
    // call this function to update it (m_menuBarFrame should be !NULL)
    void Refresh();

    // To avoid compile warning
    void Refresh( bool eraseBackground,
                          const wxRect *rect = (const wxRect *) NULL ) { wxWindow::Refresh(eraseBackground, rect); }

protected:
    // common part of all ctors
    void Init();

    wxArrayString m_titles ;
    wxMenuInfoList m_menuInfos;

    // Return the Palm position for a wxMenu which is sometimes different from
    // the wxWidgets position.
    int PalmPositionForWxMenu(wxMenu *menu, int wxpos);
#if wxUSE_ACCEL
    // the accelerator table for all accelerators in all our menus
    wxAcceleratorTable m_accelTable;
#endif // wxUSE_ACCEL

#if defined(__WXWINCE__) && wxUSE_TOOLBAR
    wxToolBar*  m_toolBar;
#endif

private:
    DECLARE_DYNAMIC_CLASS_NO_COPY(wxMenuBar)
};

#endif // _WX_MENU_H_

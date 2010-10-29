/////////////////////////////////////////////////////////////////////////////
// Name:        popupwin.h
// Purpose:     interface of wxPoppWindow
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxPopupWindow

    A special kind of top level window used for popup menus,
    combobox popups and such.

    @library{wxcore}
    @category{managedwnd}

    @see wxDialog, wxFrame
*/

class wxPopupWindow: public wxNonOwnedWindow
{
public:

    /**
      Constructor
    */
    wxPopupWindow(wxWindow *parent, int flags = wxBORDER_NONE);

    /**
      Create method for two-step creation
    */
    bool Create(wxWindow *parent, int flags = wxBORDER_NONE);

    /**
        Move the popup window to the right position, i.e. such that it is
        entirely visible.

        The popup is positioned at ptOrigin + size if it opens below and to the
        right (default), at ptOrigin - sizePopup if it opens above and to the
        left etc.

        @param ptOrigin
            Must be given in screen coordinates!
        @param sizePopup
            The size of the popup window
    */
    virtual void Position(const wxPoint& ptOrigin,
                          const wxSize& sizePopup);
};


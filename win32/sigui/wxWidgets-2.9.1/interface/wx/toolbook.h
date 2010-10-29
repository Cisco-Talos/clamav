/////////////////////////////////////////////////////////////////////////////
// Name:        toolbook.h
// Purpose:     interface of wxToolbook
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxToolbook

    wxToolbook is a class similar to wxNotebook but which uses a wxToolBar to
    show the labels instead of the tabs.

    There is no documentation for this class yet but its usage is identical to
    wxNotebook (except for the features clearly related to tabs only), so please
    refer to that class documentation for now. You can also use the
    @ref page_samples_notebook to see wxToolbook in action.

    @beginStyleTable
    @style{wxTBK_BUTTONBAR}
        Use wxButtonToolBar-based implementation under Mac OS (ignored under
        other platforms).
    @style{wxTBK_HORZ_LAYOUT}
        Shows the text and the icons alongside, not vertically stacked (only
        implement under Windows and GTK 2 platforms as it relies on
        @c wxTB_HORZ_LAYOUT flag support).
    @endStyleTable

    The common wxBookCtrl styles described in the @ref overview_bookctrl are
    also supported.

    @beginEventEmissionTable{wxBookCtrlEvent}
    @event{EVT_TOOLBOOK_PAGE_CHANGED(id, func)}
        The page selection was changed.
        Processes a @c wxEVT_COMMAND_TOOLBOOK_PAGE_CHANGED event.
    @event{EVT_TOOLBOOK_PAGE_CHANGING(id, func)}
        The page selection is about to be changed.
        Processes a @c wxEVT_COMMAND_TOOLBOOK_PAGE_CHANGING event.
        This event can be vetoed (using wxNotifyEvent::Veto()).
    @endEventTable

    @library{wxcore}
    @category{bookctrl}

    @see @ref overview_bookctrl, wxBookCtrlBase, wxNotebook,
         @ref page_samples_notebook
*/
class wxToolbook : public wxBookCtrlBase
{
public:
    //@{
    /**
        Constructs a choicebook control.
    */
    wxToolbook();
    wxToolbook(wxWindow* parent, wxWindowID id,
                 const wxPoint& pos = wxDefaultPosition,
                 const wxSize& size = wxDefaultSize,
                 long style = 0,
                 const wxString& name = wxEmptyStr);
    //@}

    /**
        Returns the wxToolBarBase associated with the control.
    */
    wxToolBarBase* GetToolBar() const;
};


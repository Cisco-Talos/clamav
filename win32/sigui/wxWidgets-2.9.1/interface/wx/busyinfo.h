/////////////////////////////////////////////////////////////////////////////
// Name:        busyinfo.h
// Purpose:     interface of wxBusyInfo
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxBusyInfo

    This class makes it easy to tell your user that the program is temporarily busy.
    Just create a wxBusyInfo object on the stack, and within the current scope,
    a message window will be shown.

    For example:

    @code
        wxBusyInfo wait("Please wait, working...");

        for (int i = 0; i < 100000; i++)
        {
            DoACalculation();
        }
    @endcode

    It works by creating a window in the constructor, and deleting it
    in the destructor.

    You may also want to call wxTheApp->Yield() to refresh the window
    periodically (in case it had been obscured by other windows, for
    example) like this:

    @code
        wxWindowDisabler disableAll;
        wxBusyInfo wait("Please wait, working...");

        for (int i = 0; i < 100000; i++)
        {
            DoACalculation();

            if ( !(i % 1000) )
                wxTheApp->Yield();
        }
    @endcode

    but take care to not cause undesirable reentrancies when doing it (see
    wxApp::Yield for more details). The simplest way to do it is to use
    wxWindowDisabler class as illustrated in the above example.

    Note that a wxBusyInfo is always built with the @c wxSTAY_ON_TOP window style
    (see wxFrame window styles for more info).

    @library{wxcore}
    @category{cmndlg}
*/
class wxBusyInfo
{
public:
    /**
        Constructs a busy info window as child of @a parent and displays @e msg in it.

        @note If @a parent is not @NULL you must ensure that it is not
              closed while the busy info is shown.
    */
    wxBusyInfo(const wxString& msg, wxWindow* parent = NULL);

    /**
        Hides and closes the window containing the information text.
    */
    virtual ~wxBusyInfo();
};


/////////////////////////////////////////////////////////////////////////////
// Name:        wupdlock.h
// Purpose:     interface of wxWindowUpdateLocker
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxWindowUpdateLocker

    This tiny class prevents redrawing of a wxWindow during its lifetime by using
    wxWindow::Freeze() and wxWindow::Thaw() methods.

    It is typically used for creating automatic objects to temporarily suppress
    window updates before a batch of operations is performed:

    @code
    void MyFrame::Foo()
        {
            m_text = new wxTextCtrl(this, ...);

            wxWindowUpdateLocker noUpdates(m_text);
            m_text-AppendText();
            ... many other operations with m_text...
            m_text-WriteText();
        }
    @endcode

    Using this class is easier and safer than calling wxWindow::Freeze() and
    wxWindow::Thaw() because you don't risk to forget calling the latter.

    @library{wxbase}
    @category{misc}
*/
class wxWindowUpdateLocker
{
public:
    /**
        Creates an object preventing the updates of the specified @e win.
        The parameter must be non-@NULL and the window must exist for longer than
        wxWindowUpdateLocker object itself.
    */
    wxWindowUpdateLocker(wxWindow* win);

    /**
        Destructor reenables updates for the window this object is associated with.
    */
    ~wxWindowUpdateLocker();
};


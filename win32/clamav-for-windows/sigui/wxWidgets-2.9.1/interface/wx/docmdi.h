/////////////////////////////////////////////////////////////////////////////
// Name:        docmdi.h
// Purpose:     interface of wxDocMDIParentFrame and wxDocMDIChildFrame
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxDocMDIParentFrame

    The wxDocMDIParentFrame class provides a default top-level frame for
    applications using the document/view framework. This class can only be used
    for MDI parent frames.

    It cooperates with the wxView, wxDocument, wxDocManager and wxDocTemplate
    classes.

    @library{wxcore}
    @category{docview}

    @see @ref overview_docview, @ref page_samples_docview, wxMDIParentFrame
*/
class wxDocMDIParentFrame : public wxMDIParentFrame
{
public:
    //@{
    /**
        Constructor.
    */
    wxDocMDIParentFrame();
    wxDocMDIParentFrame(wxDocManager* manager, wxFrame* parent,
                        wxWindowID id,
                        const wxString& title,
                        const wxPoint& pos = wxDefaultPosition,
                        const wxSize& size = wxDefaultSize,
                        long style = wxDEFAULT_FRAME_STYLE,
                        const wxString& name = wxFrameNameStr);
    //@}

    /**
        Destructor.
    */
    virtual ~wxDocMDIParentFrame();

    /**
        Creates the window.
    */
    bool Create(wxDocManager* manager, wxFrame* parent,
                wxWindowID id, const wxString& title,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                long style = wxDEFAULT_FRAME_STYLE,
                const wxString& name = wxFrameNameStr);

    /**
        Deletes all views and documents. If no user input cancelled the
        operation, the frame will be destroyed and the application will exit.

        Since understanding how document/view clean-up takes place can be
        difficult, the implementation of this function is shown below:

        @code
        void wxDocParentFrame::OnCloseWindow(wxCloseEvent& event)
        {
            if (m_docManager->Clear(!event.CanVeto()))
            {
                this->Destroy();
            }
            else
                event.Veto();
        }
        @endcode
    */
    void OnCloseWindow(wxCloseEvent& event);
};



/**
    @class wxDocMDIChildFrame

    The wxDocMDIChildFrame class provides a default frame for displaying
    documents on separate windows. This class can only be used for MDI child
    frames.

    The class is part of the document/view framework supported by wxWidgets,
    and cooperates with the wxView, wxDocument, wxDocManager and wxDocTemplate
    classes.

    @library{wxcore}
    @category{docview}

    @see @ref overview_docview, @ref page_samples_docview, wxMDIChildFrame
*/
class wxDocMDIChildFrame : public wxMDIChildFrame
{
public:
    /**
        Constructor.
    */
    wxDocMDIChildFrame(wxDocument* doc, wxView* view,
                       wxMDIParentFrame* parent, wxWindowID id,
                       const wxString& title,
                       const wxPoint& pos = wxDefaultPosition,
                       const wxSize& size = wxDefaultSize,
                       long style = wxDEFAULT_FRAME_STYLE,
                       const wxString& name = wxFrameNameStr);

    /**
        Destructor.
    */
    virtual ~wxDocMDIChildFrame();

    /**
        Returns the document associated with this frame.
    */
    wxDocument* GetDocument() const;

    /**
        Returns the view associated with this frame.
    */
    wxView* GetView() const;

    /**
        Sets the currently active view to be the frame's view. You may need
        to override (but still call) this function in order to set the keyboard
        focus for your subwindow.
    */
    void OnActivate(wxActivateEvent& event);

    /**
        Closes and deletes the current view and document.
    */
    void OnCloseWindow(wxCloseEvent& event);

    /**
        Sets the document for this frame.
    */
    void SetDocument(wxDocument* doc);

    /**
        Sets the view for this frame.
    */
    void SetView(wxView* view);
};


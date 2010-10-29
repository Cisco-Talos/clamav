/////////////////////////////////////////////////////////////////////////////
// Name:        html/helpfrm.h
// Purpose:     interface of wxHtmlHelpFrame
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxHtmlHelpFrame

    This class is used by wxHtmlHelpController to display help.
    It is an internal class and should not be used directly - except for the case
    when you're writing your own HTML help controller.

    @library{wxhtml}
    @category{help,html}
*/
class wxHtmlHelpFrame : public wxFrame
{
public:
    wxHtmlHelpFrame(wxHtmlHelpData* data = NULL);

    /**
        Constructor.

        For the possible values of @a style, please see wxHtmlHelpController.
    */
    wxHtmlHelpFrame(wxWindow* parent, int wxWindowID,
                    const wxString& title = wxEmptyString,
                    int style = wxHF_DEFAULT_STYLE,
                    wxHtmlHelpData* data = NULL,
                    wxConfigBase* config = NULL,
                    const wxString& rootpath = wxEmptyString);

    /**
        You may override this virtual method to add more buttons to the help window's
        toolbar. @a toolBar is a pointer to the toolbar and @a style is the style
        flag as passed to the Create() method.

        wxToolBar::Realize is called immediately after returning from this function.
    */
    virtual void AddToolbarButtons(wxToolBar* toolBar, int style);

    /**
        Creates the frame. See @ref wxHtmlHelpFrame() "the constructor"
        for a description of the parameters.
    */
    bool Create(wxWindow* parent, wxWindowID id,
                const wxString& title = wxEmptyString, int style = wxHF_DEFAULT_STYLE,
                wxConfigBase* config = NULL,
                const wxString& rootpath = wxEmptyString);

    /**
        Returns the help controller associated with the frame.
    */
    wxHtmlHelpController* GetController() const;

    /**
        Sets the help controller associated with the frame.
    */
    void SetController(wxHtmlHelpController* contoller);

    /**
        Sets the frame's title format.

        @a format must contain exactly one "%s" (it will be replaced by the page title).
    */
    void SetTitleFormat(const wxString& format);
};


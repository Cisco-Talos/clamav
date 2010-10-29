/////////////////////////////////////////////////////////////////////////////
// Name:        iconbndl.h
// Purpose:     interface of wxIconBundle
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxIconBundle

    This class contains multiple copies of an icon in different sizes.
    It is typically used in wxDialog::SetIcons and wxTopLevelWindow::SetIcons.

    @library{wxcore}
    @category{gdi}

    @stdobjects
    ::wxNullIconBundle
*/
class wxIconBundle : public wxGDIObject
{
public:
    /**
        Default ctor.
    */
    wxIconBundle();

    /**
        Initializes the bundle with the icon(s) found in the file.
    */
    wxIconBundle(const wxString& file, wxBitmapType type = wxBITMAP_TYPE_ANY);

    /**
        Initializes the bundle with the icon(s) found in the stream.

        Notice that the @a stream must be seekable, at least if it contains
        more than one icon. The stream pointer is positioned after the last
        icon read from the stream when this function returns.

        @since 2.9.0
    */
    wxIconBundle(wxInputStream& stream, wxBitmapType type = wxBITMAP_TYPE_ANY);

    /**
        Initializes the bundle with a single icon.
    */
    wxIconBundle(const wxIcon& icon);

    /**
        Copy constructor.
    */
    wxIconBundle(const wxIconBundle& ic);

    /**
        Destructor.
    */
    virtual ~wxIconBundle();

    /**
        Adds all the icons contained in the file to the bundle; if the
        collection already contains icons with the same width and height, they
        are replaced by the new ones.
    */
    void AddIcon(const wxString& file, wxBitmapType type = wxBITMAP_TYPE_ANY);

    /**
        Adds all the icons contained in the stream to the bundle; if the
        collection already contains icons with the same width and height, they
        are replaced by the new ones.

        Notice that, as well as in the constructor loading the icon bundle from
        stream, the @a stream must be seekable, at least if more than one icon
        is to be loaded from it.

        @since 2.9.0
    */
    void AddIcon(wxInputStream& stream, wxBitmapType type = wxBITMAP_TYPE_ANY);

    /**
        Adds the icon to the collection; if the collection already
        contains an icon with the same width and height, it is
        replaced by the new one.
    */
    void AddIcon(const wxIcon& icon);

    /**
        Returns the icon with the given size; if no such icon exists, returns
        the icon with size @c wxSYS_ICON_X and @c wxSYS_ICON_Y; if no such icon
        exists, returns the first icon in the bundle.

        If size = wxDefaultSize, returns the icon with size @c wxSYS_ICON_X and
        @c wxSYS_ICON_Y.
    */
    wxIcon GetIcon(const wxSize& size) const;

    /**
        Same as @code GetIcon( wxSize( size, size ) ) @endcode.
    */
    wxIcon GetIcon(wxCoord size = wxDefaultCoord) const;

    /**
        Returns the icon with exactly the given size or ::wxNullIcon if this
        size is not available.
    */
    wxIcon GetIconOfExactSize(const wxSize& size) const;

    /**
        Returns @true if the bundle doesn't contain any icons, @false otherwise
        (in which case a call to GetIcon() with default parameter should return
        a valid icon).
    */
    bool IsEmpty() const;

    /**
        Assignment operator, using @ref overview_refcount "reference counting".
    */
    wxIconBundle& operator=(const wxIconBundle& ic);

    /**
        Equality operator. This returns @true if two icon bundles are equal.
    */
    bool operator ==(const wxIconBundle& ic);

    /**
        Inequality operator. This returns true if two icon bundles are not equal.
    */
    bool operator !=(const wxIconBundle& ic);
};


/**
    An empty wxIconBundle.
*/
wxIconBundle wxNullIconBundle;



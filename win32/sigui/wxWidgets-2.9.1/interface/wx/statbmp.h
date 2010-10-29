/////////////////////////////////////////////////////////////////////////////
// Name:        statbmp.h
// Purpose:     interface of wxStaticBitmap
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxStaticBitmap

    A static bitmap control displays a bitmap. Native implementations on some
    platforms are only meant for display of the small icons in the dialog
    boxes. In particular, under Windows 9x the size of bitmap is limited
    to 64*64 pixels.

    If you want to display larger images portably, you may use generic
    implementation wxGenericStaticBitmap declared in \<wx/generic/statbmpg.h\>.

    @library{wxcore}
    @category{ctrl}
    @appearance{staticbitmap.png}

    @see wxStaticBitmap, wxStaticBox
*/
class wxStaticBitmap : public wxControl
{
public:
    /**
      Default constructor
    */
    wxStaticBitmap();

    /**
        Constructor, creating and showing a static bitmap control.

        @param parent
            Parent window. Should not be @NULL.
        @param id
            Control identifier. A value of -1 denotes a default value.
        @param label
            Bitmap label.
        @param pos
            Window position.
        @param size
            Window size.
        @param style
            Window style. See wxStaticBitmap.
        @param name
            Window name.

        @see Create()
    */
    wxStaticBitmap(wxWindow* parent, wxWindowID id,
                   const wxBitmap& label,
                   const wxPoint& pos = wxDefaultPosition,
                   const wxSize& size = wxDefaultSize,
                   long style = 0,
                   const wxString& name = wxStaticBitmapNameStr);

    /**
        Creation function, for two-step construction. For details see wxStaticBitmap().
    */
    bool Create(wxWindow* parent, wxWindowID id, const wxBitmap& label,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize, long style = 0,
                const wxString& name = wxStaticBitmapNameStr);

    /**
        Returns the bitmap currently used in the control.
        Notice that this method can be called even if SetIcon() had been used.

        @see SetBitmap()
    */
    virtual wxBitmap GetBitmap() const;

    /**
        Returns the icon currently used in the control.
        Notice that this method can only be called if SetIcon() had been used: an icon
        can't be retrieved from the control if a bitmap had been set
        (using wxStaticBitmap::SetBitmap).

        @see SetIcon()
    */
    virtual wxIcon GetIcon() const;

    /**
        Sets the bitmap label.

        @param label
            The new bitmap.

        @see GetBitmap()
    */
    virtual void SetBitmap(const wxBitmap& label);

    /**
        Sets the label to the given icon.

        @param label
            The new icon.
    */
    virtual void SetIcon(const wxIcon& label);
};


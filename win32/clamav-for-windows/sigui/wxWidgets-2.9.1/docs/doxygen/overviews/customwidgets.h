/////////////////////////////////////////////////////////////////////////////
// Name:        customwidgets.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_customwidgets Creating a custom widget

@li @ref overview_customwidgets_whenwhy
@li @ref overview_customwidgets_how

<hr>


@section overview_customwidgets_whenwhy When and why you should write your custom widget

Typically combining the existing @ref group_class_ctrl controls in wxDialogs and
wxFrames is sufficient to fullfill any GUI design.
Using the wxWidgets standard controls makes your GUI looks native on all ports
and is obviously easier and faster.

However there are situations where you need to show some particular kind of data
which is not suited to any existing control.
In these cases rather than hacking an existing control for something it has not
been coinceived for, it's better to write a new widget.


@section overview_customwidgets_how How to write the custom widget

There are at least two very different ways to implement a new widget.

The first is to build it upon wxWidgets existing classes, thus deriving it from
wxControl or wxWindow. In this way you'll get a @b generic widget.
This method has the advantage that writing a single
implementation works on all ports; the disadvantage is that it the widget will
look the same on all platforms, and thus it may not integrate well with the
native look and feel.

The second method is to build it directly upon the native toolkits of the platforms you
want to support (e.g. GTK+, Carbon and GDI). In this way you'll get a @b native widget.
This method in fact has the advantage of a native look and feel but requires different
implementations and thus more work.

In both cases you'll want to better explore some hot topics like:
- @ref overview_windowsizing
- @ref overview_events_custom to implement your custom widget's events.
You will probably need also to gain some familiarity with the wxWidgets sources,
since you'll need to interface with some undocumented wxWidgets internal mechanisms.


@subsection overview_customwidgets_how_generic Writing a generic widget

Generic widgets are typically derived from wxControl or wxWindow.
They are easy to write. The typical "template" is as follows:

@code

enum MySpecialWidgetStyles
{
    SWS_LOOK_CRAZY = 1,
    SWS_LOOK_SERIOUS = 2,
    SWS_SHOW_BUTTON = 4,

    SWS_DEFAULT_STYLE = (SWS_SHOW_BUTTON|SWS_LOOK_SERIOUS)
};

class MySpecialWidget : public wxControl
{
public:
    MySpecialWidget() { Init(); }

    MySpecialWidget(wxWindow *parent,
                    wxWindowID winid,
                    const wxString& label,
                    const wxPoint& pos = wxDefaultPosition,
                    const wxSize& size = wxDefaultSize,
                    long style = SWS_DEFAULT_STYLE,
                    const wxValidator& val = wxDefaultValidator,
                    const wxString& name = "MySpecialWidget")
    {
        Init();

        Create(parent, winid, label, pos, size, style, val, name);
    }

    bool Create(wxWindow *parent,
                wxWindowID winid,
                const wxString& label,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                long style = SWS_DEFAULT_STYLE,
                const wxValidator& val = wxDefaultValidator,
                const wxString& name = wxCollapsiblePaneNameStr);

    // accessors...

protected:

    void Init() {
        // init widget's internals...
    }

    virtual wxSize DoGetBestSize() const {
        // we need to calculate and return the best size of the widget...
    }

    void OnPaint(wxPaintEvent&) {
        // draw the widget on a wxDC...
    }

private:
    DECLARE_DYNAMIC_CLASS(MySpecialWidget)
    DECLARE_EVENT_TABLE()
};
@endcode



@subsection overview_customwidgets_how_native Writing a native widget

Writing a native widget is typically more difficult as it requires you to
know the APIs of the platforms you want to support.
See @ref page_port_nativedocs for links to the documentation manuals of the
various toolkits.

The organization used by wxWidgets consists in:
- declaring the common interface of the control in a generic header, using
  the 'Base' postfix; e.g. MySpecialWidgetBase.
  See for example the wxWidgets' @c "wx/button.h" file.

- declaring the real widget class inheriting from the Base version in
  platform-specific headers; see for example the wxWidgets' @c "wx/gtk/button.h" file.

- separing the different implementations in different source files, putting
  all common stuff in a separate source.
  See for example the wxWidgets' @c "src/common/btncmn.cpp", @c "src/gtk/button.cpp"
  and @c "src/msw/button.cpp" files.

*/


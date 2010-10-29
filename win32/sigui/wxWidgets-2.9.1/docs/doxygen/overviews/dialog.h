/////////////////////////////////////////////////////////////////////////////
// Name:        dialog.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_dialog wxDialog Overview

Classes: wxDialog, wxDialogLayoutAdapter

A dialog box is similar to a panel, in that it is a window which can
be used for placing controls, with the following exceptions:

@li A surrounding frame is implicitly created.
@li Extra functionality is automatically given to the dialog box,
    such as tabbing between items (currently Windows only).
@li If the dialog box is @e modal, the calling program is blocked
    until the dialog box is dismissed.

For a set of dialog convenience functions, including file selection, see
@ref group_funcmacro_dialog.

See also wxTopLevelWindow and wxWindow for inherited
member functions. Validation of data in controls is covered in @ref overview_validator.


@li @ref overview_dialog_autoscrolling


<hr>



@section overview_dialog_autoscrolling Automatic scrolling dialogs

As an ever greater variety of mobile hardware comes to market, it becomes more
imperative for wxWidgets applications to adapt to these platforms without putting
too much burden on the programmer. One area where wxWidgets can help is in adapting
dialogs for the lower resolution screens that inevitably accompany a smaller form factor.
wxDialog therefore supplies a global wxDialogLayoutAdapter class that implements
automatic scrolling adaptation for most sizer-based custom dialogs.

Many applications should therefore be able to adapt to small displays with little
or no work, as far as dialogs are concerned.
By default this adaptation is off. To switch scrolling adaptation on globally in
your application, call the static function wxDialog::EnableLayoutAdaptation passing @true.
You can also adjust adaptation on a per-dialog basis by calling
wxDialog::SetLayoutAdaptationMode with one of @c wxDIALOG_ADAPTATION_MODE_DEFAULT
(use the global setting), @c wxDIALOG_ADAPTATION_MODE_ENABLED or @c wxDIALOG_ADAPTATION_MODE_DISABLED.

The last two modes override the global adaptation setting.
With adaptation enabled, if the display size is too small for the dialog, wxWidgets (or rather the
standard adapter class wxStandardDialogLayoutAdapter) will make part of the dialog scrolling,
leaving standard buttons in a non-scrolling part at the bottom of the dialog.
This is done as follows, in wxDialogLayoutAdapter::DoLayoutAdaptation called from
within wxDialog::Show or wxDialog::ShowModal:

@li If wxDialog::GetContentWindow returns a window derived from wxBookCtrlBase,
    the pages are made scrollable and no other adaptation is done.
@li wxWidgets looks for a wxStdDialogButtonSizer and uses it for the non-scrolling part.
@li If that search failed, wxWidgets looks for a horizontal wxBoxSizer with one or more
    standard buttons, with identifiers such as @c wxID_OK and @c wxID_CANCEL.
@li If that search failed too, wxWidgets finds 'loose' standard buttons (in any kind of sizer)
    and adds them to a wxStdDialogButtonSizer.
    If no standard buttons were found, the whole dialog content will scroll.
@li All the children apart from standard buttons are reparented onto a new ::wxScrolledWindow
    object, using the old top-level sizer for the scrolled window and creating a new top-level
    sizer to lay out the scrolled window and standard button sizer.


@subsection overview_dialog_autoscrolling_custom Customising scrolling adaptation

In addition to switching adaptation on and off globally and per dialog,
you can choose how aggressively wxWidgets will search for standard buttons by setting
wxDialog::SetLayoutAdaptationLevel. By default, all the steps described above will be
performed but by setting the level to 1, for example, you can choose to only look for
wxStdDialogButtonSizer.

You can use wxDialog::AddMainButtonId to add identifiers for buttons that should also be
treated as standard buttons for the non-scrolling area.

You can derive your own class from wxDialogLayoutAdapter or wxStandardDialogLayoutAdapter and call
wxDialog::SetLayoutAdapter, deleting the old object that this function returns. Override
the functions CanDoLayoutAdaptation and DoLayoutAdaptation to test for adaptation applicability
and perform the adaptation.

You can also override wxDialog::CanDoLayoutAdaptation and wxDialog::DoLayoutAdaptation
in a class derived from wxDialog.


@subsection overview_dialog_autoscrolling_fail Situations where automatic scrolling adaptation may fail

Because adaptation rearranges your sizer and window hierarchy, it is not fool-proof,
and may fail in the following situations:

@li The dialog doesn't use sizers.
@li The dialog implementation makes assumptions about the window hierarchy,
    for example getting the parent of a control and casting to the dialog class.
@li The dialog does custom painting and/or event handling not handled by the scrolled window.
    If this problem can be solved globally, you can derive a new adapter class from
    wxStandardDialogLayoutAdapter and override its CreateScrolledWindow function to return
    an instance of your own class.
@li The dialog has unusual layout, for example a vertical sizer containing a mixture of
    standard buttons and other controls.
@li The dialog makes assumptions about the sizer hierarchy, for example to show or hide
    children of the top-level sizer. However, the original sizer hierarchy will still hold
    until Show or ShowModal is called.

You can help make sure that your dialogs will continue to function after adaptation by:

@li avoiding the above situations and assumptions;
@li using wxStdDialogButtonSizer;
@li only making assumptions about hierarchy immediately after the dialog is created;
@li using an intermediate sizer under the main sizer, a @false top-level sizer that
    can be relied on to exist for the purposes of manipulating child sizers and windows;
@li overriding wxDialog::GetContentWindow to return a book control if your dialog implements
    pages: wxWidgets will then only make the pages scrollable.


@subsection overview_dialog_propertysheet wxPropertySheetDialog and wxWizard

Adaptation for wxPropertySheetDialog is always done by simply making the pages
scrollable, since wxDialog::GetContentWindow returns the dialog's book control and
this is handled by the standard layout adapter.

wxWizard uses its own CanDoLayoutAdaptation and DoLayoutAdaptation functions rather
than the global adapter: again, only the wizard pages are made scrollable.

*/


/////////////////////////////////////////////////////////////////////////////
// Name:        propgrid.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_propgrid wxPropertyGrid Overview

Key Classes:
@li wxPGProperty
@li wxPropertyGrid
@li wxPropertyGridEvent
@li wxPropertyGridManager
@li wxPropertyGridPage

  wxPropertyGrid is a specialized grid for editing properties - in other
words name = value pairs. List of ready-to-use property classes include
strings, numbers, flag sets, fonts, colours and many others. It is possible,
for example, to categorize properties, set up a complete tree-hierarchy,
add more than two columns, and set arbitrary per-property attributes.

  As this version of wxPropertyGrid has some backward-incompatible changes
from version 1.4, everybody who need to maintain custom property classes
should carefully read final section in @ref propgrid_compat.

@li @ref propgrid_basics
@li @ref propgrid_categories
@li @ref propgrid_parentprops
@li @ref propgrid_enumandflags
@li @ref propgrid_advprops
@li @ref propgrid_processingvalues
@li @ref propgrid_iterating
@li @ref propgrid_events
@li @ref propgrid_tooltipandhint
@li @ref propgrid_validating
@li @ref propgrid_populating
@li @ref propgrid_cellrender
@li @ref propgrid_customizing
@li @ref propgrid_usage2
@li @ref propgrid_subclassing
@li @ref propgrid_misc
@li @ref propgrid_proplist
@li @ref propgrid_compat

@section propgrid_basics Creating and Populating wxPropertyGrid

As seen here, wxPropertyGrid is constructed in the same way as
other wxWidgets controls:

@code

// Necessary header file
#include <wx/propgrid/propgrid.h>

...

    // Assumes code is in frame/dialog constructor

    // Construct wxPropertyGrid control
    wxPropertyGrid* pg = new wxPropertyGrid(
        this, // parent
        PGID, // id
        wxDefaultPosition, // position
        wxDefaultSize, // size
        // Here are just some of the supported window styles
        wxPG_AUTO_SORT | // Automatic sorting after items added
        wxPG_SPLITTER_AUTO_CENTER | // Automatically center splitter until user manually adjusts it
        // Default style
        wxPG_DEFAULT_STYLE );

    // Window style flags are at premium, so some less often needed ones are
    // available as extra window styles (wxPG_EX_xxx) which must be set using
    // SetExtraStyle member function. wxPG_EX_HELP_AS_TOOLTIPS, for instance,
    // allows displaying help strings as tool tips.
    pg->SetExtraStyle( wxPG_EX_HELP_AS_TOOLTIPS );

@endcode

  (for complete list of new window styles, see @ref propgrid_window_styles)

  wxPropertyGrid is usually populated with lines like this:

@code
    pg->Append( new wxStringProperty("Label", "Name", "Initial Value") );
@endcode

Naturally, wxStringProperty is a property class. Only the first function argument (label)
is mandatory. Second one, name, defaults to label and, third, the initial value, to
default value. If constant wxPG_LABEL is used as the name argument, then the label is
automatically used as a name as well (this is more efficient than manually defining both
as the same). Use of empty name is discouraged and will sometimes result in run-time error.
Note that all property class constructors have quite similar constructor argument list.

To demonstrate other common property classes, here's another code snippet:

@code

    // Add int property
    pg->Append( new wxIntProperty("IntProperty", wxPG_LABEL, 12345678) );

    // Add float property (value type is actually double)
    pg->Append( new wxFloatProperty("FloatProperty", wxPG_LABEL, 12345.678) );

    // Add a bool property
    pg->Append( new wxBoolProperty("BoolProperty", wxPG_LABEL, false) );

    // A string property that can be edited in a separate editor dialog.
    pg->Append( new wxLongStringProperty("LongStringProperty",
                                         wxPG_LABEL,
                                         "This is much longer string than the "
                                         "first one. Edit it by clicking the button."));

    // String editor with dir selector button.
    pg->Append( new wxDirProperty("DirProperty", wxPG_LABEL, ::wxGetUserHome()) );

    // wxArrayStringProperty embeds a wxArrayString.
    pg->Append( new wxArrayStringProperty("Label of ArrayStringProperty",
                                          "NameOfArrayStringProp"));

    // A file selector property.
    pg->Append( new wxFileProperty("FileProperty", wxPG_LABEL, wxEmptyString) );

    // Extra: set wild card for file property (format same as in wxFileDialog).
    pg->SetPropertyAttribute( "FileProperty",
                              wxPG_FILE_WILDCARD,
                              "All files (*.*)|*.*" );

@endcode

  Operations on properties are usually done by directly calling wxPGProperty's
or wxPropertyGridInterface's member functions. wxPropertyGridInterface is an
abstract base class for property containers such as wxPropertyGrid,
wxPropertyGridManager, and wxPropertyGridPage. Note however that wxPGProperty's
member functions generally do not refresh the grid.

  wxPropertyGridInterface's property operation member functions , such as
SetPropertyValue() and DisableProperty(), all accept a special wxPGPropArg id
argument, using which you can refer to properties either by their pointer
(for performance) or by their name (for convenience). For instance:

@code
    // Add a file selector property.
    wxPGPropety* prop = pg->Append( new wxFileProperty("FileProperty",
                                    wxPG_LABEL,
                                    wxEmptyString) );

    // Valid: Set wild card by name
    pg->SetPropertyAttribute( "FileProperty",
                              wxPG_FILE_WILDCARD,
                              "All files (*.*)|*.*" );

    // Also Valid: Set wild card by property pointer
    pg->SetPropertyAttribute( prop,
                              wxPG_FILE_WILDCARD,
                              "All files (*.*)|*.*" );
@endcode

  Using pointer is faster, since it doesn't require hash map lookup. Anyway,
you can always get property pointer (wxPGProperty*) as return value from Append()
or Insert(), or by calling wxPropertyGridInterface::GetPropertyByName() or
just plain GetProperty().

@section propgrid_categories Categories

  wxPropertyGrid has a hierarchic property storage and display model, which
allows property categories to hold child properties and even other
categories. Other than that, from the programmer's point of view, categories
can be treated exactly the same as "other" properties. For example, despite
its name, GetPropertyByName() also returns a category by name. Note however
that sometimes the label of a property category may be referred as caption
(for example, there is wxPropertyGrid::SetCaptionTextColour() method
that sets text colour of property category labels).

  When category is added at the top (i.e. root) level of the hierarchy,
it becomes a *current category*. This means that all other (non-category)
properties after it are automatically appended to it. You may add
properties to specific categories by using wxPropertyGridInterface::Insert
or wxPropertyGridInterface::AppendIn.

  Category code sample:

@code

    // One way to add category (similar to how other properties are added)
    pg->Append( new wxPropertyCategory("Main") );

    // All these are added to "Main" category
    pg->Append( new wxStringProperty("Name") );
    pg->Append( new wxIntProperty("Age",wxPG_LABEL,25) );
    pg->Append( new wxIntProperty("Height",wxPG_LABEL,180) );
    pg->Append( new wxIntProperty("Weight") );

    // Another one
    pg->Append( new wxPropertyCategory("Attributes") );

    // All these are added to "Attributes" category
    pg->Append( new wxIntProperty("Intelligence") );
    pg->Append( new wxIntProperty("Agility") );
    pg->Append( new wxIntProperty("Strength") );

@endcode


@section propgrid_parentprops Tree-like Property Structure

  Basically any property can have children. There are few limitations, however.

@remarks
- Names of properties with non-category, non-root parents are not stored in global
  hash map. Instead, they can be accessed with strings like "Parent.Child".
  For instance, in the sample below, child property named "Max. Speed (mph)"
  can be accessed by global name "Car.Speeds.Max Speed (mph)".
- If you want to property's value to be a string composed of the child property values,
  you must use wxStringProperty as parent and use magic string "<composed>" as its
  value.
- Events (eg. change of value) that occur in parent do not propagate to children. Events
  that occur in children will propagate to parents, but only if they are wxStringProperties
  with "<composed>" value.

Sample:

@code
    wxPGProperty* carProp = pg->Append(new wxStringProperty("Car",
                                         wxPG_LABEL,
                                         "<composed>"));

    pg->AppendIn(carProp, new wxStringProperty("Model",
                                                wxPG_LABEL,
                                                "Lamborghini Diablo SV"));

    pg->AppendIn(carProp, new wxIntProperty("Engine Size (cc)",
                                            wxPG_LABEL,
                                            5707) );

    wxPGProperty* speedsProp = pg->AppendIn(carProp,
                                            new wxStringProperty("Speeds",
                                              wxPG_LABEL,
                                              "<composed>"));

    pg->AppendIn( speedsProp, new wxIntProperty("Max. Speed (mph)",
                                                wxPG_LABEL,290) );
    pg->AppendIn( speedsProp, new wxFloatProperty("0-100 mph (sec)",
                                                  wxPG_LABEL,3.9) );
    pg->AppendIn( speedsProp, new wxFloatProperty("1/4 mile (sec)",
                                                  wxPG_LABEL,8.6) );

    // This is how child property can be referred to by name
    pg->SetPropertyValue( "Car.Speeds.Max. Speed (mph)", 300 );

    pg->AppendIn(carProp, new wxIntProperty("Price ($)",
                                            wxPG_LABEL,
                                            300000) );

    // Displayed value of "Car" property is now very close to this:
    // "Lamborghini Diablo SV; 5707 [300; 3.9; 8.6] 300000"

@endcode

@section propgrid_enumandflags wxEnumProperty and wxFlagsProperty

  wxEnumProperty is used when you want property's (integer or string) value
to be selected from a popup list of choices.

  Creating wxEnumProperty is slightly more complex than those described
earlier. You have to provide list of constant labels, and optionally relevant
values (if label indexes are not sufficient).

@remarks

- Value wxPG_INVALID_VALUE (equals INT_MAX) is not allowed as list
  item value.

A very simple example:

@code

    //
    // Using wxArrayString
    //
    wxArrayString arrDiet;
    arr.Add("Herbivore");
    arr.Add("Carnivore");
    arr.Add("Omnivore");

    pg->Append( new wxEnumProperty("Diet",
                                   wxPG_LABEL,
                                   arrDiet) );

    //
    // Using wxChar* array
    //
    const wxChar* arrayDiet[] =
    { wxT("Herbivore"), wxT("Carnivore"), wxT("Omnivore"), NULL };

    pg->Append( new wxEnumProperty("Diet",
                                   wxPG_LABEL,
                                   arrayDiet) );

@endcode

Here's extended example using values as well:

@code

    //
    // Using wxArrayString and wxArrayInt
    //
    wxArrayString arrDiet;
    arr.Add("Herbivore");
    arr.Add("Carnivore");
    arr.Add("Omnivore");

    wxArrayInt arrIds;
    arrIds.Add(40);
    arrIds.Add(45);
    arrIds.Add(50);

    // Note that the initial value (the last argument) is the actual value,
    // not index or anything like that. Thus, our value selects "Omnivore".
    pg->Append( new wxEnumProperty("Diet",
                                   wxPG_LABEL,
                                   arrDiet,
                                   arrIds,
                                   50));

@endcode

  wxPGChoices is a class where wxEnumProperty, and other properties which
  require storage for list of items, actually stores strings and values. It is
  used to facilitate reference counting, and therefore recommended way of
  adding items when multiple properties share the same set.

  You can use wxPGChoices directly as well, filling it and then passing it
  to the constructor. In fact, if you wish to display bitmaps next to labels,
  your best choice is to use this approach.

@code

    wxPGChoices chs;
    chs.Add("Herbivore", 40);
    chs.Add("Carnivore", 45);
    chs.Add("Omnivore", 50);

    // Let's add an item with bitmap, too
    chs.Add("None of the above", wxBitmap(), 60);

    pg->Append( new wxEnumProperty("Primary Diet",
                                   wxPG_LABEL,
                                   chs) );

    // Add same choices to another property as well - this is efficient due
    // to reference counting
    pg->Append( new wxEnumProperty("Secondary Diet",
                                   wxPG_LABEL,
                                   chs) );
@endcode

You can later change choices of property by using wxPGProperty::AddChoice(),
wxPGProperty::InsertChoice(), wxPGProperty::DeleteChoice(), and
wxPGProperty::SetChoices().

<b>wxEditEnumProperty</b> works exactly like wxEnumProperty, except
is uses non-read-only combo box as default editor, and value is stored as
string when it is not any of the choices.

wxFlagsProperty has similar construction:

@code

    const wxChar* flags_prop_labels[] = { wxT("wxICONIZE"),
        wxT("wxCAPTION"), wxT("wxMINIMIZE_BOX"), wxT("wxMAXIMIZE_BOX"), NULL };

    // this value array would be optional if values matched string indexes
    long flags_prop_values[] = { wxICONIZE, wxCAPTION, wxMINIMIZE_BOX,
        wxMAXIMIZE_BOX };

    pg->Append( new wxFlagsProperty("Window Style",
                                    wxPG_LABEL,
                                    flags_prop_labels,
                                    flags_prop_values,
                                    wxDEFAULT_FRAME_STYLE) );

@endcode

wxFlagsProperty can use wxPGChoices just the same way as wxEnumProperty
<b>Note:</b> When changing "choices" (ie. flag labels) of wxFlagsProperty,
you will need to use wxPGProperty::SetChoices() to replace all choices
at once - otherwise implicit child properties will not get updated properly.

@section propgrid_advprops Specialized Properties

  This section describes the use of less often needed property classes.
To use them, you have to include <wx/propgrid/advprops.h>.

@code

// Necessary extra header file
#include <wx/propgrid/advprops.h>

...

    // Date property.
    pg->Append( new wxDateProperty("MyDateProperty",
                                   wxPG_LABEL,
                                   wxDateTime::Now()) );

    // Image file property. Wild card is auto-generated from available
    // image handlers, so it is not set this time.
    pg->Append( new wxImageFileProperty("Label of ImageFileProperty",
                                        "NameOfImageFileProp") );

    // Font property has sub-properties. Note that we give window's font as
    // initial value.
    pg->Append( new wxFontProperty("Font",
                                   wxPG_LABEL,
                                   GetFont()) );

    // Colour property with arbitrary colour.
    pg->Append( new wxColourProperty("My Colour 1",
                                     wxPG_LABEL,
                                     wxColour(242,109,0) ) );

    // System colour property.
    pg->Append( new wxSystemColourProperty("My SysColour 1",
                                           wxPG_LABEL,
                                           wxSystemSettings::GetColour(wxSYS_COLOUR_WINDOW)) );

    // System colour property with custom colour.
    pg->Append( new wxSystemColourProperty("My SysColour 2",
                                           wxPG_LABEL,
                                           wxColour(0,200,160) ) );

    // Cursor property
    pg->Append( new wxCursorProperty("My Cursor",
                                     wxPG_LABEL,
                                     wxCURSOR_ARROW));

@endcode


@section propgrid_processingvalues Processing Property Values

Properties store their values internally as wxVariant, but is also possible to
obtain them as wxAny, using implicit conversion. You can get property
values with wxPGProperty::GetValue() and
wxPropertyGridInterface::GetPropertyValue().

Below is a code example which handles wxEVT_PG_CHANGED event:

@code

void MyWindowClass::OnPropertyGridChanged(wxPropertyGridEvent& event)
{
    wxPGProperty* property = event.GetProperty();

    // Do nothing if event did not have associated property
    if ( !property )
        return;

    // GetValue() returns wxVariant, but it is converted transparently to
    // wxAny
    wxAny value = property->GetValue();

    // Also, handle the case where property value is unspecified
    if ( value.IsNull() )
        return;

    // Handle changes in values, as needed
    if ( property.GetName() == "MyStringProperty" )
        OnMyStringPropertyChanged(value.As<wxString>());
    else if ( property.GetName() == "MyColourProperty" )
        OnMyColourPropertyChanged(value.As<wxColour>());
}

@endcode

You can get a string-representation of property's value using
wxPGProperty::GetValueAsString() or
wxPropertyGridInterface::GetPropertyValueAsString(). This particular function
is very safe to use with any kind of property.

@note There is a one case in which you may want to take extra care when
      dealing with raw wxVariant values. That is, integer-type properties,
      such as wxIntProperty and wxUIntProperty, store value internally as
      wx(U)LongLong when number doesn't fit into standard long type. Using
      << operator to get wx(U)LongLong from wxVariant is customized to work
      quite safely with various types of variant data. However, you can also
      bypass this problem by using wxAny in your code instead of wxVariant.

Note that in some cases property value can be Null variant, which means
that property value is unspecified. This usually occurs only when
wxPG_EX_AUTO_UNSPECIFIED_VALUES extra window style is defined or when you
manually set property value to Null (or unspecified).


@section propgrid_iterating Iterating through a property container

You can use somewhat STL'ish iterator classes to iterate through the grid.
Here is a simple example of forward iterating through all individual
properties (not categories nor private child properties that are normally
'transparent' to application code):

@code

    wxPropertyGridIterator it;

    for ( it = pg->GetIterator();
          !it.AtEnd();
          it++ )
    {
        wxPGProperty* p = *it;
        // Do something with the property
    }

@endcode

As expected there is also a const iterator:

@code

    wxPropertyGridConstIterator it;

    for ( it = pg->GetIterator();
          !it.AtEnd();
          it++ )
    {
        const wxPGProperty* p = *it;
        // Do something with the property
    }

@endcode

You can give some arguments to GetIterator to determine which properties
get automatically filtered out. For complete list of options, see
@ref propgrid_iterator_flags. GetIterator() also accepts other arguments.
See wxPropertyGridInterface::GetIterator() for details.

This example reverse-iterates through all visible items:

@code

    wxPropertyGridIterator it;

    for ( it = pg->GetIterator(wxPG_ITERATE_VISIBLE, wxBOTTOM);
          !it.AtEnd();
          it-- )
    {
        wxPGProperty* p = *it;
        // Do something with the property
    }

@endcode

@beginWxPythonOnly
PropertyGridInterface has some useful pythonic iterators as attributes.
@c Properties lets you iterate through all items that are not category
captions or private children. @c Items lets you iterate through everything
except private children. Also, there are GetPyIterator() and GetPyVIterator(),
which return pythonic iterators instead of normal wxPropertyGridIterator.

If you need to use C++ style iterators in wxPython code, note that
Instead of ++ operator, use Next() method, and instead of
* operator, use GetProperty() method.
@endWxPythonOnly

GetIterator() only works with wxPropertyGrid and the individual pages
of wxPropertyGridManager. In order to iterate through an arbitrary
property container (such as entire wxPropertyGridManager), you need to use
wxPropertyGridInterface::GetVIterator(). Note however that this virtual
iterator is limited to forward iteration.

@code

    wxPGVIterator it;

    for ( it = manager->GetVIterator();
          !it.AtEnd();
          it.Next() )
    {
        wxPGProperty* p = it.GetProperty();
        // Do something with the property
    }

@endcode

@section propgrid_populating Populating wxPropertyGrid Automatically

@subsection propgrid_fromvariants Populating from List of wxVariants

Example of populating an empty wxPropertyGrid from a values stored
in an arbitrary list of wxVariants.

@code

    // This is a static method that initializes *all* built-in type handlers
    // available, including those for wxColour and wxFont. Refers to *all*
    // included properties, so when compiling with static library, this
    // method may increase the executable size noticeably.
    pg->InitAllTypeHandlers();

    // Get contents of the grid as a wxVariant list
    wxVariant all_values = pg->GetPropertyValues();

    // Populate the list with values. If a property with appropriate
    // name is not found, it is created according to the type of variant.
    pg->SetPropertyValues( my_list_variant );

@endcode

@subsection propgrid_fromfile Loading Population from a Text-based Storage

Class wxPropertyGridPopulator may be helpful when writing code that
loads properties from a text-source. In fact, the wxPropertyGrid xrc-handler
(which may not be currently included in wxWidgets, but probably will be in
near future) uses it.

@subsection editablestate Saving and Restoring User-Editable State

You can use wxPropertyGridInterface::SaveEditableState() and
wxPropertyGridInterface::RestoreEditableState() to save and restore
user-editable state (selected property, expanded/collapsed properties,
selected page, scrolled position, and splitter positions).

@section propgrid_events Event Handling

Probably the most important event is the Changed event which occurs when
value of any property is changed by the user. Use EVT_PG_CHANGED(id,func)
in your event table to use it.

For complete list of event types, see wxPropertyGrid class reference.

However, one type of event that might need focused attention is EVT_PG_CHANGING,
which occurs just prior property value is being changed by user. You can
acquire pending value using wxPropertyGridEvent::GetValue(), and if it is
not acceptable, call wxPropertyGridEvent::Veto() to prevent the value change
from taking place.

@code

void MyForm::OnPropertyGridChanging( wxPropertyGridEvent& event )
{
    wxPGProperty* property = event.GetProperty();

    if ( property == m_pWatchThisProperty )
    {
        // GetValue() returns the pending value, but is only
        // supported by wxEVT_PG_CHANGING.
        if ( event.GetValue().GetString() == g_pThisTextIsNotAllowed )
        {
            event.Veto();
            return;
        }
    }
}

@endcode

@remarks On Child Property Event Handling
- For properties which have private, implicit children (wxFontProperty and
  wxFlagsProperty), events occur for the main parent property only.
  For other properties events occur for the children themselves. See
  @ref propgrid_parentprops.

- When property's child gets changed, you can use wxPropertyGridEvent::GetMainParent()
  to obtain its topmost non-category parent (useful, if you have deeply nested
  properties).

@section propgrid_tooltipandhint Help String, Hint and Tool Tips

For each property you can specify two different types of help text. First,
you can use wxPropertyGridInterface::SetPropertyHelpString() or
wxPGProperty::SetHelpString() to set property's help text. Second, you
can use wxPGProperty::SetAttribute() to set property's "Hint" attribute.

Difference between hint and help string is that the hint is shown in an empty
property value cell, while help string is shown either in the description text
box, as a tool tip, or on the status bar, whichever of these is available.

To enable display of help string as tool tips, you must explicitly use
the wxPG_EX_HELP_AS_TOOLTIPS extra window style.

@section propgrid_validating Validating Property Values

There are various ways to make sure user enters only correct values. First, you
can use wxValidators similar to as you would with ordinary controls. Use
wxPropertyGridInterface::SetPropertyValidator() to assign wxValidator to
property.

Second, you can subclass a property and override wxPGProperty::ValidateValue(),
or handle wxEVT_PG_CHANGING for the same effect. Both of these ways do not
actually prevent user from temporarily entering invalid text, but they do give
you an opportunity to warn the user and block changed value from being committed
in a property.

Various validation failure options can be controlled globally with
wxPropertyGrid::SetValidationFailureBehavior(), or on an event basis by
calling wxEvent::SetValidationFailureBehavior(). Here's a code snippet of
how to handle wxEVT_PG_CHANGING, and to set custom failure behaviour and
message.

@code
    void MyFrame::OnPropertyGridChanging(wxPropertyGridEvent& event)
    {
        wxPGProperty* property = event.GetProperty();

        // You must use wxPropertyGridEvent::GetValue() to access
        // the value to be validated.
        wxVariant pendingValue = event.GetValue();

        if ( property->GetName() == "Font" )
        {
            // Make sure value is not unspecified
            if ( !pendingValue.IsNull() )
            {
                wxFont font;
                font << pendingValue;

                // Let's just allow Arial font
                if ( font.GetFaceName() != "Arial" )
                {
                    event.Veto();
                    event.SetValidationFailureBehavior(wxPG_VFB_STAY_IN_PROPERTY |
                                                       wxPG_VFB_BEEP |
                                                       wxPG_VFB_SHOW_MESSAGEBOX);
                }
            }
        }
    }
@endcode


@section propgrid_cellrender Customizing Individual Cell Appearance

You can control text colour, background colour, and attached image of
each cell in the property grid. Use wxPropertyGridInterface::SetPropertyCell() or
wxPGProperty::SetCell() for this purpose.

In addition, it is possible to control these characteristics for
wxPGChoices list items. See wxPGChoices class reference for more info.


@section propgrid_customizing Customizing Properties (without sub-classing)

In this section are presented miscellaneous ways to have custom appearance
and behavior for your properties without all the necessary hassle
of sub-classing a property class etc.

@subsection propgrid_customimage Setting Value Image

Every property can have a small value image placed in front of the
actual value text. Built-in example of this can be seen with
wxColourProperty and wxImageFileProperty, but for others it can
be set using wxPropertyGrid::SetPropertyImage method.

@subsection propgrid_customeditor Setting Property's Editor Control(s)

You can set editor control (or controls, in case of a control and button),
of any property using wxPropertyGrid::SetPropertyEditor. Editors are passed
as wxPGEditor_EditorName, and valid built-in EditorNames are
TextCtrl, Choice, ComboBox, CheckBox, TextCtrlAndButton, ChoiceAndButton,
SpinCtrl, and DatePickerCtrl. Two last mentioned ones require call to
static member function wxPropertyGrid::RegisterAdditionalEditors().

Following example changes wxColourProperty's editor from default Choice
to TextCtrlAndButton. wxColourProperty has its internal event handling set
up so that button click events of the button will be used to trigger
colour selection dialog.

@code

    wxPGProperty* colProp = new wxColourProperty("Text Colour");
    pg->Append(colProp);
    pg->SetPropertyEditor(colProp, wxPGEditor_TextCtrlAndButton);

@endcode

Naturally, creating and setting custom editor classes is a possibility as
well. For more information, see wxPGEditor class reference.

@subsection propgrid_editorattrs Property Attributes Recognized by Editors

<b>SpinCtrl</b> editor can make use of property's "Min", "Max", "Step" and
"Wrap" attributes.

@subsection propgrid_multiplebuttons Adding Multiple Buttons Next to an Editor

See wxPGMultiButton class reference.

@subsection propgrid_customeventhandling Handling Events Passed from Properties

<b>wxEVT_COMMAND_BUTTON_CLICKED </b>(corresponds to event table macro EVT_BUTTON):
Occurs when editor button click is not handled by the property itself
(as is the case, for example, if you set property's editor to TextCtrlAndButton
from the original TextCtrl).

@subsection propgrid_attributes Property Attributes

Miscellaneous values, often specific to a property type, can be set
using wxPropertyGridInterface::SetPropertyAttribute() and
wxPropertyGridInterface::SetPropertyAttributeAll() methods.

Attribute names are strings and values wxVariant. Arbitrary names are allowed
in order to store values that are relevant to application only and not
property grid. Constant equivalents of all attribute string names are
provided. Some of them are defined as cached strings, so using these constants
can provide for smaller binary size.

For complete list of attributes, see @ref propgrid_property_attributes.


@section propgrid_usage2 Using wxPropertyGridManager

wxPropertyGridManager is an efficient multi-page version of wxPropertyGrid,
which can optionally have tool bar for mode and page selection, and a help text
box. For more information, see wxPropertyGridManager class reference.

@subsection propgrid_propgridpage wxPropertyGridPage

wxPropertyGridPage is holder of properties for one page in manager. It is derived from
wxEvtHandler, so you can subclass it to process page-specific property grid events. Hand
over your page instance in wxPropertyGridManager::AddPage().

Please note that the wxPropertyGridPage itself only sports subset of wxPropertyGrid API
(but unlike manager, this include item iteration). Naturally it inherits from
wxPropertyGridInterface.

For more information, see wxPropertyGridPage class reference.


@section propgrid_subclassing Sub-classing wxPropertyGrid and wxPropertyGridManager

Few things to note:

- Only a small percentage of member functions are virtual. If you need more,
  just e-mail to wx-dev mailing list.

- Data manipulation is done in wxPropertyGridPageState class. So, instead of
  overriding wxPropertyGrid::Insert(), you'll probably want to override
  wxPropertyGridPageState::DoInsert(). See header file for details.

- Override wxPropertyGrid::CreateState() to instantiate your derivate
  wxPropertyGridPageState. For wxPropertyGridManager, you'll need to subclass
  wxPropertyGridPage instead (since it is derived from wxPropertyGridPageState),
  and hand over instances in wxPropertyGridManager::AddPage() calls.

- You can use a derivate wxPropertyGrid with manager by overriding
  wxPropertyGridManager::CreatePropertyGrid() member function.


@section propgrid_misc Miscellaneous Topics

@subsection propgrid_namescope Property Name Scope

  All properties which parent is category or root can be accessed
directly by their base name (ie. name given for property in its constructor).
Other properties can be accessed via "ParentsName.BaseName" notation,
Naturally, all property names should be unique.

@subsection propgrid_nonuniquelabels Non-unique Labels

  It is possible to have properties with identical label under same parent.
However, care must be taken to ensure that each property still has
unique (base) name.

@subsection propgrid_boolproperty wxBoolProperty

  There are few points about wxBoolProperty that require further discussion:
  - wxBoolProperty can be shown as either normal combo box or as a check box.
    Property attribute wxPG_BOOL_USE_CHECKBOX is used to change this.
    For example, if you have a wxFlagsProperty, you can
    set its all items to use check box using the following:
    @code
        pg->SetPropertyAttribute("MyFlagsProperty", wxPG_BOOL_USE_CHECKBOX, true, wxPG_RECURSE);
    @endcode

    Following will set all individual bool properties in your control to
    use check box:

    @code
        pg->SetPropertyAttributeAll(wxPG_BOOL_USE_CHECKBOX, true);
    @endcode

  - Default item names for wxBoolProperty are ["False", "True"]. This can be
    changed using static function wxPropertyGrid::SetBoolChoices(trueChoice,
    falseChoice).

@subsection propgrid_textctrlupdates Updates from wxTextCtrl Based Editor

  Changes from wxTextCtrl based property editors are committed (ie.
wxEVT_PG_CHANGED is sent etc.) *only* when (1) user presser enter, (2)
user moves to edit another property, or (3) when focus leaves
the grid.

  Because of this, you may find it useful, in some apps, to call
wxPropertyGrid::CommitChangesFromEditor() just before you need to do any
computations based on property grid values. Note that CommitChangesFromEditor()
will dispatch wxEVT_PG_CHANGED with ProcessEvent, so any of your event handlers
will be called immediately.

@subsection propgrid_splittercentering Centering the Splitter

  If you need to center the splitter, but only once when the program starts,
then do <b>not</b> use the wxPG_SPLITTER_AUTO_CENTER window style, but the
wxPropertyGrid::CenterSplitter() method. <b>However, be sure to call it after
the sizer setup and SetSize calls!</b> (ie. usually at the end of the
frame/dialog constructor)

  Splitter centering behavior can be customized using
wxPropertyGridInterface::SetColumnProportion(). Usually it is used to set
non-equal column proportions, which in essence stops the splitter(s) from
being 'centered' as such, and instead just auto-resized.

@subsection propgrid_splittersetting Setting Splitter Position When Creating Property Grid

Splitter position cannot exceed grid size, and therefore setting it during
form creation may fail as initial grid size is often smaller than desired
splitter position, especially when sizers are being used.

@subsection propgrid_colourproperty wxColourProperty and wxSystemColourProperty

Through sub-classing, these two property classes provide substantial customization
features. Subclass wxSystemColourProperty if you want to use wxColourPropertyValue
(which features colour type in addition to wxColour), and wxColourProperty if plain
wxColour is enough.

Override wxSystemColourProperty::ColourToString() to redefine how colours are
printed as strings.

Override wxSystemColourProperty::GetCustomColourIndex() to redefine location of
the item that triggers colour picker dialog (default is last).

Override wxSystemColourProperty::GetColour() to determine which colour matches
which choice entry.

@section propgrid_proplist Property Class Descriptions

See @ref pgproperty_properties

@section propgrid_compat Changes from wxPropertyGrid 1.4

Version of wxPropertyGrid bundled with wxWidgets 2.9+ has various backward-
incompatible changes from version 1.4, which had a stable API and will remain
as the last separate branch.

Note that in general any behavior-breaking changes should not compile or run
without warnings or errors.

@subsection propgrid_compat_general General Changes

  - Tab-traversal can no longer be used to travel between properties. Now
    it only causes focus to move from main grid to editor of selected property.
    Arrow keys are now your primary means of navigating between properties,
    with keyboard. This change allowed fixing broken tab traversal on wxGTK
    (which is open issue in wxPropertyGrid 1.4).

  - wxPG_EX_UNFOCUS_ON_ENTER style is removed and is now default behavior.
    That is, when enter is pressed, editing is considered done and focus
    moves back to the property grid from the editor control.

  - A few member functions were removed from wxPropertyGridInterface.
    Please use wxPGProperty's counterparts from now on.

  - wxPGChoices now has proper Copy-On-Write behavior.

  - wxPGChoices::SetExclusive() was renamed to AllocExclusive().

  - wxPGProperty::SetPropertyChoicesExclusive() was removed. Instead, use
    GetChoices().AllocExclusive().

  - wxPGProperty::ClearModifiedStatus() is removed. Please use
    SetModifiedStatus() instead.

  - wxPropertyGridInterface::GetExpandedProperties() is removed. You should
    now use wxPropertyGridInterface::GetEditableState() instead.

  - wxPG_EX_DISABLE_TLP_TRACKING is now enabled by default. To get the old
    behavior (recommended if you don't use a system that reparents the grid
    on its own), use the wxPG_EX_ENABLE_TLP_TRACKING extra style.

  - Extended window style wxPG_EX_LEGACY_VALIDATORS was removed.

  - Default property validation failure behavior has been changed to
    (wxPG_VFB_MARK_CELL | wxPG_VFB_SHOW_MESSAGEBOX), which means that the
    cell is marked red and wxMessageBox is shown. This is more user-friendly
    than the old behavior, which simply beeped and prevented leaving the
    property editor until a valid value was entered.

  - wxPropertyGridManager now has same Get/SetSelection() semantics as
    wxPropertyGrid.

  - Various wxPropertyGridManager page-related functions now return pointer
    to the page object instead of index.

  - wxArrayEditorDialog used by wxArrayStringProperty and some sample
    properties has been renamed to wxPGArrayEditorDialog. Also, it now uses
    wxEditableListBox for editing.

  - Instead of calling wxPropertyGrid::SetButtonShortcut(), use
    wxPropertyGrid::SetActionTrigger(wxPG_ACTION_PRESS_BUTTON).

  - wxPGProperty::GetCell() now returns a reference. AcquireCell() was removed.

  - wxPGMultiButton::FinalizePosition() has been renamed to Finalize(),
    and it has slightly different argument list.

  - wxPropertyGridEvent::HasProperty() is removed. You can use GetProperty()
    as immediate replacement when checking if event has a property.

  - "InlineHelp" property has been replaced with "Hint".

  - wxPropertyGrid::CanClose() has been removed. Call
    wxPropertyGridInterface::EditorValidate() instead.

@subsection propgrid_compat_propdev Property and Editor Sub-classing Changes

  - Confusing custom property macros have been eliminated.

  - Implement wxPGProperty::ValueToString() instead of GetValueAsString().

  - wxPGProperty::ChildChanged() must now return the modified value of
    whole property instead of writing it back into 'thisValue' argument.

  - Removed wxPropertyGrid::PrepareValueForDialogEditing(). Use
    wxPropertyGrid::GetPendingEditedValue() instead.

  - wxPGProperty::GetChoiceInfo() is removed, as all properties now carry
    wxPGChoices instance (protected wxPGProperty::m_choices).

  - Connect() should no longer be called in implementations of
    wxPGEditor::CreateControls(). wxPropertyGrid automatically passes all
    events from editor to wxPGEditor::OnEvent() and wxPGProperty::OnEvent(),
    as appropriate.

  - wxPython: Previously some of the reimplemented member functions needed a
    'Py' prefix. This is no longer necessary. For instance, if you previously
    implemented PyStringToValue() for your custom property, you should now
    just implement StringToValue().
*/

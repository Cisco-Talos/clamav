/////////////////////////////////////////////////////////////////////////////
// Name:        property.h
// Purpose:     interface of wxPGProperty
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////


#define wxNullProperty  ((wxPGProperty*)NULL)


/**
    @section propgrid_property_attributes wxPropertyGrid Property Attribute Identifiers

    wxPGProperty::SetAttribute() and wxPropertyGridInterface::SetPropertyAttribute()
    accept one of these as attribute name argument.

    You can use strings instead of constants.
    However, some of these constants are redefined to use cached strings which
    may reduce your binary size by some amount.

    @{
*/

/** Set default value for property.
*/
#define wxPG_ATTR_DEFAULT_VALUE           wxS("DefaultValue")

/** Universal, int or double. Minimum value for numeric properties.
*/
#define wxPG_ATTR_MIN                     wxS("Min")

/** Universal, int or double. Maximum value for numeric properties.
*/
#define wxPG_ATTR_MAX                     wxS("Max")

/** Universal, string. When set, will be shown as text after the displayed
    text value. Alternatively, if third column is enabled, text will be shown
    there (for any type of property).
*/
#define wxPG_ATTR_UNITS                     wxS("Units")

/** When set, will be shown as 'greyed' text in property's value cell when
    the actual displayed value is blank.
*/
#define wxPG_ATTR_HINT                      wxS("Hint")

/**
    @deprecated Use "Hint" (wxPG_ATTR_HINT) instead.
*/
#define wxPG_ATTR_INLINE_HELP               wxS("InlineHelp")

/** Universal, wxArrayString. Set to enable auto-completion in any
    wxTextCtrl-based property editor.
*/
#define wxPG_ATTR_AUTOCOMPLETE              wxS("AutoComplete")

/** wxBoolProperty and wxFlagsProperty specific. Value type is bool.
    Default value is False.

    When set to True, bool property will use check box instead of a
    combo box as its editor control. If you set this attribute
    for a wxFlagsProperty, it is automatically applied to child
    bool properties.
*/
#define wxPG_BOOL_USE_CHECKBOX              wxS("UseCheckbox")

/** wxBoolProperty and wxFlagsProperty specific. Value type is bool.
    Default value is False.

    Set to True for the bool property to cycle value on double click
    (instead of showing the popup listbox). If you set this attribute
    for a wxFlagsProperty, it is automatically applied to child
    bool properties.
*/
#define wxPG_BOOL_USE_DOUBLE_CLICK_CYCLING  wxS("UseDClickCycling")

/** wxFloatProperty (and similar) specific, int, default -1. Sets the (max) precision
    used when floating point value is rendered as text. The default -1 means infinite
    precision.
*/
#define wxPG_FLOAT_PRECISION                wxS("Precision")

/** The text will be echoed as asterisks (wxTE_PASSWORD will be passed to textctrl etc).
*/
#define wxPG_STRING_PASSWORD                wxS("Password")

/** Define base used by a wxUIntProperty. Valid constants are
    wxPG_BASE_OCT, wxPG_BASE_DEC, wxPG_BASE_HEX and wxPG_BASE_HEXL
    (lowercase characters).
*/
#define wxPG_UINT_BASE                      wxS("Base")

/** Define prefix rendered to wxUIntProperty. Accepted constants
    wxPG_PREFIX_NONE, wxPG_PREFIX_0x, and wxPG_PREFIX_DOLLAR_SIGN.
    <b>Note:</b> Only wxPG_PREFIX_NONE works with Decimal and Octal
    numbers.
*/
#define wxPG_UINT_PREFIX                    wxS("Prefix")

/** wxFileProperty/wxImageFileProperty specific, wxChar*, default is detected/varies.
    Sets the wildcard used in the triggered wxFileDialog. Format is the
    same.
*/
#define wxPG_FILE_WILDCARD                  wxS("Wildcard")

/** wxFileProperty/wxImageFileProperty specific, int, default 1.
    When 0, only the file name is shown (i.e. drive and directory are hidden).
*/
#define wxPG_FILE_SHOW_FULL_PATH            wxS("ShowFullPath")

/** Specific to wxFileProperty and derived properties, wxString, default empty.
    If set, then the filename is shown relative to the given path string.
*/
#define wxPG_FILE_SHOW_RELATIVE_PATH        wxS("ShowRelativePath")

/** Specific to wxFileProperty and derived properties, wxString, default is empty.
    Sets the initial path of where to look for files.
*/
#define wxPG_FILE_INITIAL_PATH              wxS("InitialPath")

/** Specific to wxFileProperty and derivatives, wxString, default is empty.
    Sets a specific title for the dir dialog.
*/
#define wxPG_FILE_DIALOG_TITLE              wxS("DialogTitle")

/** Specific to wxDirProperty, wxString, default is empty.
    Sets a specific message for the dir dialog.
*/
#define wxPG_DIR_DIALOG_MESSAGE             wxS("DialogMessage")

/**
    wxArrayStringProperty's string delimiter character. If this is aquotation
    mark or hyphen, then strings will be quoted instead (with given
    character).

    Default delimiter is quotation mark.
*/
#define wxPG_ARRAY_DELIMITER                wxS("Delimiter")

/** Sets displayed date format for wxDateProperty.
*/
#define wxPG_DATE_FORMAT                    wxS("DateFormat")

/** Sets wxDatePickerCtrl window style used with wxDateProperty. Default
    is wxDP_DEFAULT | wxDP_SHOWCENTURY. Using wxDP_ALLOWNONE will enable
    better unspecified value support in the editor.
*/
#define wxPG_DATE_PICKER_STYLE              wxS("PickerStyle")

/** SpinCtrl editor, int or double. How much number changes when button is
    pressed (or up/down on keybard).
*/
#define wxPG_ATTR_SPINCTRL_STEP             wxS("Step")

/** SpinCtrl editor, bool. If @true, value wraps at Min/Max.
*/
#define wxPG_ATTR_SPINCTRL_WRAP             wxS("Wrap")

/** SpinCtrl editor, bool. If @true, value can also by changed by moving
    mouse when left mouse button is being pressed.
*/
#define wxPG_ATTR_SPINCTRL_MOTIONSPIN       wxS("MotionSpin")

/** wxMultiChoiceProperty, int. If 0, no user strings allowed. If 1, user strings
    appear before list strings. If 2, user strings appear after list string.
*/
#define wxPG_ATTR_MULTICHOICE_USERSTRINGMODE    wxS("UserStringMode")

/** wxColourProperty and its kind, int, default 1. Setting this attribute to 0 hides custom
    colour from property's list of choices.
*/
#define wxPG_COLOUR_ALLOW_CUSTOM            wxS("AllowCustom")

/** @}
*/


/** @section propgrid_propflags wxPGProperty Flags
    @{
*/

enum wxPGPropertyFlags
{

/** Indicates bold font.
*/
wxPG_PROP_MODIFIED                  = 0x0001,

/** Disables ('greyed' text and editor does not activate) property.
*/
wxPG_PROP_DISABLED                  = 0x0002,

/** Hider button will hide this property.
*/
wxPG_PROP_HIDDEN                    = 0x0004,

/** This property has custom paint image just in front of its value.
    If property only draws custom images into a popup list, then this
    flag should not be set.
*/
wxPG_PROP_CUSTOMIMAGE               = 0x0008,

/** Do not create text based editor for this property (but button-triggered
    dialog and choice are ok).
*/
wxPG_PROP_NOEDITOR                  = 0x0010,

/** Property is collapsed, ie. it's children are hidden.
*/
wxPG_PROP_COLLAPSED                 = 0x0020,

/**
    If property is selected, then indicates that validation failed for pending
    value.

    If property is not selected, then indicates that the the actual property
    value has failed validation (NB: this behavior is not currently supported,
    but may be used in future).
*/
wxPG_PROP_INVALID_VALUE             = 0x0040,

// 0x0080,

/** Switched via SetWasModified(). Temporary flag - only used when
    setting/changing property value.
*/
wxPG_PROP_WAS_MODIFIED              = 0x0200,

/**
    If set, then child properties (if any) are private, and should be
    "invisible" to the application.
*/
wxPG_PROP_AGGREGATE                 = 0x0400,

/** If set, then child properties (if any) are copies and should not
    be deleted in dtor.
*/
wxPG_PROP_CHILDREN_ARE_COPIES       = 0x0800,

/**
    Classifies this item as a non-category.

    Used for faster item type identification.
*/
wxPG_PROP_PROPERTY                  = 0x1000,

/**
    Classifies this item as a category.

    Used for faster item type identification.
*/
wxPG_PROP_CATEGORY                  = 0x2000,

/** Classifies this item as a property that has children, but is not aggregate
    (ie children are not private).
*/
wxPG_PROP_MISC_PARENT               = 0x4000,

/** Property is read-only. Editor is still created for wxTextCtrl-based
    property editors. For others, editor is not usually created because
    they do implement wxTE_READONLY style or equivalent.
*/
wxPG_PROP_READONLY                  = 0x8000,

//
// NB: FLAGS ABOVE 0x8000 CANNOT BE USED WITH PROPERTY ITERATORS
//

/** Property's value is composed from values of child properties.
    @remarks
    This flag cannot be used with property iterators.
*/
wxPG_PROP_COMPOSED_VALUE            = 0x00010000,

/** Common value of property is selectable in editor.
    @remarks
    This flag cannot be used with property iterators.
*/
wxPG_PROP_USES_COMMON_VALUE         = 0x00020000,

/** Property can be set to unspecified value via editor.
    Currently, this applies to following properties:
    - wxIntProperty, wxUIntProperty, wxFloatProperty, wxEditEnumProperty:
      Clear the text field

    @remarks
    This flag cannot be used with property iterators.
*/
wxPG_PROP_AUTO_UNSPECIFIED          = 0x00040000,

/** Indicates the bit useable by derived properties.
*/
wxPG_PROP_CLASS_SPECIFIC_1          = 0x00080000,

/** Indicates the bit useable by derived properties.
*/
wxPG_PROP_CLASS_SPECIFIC_2          = 0x00100000,

/** Indicates that the property is being deleted and should be ignored.
*/
wxPG_PROP_BEING_DELETED             = 0x00200000

};

/** Topmost flag.
*/
#define wxPG_PROP_MAX               wxPG_PROP_AUTO_UNSPECIFIED

/** Property with children must have one of these set, otherwise iterators
    will not work correctly.
    Code should automatically take care of this, however.
*/
#define wxPG_PROP_PARENTAL_FLAGS \
    ((wxPGPropertyFlags)(wxPG_PROP_AGGREGATE | \
                         wxPG_PROP_CATEGORY | \
                         wxPG_PROP_MISC_PARENT))

/** @}
*/


/**
    @class wxPGProperty

    wxPGProperty is base class for all wxPropertyGrid properties. In
    sections below we cover few related topics.

    @li @ref pgproperty_properties
    @li @ref pgproperty_creating

    @section pgproperty_properties Supplied Ready-to-use Property Classes

    Here is a list and short description of supplied fully-functional
    property classes. They are located in either props.h or advprops.h.

    @li @ref wxArrayStringProperty
    @li @ref wxBoolProperty
    @li @ref wxColourProperty
    @li @ref wxCursorProperty
    @li @ref wxDateProperty
    @li @ref wxDirProperty
    @li @ref wxEditEnumProperty
    @li @ref wxEnumProperty
    @li @ref wxFileProperty
    @li @ref wxFlagsProperty
    @li @ref wxFloatProperty
    @li @ref wxFontProperty
    @li @ref wxImageFileProperty
    @li @ref wxIntProperty
    @li @ref wxLongStringProperty
    @li @ref wxMultiChoiceProperty
    @li @ref wxPropertyCategory
    @li @ref wxStringProperty
    @li @ref wxSystemColourProperty
    @li @ref wxUIntProperty

    @subsection wxPropertyCategory

    Not an actual property per se, but a header for a group of properties.
    Regardless inherits from wxPGProperty, and supports displaying 'labels'
    for columns other than the first one. Easiest way to set category's
    label for second column is to call wxPGProperty::SetValue() with string
    argument.

    @subsection wxStringProperty

    Simple string property. wxPG_STRING_PASSWORD attribute may be used
    to echo value as asterisks and use wxTE_PASSWORD for wxTextCtrl.
    wxPG_ATTR_AUTOCOMPLETE attribute may be used to enable auto-completion
    (use a wxArrayString value), and is also supported by any property that
    happens to use a wxTextCtrl-based editor.

    @remarks wxStringProperty has a special trait: if it has value of
            "<composed>", and also has child properties, then its displayed
            value becomes composition of child property values, similar as
            with wxFontProperty, for instance.

    @subsection wxIntProperty

    Like wxStringProperty, but converts text to a signed long integer.
    wxIntProperty seamlessly supports 64-bit integers (ie. wxLongLong).
    To safely convert variant to integer, use code like this:

    @code
        wxLongLong ll;
        ll << property->GetValue();

        // or
        wxLongLong ll = propertyGrid->GetPropertyValueAsLong(property);
    @endcode

    @subsection wxUIntProperty

    Like wxIntProperty, but displays value as unsigned int. To set
    the prefix used globally, manipulate wxPG_UINT_PREFIX string attribute.
    To set the globally used base, manipulate wxPG_UINT_BASE int
    attribute. Regardless of current prefix, understands (hex) values starting
    with both "0x" and "$".
    Like wxIntProperty, wxUIntProperty seamlessly supports 64-bit unsigned
    integers (ie. wxULongLong). Same wxVariant safety rules apply.

    @subsection wxFloatProperty

    Like wxStringProperty, but converts text to a double-precision floating point.
    Default float-to-text precision is 6 decimals, but this can be changed
    by modifying wxPG_FLOAT_PRECISION attribute.

    @subsection wxBoolProperty

    Represents a boolean value. wxChoice is used as editor control, by the
    default. wxPG_BOOL_USE_CHECKBOX attribute can be set to true inorder to use
    check box instead.

    @subsection wxLongStringProperty

    Like wxStringProperty, but has a button that triggers a small text editor
    dialog. Note that in long string values, tabs are represented by "\t" and
    line break by "\n".

    To display custom dialog on button press, you can subclass
    wxLongStringProperty and implement OnButtonClick, like this:

    @code
        virtual bool OnButtonClick( wxPropertyGrid* propGrid, wxString& value )
        {
            wxSize dialogSize(...size of your dialog...);

            wxPoint dlgPos = propGrid->GetGoodEditorDialogPosition(this,
                                                                   dialogSize)

            // Create dialog dlg at dlgPos. Use value as initial string
            // value.
            ...

            if ( dlg.ShowModal() == wxID_OK )
            {
                value = dlg.GetStringValue);
                return true;
            }
            return false;
        }
    @endcode

    Also, if you wish not to have line breaks and tabs translated to
    escape sequences, then do following in constructor of your subclass:

    @code
        m_flags |= wxPG_PROP_NO_ESCAPE;
    @endcode

    @subsection wxDirProperty

    Like wxLongStringProperty, but the button triggers dir selector instead.
    Supported properties (all with string value): wxPG_DIR_DIALOG_MESSAGE.

    @subsection wxFileProperty

    Like wxLongStringProperty, but the button triggers file selector instead.
    Default wildcard is "All files..." but this can be changed by setting
    wxPG_FILE_WILDCARD attribute (see wxFileDialog for format details).
    Attribute wxPG_FILE_SHOW_FULL_PATH can be set to @false inorder to show
    only the filename, not the entire path.

    @subsection wxEnumProperty

    Represents a single selection from a list of choices -
    wxOwnerDrawnComboBox is used to edit the value.

    @subsection wxFlagsProperty

    Represents a bit set that fits in a long integer. wxBoolProperty sub-
    properties are created for editing individual bits. Textctrl is created to
    manually edit the flags as a text; a continous sequence of spaces, commas
    and semicolons are considered as a flag id separator.

    <b>Note:</b> When changing "choices" (ie. flag labels) of wxFlagsProperty,
    you will need to use wxPGProperty::SetChoices() - otherwise they will not
    get updated properly.

    wxFlagsProperty supports the same attributes as wxBoolProperty.

    @subsection wxArrayStringProperty

    Allows editing of a list of strings in wxTextCtrl and in a separate dialog.

    @subsection wxDateProperty

    wxDateTime property. Default editor is DatePickerCtrl, altough TextCtrl
    should work as well. wxPG_DATE_FORMAT attribute can be used to change
    string wxDateTime::Format uses (altough default is recommended as it is
    locale-dependant), and wxPG_DATE_PICKER_STYLE allows changing window
    style given to DatePickerCtrl (default is wxDP_DEFAULT|wxDP_SHOWCENTURY).
    Using wxDP_ALLOWNONE will enable better unspecified value support.

    @subsection wxEditEnumProperty

    Represents a string that can be freely edited or selected from list of choices -
    custom combobox control is used to edit the value.

    @subsection wxMultiChoiceProperty

    Allows editing a multiple selection from a list of strings. This is
    property is pretty much built around concept of wxMultiChoiceDialog.
    It uses wxArrayString value.

    @subsection wxImageFileProperty

    Like wxFileProperty, but has thumbnail of the image in front of
    the filename and autogenerates wildcard from available image handlers.

    @subsection wxColourProperty

    <b>Useful alternate editor:</b> Choice.

    Represents wxColour. wxButton is used to trigger a colour picker dialog.
    There are various sub-classing opportunities with this class. See
    below in wxSystemColourProperty section for details.

    @subsection wxFontProperty

    Represents wxFont. Various sub-properties are used to edit individual
    subvalues.

    @subsection wxSystemColourProperty

    Represents wxColour and a system colour index. wxChoice is used to edit
    the value. Drop-down list has color images. Note that value type
    is wxColourPropertyValue instead of wxColour (which wxColourProperty
    uses).

    @code
        class wxColourPropertyValue : public wxObject
        {
        public:
            //  An integer value relating to the colour, and which exact
            //  meaning depends on the property with which it is used.
            //
            //  For wxSystemColourProperty:
            //  Any of wxSYS_COLOUR_XXX, or any web-colour ( use wxPG_TO_WEB_COLOUR
            //  macro - (currently unsupported) ), or wxPG_COLOUR_CUSTOM.
            wxUint32    m_type;

            // Resulting colour. Should be correct regardless of type.
            wxColour    m_colour;
        };
    @endcode

    in wxSystemColourProperty, and its derived class wxColourProperty, there
    are various sub-classing features. To set basic list list of colour
    names, call wxPGProperty::SetChoices().

    @code
        // Override in derived class to customize how colours are translated
        // to strings.
        virtual wxString ColourToString( const wxColour& col, int index ) const;

        // Returns index of entry that triggers colour picker dialog
        // (default is last).
        virtual int GetCustomColourIndex() const;

        // Helper function to show the colour dialog
        bool QueryColourFromUser( wxVariant& variant ) const;

        // Returns colour for given choice.
        // Default function returns wxSystemSettings::GetColour(index).
        virtual wxColour GetColour( int index ) const;
    @endcode

    @subsection wxCursorProperty

    Represents a wxCursor. wxChoice is used to edit the value.
    Drop-down list has cursor images under some (wxMSW) platforms.


    @section pgproperty_creating Creating Custom Properties

    New properties can be created by subclassing wxPGProperty or one
    of the provided property classes, and (re)implementing necessary
    member functions. Below, each virtual member function has ample
    documentation about its purpose and any odd details which to keep
    in mind.

    Here is a very simple 'template' code:

    @code
        class MyProperty : public wxPGProperty
        {
        public:
            // Default constructor
            MyProperty() { }

            // All arguments of this ctor must have a default value -
            // use wxPG_LABEL for label and name
            MyProperty( const wxString& label = wxPG_LABEL,
                        const wxString& name = wxPG_LABEL,
                        const wxString& value = wxEmptyString )
                : wxPGProperty(label, name)
            {
                // m_value is wxVariant
                m_value = value;
            }

            virtual ~MyProperty() { }

            const wxPGEditor* DoGetEditorClass() const
            {
                // Determines editor used by property.
                // You can replace 'TextCtrl' below with any of these
                // builtin-in property editor identifiers: Choice, ComboBox,
                // TextCtrlAndButton, ChoiceAndButton, CheckBox, SpinCtrl,
                // DatePickerCtrl.
                return wxPGEditor_TextCtrl;
            }

            virtual wxString ValueToString( wxVariant& value,
                                            int argFlags ) const
            {
                // TODO: Convert given property value to a string
            }

            virtual bool StringToValue( wxVariant& variant, const wxString& text, int argFlags )
            {
                // TODO: Adapt string to property value.
            }

        protected:
        };
    @endcode

    Since wxPGProperty derives from wxObject, you can use standard
    wxDECLARE_DYNAMIC_CLASS and wxIMPLEMENT_DYNAMIC_CLASS macros. From the
    above example they were omitted for sake of simplicity, and besides,
    they are only really needed if you need to use wxRTTI with your
    property class.

    You can change the 'value type' of a property by simply assigning different
    type of variant with SetValue. <b>It is mandatory to implement
    wxVariantData class for all data types used as property values.</b>
    You can use macros declared in wxPropertyGrid headers. For instance:

    @code
        // In header file:
        // (If you need to have export declaration, use version of macros
        // with _EXPORTED postfix)
        WX_PG_DECLARE_VARIANT_DATA(MyDataClass)

        // In sources file:
        WX_PG_IMPLEMENT_VARIANT_DATA(MyDataClass)

        // Or, if you don't have valid == operator:
        WX_PG_IMPLEMENT_VARIANT_DATA_DUMMY_EQ(MyDataClass)
    @endcode

    @library{wxpropgrid}
    @category{propgrid}
*/
class wxPGProperty : public wxObject
{
public:
    typedef wxUint32 FlagType;

    /**
        Default constructor.
    */
    wxPGProperty();

    /**
        Constructor.
        Non-abstract property classes should have constructor of this style:

        @code

        MyProperty( const wxString& label, const wxString& name, const T& value )
            : wxPGProperty(label, name)
        {
            // Generally recommended way to set the initial value
            // (as it should work in pretty much 100% of cases).
            wxVariant variant;
            variant << value;
            SetValue(variant);

            // If has private child properties then create them here.
            // For example:
            //     AddPrivateChild( new wxStringProperty("Subprop 1",
            //                                           wxPG_LABEL,
            //                                           value.GetSubProp1()));
        }

        @endcode
    */
    wxPGProperty( const wxString& label, const wxString& name );

    /**
        Virtual destructor. It is customary for derived properties to implement this.
    */
    virtual ~wxPGProperty();

    /**
        This virtual function is called after m_value has been set.

        @remarks
        - If m_value was set to Null variant (ie. unspecified value), OnSetValue()
          will not be called.
        - m_value may be of any variant type. Typically properties internally support only
          one variant type, and as such OnSetValue() provides a good opportunity to convert
          supported values into internal type.
        - Default implementation does nothing.
    */
    virtual void OnSetValue();

    /**
        Override this to return something else than m_value as the value.
    */
    virtual wxVariant DoGetValue() const;

    /**
        Implement this function in derived class to check the value.
        Return @true if it is ok. Returning @false prevents property change events
        from occurring.

        @remarks
        - Default implementation always returns @true.
    */
    virtual bool ValidateValue( wxVariant& value, wxPGValidationInfo& validationInfo ) const;

    /**
        Converts text into wxVariant value appropriate for this property.

        @param variant
            On function entry this is the old value (should not be wxNullVariant
            in normal cases). Translated value must be assigned back to it.

        @param text
            Text to be translated into variant.

        @param argFlags
            If wxPG_FULL_VALUE is set, returns complete, storable value instead
            of displayable one (they may be different).
            If wxPG_COMPOSITE_FRAGMENT is set, text is interpreted as a part of
            composite property string value (as generated by ValueToString()
            called with this same flag).

        @return Returns @true if resulting wxVariant value was different.

        @remarks Default implementation converts semicolon delimited tokens into
                child values. Only works for properties with children.

                You might want to take into account that m_value is Null variant
                if property value is unspecified (which is usually only case if
                you explicitly enabled that sort behavior).
    */
    virtual bool StringToValue( wxVariant& variant, const wxString& text, int argFlags = 0 ) const;

    /**
        Converts integer (possibly a choice selection) into wxVariant value
        appropriate for this property.

        @param variant
            On function entry this is the old value (should not be wxNullVariant
            in normal cases). Translated value must be assigned back to it.
        @param number
            Integer to be translated into variant.
        @param argFlags
            If wxPG_FULL_VALUE is set, returns complete, storable value instead
            of displayable one.

        @return Returns @true if resulting wxVariant value was different.

        @remarks
        - If property is not supposed to use choice or spinctrl or other editor
          with int-based value, it is not necessary to implement this method.
        - Default implementation simply assign given int to m_value.
        - If property uses choice control, and displays a dialog on some choice
          items, then it is preferred to display that dialog in IntToValue
          instead of OnEvent.
        - You might want to take into account that m_value is Mull variant if
          property value is unspecified (which is usually only case if you
          explicitly enabled that sort behavior).
    */
    virtual bool IntToValue( wxVariant& variant, int number, int argFlags = 0 ) const;

    /**
        Converts property value into a text representation.

        @param value
            Value to be converted.
        @param argFlags
            If 0 (default value), then displayed string is returned.
            If wxPG_FULL_VALUE is set, returns complete, storable string value
            instead of displayable. If wxPG_EDITABLE_VALUE is set, returns
            string value that must be editable in textctrl.
            If wxPG_COMPOSITE_FRAGMENT is set, returns text that is appropriate to
            display as a part of string property's composite text representation.

        @remarks Default implementation calls GenerateComposedValue().
    */
    virtual wxString ValueToString( wxVariant& value, int argFlags = 0 ) const;

    /**
        Converts string to a value, and if successful, calls SetValue() on it.
        Default behavior is to do nothing.

        @param text
            String to get the value from.
        @param flags
            @todo docme

        @return @true if value was changed.
    */
    bool SetValueFromString( const wxString& text, int flags = 0 );

    /**
        Converts integer to a value, and if succesful, calls SetValue() on it.
        Default behavior is to do nothing.

        @param value
            Int to get the value from.
        @param flags
            If has wxPG_FULL_VALUE, then the value given is a actual value and not an index.

        @return @true if value was changed.
    */
    bool SetValueFromInt( long value, int flags = 0 );

    /**
        Returns size of the custom painted image in front of property. This method
        must be overridden to return non-default value if OnCustomPaint is to be
        called.

        @param item
            Normally -1, but can be an index to the property's list of items.

        @remarks
        - Default behavior is to return wxSize(0,0), which means no image.
        - Default image width or height is indicated with dimension -1.
        - You can also return wxPG_DEFAULT_IMAGE_SIZE which equals wxSize(-1, -1).
    */
    virtual wxSize OnMeasureImage( int item = -1 ) const;

    /**
        Events received by editor widgets are processed here. Note that editor class
        usually processes most events. Some, such as button press events of
        TextCtrlAndButton class, can be handled here. Also, if custom handling
        for regular events is desired, then that can also be done (for example,
        wxSystemColourProperty custom handles wxEVT_COMMAND_CHOICE_SELECTED
        to display colour picker dialog when 'custom' selection is made).

        If the event causes value to be changed, SetValueInEvent() should be called
        to set the new value.

        The parameter @a event is the associated wxEvent.

        @retval
            Should return @true if any changes in value should be reported.

        @remarks
        - If property uses choice control, and displays a dialog on some choice items,
          then it is preferred to display that dialog in IntToValue instead of OnEvent.
    */
    virtual bool OnEvent( wxPropertyGrid* propgrid, wxWindow* wnd_primary, wxEvent& event );

    /**
        Called after value of a child property has been altered. Must return
        new value of the whole property (after any alterations warrented by
        child's new value).

        Note that this function is usually called at the time that value of
        this property, or given child property, is still pending for change,
        and as such, result of GetValue() or m_value should not be relied
        on.

        Sample pseudo-code implementation:

        @code
        wxVariant MyProperty::ChildChanged( wxVariant& thisValue,
                                            int childIndex,
                                            wxVariant& childValue ) const
        {
            // Acquire reference to actual type of data stored in variant
            // (TFromVariant only exists if wxPropertyGrid's wxVariant-macros
            // were used to create the variant class).
            T& data = TFromVariant(thisValue);

            // Copy childValue into data.
            switch ( childIndex )
            {
                case 0:
                    data.SetSubProp1( childvalue.GetLong() );
                    break;
                case 1:
                    data.SetSubProp2( childvalue.GetString() );
                    break;
                ...
            }

            // Return altered data
            return data;
        }
        @endcode

        @param thisValue
            Value of this property. Changed value should be returned (in
            previous versions of wxPropertyGrid it was only necessary to
            write value back to this argument).
        @param childIndex
            Index of child changed (you can use Item(childIndex) to get
            child property).
        @param childValue
            (Pending) value of the child property.

        @return
            Modified value of the whole property.
    */
    virtual wxVariant ChildChanged( wxVariant& thisValue,
                                    int childIndex,
                                    wxVariant& childValue ) const;

    /**
        Returns pointer to an instance of used editor.
    */
    virtual const wxPGEditor* DoGetEditorClass() const;

    /**
        Returns pointer to the wxValidator that should be used
        with the editor of this property (@NULL for no validator).
        Setting validator explicitly via SetPropertyValidator
        will override this.

        In most situations, code like this should work well
        (macros are used to maintain one actual validator instance,
        so on the second call the function exits within the first
        macro):

        @code

        wxValidator* wxMyPropertyClass::DoGetValidator () const
        {
            WX_PG_DOGETVALIDATOR_ENTRY()

            wxMyValidator* validator = new wxMyValidator(...);

            ... prepare validator...

            WX_PG_DOGETVALIDATOR_EXIT(validator)
        }

        @endcode

        @remarks
        You can get common filename validator by returning
        wxFileProperty::GetClassValidator(). wxDirProperty,
        for example, uses it.
    */
    virtual wxValidator* DoGetValidator () const;

    /**
        Override to paint an image in front of the property value text or drop-down
        list item (but only if wxPGProperty::OnMeasureImage is overridden as well).

        If property's OnMeasureImage() returns size that has height != 0 but less than
        row height ( < 0 has special meanings), wxPropertyGrid calls this method to
        draw a custom image in a limited area in front of the editor control or
        value text/graphics, and if control has drop-down list, then the image is
        drawn there as well (even in the case OnMeasureImage() returned higher height
        than row height).

        NOTE: Following applies when OnMeasureImage() returns a "flexible" height (
        using wxPG_FLEXIBLE_SIZE(W,H) macro), which implies variable height items:
        If rect.x is < 0, then this is a measure item call, which means that
        dc is invalid and only thing that should be done is to set paintdata.m_drawnHeight
        to the height of the image of item at index paintdata.m_choiceItem. This call
        may be done even as often as once every drop-down popup show.

        @param dc
        wxDC to paint on.
        @param rect
        Box reserved for custom graphics. Includes surrounding rectangle, if any.
        If x is < 0, then this is a measure item call (see above).
        @param paintdata
        wxPGPaintData structure with much useful data about painted item.
        @code
        struct wxPGPaintData
        {
            // wxPropertyGrid.
            const wxPropertyGrid*   m_parent;

            // Normally -1, otherwise index to drop-down list item that has to be drawn.
            int                     m_choiceItem;

            // Set to drawn width in OnCustomPaint (optional).
            int                     m_drawnWidth;

            // In a measure item call, set this to the height of item at m_choiceItem index
            int                     m_drawnHeight;
        };
        @endcode

        @remarks
            - You can actually exceed rect width, but if you do so then paintdata.m_drawnWidth
              must be set to the full width drawn in pixels.
            - Due to technical reasons, rect's height will be default even if custom height
              was reported during measure call.
            - Brush is guaranteed to be default background colour. It has been already used to
              clear the background of area being painted. It can be modified.
            - Pen is guaranteed to be 1-wide 'black' (or whatever is the proper colour) pen for
              drawing framing rectangle. It can be changed as well.

        @see ValueToString()
    */
    virtual void OnCustomPaint( wxDC& dc, const wxRect& rect, wxPGPaintData& paintdata );

    /**
        Returns used wxPGCellRenderer instance for given property column (label=0, value=1).

        Default implementation returns editor's renderer for all columns.
    */
    virtual wxPGCellRenderer* GetCellRenderer( int column ) const;

    /**
        Returns which choice is currently selected. Only applies to properties
        which have choices.

        Needs to reimplemented in derived class if property value does not
        map directly to a choice. Integer as index, bool, and string usually do.
    */
    virtual int GetChoiceSelection() const;

    /**
        Refresh values of child properties. Automatically called after value is set.
    */
    virtual void RefreshChildren();

    /**
        Reimplement this member function to add special handling for
        attributes of this property.

        @return Return @false to have the attribute automatically stored in
                m_attributes. Default implementation simply does that and
                nothing else.

        @remarks To actually set property attribute values from the
                 application, use wxPGProperty::SetAttribute() instead.
    */
    virtual bool DoSetAttribute( const wxString& name, wxVariant& value );

    /**
        Returns value of an attribute.

        Override if custom handling of attributes is needed.

        Default implementation simply return @NULL variant.
    */
    virtual wxVariant DoGetAttribute( const wxString& name ) const;

    /**
        Returns instance of a new wxPGEditorDialogAdapter instance, which is
        used when user presses the (optional) button next to the editor control;

        Default implementation returns @NULL (ie. no action is generated when
        button is pressed).
    */
    virtual wxPGEditorDialogAdapter* GetEditorDialog() const;

    /**
        Called whenever validation has failed with given pending value.

        @remarks If you implement this in your custom property class, please
                 remember to call the baser implementation as well, since they
                 may use it to revert property into pre-change state.
    */
    virtual void OnValidationFailure( wxVariant& pendingValue );

    /**
        Append a new choice to property's list of choices.

        @param label
            Label for added choice.

        @param value
            Value for new choice. Do not specify if you wish this
            to equal choice index.

        @return
            Index to added choice.
    */
    int AddChoice( const wxString& label, int value = wxPG_INVALID_VALUE );

    /**
        Adds a private child property.

        @deprecated Use AddPrivateChild() instead.

        @see AddPrivateChild()
    */
    wxDEPRECATED( void AddChild( wxPGProperty* prop ) );

    /**
        Adds a private child property. If you use this instead of
        wxPropertyGridInterface::Insert() or
        wxPropertyGridInterface::AppendIn(), then property's parental
        type will automatically be set up to wxPG_PROP_AGGREGATE. In other
        words, all properties of this property will become private.
    */
    void AddPrivateChild( wxPGProperty* prop );

    /**
        Adapts list variant into proper value using consecutive
        ChildChanged() calls.
    */
    void AdaptListToValue( wxVariant& list, wxVariant* value ) const;

    /**
        Use this member function to add independent (ie. regular) children to
        a property.

        @return Appended childProperty.

        @remarks wxPropertyGrid is not automatically refreshed by this
                function.

        @see InsertChild(), AddPrivateChild()
    */
    wxPGProperty* AppendChild( wxPGProperty* childProperty );

    /**
        Determines, recursively, if all children are not unspecified.

        @param pendingList
            Assumes members in this wxVariant list as pending
            replacement values.
    */
    bool AreAllChildrenSpecified( wxVariant* pendingList = NULL ) const;

    /**
        Returns @true if children of this property are component values (for instance,
        points size, face name, and is_underlined are component values of a font).
    */
    bool AreChildrenComponents() const;

    /**
        Sets or clears given property flag.

        @see propgrid_propflags
    */
    void ChangeFlag( wxPGPropertyFlags flag, bool set );

    /**
        Deletes children of the property.
    */
    void DeleteChildren();

    /**
        Removes entry from property's wxPGChoices and editor control (if it is active).

        If selected item is deleted, then the value is set to unspecified.
    */
    void DeleteChoice( int index );

    /** Deletes all child properties. */
    void Empty();

    /**
        Composes text from values of child properties.
    */
    wxString GenerateComposedValue() const;

    /**
        Returns property attribute value, null variant if not found.
    */
    wxVariant GetAttribute( const wxString& name ) const;

    /** Returns named attribute, as string, if found. Otherwise defVal is returned.
    */
    wxString GetAttribute( const wxString& name, const wxString& defVal ) const;

    /** Returns named attribute, as long, if found. Otherwise defVal is returned.
    */
    long GetAttributeAsLong( const wxString& name, long defVal ) const;

    /** Returns named attribute, as double, if found. Otherwise defVal is returned.
    */
    double GetAttributeAsDouble( const wxString& name, double defVal ) const;

    /**
        Returns attributes as list wxVariant.
    */
    wxVariant GetAttributesAsList() const;

    /**
        Returns editor used for given column. @NULL for no editor.
    */
    const wxPGEditor* GetColumnEditor( int column ) const;

    /** Returns property's base name (ie. parent's name is not added in any case) */
    const wxString& GetBaseName() const;

    /**
        Returns wxPGCell of given column.

        @remarks const version of this member function returns 'default'
                 wxPGCell object if the property itself didn't hold
                 cell data.
    */
    const wxPGCell& GetCell( unsigned int column ) const;

    /**
        Returns wxPGCell of given column, creating one if necessary.
    */
    wxPGCell& GetCell( unsigned int column );

    /**
        Returns wxPGCell of given column, creating one if necessary.
    */
    wxPGCell& GetOrCreateCell( unsigned int column );

    /**
        Returns number of child properties.
    */
    unsigned int GetChildCount() const;

    /**
        Returns height of children, recursively, and
        by taking expanded/collapsed status into account.

        @param lh
            Line height. Pass result of GetGrid()->GetRowHeight() here.

        @param iMax
            Only used (internally) when finding property y-positions.
    */
    int GetChildrenHeight( int lh, int iMax = -1 ) const;

    /**
        Returns read-only reference to property's list of choices.
    */
    const wxPGChoices& GetChoices() const;

    /**
        Returns client data (void*) of a property.
    */
    void* GetClientData() const;

    /** Sets managed client object of a property.
    */
    wxClientData *GetClientObject() const;

    /**
        Returns property's default value. If property's value type is not
        a built-in one, and "DefaultValue" attribute is not defined, then
        this function usually returns Null variant.
    */
    wxVariant GetDefaultValue() const;

    /** Returns property's displayed text.
    */
    wxString GetDisplayedString() const;

    /**
        Returns wxPGEditor that will be used and created when
        property becomes selected. Returns more accurate value
        than DoGetEditorClass().
    */
    const wxPGEditor* GetEditorClass() const;

    /**
        Returns property flags.
    */
    FlagType GetFlags() const;

    /** Returns property grid where property lies. */
    wxPropertyGrid* GetGrid() const;

    /**
        Returns owner wxPropertyGrid, but only if one is currently on a page
        displaying this property.
    */
    wxPropertyGrid* GetGridIfDisplayed() const;

    /**
        Returns property's help or description text.

        @see SetHelpString()
    */
    const wxString& GetHelpString() const;

    /**
        Returns position in parent's array.
    */
    unsigned int GetIndexInParent() const;

    /** Returns property's label. */
    const wxString& GetLabel() const;

    /**
        Returns last visible child property, recursively.
    */
    const wxPGProperty* GetLastVisibleSubItem() const;

    /**
        Returns highest level non-category, non-root parent. Useful when you
        have nested properties with children.

        @remarks If immediate parent is root or category, this will return the
                property itself.
    */
    wxPGProperty* GetMainParent() const;

    /** Returns maximum allowed length of property's text value.
    */
    int GetMaxLength() const;

    /** Returns property's name with all (non-category, non-root) parents. */
    wxString GetName() const;

    /** Return parent of property */
    wxPGProperty* GetParent() const;

    /**
        Returns (direct) child property with given name (or @NULL if not found).
    */
    wxPGProperty* GetPropertyByName( const wxString& name ) const;

    /** Gets assignable version of property's validator. */
    wxValidator* GetValidator() const;

    /**
        Returns property's value.
    */
    wxVariant GetValue() const;

    /**
        Returns bitmap that appears next to value text. Only returns non-@NULL
        bitmap if one was set with SetValueImage().
    */
    wxBitmap* GetValueImage() const;

    /** Returns text representation of property's value.

        @param argFlags
            If 0 (default value), then displayed string is returned.
            If wxPG_FULL_VALUE is set, returns complete, storable string value
            instead of displayable. If wxPG_EDITABLE_VALUE is set, returns
            string value that must be editable in textctrl. If
            wxPG_COMPOSITE_FRAGMENT is set, returns text that is appropriate to
            display as a part of string property's composite text
            representation.

        @remarks In older versions, this function used to be overridden to convert
                 property's value into a string representation. This function is
                 now handled by ValueToString(), and overriding this function now
                 will result in run-time assertion failure.
    */
    virtual wxString GetValueAsString( int argFlags = 0 ) const;

    /** Synonymous to GetValueAsString().

        @deprecated Use GetValueAsString() instead.

        @see GetValueAsString()
    */
    wxDEPRECATED( wxString GetValueString( int argFlags = 0 ) const );

    /**
        Returns value type used by this property.
    */
    wxString GetValueType() const;

    /**
        Returns coordinate to the top y of the property. Note that the
        position of scrollbars is not taken into account.
    */
    int GetY() const;

    /**
        Returns non-zero if property has given flag set.

        @see propgrid_propflags
    */
    FlagType HasFlag( wxPGPropertyFlags flag ) const;

    /**
        Returns @true if property has even one visible child.
    */
    bool HasVisibleChildren() const;

    /**
        Hides or reveals the property.

        @param hide
            @true for hide, @false for reveal.

        @param flags
            By default changes are applied recursively. Set this parameter wxPG_DONT_RECURSE to prevent this.
    */
    bool Hide( bool hide, int flags = wxPG_RECURSE );

    /**
        Returns index of given child property. wxNOT_FOUND if
        given property is not child of this.
    */
    int Index( const wxPGProperty* p ) const;

    /**
        Use this member function to add independent (ie. regular) children to
        a property.

        @return Inserted childProperty.

        @remarks wxPropertyGrid is not automatically refreshed by this
                function.

        @see AppendChild(), AddPrivateChild()
    */
    wxPGProperty* InsertChild( int index, wxPGProperty* childProperty );

    /**
        Inserts a new choice to property's list of choices.

        @param label
            Text for new choice

        @param index
            Insertion position. Use wxNOT_FOUND to append.

        @param value
            Value for new choice. Do not specify if you wish this
            to equal choice index.
    */
    int InsertChoice( const wxString& label, int index, int value = wxPG_INVALID_VALUE );

    /**
        Returns @true if this property is actually a wxPropertyCategory.
    */
    bool IsCategory() const;

    /**
        Returns @true if property is enabled.
    */
    bool IsEnabled() const;

    /**
        Returns @true if property has visible children.
    */
    bool IsExpanded() const;

    /**
        Returns @true if this property is actually a wxRootProperty.
    */
    bool IsRoot() const;

    /**
        Returns @true if candidateParent is some parent of this property.
    */
    bool IsSomeParent( wxPGProperty* candidateParent ) const;

    /**
        Returns true if property has editable wxTextCtrl when selected.

        @remarks Altough disabled properties do not displayed editor, they still
                return @true here as being disabled is considered a temporary
                condition (unlike being read-only or having limited editing enabled).
    */
    bool IsTextEditable() const;

    /**
        Returns @true if property's value is considered unspecified. This
        usually means that value is Null variant.
    */
    bool IsValueUnspecified() const;

    /**
        Returns true if all parents expanded.
    */
    bool IsVisible() const;

    /**
        Returns child property at index i.
    */
    wxPGProperty* Item( unsigned int i ) const;

    /**
        If property's editor is active, then update it's value.
    */
    void RefreshEditor();

    /**
        Sets an attribute for this property.

        @param name
            Text identifier of attribute. See @ref propgrid_property_attributes.

        @param value
            Value of attribute.

        @remarks Setting attribute's value to Null variant will simply remove it
                from property's set of attributes.
    */
    void SetAttribute( const wxString& name, wxVariant value );

    /**
        Sets property's background colour.

        @param colour
            Background colour to use.

        @param flags
            Default is wxPG_RECURSE which causes colour to be set recursively.
            Omit this flag to only set colour for the property in question
            and not any of its children.
    */
    void SetBackgroundColour( const wxColour& colour,
                              int flags = wxPG_RECURSE );

    /**
        Sets editor for a property.

        @param editor
            For builtin editors, use wxPGEditor_X, where X is builtin editor's
            name (TextCtrl, Choice, etc. see wxPGEditor documentation for full list).

        For custom editors, use pointer you received from wxPropertyGrid::RegisterEditorClass().
    */
    void SetEditor( const wxPGEditor* editor );

    /**
        Sets editor for a property, by editor name.
    */
    void SetEditor( const wxString& editorName );

    /**
        Sets cell information for given column.
    */
    void SetCell( int column, const wxPGCell& cell );

    /**
        Sets new set of choices for the property.

        @remarks This operation deselects the property and clears its
                 value.
    */
    bool SetChoices( wxPGChoices& choices );

    /**
        Sets client data (void*) of a property.

        @remarks This untyped client data has to be deleted manually.
    */
    void SetClientData( void* clientData );

    /** Returns client object of a property.
    */
    void SetClientObject(wxClientData* clientObject);

    /**
        Sets selected choice and changes property value.

        Tries to retain value type, although currently if it is not string,
        then it is forced to integer.
    */
    void SetChoiceSelection( int newValue );

    /** Set default value of a property. Synonymous to

        @code
            SetAttribute("DefaultValue", value);
        @endcode
    */
    void SetDefaultValue( wxVariant& value );

    /**
        Sets given property flag.

        @see propgrid_propflags
    */
    void SetFlag( wxPGPropertyFlags flag );

    /**
        Sets or clears given property flag, recursively.

        @see propgrid_propflags
    */
    void SetFlagRecursively( wxPGPropertyFlags flag, bool set );

    /**
        Sets property's help string, which is shown, for example, in
        wxPropertyGridManager's description text box.
    */
    void SetHelpString( const wxString& helpString );

    /**
        Sets property's label.

        @remarks Properties under same parent may have same labels. However,
                property names must still remain unique.
    */
    void SetLabel( const wxString& label );

    /**
        Set max length of text in text editor.
    */
    bool SetMaxLength( int maxLen );

    /**
        Sets property's "is it modified?" flag. Affects children recursively.
    */
    void SetModifiedStatus( bool modified );

    /**
        Sets new (base) name for property.
    */
    void SetName( const wxString& newName );

    /**
        Changes what sort of parent this property is for its children.

        @param flag
            Use one of the following values: wxPG_PROP_MISC_PARENT (for generic
            parents), wxPG_PROP_CATEGORY (for categories), or
            wxPG_PROP_AGGREGATE (for derived property classes with private
            children).

        @remarks You generally do not need to call this function.
    */
    void SetParentalType( int flag );

    /**
        Sets property's text colour.

        @param colour
            Text colour to use.

        @param flags
            Default is wxPG_RECURSE which causes colour to be set recursively.
            Omit this flag to only set colour for the property in question
            and not any of its children.
    */
    void SetTextColour( const wxColour& colour,
                        int flags = wxPG_RECURSE );

    /** Sets wxValidator for a property */
    void SetValidator( const wxValidator& validator );

    /**
        Call this to set value of the property. Unlike methods in wxPropertyGrid,
        this does not automatically update the display.

        @remarks
            Use wxPropertyGrid::ChangePropertyValue() instead if you need to run through
            validation process and send property change event.

            If you need to change property value in event, based on user input, use
            SetValueInEvent() instead.

        @param value
            The value to set.
        @param pList
            Pointer to list variant that contains child values. Used to indicate
            which children should be marked as modified. Usually you just use @NULL.
        @param flags
            wxPG_SETVAL_REFRESH_EDITOR is set by default, to refresh editor
            and redraw properties.
    */
    void SetValue( wxVariant value, wxVariant* pList = NULL,
                   int flags = wxPG_SETVAL_REFRESH_EDITOR );

    /**
        Set wxBitmap in front of the value. This bitmap may be ignored
        by custom cell renderers.
    */
    void SetValueImage( wxBitmap& bmp );

    /**
        Call this function in OnEvent(), OnButtonClick() etc. to change the
        property value based on user input.

        @remarks This method is const since it doesn't actually modify value, but posts
                given variant as pending value, stored in wxPropertyGrid.
    */
    void SetValueInEvent( wxVariant value ) const;

    /**
        Sets property's value to unspecified (ie. Null variant).
    */
    void SetValueToUnspecified();

    /**
        Call with @false in OnSetValue() to cancel value changes after all
        (ie. cancel @true returned by StringToValue() or IntToValue()).
    */
    void SetWasModified( bool set = true );

    /**
        Updates composed values of parent non-category properties, recursively.
        Returns topmost property updated.
    */
    wxPGProperty* UpdateParentValues();

    /**
        Returns @true if containing grid uses wxPG_EX_AUTO_UNSPECIFIED_VALUES.
    */
    bool UsesAutoUnspecified() const;
};


/**
    @class wxPGCell

    Base class for wxPropertyGrid cell information.

    @library{wxpropgrid}
    @category{propgrid}
*/
class wxPGCell : public wxObject
{
public:
    wxPGCell();
    wxPGCell(const wxPGCell& other);
    wxPGCell( const wxString& text,
              const wxBitmap& bitmap = wxNullBitmap,
              const wxColour& fgCol = wxNullColour,
              const wxColour& bgCol = wxNullColour );

    virtual ~wxPGCell();

    const wxPGCellData* GetData() const;

    /**
        Returns @true if this cell has custom text stored within.
    */
    bool HasText() const;

    /**
        Merges valid data from srcCell into this.
    */
    void MergeFrom( const wxPGCell& srcCell );

    void SetText( const wxString& text );
    void SetBitmap( const wxBitmap& bitmap );
    void SetFgCol( const wxColour& col );

    /**
        Sets font of the cell.

        @remarks Because wxPropertyGrid does not support rows of
                 different height, it makes little sense to change
                 size of the font. Therefore it is recommended
                 to use return value of wxPropertyGrid::GetFont()
                 or wxPropertyGrid::GetCaptionFont() as a basis
                 for the font that, after modifications, is passed
                 to this member function.
    */
    void SetFont( const wxFont& font );

    void SetBgCol( const wxColour& col );

    const wxString& GetText() const;
    const wxBitmap& GetBitmap() const;
    const wxColour& GetFgCol() const;

    /**
        Returns font of the cell. If no specific font is set for this
        cell, then the font will be invalid.
    */
    const wxFont& GetFont() const;

    const wxColour& GetBgCol() const;

    wxPGCell& operator=( const wxPGCell& other );
};


/**
    @class wxPGChoices

    Helper class for managing choices of wxPropertyGrid properties.
    Each entry can have label, value, bitmap, text colour, and background
    colour.

    wxPGChoices uses reference counting, similar to other wxWidgets classes.
    This means that assignment operator and copy constructor only copy the
    reference and not the actual data. Use Copy() member function to create a
    real copy.

    @remarks If you do not specify value for entry, index is used.

    @library{wxpropgrid}
    @category{propgrid}
*/
class wxPGChoices
{
public:
    typedef long ValArrItem;

    /**
        Default constructor.
    */
    wxPGChoices();

    /**
        Copy constructor, uses reference counting. To create a real copy,
        use Copy() member function instead.
    */
    wxPGChoices( const wxPGChoices& a );

    /** Constructor. */
    wxPGChoices( const wxChar** labels, const long* values = NULL );

    /** Constructor. */
    wxPGChoices( const wxArrayString& labels, const wxArrayInt& values = wxArrayInt() );

    /** Constructor. */
    wxPGChoices( wxPGChoicesData* data );

    /** Destructor. */
    ~wxPGChoices();

    /**
        Adds to current. If did not have own copies, creates them now. If was empty,
        identical to set except that creates copies.
    */
    void Add( const wxChar** labels, const ValArrItem* values = NULL );

    /** Version that works with wxArrayString. */
    void Add( const wxArrayString& arr, const ValArrItem* values = NULL );

    /** Version that works with wxArrayString and wxArrayInt. */
    void Add( const wxArrayString& arr, const wxArrayInt& arrint );

    /** Adds single item. */
    wxPGChoiceEntry& Add( const wxString& label, int value = wxPG_INVALID_VALUE );

    /** Adds a single item, with bitmap. */
    wxPGChoiceEntry& Add( const wxString& label, const wxBitmap& bitmap,
                          int value = wxPG_INVALID_VALUE );

    /** Adds a single item with full entry information. */
    wxPGChoiceEntry& Add( const wxPGChoiceEntry& entry );

    /** Adds single item, sorted. */
    wxPGChoiceEntry& AddAsSorted( const wxString& label, int value = wxPG_INVALID_VALUE );

    /**
        Assigns choices data, using reference counting. To create a real copy,
        use Copy() member function instead.
    */
    void Assign( const wxPGChoices& a );

    /**
        Assigns data from another set of choices.
    */
    void AssignData( wxPGChoicesData* data );

    /**
        Deletes all items.
    */
    void Clear();

    /**
        Returns a real copy of the choices.
    */
    wxPGChoices Copy() const;

    /**
        Returns labe of item.
    */
    const wxString& GetLabel( unsigned int ind ) const;

    /**
        Returns number of items.
    */
    unsigned int GetCount() const;

    /**
        Returns value of item;
    */
    int GetValue( unsigned int ind ) const;

    /**
        Returns array of values matching the given strings. Unmatching strings
        result in wxPG_INVALID_VALUE entry in array.
    */
    wxArrayInt GetValuesForStrings( const wxArrayString& strings ) const;

    /**
        Returns array of indices matching given strings. Unmatching strings
        are added to 'unmatched', if not @NULL.
    */
    wxArrayInt GetIndicesForStrings( const wxArrayString& strings,
                                     wxArrayString* unmatched = NULL ) const;

    /** Returns property at given virtual y coordinate.
    */
    wxPGProperty* GetItemAtY( unsigned int y ) const;

    /**
        Returns @true if item at given index has a valid value;
    */
    bool HasValue( unsigned int i ) const;

    /**
        Returns index of item with given label.
    */
    int Index( const wxString& label ) const;

    /**
        Returns index of item with given value.
    */
    int Index( int val ) const;

    /**
        Inserts single item.
    */
    wxPGChoiceEntry& Insert( const wxString& label, int index, int value = wxPG_INVALID_VALUE );

    /**
        Inserts a single item with full entry information.
    */
    wxPGChoiceEntry& Insert( const wxPGChoiceEntry& entry, int index );

    /**
        Returns @false if this is a constant empty set of choices,
        which should not be modified.
    */
    bool IsOk() const;

    /**
        Returns item at given index.
    */
    const wxPGChoiceEntry& Item( unsigned int i ) const;

    /**
        Returns item at given index.
    */
    wxPGChoiceEntry& Item( unsigned int i );

    /**
        Removes count items starting at position nIndex.
    */
    void RemoveAt(size_t nIndex, size_t count = 1);

    /**
        Sets contents from lists of strings and values.
    */
    void Set( const wxChar** labels, const long* values = NULL );

    /**
        Sets contents from lists of strings and values.
    */
    void Set( const wxArrayString& labels, const wxArrayInt& values = wxArrayInt() );

    /**
        Creates exclusive copy of current choices.
    */
    void AllocExclusive();

    /**
        Returns array of choice labels.
    */
    wxArrayString GetLabels() const;

    void operator= (const wxPGChoices& a);

    wxPGChoiceEntry& operator[](unsigned int i);
    const wxPGChoiceEntry& operator[](unsigned int i) const;
};

// -----------------------------------------------------------------------

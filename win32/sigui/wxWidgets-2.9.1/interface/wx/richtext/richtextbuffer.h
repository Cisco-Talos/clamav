/////////////////////////////////////////////////////////////////////////////
// Name:        richtext/richtextbuffer.h
// Purpose:     interface of wxRichTextBuffer
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////



/*!
 * File types in wxRichText context.
 */
enum wxRichTextFileType
{
    wxRICHTEXT_TYPE_ANY = 0,
    wxRICHTEXT_TYPE_TEXT,
    wxRICHTEXT_TYPE_XML,
    wxRICHTEXT_TYPE_HTML,
    wxRICHTEXT_TYPE_RTF,
    wxRICHTEXT_TYPE_PDF
};

/*!
 * Flags determining the available space, passed to Layout
 */

#define wxRICHTEXT_FIXED_WIDTH      0x01
#define wxRICHTEXT_FIXED_HEIGHT     0x02
#define wxRICHTEXT_VARIABLE_WIDTH   0x04
#define wxRICHTEXT_VARIABLE_HEIGHT  0x08

// Only lay out the part of the buffer that lies within
// the rect passed to Layout.
#define wxRICHTEXT_LAYOUT_SPECIFIED_RECT 0x10

/*!
 * Flags to pass to Draw
 */

// Ignore paragraph cache optimization, e.g. for printing purposes
// where one line may be drawn higher (on the next page) compared
// with the previous line
#define wxRICHTEXT_DRAW_IGNORE_CACHE    0x01

/*!
 * Flags returned from hit-testing
 */
enum wxRichTextHitTestFlags
{
    /// The point was not on this object
    wxRICHTEXT_HITTEST_NONE =    0x01,

    /// The point was before the position returned from HitTest
    wxRICHTEXT_HITTEST_BEFORE =  0x02,

    /// The point was after the position returned from HitTest
    wxRICHTEXT_HITTEST_AFTER =   0x04,

    /// The point was on the position returned from HitTest
    wxRICHTEXT_HITTEST_ON =      0x08,

    /// The point was on space outside content
    wxRICHTEXT_HITTEST_OUTSIDE = 0x10
};

/*!
 * Flags for GetRangeSize
 */

#define wxRICHTEXT_FORMATTED        0x01
#define wxRICHTEXT_UNFORMATTED      0x02
#define wxRICHTEXT_CACHE_SIZE       0x04
#define wxRICHTEXT_HEIGHT_ONLY      0x08

/*!
 * Flags for SetStyle/SetListStyle
 */

#define wxRICHTEXT_SETSTYLE_NONE            0x00

// Specifies that this operation should be undoable
#define wxRICHTEXT_SETSTYLE_WITH_UNDO       0x01

// Specifies that the style should not be applied if the
// combined style at this point is already the style in question.
#define wxRICHTEXT_SETSTYLE_OPTIMIZE        0x02

// Specifies that the style should only be applied to paragraphs,
// and not the content. This allows content styling to be
// preserved independently from that of e.g. a named paragraph style.
#define wxRICHTEXT_SETSTYLE_PARAGRAPHS_ONLY 0x04

// Specifies that the style should only be applied to characters,
// and not the paragraph. This allows content styling to be
// preserved independently from that of e.g. a named paragraph style.
#define wxRICHTEXT_SETSTYLE_CHARACTERS_ONLY 0x08

// For SetListStyle only: specifies starting from the given number, otherwise
// deduces number from existing attributes
#define wxRICHTEXT_SETSTYLE_RENUMBER        0x10

// For SetListStyle only: specifies the list level for all paragraphs, otherwise
// the current indentation will be used
#define wxRICHTEXT_SETSTYLE_SPECIFY_LEVEL   0x20

// Resets the existing style before applying the new style
#define wxRICHTEXT_SETSTYLE_RESET           0x40

// Removes the given style instead of applying it
#define wxRICHTEXT_SETSTYLE_REMOVE          0x80

/*!
 * Flags for text insertion
 */

#define wxRICHTEXT_INSERT_NONE                              0x00
#define wxRICHTEXT_INSERT_WITH_PREVIOUS_PARAGRAPH_STYLE     0x01
#define wxRICHTEXT_INSERT_INTERACTIVE                       0x02

// A special flag telling the buffer to keep the first paragraph style
// as-is, when deleting a paragraph marker. In future we might pass a
// flag to InsertFragment and DeleteRange to indicate the appropriate mode.
#define wxTEXT_ATTR_KEEP_FIRST_PARA_STYLE   0x10000000

/*!
 * Default superscript/subscript font multiplication factor
 */

#define wxSCRIPT_MUL_FACTOR             1.5


/**
    @class wxRichTextBuffer

    This class represents the whole buffer associated with a wxRichTextCtrl.

    @library{wxrichtext}
    @category{richtext}

    @see wxTextAttr, wxRichTextCtrl
*/
class wxRichTextBuffer : public wxRichTextParagraphLayoutBox
{
public:
    /**
        Default constructor.
    */
    wxRichTextBuffer();

    /**
        Copy ctor.
    */
    wxRichTextBuffer(const wxRichTextBuffer& obj);

    /**
        Destructor.
    */
    virtual ~wxRichTextBuffer();

    /**
        Adds an event handler to the buffer's list of handlers.

        A buffer associated with a control has the control as the only event handler,
        but the application is free to add more if further notification is required.
        All handlers are notified of an event originating from the buffer, such as
        the replacement of a style sheet during loading.

        The buffer never deletes any of the event handlers, unless RemoveEventHandler()
        is called with @true as the second argument.
    */
    bool AddEventHandler(wxEvtHandler* handler);

    /**
        Adds a file handler.
    */
    static void AddHandler(wxRichTextFileHandler* handler);

    /**
        Adds a paragraph of text.
    */
    virtual wxRichTextRange AddParagraph(const wxString& text,
                                         wxTextAttr* paraStyle = 0);

    /**
        Returns @true if the buffer is currently collapsing commands into a single
        notional command.
    */
    virtual bool BatchingUndo() const;

    /**
        Begins using alignment.
    */
    bool BeginAlignment(wxTextAttrAlignment alignment);

    /**
        Begins collapsing undo/redo commands. Note that this may not work properly
        if combining commands that delete or insert content, changing ranges for
        subsequent actions.

        @a cmdName should be the name of the combined command that will appear
        next to Undo and Redo in the edit menu.
    */
    virtual bool BeginBatchUndo(const wxString& cmdName);

    /**
        Begin applying bold.
    */
    bool BeginBold();

    /**
        Begins applying the named character style.
    */
    bool BeginCharacterStyle(const wxString& characterStyle);

    /**
        Begins using this font.
    */
    bool BeginFont(const wxFont& font);

    /**
        Begins using the given point size.
    */
    bool BeginFontSize(int pointSize);

    /**
        Begins using italic.
    */
    bool BeginItalic();

    /**
        Begin using @a leftIndent for the left indent, and optionally @a leftSubIndent for
        the sub-indent. Both are expressed in tenths of a millimetre.

        The sub-indent is an offset from the left of the paragraph, and is used for all
        but the first line in a paragraph. A positive value will cause the first line to appear
        to the left of the subsequent lines, and a negative value will cause the first line to be
        indented relative to the subsequent lines.
    */
    bool BeginLeftIndent(int leftIndent, int leftSubIndent = 0);

    /**
        Begins line spacing using the specified value. @e spacing is a multiple, where
        10 means single-spacing, 15 means 1.5 spacing, and 20 means double spacing.

        The ::wxTextAttrLineSpacing enumeration values are defined for convenience.
    */
    bool BeginLineSpacing(int lineSpacing);

    /**
        Begins using a specified list style.
        Optionally, you can also pass a level and a number.
    */
    bool BeginListStyle(const wxString& listStyle, int level = 1,
                        int number = 1);

    /**
        Begins a numbered bullet.

        This call will be needed for each item in the list, and the
        application should take care of incrementing the numbering.

        @a bulletNumber is a number, usually starting with 1.
        @a leftIndent and @a leftSubIndent are values in tenths of a millimetre.
        @a bulletStyle is a bitlist of the following values:

        wxRichTextBuffer uses indentation to render a bulleted item.
        The left indent is the distance between the margin and the bullet.
        The content of the paragraph, including the first line, starts
        at leftMargin + leftSubIndent.
        So the distance between the left edge of the bullet and the
        left of the actual paragraph is leftSubIndent.
    */
    bool BeginNumberedBullet(int bulletNumber, int leftIndent,
                             int leftSubIndent,
                             int bulletStyle = wxTEXT_ATTR_BULLET_STYLE_ARABIC|wxTEXT_ATTR_BULLET_STYLE_PERIOD);

    /**
        Begins paragraph spacing; pass the before-paragraph and after-paragraph spacing
        in tenths of a millimetre.
    */
    bool BeginParagraphSpacing(int before, int after);

    /**
        Begins applying the named paragraph style.
    */
    bool BeginParagraphStyle(const wxString& paragraphStyle);

    /**
        Begins a right indent, specified in tenths of a millimetre.
    */
    bool BeginRightIndent(int rightIndent);

    /**
        Begins applying a standard bullet, using one of the standard bullet names
        (currently @c standard/circle or @c standard/square.

        See BeginNumberedBullet() for an explanation of how indentation is used to
        render the bulleted paragraph.
    */
    bool BeginStandardBullet(const wxString& bulletName,
                             int leftIndent,
                             int leftSubIndent,
                             int bulletStyle = wxTEXT_ATTR_BULLET_STYLE_STANDARD);

    /**
        Begins using a specified style.
    */
    virtual bool BeginStyle(const wxTextAttr& style);

    /**
        Begins suppressing undo/redo commands. The way undo is suppressed may be
        implemented differently by each command.
        If not dealt with by a command implementation, then it will be implemented
        automatically by not storing the command in the undo history when the
        action is submitted to the command processor.
    */
    virtual bool BeginSuppressUndo();

    /**
        Begins applying a symbol bullet, using a character from the current font.

        See BeginNumberedBullet() for an explanation of how indentation is used
        to render the bulleted paragraph.
    */
    bool BeginSymbolBullet(const wxString& symbol, int leftIndent,
                           int leftSubIndent,
                           int bulletStyle = wxTEXT_ATTR_BULLET_STYLE_SYMBOL);

    /**
        Begins using the specified text foreground colour.
    */
    bool BeginTextColour(const wxColour& colour);

    /**
        Begins applying wxTEXT_ATTR_URL to the content.

        Pass a URL and optionally, a character style to apply, since it is common
        to mark a URL with a familiar style such as blue text with underlining.
    */
    bool BeginURL(const wxString& url,
                  const wxString& characterStyle = wxEmptyString);

    /**
        Begins using underline.
    */
    bool BeginUnderline();

    /**
        Returns @true if content can be pasted from the clipboard.
    */
    virtual bool CanPasteFromClipboard() const;

    /**
        Cleans up the file handlers.
    */
    static void CleanUpHandlers();

    /**
        Clears the buffer.
    */
    virtual void Clear();

    /**
        Clears the list style from the given range, clearing list-related attributes
        and applying any named paragraph style associated with each paragraph.

        @a flags is a bit list of the following:
        - wxRICHTEXT_SETSTYLE_WITH_UNDO: specifies that this command will be undoable.

        @see SetListStyle(), PromoteList(), NumberList()
    */
    virtual bool ClearListStyle(const wxRichTextRange& range,
                        int flags = wxRICHTEXT_SETSTYLE_WITH_UNDO);

    /**
        Clears the style stack.
    */
    virtual void ClearStyleStack();

    /**
        Clones the object.
    */
    virtual wxRichTextObject* Clone() const;

    /**
        Copies the given buffer.
    */
    void Copy(const wxRichTextBuffer& obj);

    /**
        Copy the given range to the clipboard.
    */
    virtual bool CopyToClipboard(const wxRichTextRange& range);

    /**
        Submits a command to delete the given range.
    */
    bool DeleteRangeWithUndo(const wxRichTextRange& range,
                             wxRichTextCtrl* ctrl);

    //@{
    /**
        Dumps the contents of the buffer for debugging purposes.
    */
    void Dump();
    void Dump(wxTextOutputStream& stream);
    //@}

    /**
        Ends alignment.
    */
    bool EndAlignment();

    /**
        Ends all styles that have been started with a Begin... command.
    */
    virtual bool EndAllStyles();

    /**
        Ends collapsing undo/redo commands, and submits the combined command.
    */
    virtual bool EndBatchUndo();

    /**
        Ends using bold.
    */
    bool EndBold();

    /**
        Ends using the named character style.
    */
    bool EndCharacterStyle();

    /**
        Ends using a font.
    */
    bool EndFont();

    /**
        Ends using a point size.
    */
    bool EndFontSize();

    /**
        Ends using italic.
    */
    bool EndItalic();

    /**
        Ends using a left indent.
    */
    bool EndLeftIndent();

    /**
        Ends using a line spacing.
    */
    bool EndLineSpacing();

    /**
        Ends using a specified list style.
    */
    bool EndListStyle();

    /**
        Ends a numbered bullet.
    */
    bool EndNumberedBullet();

    /**
        Ends paragraph spacing.
    */
    bool EndParagraphSpacing();

    /**
        Ends applying a named character style.
    */
    bool EndParagraphStyle();

    /**
        Ends using a right indent.
    */
    bool EndRightIndent();

    /**
        Ends using a standard bullet.
    */
    bool EndStandardBullet();

    /**
        Ends the current style.
    */
    virtual bool EndStyle();

    /**
        Ends suppressing undo/redo commands.
    */
    virtual bool EndSuppressUndo();

    /**
        Ends using a symbol bullet.
    */
    bool EndSymbolBullet();

    /**
        Ends using a text foreground colour.
    */
    bool EndTextColour();

    /**
        Ends applying a URL.
    */
    bool EndURL();

    /**
        Ends using underline.
    */
    bool EndUnderline();

    /**
        Finds a handler by type.
    */
    static wxRichTextFileHandler* FindHandler(wxRichTextFileType imageType);

    /**
        Finds a handler by extension and type.
    */
    static wxRichTextFileHandler* FindHandler(const wxString& extension, wxRichTextFileType imageType);

    /**
        Finds a handler by name.
    */
    static wxRichTextFileHandler* FindHandler(const wxString& name);

    /**
        Finds a handler by filename or, if supplied, type.
    */
    static wxRichTextFileHandler* FindHandlerFilenameOrType(const wxString& filename, wxRichTextFileType imageType);

    /**
        Gets the basic (overall) style.

        This is the style of the whole buffer before further styles are applied,
        unlike the default style, which only affects the style currently being
        applied (for example, setting the default style to bold will cause
        subsequently inserted text to be bold).
    */
    virtual const wxTextAttr& GetBasicStyle() const;

    /**
        Gets the collapsed command.
    */
    virtual wxRichTextCommand* GetBatchedCommand() const;

    /**
        Gets the command processor.
        A text buffer always creates its own command processor when it is initialized.
    */
    wxCommandProcessor* GetCommandProcessor() const;

    /**
        Returns the current default style, affecting the style currently being applied
        (for example, setting the default style to bold will cause subsequently
        inserted text to be bold).
    */
    virtual const wxTextAttr& GetDefaultStyle() const;

    /**
        Gets a wildcard incorporating all visible handlers.
        If @a types is present, it will be filled with the file type corresponding
        to each filter. This can be used to determine the type to pass to LoadFile()
        given a selected filter.
    */
    static wxString GetExtWildcard(bool combine = false, bool save = false,
                                   wxArrayInt* types = NULL);

    /**
        Returns the list of file handlers.
    */
    static wxList& GetHandlers();

    /**
        Returns the object to be used to render certain aspects of the content, such as
        bullets.
    */
    static wxRichTextRenderer* GetRenderer();

    /**
        Gets the attributes at the given position.

        This function gets the combined style - that is, the style you see on the
        screen as a result of combining base style, paragraph style and character
        style attributes. To get the character or paragraph style alone,
        use GetUncombinedStyle().
    */
    virtual bool GetStyle(long position, wxTextAttr& style);

    /**
        This function gets a style representing the common, combined attributes in the
        given range.
        Attributes which have different values within the specified range will not be
        included the style flags.

        The function is used to get the attributes to display in the formatting dialog:
        the user can edit the attributes common to the selection, and optionally specify the
        values of further attributes to be applied uniformly.

        To apply the edited attributes, you can use SetStyle() specifying
        the wxRICHTEXT_SETSTYLE_OPTIMIZE flag, which will only apply attributes that
        are different from the @e combined attributes within the range.
        So, the user edits the effective, displayed attributes for the range,
        but his choice won't be applied unnecessarily to content. As an example,
        say the style for a paragraph specifies bold, but the paragraph text doesn't
        specify a weight.
        The combined style is bold, and this is what the user will see on-screen and
        in the formatting dialog. The user now specifies red text, in addition to bold.
        When applying with SetStyle(), the content font weight attributes won't be
        changed to bold because this is already specified by the paragraph.
        However the text colour attributes @e will be changed to show red.
    */
    virtual bool GetStyleForRange(const wxRichTextRange& range,
                                  wxTextAttr& style);

    /**
        Returns the current style sheet associated with the buffer, if any.
    */
    virtual wxRichTextStyleSheet* GetStyleSheet() const;

    /**
        Get the size of the style stack, for example to check correct nesting.
    */
    virtual size_t GetStyleStackSize() const;

    /**
        Gets the attributes at the given position.

        This function gets the @e uncombined style - that is, the attributes associated
        with the paragraph or character content, and not necessarily the combined
        attributes you see on the screen. To get the combined attributes, use GetStyle().
        If you specify (any) paragraph attribute in @e style's flags, this function
        will fetch the paragraph attributes.
        Otherwise, it will return the character attributes.
    */
    virtual bool GetUncombinedStyle(long position, wxTextAttr& style);

    /**
        Finds the text position for the given position, putting the position in
        @a textPosition if one is found.
        @a pt is in logical units (a zero y position is at the beginning of the buffer).

        @return One of the ::wxRichTextHitTestFlags values.
    */
    virtual int HitTest(wxDC& dc, const wxPoint& pt, long& textPosition);

    /**
        Initialisation.
    */
    void Init();

    /**
        Initialises the standard handlers.
        Currently, only the plain text loading/saving handler is initialised by default.
    */
    static void InitStandardHandlers();

    /**
        Inserts a handler at the front of the list.
    */
    static void InsertHandler(wxRichTextFileHandler* handler);

    /**
        Submits a command to insert the given image.
    */
    bool InsertImageWithUndo(long pos, const wxRichTextImageBlock& imageBlock,
                             wxRichTextCtrl* ctrl, int flags = 0);

    /**
        Submits a command to insert a newline.
    */
    bool InsertNewlineWithUndo(long pos, wxRichTextCtrl* ctrl, int flags = 0);

    /**
        Submits a command to insert the given text.
    */
    bool InsertTextWithUndo(long pos, const wxString& text,
                            wxRichTextCtrl* ctrl, int flags = 0);

    /**
        Returns @true if the buffer has been modified.
    */
    bool IsModified() const;

    /**
        Loads content from a stream.
    */
    virtual bool LoadFile(wxInputStream& stream,
                          wxRichTextFileType type = wxRICHTEXT_TYPE_ANY);

    /**
        Loads content from a file.
    */
    virtual bool LoadFile(const wxString& filename,
                          wxRichTextFileType type = wxRICHTEXT_TYPE_ANY);

    /**
        Marks the buffer as modified or unmodified.
    */
    void Modify(bool modify = true);

    //@{
    /**
        Numbers the paragraphs in the given range.

        Pass flags to determine how the attributes are set.
        Either the style definition or the name of the style definition (in the current
        sheet) can be passed.

        @a flags is a bit list of the following:
        - wxRICHTEXT_SETSTYLE_WITH_UNDO: specifies that this command will be undoable.
        - wxRICHTEXT_SETSTYLE_RENUMBER: specifies that numbering should start from
          @a startFrom, otherwise existing attributes are used.
        - wxRICHTEXT_SETSTYLE_SPECIFY_LEVEL: specifies that @a listLevel should be used
          as the level for all paragraphs, otherwise the current indentation will be used.

        @see SetListStyle(), PromoteList(), ClearListStyle()
    */
    bool NumberList(const wxRichTextRange& range,
                    const wxRichTextListStyleDefinition* style,
                    int flags = wxRICHTEXT_SETSTYLE_WITH_UNDO,
                    int startFrom = -1,
                    int listLevel = -1);
    bool Number(const wxRichTextRange& range,
                const wxString& styleName,
                int flags = wxRICHTEXT_SETSTYLE_WITH_UNDO,
                int startFrom = -1,
                int listLevel = -1);
    //@}

    /**
        Pastes the clipboard content to the buffer at the given position.
    */
    virtual bool PasteFromClipboard(long position);

    //@{
    /**
        Promotes or demotes the paragraphs in the given range.

        A positive @a promoteBy produces a smaller indent, and a negative number
        produces a larger indent. Pass flags to determine how the attributes are set.
        Either the style definition or the name of the style definition (in the current
        sheet) can be passed.

        @a flags is a bit list of the following:
        - wxRICHTEXT_SETSTYLE_WITH_UNDO: specifies that this command will be undoable.
        - wxRICHTEXT_SETSTYLE_RENUMBER: specifies that numbering should start from
          @a startFrom, otherwise existing attributes are used.
        - wxRICHTEXT_SETSTYLE_SPECIFY_LEVEL: specifies that @a listLevel should be used
          as the level for all paragraphs, otherwise the current indentation will be used.

        @see SetListStyle(), SetListStyle(), ClearListStyle()
    */
    bool PromoteList(int promoteBy, const wxRichTextRange& range,
                     const wxRichTextListStyleDefinition* style,
                     int flags = wxRICHTEXT_SETSTYLE_WITH_UNDO,
                     int listLevel = -1);
    bool PromoteList(int promoteBy, const wxRichTextRange& range,
                     const wxString& styleName,
                     int flags = wxRICHTEXT_SETSTYLE_WITH_UNDO,
                     int listLevel = -1);
    //@}

    /**
        Removes an event handler from the buffer's list of handlers, deleting the
        object if @a deleteHandler is @true.
    */
    bool RemoveEventHandler(wxEvtHandler* handler,
                            bool deleteHandler = false);

    /**
        Removes a handler.
    */
    static bool RemoveHandler(const wxString& name);

    /**
        Clears the buffer, adds a new blank paragraph, and clears the command history.
    */
    virtual void ResetAndClearCommands();

    /**
        Saves content to a stream.
    */
    virtual bool SaveFile(wxOutputStream& stream,
                          wxRichTextFileType type = wxRICHTEXT_TYPE_ANY);

    /**
        Saves content to a file.
    */
    virtual bool SaveFile(const wxString& filename,
                          wxRichTextFileType type = wxRICHTEXT_TYPE_ANY);

    /**
        Sets the basic (overall) style. This is the style of the whole
        buffer before further styles are applied, unlike the default style, which
        only affects the style currently being applied (for example, setting the default
        style to bold will cause subsequently inserted text to be bold).
    */
    virtual void SetBasicStyle(const wxTextAttr& style);

    /**
        Sets the default style, affecting the style currently being applied
        (for example, setting the default style to bold will cause subsequently
        inserted text to be bold).

        This is not cumulative - setting the default style will replace the previous
        default style.
    */
    virtual bool SetDefaultStyle(const wxTextAttr& style);

    //@{
    /**
        Sets the list attributes for the given range, passing flags to determine how
        the attributes are set.
        Either the style definition or the name of the style definition (in the current
        sheet) can be passed.

        @a flags is a bit list of the following:
        - wxRICHTEXT_SETSTYLE_WITH_UNDO: specifies that this command will be undoable.
        - wxRICHTEXT_SETSTYLE_RENUMBER: specifies that numbering should start from
          @a startFrom, otherwise existing attributes are used.
        - wxRICHTEXT_SETSTYLE_SPECIFY_LEVEL: specifies that @a listLevel should be used
          as the level for all paragraphs, otherwise the current indentation will be used.

        @see NumberList(), PromoteList(), ClearListStyle().
    */
    bool SetListStyle(const wxRichTextRange& range,
                      const wxRichTextListStyleDefinition* style,
                      int flags = wxRICHTEXT_SETSTYLE_WITH_UNDO,
                      int startFrom = -1,
                      int listLevel = -1);
    bool SetListStyle(const wxRichTextRange& range,
                      const wxString& styleName,
                      int flags = wxRICHTEXT_SETSTYLE_WITH_UNDO,
                      int startFrom = -1,
                      int listLevel = -1);
    //@}

    /**
        Sets @a renderer as the object to be used to render certain aspects of the
        content, such as bullets.

        You can override default rendering by deriving a new class from
        wxRichTextRenderer or wxRichTextStdRenderer, overriding one or more
        virtual functions, and setting an instance of the class using this function.
    */
    static void SetRenderer(wxRichTextRenderer* renderer);

    /**
        Sets the attributes for the given range. Pass flags to determine how the
        attributes are set.

        The end point of range is specified as the last character position of the span
        of text. So, for example, to set the style for a character at position 5,
        use the range (5,5).
        This differs from the wxRichTextCtrl API, where you would specify (5,6).

        @a flags may contain a bit list of the following values:
        - wxRICHTEXT_SETSTYLE_NONE: no style flag.
        - wxRICHTEXT_SETSTYLE_WITH_UNDO: specifies that this operation should be
          undoable.
        - wxRICHTEXT_SETSTYLE_OPTIMIZE: specifies that the style should not be applied
          if the combined style at this point is already the style in question.
        - wxRICHTEXT_SETSTYLE_PARAGRAPHS_ONLY: specifies that the style should only be
          applied to paragraphs, and not the content.
          This allows content styling to be preserved independently from that
          of e.g. a named paragraph style.
        - wxRICHTEXT_SETSTYLE_CHARACTERS_ONLY: specifies that the style should only be
          applied to characters, and not the paragraph.
          This allows content styling to be preserved independently from that
          of e.g. a named paragraph style.
        - wxRICHTEXT_SETSTYLE_RESET: resets (clears) the existing style before applying
          the new style.
        - wxRICHTEXT_SETSTYLE_REMOVE: removes the specified style.
          Only the style flags are used in this operation.
    */
    virtual bool SetStyle(const wxRichTextRange& range, const wxTextAttr& style,
                          int flags = wxRICHTEXT_SETSTYLE_WITH_UNDO);

    /**
        Sets the current style sheet, if any.

        This will allow the application to use named character and paragraph
        styles found in the style sheet.
    */
    void SetStyleSheet(wxRichTextStyleSheet* styleSheet);

    /**
        Submit an action immediately, or delay it according to whether collapsing is on.
    */
    virtual bool SubmitAction(wxRichTextAction* action);

    /**
        Returns @true if undo suppression is currently on.
    */
    virtual bool SuppressingUndo() const;
};



/**
    @class wxRichTextFileHandler

    This is the base class for file handlers, for loading and/or saving content
    associated with a wxRichTextBuffer.

    @library{wxrichtext}
    @category{richtext}
*/
class wxRichTextFileHandler : public wxObject
{
public:
    /**
        Constructor.
    */
    wxRichTextFileHandler(const wxString& name = wxEmptyString,
                          const wxString& ext = wxEmptyString,
                          int type = 0);

    /**
        Override this function and return @true if this handler can we handle
        @a filename.

        By default, this function checks the extension.
    */
    virtual bool CanHandle(const wxString& filename) const;

    /**
        Override and return @true if this handler can load content.
    */
    virtual bool CanLoad() const;

    /**
        Override and return @true if this handler can save content.
    */
    virtual bool CanSave() const;

    /**
        Returns the encoding associated with the handler (if any).
    */
    const wxString& GetEncoding() const;

    /**
        Returns the extension associated with the handler.
    */
    wxString GetExtension() const;

    /**
        Returns flags that change the behaviour of loading or saving.

        See the documentation for each handler class to see what flags are
        relevant for each handler.
    */
    int GetFlags() const;

    /**
        Returns the name of the handler.
    */
    wxString GetName() const;

    /**
        Returns the type of the handler.
    */
    int GetType() const;

    /**
        Returns @true if this handler should be visible to the user.
    */
    virtual bool IsVisible() const;

    //@{
    /**
        Loads content from a stream or file.
        Not all handlers will implement file loading.
    */
    bool LoadFile(wxRichTextBuffer* buffer, wxInputStream& stream);
    bool LoadFile(wxRichTextBuffer* buffer, const wxString& filename);
    //@}

    //@{
    /**
        Saves content to a stream or file.
        Not all handlers will implement file saving.
    */
    bool SaveFile(wxRichTextBuffer* buffer, wxOutputStream& stream);
    bool SaveFile(wxRichTextBuffer* buffer, const wxString& filename);
    //@}

    /**
        Sets the encoding to use when saving a file.
        If empty, a suitable encoding is chosen.
    */
    void SetEncoding(const wxString& encoding);

    /**
        Sets the default extension to recognise.
    */
    void SetExtension(const wxString& ext);

    /**
        Sets flags that change the behaviour of loading or saving.
        See the documentation for each handler class to see what flags are relevant
        for each handler.

        You call this function directly if you are using a file handler explicitly
        (without going through the text control or buffer LoadFile/SaveFile API).
        Or, you can call the control or buffer's SetHandlerFlags function to set
        the flags that will be used for subsequent load and save operations.
    */
    void SetFlags(int flags);

    /**
        Sets the name of the handler.
    */
    void SetName(const wxString& name);

    /**
        Sets the handler type.
    */
    void SetType(int type);

    /**
        Sets whether the handler should be visible to the user (via the application's
        load and save dialogs).
    */
    virtual void SetVisible(bool visible);

protected:
    /**
        Override to load content from @a stream into @a buffer.
    */
    virtual bool DoLoadFile(wxRichTextBuffer* buffer,
                            wxInputStream& stream) = 0;

    /**
        Override to save content to @a stream from @a buffer.
    */
    virtual bool DoSaveFile(wxRichTextBuffer* buffer,
                            wxOutputStream& stream) = 0;
};



/**
    @class wxRichTextRange

    This class stores beginning and end positions for a range of data.

    @library{wxrichtext}
    @category{richtext}
*/
class wxRichTextRange
{
public:
    //@{
    /**
        Constructors.
    */
    wxRichTextRange(long start, long end);
    wxRichTextRange(const wxRichTextRange& range);
    wxRichTextRange();
    //@}

    /**
        Destructor.
    */
    ~wxRichTextRange();

    /**
        Returns @true if the given position is within this range.
        Does not match if the range is empty.
    */
    bool Contains(long pos) const;

    /**
        Converts the internal range, which uses the first and last character positions
        of the range, to the API-standard range, whose end is one past the last
        character in the range.
        In other words, one is added to the end position.
    */
    wxRichTextRange FromInternal() const;

    /**
        Returns the end position.
    */
    long GetEnd() const;

    /**
        Returns the length of the range.
    */
    long GetLength() const;

    /**
        Returns the start of the range.
    */
    long GetStart() const;

    /**
        Returns @true if this range is completely outside @e range.
    */
    bool IsOutside(const wxRichTextRange& range) const;

    /**
        Returns @true if this range is completely within @e range.
    */
    bool IsWithin(const wxRichTextRange& range) const;

    /**
        Limits this range to be within @e range.
    */
    bool LimitTo(const wxRichTextRange& range);

    /**
        Sets the end of the range.
    */
    void SetEnd(long end);

    /**
        Sets the range.
    */
    void SetRange(long start, long end);

    /**
        Sets the start of the range.
    */
    void SetStart(long start);

    /**
        Swaps the start and end.
    */
    void Swap();

    /**
        Converts the API-standard range, whose end is one past the last character in
        the range, to the internal form, which uses the first and last character
        positions of the range.
        In other words, one is subtracted from the end position.
    */
    wxRichTextRange ToInternal() const;

    /**
        Adds @a range to this range.
    */
    wxRichTextRange operator+(const wxRichTextRange& range) const;

    /**
        Subtracts @a range from this range.
    */
    wxRichTextRange operator-(const wxRichTextRange& range) const;

    /**
        Assigns @a range to this range.
    */
    void operator=(const wxRichTextRange& range);

    /**
        Returns @true if @a range is the same as this range.
    */
    bool operator==(const wxRichTextRange& range) const;
};


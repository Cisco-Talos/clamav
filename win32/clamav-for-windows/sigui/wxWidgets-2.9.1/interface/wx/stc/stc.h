/////////////////////////////////////////////////////////////////////////////
// Name:        stc/stc.h
// Purpose:     interface of wxStyledTextEvent
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxStyledTextEvent

    The type of events sent from wxStyledTextCtrl.

    @todo list styled text ctrl events.

    @library{wxbase}
    @category{events,stc}
*/
class wxStyledTextEvent : public wxCommandEvent
{
public:
    //@{
    /**
        Ctors; used internally by wxWidgets.
    */
    wxStyledTextEvent(wxEventType commandType = 0, int id = 0);
    wxStyledTextEvent(const wxStyledTextEvent& event);
    //@}

    /**

    */
    bool GetAlt() const;

    /**

    */
    bool GetControl() const;

    /**

    */
    bool GetDragAllowMove();

    /**

    */
    wxDragResult GetDragResult();

    /**

    */
    wxString GetDragText();

    /**

    */
    int GetFoldLevelNow() const;

    /**

    */
    int GetFoldLevelPrev() const;

    /**

    */
    int GetKey() const;

    /**

    */
    int GetLParam() const;

    /**

    */
    int GetLength() const;

    /**

    */
    int GetLine() const;

    /**

    */
    int GetLinesAdded() const;

    /**

    */
    int GetListType() const;

    /**

    */
    int GetMargin() const;

    /**

    */
    int GetMessage() const;

    /**

    */
    int GetModificationType() const;

    /**

    */
    int GetModifiers() const;

    /**

    */
    int GetPosition() const;

    /**

    */
    bool GetShift() const;

    /**

    */
    wxString GetText() const;

    /**

    */
    int GetWParam() const;

    /**

    */
    int GetX() const;

    /**

    */
    int GetY() const;

    /**

    */
    void SetDragAllowMove(bool val);

    /**

    */
    void SetDragResult(wxDragResult val);

    /**

    */
    void SetDragText(const wxString& val);

    /**

    */
    void SetFoldLevelNow(int val);

    /**

    */
    void SetFoldLevelPrev(int val);

    /**

    */
    void SetKey(int k);

    /**

    */
    void SetLParam(int val);

    /**

    */
    void SetLength(int len);

    /**

    */
    void SetLine(int val);

    /**

    */
    void SetLinesAdded(int num);

    /**

    */
    void SetListType(int val);

    /**

    */
    void SetMargin(int val);

    /**

    */
    void SetMessage(int val);

    /**

    */
    void SetModificationType(int t);

    /**

    */
    void SetModifiers(int m);

    /**

    */
    void SetPosition(int pos);

    /**

    */
    void SetText(const wxString& t);

    /**

    */
    void SetWParam(int val);

    /**

    */
    void SetX(int val);

    /**

    */
    void SetY(int val);
};



/**
    @class wxStyledTextCtrl

    A wxWidgets implementation of the Scintilla source code editing component.

    As well as features found in standard text editing components, Scintilla
    includes features especially useful when editing and debugging source code.
    These include support for syntax styling, error indicators, code completion
    and call tips.

    The selection margin can contain markers like those used in debuggers to indicate
    breakpoints and the current line. Styling choices are more open than with many
    editors, allowing the use of proportional fonts, bold and italics, multiple
    foreground and background colours and multiple fonts.

    wxStyledTextCtrl is a 1 to 1 mapping of "raw" scintilla interface, whose
    documentation can be found in the Scintilla website (http://www.scintilla.org/).

    @beginEventEmissionTable{wxStyledTextEvent}
    @event{EVT_STC_CHANGE(id, fn)}
        TOWRITE
    @event{EVT_STC_STYLENEEDED(id, fn)}
        TOWRITE
    @event{EVT_STC_CHARADDED(id, fn)}
        TOWRITE
    @event{EVT_STC_SAVEPOINTREACHED(id, fn)}
        TOWRITE
    @event{EVT_STC_SAVEPOINTLEFT(id, fn)}
        TOWRITE
    @event{EVT_STC_ROMODIFYATTEMPT(id, fn)}
        TOWRITE
    @event{EVT_STC_KEY(id, fn)}
        TOWRITE
    @event{EVT_STC_DOUBLECLICK(id, fn)}
        TOWRITE
    @event{EVT_STC_UPDATEUI(id, fn)}
        TOWRITE
    @event{EVT_STC_MODIFIED(id, fn)}
        TOWRITE
    @event{EVT_STC_MACRORECORD(id, fn)}
        TOWRITE
    @event{EVT_STC_MARGINCLICK(id, fn)}
        TOWRITE
    @event{EVT_STC_NEEDSHOWN(id, fn)}
        TOWRITE
    @event{EVT_STC_PAINTED(id, fn)}
        TOWRITE
    @event{EVT_STC_USERLISTSELECTION(id, fn)}
        TOWRITE
    @event{EVT_STC_URIDROPPED(id, fn)}
        TOWRITE
    @event{EVT_STC_DWELLSTART(id, fn)}
        TOWRITE
    @event{EVT_STC_DWELLEND(id, fn)}
        TOWRITE
    @event{EVT_STC_START_DRAG(id, fn)}
        TOWRITE
    @event{EVT_STC_DRAG_OVER(id, fn)}
        TOWRITE
    @event{EVT_STC_DO_DROP(id, fn)}
        TOWRITE
    @event{EVT_STC_ZOOM(id, fn)}
        TOWRITE
    @event{EVT_STC_HOTSPOT_CLICK(id, fn)}
        TOWRITE
    @event{EVT_STC_HOTSPOT_DCLICK(id, fn)}
        TOWRITE
    @event{EVT_STC_CALLTIP_CLICK(id, fn)}
        TOWRITE
    @event{EVT_STC_AUTOCOMP_SELECTION(id, fn)}
        TOWRITE
    @event{EVT_STC_INDICATOR_CLICK(id, fn)}
        TOWRITE
    @event{EVT_STC_INDICATOR_RELEASE(id, fn)}
        TOWRITE
    @event{EVT_STC_AUTOCOMP_CANCELLED(id, fn)}
        TOWRITE
    @event{EVT_STC_AUTOCOMP_CHAR_DELETED(id, fn)}
        TOWRITE
    @endEventTable

    @library{wxbase}
    @category{stc}

    @see wxStyledTextEvent
*/
class wxStyledTextCtrl : public wxControl
{
public:
    /**
        Ctor.
    */
    wxStyledTextCtrl::wxStyledTextCtrl(wxWindow* parent,
                                       wxWindowID id = wxID_ANY,
                                       const wxPoint& pos = wxDefaultPosition,
                                       const wxSize& size = wxDefaultSize,
                                       long style = 0,
                                       const wxString& name = wxSTCNameStr);

    /**
        Extend life of document.
    */
    void AddRefDocument(void* docPointer);

    /**
        Add array of cells to document.
    */
    void AddStyledText(const wxMemoryBuffer& data);

    /**
        Add text to the document at current position.
    */
    void AddText(const wxString& text);

    /**
        The following methods are nearly equivallent to their similarly named
        cousins above.  The difference is that these methods bypass wxString
        and always use a char* even if used in a unicode build of wxWidgets.
        In that case the character data will be utf-8 encoded since that is
        what is used internally by Scintilla in unicode builds.
        Add text to the document at current position.
    */
    void AddTextRaw(const char* text);

    /**
        Enlarge the document to a particular size of text bytes.
    */
    void Allocate(int bytes);

    /**
        Append a string to the end of the document without changing the selection.
    */
    virtual void AppendText(const wxString& text);

    /**
        Append a string to the end of the document without changing the selection.
    */
    void AppendTextRaw(const char* text);

    /**
        Is there an auto-completion list visible?
    */
    bool AutoCompActive();

    /**
        Remove the auto-completion list from the screen.
    */
    void AutoCompCancel();

    /**
        User has selected an item so remove the list and insert the selection.
    */
    void AutoCompComplete();

    /**
        Retrieve whether or not autocompletion is hidden automatically when nothing
        matches.
    */
    bool AutoCompGetAutoHide() const;

    /**
        Retrieve whether auto-completion cancelled by backspacing before start.
    */
    bool AutoCompGetCancelAtStart() const;

    /**
        Retrieve whether a single item auto-completion list automatically choose the
        item.
    */
    bool AutoCompGetChooseSingle() const;

    /**
        Get currently selected item position in the auto-completion list
    */
    int AutoCompGetCurrent();

    /**
        Retrieve whether or not autocompletion deletes any word characters
        after the inserted text upon completion.
    */
    bool AutoCompGetDropRestOfWord() const;

    /**
        Retrieve state of ignore case flag.
    */
    bool AutoCompGetIgnoreCase() const;

    /**
        Set the maximum height, in rows, of auto-completion and user lists.
    */
    int AutoCompGetMaxHeight() const;

    /**
        Get the maximum width, in characters, of auto-completion and user lists.
    */
    int AutoCompGetMaxWidth() const;

    /**
        Retrieve the auto-completion list separator character.
    */
    int AutoCompGetSeparator() const;

    /**
        Retrieve the auto-completion list type-separator character.
    */
    int AutoCompGetTypeSeparator() const;

    /**
        Retrieve the position of the caret when the auto-completion list was displayed.
    */
    int AutoCompPosStart();

    /**
        Select the item in the auto-completion list that starts with a string.
    */
    void AutoCompSelect(const wxString& text);

    /**
        Set whether or not autocompletion is hidden automatically when nothing matches.
    */
    void AutoCompSetAutoHide(bool autoHide);

    /**
        Should the auto-completion list be cancelled if the user backspaces to a
        position before where the box was created.
    */
    void AutoCompSetCancelAtStart(bool cancel);

    /**
        Should a single item auto-completion list automatically choose the item.
    */
    void AutoCompSetChooseSingle(bool chooseSingle);

    /**
        Set whether or not autocompletion deletes any word characters
        after the inserted text upon completion.
    */
    void AutoCompSetDropRestOfWord(bool dropRestOfWord);

    /**
        Define a set of characters that when typed will cause the autocompletion to
        choose the selected item.
    */
    void AutoCompSetFillUps(const wxString& characterSet);

    /**
        Set whether case is significant when performing auto-completion searches.
    */
    void AutoCompSetIgnoreCase(bool ignoreCase);

    /**
        Set the maximum height, in rows, of auto-completion and user lists.
        The default is 5 rows.
    */
    void AutoCompSetMaxHeight(int rowCount);

    /**
        Set the maximum width, in characters, of auto-completion and user lists.
        Set to 0 to autosize to fit longest item, which is the default.
    */
    void AutoCompSetMaxWidth(int characterCount);

    /**
        Change the separator character in the string setting up an auto-completion list.
        Default is space but can be changed if items contain space.
    */
    void AutoCompSetSeparator(int separatorCharacter);

    /**
        Change the type-separator character in the string setting up an auto-completion list.
        Default is '?' but can be changed if items contain '?'.
    */
    void AutoCompSetTypeSeparator(int separatorCharacter);

    /**
        Display a auto-completion list.
        The lenEntered parameter indicates how many characters before
        the caret should be used to provide context.
    */
    void AutoCompShow(int lenEntered, const wxString& itemList);

    /**
        Define a set of character that when typed cancel the auto-completion list.
    */
    void AutoCompStops(const wxString& characterSet);

    /**
        Dedent the selected lines.
    */
    void BackTab();

    /**
        Start a sequence of actions that is undone and redone as a unit.
        May be nested.
    */
    void BeginUndoAction();

    /**
        Highlight the character at a position indicating there is no matching brace.
    */
    void BraceBadLight(int pos);

    /**
        Highlight the characters at two positions.
    */
    void BraceHighlight(int pos1, int pos2);

    /**
        Find the position of a matching brace or INVALID_POSITION if no match.
    */
    int BraceMatch(int pos);

    /**
        Is there an active call tip?
    */
    bool CallTipActive();

    /**
        Remove the call tip from the screen.
    */
    void CallTipCancel();

    /**
        Retrieve the position where the caret was before displaying the call tip.
    */
    int CallTipPosAtStart();

    /**
        Set the background colour for the call tip.
    */
    void CallTipSetBackground(const wxColour& back);

    /**
        Set the foreground colour for the call tip.
    */
    void CallTipSetForeground(const wxColour& fore);

    /**
        Set the foreground colour for the highlighted part of the call tip.
    */
    void CallTipSetForegroundHighlight(const wxColour& fore);

    /**
        Highlight a segment of the definition.
    */
    void CallTipSetHighlight(int start, int end);

    /**
        Show a call tip containing a definition near position pos.
    */
    void CallTipShow(int pos, const wxString& definition);

    /**
        Enable use of STYLE_CALLTIP and set call tip tab size in pixels.
    */
    void CallTipUseStyle(int tabSize);

    /**
        Will a paste succeed?
    */
    virtual bool CanPaste() const;

    /**
        Are there any redoable actions in the undo history?
    */
    virtual bool CanRedo() const;

    /**
        Are there any undoable actions in the undo history?
    */
    virtual bool CanUndo() const;

    /**
        Cancel any modes such as call tip or auto-completion list display.
    */
    void Cancel();

    /**
        Move caret left one character.
    */
    void CharLeft();

    /**
        Move caret left one character extending selection to new caret position.
    */
    void CharLeftExtend();

    /**
        Move caret left one character, extending rectangular selection to new caret
        position.
    */
    void CharLeftRectExtend();

    /**
        Move caret right one character.
    */
    void CharRight();

    /**
        Move caret right one character extending selection to new caret position.
    */
    void CharRightExtend();

    /**
        Move caret right one character, extending rectangular selection to new caret
        position.
    */
    void CharRightRectExtend();

    /**
        Set the last x chosen value to be the caret x position.
    */
    void ChooseCaretX();

    /**
        Clear the selection.
    */
    virtual void Clear();

    /**
        Delete all text in the document.
    */
    void ClearAll();

    /**
        Set all style bytes to 0, remove all folding information.
    */
    void ClearDocumentStyle();

    /**
        Clear all the registered images.
    */
    void ClearRegisteredImages();

    /**
        When key+modifier combination km is pressed perform msg.
    */
    void CmdKeyAssign(int key, int modifiers, int cmd);

    /**
        When key+modifier combination km is pressed do nothing.
    */
    void CmdKeyClear(int key, int modifiers);

    /**
        Drop all key mappings.
    */
    void CmdKeyClearAll();

    /**
        Perform one of the operations defined by the wxSTC_CMD_* constants.
    */
    void CmdKeyExecute(int cmd);

    /**
        Colourise a segment of the document using the current lexing language.
    */
    void Colourise(int start, int end);

    /**
        Convert all line endings in the document to one mode.
    */
    void ConvertEOLs(int eolMode);

    /**
        Copy the selection to the clipboard.
    */
    virtual void Copy();

    /**
        Copy a range of text to the clipboard. Positions are clipped into the document.
    */
    void CopyRange(int start, int end);

    /**
        Copy argument text to the clipboard.
    */
    void CopyText(int length, const wxString& text);

    /**

    */
    bool Create(wxWindow* parent, wxWindowID id = wxID_ANY,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                long style = 0,
                const wxString& name = wxSTCNameStr);

    /**
        Create a new document object.
        Starts with reference count of 1 and not selected into editor.
    */
    void* CreateDocument();

    /**
        Cut the selection to the clipboard.
    */
    virtual void Cut();

    /**
        Delete back from the current position to the start of the line.
    */
    void DelLineLeft();

    /**
        Delete forwards from the current position to the end of the line.
    */
    void DelLineRight();

    /**
        Delete the word to the left of the caret.
    */
    void DelWordLeft();

    /**
        Delete the word to the right of the caret.
    */
    void DelWordRight();

    /**
        Delete the selection or if no selection, the character before the caret.
    */
    void DeleteBack();

    /**
        Delete the selection or if no selection, the character before the caret.
        Will not delete the character before at the start of a line.
    */
    void DeleteBackNotLine();

    /**
        Allow for simulating a DnD DragOver
    */
    wxDragResult DoDragOver(wxCoord x, wxCoord y, wxDragResult def);

    /**
        Allow for simulating a DnD DropText
    */
    bool DoDropText(long x, long y, const wxString& data);

    /**
        Find the document line of a display line taking hidden lines into account.
    */
    int DocLineFromVisible(int lineDisplay);

    /**
        Move caret to last position in document.
    */
    void DocumentEnd();

    /**
        Move caret to last position in document extending selection to new caret
        position.
    */
    void DocumentEndExtend();

    /**
        Move caret to first position in document.
    */
    void DocumentStart();

    /**
        Move caret to first position in document extending selection to new caret
        position.
    */
    void DocumentStartExtend();

    /**
        Switch from insert to overtype mode or the reverse.
    */
    void EditToggleOvertype();

    /**
        Delete the undo history.
    */
    void EmptyUndoBuffer();

    /**
        End a sequence of actions that is undone and redone as a unit.
    */
    void EndUndoAction();

    /**
        Ensure the caret is visible.
    */
    void EnsureCaretVisible();

    /**
        Ensure a particular line is visible by expanding any header line hiding it.
    */
    void EnsureVisible(int line);

    /**
        Ensure a particular line is visible by expanding any header line hiding it.
        Use the currently set visibility policy to determine which range to display.
    */
    void EnsureVisibleEnforcePolicy(int line);

    /**
        Find the position of a column on a line taking into account tabs and
        multi-byte characters. If beyond end of line, return line end position.
    */
    int FindColumn(int line, int column);

    /**
        Find some text in the document.
    */
    int FindText(int minPos, int maxPos, const wxString& text,
                 int flags = 0);

    /**
        Insert a Form Feed character.
    */
    void FormFeed();

    /**
        On Windows, will draw the document into a display context such as a printer.
    */
    int FormatRange(bool doDraw, int startPos, int endPos,
                    wxDC* draw, wxDC* target,
                    wxRect renderRect,
                    wxRect pageRect);

    /**
        Returns the position of the opposite end of the selection to the caret.
    */
    int GetAnchor() const;

    /**
        Does a backspace pressed when caret is within indentation unindent?
    */
    bool GetBackSpaceUnIndents() const;

    /**
        Is drawing done first into a buffer or direct to the screen?
    */
    bool GetBufferedDraw() const;

    /**
        Get the foreground colour of the caret.
    */
    wxColour GetCaretForeground() const;

    /**
        Get the background alpha of the caret line.
    */
    int GetCaretLineBackAlpha() const;

    /**
        Get the colour of the background of the line containing the caret.
    */
    wxColour GetCaretLineBackground() const;

    /**
        Is the background of the line containing the caret in a different colour?
    */
    bool GetCaretLineVisible() const;

    /**
        Get the time in milliseconds that the caret is on and off.
    */
    int GetCaretPeriod() const;

    /**
        Can the caret preferred x position only be changed by explicit movement
        commands?
    */
    bool GetCaretSticky() const;

    /**
        Returns the width of the insert mode caret.
    */
    int GetCaretWidth() const;

    /**
        Returns the character byte at the position.
    */
    int GetCharAt(int pos) const;

    /**
        Get the code page used to interpret the bytes of the document as characters.
    */
    int GetCodePage() const;

    /**
        Retrieve the column number of a position, taking tab width into account.
    */
    int GetColumn(int pos) const;

    /**
        Get the way control characters are displayed.
    */
    int GetControlCharSymbol() const;

    /**

    */
    wxString GetCurLine(int* linePos = NULL);

    /**

    */
    wxCharBuffer GetCurLineRaw(int* linePos = NULL);

    /**
        END of generated section
        Others...
        Returns the line number of the line with the caret.
    */
    int GetCurrentLine();

    /**
        Returns the position of the caret.
    */
    int GetCurrentPos() const;

    /**
        Retrieve a pointer to the document object.
    */
    void* GetDocPointer();

    /**
        Retrieve the current end of line mode - one of CRLF, CR, or LF.
    */
    int GetEOLMode() const;

    /**
        Retrieve the colour used in edge indication.
    */
    wxColour GetEdgeColour() const;

    /**
        Retrieve the column number which text should be kept within.
    */
    int GetEdgeColumn() const;

    /**
        Retrieve the edge highlight mode.
    */
    int GetEdgeMode() const;

    /**
        Retrieve whether the maximum scroll position has the last
        line at the bottom of the view.
    */
    bool GetEndAtLastLine() const;

    /**
        Retrieve the position of the last correctly styled character.
    */
    int GetEndStyled() const;

    /**
        Retrieve the display line at the top of the display.
    */
    int GetFirstVisibleLine() const;

    /**
        Is a header line expanded?
    */
    bool GetFoldExpanded(int line) const;

    /**
        Retrieve the fold level of a line.
    */
    int GetFoldLevel(int line) const;

    /**
        Find the parent line of a child line.
    */
    int GetFoldParent(int line) const;

    /**
        Get the highlighted indentation guide column.
    */
    int GetHighlightGuide() const;

    /**
        Retrieve indentation size.
    */
    int GetIndent() const;

    /**
        Are the indentation guides visible?
    */
    int GetIndentationGuides() const;

    /**
        Find the last child line of a header line.
    */
    int GetLastChild(int line, int level) const;

    /**
        Can be used to prevent the EVT_CHAR handler from adding the char
    */
    bool GetLastKeydownProcessed();

    /**
        Retrieve the degree of caching of layout information.
    */
    int GetLayoutCache() const;

    /**
        Returns the number of bytes in the document.
    */
    int GetLength() const;

    /**
        Retrieve the lexing language of the document.
    */
    int GetLexer() const;

    /**
        Retrieve the contents of a line.
    */
    wxString GetLine(int line) const;

    /**
        Returns the number of lines in the document. There is always at least one.
    */
    int GetLineCount() const;

    /**
        Get the position after the last visible characters on a line.
    */
    int GetLineEndPosition(int line) const;

    /**
        Retrieve the position before the first non indentation character on a line.
    */
    int GetLineIndentPosition(int line) const;

    /**
        Retrieve the number of columns that a line is indented.
    */
    int GetLineIndentation(int line) const;

    /**
        Retrieve the contents of a line.
    */
    wxCharBuffer GetLineRaw(int line);

    /**
        Retrieve the position of the end of the selection at the given line
        (INVALID_POSITION if no selection on this line).
    */
    int GetLineSelEndPosition(int line);

    /**
        Retrieve the position of the start of the selection at the given line
        (INVALID_POSITION if no selection on this line).
    */
    int GetLineSelStartPosition(int line);

    /**
        Retrieve the extra styling information for a line.
    */
    int GetLineState(int line) const;

    /**
        Is a line visible?
    */
    bool GetLineVisible(int line) const;

    /**
        Returns the size in pixels of the left margin.
    */
    int GetMarginLeft() const;

    /**
        Retrieve the marker mask of a margin.
    */
    int GetMarginMask(int margin) const;

    /**
        Returns the size in pixels of the right margin.
    */
    int GetMarginRight() const;

    /**
        Retrieve the mouse click sensitivity of a margin.
    */
    bool GetMarginSensitive(int margin) const;

    /**
        Retrieve the type of a margin.
    */
    int GetMarginType(int margin) const;

    /**
        Retrieve the width of a margin in pixels.
    */
    int GetMarginWidth(int margin) const;

    /**
        Retrieve the last line number that has line state.
    */
    int GetMaxLineState() const;

    /**
        Get which document modification events are sent to the container.
    */
    int GetModEventMask() const;

    /**
        Is the document different from when it was last saved?
    */
    bool GetModify() const;

    /**
        Get whether mouse gets captured.
    */
    bool GetMouseDownCaptures() const;

    /**
        Retrieve the time the mouse must sit still to generate a mouse dwell event.
    */
    int GetMouseDwellTime() const;

    /**
        Returns @true if overtype mode is active otherwise @false is returned.
    */
    bool GetOvertype() const;

    /**
        Get convert-on-paste setting
    */
    bool GetPasteConvertEndings() const;

    /**
        Returns the print colour mode.
    */
    int GetPrintColourMode() const;

    /**
        Returns the print magnification.
    */
    int GetPrintMagnification() const;

    /**
        Is printing line wrapped?
    */
    int GetPrintWrapMode() const;

    /**
        Retrieve a 'property' value previously set with SetProperty.
    */
    wxString GetProperty(const wxString& key);

    /**
        Retrieve a 'property' value previously set with SetProperty,
        with '$()' variable replacement on returned buffer.
    */
    wxString GetPropertyExpanded(const wxString& key);

    /**
        Retrieve a 'property' value previously set with SetProperty,
        interpreted as an int AFTER any '$()' variable replacement.
    */
    int GetPropertyInt(const wxString& key) const;

    /**
        In read-only mode?
    */
    bool GetReadOnly() const;

    /**
        Get cursor type.
    */
    int GetSTCCursor() const;

    /**
        Get internal focus flag.
    */
    bool GetSTCFocus() const;

    /**
        Retrieve the document width assumed for scrolling.
    */
    int GetScrollWidth() const;

    /**
        Get the search flags used by SearchInTarget.
    */
    int GetSearchFlags() const;

    /**
        Get the alpha of the selection.
    */
    int GetSelAlpha() const;

    /**
        Retrieve the selected text.
    */
    wxString GetSelectedText();

    /**
        Retrieve the selected text.
    */
    wxCharBuffer GetSelectedTextRaw();

    /**

    */
    void GetSelection(int* OUTPUT, int* OUTPUT);

    /**
        Returns the position at the end of the selection.
    */
    int GetSelectionEnd() const;

    /**
        Get the mode of the current selection.
    */
    int GetSelectionMode() const;

    /**
        Returns the position at the start of the selection.
    */
    int GetSelectionStart() const;

    /**
        Get error status.
    */
    int GetStatus() const;

    /**
        Returns the style byte at the position.
    */
    int GetStyleAt(int pos) const;

    /**
        Retrieve number of bits in style bytes used to hold the lexical state.
    */
    int GetStyleBits() const;

    /**
        Retrieve the number of bits the current lexer needs for styling.
    */
    int GetStyleBitsNeeded() const;

    /**
        Retrieve a buffer of cells.
    */
    wxMemoryBuffer GetStyledText(int startPos, int endPos);

    /**
        Does a tab pressed when caret is within indentation indent?
    */
    bool GetTabIndents() const;

    /**
        Retrieve the visible size of a tab.
    */
    int GetTabWidth() const;

    /**
        Get the position that ends the target.
    */
    int GetTargetEnd() const;

    /**
        Get the position that starts the target.
    */
    int GetTargetStart() const;

    /**
        Retrieve all the text in the document.
    */
    wxString GetText() const;

    /**
        Retrieve the number of characters in the document.
    */
    int GetTextLength() const;

    /**
        Retrieve a range of text.
    */
    wxString GetTextRange(int startPos, int endPos);

    /**
        Retrieve a range of text.
    */
    wxCharBuffer GetTextRangeRaw(int startPos, int endPos);

    /**
        Retrieve all the text in the document.
    */
    wxCharBuffer GetTextRaw();

    /**
        Is drawing done in two phases with backgrounds drawn before foregrounds?
    */
    bool GetTwoPhaseDraw() const;

    /**
        Is undo history being collected?
    */
    bool GetUndoCollection() const;

    /**
        Returns the current UseAntiAliasing setting.
    */
    bool GetUseAntiAliasing();

    /**
        Is the horizontal scroll bar visible?
    */
    bool GetUseHorizontalScrollBar() const;

    /**
        Retrieve whether tabs will be used in indentation.
    */
    bool GetUseTabs() const;

    /**
        Is the vertical scroll bar visible?
    */
    bool GetUseVerticalScrollBar() const;

    /**
        Are the end of line characters visible?
    */
    bool GetViewEOL() const;

    /**
        Are white space characters currently visible?
        Returns one of SCWS_* constants.
    */
    int GetViewWhiteSpace() const;

    /**
        Retrieve whether text is word wrapped.
    */
    int GetWrapMode() const;

    /**
        Retrive the start indent for wrapped lines.
    */
    int GetWrapStartIndent() const;

    /**
        Retrive the display mode of visual flags for wrapped lines.
    */
    int GetWrapVisualFlags() const;

    /**
        Retrive the location of visual flags for wrapped lines.
    */
    int GetWrapVisualFlagsLocation() const;

    /**

    */
    int GetXOffset() const;

    /**
        Retrieve the zoom level.
    */
    int GetZoom() const;

    /**
        Set caret to start of a line and ensure it is visible.
    */
    void GotoLine(int line);

    /**
        Set caret to a position and ensure it is visible.
    */
    void GotoPos(int pos);

    /**
        Make a range of lines invisible.
    */
    void HideLines(int lineStart, int lineEnd);

    /**
        Draw the selection in normal style or with selection highlighted.
    */
    void HideSelection(bool normal);

    /**
        Move caret to first position on line.
    */
    void Home();

    /**
        Move caret to first position on display line.
    */
    void HomeDisplay();

    /**
        Move caret to first position on display line extending selection to
        new caret position.
    */
    void HomeDisplayExtend();

    /**
        Move caret to first position on line extending selection to new caret position.
    */
    void HomeExtend();

    /**
        Move caret to first position on line, extending rectangular selection to new
        caret position.
    */
    void HomeRectExtend();

    /**
        These are like their namesakes Home(Extend)?, LineEnd(Extend)?, VCHome(Extend)?
        except they behave differently when word-wrap is enabled:
        They go first to the start / end of the display line, like (Home|LineEnd)Display
        The difference is that, the cursor is already at the point, it goes on to the
        start or end of the document line, as appropriate for (Home|LineEnd|VCHome)(Extend)?.
    */
    void HomeWrap();

    /**

    */
    void HomeWrapExtend();

    /**
        Retrieve the foreground colour of an indicator.
    */
    wxColour IndicatorGetForeground(int indic) const;

    /**
        Retrieve the style of an indicator.
    */
    int IndicatorGetStyle(int indic) const;

    /**
        Set the foreground colour of an indicator.
    */
    void IndicatorSetForeground(int indic, const wxColour& fore);

    /**
        Set an indicator to plain, squiggle or TT.
    */
    void IndicatorSetStyle(int indic, int style);

    /**
        Insert string at a position.
    */
    void InsertText(int pos, const wxString& text);

    /**
        Insert string at a position.
    */
    void InsertTextRaw(int pos, const char* text);

    /**
        Copy the line containing the caret.
    */
    void LineCopy();

    /**
        Cut the line containing the caret.
    */
    void LineCut();

    /**
        Delete the line containing the caret.
    */
    void LineDelete();

    /**
        Move caret down one line.
    */
    void LineDown();

    /**
        Move caret down one line extending selection to new caret position.
    */
    void LineDownExtend();

    /**
        Move caret down one line, extending rectangular selection to new caret position.
    */
    void LineDownRectExtend();

    /**
        Duplicate the current line.
    */
    void LineDuplicate();

    /**
        Move caret to last position on line.
    */
    void LineEnd();

    /**
        Move caret to last position on display line.
    */
    void LineEndDisplay();

    /**
        Move caret to last position on display line extending selection to new
        caret position.
    */
    void LineEndDisplayExtend();

    /**
        Move caret to last position on line extending selection to new caret position.
    */
    void LineEndExtend();

    /**
        Move caret to last position on line, extending rectangular selection to new
        caret position.
    */
    void LineEndRectExtend();

    /**

    */
    void LineEndWrap();

    /**

    */
    void LineEndWrapExtend();

    /**
        Retrieve the line containing a position.
    */
    int LineFromPosition(int pos) const;

    /**
        How many characters are on a line, including end of line characters?
    */
    int LineLength(int line) const;

    /**
        Scroll horizontally and vertically.
    */
    void LineScroll(int columns, int lines);

    /**
        Scroll the document down, keeping the caret visible.
    */
    void LineScrollDown();

    /**
        Scroll the document up, keeping the caret visible.
    */
    void LineScrollUp();

    /**
        Switch the current line with the previous.
    */
    void LineTranspose();

    /**
        Move caret up one line.
    */
    void LineUp();

    /**
        Move caret up one line extending selection to new caret position.
    */
    void LineUpExtend();

    /**
        Move caret up one line, extending rectangular selection to new caret position.
    */
    void LineUpRectExtend();

    /**
        Join the lines in the target.
    */
    void LinesJoin();

    /**
        Retrieves the number of lines completely visible.
    */
    int LinesOnScreen() const;

    /**
        Split the lines in the target into lines that are less wide than pixelWidth
        where possible.
    */
    void LinesSplit(int pixelWidth);

    /**
        Load the contents of filename into the editor
    */
    bool LoadFile(const wxString& file, int fileType = wxTEXT_TYPE_ANY);

    /**
        Transform the selection to lower case.
    */
    void LowerCase();

    /**
        Add a marker to a line, returning an ID which can be used to find or delete the
        marker.
    */
    int MarkerAdd(int line, int markerNumber);

    /**
        Add a set of markers to a line.
    */
    void MarkerAddSet(int line, int set);

    /**
        Set the symbol used for a particular marker number,
        and optionally the fore and background colours.
    */
    void MarkerDefine(int markerNumber, int markerSymbol,
                      const wxColour& foreground = wxNullColour,
                      const wxColour& background = wxNullColour);

    /**
        Define a marker from a bitmap
    */
    void MarkerDefineBitmap(int markerNumber, const wxBitmap& bmp);

    /**
        Delete a marker from a line.
    */
    void MarkerDelete(int line, int markerNumber);

    /**
        Delete all markers with a particular number from all lines.
    */
    void MarkerDeleteAll(int markerNumber);

    /**
        Delete a marker.
    */
    void MarkerDeleteHandle(int handle);

    /**
        Get a bit mask of all the markers set on a line.
    */
    int MarkerGet(int line);

    /**
        Retrieve the line number at which a particular marker is located.
    */
    int MarkerLineFromHandle(int handle);

    /**
        Find the next line after lineStart that includes a marker in mask.
    */
    int MarkerNext(int lineStart, int markerMask);

    /**
        Find the previous line before lineStart that includes a marker in mask.
    */
    int MarkerPrevious(int lineStart, int markerMask);

    /**
        Set the alpha used for a marker that is drawn in the text area, not the margin.
    */
    void MarkerSetAlpha(int markerNumber, int alpha);

    /**
        Set the background colour used for a particular marker number.
    */
    void MarkerSetBackground(int markerNumber, const wxColour& back);

    /**
        Set the foreground colour used for a particular marker number.
    */
    void MarkerSetForeground(int markerNumber, const wxColour& fore);

    /**
        Move the caret inside current view if it's not there already.
    */
    void MoveCaretInsideView();

    /**
        Insert a new line, may use a CRLF, CR or LF depending on EOL mode.
    */
    void NewLine();

    /**
        Move caret one page down.
    */
    void PageDown();

    /**
        Move caret one page down extending selection to new caret position.
    */
    void PageDownExtend();

    /**
        Move caret one page down, extending rectangular selection to new caret position.
    */
    void PageDownRectExtend();

    /**
        Move caret one page up.
    */
    void PageUp();

    /**
        Move caret one page up extending selection to new caret position.
    */
    void PageUpExtend();

    /**
        Move caret one page up, extending rectangular selection to new caret position.
    */
    void PageUpRectExtend();

    /**
        Move caret between paragraphs (delimited by empty lines).
    */
    void ParaDown();

    /**

    */
    void ParaDownExtend();

    /**

    */
    void ParaUp();

    /**

    */
    void ParaUpExtend();

    /**
        Paste the contents of the clipboard into the document replacing the selection.
    */
    virtual void Paste();

    /**
        Retrieve the point in the window where a position is displayed.
    */
    wxPoint PointFromPosition(int pos);

    /**
        Given a valid document position, return the next position taking code
        page into account. Maximum value returned is the last position in the document.
    */
    int PositionAfter(int pos);

    /**
        Given a valid document position, return the previous position taking code
        page into account. Returns 0 if passed 0.
    */
    int PositionBefore(int pos);

    /**
        Retrieve the position at the start of a line.
    */
    int PositionFromLine(int line) const;

    /**
        Find the position from a point within the window.
    */
    int PositionFromPoint(wxPoint pt) const;

    /**
        Find the position from a point within the window but return
        INVALID_POSITION if not close to text.
    */
    int PositionFromPointClose(int x, int y);

    /**
        Redoes the next action on the undo history.
    */
    virtual void Redo();

    /**
        Register an image for use in autocompletion lists.
    */
    void RegisterImage(int type, const wxBitmap& bmp);

    /**
        Release a reference to the document, deleting document if it fades to black.
    */
    void ReleaseDocument(void* docPointer);

    /**
        Replace the selected text with the argument text.
    */
    void ReplaceSelection(const wxString& text);

    /**
        Replace the target text with the argument text.
        Text is counted so it can contain NULs.
        Returns the length of the replacement text.
    */
    int ReplaceTarget(const wxString& text);

    /**
        Replace the target text with the argument text after d processing.
        Text is counted so it can contain NULs.

        Looks for d where d is between 1 and 9 and replaces these with the strings
        matched in the last search operation which were surrounded by ( and ).

        Returns the length of the replacement text including any change
        caused by processing the d patterns.
    */
    int ReplaceTargetRE(const wxString& text);

    /**
        Write the contents of the editor to filename
    */
    bool SaveFile(const wxString& file = wxEmptyString, int fileType = wxTEXT_TYPE_ANY);

    /**
        Scroll enough to make the given column visible
    */
    void ScrollToColumn(int column);

    /**
        Scroll enough to make the given line visible
    */
    void ScrollToLine(int line);

    /**
        Sets the current caret position to be the search anchor.
    */
    void SearchAnchor();

    /**
        Search for a counted string in the target and set the target to the found
        range. Text is counted so it can contain NULs.
        Returns length of range or -1 for failure in which case target is not moved.
    */
    int SearchInTarget(const wxString& text);

    /**
        Find some text starting at the search anchor.
        Does not ensure the selection is visible.
    */
    int SearchNext(int flags, const wxString& text);

    /**
        Find some text starting at the search anchor and moving backwards.
        Does not ensure the selection is visible.
    */
    int SearchPrev(int flags, const wxString& text);

    /**
        Select all the text in the document.
    */
    virtual void SelectAll();

    /**
        Duplicate the selection. If selection empty duplicate the line containing the
        caret.
    */
    void SelectionDuplicate();

    /**
        Is the selection rectangular? The alternative is the more common stream
        selection.
    */
    bool SelectionIsRectangle() const;

    /**
        Send a message to Scintilla
    */
    wxIntPtr SendMsg(int msg, wxUIntPtr wp = 0, wxIntPtr lp = 0) const;

    /**
        Set the selection anchor to a position. The anchor is the opposite
        end of the selection from the caret.
    */
    void SetAnchor(int posAnchor);

    /**
        Sets whether a backspace pressed when caret is within indentation unindents.
    */
    void SetBackSpaceUnIndents(bool bsUnIndents);

    /**
        If drawing is buffered then each line of text is drawn into a bitmap buffer
        before drawing it to the screen to avoid flicker.
    */
    void SetBufferedDraw(bool buffered);

    /**
        Set the foreground colour of the caret.
    */
    void SetCaretForeground(const wxColour& fore);

    /**
        Set background alpha of the caret line.
    */
    void SetCaretLineBackAlpha(int alpha);

    /**
        Set the colour of the background of the line containing the caret.
    */
    void SetCaretLineBackground(const wxColour& back);

    /**
        Display the background of the line containing the caret in a different colour.
    */
    void SetCaretLineVisible(bool show);

    /**
        Get the time in milliseconds that the caret is on and off. 0 = steady on.
    */
    void SetCaretPeriod(int periodMilliseconds);

    /**
        Stop the caret preferred x position changing when the user types.
    */
    void SetCaretSticky(bool useCaretStickyBehaviour);

    /**
        Set the width of the insert mode caret.
    */
    void SetCaretWidth(int pixelWidth);

    /**
        Reset the set of characters for whitespace and word characters to the defaults.
    */
    void SetCharsDefault();

    /**
        Set the code page used to interpret the bytes of the document as characters.
    */
    void SetCodePage(int codePage);

    /**
        Change the way control characters are displayed:
        If symbol is  32, keep the drawn way, else, use the given character.
    */
    void SetControlCharSymbol(int symbol);

    /**
        Sets the position of the caret.
    */
    void SetCurrentPos(int pos);

    /**
        Change the document object used.
    */
    void SetDocPointer(void* docPointer);

    /**
        Set the current end of line mode.
    */
    void SetEOLMode(int eolMode);

    /**
        Change the colour used in edge indication.
    */
    void SetEdgeColour(const wxColour& edgeColour);

    /**
        Set the column number of the edge.
        If text goes past the edge then it is highlighted.
    */
    void SetEdgeColumn(int column);

    /**
        The edge may be displayed by a line (EDGE_LINE) or by highlighting text that
        goes beyond it (EDGE_BACKGROUND) or not displayed at all (EDGE_NONE).
    */
    void SetEdgeMode(int mode);

    /**
        Sets the scroll range so that maximum scroll position has
        the last line at the bottom of the view (default).
        Setting this to @false allows scrolling one page below the last line.
    */
    void SetEndAtLastLine(bool endAtLastLine);

    /**
        Show the children of a header line.
    */
    void SetFoldExpanded(int line, bool expanded);

    /**
        Set some style options for folding.
    */
    void SetFoldFlags(int flags);

    /**
        Set the fold level of a line.
        This encodes an integer level along with flags indicating whether the
        line is a header and whether it is effectively white space.
    */
    void SetFoldLevel(int line, int level);

    /**
        Set the colours used as a chequerboard pattern in the fold margin
    */
    void SetFoldMarginColour(bool useSetting, const wxColour& back);

    /**

    */
    void SetFoldMarginHiColour(bool useSetting, const wxColour& fore);

    /**
        Set the horizontal scrollbar to use instead of the ont that's built-in.
    */
    void SetHScrollBar(wxScrollBar* bar);

    /**
        Set the highlighted indentation guide column.
        0 = no highlighted guide.
    */
    void SetHighlightGuide(int column);

    /**
        Set a back colour for active hotspots.
    */
    void SetHotspotActiveBackground(bool useSetting,
                                    const wxColour& back);

    /**
        Set a fore colour for active hotspots.
    */
    void SetHotspotActiveForeground(bool useSetting,
                                    const wxColour& fore);

    /**
        Enable / Disable underlining active hotspots.
    */
    void SetHotspotActiveUnderline(bool underline);

    /**
        Limit hotspots to single line so hotspots on two lines don't merge.
    */
    void SetHotspotSingleLine(bool singleLine);

    /**
        Set the number of spaces used for one level of indentation.
    */
    void SetIndent(int indentSize);

    /**
        Show or hide indentation guides.
    */
    void SetIndentationGuides(int indentView);

    /**
        Set up the key words used by the lexer.
    */
    void SetKeyWords(int keywordSet, const wxString& keyWords);

    /**

    */
    void SetLastKeydownProcessed(bool val);

    /**
        Sets the degree of caching of layout information.
    */
    void SetLayoutCache(int mode);

    /**
        Set the lexing language of the document.
    */
    void SetLexer(int lexer);

    /**
        Set the lexing language of the document based on string name.
    */
    void SetLexerLanguage(const wxString& language);

    /**
        Change the indentation of a line to a number of columns.
    */
    void SetLineIndentation(int line, int indentSize);

    /**
        Used to hold extra styling information for each line.
    */
    void SetLineState(int line, int state);

    /**
        Sets the size in pixels of the left margin.
    */
    void SetMarginLeft(int pixelWidth);

    /**
        Set a mask that determines which markers are displayed in a margin.
    */
    void SetMarginMask(int margin, int mask);

    /**
        Sets the size in pixels of the right margin.
    */
    void SetMarginRight(int pixelWidth);

    /**
        Make a margin sensitive or insensitive to mouse clicks.
    */
    void SetMarginSensitive(int margin, bool sensitive);

    /**
        Set a margin to be either numeric or symbolic.
    */
    void SetMarginType(int margin, int marginType);

    /**
        Set the width of a margin to a width expressed in pixels.
    */
    void SetMarginWidth(int margin, int pixelWidth);

    /**
        Set the left and right margin in the edit area, measured in pixels.
    */
    void SetMargins(int left, int right);

    /**
        Set which document modification events are sent to the container.
    */
    void SetModEventMask(int mask);

    /**
        Set whether the mouse is captured when its button is pressed.
    */
    void SetMouseDownCaptures(bool captures);

    /**
        Sets the time the mouse must sit still to generate a mouse dwell event.
    */
    void SetMouseDwellTime(int periodMilliseconds);

    /**
        Set to overtype (@true) or insert mode.
    */
    void SetOvertype(bool overtype);

    /**
        Enable/Disable convert-on-paste for line endings
    */
    void SetPasteConvertEndings(bool convert);

    /**
        Modify colours when printing for clearer printed text.
    */
    void SetPrintColourMode(int mode);

    /**
        Sets the print magnification added to the point size of each style for printing.
    */
    void SetPrintMagnification(int magnification);

    /**
        Set printing to line wrapped (SC_WRAP_WORD) or not line wrapped (SC_WRAP_NONE).
    */
    void SetPrintWrapMode(int mode);

    /**
        Set up a value that may be used by a lexer for some optional feature.
    */
    void SetProperty(const wxString& key, const wxString& value);

    /**
        Set to read only or read write.
    */
    void SetReadOnly(bool readOnly);

    /**
        Sets the cursor to one of the SC_CURSOR* values.
    */
    void SetSTCCursor(int cursorType);

    /**
        Change internal focus flag.
    */
    void SetSTCFocus(bool focus);

    /**
        Remember the current position in the undo history as the position
        at which the document was saved.
    */
    void SetSavePoint();

    /**
        Sets the document width assumed for scrolling.
    */
    void SetScrollWidth(int pixelWidth);

    /**
        Set the search flags used by SearchInTarget.
    */
    void SetSearchFlags(int flags);

    /**
        Set the alpha of the selection.
    */
    void SetSelAlpha(int alpha);

    /**
        Set the background colour of the main and additional selections and whether to use this setting.
    */
    void SetSelBackground(bool useSetting, const wxColour& back);

    /**
        Set the foreground colour of the main and additional selections and whether to use this setting.
    */
    void SetSelForeground(bool useSetting, const wxColour& fore);

    /**
        Select a range of text.
    */
    virtual void SetSelection(long from, long to);

    /**
        Sets the position that ends the selection - this becomes the currentPosition.
    */
    void SetSelectionEnd(int pos);

    /**
        Set the selection mode to stream (wxSTC_SEL_STREAM) or rectangular
        (wxSTC_SEL_RECTANGLE/wxSTC_SEL_THIN) or by lines (wxSTC_SEL_LINES).
    */
    void SetSelectionMode(int mode);

    /**
        Sets the position that starts the selection - this becomes the anchor.
    */
    void SetSelectionStart(int pos);

    /**
        Change error status - 0 = OK.
    */
    void SetStatus(int statusCode);

    /**
        Divide each styling byte into lexical class bits (default: 5) and indicator
        bits (default: 3). If a lexer requires more than 32 lexical states, then this
        is used to expand the possible states.
    */
    void SetStyleBits(int bits);

    /**
        Set the styles for a segment of the document.
    */
    void SetStyleBytes(int length, char* styleBytes);

    /**
        Change style from current styling position for length characters to a style
        and move the current styling position to after this newly styled segment.
    */
    void SetStyling(int length, int style);

    /**
        Sets whether a tab pressed when caret is within indentation indents.
    */
    void SetTabIndents(bool tabIndents);

    /**
        Change the visible size of a tab to be a multiple of the width of a space
        character.
    */
    void SetTabWidth(int tabWidth);

    /**
        Sets the position that ends the target which is used for updating the
        document without affecting the scroll position.
    */
    void SetTargetEnd(int pos);

    /**
        Sets the position that starts the target which is used for updating the
        document without affecting the scroll position.
    */
    void SetTargetStart(int pos);

    /**
        Replace the contents of the document with the argument text.
    */
    void SetText(const wxString& text);

    /**
        Replace the contents of the document with the argument text.
    */
    void SetTextRaw(const char* text);

    /**
        In twoPhaseDraw mode, drawing is performed in two phases, first the background
        and then the foreground. This avoids chopping off characters that overlap the
        next run.
    */
    void SetTwoPhaseDraw(bool twoPhase);

    /**
        Choose between collecting actions into the undo
        history and discarding them.
    */
    void SetUndoCollection(bool collectUndo);

    /**
        Specify whether anti-aliased fonts should be used.  Will have no effect
        on some platforms, but on some (wxMac for example) can greatly improve
        performance.
    */
    void SetUseAntiAliasing(bool useAA);

    /**
        Show or hide the horizontal scroll bar.
    */
    void SetUseHorizontalScrollBar(bool show);

    /**
        Indentation will only use space characters if useTabs is @false, otherwise
        it will use a combination of tabs and spaces.
    */
    void SetUseTabs(bool useTabs);

    /**
        Show or hide the vertical scroll bar.
    */
    void SetUseVerticalScrollBar(bool show);

    /**
        Set the vertical scrollbar to use instead of the ont that's built-in.
    */
    void SetVScrollBar(wxScrollBar* bar);

    /**
        Make the end of line characters visible or invisible.
    */
    void SetViewEOL(bool visible);

    /**
        Make white space characters invisible, always visible or visible outside
        indentation.
    */
    void SetViewWhiteSpace(int viewWS);

    /**
        Set the way the display area is determined when a particular line
        is to be moved to by Find, FindNext, GotoLine, etc.
    */
    void SetVisiblePolicy(int visiblePolicy, int visibleSlop);

    /**
        Set the background colour of all whitespace and whether to use this setting.
    */
    void SetWhitespaceBackground(bool useSetting,
                                 const wxColour& back);

    /**
        Set the set of characters making up whitespace for when moving or selecting by
        word.
        Should be called after SetWordChars.
    */
    void SetWhitespaceChars(const wxString& characters);

    /**
        Set the foreground colour of all whitespace and whether to use this setting.
    */
    void SetWhitespaceForeground(bool useSetting,
                                 const wxColour& fore);

    /**
       Set the size of the dots used to mark space characters.
    */
    void SetWhitespaceSize(int size);

    /**
       Get the size of the dots used to mark space characters.
    */
    int GetWhitespaceSize() const;

    
    /**
        Set the set of characters making up words for when moving or selecting by word.
        First sets defaults like SetCharsDefault.
    */
    void SetWordChars(const wxString& characters);

    /**
        Sets whether text is word wrapped.
    */
    void SetWrapMode(int mode);

    /**
        Set the start indent for wrapped lines.
    */
    void SetWrapStartIndent(int indent);

    /**
        Set the display mode of visual flags for wrapped lines.
    */
    void SetWrapVisualFlags(int wrapVisualFlags);

    /**
        Set the location of visual flags for wrapped lines.
    */
    void SetWrapVisualFlagsLocation(int wrapVisualFlagsLocation);

    /**
        Set the way the caret is kept visible when going sideway.
        The exclusion zone is given in pixels.
    */
    void SetXCaretPolicy(int caretPolicy, int caretSlop);

    /**
        Get and Set the xOffset (ie, horizonal scroll position).
    */
    void SetXOffset(int newOffset);

    /**
        Set the way the line the caret is on is kept visible.
        The exclusion zone is given in lines.
    */
    void SetYCaretPolicy(int caretPolicy, int caretSlop);

    /**
        Set the zoom level. This number of points is added to the size of all fonts.
        It may be positive to magnify or negative to reduce.
    */
    void SetZoom(int zoom);

    /**
        Make a range of lines visible.
    */
    void ShowLines(int lineStart, int lineEnd);

    /**
        Start notifying the container of all key presses and commands.
    */
    void StartRecord();

    /**
        Set the current styling position to pos and the styling mask to mask.
        The styling mask can be used to protect some bits in each styling byte from
        modification.
    */
    void StartStyling(int pos, int mask);

    /**
        Stop notifying the container of all key presses and commands.
    */
    void StopRecord();

    /**
        Move caret to bottom of page, or one page down if already at bottom of page.
    */
    void StutteredPageDown();

    /**
        Move caret to bottom of page, or one page down if already at bottom of page,
        extending selection to new caret position.
    */
    void StutteredPageDownExtend();

    /**
        Move caret to top of page, or one page up if already at top of page.
    */
    void StutteredPageUp();

    /**
        Move caret to top of page, or one page up if already at top of page, extending
        selection to new caret position.
    */
    void StutteredPageUpExtend();

    /**
        Clear all the styles and make equivalent to the global default style.
    */
    void StyleClearAll();

    /**
        Reset the default style to its state at startup
    */
    void StyleResetDefault();

    /**
        Set the background colour of a style.
    */
    void StyleSetBackground(int style, const wxColour& back);

    /**
        Set a style to be bold or not.
    */
    void StyleSetBold(int style, bool bold);

    /**
        Set a style to be mixed case, or to force upper or lower case.
    */
    void StyleSetCase(int style, int caseForce);

    /**
        Set a style to be changeable or not (read only).
        Experimental feature, currently buggy.
    */
    void StyleSetChangeable(int style, bool changeable);

    /**
        Set the character set of the font in a style.  Converts the Scintilla
        character set values to a wxFontEncoding.
    */
    void StyleSetCharacterSet(int style, int characterSet);

    /**
        Set a style to have its end of line filled or not.
    */
    void StyleSetEOLFilled(int style, bool filled);

    /**
        Set the font of a style.
    */
    void StyleSetFaceName(int style, const wxString& fontName);

    /**
        Set style size, face, bold, italic, and underline attributes from
        a wxFont's attributes.
    */
    void StyleSetFont(int styleNum, wxFont& font);

    /**
        Set all font style attributes at once.
    */
    void StyleSetFontAttr(int styleNum, int size,
                          const wxString& faceName,
                          bool bold,
                          bool italic,
                          bool underline,
                          wxFontEncoding encoding = wxFONTENCODING_DEFAULT);

    /**
        Set the font encoding to be used by a style.
    */
    void StyleSetFontEncoding(int style, wxFontEncoding encoding);

    /**
        Set the foreground colour of a style.
    */
    void StyleSetForeground(int style, const wxColour& fore);

    /**
        Set a style to be a hotspot or not.
    */
    void StyleSetHotSpot(int style, bool hotspot);

    /**
        Set a style to be italic or not.
    */
    void StyleSetItalic(int style, bool italic);

    /**
        Set the size of characters of a style.
    */
    void StyleSetSize(int style, int sizePoints);

    /**
        Extract style settings from a spec-string which is composed of one or
        more of the following comma separated elements:
        bold                    turns on bold
        italic                  turns on italics
        fore:[name or \#RRGGBB]  sets the foreground colour
        back:[name or \#RRGGBB]  sets the background colour
        face:[facename]         sets the font face name to use
        size:[num]              sets the font size in points
        eol                     turns on eol filling
        underline               turns on underlining
    */
    void StyleSetSpec(int styleNum, const wxString& spec);

    /**
        Set a style to be underlined or not.
    */
    void StyleSetUnderline(int style, bool underline);

    /**
        Set a style to be visible or not.
    */
    void StyleSetVisible(int style, bool visible);

    /**
        If selection is empty or all on one line replace the selection with a tab
        character.
        If more than one line selected, indent the lines.
    */
    void Tab();

    /**
        Make the target range start and end be the same as the selection range start
        and end.
    */
    void TargetFromSelection();

    /**
        Retrieve the height of a particular line of text in pixels.
    */
    int TextHeight(int line);

    /**
        Measure the pixel width of some text in a particular style.
        NUL terminated text argument.
        Does not handle tab or control characters.
    */
    int TextWidth(int style, const wxString& text);

    /**
        Switch between sticky and non-sticky: meant to be bound to a key.
    */
    void ToggleCaretSticky();

    /**
        Switch a header line between expanded and contracted.
    */
    void ToggleFold(int line);

    /**
        Undo one action in the undo history.
    */
    virtual void Undo();

    /**
        Transform the selection to upper case.
    */
    void UpperCase();

    /**
        Set whether a pop up menu is displayed automatically when the user presses
        the wrong mouse button.
    */
    void UsePopUp(bool allowPopUp);

    /**
        Display a list of strings and send notification when user chooses one.
    */
    void UserListShow(int listType, const wxString& itemList);

    /**
        Move caret to before first visible character on line.
        If already there move to first character on line.
    */
    void VCHome();

    /**
        Like VCHome but extending selection to new caret position.
    */
    void VCHomeExtend();

    /**
        Move caret to before first visible character on line.
        If already there move to first character on line.
        In either case, extend rectangular selection to new caret position.
    */
    void VCHomeRectExtend();

    /**

    */
    void VCHomeWrap();

    /**

    */
    void VCHomeWrapExtend();

    /**
        Find the display line of a document line taking hidden lines into account.
    */
    int VisibleFromDocLine(int line);

    /**
        Get position of end of word.
    */
    int WordEndPosition(int pos, bool onlyWordCharacters);

    /**
        Move caret left one word.
    */
    void WordLeft();

    /**
        Move caret left one word, position cursor at end of word.
    */
    void WordLeftEnd();

    /**
        Move caret left one word, position cursor at end of word, extending selection
        to new caret position.
    */
    void WordLeftEndExtend();

    /**
        Move caret left one word extending selection to new caret position.
    */
    void WordLeftExtend();

    /**
        Move to the previous change in capitalisation.
    */
    void WordPartLeft();

    /**
        Move to the previous change in capitalisation extending selection
        to new caret position.
    */
    void WordPartLeftExtend();

    /**
        Move to the change next in capitalisation.
    */
    void WordPartRight();

    /**
        Move to the next change in capitalisation extending selection
        to new caret position.
    */
    void WordPartRightExtend();

    /**
        Move caret right one word.
    */
    void WordRight();

    /**
        Move caret right one word, position cursor at end of word.
    */
    void WordRightEnd();

    /**
        Move caret right one word, position cursor at end of word, extending selection
        to new caret position.
    */
    void WordRightEndExtend();

    /**
        Move caret right one word extending selection to new caret position.
    */
    void WordRightExtend();

    /**
        Get position of start of word.
    */
    int WordStartPosition(int pos, bool onlyWordCharacters);

    /**
        The number of display lines needed to wrap a document line
    */
    int WrapCount(int line);

    /**
        Magnify the displayed text by increasing the sizes by 1 point.
    */
    void ZoomIn();

    /**
        Make the displayed text smaller by decreasing the sizes by 1 point.
    */
    void ZoomOut();


    /**
       Sets how wrapped sublines are placed. Default is fixed.
    */
    void SetWrapIndentMode(int mode);

    /**
       Retrieve how wrapped sublines are placed. Default is fixed.
    */
    int GetWrapIndentMode() const;

    /**
       Scroll so that a display line is at the top of the display.
    */
    void SetFirstVisibleLine(int lineDisplay);



    /**
       Copy the selection, if selection empty copy the line with the caret
    */
    void CopyAllowLine();

    /**
       Compact the document buffer and return a read-only pointer to the
       characters in the document.
    */
    const char* GetCharacterPointer();

    /**
       Always interpret keyboard input as Unicode
    */
    void SetKeysUnicode(bool keysUnicode);

    /**
       Are keys always interpreted as Unicode?
    */
    bool GetKeysUnicode() const;

    /**
       Set the alpha fill colour of the given indicator.
    */
    void IndicatorSetAlpha(int indicator, int alpha);

    /**
       Get the alpha fill colour of the given indicator.
    */
    int IndicatorGetAlpha(int indicator) const;

    /**
       Set extra ascent for each line
    */
    void SetExtraAscent(int extraAscent);

    /**
       Get extra ascent for each line
    */
    int GetExtraAscent() const;

    /**
       Set extra descent for each line
    */
    void SetExtraDescent(int extraDescent);

    /**
       Get extra descent for each line
    */
    int GetExtraDescent() const;

    /**
       Which symbol was defined for markerNumber with MarkerDefine
    */
    int GetMarkerSymbolDefined(int markerNumber);

    /**
       Set the text in the text margin for a line
    */
    void MarginSetText(int line, const wxString& text);

    /**
       Get the text in the text margin for a line
    */
    wxString MarginGetText(int line) const;

    /**
       Set the style number for the text margin for a line
    */
    void MarginSetStyle(int line, int style);

    /**
       Get the style number for the text margin for a line
    */
    int MarginGetStyle(int line) const;

    /**
       Set the style in the text margin for a line
    */
    void MarginSetStyles(int line, const wxString& styles);

    /**
       Get the styles in the text margin for a line
    */
    wxString MarginGetStyles(int line) const;

    /**
       Clear the margin text on all lines
    */
    void MarginTextClearAll();

    /**
       Get the start of the range of style numbers used for margin text
    */
    void MarginSetStyleOffset(int style);

    /**
       Get the start of the range of style numbers used for margin text
    */
    int MarginGetStyleOffset() const;

    /**
       Set the annotation text for a line
    */
    void AnnotationSetText(int line, const wxString& text);

    /**
       Get the annotation text for a line
    */
    wxString AnnotationGetText(int line) const;

    /**
       Set the style number for the annotations for a line
    */
    void AnnotationSetStyle(int line, int style);

    /**
       Get the style number for the annotations for a line
    */
    int AnnotationGetStyle(int line) const;

    /**
       Set the annotation styles for a line
    */
    void AnnotationSetStyles(int line, const wxString& styles);

    /**
       Get the annotation styles for a line
    */
    wxString AnnotationGetStyles(int line) const;

    /**
       Get the number of annotation lines for a line
    */
    int AnnotationGetLines(int line) const;

    /**
       Clear the annotations from all lines
    */
    void AnnotationClearAll();

    /**
       Set the visibility for the annotations for a view
    */
    void AnnotationSetVisible(int visible);

    /**
       Get the visibility for the annotations for a view
    */
    int AnnotationGetVisible() const;

    /**
       Get the start of the range of style numbers used for annotations
    */
    void AnnotationSetStyleOffset(int style);

    /**
       Get the start of the range of style numbers used for annotations
    */
    int AnnotationGetStyleOffset() const;

    /**
       Add a container action to the undo stack
    */
    void AddUndoAction(int token, int flags);

    /**
       Find the position of a character from a point within the window.
    */
    int CharPositionFromPoint(int x, int y);

    /**
       Find the position of a character from a point within the window.
       Return INVALID_POSITION if not close to text.
    */
    int CharPositionFromPointClose(int x, int y);

    /**
       Set whether multiple selections can be made
    */
    void SetMultipleSelection(bool multipleSelection);

    /**
       Whether multiple selections can be made
    */
    bool GetMultipleSelection() const;

    /**
       Set whether typing can be performed into multiple selections
    */
    void SetAdditionalSelectionTyping(bool additionalSelectionTyping);

    /**
       Whether typing can be performed into multiple selections
    */
    bool GetAdditionalSelectionTyping() const;

    /**
       Set whether additional carets will blink
    */
    void SetAdditionalCaretsBlink(bool additionalCaretsBlink);

    /**
       Whether additional carets will blink
    */
    bool GetAdditionalCaretsBlink() const;

    /**
       Set whether additional carets are visible
    */
    void SetAdditionalCaretsVisible(bool additionalCaretsBlink);

    /**
       Whether additional carets are visible
    */
    bool GetAdditionalCaretsVisible() const;

    /**
       How many selections are there?
    */
    int GetSelections() const;

    /**
       Clear selections to a single empty stream selection
    */
    void ClearSelections();

    /**
       Add a selection
    */
    int AddSelection(int caret, int anchor);

    /**
       Set the main selection
    */
    void SetMainSelection(int selection);

    /**
       Which selection is the main selection
    */
    int GetMainSelection() const;

    void SetSelectionNCaret(int selection, int pos);
    int GetSelectionNCaret(int selection) const;
    void SetSelectionNAnchor(int selection, int posAnchor);
    int GetSelectionNAnchor(int selection) const;
    void SetSelectionNCaretVirtualSpace(int selection, int space);
    int GetSelectionNCaretVirtualSpace(int selection) const;
    void SetSelectionNAnchorVirtualSpace(int selection, int space);
    int GetSelectionNAnchorVirtualSpace(int selection) const;

    /**
       Sets the position that starts the selection - this becomes the anchor.
    */
    void SetSelectionNStart(int selection, int pos);

    /**
       Returns the position at the start of the selection.
    */
    int GetSelectionNStart(int selection) const;

    /**
       Sets the position that ends the selection - this becomes the currentPosition.
    */
    void SetSelectionNEnd(int selection, int pos);

    /**
       Returns the position at the end of the selection.
    */
    int GetSelectionNEnd(int selection) const;
    
    void SetRectangularSelectionCaret(int pos);
    int GetRectangularSelectionCaret() const;
    void SetRectangularSelectionAnchor(int posAnchor);
    int GetRectangularSelectionAnchor() const;
    void SetRectangularSelectionCaretVirtualSpace(int space);
    int GetRectangularSelectionCaretVirtualSpace() const;
    void SetRectangularSelectionAnchorVirtualSpace(int space);
    int GetRectangularSelectionAnchorVirtualSpace() const;
    void SetVirtualSpaceOptions(int virtualSpaceOptions);
    int GetVirtualSpaceOptions() const;

    /**
       Select the modifier key to use for mouse-based rectangular selection.
    */
    void SetRectangularSelectionModifier(int modifier);

    /**
       Get the modifier key used for rectangular selection.
    */
    int GetRectangularSelectionModifier() const;

    /**
       Set the foreground colour of additional selections.  Must have
       previously called SetSelFore with non-zero first argument for this to
       have an effect.
    */
    void SetAdditionalSelForeground(const wxColour& fore);

    /**
       Set the background colour of additional selections. Must have
       previously called SetSelBack with non-zero first argument for this to
       have an effect.
    */
    void SetAdditionalSelBackground(const wxColour& back);

    /**
       Set the alpha of the selection.
    */
    void SetAdditionalSelAlpha(int alpha);

    /**
       Get the alpha of the selection.
    */
    int GetAdditionalSelAlpha() const;

    /**
       Set the foreground colour of additional carets.
    */
    void SetAdditionalCaretForeground(const wxColour& fore);

    /**
       Get the foreground colour of additional carets.
    */
    wxColour GetAdditionalCaretForeground() const;

    /**
       Set the main selection to the next selection.
    */
    void RotateSelection();

    /**
       Swap that caret and anchor of the main selection.
    */
    void SwapMainAnchorCaret();
    
};


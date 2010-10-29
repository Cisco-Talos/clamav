/////////////////////////////////////////////////////////////////////////////
// Name:        wx/palmos/textctrl.h
// Purpose:     wxTextCtrl class
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by: Yunhui Fu
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_TEXTCTRL_H_
#define _WX_TEXTCTRL_H_

class WXDLLIMPEXP_CORE wxTextCtrl : public wxTextCtrlBase
{
public:
    // creation
    // --------

    wxTextCtrl() { Init(); }
    wxTextCtrl(wxWindow *parent, wxWindowID id,
               const wxString& value = wxEmptyString,
               const wxPoint& pos = wxDefaultPosition,
               const wxSize& size = wxDefaultSize,
               long style = 0,
               const wxValidator& validator = wxDefaultValidator,
               const wxString& name = wxTextCtrlNameStr)
    {
        Init();

        Create(parent, id, value, pos, size, style, validator, name);
    }
    virtual ~wxTextCtrl();

    bool Create(wxWindow *parent, wxWindowID id,
                const wxString& value = wxEmptyString,
                const wxPoint& pos = wxDefaultPosition,
                const wxSize& size = wxDefaultSize,
                long style = 0,
                const wxValidator& validator = wxDefaultValidator,
                const wxString& name = wxTextCtrlNameStr);

    // overridden wxTextEntry methods
    // ------------------------------

    virtual wxString GetValue() const;
    virtual wxString GetRange(long from, long to) const;

    virtual bool IsEmpty() const;

    virtual int GetLineLength(long lineNo) const;
    virtual wxString GetLineText(long lineNo) const;
    virtual int GetNumberOfLines() const;

    virtual void SetMaxLength(unsigned long len);

    virtual void GetSelection(long *from, long *to) const;
    //
    // Operations
    // ----------
    //
    virtual void Clear(void);
    virtual void Replace( long            lFrom
                         ,long            lTo
                         ,const wxString& rsValue
                        );
    virtual void Remove( long lFrom
                        ,long lTo
                       );

    //virtual bool DoLoadFile(const wxString& rsFile, int fileType);

    virtual void MarkDirty();
    virtual void DiscardEdits(void);

    virtual void WriteText(const wxString& rsText);
    virtual void AppendText(const wxString& rsText);
    virtual bool EmulateKeyPress(const wxKeyEvent& rEvent);

    virtual void Copy(void);
    virtual void Cut(void);
    virtual void Paste(void);

    virtual bool CanCopy(void) const;
    virtual bool CanCut(void) const;
    virtual bool CanPaste(void) const;

    virtual void Undo(void);
    virtual void Redo();

    virtual bool CanUndo(void) const;
    virtual bool CanRedo(void) const;

    virtual void SetInsertionPoint(long lPos);
    virtual void SetInsertionPointEnd(void);
    virtual long GetInsertionPoint(void) const;
    virtual wxTextPos GetLastPosition(void) const;

    virtual void SetSelection( long lFrom
                              ,long lTo
                             );
    virtual void SetEditable(bool bEditable);
    virtual void SetWindowStyleFlag(long lStyle);

    // implement base class pure virtuals
    // ----------------------------------

    virtual bool IsModified() const;
    virtual bool IsEditable(void) const;

#if wxUSE_RICHEDIT
    // apply text attribute to the range of text (only works with richedit
    // controls)
    virtual bool SetStyle(long start, long end, const wxTextAttr& style);
    virtual bool SetDefaultStyle(const wxTextAttr& style);
    virtual bool GetStyle(long position, wxTextAttr& style);
#endif // wxUSE_RICHEDIT

    // translate between the position (which is just an index in the text ctrl
    // considering all its contents as a single strings) and (x, y) coordinates
    // which represent column and line.
    virtual long XYToPosition(long x, long y) const;
    virtual bool PositionToXY(long pos, long *x, long *y) const;

    virtual void ShowPosition(long pos);
    virtual wxTextCtrlHitTestResult HitTest(const wxPoint& pt, long *pos) const;
    virtual wxTextCtrlHitTestResult HitTest(const wxPoint& pt,
                                            wxTextCoord *col,
                                            wxTextCoord *row) const
    {
        return wxTextCtrlBase::HitTest(pt, col, row);
    }

    // Caret handling (Windows only)
    bool ShowNativeCaret(bool show = true);
    bool HideNativeCaret() { return ShowNativeCaret(false); }

    // Implementation from now on
    // --------------------------

#if wxUSE_DRAG_AND_DROP && wxUSE_RICHEDIT
    virtual void SetDropTarget(wxDropTarget *dropTarget);
#endif // wxUSE_DRAG_AND_DROP && wxUSE_RICHEDIT

    virtual void Command(wxCommandEvent& event);

#if wxUSE_RICHEDIT

    int GetRichVersion() const { return m_verRichEdit; }
    bool IsRich() const { return m_verRichEdit != 0; }

    // rich edit controls are not compatible with normal ones and wem ust set
    // the colours for them otherwise
    virtual bool SetBackgroundColour(const wxColour& colour);
    virtual bool SetForegroundColour(const wxColour& colour);
#else
    bool IsRich() const { return false; }
#endif // wxUSE_RICHEDIT

#if wxUSE_INKEDIT && wxUSE_RICHEDIT
    bool IsInkEdit() const { return m_isInkEdit != 0; }
#else
    bool IsInkEdit() const { return false; }
#endif

    virtual void AdoptAttributesFromHWND();

    virtual bool AcceptsFocusFromKeyboard() const;

    // returns true if the platform should explicitly apply a theme border
    virtual bool CanApplyThemeBorder() const;

    // callbacks
    void OnDropFiles(wxDropFilesEvent& event);
    void OnChar(wxKeyEvent& event); // Process 'enter' if required

    void OnCut(wxCommandEvent& event);
    void OnCopy(wxCommandEvent& event);
    void OnPaste(wxCommandEvent& event);
    void OnUndo(wxCommandEvent& event);
    void OnRedo(wxCommandEvent& event);
    void OnDelete(wxCommandEvent& event);
    void OnSelectAll(wxCommandEvent& event);

    void OnUpdateCut(wxUpdateUIEvent& event);
    void OnUpdateCopy(wxUpdateUIEvent& event);
    void OnUpdatePaste(wxUpdateUIEvent& event);
    void OnUpdateUndo(wxUpdateUIEvent& event);
    void OnUpdateRedo(wxUpdateUIEvent& event);
    void OnUpdateDelete(wxUpdateUIEvent& event);
    void OnUpdateSelectAll(wxUpdateUIEvent& event);

    // Show a context menu for Rich Edit controls (the standard
    // EDIT control has one already)
    void OnContextMenu(wxContextMenuEvent& event);

    // be sure the caret remains invisible if the user
    // called HideNativeCaret() before
    void OnSetFocus(wxFocusEvent& event);

    virtual wxVisualAttributes GetDefaultAttributes() const;

protected:
    // common part of all ctors
    void Init();

    virtual bool DoLoadFile(const wxString& file, int fileType);

    // creates the control of appropriate class (plain or rich edit) with the
    // styles corresponding to m_windowStyle
    //
    // this is used by ctor/Create() and when we need to recreate the control
    // later
    bool MSWCreateText(const wxString& value,
                       const wxPoint& pos,
                       const wxSize& size);

    virtual void DoSetValue(const wxString &value, int flags = 0);

    // return true if this control has a user-set limit on amount of text (i.e.
    // the limit is due to a previous call to SetMaxLength() and not built in)
    bool HasSpaceLimit(unsigned int *len) const;

    // call this to increase the size limit (will do nothing if the current
    // limit is big enough)
    //
    // returns true if we increased the limit to allow entering more text,
    // false if we hit the limit set by SetMaxLength() and so didn't change it
    bool AdjustSpaceLimit();

#if wxUSE_RICHEDIT && (!wxUSE_UNICODE || wxUSE_UNICODE_MSLU)
    // replace the selection or the entire control contents with the given text
    // in the specified encoding
    bool StreamIn(const wxString& value, wxFontEncoding encoding, bool selOnly);

    // get the contents of the control out as text in the given encoding
    wxString StreamOut(wxFontEncoding encoding, bool selOnly = false) const;
#endif // wxUSE_RICHEDIT

    // replace the contents of the selection or of the entire control with the
    // given text
    void DoWriteText(const wxString& text,
                     int flags = SetValue_SendEvent | SetValue_SelectionOnly);

    // set the selection (possibly without scrolling the caret into view)
    void DoSetSelection(long from, long to, int flags);

    // get the length of the line containing the character at the given
    // position
    long GetLengthOfLineContainingPos(long pos) const;

    // send TEXT_UPDATED event, return true if it was handled, false otherwise
    bool SendUpdateEvent();

    virtual wxSize DoGetBestSize() const;

#if wxUSE_RICHEDIT
    // we're using RICHEDIT (and not simple EDIT) control if this field is not
    // 0, it also gives the version of the RICHEDIT control being used (1, 2 or
    // 3 so far)
    int m_verRichEdit;
#endif // wxUSE_RICHEDIT

    // number of EN_UPDATE events sent by Windows when we change the controls
    // text ourselves: we want this to be exactly 1
    int m_updatesCount;

private:
    virtual void EnableTextChangedEvents(bool enable)
    {
        m_updatesCount = enable ? -1 : -2;
    }

    // implement wxTextEntry pure virtual: it implements all the operations for
    // the simple EDIT controls
    virtual WXHWND GetEditHWND() const { return m_hWnd; }

    DECLARE_EVENT_TABLE()
    DECLARE_DYNAMIC_CLASS_NO_COPY(wxTextCtrl)

    wxMenu* m_privateContextMenu;

    bool m_isNativeCaretShown;

#if wxUSE_INKEDIT && wxUSE_RICHEDIT
    int  m_isInkEdit;
#endif

};

#endif
    // _WX_TEXTCTRL_H_

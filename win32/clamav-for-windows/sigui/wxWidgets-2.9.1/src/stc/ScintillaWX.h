////////////////////////////////////////////////////////////////////////////
// Name:        ScintillaWX.h
// Purpose:     A wxWidgets implementation of Scintilla.  A class derived
//              from ScintillaBase that uses the "wx platform" defined in
//              PlatWX.cpp.  This class is one end of a bridge between
//              the wx world and the Scintilla world.  It needs a peer
//              object of type wxStyledTextCtrl to function.
//
// Author:      Robin Dunn
//
// Created:     13-Jan-2000
// RCS-ID:      $Id$
// Copyright:   (c) 2000 by Total Control Software
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef __ScintillaWX_h__
#define __ScintillaWX_h__
#include "wx/defs.h"

//----------------------------------------------------------------------

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "Platform.h"
#include "SplitVector.h"
#include "Partitioning.h"
#include "RunStyles.h"
#include "Scintilla.h"
#include "ScintillaWidget.h"
#ifdef SCI_LEXER
#include "SciLexer.h"
#include "PropSet.h"
#include "Accessor.h"
#include "KeyWords.h"
#endif
#include "ContractionState.h"
#include "SVector.h"
#include "CellBuffer.h"
#include "CallTip.h"
#include "KeyMap.h"
#include "Indicator.h"
#include "XPM.h"
#include "LineMarker.h"
#include "Style.h"
#include "AutoComplete.h"
#include "ViewStyle.h"
#include "CharClassify.h"
#include "Decoration.h"
#include "Document.h"
#include "Selection.h"
#include "PositionCache.h"
#include "Editor.h"
#include "PropSetSimple.h"
#include "ScintillaBase.h"

#ifdef __WXMSW__
#include "wx/msw/wrapwin.h"                     // HBITMAP
#endif
#if wxUSE_DRAG_AND_DROP
#include "wx/timer.h"
#endif

//----------------------------------------------------------------------


class WXDLLIMPEXP_FWD_CORE wxDC;
class WXDLLIMPEXP_FWD_STC wxStyledTextCtrl;           // forward
class ScintillaWX;


//----------------------------------------------------------------------
// Helper classes

#if wxUSE_DRAG_AND_DROP
class wxSTCDropTarget : public wxTextDropTarget {
public:
    void SetScintilla(ScintillaWX* swx) {
        m_swx = swx;
    }

    bool OnDropText(wxCoord x, wxCoord y, const wxString& data);
    wxDragResult OnEnter(wxCoord x, wxCoord y, wxDragResult def);
    wxDragResult OnDragOver(wxCoord x, wxCoord y, wxDragResult def);
    void OnLeave();

private:
    ScintillaWX* m_swx;
};
#endif

//----------------------------------------------------------------------

class ScintillaWX : public ScintillaBase {
public:

    ScintillaWX(wxStyledTextCtrl* win);
    ~ScintillaWX();

    // base class virtuals
    virtual void Initialise();
    virtual void Finalise();
    virtual void StartDrag();
    virtual bool SetIdle(bool on);
    virtual void SetTicking(bool on);
    virtual void SetMouseCapture(bool on);
    virtual bool HaveMouseCapture();
    virtual void ScrollText(int linesToMove);
    virtual void SetVerticalScrollPos();
    virtual void SetHorizontalScrollPos();
    virtual bool ModifyScrollBars(int nMax, int nPage);
    virtual void Copy();
    virtual void Paste();
    virtual void CopyToClipboard(const SelectionText &selectedText);

    virtual void CreateCallTipWindow(PRectangle rc);
    virtual void AddToPopUp(const char *label, int cmd = 0, bool enabled = true);
    virtual void ClaimSelection();

    virtual sptr_t DefWndProc(unsigned int iMessage,
                              uptr_t wParam,
                              sptr_t lParam);
    virtual sptr_t WndProc(unsigned int iMessage,
                           uptr_t wParam,
                           sptr_t lParam);

    virtual void NotifyChange();
    virtual void NotifyParent(SCNotification scn);

    virtual void CancelModes();

    virtual void UpdateSystemCaret();

    // Event delegates
    void DoPaint(wxDC* dc, wxRect rect);
    void DoHScroll(int type, int pos);
    void DoVScroll(int type, int pos);
    void DoSize(int width, int height);
    void DoLoseFocus();
    void DoGainFocus();
    void DoSysColourChange();
    void DoLeftButtonDown(Point pt, unsigned int curTime, bool shift, bool ctrl, bool alt);
    void DoLeftButtonUp(Point pt, unsigned int curTime, bool ctrl);
    void DoLeftButtonMove(Point pt);
    void DoMiddleButtonUp(Point pt);
    void DoMouseWheel(int rotation, int delta, int linesPerAction, int ctrlDown, bool isPageScroll);
    void DoAddChar(int key);
    int  DoKeyDown(const wxKeyEvent& event, bool* consumed);
    void DoTick() { Tick(); }
    void DoOnIdle(wxIdleEvent& evt);

#if wxUSE_DRAG_AND_DROP
    bool DoDropText(long x, long y, const wxString& data);
    wxDragResult DoDragEnter(wxCoord x, wxCoord y, wxDragResult def);
    wxDragResult DoDragOver(wxCoord x, wxCoord y, wxDragResult def);
    void DoDragLeave();
#endif

    void DoCommand(int ID);
    void DoContextMenu(Point pt);
    void DoOnListBox();


    // helpers
    void FullPaint();
    bool CanPaste();
    bool GetHideSelection() { return hideSelection; }
    void DoScrollToLine(int line);
    void DoScrollToColumn(int column);
    void ClipChildren(wxDC& dc, PRectangle rect);
    void SetUseAntiAliasing(bool useAA);
    bool GetUseAntiAliasing();

private:
    bool                capturedMouse;
    bool                focusEvent;
    wxStyledTextCtrl*   stc;

#if wxUSE_DRAG_AND_DROP
    wxSTCDropTarget*    dropTarget;
    wxDragResult        dragResult;
#endif

    int                 wheelRotation;

    // For use in creating a system caret
    bool HasCaretSizeChanged();
    bool CreateSystemCaret();
    bool DestroySystemCaret();
#ifdef __WXMSW__
    HBITMAP sysCaretBitmap;
    int sysCaretWidth;
    int sysCaretHeight;
#endif
   
    friend class wxSTCCallTip;
};

//----------------------------------------------------------------------
#endif

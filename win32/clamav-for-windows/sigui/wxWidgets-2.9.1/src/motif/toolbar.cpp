/////////////////////////////////////////////////////////////////////////////
// Name:        src/motif/toolbar.cpp
// Purpose:     wxToolBar
// Author:      Julian Smart
// Modified by: 13.12.99 by VZ during toolbar classes reorganization
// Created:     04/01/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// ============================================================================
// declarations
// ============================================================================

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#include "wx/toolbar.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/frame.h"
    #include "wx/timer.h"
    #include "wx/settings.h"
#endif

#ifdef __VMS__
#pragma message disable nosimpint
#endif
#include <Xm/Xm.h>
#include <Xm/PushBG.h>
#include <Xm/PushB.h>
#include <Xm/Label.h>
#include <Xm/ToggleB.h>
#include <Xm/ToggleBG.h>
#include <Xm/Form.h>
#ifdef __VMS__
#pragma message enable nosimpint
#endif

#include "wx/motif/private.h"
#include "wx/motif/bmpmotif.h"

// ----------------------------------------------------------------------------
// wxWin macros
// ----------------------------------------------------------------------------

IMPLEMENT_DYNAMIC_CLASS(wxToolBar, wxControl)

// ----------------------------------------------------------------------------
// private functions
// ----------------------------------------------------------------------------

static void wxToolButtonCallback (Widget w, XtPointer clientData,
                    XtPointer ptr);
static void wxToolButtonPopupCallback (Widget w, XtPointer client_data,
                     XEvent *event, Boolean *continue_to_dispatch);

// ----------------------------------------------------------------------------
// private classes
// ----------------------------------------------------------------------------

class wxToolBarTimer : public wxTimer
{
public:
    virtual void Notify();

    static Widget help_popup;
    static Widget buttonWidget;
    static wxString helpString;
};

class wxToolBarTool : public wxToolBarToolBase
{
public:
    wxToolBarTool(wxToolBar *tbar,
                  int id,
                  const wxString& label,
                  const wxBitmap& bmpNormal,
                  const wxBitmap& bmpToggled,
                  wxItemKind kind,
                  wxObject *clientData,
                  const wxString& shortHelp,
                  const wxString& longHelp)
        : wxToolBarToolBase(tbar, id, label, bmpNormal, bmpToggled, kind,
                            clientData, shortHelp, longHelp)
    {
        Init();
    }

    wxToolBarTool(wxToolBar *tbar, wxControl *control, const wxString& label)
        : wxToolBarToolBase(tbar, control, label)
    {
        Init();
    }

    virtual ~wxToolBarTool();

    // accessors
    void SetWidget(Widget widget) { m_widget = widget; }
    Widget GetButtonWidget() const { return m_widget; }

    Pixmap GetArmPixmap()
    {
        m_bitmapCache.SetBitmap( GetNormalBitmap() );
        return (Pixmap)m_bitmapCache.GetArmPixmap( (WXWidget)m_widget );
    }

    Pixmap GetInsensPixmap()
    {
        m_bitmapCache.SetBitmap( GetNormalBitmap() );
        return (Pixmap)m_bitmapCache.GetInsensPixmap( (WXWidget)m_widget );
    }
protected:
    void Init();

    Widget m_widget;
    wxBitmapCache m_bitmapCache;
};

// ----------------------------------------------------------------------------
// globals
// ----------------------------------------------------------------------------

static wxToolBarTimer* wxTheToolBarTimer = NULL;

Widget wxToolBarTimer::help_popup = (Widget) 0;
Widget wxToolBarTimer::buttonWidget = (Widget) 0;
wxString wxToolBarTimer::helpString;

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxToolBarTool
// ----------------------------------------------------------------------------

wxToolBarToolBase *wxToolBar::CreateTool(int id,
                                         const wxString& label,
                                         const wxBitmap& bmpNormal,
                                         const wxBitmap& bmpToggled,
                                         wxItemKind kind,
                                         wxObject *clientData,
                                         const wxString& shortHelp,
                                         const wxString& longHelp)
{
    return new wxToolBarTool(this, id, label, bmpNormal, bmpToggled, kind,
                             clientData, shortHelp, longHelp);
}


wxToolBarToolBase *
wxToolBar::CreateTool(wxControl *control, const wxString& label)
{
    return new wxToolBarTool(this, control, label);
}

void wxToolBarTool::Init()
{
    m_widget = (Widget)0;
}

wxToolBarTool::~wxToolBarTool()
{
    if ( m_widget )
        XtDestroyWidget(m_widget);
}

// ----------------------------------------------------------------------------
// wxToolBar construction
// ----------------------------------------------------------------------------

void wxToolBar::Init()
{
    m_maxWidth = -1;
    m_maxHeight = -1;
    m_defaultWidth = 24;
    m_defaultHeight = 22;
    m_toolPacking = 2;
    m_toolSeparation = 8;
    m_xMargin = 2;
    m_yMargin = 2;
    m_maxRows = 100;
    m_maxCols = 100;
}

bool wxToolBar::Create(wxWindow *parent,
                       wxWindowID id,
                       const wxPoint& pos,
                       const wxSize& size,
                       long style,
                       const wxString& name)
{
    if( !wxControl::CreateControl( parent, id, pos, size, style,
                                   wxDefaultValidator, name ) )
        return false;
    PreCreation();

    FixupStyle();

    Widget parentWidget = (Widget) parent->GetClientWidget();

    Widget toolbar = XtVaCreateManagedWidget("toolbar",
                    xmBulletinBoardWidgetClass, (Widget) parentWidget,
                    XmNmarginWidth, 0,
                    XmNmarginHeight, 0,
                    XmNresizePolicy, XmRESIZE_NONE,
                    NULL);
/*
    Widget toolbar = XtVaCreateManagedWidget("toolbar",
                xmFormWidgetClass, (Widget) m_clientWidget,
                XmNtraversalOn, False,
                XmNhorizontalSpacing, 0,
                XmNverticalSpacing, 0,
                XmNleftOffset, 0,
                XmNrightOffset, 0,
                XmNmarginWidth, 0,
                XmNmarginHeight, 0,
                NULL);
*/

    m_mainWidget = (WXWidget) toolbar;

    wxPoint rPos = pos;
    wxSize  rSize = size;

    if( rPos.x == -1 ) rPos.x = 0;
    if( rPos.y == -1 ) rPos.y = 0;
    if( rSize.x == -1 && GetParent() )
        rSize.x = GetParent()->GetSize().x;

    PostCreation();
    AttachWidget (parent, m_mainWidget, (WXWidget) NULL,
                  rPos.x, rPos.y, rSize.x, rSize.y);

    return true;
}

wxToolBar::~wxToolBar()
{
    wxDELETE(wxTheToolBarTimer);
}

bool wxToolBar::Realize()
{
    if ( m_tools.GetCount() == 0 )
    {
        // nothing to do
        return true;
    }

    bool isVertical = GetWindowStyle() & wxTB_VERTICAL;

    // Separator spacing
    const int separatorSize = GetToolSeparation(); // 8;
    wxSize margins = GetToolMargins();
    int packing = GetToolPacking();
    int marginX = margins.x;
    int marginY = margins.y;

    int currentX = marginX;
    int currentY = marginY;

    int buttonHeight = 0, buttonWidth = 0;

    Widget button;
    Pixmap pixmap, insensPixmap;
    wxBitmap bmp, insensBmp;

    wxToolBarToolsList::compatibility_iterator node = m_tools.GetFirst();
    while ( node )
    {
        wxToolBarTool *tool = (wxToolBarTool *)node->GetData();

        switch ( tool->GetStyle() )
        {
            case wxTOOL_STYLE_CONTROL:
            {
                wxControl* control = tool->GetControl();
                wxSize sz = control->GetSize();
                wxPoint pos = control->GetPosition();
                // Allow a control to specify a y[x]-offset by setting
                // its initial position, but still don't allow it to
                // position itself above the top[left] margin.
                int controlY = (pos.y > 0) ? pos.y : currentY;
                int controlX = (pos.x > 0) ? pos.x : currentX;
                control->Move( isVertical ? controlX : currentX,
                               isVertical ? currentY : controlY );
                if ( isVertical )
                    currentY += sz.y + packing;
                else
                    currentX += sz.x + packing;

                break;
            }
            case wxTOOL_STYLE_SEPARATOR:
                // skip separators for vertical toolbars
                if( !isVertical )
                {
                    currentX += separatorSize;
                }
                break;

            case wxTOOL_STYLE_BUTTON:
                button = (Widget) 0;

                if ( tool->CanBeToggled() && !tool->GetButtonWidget() )
                {
                    button = XtVaCreateWidget("toggleButton",
                            xmToggleButtonWidgetClass, (Widget) m_mainWidget,
                            XmNx, currentX, XmNy, currentY,
                            XmNindicatorOn, False,
                            XmNshadowThickness, 2,
                            XmNborderWidth, 0,
                            XmNspacing, 0,
                            XmNmarginWidth, 0,
                            XmNmarginHeight, 0,
                            XmNmultiClick, XmMULTICLICK_KEEP,
                            XmNlabelType, XmPIXMAP,
                            NULL);
                    XtAddCallback ((Widget) button,
                                   XmNvalueChangedCallback,
                                   (XtCallbackProc) wxToolButtonCallback,
                                   (XtPointer) this);

                    XtVaSetValues ((Widget) button,
                                   XmNselectColor,
                                   m_backgroundColour.AllocColour
                                       (XtDisplay((Widget) button)),
                                   NULL);
                }
                else if( !tool->GetButtonWidget() )
                {
                    button = XtVaCreateWidget("button",
                            xmPushButtonWidgetClass, (Widget) m_mainWidget,
                            XmNx, currentX, XmNy, currentY,
                            XmNpushButtonEnabled, True,
                            XmNmultiClick, XmMULTICLICK_KEEP,
                            XmNlabelType, XmPIXMAP,
                            NULL);
                    XtAddCallback (button,
                                   XmNactivateCallback,
                                   (XtCallbackProc) wxToolButtonCallback,
                                   (XtPointer) this);
                }

                if( !tool->GetButtonWidget() )
                {
                    wxDoChangeBackgroundColour((WXWidget) button,
                                               m_backgroundColour, true);

                    tool->SetWidget(button);
                }
                else
                {
                    button = (Widget)tool->GetButtonWidget();
                    XtVaSetValues( button,
                                   XmNx, currentX, XmNy, currentY,
                                   NULL );
                }

                // For each button, if there is a mask, we must create
                // a new wxBitmap that has the correct background colour
                // for the button. Otherwise the background will just be
                // e.g. black if a transparent XPM has been loaded.
                bmp = tool->GetNormalBitmap();
                insensBmp = tool->GetDisabledBitmap();
                if ( bmp.GetMask() || insensBmp.GetMask() )
                {
                    WXPixel backgroundPixel;
                    XtVaGetValues(button, XmNbackground, &backgroundPixel,
                                  NULL);

                    wxColour col;
                    col.SetPixel(backgroundPixel);

                    if( bmp.Ok() && bmp.GetMask() )
                    {
                        bmp = wxCreateMaskedBitmap(bmp, col);
                        tool->SetNormalBitmap(bmp);
                    }

                    if( insensBmp.Ok() && insensBmp.GetMask() )
                    {
                        insensBmp = wxCreateMaskedBitmap(insensBmp, col);
                        tool->SetDisabledBitmap(insensBmp);
                    }
                }

                // Create a selected/toggled bitmap. If there isn't a 2nd
                // bitmap, we need to create it (with a darker, selected
                // background)
                WXPixel backgroundPixel;
                if ( tool->CanBeToggled() )
                    XtVaGetValues(button, XmNselectColor, &backgroundPixel,
                                  NULL);
                else
                    XtVaGetValues(button, XmNarmColor, &backgroundPixel,
                                  NULL);
                wxColour col;
                col.SetPixel(backgroundPixel);

                pixmap = (Pixmap) bmp.GetDrawable();
                {
                    wxBitmap tmp = tool->GetDisabledBitmap();

                    insensPixmap = tmp.Ok() ?
                            (Pixmap)tmp.GetDrawable() :
                            tool->GetInsensPixmap();
                }

                if (tool->CanBeToggled())
                {
                    // Toggle button
                    Pixmap pixmap2 = tool->GetArmPixmap();
                    Pixmap insensPixmap2 = tool->GetInsensPixmap();

                    XtVaSetValues (button,
                            XmNfillOnSelect, True,
                            XmNlabelPixmap, pixmap,
                            XmNselectPixmap, pixmap2,
                            XmNlabelInsensitivePixmap, insensPixmap,
                            XmNselectInsensitivePixmap, insensPixmap2,
                            XmNlabelType, XmPIXMAP,
                            NULL);
                }
                else
                {
                    Pixmap pixmap2 = tool->GetArmPixmap();

                    // Normal button
                    XtVaSetValues(button,
                            XmNlabelPixmap, pixmap,
                            XmNlabelInsensitivePixmap, insensPixmap,
                            XmNarmPixmap, pixmap2,
                            NULL);
                }

                XtManageChild(button);

                {
                    Dimension width, height;
                    XtVaGetValues(button,
                                  XmNwidth, &width,
                                  XmNheight, & height,
                                  NULL);
                    if ( isVertical )
                        currentY += height + packing;
                    else
                        currentX += width + packing;
                    buttonHeight = wxMax(buttonHeight, height);
                    buttonWidth = wxMax(buttonWidth, width);
                }

                XtAddEventHandler (button, EnterWindowMask | LeaveWindowMask,
                        False, wxToolButtonPopupCallback, (XtPointer) this);

                break;
        }

        node = node->GetNext();
    }

    SetSize( -1, -1,
             isVertical ? buttonWidth + 2 * marginX : -1,
             isVertical ? -1 : buttonHeight +  2*marginY );

    return true;
}

wxToolBarToolBase *wxToolBar::FindToolForPosition(wxCoord WXUNUSED(x),
                                                  wxCoord WXUNUSED(y)) const
{
    wxFAIL_MSG( wxT("TODO") );

    return NULL;
}

bool wxToolBar::DoInsertTool(size_t WXUNUSED(pos), wxToolBarToolBase *tool)
{
    tool->Attach(this);

    return true;
}

bool wxToolBar::DoDeleteTool(size_t WXUNUSED(pos), wxToolBarToolBase *tool)
{
    tool->Detach();

    bool isVertical = GetWindowStyle() & wxTB_VERTICAL;
    const int separatorSize = GetToolSeparation(); // 8;
    int packing = GetToolPacking();
    int offset = 0;

    for( wxToolBarToolsList::compatibility_iterator node = m_tools.GetFirst();
         node; node = node->GetNext() )
    {
        wxToolBarTool *t = (wxToolBarTool*)node->GetData();

        if( t == tool )
        {
            switch ( t->GetStyle() )
            {
            case wxTOOL_STYLE_CONTROL:
            {
                wxSize size = t->GetControl()->GetSize();
                offset = isVertical ? size.y : size.x;
                offset += packing;
                break;
            }
            case wxTOOL_STYLE_SEPARATOR:
                offset = isVertical ? 0 : separatorSize;
                break;
            case wxTOOL_STYLE_BUTTON:
            {
                Widget w = t->GetButtonWidget();
                Dimension width, height;

                XtVaGetValues( w,
                               XmNwidth, &width,
                               XmNheight, &height,
                               NULL );

                offset = isVertical ? height : width;
                offset += packing;
                break;
            }
            }
        }
        else if( offset )
        {
            switch ( t->GetStyle() )
            {
            case wxTOOL_STYLE_CONTROL:
            {
                wxPoint location = t->GetControl()->GetPosition();

                if( isVertical )
                    location.y -= offset;
                else
                    location.x -= offset;

                t->GetControl()->Move( location );
                break;
            }
            case wxTOOL_STYLE_SEPARATOR:
                break;
            case wxTOOL_STYLE_BUTTON:
            {
                Dimension x, y;
                XtVaGetValues( t->GetButtonWidget(),
                               XmNx, &x,
                               XmNy, &y,
                               NULL );

                if( isVertical )
                    y = (Dimension)(y - offset);
                else
                    x = (Dimension)(x - offset);

                XtVaSetValues( t->GetButtonWidget(),
                               XmNx, x,
                               XmNy, y,
                               NULL );
                break;
            }
            }
        }
    }

    return true;
}

void wxToolBar::DoEnableTool(wxToolBarToolBase *toolBase, bool enable)
{
    wxToolBarTool *tool = (wxToolBarTool *)toolBase;
    if (tool->GetButtonWidget()){
        XtSetSensitive(tool->GetButtonWidget(), (Boolean) enable);
    } else if (wxTOOL_STYLE_CONTROL == tool->GetStyle()){
        // Controls (such as wxChoice) do not have button widgets
        tool->GetControl()->Enable(enable);
    }
}

void wxToolBar::DoToggleTool(wxToolBarToolBase *toolBase, bool toggle)
{
    wxToolBarTool *tool = (wxToolBarTool *)toolBase;

    XmToggleButtonSetState(tool->GetButtonWidget(), (Boolean) toggle, False);
}

void wxToolBar::DoSetToggle(wxToolBarToolBase * WXUNUSED(tool),
                            bool WXUNUSED(toggle))
{
    // nothing to do
}

void wxToolBar::DoSetSize(int x, int y, int width, int height, int sizeFlags)
{
    int old_width, old_height;
    GetSize(&old_width, &old_height);

    // Correct width and height if needed.
    if ( width == -1 || height == -1 )
    {
        wxSize defaultSize = GetSize();

        if ( width == -1 )
            width = defaultSize.x;
        if ( height == -1 )
            height = defaultSize.y;
    }

    wxToolBarBase::DoSetSize(x, y, width, height, sizeFlags);

    // We must refresh the frame size when the toolbar changes size
    // otherwise the toolbar can be shown incorrectly
    if ( old_width != width || old_height != height )
    {
        // But before we send the size event check it
        // we have a frame that is not being deleted.
        wxFrame *frame = wxDynamicCast(GetParent(), wxFrame);
        if ( frame && !frame->IsBeingDeleted() )
        {
            frame->SendSizeEvent();
        }
    }
}

// ----------------------------------------------------------------------------
// Motif callbacks
// ----------------------------------------------------------------------------

wxToolBarToolBase *wxToolBar::FindToolByWidget(WXWidget w) const
{
    wxToolBarToolsList::compatibility_iterator node = m_tools.GetFirst();
    while ( node )
    {
        wxToolBarTool *tool = (wxToolBarTool *)node->GetData();
        if ( tool->GetButtonWidget() == w)
        {
            return tool;
        }

        node = node->GetNext();
    }

    return NULL;
}

static void wxToolButtonCallback(Widget w,
                                 XtPointer clientData,
                                 XtPointer WXUNUSED(ptr))
{
    wxToolBar *toolBar = (wxToolBar *) clientData;
    wxToolBarToolBase *tool = toolBar->FindToolByWidget((WXWidget) w);
    if ( !tool )
        return;

    if ( tool->CanBeToggled() )
        tool->Toggle();

    if ( !toolBar->OnLeftClick(tool->GetId(), tool->IsToggled()) )
    {
        // revert
        tool->Toggle();
    }
}


static void wxToolButtonPopupCallback(Widget w,
                                      XtPointer client_data,
                                      XEvent *event,
                                      Boolean *WXUNUSED(continue_to_dispatch))
{
    // TODO: retrieve delay before popping up tooltip from wxSystemSettings.
    static const int delayMilli = 800;

    wxToolBar* toolBar = (wxToolBar*) client_data;
    wxToolBarToolBase *tool = toolBar->FindToolByWidget((WXWidget) w);

    if ( !tool )
        return;

    wxString tooltip = tool->GetShortHelp();
    if ( !tooltip )
        return;

    if (!wxTheToolBarTimer)
        wxTheToolBarTimer = new wxToolBarTimer;

    wxToolBarTimer::buttonWidget = w;
    wxToolBarTimer::helpString = tooltip;

    /************************************************************/
    /* Popup help label                                         */
    /************************************************************/
    if (event->type == EnterNotify)
    {
        if (wxToolBarTimer::help_popup != (Widget) 0)
        {
            XtDestroyWidget (wxToolBarTimer::help_popup);
            XtPopdown (wxToolBarTimer::help_popup);
        }
        wxToolBarTimer::help_popup = (Widget) 0;

        // One shot
        wxTheToolBarTimer->Start(delayMilli, true);

    }
    /************************************************************/
    /* Popdown help label                                       */
    /************************************************************/
    else if (event->type == LeaveNotify)
    {
        if (wxTheToolBarTimer)
            wxTheToolBarTimer->Stop();
        if (wxToolBarTimer::help_popup != (Widget) 0)
        {
            XtDestroyWidget (wxToolBarTimer::help_popup);
            XtPopdown (wxToolBarTimer::help_popup);
        }
        wxToolBarTimer::help_popup = (Widget) 0;
    }
}

void wxToolBarTimer::Notify()
{
    Position x, y;

        /************************************************************/
        /* Create shell without window decorations                  */
        /************************************************************/
        help_popup = XtVaCreatePopupShell ("shell",
                                           overrideShellWidgetClass, (Widget) wxTheApp->GetTopLevelWidget(),
                                           NULL);

        /************************************************************/
        /* Get absolute position on display of toolbar button       */
        /************************************************************/
        XtTranslateCoords (buttonWidget,
                           (Position) 0,
                           (Position) 0,
                           &x, &y);

        // Move the tooltip more or less above the button
        int yOffset = 20; // TODO: What should be really?
        y = (Position)(y - yOffset);
        if (y < yOffset) y = 0;

        /************************************************************/
        /* Set the position of the help popup                       */
        /************************************************************/
        XtVaSetValues (help_popup,
                       XmNx, (Position) x,
                       XmNy, (Position) y,
                       NULL);

        /************************************************************/
        /* Create help label                                        */
        /************************************************************/
        XmString text = XmStringCreateSimple ((char*) (const char*) helpString);
        XtVaCreateManagedWidget ("help_label",
                                 xmLabelWidgetClass, help_popup,
                                 XmNlabelString, text,
                                 XtVaTypedArg,
                                 XmNforeground, XtRString, "black",
                                                strlen("black")+1,
                                 XtVaTypedArg,
                                 XmNbackground, XtRString, "LightGoldenrod",
                                                strlen("LightGoldenrod")+1,
                                 NULL);
        XmStringFree (text);

        /************************************************************/
        /* Popup help label                                         */
        /************************************************************/
        XtPopup (help_popup, XtGrabNone);
}

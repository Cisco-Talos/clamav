/////////////////////////////////////////////////////////////////////////////
// Name:        src/motif/gauge.cpp
// Purpose:     wxGauge class
// Author:      Julian Smart
// Modified by:
// Created:     17/09/98
// RCS-ID:      $Id$
// Copyright:   (c) Julian Smart
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __VMS
#include "wx/vms_x_fix.h"
#undef XtDisplay
#undef XtScreen
#undef XtWindow
#undef XtIsRealized
#undef XtParent
#undef XtClass
#endif

#include "wx/gauge.h"

#ifndef WX_PRECOMP
    #include "wx/math.h"
#endif

#ifdef __OS2__
#include <types.h>
#endif

#ifdef __VMS__
#pragma message disable nosimpint
#endif
#include <Xm/Xm.h>
#ifdef __WXMOTIF20__
#include <Xm/Scale.h>
#endif // __WXMOTIF20__
#ifdef __VMS__
#pragma message enable nosimpint
#endif
#include "wx/motif/private.h"

IMPLEMENT_DYNAMIC_CLASS(wxGauge, wxControl)

#if !wxCHECK_MOTIF_VERSION( 2, 0 ) || wxCHECK_LESSTIF()

// XmGauge copyright notice:

/*
* Copyright 1994 GROUPE BULL
*
* Permission to use, copy, modify, and distribute this software and its
* documentation for any purpose and without fee is hereby granted, provided
* that the above copyright notice appear in all copies and that both that
* copyright notice and this permission notice appear in supporting
* documentation, and that the name of GROUPE BULL not be used in advertising
* or publicity pertaining to distribution of the software without specific,
* written prior permission.  GROUPE BULL makes no representations about the
* suitability of this software for any purpose.  It is provided "as is"
* without express or implied warranty.
*
* GROUPE BULL disclaims all warranties with regard to this software,
* including all implied warranties of merchantability and fitness,
* in no event shall GROUPE BULL be liable for any special,
* indirect or consequential damages or any damages
* whatsoever resulting from loss of use, data or profits,
* whether in an action of contract, negligence or other tortious
* action, arising out of or in connection with the use
* or performance of this software.
*
*/

//// PUBLIC XMGAUGE DECLARATIONS
typedef struct _XmGaugeClassRec*  XmGaugeWidgetClass;
typedef struct _XmGaugeRec*       XmGaugeWidget;

#ifdef __cplusplus
extern "C" WidgetClass xmGaugeWidgetClass;
#else
extern WidgetClass xmGaugeWidgetClass;
#endif

typedef struct _XmGaugeCallbackStruct{
    int reason;
    XEvent *event;
    int value;
} XmGaugeCallbackStruct;


void
XmGaugeSetValue(Widget w, int value);

int
XmGaugeGetValue(Widget w);

#endif // !wxCHECK_MOTIF_VERSION( 2, 0 ) || wxCHECK_LESSTIF()

bool wxGauge::Create(wxWindow *parent, wxWindowID id,
                     int range,
                     const wxPoint& pos,
                     const wxSize& size,
                     long style,
                     const wxValidator& validator,
                     const wxString& name)
{
    if( !CreateControl( parent, id, pos, size, style, validator, name ) )
        return false;
    PreCreation();

    Widget parentWidget = (Widget) parent->GetClientWidget();

    Arg args[7];
    int count = 4;
    if (style & wxGA_HORIZONTAL)
    {
        XtSetArg (args[0], XmNorientation, XmHORIZONTAL);
        XtSetArg (args[1], XmNprocessingDirection, XmMAX_ON_RIGHT);
    }
    else
    {
        XtSetArg (args[0], XmNorientation, XmVERTICAL);
        XtSetArg (args[1], XmNprocessingDirection, XmMAX_ON_TOP);
    }
    XtSetArg(args[2], XmNminimum, 0);
    XtSetArg(args[3], XmNmaximum, range);
#if wxCHECK_MOTIF_VERSION( 2, 0 ) && !wxCHECK_LESSTIF()
    XtSetArg(args[4], XmNeditable, False); ++count;
    XtSetArg(args[5], XmNslidingMode, XmTHERMOMETER); ++count;
    // XtSetArg(args[6], XmNsliderVisual, XmFOREGROUND_COLOR ); ++count;
    Widget gaugeWidget =
        XtCreateManagedWidget("gauge", xmScaleWidgetClass,
                              parentWidget, args, count);
#else
    Widget gaugeWidget =
        XtCreateManagedWidget("gauge", xmGaugeWidgetClass,
                              parentWidget, args, count);
#endif
    m_mainWidget = (WXWidget) gaugeWidget ;

    XtManageChild (gaugeWidget);

    int x = pos.x; int y = pos.y;
    wxSize best = GetBestSize();
    if( size.x != wxDefaultCoord ) best.x = size.x;
    if( size.y != wxDefaultCoord ) best.y = size.y;

    PostCreation();
    AttachWidget (parent, m_mainWidget, (WXWidget) NULL, x, y,
                  best.x, best.y);

    return true;
}

wxSize wxGauge::DoGetBestSize() const
{
    if( HasFlag(wxGA_HORIZONTAL) )
        return wxSize( 100, 18 );
    else
        return wxSize( 18, 100 );
}

void wxGauge::SetShadowWidth(int w)
{
    if (w == 0)
        w = 1;
    XtVaSetValues((Widget) m_mainWidget, XmNshadowThickness, w, NULL);
}

void wxGauge::SetRange(int r)
{
    XtVaSetValues((Widget) m_mainWidget, XmNmaximum, r, NULL);
}

void wxGauge::SetValue(int pos)
{
    XtVaSetValues((Widget) m_mainWidget, XmNvalue, pos, NULL);
}

int wxGauge::GetShadowWidth() const
{
    Dimension w;
    XtVaGetValues((Widget) m_mainWidget, XmNshadowThickness, &w, NULL);
    return (int)w;
}

int wxGauge::GetRange() const
{
    int r;
    XtVaGetValues((Widget) m_mainWidget, XmNmaximum, &r, NULL);
    return (int)r;
}

int wxGauge::GetValue() const
{
    int pos;
    XtVaGetValues((Widget) m_mainWidget, XmNvalue, &pos, NULL);
    return pos;
}

void wxGauge::DoMoveWindow(int x, int y, int width, int height)
{
    wxGaugeBase::DoMoveWindow( x, y, width, height );
#ifdef __WXMOTIF20__
    XtVaSetValues( (Widget)m_mainWidget,
                   XmNscaleHeight, height,
                   NULL );
#endif
}

#if !wxCHECK_MOTIF_VERSION( 2, 0 ) || wxCHECK_LESSTIF()

//// PRIVATE DECLARATIONS FOR XMGAUGE

#include <Xm/PrimitiveP.h>
#include <Xm/DrawP.h>

typedef struct {
    int empty;
} XmGaugeClassPart;

typedef struct _XmGaugeClassRec {
    CoreClassPart         core_class;
    XmPrimitiveClassPart  primitive_class;
    XmGaugeClassPart      gauge_class;
} XmGaugeClassRec;


typedef struct _XmGaugePart{
    int value;
    int minimum;
    int maximum;
    unsigned char orientation;
    unsigned char processingDirection;

    XtCallbackList dragCallback;
    XtCallbackList valueChangedCallback;

    /* private fields */
    Boolean dragging; /* drag in progress ? */
    int oldx, oldy;
    GC gc;
} XmGaugePart;


typedef struct _XmGaugeRec {
    CorePart         core;
    XmPrimitivePart  primitive;
    XmGaugePart      gauge;
} XmGaugeRec;

extern XmGaugeClassRec xmGaugeClassRec;

/* Copyright 1994 GROUPE BULL -- See license conditions in file COPYRIGHT */

//// XMGAUGE IMPLEMENTATION

void
GaugePick(Widget w, XEvent *e, String *args, Cardinal  *num_args);
void
GaugeDrag(Widget w, XEvent *e, String *args, Cardinal  *num_args);
void
GaugeDrop(Widget w, XEvent *e, String *args, Cardinal  *num_args);



static char translations[] =
"<Btn1Down>: GaugePick()\n\
                            <Btn1Motion>: GaugeDrag()\n\
                            <Btn1Up>: GaugeDrop()\n\
                            ";



static XtActionsRec actions[] = {
    {"GaugePick", GaugePick},
    {"GaugeDrag", GaugeDrag},
    {"GaugeDrop", GaugeDrop},
};

static void
DrawSlider(XmGaugeWidget gw, Boolean clear)
{
#define THIS gw->gauge
    int size, sht;
    float ratio;
    /***chubraev
    char string[20];
    int len;
    unsigned long backgr,foregr;
    XRectangle rects[1];
    ***/

    sht = gw->primitive.shadow_thickness;

    ratio =  (float)THIS.value/
        (float)(THIS.maximum - THIS.minimum);
        /***chubraev
        sprintf(string,"%-d%%",(int)(ratio*100));
        len=strlen(string);
        XtVaGetValues(gw,XmNbackground,&backgr,XmNforeground,&foregr,NULL);
    ***/

    if(clear) {
        XClearArea(XtDisplay(gw), XtWindow(gw), sht, sht,
            gw->core.width - 2 * sht, gw->core.height - 2 * sht, False);
    }
    switch(THIS.orientation) {
    case XmHORIZONTAL:
        size = (int) ((gw->core.width - 2 * sht)*ratio);
        /***chubraev
        XDrawString(XtDisplay(gw), XtWindow(gw), THIS.gc, sht+gw->core.width/2,
        gw->core.height - 2 * sht, string, len);
        ***/
        switch(THIS.processingDirection) {
        case XmMAX_ON_RIGHT:
        case XmMAX_ON_BOTTOM:
            XFillRectangle(XtDisplay(gw), XtWindow(gw), THIS.gc,
                sht, sht, size, gw->core.height - 2 * sht);

                /***chubraev
                rects[0].x = sht; rects[0].y = sht;
                rects[0].width = size; rects[0].height = gw->core.height - 2 * sht;
            ***/
            break;
        case XmMAX_ON_LEFT:
        case XmMAX_ON_TOP:
            XFillRectangle(XtDisplay(gw), XtWindow(gw), THIS.gc,
                gw->core.width - size - sht, sht,
                size, gw->core.height - 2 * sht);

                /***chubraev
                rects[0].x = gw->core.width - size - sht; rects[0].y = sht;
                rects[0].width = size; rects[0].height = gw->core.height - 2 * sht;
            ***/
            break;
        }
        /***chubraev
        XSetClipRectangles(XtDisplay(gw), THIS.gc, 0, 0, rects, 1, Unsorted);
        XSetForeground(XtDisplay(gw), THIS.gc, backgr);
        XDrawString(XtDisplay(gw), XtWindow(gw), THIS.gc, sht+gw->core.width/2,
        gw->core.height - 2 * sht, string, len);
        ***/

        break;
        case XmVERTICAL:
            size = (int) ((gw->core.height - 2 * sht)*ratio);
            /***chubraev
            XDrawString(XtDisplay(gw), XtWindow(gw), THIS.gc, sht,
            sht+gw->core.height/2, string,len);
            ***/
            switch(THIS.processingDirection) {
            case XmMAX_ON_RIGHT:
            case XmMAX_ON_BOTTOM:
                XFillRectangle(XtDisplay(gw), XtWindow(gw), THIS.gc,
                    sht, sht, gw->core.width - 2 * sht, size);

                    /***chubraev
                    rects[0].x = sht; rects[0].y = sht;
                    rects[0].width = gw->core.width - 2 * sht; rects[0].height = size;
                ***/
                break;
            case XmMAX_ON_LEFT:
            case XmMAX_ON_TOP:
                XFillRectangle(XtDisplay(gw), XtWindow(gw), THIS.gc,
                    sht, gw->core.height - size - sht,
                    gw->core.width - 2 * sht, size);

                    /***chubraev
                    rects[0].x = sht; rects[0].y = gw->core.height - size - sht;
                    rects[0].width = gw->core.width - 2 * sht; rects[0].height = size;
                ***/
            }
            /***chubraev
            XSetClipRectangles(XtDisplay(gw), THIS.gc, 0, 0, rects, 1, Unsorted);
            XSetForeground(XtDisplay(gw), THIS.gc, backgr);
            XDrawString(XtDisplay(gw), XtWindow(gw), THIS.gc, sht,
            sht+gw->core.height/2, string,len);
            ***/
            break;
    }
    /***chubraev
    XSetClipMask(XtDisplay(gw), THIS.gc, None);
    XSetForeground(XtDisplay(gw), THIS.gc, foregr);
    ***/
#undef THIS
}

/* Old code
*/
#if 0
static void
DrawSlider(XmGaugeWidget gw, Boolean clear)
{
#define THIS gw->gauge
    int size, sht;
    /*    float ratio; */

    sht = gw->primitive.shadow_thickness;
    /* See fix comment below: can cause divide by zero error.
    ratio = (float)((float)THIS.maximum -
    (float)THIS.minimum) / (float)THIS.value;
    */
    if(clear) {
        XClearArea(XtDisplay(gw), XtWindow(gw), sht, sht,
            gw->core.width - 2 * sht, gw->core.height - 2 * sht, False);
    }
    switch(THIS.orientation) {
    case XmHORIZONTAL:
        /* size = (gw->core.width - 2 * sht) / ratio; */
        /* A fix suggested by Dmitri Chubraev */
        size = (gw->core.width - 2 * sht) /((float)THIS.maximum-(float)THIS.minimum)*(float)THIS.value;
        switch(THIS.processingDirection) {
        case XmMAX_ON_RIGHT:
        case XmMAX_ON_BOTTOM:
            XFillRectangle(XtDisplay(gw), XtWindow(gw), THIS.gc,
                sht, sht, size, gw->core.height - 2 * sht);
            break;
        case XmMAX_ON_LEFT:
        case XmMAX_ON_TOP:
            XFillRectangle(XtDisplay(gw), XtWindow(gw), THIS.gc,
                gw->core.width - size - sht, sht,
                size, gw->core.height - 2 * sht);
            break;
        }
        break;
        case XmVERTICAL:
            size = (gw->core.height - 2 * sht) /((float)THIS.maximum-(float)THIS.minimum)*(float)THIS.value;
            /* size = (gw->core.height - 2 * sht)/ ratio; */
            switch(THIS.processingDirection) {
            case XmMAX_ON_RIGHT:
            case XmMAX_ON_BOTTOM:
                XFillRectangle(XtDisplay(gw), XtWindow(gw), THIS.gc,
                    sht, sht, gw->core.width - 2 * sht, size);
                break;
            case XmMAX_ON_LEFT:
            case XmMAX_ON_TOP:
                XFillRectangle(XtDisplay(gw), XtWindow(gw), THIS.gc,
                    sht, gw->core.height - size - sht,
                    gw->core.width - 2 * sht, size);
            }
            break;
    }
#undef THIS
}
#endif

static void
Initialize(Widget WXUNUSED(req), Widget new_w, ArgList WXUNUSED(args), Cardinal *WXUNUSED(num_args ))
{
    XmGaugeWidget gw = (XmGaugeWidget)new_w;
#define THIS gw->gauge
    XGCValues values;

    values.foreground = gw->primitive.foreground;
    THIS.gc = XtGetGC(new_w, GCForeground, &values);

#undef THIS

}



static void
Destroy(Widget w)
{
    XmGaugeWidget gw = (XmGaugeWidget)w;
#define THIS gw->gauge
    XtReleaseGC(w, THIS.gc);
#undef THIS
}




static Boolean
SetValues(
          Widget cw,
          Widget WXUNUSED(rw),
          Widget nw,
          ArgList WXUNUSED(args),
          Cardinal *WXUNUSED(num_args) )
{
    XmGaugeWidget cgw = (XmGaugeWidget)cw;
    XmGaugeWidget ngw = (XmGaugeWidget)nw;

    Boolean redraw = False;
    if(cgw->primitive.foreground != ngw->primitive.foreground) {
        XGCValues values;

        redraw = True;
        XtReleaseGC(nw, ngw->gauge.gc);
        values.foreground = ngw->primitive.foreground;
        ngw->gauge.gc = XtGetGC(nw, GCForeground, &values);
    }
    if(cgw->gauge.value != ngw->gauge.value) {
        redraw = True;
    }
    return redraw;
}




static void
ExposeProc(Widget w, XEvent *WXUNUSED(event), Region WXUNUSED(r))
{
    XmGaugeWidget gw = (XmGaugeWidget)w;
#define THIS gw->gauge
    int sht;

    sht = gw->primitive.shadow_thickness;
    _XmDrawShadows(XtDisplay(w), XtWindow(w),
        gw->primitive.top_shadow_GC,
        gw->primitive.bottom_shadow_GC,
        0, 0, w->core.width, w->core.height,
        (Dimension)sht, XmSHADOW_IN);
    DrawSlider(gw, False);
#undef THIS
}





static XtResource
resources[] = {
#define offset(field) XtOffset(XmGaugeWidget, gauge.field)
    {XmNvalue, XmCValue, XtRInt, sizeof(int),
        offset(value), XtRImmediate, (caddr_t)10},

    {XmNminimum, XmCValue, XtRInt, sizeof(int),
    offset(minimum), XtRImmediate, (caddr_t)0},

    {XmNmaximum, XmCValue, XtRInt, sizeof(int),
    offset(maximum), XtRImmediate, (caddr_t)100},

    {XmNorientation, XmCOrientation, XmROrientation, sizeof(unsigned char),
    offset(orientation), XtRImmediate, (caddr_t)XmVERTICAL},

    {XmNprocessingDirection, XmCProcessingDirection,
    XmRProcessingDirection, sizeof(unsigned char),
    offset(processingDirection), XtRImmediate, (caddr_t)XmMAX_ON_RIGHT},

    {XmNdragCallback, XmCCallback, XmRCallback, sizeof(XtCallbackList),
    offset(dragCallback), XtRImmediate, (caddr_t)NULL},

    {XmNvalueChangedCallback, XmCCallback, XmRCallback, sizeof(XtCallbackList),
    offset(valueChangedCallback), XtRImmediate, (caddr_t)NULL},


#undef offset
};


XmGaugeClassRec xmGaugeClassRec = {
    {    /* core fields */
        (WidgetClass) &xmPrimitiveClassRec, /* superclass */
        "XmGauge",            /* class_name */
        sizeof(XmGaugeRec),   /* widget_size */
        NULL,                 /* class_initialize */
        NULL,                 /* class_part_initialize */
        False,                /* class_inited */
        Initialize,           /* initialize */
        NULL,                 /* initialize_hook */
        XtInheritRealize,     /* realize */
        actions,              /* actions */
        XtNumber(actions),    /* num_actions */
        resources,            /* resources */
        XtNumber(resources),  /* num_resources */
        NULLQUARK,            /* xrm_class */
        True,                 /* compress_motion */
        True,                 /* compress_exposure */
        True,                 /* compress_enterleave */
        False,                /* visible_interest */
        Destroy,              /* destroy */
        NULL,                 /* resize */
        ExposeProc,           /* expose */
        SetValues,            /* set_values */
        NULL,                 /* set_values_hook */
        XtInheritSetValuesAlmost, /* set_values_almost */
        NULL,                 /* get_values_hook */
        NULL,                 /* accept_focus */
        XtVersion,            /* version */
        NULL,                 /* callback_private */
        translations,         /* tm_table */
        NULL,                 /* query_geometry */
        NULL,                 /* display_accelerator */
        NULL                  /* extension */
    },
    /* primitive_class fields */
    {
        NULL,                 /* border_highlight */
        NULL,                 /* border_unhighlight */
        NULL,                 /* translations */
        NULL,                 /* arm_and_activate */
        NULL,                 /* syn_resources */
        0,                    /* num_syn_resources */
        NULL                  /* extension */
    },
    { /* gauge fields */
        0                     /* empty */
    }
};

WidgetClass xmGaugeWidgetClass = (WidgetClass)&xmGaugeClassRec;




void
GaugePick(Widget WXUNUSED(w), XEvent *WXUNUSED(e), String *WXUNUSED(args), Cardinal  *WXUNUSED(num_args))
{
    /* Commented out for a read-only gauge in wxWidgets */
#if 0
    XmGaugeWidget gw = (XmGaugeWidget)w;
#define THIS gw->gauge
    int size, sht;
    float ratio;
    Boolean dragging = False;
    XButtonEvent *event = (XButtonEvent *)e;
    int x, y;

    x = event->x;
    y = event->y;
    sht = gw->primitive.shadow_thickness;
    _XmDrawShadows(XtDisplay(w), XtWindow(w),
        gw->primitive.top_shadow_GC,
        gw->primitive.bottom_shadow_GC,
        0, 0, w->core.width, w->core.height,
        sht, XmSHADOW_IN);


    ratio = (float)((float)THIS.maximum -
        (float)THIS.minimum) / (float)THIS.value;
    switch(THIS.orientation) {
    case XmHORIZONTAL:
        size = (w->core.width - 2 * sht) / ratio;
        switch(THIS.processingDirection) {
        case XmMAX_ON_RIGHT:
        case XmMAX_ON_BOTTOM:
            dragging = (x > sht) && (y > sht) &&
                (x < sht + size) && (y < w->core.height - sht);
            break;
        case XmMAX_ON_LEFT:
        case XmMAX_ON_TOP:
            dragging = (x > w->core.width - size - sht) && (y > sht) &&
                (x < w->core.width - sht) && (y < w->core.height + sht);
            break;
        }
        break;
        case XmVERTICAL:
            size = (w->core.height - 2 * sht) / ratio;
            switch(THIS.processingDirection) {
            case XmMAX_ON_RIGHT:
            case XmMAX_ON_BOTTOM:
                dragging = (x > sht) && (y > sht) &&
                    (x < w->core.width - sht) &&
                    (y < w->core.width - 2 * sht + size);
                break;
            case XmMAX_ON_LEFT:
            case XmMAX_ON_TOP:
                dragging = (x > sht) && (y > w->core.height - size - sht) &&
                    (x < w->core.width - sht) && (y < w->core.height - sht);
            }
            break;
    }
    THIS.dragging = dragging;
    THIS.oldx = x;
    THIS.oldy = y;
#undef THIS
#endif
}

void
GaugeDrag(Widget WXUNUSED(w), XEvent *WXUNUSED(e), String *WXUNUSED(args), Cardinal  *WXUNUSED(num_args))
{
    /* Commented out for a read-only gauge in wxWidgets */
#if 0
    XmGaugeWidget gw = (XmGaugeWidget)w;
#define THIS gw->gauge
    int sht, x, y, max, value;
    float ratio, nratio, size, nsize, fvalue, delta;
    XMotionEvent *event = (XMotionEvent *)e;

    if( ! THIS.dragging) return;

    x = event->x;
    y = event->y;
    sht = gw->primitive.shadow_thickness;

    ratio = (float)THIS.value / (float)((float)THIS.maximum -
        (float)THIS.minimum);
    switch(THIS.orientation) {
    case XmHORIZONTAL:
        max = (w->core.width - 2 * sht);
        size = (float)max * ratio;
        delta =  (float)x - (float)THIS.oldx;
        break;
    case XmVERTICAL:
        max = (w->core.height - 2 * sht);
        size = (float) max * ratio;
        delta =  (float)y - (float)THIS.oldy;
        break;
    }
    switch(THIS.processingDirection) {
    case XmMAX_ON_RIGHT:
    case XmMAX_ON_BOTTOM:
        nsize = size + delta;
        break;
    default:
        nsize = size - delta;
    }
    if(nsize > (float)max) nsize = (float)max;
    if(nsize < (float)0 ) nsize = (float)0;
    nratio =  nsize / (float)max;

    fvalue = (int)((float)THIS.maximum -
        (float)THIS.minimum) * (float)nsize / (float)max;
    value = wxRound(fvalue);

    THIS.value = value;
    THIS.oldx = x;
    THIS.oldy = y;

    /* clear old slider only if it was larger */
    DrawSlider(gw, (nsize < size));

    {
        XmGaugeCallbackStruct call;

        if(NULL  != THIS.dragCallback) {
            call.reason = XmCR_DRAG;
            call.event = e;
            call.value = THIS.value;
            XtCallCallbacks(w, XmNdragCallback, &call);
        }
    }
#undef THIS
#endif
}


void
GaugeDrop(Widget WXUNUSED(w), XEvent *WXUNUSED(e), String *WXUNUSED(args), Cardinal  *WXUNUSED(num_args))
{
    /* Commented out for a read-only gauge in wxWidgets */
#if 0
    XmGaugeWidget gw = (XmGaugeWidget)w;
#define THIS gw->gauge
    if( ! THIS.dragging) return;

    if(NULL  != THIS.valueChangedCallback) {
        XmGaugeCallbackStruct call;
        call.reason = XmCR_VALUE_CHANGED;
        call.event = e;
        call.value = THIS.value;
        XtCallCallbacks(w, XmNvalueChangedCallback, &call);
    }
    THIS.dragging = False;
#undef THIS
#endif
}

void
XmGaugeSetValue(Widget w, int value)
{
    XmGaugeWidget gw = (XmGaugeWidget)w;

    gw->gauge.value = value;
    DrawSlider(gw, True);
    XFlush(XtDisplay(w));
}

int
XmGaugeGetValue(Widget w)
{
    XmGaugeWidget gw = (XmGaugeWidget)w;

    return gw->gauge.value;
}

#endif // !wxCHECK_MOTIF_VERSION( 2, 0 ) || wxCHECK_LESSTIF()

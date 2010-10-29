/* ///////////////////////////////////////////////////////////////////////////
// Name:        src/gtk1/win_gtk.c
// Purpose:     Native GTK+ widget for wxWidgets, based on GtkLayout and
//              GtkFixed. It makes use of the gravity window property and
//              therefore does not work with GTK 1.0.
// Author:      Robert Roebling
// Id:          $Id$
// Copyright:   (c) 1998 Robert Roebling
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////// */

#ifdef VMS
#define XCheckIfEvent XCHECKIFEVENT
#endif

#include "wx/platform.h"
#include "wx/gtk1/win_gtk.h"
#include "gtk/gtksignal.h"
#include "gtk/gtkprivate.h"
#include "gdk/gdkx.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/Xatom.h>

#define IS_ONSCREEN(x,y) ((x >= G_MINSHORT) && (x <= G_MAXSHORT) && \
                          (y >= G_MINSHORT) && (y <= G_MAXSHORT))


typedef struct _GtkPizzaAdjData  GtkPizzaAdjData;

struct _GtkPizzaAdjData
{
    gint dx;
    gint dy;
};

static void gtk_pizza_class_init    (GtkPizzaClass    *klass);
static void gtk_pizza_init          (GtkPizza         *pizza);

static void gtk_pizza_realize       (GtkWidget        *widget);
static void gtk_pizza_unrealize     (GtkWidget        *widget);

static void gtk_pizza_map           (GtkWidget        *widget);

static void gtk_pizza_size_request  (GtkWidget        *widget,
                                     GtkRequisition   *requisition);
static void gtk_pizza_size_allocate (GtkWidget        *widget,
                                     GtkAllocation    *allocation);
static void gtk_pizza_draw          (GtkWidget        *widget,
                                     GdkRectangle     *area);
static gint gtk_pizza_expose        (GtkWidget        *widget,
                                     GdkEventExpose   *event);
static void gtk_pizza_style_set     (GtkWidget *widget,
                                     GtkStyle  *previous_style);
static void gtk_pizza_add           (GtkContainer     *container,
                                     GtkWidget        *widget);
static void gtk_pizza_remove        (GtkContainer     *container,
                                     GtkWidget        *widget);
static void gtk_pizza_forall        (GtkContainer     *container,
                                     gboolean          include_internals,
                                     GtkCallback       callback,
                                     gpointer          callback_data);

static void     gtk_pizza_allocate_child     (GtkPizza      *pizza,
                                              GtkPizzaChild *child);
static void     gtk_pizza_adjust_allocations_recurse (GtkWidget *widget,
                                                      gpointer   cb_data);

static void     gtk_pizza_position_child     (GtkPizza      *pizza,
                                              GtkPizzaChild *child);
static void     gtk_pizza_position_children  (GtkPizza      *pizza);

static GdkFilterReturn gtk_pizza_filter      (GdkXEvent      *gdk_xevent,
                                              GdkEvent       *event,
                                              gpointer        data);
static GdkFilterReturn gtk_pizza_main_filter (GdkXEvent      *gdk_xevent,
                                              GdkEvent       *event,
                                              gpointer        data);

static GtkType gtk_pizza_child_type (GtkContainer     *container);

static void  gtk_pizza_scroll_set_adjustments (GtkPizza      *pizza,
                                               GtkAdjustment *hadj,
                                               GtkAdjustment *vadj);


static GtkContainerClass *pizza_parent_class = NULL;

static gboolean gravity_works;

GtkType
gtk_pizza_get_type ()
{
    static GtkType pizza_type = 0;

    if (!pizza_type)
    {
        GtkTypeInfo pizza_info =
        {
            "GtkPizza",
            sizeof (GtkPizza),
            sizeof (GtkPizzaClass),
            (GtkClassInitFunc) gtk_pizza_class_init,
            (GtkObjectInitFunc) gtk_pizza_init,
            /* reserved_1 */ NULL,
            /* reserved_2 */ NULL,
            (GtkClassInitFunc) NULL,
        };
        pizza_type = gtk_type_unique (gtk_container_get_type (), &pizza_info);
    }

    return pizza_type;
}

static void
gtk_pizza_class_init (GtkPizzaClass *klass)
{
    GtkObjectClass *object_class;
    GtkWidgetClass *widget_class;
    GtkContainerClass *container_class;

    object_class = (GtkObjectClass*) klass;
    widget_class = (GtkWidgetClass*) klass;
    container_class = (GtkContainerClass*) klass;
    pizza_parent_class = gtk_type_class (GTK_TYPE_CONTAINER);

    widget_class->map = gtk_pizza_map;
    widget_class->realize = gtk_pizza_realize;
    widget_class->unrealize = gtk_pizza_unrealize;
    widget_class->size_request = gtk_pizza_size_request;
    widget_class->size_allocate = gtk_pizza_size_allocate;
    widget_class->draw = gtk_pizza_draw;
    widget_class->expose_event = gtk_pizza_expose;
    widget_class->style_set = gtk_pizza_style_set;

    container_class->add = gtk_pizza_add;
    container_class->remove = gtk_pizza_remove;
    container_class->forall = gtk_pizza_forall;

    container_class->child_type = gtk_pizza_child_type;

    klass->set_scroll_adjustments = gtk_pizza_scroll_set_adjustments;

    widget_class->set_scroll_adjustments_signal =
    gtk_signal_new ("set_scroll_adjustments",
                    GTK_RUN_LAST,
                    object_class->type,
                    GTK_SIGNAL_OFFSET (GtkPizzaClass, set_scroll_adjustments),
                    gtk_marshal_NONE__POINTER_POINTER,
                    GTK_TYPE_NONE, 2, GTK_TYPE_ADJUSTMENT, GTK_TYPE_ADJUSTMENT);
}

static GtkType
gtk_pizza_child_type (GtkContainer     *container)
{
    return GTK_TYPE_WIDGET;
}

static void
gtk_pizza_init (GtkPizza *pizza)
{
    GTK_WIDGET_UNSET_FLAGS (pizza, GTK_NO_WINDOW);

    pizza->shadow_type = GTK_MYSHADOW_NONE;

    pizza->children = NULL;

    pizza->width = 20;
    pizza->height = 20;

    pizza->bin_window = NULL;

    pizza->xoffset = 0;
    pizza->yoffset = 0;

    pizza->configure_serial = 0;
    pizza->scroll_x = 0;
    pizza->scroll_y = 0;
    pizza->visibility = GDK_VISIBILITY_PARTIAL;

    pizza->clear_on_draw = TRUE;
    pizza->use_filter = TRUE;
    pizza->external_expose = FALSE;
}

GtkWidget*
gtk_pizza_new ()
{
    GtkPizza *pizza;

    pizza = gtk_type_new (gtk_pizza_get_type ());

    return GTK_WIDGET (pizza);
}

static void
gtk_pizza_scroll_set_adjustments (GtkPizza     *pizza,
                                    GtkAdjustment  *hadj,
                                    GtkAdjustment  *vadj)
{
   /* We handle scrolling in the wxScrolledWindow, not here. */
}

void
gtk_pizza_set_shadow_type (GtkPizza        *pizza,
                           GtkMyShadowType  type)
{
    g_return_if_fail (pizza != NULL);
    g_return_if_fail (GTK_IS_PIZZA (pizza));

    if ((GtkMyShadowType) pizza->shadow_type != type)
    {
        pizza->shadow_type = type;

        if (GTK_WIDGET_VISIBLE (pizza))
        {
            gtk_widget_size_allocate (GTK_WIDGET (pizza), &(GTK_WIDGET (pizza)->allocation));
            gtk_widget_queue_draw (GTK_WIDGET (pizza));
        }
    }
}

void
gtk_pizza_set_clear (GtkPizza  *pizza,
                     gboolean   clear)
{
    g_return_if_fail (pizza != NULL);
    g_return_if_fail (GTK_IS_PIZZA (pizza));

    pizza->clear_on_draw = clear;
}

void
gtk_pizza_set_filter (GtkPizza  *pizza,
                      gboolean   use)
{
    g_return_if_fail (pizza != NULL);
    g_return_if_fail (GTK_IS_PIZZA (pizza));

    pizza->use_filter = use;
}

void
gtk_pizza_set_external (GtkPizza  *pizza,
                        gboolean   expose)
{
    g_return_if_fail (pizza != NULL);
    g_return_if_fail (GTK_IS_PIZZA (pizza));

    pizza->external_expose = expose;
}

void
gtk_pizza_put (GtkPizza   *pizza,
               GtkWidget  *widget,
               gint        x,
               gint        y,
               gint        width,
               gint        height)
{
    GtkPizzaChild *child_info;

    g_return_if_fail (pizza != NULL);
    g_return_if_fail (GTK_IS_PIZZA (pizza));
    g_return_if_fail (widget != NULL);

    child_info = g_new (GtkPizzaChild, 1);

    child_info->widget = widget;
    child_info->x = x;
    child_info->y = y;
    child_info->width = width;
    child_info->height = height;

    pizza->children = g_list_append (pizza->children, child_info);

    if (GTK_WIDGET_REALIZED (pizza))
      gtk_widget_set_parent_window (widget, pizza->bin_window);

    gtk_widget_set_parent (widget, GTK_WIDGET (pizza));

    if (!IS_ONSCREEN (x, y))
       GTK_PRIVATE_SET_FLAG (widget, GTK_IS_OFFSCREEN);

    gtk_widget_set_usize (widget, width, height);
}

void
gtk_pizza_move (GtkPizza     *pizza,
                  GtkWidget  *widget,
                  gint        x,
                  gint        y)
{
    GtkPizzaChild *child;
    GList *children;

    g_return_if_fail (pizza != NULL);
    g_return_if_fail (GTK_IS_PIZZA (pizza));
    g_return_if_fail (widget != NULL);

    children = pizza->children;
    while (children)
    {
        child = children->data;
        children = children->next;

        if (child->widget == widget)
        {
            if ((child->x == x) && (child->y == y))
                break;

            child->x = x;
            child->y = y;

            if (GTK_WIDGET_VISIBLE (widget) && GTK_WIDGET_VISIBLE (pizza))
                gtk_widget_queue_resize (widget);
            break;
        }
    }
}

void
gtk_pizza_resize (GtkPizza    *pizza,
                  GtkWidget   *widget,
                  gint         width,
                  gint         height)
{
    GtkPizzaChild *child;
    GList *children;

    g_return_if_fail (pizza != NULL);
    g_return_if_fail (GTK_IS_PIZZA (pizza));
    g_return_if_fail (widget != NULL);

    children = pizza->children;
    while (children)
    {
        child = children->data;
        children = children->next;

        if (child->widget == widget)
        {
            if ((child->width == width) && (child->height == height))
                break;

            child->width = width;
            child->height = height;

            gtk_widget_set_usize (widget, width, height);

            if (GTK_WIDGET_VISIBLE (widget) && GTK_WIDGET_VISIBLE (pizza))
                gtk_widget_queue_resize (widget);
            break;
        }
    }
}

void
gtk_pizza_set_size (GtkPizza   *pizza,
                    GtkWidget  *widget,
                    gint        x,
                    gint        y,
                    gint        width,
                    gint        height)
{
    GtkPizzaChild *child;
    GList *children;

    g_return_if_fail (pizza != NULL);
    g_return_if_fail (GTK_IS_PIZZA (pizza));
    g_return_if_fail (widget != NULL);

    children = pizza->children;
    while (children)
    {
        child = children->data;
        children = children->next;

        if (child->widget == widget)
        {
            if ((child->x == x) &&
                (child->y == y) &&
                (child->width == width) &&
                (child->height == height)) return;

            child->x = x;
            child->y = y;
            child->width = width;
            child->height = height;

            gtk_widget_set_usize (widget, width, height);

            if (GTK_WIDGET_VISIBLE (widget) && GTK_WIDGET_VISIBLE (pizza))
                gtk_widget_queue_resize (widget);

            return;
        }
    }
}

gint
gtk_pizza_child_resized  (GtkPizza   *pizza,
                          GtkWidget  *widget)
{
    GtkPizzaChild *child;
    GList *children;

    g_return_val_if_fail (pizza != NULL, FALSE);
    g_return_val_if_fail (GTK_IS_PIZZA (pizza), FALSE);
    g_return_val_if_fail (widget != NULL, FALSE);

    children = pizza->children;
    while (children)
    {
        child = children->data;
        children = children->next;

        if (child->widget == widget)
        {
            return ((child->width == widget->allocation.width) &&
                    (child->height == widget->allocation.height));
        }
    }

    return FALSE;
}

static void
gtk_pizza_map (GtkWidget *widget)
{
    GtkPizza *pizza;
    GtkPizzaChild *child;
    GList *children;

    g_return_if_fail (widget != NULL);
    g_return_if_fail (GTK_IS_PIZZA (widget));

    GTK_WIDGET_SET_FLAGS (widget, GTK_MAPPED);
    pizza = GTK_PIZZA (widget);

    children = pizza->children;
    while (children)
    {
        child = children->data;
        children = children->next;

        if ( GTK_WIDGET_VISIBLE (child->widget) &&
            !GTK_WIDGET_MAPPED (child->widget) &&
            !GTK_WIDGET_IS_OFFSCREEN (child->widget))
        {
            gtk_widget_map (child->widget);
        }
    }

    gdk_window_show (widget->window);
    gdk_window_show (pizza->bin_window);
}

static void
gtk_pizza_realize (GtkWidget *widget)
{
    GtkPizza *pizza;
    GdkWindowAttr attributes;
    gint attributes_mask;
    GtkPizzaChild *child;
    GList *children;

    g_return_if_fail (widget != NULL);
    g_return_if_fail (GTK_IS_PIZZA (widget));

    pizza = GTK_PIZZA (widget);
    GTK_WIDGET_SET_FLAGS (widget, GTK_REALIZED);

    attributes.window_type = GDK_WINDOW_CHILD;

    attributes.x = widget->allocation.x;
    attributes.y = widget->allocation.y;
    attributes.width = widget->allocation.width;
    attributes.height = widget->allocation.height;

#ifndef __WXUNIVERSAL__
    if (pizza->shadow_type == GTK_MYSHADOW_NONE)
    {
        /* no border, no changes to sizes */
    }
    else if (pizza->shadow_type == GTK_MYSHADOW_THIN)
    {
        /* GTK_MYSHADOW_THIN == wxSIMPLE_BORDER */
        attributes.x += 1;
        attributes.y += 1;
        attributes.width -= 2;
        attributes.height -= 2;
    }
    else
    {
        /* GTK_MYSHADOW_IN == wxSUNKEN_BORDER */
        /* GTK_MYSHADOW_OUT == wxRAISED_BORDER */
        attributes.x += 2;
        attributes.y += 2;
        attributes.width -= 4;
        attributes.height -= 4;
    }
#endif /* __WXUNIVERSAL__ */

    /* minimal size */
    if (attributes.width < 2) attributes.width = 2;
    if (attributes.height < 2) attributes.height = 2;

    attributes.wclass = GDK_INPUT_OUTPUT;
    attributes.visual = gtk_widget_get_visual (widget);
    attributes.colormap = gtk_widget_get_colormap (widget);
    attributes.event_mask = GDK_VISIBILITY_NOTIFY_MASK;
    attributes_mask = GDK_WA_X | GDK_WA_Y | GDK_WA_VISUAL | GDK_WA_COLORMAP;

    widget->window = gdk_window_new(gtk_widget_get_parent_window (widget),
                                     &attributes, attributes_mask);
    gdk_window_set_user_data (widget->window, widget);

    attributes.x = 0;
    attributes.y = 0;

    attributes.event_mask = gtk_widget_get_events (widget);
    attributes.event_mask |= GDK_EXPOSURE_MASK              |
                             GDK_POINTER_MOTION_MASK        |
                             GDK_POINTER_MOTION_HINT_MASK   |
                             GDK_BUTTON_MOTION_MASK         |
                             GDK_BUTTON1_MOTION_MASK        |
                             GDK_BUTTON2_MOTION_MASK        |
                             GDK_BUTTON3_MOTION_MASK        |
                             GDK_BUTTON_PRESS_MASK          |
                             GDK_BUTTON_RELEASE_MASK        |
                             GDK_KEY_PRESS_MASK             |
                             GDK_KEY_RELEASE_MASK           |
                             GDK_ENTER_NOTIFY_MASK          |
                             GDK_LEAVE_NOTIFY_MASK          |
                             GDK_FOCUS_CHANGE_MASK;

    pizza->bin_window = gdk_window_new(widget->window,
                                          &attributes, attributes_mask);
    gdk_window_set_user_data (pizza->bin_window, widget);

    widget->style = gtk_style_attach (widget->style, widget->window);
    gtk_style_set_background (widget->style, widget->window, GTK_STATE_NORMAL);
    gtk_style_set_background (widget->style, pizza->bin_window, GTK_STATE_NORMAL );

/*
    gdk_window_set_back_pixmap( widget->window, NULL, FALSE );
    gdk_window_set_back_pixmap( pizza->bin_window, NULL, FALSE );
*/

    /* add filters for intercepting visibility and expose events */
    gdk_window_add_filter (widget->window, gtk_pizza_main_filter, pizza);
    gdk_window_add_filter (pizza->bin_window, gtk_pizza_filter, pizza);

    /* we NEED gravity or we'll give up */
    gravity_works = gdk_window_set_static_gravities (pizza->bin_window, TRUE);

    /* cannot be done before realisation */
    children = pizza->children;
    while (children)
    {
        child = children->data;
        children = children->next;

        gtk_widget_set_parent_window (child->widget, pizza->bin_window);
    }
}

static void
gtk_pizza_unrealize (GtkWidget *widget)
{
    GtkPizza *pizza;

    g_return_if_fail (widget != NULL);
    g_return_if_fail (GTK_IS_PIZZA (widget));

    pizza = GTK_PIZZA (widget);

    gdk_window_set_user_data (pizza->bin_window, NULL);
    gdk_window_destroy (pizza->bin_window);
    pizza->bin_window = NULL;

    if (GTK_WIDGET_CLASS (pizza_parent_class)->unrealize)
       (* GTK_WIDGET_CLASS (pizza_parent_class)->unrealize) (widget);
}

static void
gtk_pizza_size_request (GtkWidget      *widget,
                        GtkRequisition *requisition)
{
    GtkPizza *pizza;
    GtkPizzaChild *child;
    GList *children;
    GtkRequisition child_requisition;

    g_return_if_fail (widget != NULL);
    g_return_if_fail (GTK_IS_PIZZA (widget));
    g_return_if_fail (requisition != NULL);

    pizza = GTK_PIZZA (widget);

    children = pizza->children;
    while (children)
    {
        child = children->data;
        children = children->next;

        if (GTK_WIDGET_VISIBLE (child->widget))
        {
            gtk_widget_size_request (child->widget, &child_requisition);
        }
    }

    /* request very little, I'm not sure if requesting nothing
       will always have positive effects on stability... */
    requisition->width = 2;
    requisition->height = 2;
}

static void
gtk_pizza_size_allocate (GtkWidget     *widget,
                         GtkAllocation *allocation)
{
    GtkPizza *pizza;
    gint border;
    gint x,y,w,h;
    GtkPizzaChild *child;
    GList *children;

    g_return_if_fail (widget != NULL);
    g_return_if_fail (GTK_IS_PIZZA(widget));
    g_return_if_fail (allocation != NULL);

    pizza = GTK_PIZZA (widget);

    widget->allocation = *allocation;

    if (pizza->shadow_type == GTK_MYSHADOW_NONE)
        border = 0;
    else
    if (pizza->shadow_type == GTK_MYSHADOW_THIN)
        border = 1;
    else
        border = 2;

    x = allocation->x + border;
    y = allocation->y + border;
    w = allocation->width - border*2;
    h = allocation->height - border*2;

    if (GTK_WIDGET_REALIZED (widget))
    {
        gdk_window_move_resize( widget->window, x, y, w, h );
        gdk_window_move_resize( pizza->bin_window, 0, 0, w, h );
    }

    children = pizza->children;
    while (children)
    {
        child = children->data;
        children = children->next;

        gtk_pizza_position_child (pizza, child);
        gtk_pizza_allocate_child (pizza, child);
    }
}

static void
gtk_pizza_draw (GtkWidget    *widget,
                GdkRectangle *area)
{
    GtkPizza *pizza;
    GtkPizzaChild *child;
    GdkRectangle child_area;
    GList *children;

    g_return_if_fail (widget != NULL);
    g_return_if_fail (GTK_IS_PIZZA (widget));

    pizza = GTK_PIZZA (widget);

    /* Sometimes, We handle all expose events in window.cpp now. */
    if (pizza->external_expose)
        return;

    children = pizza->children;
    if ( !(GTK_WIDGET_APP_PAINTABLE (widget)) &&
         (pizza->clear_on_draw))
    {
        gdk_window_clear_area( pizza->bin_window,
                                area->x, area->y, area->width, area->height);
    }

    while (children)
    {
        child = children->data;
        children = children->next;

        if (gtk_widget_intersect (child->widget, area, &child_area))
            gtk_widget_draw (child->widget, &child_area);
    }
}

static gint
gtk_pizza_expose (GtkWidget      *widget,
                  GdkEventExpose *event)
{
    GtkPizza *pizza;
    GtkPizzaChild *child;
    GdkEventExpose child_event;
    GList *children;

    g_return_val_if_fail (widget != NULL, FALSE);
    g_return_val_if_fail (GTK_IS_PIZZA (widget), FALSE);
    g_return_val_if_fail (event != NULL, FALSE);

    pizza = GTK_PIZZA (widget);

    if (event->window != pizza->bin_window)
        return FALSE;

    /* We handle all expose events in window.cpp now. */
    if (pizza->external_expose)
        return FALSE;

    children = pizza->children;
    while (children)
    {
        child = children->data;
        children = children->next;

        child_event = *event;

        if (GTK_WIDGET_NO_WINDOW (child->widget) &&
            GTK_WIDGET_DRAWABLE (child->widget) &&
            gtk_widget_intersect (child->widget, &event->area, &child_event.area))
        {
            gtk_widget_event (child->widget, (GdkEvent*) &child_event);
        }
    }

    return TRUE;
}

static void
gtk_pizza_style_set(GtkWidget *widget, GtkStyle  *previous_style)
{
    if (GTK_WIDGET_REALIZED(widget))
    {
        gtk_style_set_background(widget->style, widget->window, GTK_STATE_NORMAL);
        gtk_style_set_background(widget->style, GTK_PIZZA(widget)->bin_window, GTK_STATE_NORMAL );
    }

    (* GTK_WIDGET_CLASS (pizza_parent_class)->style_set) (widget, previous_style);
}

static void
gtk_pizza_add (GtkContainer *container,
               GtkWidget    *widget)
{
    g_return_if_fail (container != NULL);
    g_return_if_fail (GTK_IS_PIZZA (container));
    g_return_if_fail (widget != NULL);

    gtk_pizza_put (GTK_PIZZA (container), widget, 0, 0, 20, 20 );
}

static void
gtk_pizza_remove (GtkContainer *container,
                  GtkWidget    *widget)
{
    GtkPizza *pizza;
    GtkPizzaChild *child;
    GList *children;

    g_return_if_fail (container != NULL);
    g_return_if_fail (GTK_IS_PIZZA (container));
    g_return_if_fail (widget != NULL);

    pizza = GTK_PIZZA (container);

    children = pizza->children;
    while (children)
    {
        child = children->data;

        if (child->widget == widget)
        {
            gtk_widget_unparent (widget);

            /* security checks */
            g_return_if_fail (GTK_IS_WIDGET (widget));

            pizza->children = g_list_remove_link (pizza->children, children);
            g_list_free (children);
            g_free (child);

            /* security checks */
            g_return_if_fail (GTK_IS_WIDGET (widget));

            GTK_PRIVATE_UNSET_FLAG (widget, GTK_IS_OFFSCREEN);

            break;
        }

        children = children->next;
    }
}

static void
gtk_pizza_forall (GtkContainer *container,
                  gboolean      include_internals,
                  GtkCallback   callback,
                  gpointer      callback_data)
{
    GtkPizza *pizza;
    GtkPizzaChild *child;
    GList *children;

    g_return_if_fail (container != NULL);
    g_return_if_fail (GTK_IS_PIZZA (container));
    g_return_if_fail (callback != (GtkCallback)NULL);

    pizza = GTK_PIZZA (container);

    children = pizza->children;
    while (children)
    {
        child = children->data;
        children = children->next;

        (* callback) (child->widget, callback_data);
    }
}

static void
gtk_pizza_allocate_child (GtkPizza      *pizza,
                          GtkPizzaChild *child)
{
    GtkAllocation allocation;
    GtkRequisition requisition;

    allocation.x = child->x - pizza->xoffset;
    allocation.y = child->y - pizza->yoffset;
    gtk_widget_get_child_requisition (child->widget, &requisition);
    allocation.width = requisition.width;
    allocation.height = requisition.height;

    gtk_widget_size_allocate (child->widget, &allocation);
}

static void
gtk_pizza_adjust_allocations_recurse (GtkWidget *widget,
                                       gpointer   cb_data)
{
    GtkPizzaAdjData *data = cb_data;

    widget->allocation.x += data->dx;
    widget->allocation.y += data->dy;

    if (GTK_WIDGET_NO_WINDOW (widget) && GTK_IS_CONTAINER (widget))
    {
        gtk_container_forall (GTK_CONTAINER (widget),
                          gtk_pizza_adjust_allocations_recurse,
                          cb_data);
    }
}

static void
gtk_pizza_adjust_allocations (GtkPizza *pizza,
                               gint       dx,
                               gint       dy)
{
    GList *tmp_list;
    GtkPizzaAdjData data;

    data.dx = dx;
    data.dy = dy;

    tmp_list = pizza->children;
    while (tmp_list)
    {
        GtkPizzaChild *child = tmp_list->data;
        tmp_list = tmp_list->next;

        child->widget->allocation.x += dx;
        child->widget->allocation.y += dy;

        if (GTK_WIDGET_NO_WINDOW (child->widget) &&
            GTK_IS_CONTAINER (child->widget))
        {
            gtk_container_forall (GTK_CONTAINER (child->widget),
                                  gtk_pizza_adjust_allocations_recurse,
                                  &data);
        }
    }
}

static void
gtk_pizza_position_child (GtkPizza      *pizza,
                          GtkPizzaChild *child)
{
    gint x;
    gint y;

    x = child->x - pizza->xoffset;
    y = child->y - pizza->yoffset;

    if (IS_ONSCREEN (x,y))
    {
        if (GTK_WIDGET_MAPPED (pizza) &&
          GTK_WIDGET_VISIBLE (child->widget))
        {
            if (!GTK_WIDGET_MAPPED (child->widget))
                gtk_widget_map (child->widget);
        }

        if (GTK_WIDGET_IS_OFFSCREEN (child->widget))
            GTK_PRIVATE_UNSET_FLAG (child->widget, GTK_IS_OFFSCREEN);
    }
    else
    {
        if (!GTK_WIDGET_IS_OFFSCREEN (child->widget))
            GTK_PRIVATE_SET_FLAG (child->widget, GTK_IS_OFFSCREEN);

        if (GTK_WIDGET_MAPPED (child->widget))
            gtk_widget_unmap (child->widget);
    }
}

static void
gtk_pizza_position_children (GtkPizza *pizza)
{
    GList *tmp_list;

    tmp_list = pizza->children;
    while (tmp_list)
    {
        GtkPizzaChild *child = tmp_list->data;
        tmp_list = tmp_list->next;

        gtk_pizza_position_child (pizza, child);
    }
}

/* This function is used to find events to process while scrolling */
static Bool
gtk_pizza_expose_predicate (Display *display,
                  XEvent  *xevent,
                  XPointer arg)
{
    if ((xevent->type == Expose) ||
       ((xevent->xany.window == *(Window *)arg) &&
       (xevent->type == ConfigureNotify)))
        return True;
    else
        return False;
}

/* This is the main routine to do the scrolling. Scrolling is
 * done by "Guffaw" scrolling, as in the Mozilla XFE, with
 * a few modifications.
 *
 * The main improvement is that we keep track of whether we
 * are obscured or not. If not, we ignore the generated expose
 * events and instead do the exposes ourself, without having
 * to wait for a roundtrip to the server. This also provides
 * a limited form of expose-event compression, since we do
 * the affected area as one big chunk.
 */

void
gtk_pizza_scroll (GtkPizza *pizza, gint dx, gint dy)
{
    GtkWidget *widget;
    XEvent xevent;
    XID win;

    gint x,y,w,h,border;

    widget = GTK_WIDGET (pizza);

    pizza->xoffset += dx;
    pizza->yoffset += dy;

    if (!GTK_WIDGET_MAPPED (pizza))
    {
        gtk_pizza_position_children (pizza);
        return;
    }

    gtk_pizza_adjust_allocations (pizza, -dx, -dy);

    if (pizza->shadow_type == GTK_MYSHADOW_NONE)
        border = 0;
    else
    if (pizza->shadow_type == GTK_MYSHADOW_THIN)
        border = 1;
    else
        border = 2;

    x = 0;
    y = 0;
    w = widget->allocation.width - 2*border;
    h = widget->allocation.height - 2*border;

    if (dx > 0)
    {
        if (gravity_works)
        {
          gdk_window_resize (pizza->bin_window,
                             w + dx,
                             h);
          gdk_window_move   (pizza->bin_window, x-dx, y);
          gdk_window_move_resize (pizza->bin_window, x, y, w, h );
        }
        else
        {
          /* FIXME */
        }
    }
    else if (dx < 0)
    {
        if (gravity_works)
        {
          gdk_window_move_resize (pizza->bin_window,
                                  x + dx,
                                  y,
                                  w - dx,
                                  h);
          gdk_window_move   (pizza->bin_window, x, y);
          gdk_window_resize (pizza->bin_window, w, h );
        }
        else
        {
          /* FIXME */
        }
    }

    if (dy > 0)
    {
        if (gravity_works)
        {
          gdk_window_resize (pizza->bin_window, w, h + dy);
          gdk_window_move   (pizza->bin_window, x, y-dy);
          gdk_window_move_resize (pizza->bin_window,
                                  x, y, w, h );
        }
        else
        {
          /* FIXME */
        }
    }
    else if (dy < 0)
    {
        if (gravity_works)
        {
          gdk_window_move_resize (pizza->bin_window,
                                  x, y+dy, w, h - dy );
          gdk_window_move   (pizza->bin_window, x, y);
          gdk_window_resize (pizza->bin_window, w, h );
        }
        else
        {
          /* FIXME */
        }
    }

    gtk_pizza_position_children (pizza);

    gdk_flush();

    win = GDK_WINDOW_XWINDOW (pizza->bin_window);
    while (XCheckIfEvent(GDK_WINDOW_XDISPLAY (pizza->bin_window),
                         &xevent,
                         gtk_pizza_expose_predicate,
                         (XPointer)&win))
    {
        GdkEvent event;
        GtkWidget *event_widget;

        if ((xevent.xany.window == GDK_WINDOW_XWINDOW (pizza->bin_window)) )
            gtk_pizza_filter (&xevent, &event, pizza);

        if (xevent.type == Expose)
        {
            event.expose.window = gdk_window_lookup (xevent.xany.window);
            gdk_window_get_user_data (event.expose.window,
                                    (gpointer *)&event_widget);

            if (event_widget)
            {
                event.expose.type = GDK_EXPOSE;
                event.expose.area.x = xevent.xexpose.x;
                event.expose.area.y = xevent.xexpose.y;
                event.expose.area.width = xevent.xexpose.width;
                event.expose.area.height = xevent.xexpose.height;
                event.expose.count = xevent.xexpose.count;

                gdk_window_ref (event.expose.window);
                gtk_widget_event (event_widget, &event);
                gdk_window_unref (event.expose.window);
            }
        }
    }
}


/* The main event filter. Actually, we probably don't really need
 * to install this as a filter at all, since we are calling it
 * directly above in the expose-handling hack. But in case scrollbars
 * are fixed up in some manner...
 *
 * This routine identifies expose events that are generated when
 * we've temporarily moved the bin_window_origin, and translates
 * them or discards them, depending on whether we are obscured
 * or not.
 */
static GdkFilterReturn
gtk_pizza_filter (GdkXEvent *gdk_xevent,
                   GdkEvent  *event,
                   gpointer   data)
{
    XEvent *xevent;
    GtkPizza *pizza;

    xevent = (XEvent *)gdk_xevent;

    pizza = GTK_PIZZA (data);

    if (!pizza->use_filter)
        return GDK_FILTER_CONTINUE;

    switch (xevent->type)
    {
        case Expose:
            if (xevent->xexpose.serial == pizza->configure_serial)
            {
                xevent->xexpose.x += pizza->scroll_x;
                xevent->xexpose.y += pizza->scroll_y;
            }
            break;

        case ConfigureNotify:
            {
                pizza->configure_serial = xevent->xconfigure.serial;
                pizza->scroll_x = xevent->xconfigure.x;
                pizza->scroll_y = xevent->xconfigure.y;
            }
            break;
    }

    return GDK_FILTER_CONTINUE;
}

/* Although GDK does have a GDK_VISIBILITY_NOTIFY event,
 * there is no corresponding event in GTK, so we have
 * to get the events from a filter
 */
static GdkFilterReturn
gtk_pizza_main_filter (GdkXEvent *gdk_xevent,
                        GdkEvent  *event,
                        gpointer   data)
{
    XEvent *xevent;
    GtkPizza *pizza;

    xevent = (XEvent *)gdk_xevent;
    pizza = GTK_PIZZA (data);

    if (!pizza->use_filter)
        return GDK_FILTER_CONTINUE;

    if (xevent->type == VisibilityNotify)
    {
        switch (xevent->xvisibility.state)
        {
            case VisibilityFullyObscured:
                pizza->visibility = GDK_VISIBILITY_FULLY_OBSCURED;
                break;

            case VisibilityPartiallyObscured:
                pizza->visibility = GDK_VISIBILITY_PARTIAL;
                break;

            case VisibilityUnobscured:
                pizza->visibility = GDK_VISIBILITY_UNOBSCURED;
                break;
        }

        return GDK_FILTER_REMOVE;
    }

    return GDK_FILTER_CONTINUE;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */

/**
 * This file gets included from dcclient.cpp and implements
 * the X11 interface to Pango.
 * Copyright (C) Owen Taylor and Robert Roebling.
 * Licence: The wxWindows licence
 */

/* Declaration */

void
x11_draw_glyphs( Drawable       drawable,
		         GC             gc,
		         PangoFont     *font,
		         int            x,
		         int            y,
		         PangoGlyphString *glyphs);

void
x11_draw_layout_line_with_colors( Drawable         drawable,
                                  GC               gc,
                                  int              x,
                                  int              y,
                                  PangoLayoutLine  *line,
                                  XColor           *foreground,
                                  XColor           *background);

void
x11_draw_layout_with_colors( Drawable      drawable,
                             GC            gc,
                             int           x,
                             int           y,
                             PangoLayout  *layout,
                             XColor       *foreground,
                             XColor       *background);

void
x11_draw_layout( Drawable     drawable,
                 GC           gc,
                 int          x,
                 int          y,
                 PangoLayout *layout);

void
x11_pango_get_item_properties( PangoItem      *item,
                               PangoUnderline *uline,
                               gboolean       *strikethrough,
                               gint           *rise,
                               PangoColor     *fg_color,
                               gboolean       *fg_set,
                               PangoColor     *bg_color,
                               gboolean       *bg_set,
                               gboolean       *shape_set,
                               PangoRectangle *ink_rect,
                               PangoRectangle *logical_rect);

/* Implementation */

void
x11_draw_glyphs( Drawable       drawable,
		         GC             gc,
		         PangoFont     *font,
		         int            x,
		         int            y,
		         PangoGlyphString *glyphs)
{
    if (PANGO_XFT_IS_FONT (font))
    {
        pango_xft_picture_render( wxGlobalDisplay(), drawable, drawable, font, glyphs, x, y );
    }
    else
    {
        pango_x_render( wxGlobalDisplay(), drawable, gc, font, glyphs, x, y );
    }
}

void
x11_draw_layout_line_with_colors( Drawable         drawable,
                                  GC               gc,
                                  int              x,
                                  int              y,
                                  PangoLayoutLine  *line,
                                  XColor           *foreground,
                                  XColor           *background)
{
    PangoRectangle overall_rect;
    PangoRectangle logical_rect;
    PangoRectangle ink_rect;
    PangoContext *context;
    gint x_off = 0;
    gint rise = 0;

    context = pango_layout_get_context (line->layout);

    pango_layout_line_get_extents (line,NULL, &overall_rect);

    GSList *tmp_list = line->runs;
    while (tmp_list)
    {
        PangoUnderline uline = PANGO_UNDERLINE_NONE;
        PangoLayoutRun *run = (PangoLayoutRun *) tmp_list->data;
        PangoColor fg_color, bg_color;
        gboolean strike, fg_set, bg_set, shape_set;
        gint risen_y;

        tmp_list = tmp_list->next;

        x11_pango_get_item_properties (run->item, &uline,
            &strike, &rise,  &fg_color, &fg_set, &bg_color, &bg_set,
            &shape_set, &ink_rect, &logical_rect);

        /* we subtract the rise because X coordinates are upside down */
        risen_y = y - rise / PANGO_SCALE;

        if (!shape_set)
        {
            if (uline == PANGO_UNDERLINE_NONE)
                pango_glyph_string_extents (run->glyphs, run->item->analysis.font, NULL, &logical_rect);
            else
                pango_glyph_string_extents (run->glyphs, run->item->analysis.font, &ink_rect, &logical_rect);
        }

#if 0
	    XDrawRectangle( drawable, gc, TRUE,
			      x + (x_off + logical_rect.x) / PANGO_SCALE,
			      risen_y + overall_rect.y / PANGO_SCALE,
			      logical_rect.width / PANGO_SCALE,
			      overall_rect.height / PANGO_SCALE);
#endif

        if (!shape_set)
        {
            int gx = x + x_off / PANGO_SCALE;
            int gy = risen_y;

            x11_draw_glyphs( drawable, gc, run->item->analysis.font, gx, gy, run->glyphs);
        }

        if (uline ==  PANGO_UNDERLINE_SINGLE)
        {
            XDrawLine( wxGlobalDisplay(), drawable, gc,
			  x + (x_off + ink_rect.x) / PANGO_SCALE - 1,
                          risen_y + 1,
			  x + (x_off + ink_rect.x + ink_rect.width) / PANGO_SCALE,
                         risen_y + 1);
        }

        x_off += logical_rect.width;
    }
}

void
x11_draw_layout_with_colors( Drawable      drawable,
                             GC            gc,
                             int           x,
                             int           y,
                             PangoLayout  *layout,
                             XColor       *foreground,
                             XColor       *background)
{
    PangoLayoutIter *iter = pango_layout_get_iter (layout);

    do
    {
        PangoLayoutLine *line = pango_layout_iter_get_line (iter);

        PangoRectangle logical_rect;
        pango_layout_iter_get_line_extents (iter, NULL, &logical_rect);

        int baseline = pango_layout_iter_get_baseline (iter);

        x11_draw_layout_line_with_colors( drawable, gc,
                                          x + logical_rect.x / PANGO_SCALE,
                                          y + baseline / PANGO_SCALE,
                                          line,
                                          foreground,
                                          background);

    } while (pango_layout_iter_next_line (iter));

    pango_layout_iter_free (iter);
}

void
x11_draw_layout( Drawable     drawable,
                 GC           gc,
                 int          x,
                 int          y,
                 PangoLayout *layout)
{
    wxCHECK_RET( layout, wxT("No layout") );

    x11_draw_layout_with_colors (drawable, gc, x, y, layout, NULL, NULL);
}

void
x11_pango_get_item_properties( PangoItem      *item,
                               PangoUnderline *uline,
                               gboolean       *strikethrough,
                               gint           *rise,
                               PangoColor     *fg_color,
                               gboolean       *fg_set,
                               PangoColor     *bg_color,
                               gboolean       *bg_set,
                               gboolean       *shape_set,
                               PangoRectangle *ink_rect,
                               PangoRectangle *logical_rect)
{
  GSList *tmp_list = item->analysis.extra_attrs;

  if (strikethrough)
      *strikethrough = FALSE;

  if (fg_set)
    *fg_set = FALSE;

  if (bg_set)
    *bg_set = FALSE;

  if (shape_set)
    *shape_set = FALSE;

  if (rise)
    *rise = 0;

  while (tmp_list)
    {
      PangoAttribute *attr = (PangoAttribute *) tmp_list->data;

      switch (attr->klass->type)
	{
	case PANGO_ATTR_UNDERLINE:
	  if (uline)
	    *uline = (PangoUnderline) ((PangoAttrInt *)attr)->value;
	  break;

	case PANGO_ATTR_STRIKETHROUGH:
	    if (strikethrough)
		*strikethrough = ((PangoAttrInt *)attr)->value;
	    break;
	
	case PANGO_ATTR_FOREGROUND:
	  if (fg_color)
	    *fg_color = ((PangoAttrColor *)attr)->color;
	  if (fg_set)
	    *fg_set = TRUE;
	
	  break;
	
	case PANGO_ATTR_BACKGROUND:
	  if (bg_color)
	    *bg_color = ((PangoAttrColor *)attr)->color;
	  if (bg_set)
	    *bg_set = TRUE;
	
	  break;

	case PANGO_ATTR_SHAPE:
	  if (shape_set)
	    *shape_set = TRUE;
	  if (logical_rect)
	    *logical_rect = ((PangoAttrShape *)attr)->logical_rect;
	  if (ink_rect)
	    *ink_rect = ((PangoAttrShape *)attr)->ink_rect;
	  break;

        case PANGO_ATTR_RISE:
          if (rise)
            *rise = ((PangoAttrInt *)attr)->value;
          break;

	default:
	  break;
	}
      tmp_list = tmp_list->next;
    }
}


/////////////////////////////////////////////////////////////////////////////
// Name:        bookctrl.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_bookctrl wxBookCtrl Overview

Classes:

@li wxChoicebook
@li wxListbook
@li wxNotebook
@li wxTreebook
@li wxToolbook

Sections:

@li @ref overview_bookctrl_intro
@li @ref overview_bookctrl_bestbookctrl


<hr>


@section overview_bookctrl_intro Introduction

A book control is a convenient way of displaying multiple pages of information,
displayed one page at a time. wxWidgets has five variants of this control:

@li wxChoicebook: controlled by a wxChoice
@li wxListbook: controlled by a wxListCtrl
@li wxNotebook: uses a row of tabs
@li wxTreebook: controlled by a wxTreeCtrl
@li wxToolbook: controlled by a wxToolBar

See the @ref page_samples_notebook for an example of wxBookCtrl usage.


@section overview_bookctrl_bestbookctrl Best Book

::wxBookCtrl is mapped to the class best suited for a given platform. Currently
it provides wxChoicebook for smartphones equipped with WinCE, and wxNotebook
for all other platforms. The mapping consists of:

@beginTable
@row2col{ ::wxBookCtrl, wxChoicebook or wxNotebook }
@row2col{ @c wxEVT_COMMAND_BOOKCTRL_PAGE_CHANGED,
          @c wxEVT_COMMAND_CHOICEBOOK_PAGE_CHANGED or
          @c wxEVT_COMMAND_NOTEBOOK_PAGE_CHANGED }
@row2col{ @c wxEVT_COMMAND_BOOKCTRL_PAGE_CHANGING,
          @c wxEVT_COMMAND_CHOICEBOOK_PAGE_CHANGING or
          @c wxEVT_COMMAND_NOTEBOOK_PAGE_CHANGING }
@row2col{ @c EVT_BOOKCTRL_PAGE_CHANGED(id\, fn),
          @c EVT_CHOICEBOOK_PAGE_CHANGED(id, fn) or
          @c EVT_NOTEBOOK_PAGE_CHANGED(id, fn) }
@row2col{ @c EVT_BOOKCTRL_PAGE_CHANGING(id\, fn),
          @c EVT_CHOICEBOOK_PAGE_CHANGING(id, fn) or
          @c EVT_NOTEBOOK_PAGE_CHANGING(id, fn) }
@endTable

For orientation of the book controller, use following flags in style:

@li @b wxBK_TOP: controller above pages
@li @b wxBK_BOTTOM: controller below pages
@li @b wxBK_LEFT: controller on the left
@li @b wxBK_RIGHT: controller on the right
@li @b wxBK_DEFAULT: native controller placement

*/


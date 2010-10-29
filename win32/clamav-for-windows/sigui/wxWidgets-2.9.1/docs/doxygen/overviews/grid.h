/////////////////////////////////////////////////////////////////////////////
// Name:        grid.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_grid wxGrid Overview

Classes: wxGrid

@li @ref overview_grid_intro
@li @ref overview_grid_simpleexample
@li @ref overview_grid_complexexample
@li @ref overview_grid_classrelations
@li @ref overview_grid_keyboardmouse


<hr>


@section overview_grid_intro Introduction

wxGrid and its related classes are used for displaying and editing tabular
data. wxGrid supports custom attributes for the table cells, allowing to
completely customize its appearance and uses a separate grid table
(wxGridTableBase-derived) class for the data management meaning that it
can be used to display arbitrary amounts of data.

@section overview_grid_simpleexample Getting started: a simple example

For simple applications you need only refer to the wxGrid class in your
code. This example shows how you might create a grid in a frame or
dialog constructor and illustrates some of the formatting functions.

@code
    // Create a wxGrid object

    grid = new wxGrid( this,
                        -1,
                        wxPoint( 0, 0 ),
                        wxSize( 400, 300 ) );

    // Then we call CreateGrid to set the dimensions of the grid
    // (100 rows and 10 columns in this example)
    grid->CreateGrid( 100, 10 );

    // We can set the sizes of individual rows and columns
    // in pixels
    grid->SetRowSize( 0, 60 );
    grid->SetColSize( 0, 120 );

    // And set grid cell contents as strings
    grid->SetCellValue( 0, 0, "wxGrid is good" );

    // We can specify that some cells are read->only
    grid->SetCellValue( 0, 3, "This is read->only" );
    grid->SetReadOnly( 0, 3 );

    // Colours can be specified for grid cell contents
    grid->SetCellValue(3, 3, "green on grey");
    grid->SetCellTextColour(3, 3, *wxGREEN);
    grid->SetCellBackgroundColour(3, 3, *wxLIGHT_GREY);

    // We can specify the some cells will store numeric
    // values rather than strings. Here we set grid column 5
    // to hold floating point values displayed with width of 6
    // and precision of 2
    grid->SetColFormatFloat(5, 6, 2);
    grid->SetCellValue(0, 6, "3.1415");
@endcode

Here is a list of classes related to wxGrid:

@li wxGrid: The main grid control class itself.
@li wxGridTableBase: The base class for grid data provider.
@li wxGridStringTable: Simple wxGridTableBase implementation supporting only
    string data items and storing them all in memory (hence suitable for not
    too large grids only).
@li wxGridCellAttr: A cell attribute, allowing to customize its appearance as
    well as the renderer and editor used for displaying and editing it.
@li wxGridCellAttrProvider: The object responsible for storing and retrieving
    the cell attributes.
@li wxGridColLabelWindow: The window showing the grid columns labels.
@li wxGridRowLabelWindow: The window showing the grid rows labels.
@li wxGridCornerLabelWindow: The window used in the upper left grid corner.
@li wxGridWindow: The window representing the main part of the grid.
@li wxGridCellRenderer: Base class for objects used to display a cell value.
@li wxGridCellStringRenderer: Renderer showing the cell as a text string.
@li wxGridCellNumberRenderer: Renderer showing the cell as an integer number.
@li wxGridCellFloatRenderer: Renderer showing the cell as a floating point
    number.
@li wxGridCellBoolRenderer: Renderer showing the cell as checked or unchecked
    box.
@li wxGridCellEditor: Base class for objects used to edit the cell value.
@li wxGridCellStringEditor: Editor for cells containing text strings.
@li wxGridCellNumberEditor: Editor for cells containing integer numbers.
@li wxGridCellFloatEditor: Editor for cells containing floating point numbers.
@li wxGridCellBoolEditor: Editor for boolean-valued cells.
@li wxGridCellChoiceEditor: Editor allowing to choose one of the predefined
    strings (and possibly enter new one).
@li wxGridEvent: The event sent by most of wxGrid actions.
@li wxGridSizeEvent: The special event sent when a grid column or row is
    resized.
@li wxGridRangeSelectEvent: The special event sent when a range of cells is
    selected in the grid.
@li wxGridEditorCreatedEvent: The special event sent when a cell editor is
    created.
@li wxGridSelection: The object efficiently representing the grid selection.
@li wxGridTypeRegistry: Contains information about the data types supported by
    the grid.

@section overview_grid_complexexample A more complex example

@todo To be written


@section overview_grid_classrelations How the wxGrid classes relate to each other

@todo To be written


@section overview_grid_keyboardmouse Keyboard and mouse actions

@todo To be written

@section overview_grid_resizing Column and row sizes

@b NB: This section will discuss the resizing of wxGrid rows only to avoid
repetitions but everything in it also applies to grid columns, just replace @c
Row in the method names with @c Col.

Initially all wxGrid rows have the same height, which can be modified for all
of them at once using wxGrid::SetDefaultRowSize(). However, unlike simpler
controls such as wxListBox or wxListCtrl, wxGrid also allows its rows to be
individually resized to have their own height using wxGrid::SetRowSize() (as a
special case, a row may be hidden entirely by setting its size to 0, which is
done by a helper wxGrid::HideRow() method). It is also possible to resize a row
to fit its contents with wxGrid::AutoSizeRow() or do it for all rows at once
with wxGrid::AutoSizeRows().

Additionally, by default the user can also drag the row separator lines to
resize the rows interactively. This can be forbidden completely by calling
wxGrid::DisableDragRowSize() or just for the individual rows using
wxGrid::DisableRowResize().

If you do allow the user to resize the grid rows, it may be a good idea to save
their heights and restore it when the grid is recreated the next time (possibly
during a next program execution): the functions wxGrid::GetRowSizes() and
wxGrid::SetRowSizes() can help with this, you will just need to serialize
wxGridSizesInfo structure returned by the former in some way and deserialize it
back before calling the latter.

*/

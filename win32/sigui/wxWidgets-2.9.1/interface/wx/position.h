/////////////////////////////////////////////////////////////////////////////
// Name:        position.h
// Purpose:     interface of wxPosition
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxPosition

    This class represents the position of an item in any kind of grid of rows and
    columns such as wxGridBagSizer, or wxHVScrolledWindow.

    @library{wxbase}
    @category{data}

    @see wxPoint, wxSize
*/
class wxPosition
{
public:

    /**
        Construct a new wxPosition, setting the row and column to the
        default value of (0, 0).
    */
    wxPosition();

    /**
        Construct a new wxPosition, setting the row and column to the
        value of (@a row, @a col).
    */
    wxPosition(int row, int col);

    /**
        A synonym for GetColumn().
    */
    int GetCol() const;

    /**
        Get the current row value.
    */
    int GetColumn() const;

    /**
        Get the current row value.
    */
    int GetRow() const;

    /**
        A synonym for SetColumn().
    */
    void SetCol(int column);

    /**
        Set a new column value.
    */
    void SetColumn(int column);

    /**
        Set a new row value.
    */
    void SetRow(int row);


    /**
        @name Miscellaneous operators

        @{
    */
    bool operator ==(const wxPosition& p) const;
    bool operator !=(const wxPosition& p) const;
    wxPosition& operator +=(const wxPosition& p) const;
    wxPosition& operator -=(const wxPosition& p) const;
    wxPosition& operator +=(const wxSize& s) const;
    wxPosition& operator -=(const wxSize& s) const;
    wxPosition& operator +(const wxPosition& p) const;
    wxPosition& operator -(const wxPosition& p) const;
    wxPosition& operator +(const wxSize& s) const;
    wxPosition& operator -(const wxSize& s) const;
    //@}
};


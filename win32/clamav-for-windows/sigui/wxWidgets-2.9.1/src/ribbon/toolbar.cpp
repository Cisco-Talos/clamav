///////////////////////////////////////////////////////////////////////////////
// Name:        src/ribbon/toolbar.cpp
// Purpose:     Ribbon-style tool bar
// Author:      Peter Cawley
// Modified by:
// Created:     2009-07-06
// RCS-ID:      $Id$
// Copyright:   (C) Peter Cawley
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_RIBBON

#include "wx/ribbon/toolbar.h"
#include "wx/ribbon/art.h"
#include "wx/ribbon/bar.h"
#include "wx/dcbuffer.h"

#ifndef WX_PRECOMP
#endif

#ifdef __WXMSW__
#include "wx/msw/private.h"
#endif

class wxRibbonToolBarToolBase
{
public:
    wxString help_string;
    wxBitmap bitmap;
    wxBitmap bitmap_disabled;
    wxRect dropdown;
    wxPoint position;
    wxSize size;
    wxObject* client_data;
    int id;
    wxRibbonButtonKind kind;
    long state;
};

WX_DEFINE_ARRAY(wxRibbonToolBarToolBase*, wxArrayRibbonToolBarToolBase);

class wxRibbonToolBarToolGroup
{
public:
    // To identify the group as a wxRibbonToolBarToolBase*
    wxRibbonToolBarToolBase dummy_tool;

    wxArrayRibbonToolBarToolBase tools;
    wxPoint position;
    wxSize size;
};

wxDEFINE_EVENT(wxEVT_COMMAND_RIBBONTOOL_CLICKED, wxRibbonToolBarEvent);
wxDEFINE_EVENT(wxEVT_COMMAND_RIBBONTOOL_DROPDOWN_CLICKED, wxRibbonToolBarEvent);

IMPLEMENT_DYNAMIC_CLASS(wxRibbonToolBarEvent, wxCommandEvent)
IMPLEMENT_CLASS(wxRibbonToolBar, wxRibbonControl)

BEGIN_EVENT_TABLE(wxRibbonToolBar, wxRibbonControl)
    EVT_ENTER_WINDOW(wxRibbonToolBar::OnMouseEnter)
    EVT_ERASE_BACKGROUND(wxRibbonToolBar::OnEraseBackground)
    EVT_LEAVE_WINDOW(wxRibbonToolBar::OnMouseLeave)
    EVT_LEFT_DOWN(wxRibbonToolBar::OnMouseDown)
    EVT_LEFT_UP(wxRibbonToolBar::OnMouseUp)
    EVT_MOTION(wxRibbonToolBar::OnMouseMove)
    EVT_PAINT(wxRibbonToolBar::OnPaint)
    EVT_SIZE(wxRibbonToolBar::OnSize)
END_EVENT_TABLE()

wxRibbonToolBar::wxRibbonToolBar()
{
}

wxRibbonToolBar::wxRibbonToolBar(wxWindow* parent,
                  wxWindowID id,
                  const wxPoint& pos,
                  const wxSize& size,
                  long style)
    : wxRibbonControl(parent, id, pos, size, wxBORDER_NONE)
{
    CommonInit(style);
}

bool wxRibbonToolBar::Create(wxWindow* parent,
                wxWindowID id,
                const wxPoint& pos,
                const wxSize& size,
                long style)
{
    if(!wxRibbonControl::Create(parent, id, pos, size, wxBORDER_NONE))
    {
        return false;
    }

    CommonInit(style);
    return true;
}

void wxRibbonToolBar::CommonInit(long WXUNUSED(style))
{
    AppendGroup();
    m_hover_tool = NULL;
    m_active_tool = NULL;
    m_nrows_min = 1;
    m_nrows_max = 1;
    m_sizes = new wxSize[1];
    m_sizes[0] = wxSize(0, 0);
    SetBackgroundStyle(wxBG_STYLE_CUSTOM);
}

wxRibbonToolBar::~wxRibbonToolBar()
{
    size_t count = m_groups.GetCount();
    size_t i, t;
    for(i = 0; i < count; ++i)
    {
        wxRibbonToolBarToolGroup* group = m_groups.Item(i);
        size_t tool_count = group->tools.GetCount();
        for(t = 0; t < tool_count; ++t)
        {
            wxRibbonToolBarToolBase* tool = group->tools.Item(t);
            delete tool;
        }
        delete group;
    }
    m_groups.Clear();
    delete[] m_sizes;
}

wxRibbonToolBarToolBase* wxRibbonToolBar::AddTool(
                int tool_id,
                const wxBitmap& bitmap,
                const wxString& help_string,
                wxRibbonButtonKind kind)
{
    return AddTool(tool_id, bitmap, wxNullBitmap, help_string, kind, NULL);
}

wxRibbonToolBarToolBase* wxRibbonToolBar::AddDropdownTool(
            int tool_id,
            const wxBitmap& bitmap,
            const wxString& help_string)
{
    return AddTool(tool_id, bitmap, wxNullBitmap, help_string,
        wxRIBBON_BUTTON_DROPDOWN, NULL);
}

wxRibbonToolBarToolBase* wxRibbonToolBar::AddHybridTool(
            int tool_id,
            const wxBitmap& bitmap,
            const wxString& help_string)
{
    return AddTool(tool_id, bitmap, wxNullBitmap, help_string,
        wxRIBBON_BUTTON_HYBRID, NULL);
}

wxRibbonToolBarToolBase* wxRibbonToolBar::AddTool(
            int tool_id,
            const wxBitmap& bitmap,
            const wxBitmap& bitmap_disabled,
            const wxString& help_string,
            wxRibbonButtonKind kind,
            wxObject* client_data)
{
    wxASSERT(bitmap.IsOk());

    wxRibbonToolBarToolBase* tool = new wxRibbonToolBarToolBase;
    tool->id = tool_id;
    tool->bitmap = bitmap;
    if(bitmap_disabled.IsOk())
    {
        wxASSERT(bitmap.GetSize() == bitmap_disabled.GetSize());
        tool->bitmap_disabled = bitmap_disabled;
    }
    else
        tool->bitmap_disabled = MakeDisabledBitmap(bitmap);
    tool->help_string = help_string;
    tool->kind = kind;
    tool->client_data = client_data;
    tool->position = wxPoint(0, 0);
    tool->size = wxSize(0, 0);
    tool->state = 0;

    m_groups.Last()->tools.Add(tool);
    return tool;
}

wxRibbonToolBarToolBase* wxRibbonToolBar::AddSeparator()
{
    if(m_groups.Last()->tools.IsEmpty())
        return NULL;

    AppendGroup();
    return &m_groups.Last()->dummy_tool;
}

wxBitmap wxRibbonToolBar::MakeDisabledBitmap(const wxBitmap& original)
{
    wxImage img(original.ConvertToImage());
    return wxBitmap(img.ConvertToGreyscale());
}

void wxRibbonToolBar::AppendGroup()
{
    wxRibbonToolBarToolGroup* group = new wxRibbonToolBarToolGroup;
    group->position = wxPoint(0, 0);
    group->size = wxSize(0, 0);
    m_groups.Add(group);
}

bool wxRibbonToolBar::IsSizingContinuous() const
{
    return false;
}

static int GetSizeInOrientation(wxSize size, wxOrientation orientation)
{
    switch(orientation)
    {
    case wxHORIZONTAL: return size.GetWidth();
    case wxVERTICAL: return size.GetHeight();
    case wxBOTH: return size.GetWidth() * size.GetHeight();
    default: return 0;
    }
}

wxSize wxRibbonToolBar::DoGetNextSmallerSize(wxOrientation direction,
                                      wxSize relative_to) const
{
    wxSize result(relative_to);
    int area = 0;
    int nrows;
    for(nrows = m_nrows_min; nrows <= m_nrows_max; ++nrows)
    {
        wxSize size(m_sizes[nrows - m_nrows_min]);
        wxSize original(size);
        switch(direction)
        {
        case wxHORIZONTAL:
            if(size.GetWidth() < relative_to.GetWidth()
                && size.GetHeight() <= relative_to.GetHeight())
            {
                size.SetHeight(relative_to.GetHeight());
                break;
            }
            continue;
        case wxVERTICAL:
            if(size.GetWidth() <= relative_to.GetWidth()
                && size.GetHeight() < relative_to.GetHeight())
            {
                size.SetWidth(relative_to.GetWidth());
                break;
            }
            continue;
        case wxBOTH:
            if(size.GetWidth() < relative_to.GetWidth()
                && size.GetHeight() < relative_to.GetHeight())
            {
                break;
            }
            continue;
        }
        if(GetSizeInOrientation(original, direction) > area)
        {
            result = size;
            area = GetSizeInOrientation(original, direction);
        }
    }
    return result;
}

wxSize wxRibbonToolBar::DoGetNextLargerSize(wxOrientation direction,
                                 wxSize relative_to) const
{
    // Pick the smallest of our sizes which are larger than the given size
    wxSize result(relative_to);
    int area = INT_MAX;
    int nrows;
    for(nrows = m_nrows_min; nrows <= m_nrows_max; ++nrows)
    {
        wxSize size(m_sizes[nrows - m_nrows_min]);
        wxSize original(size);
        switch(direction)
        {
        case wxHORIZONTAL:
            if(size.GetWidth() > relative_to.GetWidth()
                && size.GetHeight() <= relative_to.GetHeight())
            {
                size.SetHeight(relative_to.GetHeight());
                break;
            }
            continue;
        case wxVERTICAL:
            if(size.GetWidth() <= relative_to.GetWidth()
                && size.GetHeight() > relative_to.GetHeight())
            {
                size.SetWidth(relative_to.GetWidth());
                break;
            }
            continue;
        case wxBOTH:
            if(size.GetWidth() > relative_to.GetWidth()
                && size.GetHeight() > relative_to.GetHeight())
            {
                break;
            }
            continue;
        }
        if(GetSizeInOrientation(original, direction) < area)
        {
            result = size;
            area = GetSizeInOrientation(original, direction);
        }
    }

    return result;
}

void wxRibbonToolBar::SetRows(int nMin, int nMax)
{
    if(nMax == -1)
        nMax = nMin;

    wxASSERT(1 <= nMin);
    wxASSERT(nMin <= nMax);

    m_nrows_min = nMin;
    m_nrows_max = nMax;

    delete[] m_sizes;
    m_sizes = new wxSize[m_nrows_max - m_nrows_min + 1];
    for(int i = m_nrows_min; i <= m_nrows_max; ++i)
        m_sizes[i - m_nrows_min] = wxSize(0, 0);

    Realize();
}

bool wxRibbonToolBar::Realize()
{
    if(m_art == NULL)
        return false;

    // Calculate the size of each group and the position/size of each tool
    wxMemoryDC temp_dc;
    size_t group_count = m_groups.GetCount();
    size_t g, t;
    for(g = 0; g < group_count; ++g)
    {
        wxRibbonToolBarToolBase* prev = NULL;
        wxRibbonToolBarToolGroup* group = m_groups.Item(g);
        size_t tool_count = group->tools.GetCount();
        int tallest = 0;
        for(t = 0; t < tool_count; ++t)
        {
            wxRibbonToolBarToolBase* tool = group->tools.Item(t);
            tool->size = m_art->GetToolSize(temp_dc, this,
                tool->bitmap.GetSize(), tool->kind, t == 0,
                t == (tool_count - 1), &tool->dropdown);
            tool->state = tool->state & ~wxRIBBON_TOOLBAR_TOOL_DISABLED;
            if(t == 0)
                tool->state |= wxRIBBON_TOOLBAR_TOOL_FIRST;
            if(t == tool_count - 1)
                tool->state |= wxRIBBON_TOOLBAR_TOOL_LAST;
            if(tool->size.GetHeight() > tallest)
                tallest = tool->size.GetHeight();
            if(prev)
            {
                tool->position = prev->position;
                tool->position.x += prev->size.x;
            }
            else
            {
                tool->position = wxPoint(0, 0);
            }
            prev = tool;
        }
        if(tool_count == 0)
            group->size = wxSize(0, 0);
        else
        {
            group->size = wxSize(prev->position.x + prev->size.x, tallest);
            for(t = 0; t < tool_count; ++t)
                group->tools.Item(t)->size.SetHeight(tallest);
        }
    }

    // Calculate the minimum size for each possible number of rows
    int nrows, r;
    int sep = m_art->GetMetric(wxRIBBON_ART_TOOL_GROUP_SEPARATION_SIZE);
    int smallest_area = INT_MAX;
    wxSize* row_sizes = new wxSize[m_nrows_max];
    wxOrientation major_axis = m_art->GetFlags() & wxRIBBON_BAR_FLOW_VERTICAL ?
        wxVERTICAL : wxHORIZONTAL;
    SetMinSize(wxSize(0, 0));
    for(nrows = m_nrows_min; nrows <= m_nrows_max; ++nrows)
    {
        for(r = 0; r < nrows; ++r)
            row_sizes[r] = wxSize(0, 0);
        for(g = 0; g < group_count; ++g)
        {
            wxRibbonToolBarToolGroup* group = m_groups.Item(g);
            int shortest_row = 0;
            for(r = 1; r < nrows; ++r)
            {
                if(row_sizes[r].GetWidth() < row_sizes[shortest_row].GetWidth())
                    shortest_row = r;
            }
            row_sizes[shortest_row].x += group->size.x + sep;
            if(group->size.y > row_sizes[shortest_row].y)
                row_sizes[shortest_row].y = group->size.y;
        }
        wxSize size(0, 0);
        for(r = 0; r < nrows; ++r)
        {
            if(row_sizes[r].GetWidth() != 0)
                row_sizes[r].DecBy(sep, 0);
            if(row_sizes[r].GetWidth() > size.GetWidth())
                size.SetWidth(row_sizes[r].GetWidth());
            size.IncBy(0, row_sizes[r].y);
        }
        m_sizes[nrows - m_nrows_min] = size;
        if(GetSizeInOrientation(size, major_axis) < smallest_area)
        {
            SetMinSize(size);
            smallest_area = GetSizeInOrientation(size, major_axis);
        }
    }
    delete[] row_sizes;

    // Position the groups
    wxSizeEvent dummy_event(GetSize());
    OnSize(dummy_event);

    return true;
}

void wxRibbonToolBar::OnSize(wxSizeEvent& evt)
{
    if(m_art == NULL)
        return;

    // Choose row count with largest possible area
    wxSize size = evt.GetSize();
    int row_count = m_nrows_max;
    wxOrientation major_axis = m_art->GetFlags() & wxRIBBON_BAR_FLOW_VERTICAL ?
        wxVERTICAL : wxHORIZONTAL;
    if(m_nrows_max != m_nrows_min)
    {
        int area = 0;
        for(int i = 0; i <= m_nrows_max - m_nrows_min; ++i)
        {
            if(m_sizes[i].x <= size.x && m_sizes[i].y <= size.y &&
                GetSizeInOrientation(m_sizes[i], major_axis) > area)
            {
                area = GetSizeInOrientation(m_sizes[i], major_axis);
                row_count = m_nrows_min + i;
            }
        }
    }

    // Assign groups to rows and calculate row widths
    wxSize* row_sizes = new wxSize[row_count];
    int sep = m_art->GetMetric(wxRIBBON_ART_TOOL_GROUP_SEPARATION_SIZE);

    int r;
    for(r = 0; r < row_count; ++r)
        row_sizes[r] = wxSize(0, 0);
    size_t g;
    size_t group_count = m_groups.GetCount();
    for(g = 0; g < group_count; ++g)
    {
        wxRibbonToolBarToolGroup* group = m_groups.Item(g);
        int shortest_row = 0;
        for(r = 1; r < row_count; ++r)
        {
            if(row_sizes[r].GetWidth() < row_sizes[shortest_row].GetWidth())
                shortest_row = r;
        }
        group->position = wxPoint(row_sizes[shortest_row].x, shortest_row);
        row_sizes[shortest_row].x += group->size.x + sep;
        if(group->size.y > row_sizes[shortest_row].y)
            row_sizes[shortest_row].y = group->size.y;
    }

    // Calculate row positions
    int total_height = 0;
    for(r = 0; r < row_count; ++r)
        total_height += row_sizes[r].GetHeight();
    int rowsep = (size.GetHeight() - total_height) / (row_count + 1);
    int* rowypos = new int[row_count];
    rowypos[0] = rowsep;
    for(r = 1; r < row_count; ++r)
    {
        rowypos[r] = rowypos[r - 1] + row_sizes[r - 1].GetHeight() + rowsep;
    }

    // Set group y positions
    for(g = 0; g < group_count; ++g)
    {
        wxRibbonToolBarToolGroup* group = m_groups.Item(g);
        group->position.y = rowypos[group->position.y];
    }

    delete[] rowypos;
    delete[] row_sizes;
}

wxSize wxRibbonToolBar::DoGetBestSize() const
{
    return GetMinSize();
}

void wxRibbonToolBar::OnEraseBackground(wxEraseEvent& WXUNUSED(evt))
{
    // All painting done in main paint handler to minimise flicker
}

void wxRibbonToolBar::OnPaint(wxPaintEvent& WXUNUSED(evt))
{
    wxAutoBufferedPaintDC dc(this);
    if(m_art == NULL)
        return;

    m_art->DrawToolBarBackground(dc, this, GetSize());

    size_t group_count = m_groups.GetCount();
    size_t g, t;
    for(g = 0; g < group_count; ++g)
    {
        wxRibbonToolBarToolGroup* group = m_groups.Item(g);
        size_t tool_count = group->tools.GetCount();
        if(tool_count != 0)
        {
            m_art->DrawToolGroupBackground(dc, this,
                wxRect(group->position, group->size));
            for(t = 0; t < tool_count; ++t)
            {
                wxRibbonToolBarToolBase* tool = group->tools.Item(t);
                wxRect rect(group->position + tool->position, tool->size);
                m_art->DrawTool(dc, this, rect, tool->bitmap, tool->kind,
                    tool->state);
            }
        }
    }
}

void wxRibbonToolBar::OnMouseMove(wxMouseEvent& evt)
{
    wxPoint pos(evt.GetPosition());
    wxRibbonToolBarToolBase *new_hover = NULL;

    size_t group_count = m_groups.GetCount();
    size_t g, t;
    for(g = 0; g < group_count; ++g)
    {
        wxRibbonToolBarToolGroup* group = m_groups.Item(g);
        if(group->position.x <= pos.x && pos.x < group->position.x + group->size.x
            && group->position.y <= pos.y && pos.y < group->position.y + group->size.y)
        {
            size_t tool_count = group->tools.GetCount();
            pos -= group->position;
            for(t = 0; t < tool_count; ++t)
            {
                wxRibbonToolBarToolBase* tool = group->tools.Item(t);
                if(tool->position.x <= pos.x && pos.x < tool->position.x + tool->size.x
                    && tool->position.y <= pos.y && pos.y < tool->position.y + tool->size.y)
                {
                    pos -= tool->position;
                    new_hover = tool;
                    break;
                }
            }
            break;
        }
    }

    if(new_hover != m_hover_tool)
    {
        if(m_hover_tool)
        {
            m_hover_tool->state &= ~(wxRIBBON_TOOLBAR_TOOL_HOVER_MASK
                | wxRIBBON_TOOLBAR_TOOL_ACTIVE_MASK);
        }
        m_hover_tool = new_hover;
        if(new_hover)
        {
            long what = wxRIBBON_TOOLBAR_TOOL_NORMAL_HOVERED;
            if(new_hover->dropdown.Contains(pos))
                what = wxRIBBON_TOOLBAR_TOOL_DROPDOWN_HOVERED;

            new_hover->state |= what;
            
            if(new_hover == m_active_tool)
            {
                new_hover->state &= ~wxRIBBON_TOOLBAR_TOOL_ACTIVE_MASK;
                new_hover->state |= (what << 2);
            }
        }
        Refresh(false);
    }
    else if(m_hover_tool && m_hover_tool->kind == wxRIBBON_BUTTON_HYBRID)
    {
        long newstate = m_hover_tool->state &~wxRIBBON_TOOLBAR_TOOL_HOVER_MASK;
        long what = wxRIBBON_TOOLBAR_TOOL_NORMAL_HOVERED;
        if(m_hover_tool->dropdown.Contains(pos))
            what = wxRIBBON_TOOLBAR_TOOL_DROPDOWN_HOVERED;
        newstate |= what;
        if(newstate != m_hover_tool->state)
        {
            m_hover_tool->state = newstate;
            if(m_hover_tool == m_active_tool)
            {
                m_hover_tool->state &= ~wxRIBBON_TOOLBAR_TOOL_ACTIVE_MASK;
                m_hover_tool->state |= (what << 2);
            }
            Refresh(false);
        }
    }
}

void wxRibbonToolBar::OnMouseDown(wxMouseEvent& evt)
{
    OnMouseMove(evt);
    if(m_hover_tool)
    {
        m_active_tool = m_hover_tool;
        m_active_tool->state |=
            (m_active_tool->state & wxRIBBON_TOOLBAR_TOOL_HOVER_MASK) << 2;
        Refresh(false);
    }
}

void wxRibbonToolBar::OnMouseLeave(wxMouseEvent& WXUNUSED(evt))
{
    if(m_hover_tool)
    {
        m_hover_tool->state &= ~wxRIBBON_TOOLBAR_TOOL_HOVER_MASK;
        m_hover_tool = NULL;
        Refresh(false);
    }
}

void wxRibbonToolBar::OnMouseUp(wxMouseEvent& WXUNUSED(evt))
{
    if(m_active_tool)
    {
        if(m_active_tool->state & wxRIBBON_TOOLBAR_TOOL_ACTIVE_MASK)
        {
            wxEventType evt_type = wxEVT_COMMAND_RIBBONTOOL_CLICKED;
            if(m_active_tool->state & wxRIBBON_TOOLBAR_TOOL_DROPDOWN_ACTIVE)
                evt_type = wxEVT_COMMAND_RIBBONTOOL_DROPDOWN_CLICKED;
            wxRibbonToolBarEvent notification(evt_type, m_active_tool->id);
            notification.SetEventObject(this);
            notification.SetBar(this);
            ProcessEvent(notification);
        }
        m_active_tool->state &= ~wxRIBBON_TOOLBAR_TOOL_ACTIVE_MASK;
        m_active_tool = NULL;
        Refresh(false);
    }
}

void wxRibbonToolBar::OnMouseEnter(wxMouseEvent& evt)
{
    if(m_active_tool && !evt.LeftIsDown())
    {
        m_active_tool = NULL;
    }
}

bool wxRibbonToolBarEvent::PopupMenu(wxMenu* menu)
{
    wxPoint pos = wxDefaultPosition;
    if(m_bar->m_active_tool)
    {
        // Find the group which contains the tool
        size_t group_count = m_bar->m_groups.GetCount();
        size_t g, t;
        for(g = 0; g < group_count; ++g)
        {
            wxRibbonToolBarToolGroup* group = m_bar->m_groups.Item(g);
            size_t tool_count = group->tools.GetCount();
            for(t = 0; t < tool_count; ++t)
            {
                wxRibbonToolBarToolBase* tool = group->tools.Item(t);
                if(tool == m_bar->m_active_tool)
                {
                    pos = group->position;
                    pos += tool->position;
                    pos.y += tool->size.GetHeight();
                    g = group_count;
                    break;
                }
            }
        }
    }
    return m_bar->PopupMenu(menu, pos);
}

#endif // wxUSE_RIBBON

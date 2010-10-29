///////////////////////////////////////////////////////////////////////////////
// Name:        src/common/windowid.cpp
// Purpose:     wxWindowID class - a class for managing window ids
// Author:      Brian Vanderburg II
// Created:     2007-09-21
// RCS-ID:      $Id$
// Copyright:   (c) 2007 Brian Vanderburg II
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

// ----------------------------------------------------------------------------
// Needed headers
// ----------------------------------------------------------------------------
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#ifndef WX_PRECOMP
    #include "wx/log.h"
    #include "wx/intl.h"
#endif //WX_PRECOMP

// Not needed, included in defs.h
// #include "wx/windowid.h"

#define wxTRACE_WINDOWID wxT("windowid")

namespace
{

#if wxUSE_AUTOID_MANAGEMENT


// initially no ids are in use and we allocate them consecutively, but after we
// exhaust the entire range, we wrap around and reuse the ids freed in the
// meanwhile
static const wxUint8 ID_FREE = 0;
static const wxUint8 ID_STARTCOUNT = 1;
static const wxUint8 ID_MAXCOUNT = 254;
static const wxUint8 ID_RESERVED = 255;

wxUint8 gs_autoIdsRefCount[wxID_AUTO_HIGHEST - wxID_AUTO_LOWEST + 1] = { 0 };

// this is an optimization used until we wrap around wxID_AUTO_HIGHEST: if this
// value is < wxID_AUTO_HIGHEST we know that we haven't wrapped yet and so can
// allocate the ids simply by incrementing it
wxWindowID gs_nextAutoId = wxID_AUTO_LOWEST;

// Reserve an ID
void ReserveIdRefCount(wxWindowID id)
{
    wxCHECK_RET(id >= wxID_AUTO_LOWEST && id <= wxID_AUTO_HIGHEST,
            wxT("invalid id range"));

    id -= wxID_AUTO_LOWEST;

    wxCHECK_RET(gs_autoIdsRefCount[id] == ID_FREE,
            wxT("id already in use or already reserved"));
    gs_autoIdsRefCount[id] = ID_RESERVED;
}

// Unreserve and id
void UnreserveIdRefCount(wxWindowID id)
{
    wxCHECK_RET(id >= wxID_AUTO_LOWEST && id <= wxID_AUTO_HIGHEST,
            wxT("invalid id range"));

    id -= wxID_AUTO_LOWEST;

    wxCHECK_RET(gs_autoIdsRefCount[id] == ID_RESERVED,
            wxT("id already in use or not reserved"));
    gs_autoIdsRefCount[id] = ID_FREE;
}

// Get the usage count of an id
int GetIdRefCount(wxWindowID id)
{
    wxCHECK_MSG(id >= wxID_AUTO_LOWEST && id <= wxID_AUTO_HIGHEST, 0,
            wxT("invalid id range"));

    id -= wxID_AUTO_LOWEST;
    return gs_autoIdsRefCount[id];
}

// Increase the count for an id
void IncIdRefCount(wxWindowID id)
{
    wxCHECK_RET(id >= wxID_AUTO_LOWEST && id <= wxID_AUTO_HIGHEST,
            wxT("invalid id range"));

    id -= wxID_AUTO_LOWEST;

    wxCHECK_RET(gs_autoIdsRefCount[id] != ID_MAXCOUNT, wxT("id count at max"));
    wxCHECK_RET(gs_autoIdsRefCount[id] != ID_FREE, wxT("id should first be reserved"));

    if(gs_autoIdsRefCount[id] == ID_RESERVED)
        gs_autoIdsRefCount[id] = ID_STARTCOUNT;
    else
        gs_autoIdsRefCount[id]++;

    wxLogTrace(wxTRACE_WINDOWID, wxT("Increasing ref count of ID %d to %d"),
            id + wxID_AUTO_LOWEST, gs_autoIdsRefCount[id]);
}

// Decrease the count for an id
void DecIdRefCount(wxWindowID id)
{
    wxCHECK_RET(id >= wxID_AUTO_LOWEST && id <= wxID_AUTO_HIGHEST,
            wxT("invalid id range"));

    id -= wxID_AUTO_LOWEST;

    wxCHECK_RET(gs_autoIdsRefCount[id] != ID_FREE, wxT("id count already 0"));

    // DecIdRefCount is only called on an ID that has been IncIdRefCount'ed'
    // so it should never be reserved, but test anyway
    if(gs_autoIdsRefCount[id] == ID_RESERVED)
    {
        wxFAIL_MSG(wxT("reserve id being decreased"));
        gs_autoIdsRefCount[id] = ID_FREE;
    }
    else
        gs_autoIdsRefCount[id]--;

    wxLogTrace(wxTRACE_WINDOWID, wxT("Decreasing ref count of ID %d to %d"),
            id + wxID_AUTO_LOWEST, gs_autoIdsRefCount[id]);
}

#else // wxUSE_AUTOID_MANAGEMENT

static wxWindowID gs_nextAutoId = wxID_AUTO_HIGHEST;

#endif

} // anonymous namespace


#if wxUSE_AUTOID_MANAGEMENT

void wxWindowIDRef::Assign(wxWindowID id)
{
    if ( id != m_id )
    {
        // decrease count if it is in the managed range
        if ( m_id >= wxID_AUTO_LOWEST && m_id <= wxID_AUTO_HIGHEST )
            DecIdRefCount(m_id);

        m_id = id;

        // increase count if it is in the managed range
        if ( m_id >= wxID_AUTO_LOWEST && m_id <= wxID_AUTO_HIGHEST )
            IncIdRefCount(m_id);
    }
}

#endif // wxUSE_AUTOID_MANAGEMENT



wxWindowID wxIdManager::ReserveId(int count)
{
    wxASSERT_MSG(count > 0, wxT("can't allocate less than 1 id"));


#if wxUSE_AUTOID_MANAGEMENT
    if ( gs_nextAutoId + count - 1 <= wxID_AUTO_HIGHEST )
    {
        wxWindowID id = gs_nextAutoId;

        while(count--)
        {
            ReserveIdRefCount(gs_nextAutoId++);
        }

        return id;
    }
    else
    {
        int found = 0;

        for(wxWindowID id = wxID_AUTO_LOWEST; id <= wxID_AUTO_HIGHEST; id++)
        {
            if(GetIdRefCount(id) == 0)
            {
                found++;
                if(found == count)
                {
                    // Imagine this:  100 free IDs left.  Then NewId(50) takes 50
                    // so 50 left.  Then, the 25 before that last 50 are freed, but
                    // gs_nextAutoId does not decrement and stays where it is at
                    // with 50 free. Then NewId(75) gets called, and since there
                    // are only 50 left according to gs_nextAutoId, it does a
                    // search and finds the 75 at the end.  Then NewId(10) gets
                    // called, and accorind to gs_nextAutoId, their are still
                    // 50 at the end so it returns them without testing the ref
                    // To fix this, the next ID is also updated here as needed
                    if(id >= gs_nextAutoId)
                        gs_nextAutoId = id + 1;

                    while(count--)
                        ReserveIdRefCount(id--);

                    return id + 1;
                }
            }
            else
            {
                found = 0;
            }
        }
    }

    wxLogError(_("Out of window IDs.  Recommend shutting down application."));
    return wxID_NONE;
#else // !wxUSE_AUTOID_MANAGEMENT
    // Make sure enough in the range
    wxWindowID id;

    id = gs_nextAutoId - count + 1;

    if ( id >= wxID_AUTO_LOWEST && id <= wxID_AUTO_HIGHEST )
    {
        // There is enough, but it may be time to wrap
        if(id == wxID_AUTO_LOWEST)
            gs_nextAutoId = wxID_AUTO_HIGHEST;
        else
            gs_nextAutoId = id - 1;

        return id;
    }
    else
    {
        // There is not enough at the low end of the range or
        // count was big enough to wrap around to the positive
        // Surely 'count' is not so big to take up much of the range
        gs_nextAutoId = wxID_AUTO_HIGHEST - count;
        return gs_nextAutoId + 1;
    }
#endif // wxUSE_AUTOID_MANAGEMENT/!wxUSE_AUTOID_MANAGEMENT
}

void wxIdManager::UnreserveId(wxWindowID id, int count)
{
    wxASSERT_MSG(count > 0, wxT("can't unreserve less than 1 id"));

#if wxUSE_AUTOID_MANAGEMENT
    while (count--)
        UnreserveIdRefCount(id++);
#else
    wxUnusedVar(id);
    wxUnusedVar(count);
#endif
}


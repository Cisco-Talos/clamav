///////////////////////////////////////////////////////////////////////////////
// Name:        src/palmos/notebook.cpp
// Purpose:     implementation of wxNotebook
// Author:      William Osborne - minimal working wxPalmOS port
// Modified by:
// Created:     10/13/04
// RCS-ID:      $Id$
// Copyright:   (c) William Osborne
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_NOTEBOOK

// wxWidgets
#ifndef WX_PRECOMP
  #include  "wx/string.h"
#endif  // WX_PRECOMP

// ----------------------------------------------------------------------------
// macros
// ----------------------------------------------------------------------------

// check that the page index is valid
#define IS_VALID_PAGE(nPage) ((nPage) < GetPageCount())

// ----------------------------------------------------------------------------
// event table
// ----------------------------------------------------------------------------

#include "wx/listimpl.cpp"

WX_DEFINE_LIST( wxNotebookPageInfoList )

BEGIN_EVENT_TABLE(wxNotebook, wxBookCtrlBase)
    EVT_NOTEBOOK_PAGE_CHANGED(wxID_ANY, wxNotebook::OnSelChange)

    EVT_SIZE(wxNotebook::OnSize)

    EVT_NAVIGATION_KEY(wxNotebook::OnNavigationKey)
END_EVENT_TABLE()

#if wxUSE_EXTENDED_RTTI
WX_DEFINE_FLAGS( wxNotebookStyle )

wxBEGIN_FLAGS( wxNotebookStyle )
    // new style border flags, we put them first to
    // use them for streaming out
    wxFLAGS_MEMBER(wxBORDER_SIMPLE)
    wxFLAGS_MEMBER(wxBORDER_SUNKEN)
    wxFLAGS_MEMBER(wxBORDER_DOUBLE)
    wxFLAGS_MEMBER(wxBORDER_RAISED)
    wxFLAGS_MEMBER(wxBORDER_STATIC)
    wxFLAGS_MEMBER(wxBORDER_NONE)

    // old style border flags
    wxFLAGS_MEMBER(wxSIMPLE_BORDER)
    wxFLAGS_MEMBER(wxSUNKEN_BORDER)
    wxFLAGS_MEMBER(wxDOUBLE_BORDER)
    wxFLAGS_MEMBER(wxRAISED_BORDER)
    wxFLAGS_MEMBER(wxSTATIC_BORDER)
    wxFLAGS_MEMBER(wxBORDER)

    // standard window styles
    wxFLAGS_MEMBER(wxTAB_TRAVERSAL)
    wxFLAGS_MEMBER(wxCLIP_CHILDREN)
    wxFLAGS_MEMBER(wxTRANSPARENT_WINDOW)
    wxFLAGS_MEMBER(wxWANTS_CHARS)
    wxFLAGS_MEMBER(wxFULL_REPAINT_ON_RESIZE)
    wxFLAGS_MEMBER(wxALWAYS_SHOW_SB )
    wxFLAGS_MEMBER(wxVSCROLL)
    wxFLAGS_MEMBER(wxHSCROLL)

    wxFLAGS_MEMBER(wxNB_FIXEDWIDTH)
    wxFLAGS_MEMBER(wxBK_LEFT)
    wxFLAGS_MEMBER(wxBK_RIGHT)
    wxFLAGS_MEMBER(wxBK_BOTTOM)

wxEND_FLAGS( wxNotebookStyle )

IMPLEMENT_DYNAMIC_CLASS_XTI(wxNotebook, wxBookCtrlBase,"wx/notebook.h")
IMPLEMENT_DYNAMIC_CLASS_XTI(wxNotebookPageInfo, wxObject , "wx/notebook.h" )

wxCOLLECTION_TYPE_INFO( wxNotebookPageInfo * , wxNotebookPageInfoList ) ;

template<> void wxCollectionToVariantArray( wxNotebookPageInfoList const &theList, wxxVariantArray &value)
{
    wxListCollectionToVariantArray<wxNotebookPageInfoList::compatibility_iterator>( theList , value ) ;
}

wxBEGIN_PROPERTIES_TABLE(wxNotebook)
    wxEVENT_PROPERTY( PageChanging , wxEVT_COMMAND_NOTEBOOK_PAGE_CHANGING , wxBookCtrlEvent )
    wxEVENT_PROPERTY( PageChanged , wxEVT_COMMAND_NOTEBOOK_PAGE_CHANGED , wxBookCtrlEvent )

    wxPROPERTY_COLLECTION( PageInfos , wxNotebookPageInfoList , wxNotebookPageInfo* , AddPageInfo , GetPageInfos , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
    wxPROPERTY_FLAGS( WindowStyle , wxNotebookStyle , long , SetWindowStyleFlag , GetWindowStyleFlag , EMPTY_MACROVALUE , 0 /*flags*/ , wxT("Helpstring") , wxT("group")) // style
wxEND_PROPERTIES_TABLE()

wxBEGIN_HANDLERS_TABLE(wxNotebook)
wxEND_HANDLERS_TABLE()

wxCONSTRUCTOR_5( wxNotebook , wxWindow* , Parent , wxWindowID , Id , wxPoint , Position , wxSize , Size , long , WindowStyle)


wxBEGIN_PROPERTIES_TABLE(wxNotebookPageInfo)
    wxREADONLY_PROPERTY( Page , wxNotebookPage* , GetPage , EMPTY_MACROVALUE , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
    wxREADONLY_PROPERTY( Text , wxString , GetText , wxString() , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
    wxREADONLY_PROPERTY( Selected , bool , GetSelected , false, 0 /*flags*/ , wxT("Helpstring") , wxT("group") )
    wxREADONLY_PROPERTY( ImageId , int , GetImageId , -1 , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
wxEND_PROPERTIES_TABLE()

wxBEGIN_HANDLERS_TABLE(wxNotebookPageInfo)
wxEND_HANDLERS_TABLE()

wxCONSTRUCTOR_4( wxNotebookPageInfo , wxNotebookPage* , Page , wxString , Text , bool , Selected , int , ImageId )

#else
IMPLEMENT_DYNAMIC_CLASS(wxNotebook, wxBookCtrlBase)
IMPLEMENT_DYNAMIC_CLASS(wxNotebookPageInfo, wxObject )
#endif

// ============================================================================
// implementation
// ============================================================================

// ----------------------------------------------------------------------------
// wxNotebook construction
// ----------------------------------------------------------------------------

const wxNotebookPageInfoList& wxNotebook::GetPageInfos() const
{
    wxNotebookPageInfoList* list;

    return m_pageInfos ;
}

// common part of all ctors
void wxNotebook::Init()
{
}

// default for dynamic class
wxNotebook::wxNotebook()
{
}

// the same arguments as for wxControl
wxNotebook::wxNotebook(wxWindow *parent,
                       wxWindowID id,
                       const wxPoint& pos,
                       const wxSize& size,
                       long style,
                       const wxString& name)
{
}

// Create() function
bool wxNotebook::Create(wxWindow *parent,
                        wxWindowID id,
                        const wxPoint& pos,
                        const wxSize& size,
                        long style,
                        const wxString& name)
{
    return false;
}

// ----------------------------------------------------------------------------
// wxNotebook accessors
// ----------------------------------------------------------------------------

size_t wxNotebook::GetPageCount() const
{
    return 0;
}

int wxNotebook::GetRowCount() const
{
    return 0;
}

int wxNotebook::SetSelection(size_t nPage)
{
    return 0;
}

int wxNotebook::ChangeSelection(size_t nPage)
{
    return 0;
}

bool wxNotebook::SetPageText(size_t nPage, const wxString& strText)
{
    return false;
}

wxString wxNotebook::GetPageText(size_t nPage) const
{
    return wxEmptyString;
}

int wxNotebook::GetPageImage(size_t nPage) const
{
    return -1;
}

bool wxNotebook::SetPageImage(size_t nPage, int nImage)
{
    return false;
}

void wxNotebook::SetImageList(wxImageList* imageList)
{
}

// ----------------------------------------------------------------------------
// wxNotebook size settings
// ----------------------------------------------------------------------------

void wxNotebook::SetPageSize(const wxSize& size)
{
}

void wxNotebook::SetPadding(const wxSize& padding)
{
}

void wxNotebook::SetTabSize(const wxSize& sz)
{
}

wxSize wxNotebook::CalcSizeFromPage(const wxSize& sizePage) const
{
    return wxSize(0,0);
}

void wxNotebook::AdjustPageSize(wxNotebookPage *page)
{
}

// ----------------------------------------------------------------------------
// wxNotebook operations
// ----------------------------------------------------------------------------

// remove one page from the notebook, without deleting
wxNotebookPage *wxNotebook::DoRemovePage(size_t nPage)
{
    return NULL;
}

// remove all pages
bool wxNotebook::DeleteAllPages()
{
    return true;
}

// same as AddPage() but does it at given position
bool wxNotebook::InsertPage(size_t nPage,
                            wxNotebookPage *pPage,
                            const wxString& strText,
                            bool bSelect,
                            int imageId)
{
    return false;
}

int wxNotebook::HitTest(const wxPoint& pt, long *flags) const
{
    return 0;
}


// ----------------------------------------------------------------------------
// wxNotebook callbacks
// ----------------------------------------------------------------------------

void wxNotebook::OnSize(wxSizeEvent& event)
{
}

void wxNotebook::OnSelChange(wxBookCtrlEvent& event)
{
}

void wxNotebook::OnNavigationKey(wxNavigationKeyEvent& event)
{
}

// ----------------------------------------------------------------------------
// wxNotebook base class virtuals
// ----------------------------------------------------------------------------

#if wxUSE_CONSTRAINTS

// override these 2 functions to do nothing: everything is done in OnSize

void wxNotebook::SetConstraintSizes(bool WXUNUSED(recurse))
{
}

bool wxNotebook::DoPhase(int WXUNUSED(nPhase))
{
  return true;
}

#endif // wxUSE_CONSTRAINTS

#endif // wxUSE_NOTEBOOK

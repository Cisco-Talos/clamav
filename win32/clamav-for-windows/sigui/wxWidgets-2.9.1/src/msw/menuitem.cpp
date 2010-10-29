///////////////////////////////////////////////////////////////////////////////
// Name:        src/msw/menuitem.cpp
// Purpose:     wxMenuItem implementation
// Author:      Vadim Zeitlin
// Modified by:
// Created:     11.11.97
// RCS-ID:      $Id$
// Copyright:   (c) 1998 Vadim Zeitlin <zeitlin@dptmaths.ens-cachan.fr>
// Licence:     wxWindows licence
///////////////////////////////////////////////////////////////////////////////

// ===========================================================================
// declarations
// ===========================================================================

// ---------------------------------------------------------------------------
// headers
// ---------------------------------------------------------------------------

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

#if wxUSE_MENUS

#include "wx/menuitem.h"
#include "wx/stockitem.h"

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/dcmemory.h"
    #include "wx/font.h"
    #include "wx/bitmap.h"
    #include "wx/settings.h"
    #include "wx/window.h"
    #include "wx/accel.h"
    #include "wx/string.h"
    #include "wx/log.h"
    #include "wx/menu.h"
#endif

#if wxUSE_ACCEL
    #include "wx/accel.h"
#endif // wxUSE_ACCEL

#include "wx/msw/private.h"
#include "wx/msw/dc.h"

#ifdef __WXWINCE__
// Implemented in menu.cpp
UINT GetMenuState(HMENU hMenu, UINT id, UINT flags) ;
#endif

#if wxUSE_UXTHEME
    #include "wx/msw/uxtheme.h"
#endif

// ---------------------------------------------------------------------------
// macro
// ---------------------------------------------------------------------------

// hide the ugly cast
#define GetHMenuOf(menu)    ((HMENU)menu->GetHMenu())

// ============================================================================
// implementation
// ============================================================================

#if wxUSE_OWNER_DRAWN

#include "wx/fontutil.h"
#include "wx/msw/private/metrics.h"

#ifndef SPI_GETKEYBOARDCUES
#define SPI_GETKEYBOARDCUES 0x100A
#endif

#ifndef DSS_HIDEPREFIX
#define DSS_HIDEPREFIX  0x0200
#endif

#if wxUSE_UXTHEME

enum MENUPARTS
{
    MENU_MENUITEM_TMSCHEMA = 1,
    MENU_SEPARATOR_TMSCHEMA = 6,
    MENU_POPUPBACKGROUND = 9,
    MENU_POPUPBORDERS = 10,
    MENU_POPUPCHECK = 11,
    MENU_POPUPCHECKBACKGROUND = 12,
    MENU_POPUPGUTTER = 13,
    MENU_POPUPITEM = 14,
    MENU_POPUPSEPARATOR = 15,
    MENU_POPUPSUBMENU = 16,
};


enum POPUPITEMSTATES
{
    MPI_NORMAL = 1,
    MPI_HOT = 2,
    MPI_DISABLED = 3,
    MPI_DISABLEDHOT = 4,
};

enum POPUPCHECKBACKGROUNDSTATES
{
    MCB_DISABLED = 1,
    MCB_NORMAL = 2,
    MCB_BITMAP = 3,
};

enum POPUPCHECKSTATES
{
    MC_CHECKMARKNORMAL = 1,
    MC_CHECKMARKDISABLED = 2,
    MC_BULLETNORMAL = 3,
    MC_BULLETDISABLED = 4,
};

const int TMT_MENUFONT       = 803;
const int TMT_BORDERSIZE     = 2403;
const int TMT_CONTENTMARGINS = 3602;
const int TMT_SIZINGMARGINS  = 3601;

#endif // wxUSE_UXTHEME

#endif // wxUSE_OWNER_DRAWN

// ----------------------------------------------------------------------------
// dynamic classes implementation
// ----------------------------------------------------------------------------

#if wxUSE_EXTENDED_RTTI

bool wxMenuItemStreamingCallback( const wxObject *object, wxWriter * , wxPersister * , wxxVariantArray & )
{
    const wxMenuItem * mitem = dynamic_cast<const wxMenuItem*>(object) ;
    if ( mitem->GetMenu() && !mitem->GetMenu()->GetTitle().empty() )
    {
        // we don't stream out the first two items for menus with a title, they will be reconstructed
        if ( mitem->GetMenu()->FindItemByPosition(0) == mitem || mitem->GetMenu()->FindItemByPosition(1) == mitem )
            return false ;
    }
    return true ;
}

wxBEGIN_ENUM( wxItemKind )
    wxENUM_MEMBER( wxITEM_SEPARATOR )
    wxENUM_MEMBER( wxITEM_NORMAL )
    wxENUM_MEMBER( wxITEM_CHECK )
    wxENUM_MEMBER( wxITEM_RADIO )
wxEND_ENUM( wxItemKind )

IMPLEMENT_DYNAMIC_CLASS_XTI_CALLBACK(wxMenuItem, wxObject,"wx/menuitem.h",wxMenuItemStreamingCallback)

wxBEGIN_PROPERTIES_TABLE(wxMenuItem)
    wxPROPERTY( Parent,wxMenu*, SetMenu, GetMenu, EMPTY_MACROVALUE , 0 /*flags*/ , wxT("Helpstring") , wxT("group") )
    wxPROPERTY( Id,int, SetId, GetId, EMPTY_MACROVALUE , 0 /*flags*/ , wxT("Helpstring") , wxT("group") )
    wxPROPERTY( Text, wxString , SetText, GetText, wxString(), 0 /*flags*/ , wxT("Helpstring") , wxT("group") )
    wxPROPERTY( Help, wxString , SetHelp, GetHelp, wxString(), 0 /*flags*/ , wxT("Helpstring") , wxT("group") )
    wxREADONLY_PROPERTY( Kind, wxItemKind , GetKind , EMPTY_MACROVALUE , 0 /*flags*/ , wxT("Helpstring") , wxT("group") )
    wxPROPERTY( SubMenu,wxMenu*, SetSubMenu, GetSubMenu, EMPTY_MACROVALUE , 0 /*flags*/ , wxT("Helpstring") , wxT("group") )
    wxPROPERTY( Enabled , bool , Enable , IsEnabled , wxxVariant((bool)true) , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
    wxPROPERTY( Checked , bool , Check , IsChecked , wxxVariant((bool)false) , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
    wxPROPERTY( Checkable , bool , SetCheckable , IsCheckable , wxxVariant((bool)false) , 0 /*flags*/ , wxT("Helpstring") , wxT("group"))
wxEND_PROPERTIES_TABLE()

wxBEGIN_HANDLERS_TABLE(wxMenuItem)
wxEND_HANDLERS_TABLE()

wxDIRECT_CONSTRUCTOR_6( wxMenuItem , wxMenu* , Parent , int , Id , wxString , Text , wxString , Help , wxItemKind , Kind , wxMenu* , SubMenu  )
#else
IMPLEMENT_DYNAMIC_CLASS(wxMenuItem, wxObject)
#endif

// ----------------------------------------------------------------------------
// wxMenuItem
// ----------------------------------------------------------------------------

#if wxUSE_OWNER_DRAWN

namespace
{

// helper class to keep information about metrics and other stuff
// needed for measuring and drawing menu item
class MenuDrawData
{
public:

    struct Margins
    {
        int left;
        int right;
        int top;
        int bottom;

        Margins()
            : left(0),
              right(0),
              top(0),
              bottom(0)
        {}
    };

    Margins ItemMargin;         // popup item margins

    Margins CheckMargin;        // popup check margins
    Margins CheckBgMargin;      // popup check background margins

    Margins ArrowMargin;        // popup submenu arrow margins

    Margins SeparatorMargin;    // popup separator margins

    SIZE CheckSize;             // popup check size metric
    SIZE ArrowSize;             // popup submenu arrow size metric
    SIZE SeparatorSize;         // popup separator size metric

    int TextBorder;             // popup border space between
                                // item text and gutter

    int AccelBorder;            // popup border space between
                                // item text and accelerator

    int ArrowBorder;            // popup border space between
                                // item accelerator and submenu arrow

    int Offset;                 // system added space at the end of the menu,
                                // add this offset for remove the extra space

    wxFont Font;                // default menu font

    bool AlwaysShowCues;        // must keyboard cues always be shown?

    bool Theme;                 // is data initialized for FullTheme?

    static const MenuDrawData* Get()
    {
        // notice that s_menuData can't be created as a global variable because
        // it needs a window to initialize and no windows exist at the time of
        // globals initialization yet
        if ( !ms_instance )
        {
            static MenuDrawData s_menuData;
            ms_instance = &s_menuData;
        }

    #if wxUSE_UXTHEME
        bool theme = MenuLayout() == FullTheme;
        if ( ms_instance->Theme != theme )
            ms_instance->Init();
    #endif // wxUSE_UXTHEME
        return ms_instance;
    }

    MenuDrawData()
    {
        Init();
    }


    // get the theme engine or NULL if themes
    // are not available or not supported on menu
    static wxUxThemeEngine *GetUxThemeEngine()
    {
    #if wxUSE_UXTHEME
        if ( MenuLayout() == FullTheme )
            return wxUxThemeEngine::GetIfActive();
    #endif // wxUSE_UXTHEME
        return NULL;
    }


    enum MenuLayoutType
    {
        FullTheme,      // full menu themes (Vista or new)
        PseudoTheme,    // pseudo menu themes (on XP)
        Classic
    };

    static MenuLayoutType MenuLayout()
    {
        MenuLayoutType menu = Classic;
    #if wxUSE_UXTHEME
        if ( wxUxThemeEngine::GetIfActive() != NULL )
        {
            static wxWinVersion ver = wxGetWinVersion();
            if ( ver >= wxWinVersion_Vista )
                menu = FullTheme;
            else if ( ver == wxWinVersion_XP )
                menu = PseudoTheme;
        }
    #endif // wxUSE_UXTHEME
        return menu;
    }

private:
    void Init();

    static MenuDrawData* ms_instance;
};

MenuDrawData* MenuDrawData::ms_instance = NULL;

void MenuDrawData::Init()
{
#if wxUSE_UXTHEME
    wxUxThemeEngine* theme = GetUxThemeEngine();
    if ( theme )
    {
        wxWindow* window = static_cast<wxApp*>(wxApp::GetInstance())->GetTopWindow();
        wxUxThemeHandle hTheme(window, L"MENU");

        theme->GetThemeMargins(hTheme, NULL, MENU_POPUPITEM, 0,
                               TMT_CONTENTMARGINS, NULL,
                               reinterpret_cast<MARGINS*>(&ItemMargin));

        theme->GetThemeMargins(hTheme, NULL, MENU_POPUPCHECK, 0,
                               TMT_CONTENTMARGINS, NULL,
                               reinterpret_cast<MARGINS*>(&CheckMargin));
        theme->GetThemeMargins(hTheme, NULL, MENU_POPUPCHECKBACKGROUND, 0,
                               TMT_CONTENTMARGINS, NULL,
                               reinterpret_cast<MARGINS*>(&CheckBgMargin));

        theme->GetThemeMargins(hTheme, NULL, MENU_POPUPSUBMENU, 0,
                               TMT_CONTENTMARGINS, NULL,
                               reinterpret_cast<MARGINS*>(&ArrowMargin));

        theme->GetThemeMargins(hTheme, NULL, MENU_POPUPSEPARATOR, 0,
                               TMT_SIZINGMARGINS, NULL,
                               reinterpret_cast<MARGINS*>(&SeparatorMargin));

        theme->GetThemePartSize(hTheme, NULL, MENU_POPUPCHECK, 0,
                                NULL, TS_TRUE, &CheckSize);

        theme->GetThemePartSize(hTheme, NULL, MENU_POPUPSUBMENU, 0,
                                NULL, TS_TRUE, &ArrowSize);

        theme->GetThemePartSize(hTheme, NULL, MENU_POPUPSEPARATOR, 0,
                                NULL, TS_TRUE, &SeparatorSize);

        theme->GetThemeInt(hTheme, MENU_POPUPBACKGROUND, 0, TMT_BORDERSIZE, &TextBorder);

        AccelBorder = 34;
        ArrowBorder = 0;

        Offset = -14;

        wxNativeFontInfo fontInfo;
        theme->GetThemeSysFont(hTheme, TMT_MENUFONT, &fontInfo.lf);
        Font = wxFont(fontInfo);

        Theme = true;

        // native menu doesn't uses the vertical margins
        ItemMargin.top = ItemMargin.bottom = 0;

        // native menu uses small top margin for separator
        if ( SeparatorMargin.top >= 2 )
            SeparatorMargin.top -= 2;
    }
    else
#endif // wxUSE_UXTHEME
    {
        const NONCLIENTMETRICS& metrics = wxMSWImpl::GetNonClientMetrics();

        ItemMargin = Margins();

        CheckMargin.left =
        CheckMargin.right  = ::GetSystemMetrics(SM_CXEDGE);
        CheckMargin.top =
        CheckMargin.bottom = ::GetSystemMetrics(SM_CYEDGE);

        CheckBgMargin = Margins();

        CheckSize.cx = ::GetSystemMetrics(SM_CXMENUCHECK);
        CheckSize.cy = ::GetSystemMetrics(SM_CYMENUCHECK);

        ArrowMargin = Margins();

        ArrowSize = CheckSize;

        // separator height with margins
        int sepFullSize = metrics.iMenuHeight / 2;

        SeparatorMargin.left =
        SeparatorMargin.right = 1;
        SeparatorMargin.top =
        SeparatorMargin.bottom = sepFullSize / 2 - 1;

        SeparatorSize.cx = 1;
        SeparatorSize.cy = sepFullSize - SeparatorMargin.top - SeparatorMargin.bottom;

        TextBorder = 0;
        AccelBorder = 8;
        ArrowBorder = 6;

        Offset = -12;

        Font = wxFont(wxNativeFontInfo(metrics.lfMenuFont));

        Theme = false;
    }

    int value;
    if ( ::SystemParametersInfo(SPI_GETKEYBOARDCUES, 0, &value, 0) == 0 )
    {
        // if it's not supported, we must be on an old Windows version
        // which always shows them
        value = 1;
    }

    AlwaysShowCues = value == 1;

}

} // anonymous namespace

#endif // wxUSE_OWNER_DRAWN


// ctor & dtor
// -----------

wxMenuItem::wxMenuItem(wxMenu *pParentMenu,
                       int id,
                       const wxString& text,
                       const wxString& strHelp,
                       wxItemKind kind,
                       wxMenu *pSubMenu)
          : wxMenuItemBase(pParentMenu, id, text, strHelp, kind, pSubMenu)
{
    Init();
}

#if WXWIN_COMPATIBILITY_2_8
wxMenuItem::wxMenuItem(wxMenu *parentMenu,
                       int id,
                       const wxString& text,
                       const wxString& help,
                       bool isCheckable,
                       wxMenu *subMenu)
          : wxMenuItemBase(parentMenu, id, text, help,
                           isCheckable ? wxITEM_CHECK : wxITEM_NORMAL, subMenu)
{
    Init();
}
#endif

void wxMenuItem::Init()
{
    m_radioGroup.start = -1;
    m_isRadioGroupStart = false;

#if  wxUSE_OWNER_DRAWN

    // when the color is not valid, wxOwnerDraw takes the default ones.
    // If we set the colors here and they are changed by the user during
    // the execution, then the colors are not updated until the application
    // is restarted and our menus look bad
    SetTextColour(wxNullColour);
    SetBackgroundColour(wxNullColour);

    // setting default colors switched ownerdraw on: switch it off again
    SetOwnerDrawn(false);

    //  switch ownerdraw back on if using a non default margin
    if ( !IsSeparator() )
        SetMarginWidth(GetMarginWidth());

#endif // wxUSE_OWNER_DRAWN
}

wxMenuItem::~wxMenuItem()
{
}

// misc
// ----

// return the id for calling Win32 API functions
WXWPARAM wxMenuItem::GetMSWId() const
{
    // we must use ids in unsigned short range with Windows functions, if we
    // pass ids > USHRT_MAX to them they get very confused (e.g. start
    // generating WM_COMMAND messages with negative high word of wParam), so
    // use the cast to ensure the id is in range
    return m_subMenu ? wxPtrToUInt(m_subMenu->GetHMenu())
                     : static_cast<unsigned short>(GetId());
}

// get item state
// --------------

bool wxMenuItem::IsChecked() const
{
    // fix that RTTI is always getting the correct state (separators cannot be
    // checked, but the Windows call below returns true
    if ( IsSeparator() )
        return false;

    // the item might not be attached to a menu yet
    //
    // TODO: shouldn't we just always call the base class version? It seems
    //       like it ought to always be in sync
    if ( !m_parentMenu )
        return wxMenuItemBase::IsChecked();

    HMENU hmenu = GetHMenuOf(m_parentMenu);
    int flag = ::GetMenuState(hmenu, GetMSWId(), MF_BYCOMMAND);

    return (flag & MF_CHECKED) != 0;
}

// radio group stuff
// -----------------

void wxMenuItem::SetAsRadioGroupStart()
{
    m_isRadioGroupStart = true;
}

void wxMenuItem::SetRadioGroupStart(int start)
{
    wxASSERT_MSG( !m_isRadioGroupStart,
                  wxT("should only be called for the next radio items") );

    m_radioGroup.start = start;
}

void wxMenuItem::SetRadioGroupEnd(int end)
{
    wxASSERT_MSG( m_isRadioGroupStart,
                  wxT("should only be called for the first radio item") );

    m_radioGroup.end = end;
}

// change item state
// -----------------

void wxMenuItem::Enable(bool enable)
{
    if ( m_isEnabled == enable )
        return;

    if ( m_parentMenu )
    {
        long rc = EnableMenuItem(GetHMenuOf(m_parentMenu),
                                 GetMSWId(),
                                 MF_BYCOMMAND |
                                 (enable ? MF_ENABLED : MF_GRAYED));

        if ( rc == -1 )
        {
            wxLogLastError(wxT("EnableMenuItem"));
        }
    }

    wxMenuItemBase::Enable(enable);
}

void wxMenuItem::Check(bool check)
{
    wxCHECK_RET( IsCheckable(), wxT("only checkable items may be checked") );

    if ( m_isChecked == check )
        return;

    if ( m_parentMenu )
    {
        int flags = check ? MF_CHECKED : MF_UNCHECKED;
        HMENU hmenu = GetHMenuOf(m_parentMenu);

        if ( GetKind() == wxITEM_RADIO )
        {
            // it doesn't make sense to uncheck a radio item -- what would this
            // do?
            if ( !check )
                return;

            // get the index of this item in the menu
            const wxMenuItemList& items = m_parentMenu->GetMenuItems();
            int pos = items.IndexOf(this);
            wxCHECK_RET( pos != wxNOT_FOUND,
                         wxT("menuitem not found in the menu items list?") );

            // get the radio group range
            int start,
                end;

            if ( m_isRadioGroupStart )
            {
                // we already have all information we need
                start = pos;
                end = m_radioGroup.end;
            }
            else // next radio group item
            {
                // get the radio group end from the start item
                start = m_radioGroup.start;
                end = items.Item(start)->GetData()->m_radioGroup.end;
            }

#ifdef __WIN32__
            // calling CheckMenuRadioItem() with such parameters hangs my system
            // (NT4 SP6) and I suspect this could happen to the others as well,
            // so don't do it!
            wxCHECK_RET( start != -1 && end != -1,
                         wxT("invalid ::CheckMenuRadioItem() parameter(s)") );

            if ( !::CheckMenuRadioItem(hmenu,
                                       start,   // the first radio group item
                                       end,     // the last one
                                       pos,     // the one to check
                                       MF_BYPOSITION) )
            {
                wxLogLastError(wxT("CheckMenuRadioItem"));
            }
#endif // __WIN32__

            // also uncheck all the other items in this radio group
            wxMenuItemList::compatibility_iterator node = items.Item(start);
            for ( int n = start; n <= end && node; n++ )
            {
                if ( n != pos )
                {
                    node->GetData()->m_isChecked = false;
                }

                node = node->GetNext();
            }
        }
        else // check item
        {
            if ( ::CheckMenuItem(hmenu,
                                 GetMSWId(),
                                 MF_BYCOMMAND | flags) == (DWORD)-1 )
            {
                wxFAIL_MSG(wxT("CheckMenuItem() failed, item not in the menu?"));
            }
        }
    }

    wxMenuItemBase::Check(check);
}

void wxMenuItem::SetItemLabel(const wxString& txt)
{
    wxString text = txt;

    // don't do anything if label didn't change
    if ( m_text == txt )
        return;

    // wxMenuItemBase will do stock ID checks
    wxMenuItemBase::SetItemLabel(text);

    // the item can be not attached to any menu yet and SetItemLabel() is still
    // valid to call in this case and should do nothing else
    if ( !m_parentMenu )
        return;

#if wxUSE_ACCEL
    m_parentMenu->UpdateAccel(this);
#endif // wxUSE_ACCEL

    const UINT id = GetMSWId();
    HMENU hMenu = GetHMenuOf(m_parentMenu);
    if ( !hMenu || ::GetMenuState(hMenu, id, MF_BYCOMMAND) == (UINT)-1 )
        return;

#if wxUSE_OWNER_DRAWN
    if ( IsOwnerDrawn() )
    {
        // we don't need to do anything for owner drawn items, they will redraw
        // themselves using the new text the next time they're displayed
        return;
    }
#endif // owner drawn

    // update the text of the native menu item
    WinStruct<MENUITEMINFO> info;

    // surprisingly, calling SetMenuItemInfo() with just MIIM_STRING doesn't
    // work as it resets the menu bitmap, so we need to first get the old item
    // state and then modify it
    const bool isLaterThanWin95 = wxGetWinVersion() > wxWinVersion_95;
    info.fMask = MIIM_STATE |
                 MIIM_ID |
                 MIIM_SUBMENU |
                 MIIM_CHECKMARKS |
                 MIIM_DATA;
    if ( isLaterThanWin95 )
        info.fMask |= MIIM_BITMAP | MIIM_FTYPE;
    else
        info.fMask |= MIIM_TYPE;
    if ( !::GetMenuItemInfo(hMenu, id, FALSE, &info) )
    {
        wxLogLastError(wxT("GetMenuItemInfo"));
        return;
    }

    if ( isLaterThanWin95 )
        info.fMask |= MIIM_STRING;
    //else: MIIM_TYPE already specified
    info.dwTypeData = (LPTSTR)m_text.wx_str();
    info.cch = m_text.length();
    if ( !::SetMenuItemInfo(hMenu, id, FALSE, &info) )
    {
        wxLogLastError(wxT("SetMenuItemInfo"));
    }
}

#if wxUSE_OWNER_DRAWN

int wxMenuItem::MeasureAccelWidth() const
{
    wxString accel = GetItemLabel().AfterFirst(wxT('\t'));

    wxMemoryDC dc;
    wxFont font;
    GetFontToUse(font);
    dc.SetFont(font);

    wxCoord w;
    dc.GetTextExtent(accel, &w, NULL);

    return w;
}

wxString wxMenuItem::GetName() const
{
    return GetItemLabelText();
}

bool wxMenuItem::OnMeasureItem(size_t *width, size_t *height)
{
    const MenuDrawData* data = MenuDrawData::Get();

    if ( IsOwnerDrawn() )
    {
        *width  = data->ItemMargin.left + data->ItemMargin.right;
        *height = data->ItemMargin.top  + data->ItemMargin.bottom;

        if ( IsSeparator() )
        {
            *width  += data->SeparatorSize.cx
                     + data->SeparatorMargin.left + data->SeparatorMargin.right;
            *height += data->SeparatorSize.cy
                     + data->SeparatorMargin.top + data->SeparatorMargin.bottom;
            return true;
        }

        wxString str = GetName();

        wxMemoryDC dc;
        wxFont font;
        GetFontToUse(font);
        dc.SetFont(font);

        wxCoord w, h;
        dc.GetTextExtent(str, &w, &h);

        *width = data->TextBorder + w + data->AccelBorder;
        *height = h;

        w = m_parentMenu->GetMaxAccelWidth();
        if ( w > 0 )
            *width += w + data->ArrowBorder;

        *width += data->Offset;
        *width += data->ArrowMargin.left + data->ArrowSize.cx + data->ArrowMargin.right;
    }
    else // don't draw the text, just the bitmap (if any)
    {
        *width = 0;
        *height = 0;
    }

    // bitmap

    if ( IsOwnerDrawn() )
    {
        // width of menu icon with margins in ownerdrawn menu
        // if any bitmap is not set, the width of space reserved for icon
        // image is equal to the width of std check mark,
        // if bitmap is set, then the width is set to the width of the widest
        // bitmap in menu (GetMarginWidth()) unless std check mark is wider,
        // then it's is set to std mark's width
        int imgWidth = wxMax(GetMarginWidth(), data->CheckSize.cx)
                     + data->CheckMargin.left + data->CheckMargin.right;

        *width += imgWidth + data->CheckBgMargin.left + data->CheckBgMargin.right;
    }

    if ( m_bmpChecked.IsOk() || m_bmpChecked.IsOk() )
    {
        // get size of bitmap always return valid value (0 for invalid bitmap),
        // so we don't needed check if bitmap is valid ;)
        size_t heightBmp = wxMax(m_bmpChecked.GetHeight(), m_bmpUnchecked.GetHeight());
        size_t widthtBmp = wxMax(m_bmpChecked.GetWidth(),  m_bmpUnchecked.GetWidth());

        if ( IsOwnerDrawn() )
        {
            heightBmp += data->CheckMargin.top + data->CheckMargin.bottom;
        }
        else
        {
            // we must allocate enough space for the bitmap
            *width += widthtBmp;
        }

        // Is BMP height larger than text height?
        if ( *height < heightBmp )
            *height = heightBmp;
    }

    // make sure that this item is at least as tall as the system menu height
    const size_t menuHeight = data->CheckMargin.top + data->CheckMargin.bottom
                            + data->CheckSize.cy;
    if (*height < menuHeight)
        *height = menuHeight;

    return true;
}

bool wxMenuItem::OnDrawItem(wxDC& dc, const wxRect& rc,
                            wxODAction WXUNUSED(act), wxODStatus stat)
{
    const MenuDrawData* data = MenuDrawData::Get();

    wxMSWDCImpl *impl = (wxMSWDCImpl*) dc.GetImpl();
    HDC hdc = GetHdcOf(*impl);

    RECT rect;
    wxCopyRectToRECT(rc, rect);

    int imgWidth = wxMax(GetMarginWidth(), data->CheckSize.cx);

    if ( IsOwnerDrawn() )
    {
        // font and colors to use
        wxFont font;
        GetFontToUse(font);

        wxColour colText1, colBack1;
        GetColourToUse(stat, colText1, colBack1);

        DWORD colText = wxColourToPalRGB(colText1);
        DWORD colBack = wxColourToPalRGB(colBack1);

        // calculate metrics of item parts
        RECT rcSelection;
        RECT rcSeparator;
        RECT rcGutter;
        RECT rcText;

        SetRect(&rcSelection,
                rect.left   + data->ItemMargin.left,
                rect.top    + data->ItemMargin.top,
                rect.right  - data->ItemMargin.right,
                rect.bottom - data->ItemMargin.bottom);

        SetRect(&rcSeparator,
                rcSelection.left   + data->SeparatorMargin.left,
                rcSelection.top    + data->SeparatorMargin.top,
                rcSelection.right  - data->SeparatorMargin.right,
                rcSelection.bottom - data->SeparatorMargin.bottom);

        CopyRect(&rcGutter, &rcSelection);
        rcGutter.right = data->ItemMargin.left
                       + data->CheckBgMargin.left
                       + data->CheckMargin.left
                       + imgWidth
                       + data->CheckMargin.right
                       + data->CheckBgMargin.right;

        CopyRect(&rcText, &rcSelection);
        rcText.left = rcGutter.right + data->TextBorder;

        // we draw the text label vertically centered, but this results in it
        // being 1px too low compared to native menus for some reason, fix it
        if ( data->MenuLayout() != MenuDrawData::FullTheme )
            rcText.top--;

#if wxUSE_UXTHEME
        wxUxThemeEngine* theme = MenuDrawData::GetUxThemeEngine();
        if ( theme )
        {
            POPUPITEMSTATES state;
            if ( stat & wxODDisabled )
            {
                state = (stat & wxODSelected) ? MPI_DISABLEDHOT
                                              : MPI_DISABLED;
            }
            else if ( stat & wxODSelected )
            {
                state = MPI_HOT;
            }
            else
            {
                state = MPI_NORMAL;
            }

            wxUxThemeHandle hTheme(GetMenu()->GetWindow(), L"MENU");

            if ( theme->IsThemeBackgroundPartiallyTransparent(hTheme,
                    MENU_POPUPITEM, state) )
            {
                theme->DrawThemeBackground(hTheme, hdc,
                                           MENU_POPUPBACKGROUND,
                                           0, &rect, NULL);
            }

            theme->DrawThemeBackground(hTheme, hdc, MENU_POPUPGUTTER,
                                       0, &rcGutter, NULL);

            if ( IsSeparator() )
            {
                rcSeparator.left = rcGutter.right;
                theme->DrawThemeBackground(hTheme, hdc, MENU_POPUPSEPARATOR,
                                           0, &rcSeparator, NULL);
                return true;
            }

            theme->DrawThemeBackground(hTheme, hdc, MENU_POPUPITEM,
                                       state, &rcSelection, NULL);

        }
        else
#endif // wxUSE_UXTHEME
        {
            if ( IsSeparator() )
            {
                DrawEdge(hdc, &rcSeparator, EDGE_ETCHED, BF_TOP);
                return true;
            }

            AutoHBRUSH hbr(colBack);
            SelectInHDC selBrush(hdc, hbr);
            ::FillRect(hdc, &rcSelection, hbr);
        }


        // draw text label
        // using native API because it recognizes '&'

        COLORREF colOldText = ::SetTextColor(hdc, colText);
        COLORREF colOldBack = ::SetBkColor(hdc, colBack);

        int prevMode = SetBkMode(hdc, TRANSPARENT);

        SelectInHDC selFont(hdc, GetHfontOf(font));


        // item text name without menemonic for calculating size
        wxString text = GetName();

        SIZE textSize;
        ::GetTextExtentPoint32(hdc, text.c_str(), text.length(), &textSize);

        // item text name with menemonic
        text = GetItemLabel().BeforeFirst('\t');

        int flags = DST_PREFIXTEXT;
        // themes menu is using specified color for disabled labels
        if ( data->MenuLayout() == MenuDrawData::Classic &&
             (stat & wxODDisabled) && !(stat & wxODSelected) )
            flags |= DSS_DISABLED;

        if ( (stat & wxODHidePrefix) && !data->AlwaysShowCues )
            flags |= DSS_HIDEPREFIX;

        int x = rcText.left;
        int y = rcText.top + (rcText.bottom - rcText.top - textSize.cy) / 2;

        ::DrawState(hdc, NULL, NULL, (LPARAM)text.wx_str(),
                    text.length(), x, y, 0, 0, flags);

        // ::SetTextAlign(hdc, TA_RIGHT) doesn't work with DSS_DISABLED or DSS_MONO
        // as the last parameter in DrawState() (at least with Windows98). So we have
        // to take care of right alignment ourselves.
        wxString accel = GetItemLabel().AfterFirst(wxT('\t'));
        if ( !accel.empty() )
        {
            SIZE accelSize;
            ::GetTextExtentPoint32(hdc, accel.c_str(), accel.length(), &accelSize);

            int flags = DST_TEXT;
            // themes menu is using specified color for disabled labels
            if ( data->MenuLayout() == MenuDrawData::Classic &&
                 (stat & wxODDisabled) && !(stat & wxODSelected) )
                flags |= DSS_DISABLED;

            int x = rcText.right - data->ArrowMargin.left
                                 - data->ArrowSize.cx
                                 - data->ArrowMargin.right
                                 - data->ArrowBorder;

            // right align accel on FullTheme menu, left otherwise
            if ( data->MenuLayout() == MenuDrawData::FullTheme)
                x -= accelSize.cx;
            else
                x -= m_parentMenu->GetMaxAccelWidth();

            int y = rcText.top + (rcText.bottom - rcText.top - accelSize.cy) / 2;

            ::DrawState(hdc, NULL, NULL, (LPARAM)accel.wx_str(),
                        accel.length(), x, y, 0, 0, flags);
        }

        ::SetBkMode(hdc, prevMode);
        ::SetBkColor(hdc, colOldBack);
        ::SetTextColor(hdc, colOldText);
    }


    // draw the bitmap

    RECT rcImg;
    SetRect(&rcImg,
            rect.left   + data->ItemMargin.left
                        + data->CheckBgMargin.left
                        + data->CheckMargin.left,
            rect.top    + data->ItemMargin.top
                        + data->CheckBgMargin.top
                        + data->CheckMargin.top,
            rect.left   + data->ItemMargin.left
                        + data->CheckBgMargin.left
                        + data->CheckMargin.left
                        + imgWidth,
            rect.bottom - data->ItemMargin.bottom
                        - data->CheckBgMargin.bottom
                        - data->CheckMargin.bottom);

    if ( IsCheckable() && !m_bmpChecked.Ok() )
    {
        if ( stat & wxODChecked )
        {
            DrawStdCheckMark((WXHDC)hdc, &rcImg, stat);
        }
    }
    else
    {
        wxBitmap bmp;

        if ( stat & wxODDisabled )
        {
            bmp = GetDisabledBitmap();
        }

        if ( !bmp.Ok() )
        {
            // for not checkable bitmaps we should always use unchecked one
            // because their checked bitmap is not set
            bmp = GetBitmap(!IsCheckable() || (stat & wxODChecked));

#if wxUSE_IMAGE
            if ( bmp.Ok() && stat & wxODDisabled )
            {
                // we need to grey out the bitmap as we don't have any specific
                // disabled bitmap
                wxImage imgGrey = bmp.ConvertToImage().ConvertToGreyscale();
                if ( imgGrey.Ok() )
                    bmp = wxBitmap(imgGrey);
            }
#endif // wxUSE_IMAGE
        }

        if ( bmp.Ok() )
        {
            wxMemoryDC dcMem(&dc);
            dcMem.SelectObjectAsSource(bmp);

            // center bitmap
            int nBmpWidth  = bmp.GetWidth(),
                nBmpHeight = bmp.GetHeight();

            // there should be enough space!
            wxASSERT( nBmpWidth <= imgWidth && nBmpHeight <= (rcImg.bottom - rcImg.top) );

            int x = rcImg.left + (imgWidth - nBmpWidth) / 2;
            int y = rcImg.top  + (rcImg.bottom - rcImg.top - nBmpHeight) / 2;
            dc.Blit(x, y, nBmpWidth, nBmpHeight, &dcMem, 0, 0, wxCOPY, true);
        }
    }

    return true;

}

namespace
{

// helper function for draw coloured check mark
void DrawColorCheckMark(HDC hdc, int x, int y, int cx, int cy, HDC hdcCheckMask, int idxColor)
{
    const COLORREF colBlack = RGB(0, 0, 0);
    const COLORREF colWhite = RGB(255, 255, 255);

    COLORREF colOldText = ::SetTextColor(hdc, colBlack);
    COLORREF colOldBack = ::SetBkColor(hdc, colWhite);
    int prevMode = SetBkMode(hdc, TRANSPARENT);

    // memory DC for color bitmap
    MemoryHDC hdcMem(hdc);
    CompatibleBitmap hbmpMem(hdc, cx, cy);
    SelectInHDC selMem(hdcMem, hbmpMem);

    RECT rect = { 0, 0, cx, cy };
    ::FillRect(hdcMem, &rect, ::GetSysColorBrush(idxColor));

    const COLORREF colCheck = ::GetSysColor(idxColor);
    if ( colCheck == colWhite )
    {
        ::BitBlt(hdc, x, y, cx, cy, hdcCheckMask, 0, 0, MERGEPAINT);
        ::BitBlt(hdc, x, y, cx, cy, hdcMem, 0, 0, SRCAND);
    }
    else
    {
        if ( colCheck != colBlack )
        {
            const DWORD ROP_DSna = 0x00220326;  // dest = (NOT src) AND dest
            ::BitBlt(hdcMem, 0, 0, cx, cy, hdcCheckMask, 0, 0, ROP_DSna);
        }

        ::BitBlt(hdc, x, y, cx, cy, hdcCheckMask, 0, 0, SRCAND);
        ::BitBlt(hdc, x, y, cx, cy, hdcMem, 0, 0, SRCPAINT);
    }

    ::SetBkMode(hdc, prevMode);
    ::SetBkColor(hdc, colOldBack);
    ::SetTextColor(hdc, colOldText);
}

} // anonymous namespace

void wxMenuItem::DrawStdCheckMark(WXHDC hdc_, const RECT* rc, wxODStatus stat)
{
    HDC hdc = (HDC)hdc_;

#if wxUSE_UXTHEME
    wxUxThemeEngine* theme = MenuDrawData::GetUxThemeEngine();
    if ( theme )
    {
        wxUxThemeHandle hTheme(GetMenu()->GetWindow(), L"MENU");

        const MenuDrawData* data = MenuDrawData::Get();

        // rect for background must be without check margins
        RECT rcBg;
        SetRect(&rcBg,
                rc->left   - data->CheckMargin.left,
                rc->top    - data->CheckMargin.top,
                rc->right  + data->CheckMargin.right,
                rc->bottom + data->CheckMargin.bottom);

        POPUPCHECKBACKGROUNDSTATES stateCheckBg = (stat & wxODDisabled)
                                                    ? MCB_DISABLED
                                                    : MCB_NORMAL;

        theme->DrawThemeBackground(hTheme, hdc, MENU_POPUPCHECKBACKGROUND,
                                   stateCheckBg, &rcBg, NULL);

        POPUPCHECKSTATES stateCheck;
        if ( GetKind() == wxITEM_CHECK )
        {
            stateCheck = (stat & wxODDisabled) ? MC_CHECKMARKDISABLED
                                               : MC_CHECKMARKNORMAL;
        }
        else
        {
            stateCheck = (stat & wxODDisabled) ? MC_BULLETDISABLED
                                               : MC_BULLETNORMAL;
        }

        theme->DrawThemeBackground(hTheme, hdc, MENU_POPUPCHECK,
                                   stateCheck, rc, NULL);
    }
    else
#endif // wxUSE_UXTHEME
    {
        int cx = rc->right - rc->left;
        int cy = rc->bottom - rc->top;

        // first create mask of check mark
        MemoryHDC hdcMask(hdc);
        MonoBitmap hbmpMask(cx, cy);
        SelectInHDC selMask(hdcMask,hbmpMask);

        // then draw a check mark into it
        UINT stateCheck = (GetKind() == wxITEM_CHECK) ? DFCS_MENUCHECK
                                                      : DFCS_MENUBULLET;
        RECT rect = { 0, 0, cx, cy };
        ::DrawFrameControl(hdcMask, &rect, DFC_MENU, stateCheck);

        // first draw shadow if disabled
        if ( (stat & wxODDisabled) && !(stat & wxODSelected) )
        {
            DrawColorCheckMark(hdc, rc->left + 1, rc->top + 1,
                               cx, cy, hdcMask, COLOR_3DHILIGHT);
        }

        // then draw a check mark
        int color = COLOR_MENUTEXT;
        if ( stat & wxODDisabled )
            color = COLOR_BTNSHADOW;
        else if ( stat & wxODSelected )
            color = COLOR_HIGHLIGHTTEXT;

        DrawColorCheckMark(hdc, rc->left, rc->top, cx, cy, hdcMask, color);
    }
}

void wxMenuItem::GetFontToUse(wxFont& font) const
{
    font = GetFont();
    if ( !font.IsOk() )
        font = MenuDrawData::Get()->Font;
}

void wxMenuItem::GetColourToUse(wxODStatus stat, wxColour& colText, wxColour& colBack) const
{
#if wxUSE_UXTHEME
    wxUxThemeEngine* theme = MenuDrawData::GetUxThemeEngine();
    if ( theme )
    {
        wxUxThemeHandle hTheme(GetMenu()->GetWindow(), L"MENU");

        if ( stat & wxODDisabled)
        {
            wxRGBToColour(colText, theme->GetThemeSysColor(hTheme, COLOR_GRAYTEXT));
        }
        else
        {
            colText = GetTextColour();
            if ( !colText.IsOk() )
                wxRGBToColour(colText, theme->GetThemeSysColor(hTheme, COLOR_MENUTEXT));
        }

        if ( stat & wxODSelected )
        {
            wxRGBToColour(colBack, theme->GetThemeSysColor(hTheme, COLOR_HIGHLIGHT));
        }
        else
        {
            colBack = GetBackgroundColour();
            if ( !colBack.IsOk() )
                wxRGBToColour(colBack, theme->GetThemeSysColor(hTheme, COLOR_MENU));
        }
    }
    else
#endif // wxUSE_UXTHEME
    {
        wxOwnerDrawn::GetColourToUse(stat, colText, colBack);
    }
}
#endif // wxUSE_OWNER_DRAWN

// ----------------------------------------------------------------------------
// wxMenuItemBase
// ----------------------------------------------------------------------------

wxMenuItem *wxMenuItemBase::New(wxMenu *parentMenu,
                                int id,
                                const wxString& name,
                                const wxString& help,
                                wxItemKind kind,
                                wxMenu *subMenu)
{
    return new wxMenuItem(parentMenu, id, name, help, kind, subMenu);
}

#endif // wxUSE_MENUS

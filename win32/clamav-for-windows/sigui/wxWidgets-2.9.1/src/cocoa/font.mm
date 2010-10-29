/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/font.cpp
// Purpose:     wxFont class
// Author:      AUTHOR
// Modified by:
// Created:     ??/??/98
// RCS-ID:      $Id$
// Copyright:   (c) AUTHOR
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/*! @file   font.mm
    @disucssion
    Cocoa has three classes which interact to form the font system:

    NSFont: Represents a specific font (e.g. Times-Bold) at a specific size
    with specific attributes.  That is, it's basically like this class.
    Notably, it doesn't hold an underlined flag, so this class does.
    Available on all OS X versions.

    NSFontManager: Fairly broad controller class which ties together the
    model (NSFont) with the view (NSFontPanel).  We are ignoring NSFontPanel
    in this discussion.  NSFontManager is actually a little broader than just
    a controller though.  It's also the traditional way of mutating fonts
    and asking for a font with a certain family and certain attributes.
    For example, you can use NSFont's factor methods to create a font named
    @"Times-Roman" then use NSFontManager to imbue attributes like italic and
    bold.  You might do this if, for instance, you already have times at the
    Roman weight but want to make it bold.

    Alternatively, you can use NSFontManager to ask for a font in the @"Times"
    family with the bold attribute.

    NSFontManager is available on all OS X versions.

    NSFontDescriptor: Added in OS X 10.3.  Prior to this there was no specific
    class to represent all of the attributes of a font.  Instead, a regular
    NSDictionary was used with a set of well-defined keys.  Unfortunately,
    there was no method accepting the attributes dictionary, only a method
    to retrieve it from an NSFont.  That meant that in order to create
    a new font by imbueing certain attributes like Bold one would need
    to use the specific method in NSFontManager to do so.

    The NSFontDescriptor class, on the other hand, has factory methods which
    can create a new font descriptor with an attributes dictionary as well
    as mutate (by copy) an existing font descriptor using attributes from
    an attributes dictionary.

    In theory, most of what can be done using NSFontDescriptor can just as
    well be done without it.  NSFontDescriptor is basically just a shell
    around an NSMutableDictionary with well-defined keys.


    Getting back to the broad overview, font matching is one of the weaker points
    in Cocoa's API and NSFontDescriptor is the easier to use solution.

    That said, it's not impossible to implement font matching without it. For instance,
    if you have a family name and want to list available variants (e.g. Bold, italic,
    underlined) then you can ask NSFontManager for availableMembersOfFontFamily:.

    The problem is that you can either match on family name or on font attributes
    but not on both.  To match both you have to do one then the other.
    NSFontDescriptor allows you to get a list of fonts matching both a family name
    and a particular set of attributes.  Furthermore, the attributes instead of
    being flags as in NSFontManager are instead well-defined keys in a dictionary.

    The only way to get that behavior without NSFontManager is to pare down the
    list as much as possible using the classic NSFontManager methods and then
    to instantiate each font in the list and match on each font's afmDictionary.

    A reasonable guess is that that's probably more or less exactly what
    NSFontDescriptor does internally.
 */
#include "wx/wxprec.h"

#include "wx/font.h"

#ifndef WX_PRECOMP
    #include "wx/string.h"
    #include "wx/gdicmn.h"
#endif

#include "wx/fontutil.h"
#include "wx/encinfo.h"

#include "wx/cocoa/string.h"
#include "wx/cocoa/private/fontfactory.h"
#include "wx/cocoa/autorelease.h"

#include <AppKit/NSFont.h>
#include <AppKit/NSFontManager.h>

// Helper methods for NSFont/wxNativeFontInfo
static NSFont* GetNSFontForNativeFontInfo(const wxNativeFontInfo &info);
static void UpdateNativeFontInfoWithNSFont(wxNativeFontInfo &info, NSFont *cocoaNSFont);
static wxNativeFontInfo MakeNativeFontInfoForNSFont(NSFont *cocoaNSFont, bool underlined = false);
static wxNativeFontInfo MakeNativeFontInfo(int size, wxFontFamily family, wxFontStyle style, wxFontWeight weight, bool underlined, const wxString& faceName, wxFontEncoding encoding);

/*! @discussion
    Due to 2.8 ABI compatibility concerns we probably don't want to change wxNativeFontInfo
    although this may be unfounded because this class is supposed to be internal as is
    wxNativeFontInfo so anyone who subclassed it or created one without going through
    wxFont should expect what they get (i.e. horrible breakage)
    There's a concern that wxFontRefData was in the public header when 2.8 shipped so
    it's possible that someone did subclass it to get better font behavior.

    For right now, the plan is to write it strictly ABI compatible with 2.8 and eventually
    to enhance it in trunk to accurately represent font attributes as Cocoa sees them.

    I'd like to let at least one 2.8 release go out the door and get feedback as to whether
    this is going to be a problem or not.  If so, we'll keep it strictly ABI compatible.
    If not, we'll update it.
 */
class WXDLLEXPORT wxFontRefData: public wxGDIRefData
{
    friend class WXDLLIMPEXP_FWD_CORE wxFont;
public:
    wxFontRefData()
    :   m_cocoaNSFont(nil)
    ,   m_info(MakeNativeFontInfo(10, wxDEFAULT, wxNORMAL, wxNORMAL, FALSE,
             wxT("Geneva"), wxFONTENCODING_DEFAULT))
    {
        CreateNSFontAndUpdateInfo();
    }

    wxFontRefData(const wxFontRefData& data)
    :   wxGDIRefData()
    ,   m_cocoaNSFont([data.m_cocoaNSFont retain])
    ,   m_info(data.m_info)
    {
    }

    wxFontRefData(NSFont *cocoaNSFont, bool underlined)
    :   wxGDIRefData()
    ,   m_cocoaNSFont([cocoaNSFont retain])
    ,   m_info(MakeNativeFontInfoForNSFont(m_cocoaNSFont, underlined))
    {
    }

    wxFontRefData(const wxNativeFontInfo& info)
    :   wxGDIRefData()
    ,   m_cocoaNSFont(nil)
    ,   m_info(info)
    {
        CreateNSFontAndUpdateInfo();
    }

    wxFontRefData(int size,
                  wxFontFamily family,
                  wxFontStyle style,
                  wxFontWeight weight,
                  bool underlined,
                  const wxString& faceName,
                  wxFontEncoding encoding)
    :   m_cocoaNSFont(nil)
    ,   m_info(MakeNativeFontInfo(size, family, style, weight, underlined, faceName, encoding))
    {
        CreateNSFontAndUpdateInfo();
    }

    virtual ~wxFontRefData();
protected:
    /*! @abstract   common part of some ctors
        @discussion
        This is a leftover of sorts from the old stub code.
        FIXME: Remove from trunk
     */
    void Init(int size,
              wxFontFamily family,
              wxFontStyle style,
              wxFontWeight weight,
              bool underlined,
              const wxString& faceName,
              wxFontEncoding encoding);

    /*! @discussion
        Uses the native font info to create an NSFont and then updates that info with
        the attributes of the font.  This is necessary because, for example, a font
        can be created with an empty faceName in which case some concrete typeface must
        be chosen.
        We choose to handle this by first initializing the wxNativeFontInfo with the
        properties as given by the user and then creating the NSFont and updating
        the wxNativeFontInfo to match the NSFont.
     */
    void CreateNSFontAndUpdateInfo()
    {
        wxAutoNSAutoreleasePool pool;
        [m_cocoaNSFont release];
        m_cocoaNSFont = [GetNSFontForNativeFontInfo(m_info) retain];
        UpdateNativeFontInfoWithNSFont(m_info, m_cocoaNSFont);
    }

    // font characterstics
    NSFont *m_cocoaNSFont;
    wxNativeFontInfo m_info;

public:
};

NSString *GetFamilyName(wxFontFamily family)
{
    switch(family)
    {
    case wxFONTFAMILY_DEFAULT:
    default:
        return @"Times";
    case wxFONTFAMILY_DECORATIVE:
    case wxFONTFAMILY_ROMAN:
    case wxFONTFAMILY_SCRIPT:
        return @"Times";
    case wxFONTFAMILY_SWISS:
        return @"Lucida Grande";
    case wxFONTFAMILY_MODERN:
    case wxFONTFAMILY_TELETYPE:
        return @"Monaco";
    };
}
// Returns an NSFont given the native font info
// NOTE: It is not considered alloc'd (i.e. this is a get method not an alloc/new method)
static NSFont* GetNSFontForNativeFontInfo(const wxNativeFontInfo &info)
{
    if(!info.faceName.empty())
    {
        NSFont *font = [NSFont fontWithName:wxNSStringWithWxString(info.faceName) size:info.pointSize];
        // TODO: use NSFontManager to mix in the weights and whatnot
        if(font != nil)
            return font;
        // To err or not to err?
    }
    // No font with that face name or no face name

    NSFontTraitMask cocoaTraits = 0;
    int cocoaWeight = 5;
    NSFont *font = [[NSFontManager sharedFontManager] fontWithFamily:GetFamilyName(info.family) traits:cocoaTraits weight:cocoaWeight size:info.pointSize];
    return font;
}

/*! @discussion
    Updates all fields of @a info except for underlined which is not a property of NSFont.
 */
static void UpdateNativeFontInfoWithNSFont(wxNativeFontInfo &info, NSFont *cocoaNSFont)
{
    info.pointSize = [cocoaNSFont pointSize];

    // FIXME: We could maybe improve on this?
    info.family = wxFONTFAMILY_DEFAULT;

    // FIXME: italicAngle might indicate a slanted rather than truly italic font?
    info.style = [cocoaNSFont italicAngle] == 0.0?wxFONTSTYLE_NORMAL:wxFONTSTYLE_ITALIC;

    int cocoaWeight = [[NSFontManager sharedFontManager] weightOfFont:cocoaNSFont];
    if(cocoaWeight < 5)
        info.weight = wxFONTWEIGHT_LIGHT;
    else if(cocoaWeight < 9)
        info.weight = wxFONTWEIGHT_NORMAL;
    else
        info.weight = wxFONTWEIGHT_BOLD;

    // FIXME: Is this right?  I think so.
    info.faceName = wxStringWithNSString([cocoaNSFont fontName]);

    // TODO: Translate NSStringEncoding to wxFontEncoding
    info.encoding = wxFONTENCODING_SYSTEM;
}

/*! @discussion
    Creates a new generic wxNativeFontInfo from an NSFont and an underlined flag.
    Uses UpdateNativeFontInfoWithNSFont to do the work and sets the underlined field
    of wxNativeFontInfo to the @a underlined argument.
 */
static wxNativeFontInfo MakeNativeFontInfoForNSFont(NSFont *cocoaNSFont, bool underlined)
{
    wxNativeFontInfo info;
    UpdateNativeFontInfoWithNSFont(info, cocoaNSFont);

    // NSFont are never underlined.. that's a function of the drawing system
    info.underlined = underlined;

    return info;
}

//#include "_font_test_2_8_abi_compat.h"

IMPLEMENT_DYNAMIC_CLASS(wxFont, wxGDIObject)

static wxNativeFontInfo MakeNativeFontInfo(int size, wxFontFamily family, wxFontStyle style, wxFontWeight weight, bool underlined, const wxString& faceName, wxFontEncoding encoding)
{
    wxNativeFontInfo m_info; // NOTE: not an i-var despite name
    m_info.pointSize = size;
    m_info.family = static_cast<wxFontFamily>(family);
    m_info.style = static_cast<wxFontStyle>(style);
    m_info.weight = static_cast<wxFontWeight>(weight);
    m_info.underlined = underlined;
    m_info.faceName = faceName;
    m_info.encoding = encoding;
    return m_info;
}

void wxFontRefData::Init(int size, wxFontFamily family, wxFontStyle style, wxFontWeight weight, bool underlined, const wxString& faceName, wxFontEncoding encoding)
{
    m_info = MakeNativeFontInfo(size, family, style, weight, underlined, faceName, encoding);
}

wxFontRefData::~wxFontRefData()
{
    [m_cocoaNSFont release];
    m_cocoaNSFont = nil;
    // TODO: delete font data
}

#define M_FONTDATA ((wxFontRefData*)m_refData)

wxFont wxCocoaFontFactory::InstanceForNSFont(WX_NSFont cocoaFont, bool underlined)
{
    return wxFont(new wxFontRefData(cocoaFont, underlined));
}

bool wxFont::Create(wxFontRefData *refData)
{
    UnRef();
    m_refData = refData;

    return m_refData != NULL;
}

bool wxFont::Create(const wxNativeFontInfo& nativeFontInfo)
{
    UnRef();
    m_refData = new wxFontRefData(nativeFontInfo);

    return true;
}

wxGDIRefData *wxFont::CreateGDIRefData() const
{
    return new wxFontRefData;
}

wxGDIRefData *wxFont::CloneGDIRefData(const wxGDIRefData *data) const
{
    return new wxFontRefData(*static_cast<const wxFontRefData *>(data));
}

void wxFont::SetEncoding(wxFontEncoding)
{
}

wxFontEncoding wxFont::GetEncoding() const
{
    return wxFontEncoding();
}

int wxFont::GetPointSize() const
{
    wxCHECK_MSG( Ok(), 0, wxT("invalid font") );
    return M_FONTDATA->m_info.pointSize;
}

bool wxFont::GetUnderlined() const
{
    if(M_FONTDATA)
        return M_FONTDATA->m_info.underlined;
    else
        return false;
}

wxFontStyle wxFont::GetStyle() const
{
    wxCHECK_MSG( Ok(), 0, wxT("invalid font") );
    return M_FONTDATA->m_info.style;
}

wxFontFamily wxFont::GetFamily() const
{
    wxCHECK_MSG( Ok(), 0, wxT("invalid font") );
    return M_FONTDATA->m_info.family;
}

wxFontWeight wxFont::GetWeight() const
{
    wxCHECK_MSG( Ok(), 0, wxT("invalid font") );
    return M_FONTDATA->m_info.weight;
}

const wxNativeFontInfo *wxFont::GetNativeFontInfo() const
{
    wxCHECK_MSG( Ok(), 0, wxT("invalid font") );
    return &M_FONTDATA->m_info;
}

bool wxFont::Create(int pointSize, wxFontFamily family, wxFontStyle style, wxFontWeight weight, bool underlined, const wxString& faceName, wxFontEncoding encoding)
{
    UnRef();
    m_refData = new wxFontRefData(pointSize, family, style, weight, underlined, faceName, encoding);

    RealizeResource();

    return true;
}

wxFont::~wxFont()
{
}

bool wxFont::RealizeResource()
{
    // TODO: create the font (if there is a native font object)
    return false;
}

void wxFont::SetPointSize(int pointSize)
{
    AllocExclusive();

    M_FONTDATA->m_info.pointSize = pointSize;

    RealizeResource();
}

void wxFont::SetFamily(wxFontFamily family)
{
    AllocExclusive();

    M_FONTDATA->m_info.family = static_cast<wxFontFamily>(family);

    RealizeResource();
}

void wxFont::SetStyle(wxFontStyle style)
{
    AllocExclusive();

    M_FONTDATA->m_info.style = static_cast<wxFontStyle>(style);

    RealizeResource();
}

void wxFont::SetWeight(wxFontWeight weight)
{
    AllocExclusive();

    M_FONTDATA->m_info.weight = static_cast<wxFontWeight>(weight);

    RealizeResource();
}

bool wxFont::SetFaceName(const wxString& faceName)
{
    AllocExclusive();

    M_FONTDATA->m_info.faceName = faceName;

    RealizeResource();

    return wxFontBase::SetFaceName(faceName);
}

void wxFont::SetUnderlined(bool underlined)
{
    AllocExclusive();

    M_FONTDATA->m_info.underlined = underlined;

    RealizeResource();
}

/* New font system */
wxString wxFont::GetFaceName() const
{
    wxString str;
    if (M_FONTDATA)
        str = M_FONTDATA->m_info.faceName;
    return str;
}

// vim:sts=4:sw=4:et

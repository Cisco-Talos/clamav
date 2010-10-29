/////////////////////////////////////////////////////////////////////////////
// Name:        xmlparser.cpp
// Purpose:     Parser of the API/interface XML files
// Author:      Francesco Montorsi
// Created:     2008/03/17
// RCS-ID:      $Id$
// Copyright:   (c) 2008 Francesco Montorsi
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

// For compilers that support precompilation, includes "wx/wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
    #pragma hdrstop
#endif

// for all others, include the necessary headers
#ifndef WX_PRECOMP
    #include "wx/crt.h"
#endif

#include "wx/xml/xml.h"
#include "wx/wfstream.h"
#include "wx/hashmap.h"
#include "wx/filename.h"
#include "xmlparser.h"
#include <errno.h>

#include <wx/arrimpl.cpp>
WX_DEFINE_OBJARRAY(wxTypeArray)
WX_DEFINE_OBJARRAY(wxArgumentTypeArray)
WX_DEFINE_OBJARRAY(wxMethodArray)
WX_DEFINE_OBJARRAY(wxClassArray)


#define PROGRESS_RATE             1000     // each PROGRESS_RATE nodes processed print a dot
#define ESTIMATED_NUM_CLASSES     600      // used by both wxXmlInterface-derived classes to prealloc mem


// defined in ifacecheck.cpp
extern bool g_verbose;

// global variable:
bool g_bLogEnabled = true;



// ----------------------------------------------------------------------------
// wxType
// ----------------------------------------------------------------------------

wxType wxEmptyType;

void wxType::SetTypeFromString(const wxString& t)
{
    /*
        TODO: optimize the following code writing a single function
              which works at char-level and does everything in a single pass
    */

    // clean the type string
    // ---------------------

    m_strType = t;

    // [] is the same as * for gccxml
    m_strType.Replace("[]", "*");
    m_strType.Replace("long int", "long");      // in wx typically we never write "long int", just "long"
    m_strType.Replace("long unsigned int", "unsigned long");
    m_strType.Replace("short unsigned int", "unsigned short");

    // make sure the * and & operator always use the same spacing rules
    // (to make sure GetAsString() output is always consistent)
    m_strType.Replace("*", "* ");
    m_strType.Replace("&", "& ");
    m_strType.Replace(" *", "*");
    m_strType.Replace(" &", "&");

    while (m_strType.Contains("  "))
        m_strType.Replace("  ", " ");       // do it once again

    m_strType.Replace(" ,", ",");

    // ADHOC-FIX
    m_strType.Replace("_wxArraywxArrayStringBase", "wxString");
    m_strType.Replace("ExitCode", "void*");     // used in wxThread stuff

    m_strType = m_strType.Strip(wxString::both);



    // clean the type string (this time for the comparison)
    // ----------------------------------------------------

    m_strTypeClean = m_strType;     // begin with the already-cleaned string
    m_strTypeClean.Replace("const", "");
    m_strTypeClean.Replace("static", "");
    m_strTypeClean.Replace("*", "");
    m_strTypeClean.Replace("&", "");
    m_strTypeClean.Replace("[]", "");
    m_strTypeClean = m_strTypeClean.Strip(wxString::both);

    // to avoid false errors types like wxStandardPaths and wxStandardPathsBase
    // need to be considered as the same type
    if (m_strTypeClean.EndsWith("Base"))
        m_strTypeClean = m_strTypeClean.Left(m_strTypeClean.Len()-4);

    // remove the namespace from the types; there's no problem of conflicts
    // (except for templates) and this avoids tons of false warnings
    if (m_strTypeClean.Contains("::") && !m_strTypeClean.Contains("<"))
        m_strTypeClean = m_strTypeClean.Mid(m_strTypeClean.Find("::")+2);

    // ADHOC-FIX:
    m_strTypeClean.Replace("wxWindowID", "int");
}

bool wxType::IsOk() const
{
    // NB: m_strType can contain the :: operator; think to e.g. the
    //     "reverse_iterator_impl<wxString::const_iterator>" type
    //     It can also contain commas, * and & operators etc

    return !m_strTypeClean.IsEmpty();
}

bool wxType::operator==(const wxType& m) const
{
    // brain-dead comparison:

    if (m_strTypeClean == m.m_strTypeClean &&
        IsConst() == m.IsConst() &&
        IsStatic() == m.IsStatic() &&
        IsPointer() == m.IsPointer() &&
        IsReference() == m.IsReference())
        return true;

    if (g_verbose)
    {
        wxLogMessage("Type '%s' does not match type '%s'", m_strType, m.m_strType);
        wxLogMessage(" => TypeClean %s / %s;  IsConst %d / %d; IsStatic %d / %d; IsPointer %d / %d; IsReference %d / %d",
                   m_strTypeClean, m.m_strTypeClean, IsConst(), m.IsConst(),
                   IsStatic(), m.IsStatic(), IsPointer(), m.IsPointer(),
                   IsReference(), m.IsReference());
    }

    return false;
}


// ----------------------------------------------------------------------------
// wxArgumentType
// ----------------------------------------------------------------------------

void wxArgumentType::SetDefaultValue(const wxString& defval, const wxString& defvalForCmp)
{
    m_strDefaultValue = defval.Strip(wxString::both);
    m_strDefaultValueForCmp = defvalForCmp.IsEmpty() ?
                m_strDefaultValue : defvalForCmp.Strip(wxString::both);


    // clean the default argument strings
    // ----------------------------------

    // Note: we adjust the aesthetic form of the m_strDefaultValue string for the "modify mode"
    //       of ifacecheck: we may need to write it out in an interface header

    wxString *p = NULL;
    for (int i=0; i<2; i++)     // to avoid copying&pasting the code!
    {
        if (i == 0) p = &m_strDefaultValue;
        if (i == 1) p = &m_strDefaultValueForCmp;

        if (*p == "0u" || *p == "0l") *p = "0";

        p->Replace("0x000000001", "1");
        p->Replace("\\000\\000\\000", "");    // fix for unicode strings:
        p->Replace("\\011", "\\t");
        p->Replace("e+0", "");
        p->Replace("2147483647", "__INT_MAX__");

        // ADHOC-FIX: for wxConv* default values
        p->Replace("wxConvAuto(wxFONTENCODING_DEFAULT)", "wxConvAuto()");
        p->Replace("wxGet_wxConvUTF8()", "wxConvUTF8");
        p->Replace("wxGet_wxConvLocal()", "wxConvLocal");
    }


    // clean ONLY the default argument string specific for comparison
    // --------------------------------------------------------------

    if (m_strDefaultValueForCmp.StartsWith("wxT(") &&
        m_strDefaultValueForCmp.EndsWith(")"))
    {
        // get rid of the wxT() part
        unsigned int len = m_strDefaultValueForCmp.Len();
        m_strDefaultValueForCmp = m_strDefaultValueForCmp.Mid(4,len-5);
    }

    // ADHOC-FIX:
    // doxygen likes to put wxDateTime:: in front of all wxDateTime enums;
    // fix this to avoid false positives
    m_strDefaultValueForCmp.Replace("wxDateTime::", "");
    m_strDefaultValueForCmp.Replace("wxStockGDI::", "");     // same story for some other classes
    m_strDefaultValueForCmp.Replace("wxHelpEvent::", "");    // same story for some other classes
    m_strDefaultValueForCmp.Replace("* GetColour(COLOUR_BLACK)", "*wxBLACK");

    // ADHOC-FIX:
    if (m_strDefaultValueForCmp.Contains("wxGetTranslation"))
        m_strDefaultValueForCmp = "_(TOFIX)";     // TODO: wxGetTranslation gives problems to gccxml
}

bool wxArgumentType::operator==(const wxArgumentType& m) const
{
    if ((const wxType&)(*this) != (const wxType&)m)
        return false;

    // check if the default values match
    // ---------------------------------


    // ADHOC-FIX:
    // default values for style attributes of wxWindow-derived classes in gccxml appear as raw
    // numbers; avoid false positives in this case!
    if (m_strArgName == m.m_strArgName && m_strArgName == "style" &&
        (m_strDefaultValueForCmp.IsNumber() || m.m_strDefaultValueForCmp.IsNumber()))
        return true;

    // fix for default values which were replaced by gcc-xml with their numeric values
    // (at this point we know that m_strTypeClean == m.m_strTypeClean):
    if (m_strTypeClean == "long" || m_strTypeClean == "int")
    {
        if ((m_strDefaultValueForCmp.IsNumber() && m.m_strDefaultValueForCmp.StartsWith("wx")) ||
            (m.m_strDefaultValueForCmp.IsNumber() && m_strDefaultValueForCmp.StartsWith("wx")))
        {
            if (g_verbose)
            {
                wxLogMessage("Supposing '%s'  default value to be the same of '%s'...",
                           m_strDefaultValueForCmp, m.m_strDefaultValueForCmp);
            }

            return true;
        }
    }
    else if (m_strTypeClean == "float" || m_strTypeClean == "double")
        // gccXML translates the default floating values in a hardly usable
        // format; e.g. 25.2 => 2.51999999999999992894572642398998141288757324219e+1
        // we avoid check on these...
        return true;

    if (m_strDefaultValueForCmp != m.m_strDefaultValueForCmp)
    {
        // maybe the default values are numbers.
        // in this case gccXML gives as default values things like '-0x0000001' instead of just '-1'.
        // To handle these cases, we try to convert the default value strings to numbers:
        long def1val, def2val;
        if (m_strDefaultValueForCmp.ToLong(&def1val, 0 /* auto-detect */) &&
            m.m_strDefaultValueForCmp.ToLong(&def2val, 0 /* auto-detect */))
        {
            if (def1val == def2val)
                return true;        // the default values match
        }

        if (g_verbose)
        {
            wxLogMessage("Argument type '%s = %s' has different default value from '%s = %s'",
                       m_strType, m_strDefaultValueForCmp, m.m_strType, m.m_strDefaultValueForCmp);
        }
        return false;
    }

    // we deliberately avoid checks on the argument name

    return true;
}


// ----------------------------------------------------------------------------
// wxMethod
// ----------------------------------------------------------------------------

bool wxMethod::IsOk() const
{
    // NOTE: m_retType can be a wxEmptyType, and means that this method
    //       is a ctor or a dtor.
    if (!m_retType.IsOk() && m_retType!=wxEmptyType) {
        wxLogError("'%s' method has invalid return type: %s", m_retType.GetAsString());
        return false;
    }

    if (m_strName.IsEmpty())
        return false;

    // a function can't be both const and static or virtual and static!
    if ((m_bConst && m_bStatic) || ((m_bVirtual || m_bPureVirtual) && m_bStatic)) {
        wxLogError("'%s' method can't be both const/static or virtual/static", m_strName);
        return false;
    }

    wxASSERT(!m_bPureVirtual || (m_bPureVirtual && m_bVirtual));

    for (unsigned int i=0; i<m_args.GetCount(); i++)
        if (!m_args[i].IsOk()) {
            wxLogError("'%s' method has invalid %d-th argument type: %s",
                     m_strName, i+1, m_args[i].GetAsString());
            return false;
        }

    // NB: the default value of the arguments can contain pretty much everything
    //     (think to e.g. wxPoint(3+4/2,0)   or   *wxBLACK   or  someClass<type>)
    //     so we don't do any test on their contents
    if (m_args.GetCount()>0)
    {
        bool previousArgHasDefault = m_args[0].HasDefaultValue();
        for (unsigned int i=1; i<m_args.GetCount(); i++)
        {
            if (previousArgHasDefault && !m_args[i].HasDefaultValue()) {
                wxLogError("'%s' method has %d-th argument which has no default value "
                         "(while the previous one had one!)",
                         m_strName, i+1);
                return false;
            }

            previousArgHasDefault = m_args[i].HasDefaultValue();
        }
    }

    return true;
}

bool wxMethod::MatchesExceptForAttributes(const wxMethod& m) const
{
    if (GetReturnType() != m.GetReturnType() ||
        GetName() != m.GetName())
    {
        if (g_verbose)
        {
            wxLogMessage("The method '%s' does not match method '%s'; different names/rettype", GetName(), m.GetName());
        }
        return false;
    }

    if (m_args.GetCount()!=m.m_args.GetCount()) {
        if (g_verbose)
        {
            wxLogMessage("Method '%s' has %d arguments while '%s' has %d arguments",
                       m_strName, m_args.GetCount(), m_strName, m.m_args.GetCount());
        }
        return false;
    }

    // compare argument types
    for (unsigned int i=0; i<m_args.GetCount(); i++)
        if (m_args[i] != m.m_args[i])
            return false;

    return true;
}

bool wxMethod::ActsAsDefaultCtor() const
{
    if (!IsCtor())
        return false;

    for (unsigned int i=0; i<m_args.GetCount(); i++)
        if (!m_args[i].HasDefaultValue())
            return false;

    return true;
}

bool wxMethod::operator==(const wxMethod& m) const
{
    // check attributes
    if (IsConst() != m.IsConst() ||
        IsStatic() != m.IsStatic() ||
        IsVirtual() != m.IsVirtual() ||
        IsPureVirtual() != m.IsPureVirtual() ||
        IsDeprecated() != m.IsDeprecated() ||
        GetAccessSpecifier() != m.GetAccessSpecifier())
    {
        if (g_verbose)
        {
            wxLogMessage("The method '%s' does not match method '%s'; different attributes", GetName(), m.GetName());
        }

        return false;
    }

    // check everything else
    return MatchesExceptForAttributes(m);
}

wxString wxMethod::GetAsString(bool bWithArgumentNames, bool bCleanDefaultValues,
                               bool bDeprecated, bool bAccessSpec) const
{
    wxString ret;

    // NOTE: for return and argument types, never use wxType::GetAsCleanString
    //       since in that way we'd miss important decorators like &,*,const etc

    if (m_retType!=wxEmptyType)
        ret += m_retType.GetAsString() + " ";
    //else; this is a ctor or dtor

    ret += m_strName + "(";

    for (unsigned int i=0; i<m_args.GetCount(); i++)
    {
        ret += m_args[i].GetAsString();

        const wxString& name = m_args[i].GetArgumentName();
        if (bWithArgumentNames && !name.IsEmpty())
            ret += " " + name;

        const wxString& def = bCleanDefaultValues ?
            m_args[i].GetDefaultCleanValue() : m_args[i].GetDefaultValue();
        if (!def.IsEmpty())
            ret += " = " + def;

        ret += ", ";
    }

    if (m_args.GetCount()>0)
        ret = ret.Left(ret.Len()-2);

    ret += ")";

    if (m_bConst)
        ret += " const";
    if (m_bStatic)
        ret = "static " + ret;
    if (m_bVirtual || m_bPureVirtual)
        ret = "virtual " + ret;
    if (m_bPureVirtual)
        ret += " = 0";
    if (m_bDeprecated && bDeprecated)
        ret += " [deprecated]";

    if (bAccessSpec)
    {
        switch (m_access)
        {
        case wxMAS_PUBLIC:
            ret += " [public]";
            break;
        case wxMAS_PROTECTED:
            ret += " [protected]";
            break;
        case wxMAS_PRIVATE:
            ret += " [private]";
            break;
        }
    }

    return ret;
}

void wxMethod::Dump(wxTextOutputStream& stream) const
{
    stream << "[" + m_retType.GetAsString() + "]";
    stream << "[" + m_strName + "]";

    for (unsigned int i=0; i<m_args.GetCount(); i++)
        stream << "[" + m_args[i].GetAsString() + " " + m_args[i].GetArgumentName() +
                  "=" + m_args[i].GetDefaultValue() + "]";

    if (IsConst())
        stream << " CONST";
    if (IsStatic())
        stream << " STATIC";
    if (IsVirtual())
        stream << " VIRTUAL";
    if (IsPureVirtual())
        stream << " PURE-VIRTUAL";
    if (IsDeprecated())
        stream << " DEPRECATED";

    // no final newline
}

// ----------------------------------------------------------------------------
// wxClass
// ----------------------------------------------------------------------------

wxString wxClass::GetNameWithoutTemplate() const
{
    // NB: I'm not sure this is the right terminology for this function!

    if (m_strName.Contains("<"))
        return m_strName.Left(m_strName.Find("<"));
    return m_strName;
}

bool wxClass::IsValidCtorForThisClass(const wxMethod& m) const
{
    // remember that e.g. the ctor for wxWritableCharTypeBuffer<wchar_t> is
    // named wxWritableCharTypeBuffer, without the <...> part!

    if (m.IsCtor() && m.GetName() == GetNameWithoutTemplate())
        return true;

    return false;
}

bool wxClass::IsValidDtorForThisClass(const wxMethod& m) const
{
    if (m.IsDtor() && m.GetName() == "~" + GetNameWithoutTemplate())
        return true;

    return false;
}

void wxClass::Dump(wxTextOutputStream& out) const
{
    out << m_strName + "\n";

    for (unsigned int i=0; i<m_methods.GetCount(); i++) {

        // dump all our methods
        out << "|- ";
        m_methods[i].Dump(out);
        out << "\n";
    }

    out << "\n";
}

bool wxClass::CheckConsistency() const
{
    for (unsigned int i=0; i<m_methods.GetCount(); i++)
        for (unsigned int j=0; j<m_methods.GetCount(); j++)
            if (i!=j && m_methods[i] == m_methods[j])
            {
                wxLogError("class %s has two methods with the same prototype: '%s'",
                         m_strName, m_methods[i].GetAsString());
                return false;

                // fix the problem?
                //((wxClass*)this)->m_methods.RemoveAt(j);
                //j--;
            }

    return true;
}

const wxMethod* wxClass::FindMethod(const wxMethod& m) const
{
    for (unsigned int i=0; i<m_methods.GetCount(); i++)
        if (m_methods[i] == m)
            return &m_methods[i];
    return NULL;
}

const wxMethod* wxClass::RecursiveUpwardFindMethod(const wxMethod& m,
                                                   const wxXmlInterface* allclasses) const
{
    // first, search into *this
    const wxMethod* ret = FindMethod(m);
    if (ret)
        return ret;

    // then, search into its parents
    for (unsigned int i=0; i<m_parents.GetCount(); i++)
    {
        // ignore non-wx-classes parents
        // AD-HOC FIX: discard wxScrolledT_Helper parent as it always gives errors
        if (m_parents[i].StartsWith("wx") && m_parents[i] != "wxScrolledT_Helper")
        {
            const wxClass *parent = allclasses->FindClass(m_parents[i]);
            if (!parent) {
                wxLogError("Could not find parent '%s' of class '%s'...",
                         m_parents[i], GetName());
                return false;
            }

            const wxMethod *parentMethod = parent->RecursiveUpwardFindMethod(m, allclasses);
            if (parentMethod)
                return parentMethod;
        }
    }

    // could not find anything even in parent classes...
    return NULL;
}

wxMethodPtrArray wxClass::FindMethodsNamed(const wxString& name) const
{
    wxMethodPtrArray ret;

    for (unsigned int i=0; i<m_methods.GetCount(); i++)
        if (m_methods[i].GetName() == name)
            ret.Add(&m_methods[i]);

    return ret;
}


wxMethodPtrArray wxClass::RecursiveUpwardFindMethodsNamed(const wxString& name,
                                                          const wxXmlInterface* allclasses) const
{
    // first, search into *this
    wxMethodPtrArray ret = FindMethodsNamed(name);
    if (ret.GetCount()>0)
        return ret;         // stop here, don't look upward in the parents

    // then, search into parents of this class
    for (unsigned int i=0; i<m_parents.GetCount(); i++)
    {
        // AD-HOC FIX: discard wxScrolledT_Helper parent as it always gives errors
        if (m_parents[i].StartsWith("wx") && m_parents[i] != "wxScrolledT_Helper")
        {
            const wxClass *parent = allclasses->FindClass(m_parents[i]);
            if (!parent) {
                wxLogError("Could not find parent '%s' of class '%s'...",
                         m_parents[i], GetName());
                return false;
            }

            wxMethodPtrArray temp = parent->RecursiveUpwardFindMethodsNamed(name, allclasses);
            WX_APPEND_ARRAY(ret, temp);
        }
    }

    return ret;
}



// ----------------------------------------------------------------------------
// wxXmlInterface
// ----------------------------------------------------------------------------

WX_DEFINE_SORTED_ARRAY(wxClass*, wxSortedClassArray);

int CompareWxClassObjects(wxClass *item1, wxClass *item2)
{
    // sort alphabetically
    return item1->GetName().Cmp(item2->GetName());
}

void wxXmlInterface::Dump(const wxString& filename)
{
    wxFFileOutputStream apioutput( filename );
    wxTextOutputStream apiout( apioutput );

    // dump the classes in alphabetical order
    wxSortedClassArray sorted(CompareWxClassObjects);
    sorted.Alloc(m_classes.GetCount());

    unsigned i;
    for (i=0; i<m_classes.GetCount(); i++)
        sorted.Add(&m_classes[i]);

    // now they have been sorted
    for (i=0; i<sorted.GetCount(); i++)
        sorted[i]->Dump(apiout);
}

bool wxXmlInterface::CheckConsistency() const
{
    // this check can be quite slow, so do it only for debug releases:
//#ifdef __WXDEBUG__
    for (unsigned int i=0; i<m_classes.GetCount(); i++)
    {
        if (!m_classes[i].CheckConsistency())
            return false;

        for (unsigned int j=0; j<m_classes.GetCount(); j++)
            if (i!=j && m_classes[i].GetName() == m_classes[j].GetName())
            {
                wxLogError("two classes have the same name: %s",
                         m_classes[i].GetName());
                return false;
            }
    }
//#endif

    return true;
}

wxClassPtrArray wxXmlInterface::FindClassesDefinedIn(const wxString& headerfile) const
{
    wxClassPtrArray ret;

    for (unsigned int i=0; i<m_classes.GetCount(); i++)
        if (m_classes[i].GetHeader() == headerfile)
            ret.Add(&m_classes[i]);

    return ret;
}


// ----------------------------------------------------------------------------
// wxXmlGccInterface helper declarations
// ----------------------------------------------------------------------------

// or-able flags for a toResolveTypeItem->attrib:
#define ATTRIB_CONST        1
#define ATTRIB_REFERENCE    2
#define ATTRIB_POINTER      4
#define ATTRIB_ARRAY        8

// it may sound strange but gccxml, in order to produce shorter ID names
// uses (after the underscore) characters in range 0-9 and a-z in the ID names;
// in order to be able to translate such strings into numbers using strtoul()
// we use as base 10 (possible digits) + 25 (possible characters) = 35
#define GCCXML_BASE         35

class toResolveTypeItem
{
public:
    toResolveTypeItem() { attribs=0; }
    toResolveTypeItem(unsigned int refID, unsigned int attribint)
        : ref(refID), attribs(attribint) {}

    unsigned long ref,       // the referenced type's ID
                  attribs;   // the attributes of this reference
};

#if 1

// for wxToResolveTypeHashMap, keys == gccXML IDs  and  values == toResolveTypeItem
WX_DECLARE_HASH_MAP( unsigned long, toResolveTypeItem,
                     wxIntegerHash, wxIntegerEqual,
                     wxToResolveTypeHashMap );

// for wxClassMemberIdHashMap, keys == gccXML IDs  and  values == wxClass which owns that member ID
WX_DECLARE_HASH_MAP( unsigned long, wxClass*,
                     wxIntegerHash, wxIntegerEqual,
                     wxClassMemberIdHashMap );

#else
#include <map>
typedef std::map<unsigned long, toResolveTypeItem> wxToResolveTypeHashMap;
#endif


// utility to parse gccXML ID values;
// this function is equivalent to wxString(str).Mid(1).ToULong(&id, GCCXML_BASE)
// but is a little bit faster
bool getID(unsigned long *id, const wxString& str)
{
    const wxStringCharType * const start = str.wx_str()+1;
    wxStringCharType *end;
#if wxUSE_UNICODE_WCHAR
    unsigned long val = wcstoul(start, &end, GCCXML_BASE);
#else
    unsigned long val = strtoul(start, &end, GCCXML_BASE);
#endif

    // return true only if scan was stopped by the terminating NUL and
    // if the string was not empty to start with and no under/overflow
    // occurred:
    if ( *end != '\0' || end == start || errno == ERANGE || errno == EINVAL )
        return false;

    *id = val;
    return true;
}

// utility specialized to parse efficiently the gccXML list of IDs which occur
// in nodes like <Class> ones... i.e. numeric values separed by " _" token
bool getMemberIDs(wxClassMemberIdHashMap* map, wxClass* p, const wxString& str)
{
    const wxStringCharType * const start = str.wx_str();
#if wxUSE_UNICODE_WCHAR
    size_t len = wcslen(start);
#else
    size_t len = strlen(start);
#endif

    if (len == 0 || start[0] != '_')
        return false;

    const wxStringCharType *curpos = start,
                           *end = start + len;
    wxStringCharType *nexttoken;

    while (curpos < end)
    {
        // curpos always points to the underscore of the next token to parse:
#if wxUSE_UNICODE_WCHAR
        unsigned long id = wcstoul(curpos+1, &nexttoken, GCCXML_BASE);
#else
        unsigned long id = strtoul(curpos+1, &nexttoken, GCCXML_BASE);
#endif
        if ( *nexttoken != ' ' || errno == ERANGE || errno == EINVAL )
            return false;

        // advance current position
        curpos = nexttoken + 1;

        // add this ID to the hashmap
        wxClassMemberIdHashMap::value_type v(id, p);
        map->insert(v);
    }

    return true;
}


// ----------------------------------------------------------------------------
// wxXmlGccInterface
// ----------------------------------------------------------------------------

bool wxXmlGccInterface::Parse(const wxString& filename)
{
    wxXmlDocument doc;
    wxXmlNode *child;
    int nodes = 0;

    wxLogMessage("Parsing %s...", filename);

    if (!doc.Load(filename)) {
        wxLogError("can't load %s", filename);
        return false;
    }

    // start processing the XML file
    if (doc.GetRoot()->GetName() != "GCC_XML") {
        wxLogError("invalid root node for %s", filename);
        return false;
    }

    wxString version = doc.GetRoot()->GetAttribute("cvs_revision");
    bool old = false;

#define MIN_REVISION  120

    if (!version.StartsWith("1."))
        old = true;
    if (!old)
    {
        unsigned long rev = 0;
        if (!version.Mid(2).ToULong(&rev))
            old = true;
        else
            if (rev < MIN_REVISION)
                old = true;
    }

    if (old)
    {
        wxLogError("The version of GCC-XML used for the creation of %s is too old; "
                 "the cvs_revision attribute of the root node reports '%s', "
                 "minimal required is 1.%d.", filename, version, MIN_REVISION);
        return false;
    }

    wxToResolveTypeHashMap toResolveTypes;
    wxClassMemberIdHashMap members;
    wxTypeIdHashMap types;
    wxTypeIdHashMap files;
    wxTypeIdHashMap typedefs;

    // prealloc quite a lot of memory!
    m_classes.Alloc(ESTIMATED_NUM_CLASSES);

    // build a list of wx classes and in general of all existent types
    child = doc.GetRoot()->GetChildren();
    while (child)
    {
        const wxString& n = child->GetName();

        unsigned long id = 0;
        if (!getID(&id, child->GetAttribute("id")) || (id == 0 && n != "File")) {

            // NOTE: <File> nodes can have an id == "f0"...

            wxLogError("Invalid id for node %s: %s", n, child->GetAttribute("id"));
            return false;
        }

        if (n == "Class")
        {
            wxString cname = child->GetAttribute("name");
            if (cname.IsEmpty()) {
                wxLogError("Invalid empty name for '%s' node", n);
                return false;
            }

            // only register wx classes (do remember also the IDs of their members)
            if (cname.StartsWith("wx"))
            {
                // NB: "file" attribute contains an ID value that we'll resolve later
                m_classes.Add(wxClass(cname, child->GetAttribute("file")));

                // the just-inserted class:
                wxClass *newClass = &m_classes.Last();

                // now get a list of the base classes:
                wxXmlNode *baseNode = child->GetChildren();
                while (baseNode)
                {
                    // for now we store as "parents" only the parent IDs...
                    // later we will resolve them into full class names
                    if (baseNode->GetName() == "Base")
                        newClass->AddParent(baseNode->GetAttribute("type"));

                    baseNode = baseNode->GetNext();
                }

                const wxString& ids = child->GetAttribute("members");
                if (ids.IsEmpty())
                {
                    if (child->GetAttribute("incomplete") != "1") {
                        wxLogError("Invalid member IDs for '%s' class node: %s",
                                cname, child->GetAttribute("id"));
                        return false;
                    }
                    //else: don't warn the user; it looks like "incomplete" classes
                    //      never have any member...
                }
                else
                {
                    // decode the non-empty list of IDs:
                    if (!getMemberIDs(&members, newClass, ids)) {
                        wxLogError("Invalid member IDs for '%s' class node: %s",
                                cname, child->GetAttribute("id"));
                        return false;
                    }
                }
            }

            // register this class also as possible return/argument type:
            types[id] = cname;
        }
        else if (n == "Typedef")
        {
            unsigned long typeId = 0;
            if (!getID(&typeId, child->GetAttribute("type"))) {
                wxLogError("Invalid type for node %s: %s", n, child->GetAttribute("type"));
                return false;
            }

            // this typedef node tell us that every type referenced with the
            // "typeId" ID should be called with another name:
            wxString name = child->GetAttribute("name");

            // save this typedef in a separate hashmap...
            typedefs[typeId] = name;

            types[id] = name;
        }
        else if (n == "PointerType" || n == "ReferenceType" ||
                 n == "CvQualifiedType" || n == "ArrayType")
        {
            unsigned long type = 0;
            if (!getID(&type, child->GetAttribute("type")) || type == 0) {
                wxLogError("Invalid type for node %s: %s", n, child->GetAttribute("type"));
                return false;
            }

            unsigned long attr = 0;
            if (n == "PointerType")
                attr = ATTRIB_POINTER;
            else if (n == "ReferenceType")
                attr = ATTRIB_REFERENCE;
            else if (n == "CvQualifiedType" && child->GetAttribute("const") == "1")
                attr = ATTRIB_CONST;
            else if (n == "ArrayType")
                attr = ATTRIB_ARRAY;

            // these nodes make reference to other types... we'll resolve them later
            toResolveTypes[id] = toResolveTypeItem(type, attr);
        }
        else if (n == "FunctionType" || n == "MethodType")
        {
            /*
                 TODO: parsing FunctionType and MethodType nodes is not as easy
                       as for other "simple" types.
            */

            wxString argstr;
            wxXmlNode *arg = child->GetChildren();
            while (arg)
            {
                if (arg->GetName() == "Argument")
                    argstr += arg->GetAttribute("type") + ", ";
                arg = arg->GetNext();
            }

            if (argstr.Len() > 0)
                argstr = argstr.Left(argstr.Len()-2);       // remove final comma

            // these nodes make reference to other types... we'll resolve them later
            //toResolveTypes[id] = toResolveTypeItem(ret, 0);
            //types[id] = child->GetAttribute("returns") + "(" + argstr + ")";

            types[id] = "TOFIX";   // typically this type will be "fixed" thanks
                                   // to a typedef later...
        }
        else if (n == "File")
        {
            if (!child->GetAttribute("id").StartsWith("f")) {
                wxLogError("Unexpected file ID: %s", child->GetAttribute("id"));
                return false;
            }

            // just ignore this node... all file IDs/names were already parsed
            files[id] = child->GetAttribute("name");
        }
        else
        {
            // we register everything else as a possible return/argument type:
            const wxString& name = child->GetAttribute("name");

            if (!name.IsEmpty())
            {
                //typeIds.Add(id);
                //typeNames.Add(name);
                types[id] = name;
            }
            else
            {
                // this may happen with unnamed structs/union, special ctors,
                // or other exotic things which we are not interested to, since
                // they're never used as return/argument types by wxWidgets methods

                if (g_verbose)
                {
                    wxLogWarning("Type node '%s' with ID '%s' does not have name attribute",
                               n, child->GetAttribute("id"));
                }

                types[id] = "TOFIX";
            }
        }

        child = child->GetNext();

        // give feedback to the user about the progress...
        if ((++nodes%PROGRESS_RATE)==0) ShowProgress();
    }

    // some nodes with IDs referenced by methods as return/argument types, do reference
    // in turn other nodes (see PointerType, ReferenceType and CvQualifierType above);
    // thus we need to resolve their name iteratively:
    while (toResolveTypes.size()>0)
    {
        if (g_verbose)
        {
            wxLogMessage("%d types were collected; %d types need yet to be resolved...",
                       types.size(), toResolveTypes.size());
        }

        for (wxToResolveTypeHashMap::iterator i = toResolveTypes.begin();
             i != toResolveTypes.end();)
        {
            unsigned long id = i->first;
            unsigned long referenced = i->second.ref;

            wxTypeIdHashMap::iterator primary = types.find(referenced);
            if (primary != types.end())
            {
                // this to-resolve-type references a "primary" type

                wxString newtype = primary->second;
                int attribs = i->second.attribs;

                // attribs may contain a combination of ATTRIB_* flags:
                if (attribs & ATTRIB_CONST)
                    newtype = "const " + newtype;
                if (attribs & ATTRIB_REFERENCE)
                    newtype = newtype + "&";
                if (attribs & ATTRIB_POINTER)
                    newtype = newtype + "*";
                if (attribs & ATTRIB_ARRAY)
                    newtype = newtype + "[]";

                // add the resolved type to the list of "primary" types
                if (newtype.Contains("TOFIX") && typedefs[id] != "")
                    types[id] = typedefs[id];       // better use a typedef for this type!
                else
                    types[id] = newtype;

                // this one has been resolved; erase it through its iterator!
                toResolveTypes.erase(i);

                // now iterator i is invalid; assign it again to the beginning
                i = toResolveTypes.begin();
            }
            else
            {
                // then search in the referenced types themselves:
                wxToResolveTypeHashMap::iterator idx2 = toResolveTypes.find(referenced);
                if (idx2 != toResolveTypes.end())
                {
                    // merge this to-resolve-type with the idx2->second type
                    i->second.ref = idx2->second.ref;
                    i->second.attribs |= idx2->second.attribs;

                    // this type will eventually be solved in the next while() iteration
                    i++;
                }
                else
                {
                    wxLogError("Cannot solve '%d' reference type!", referenced);
                    return false;
                }
            }
        }
    }

    // resolve header names
    unsigned i;
    for (i=0; i<m_classes.GetCount(); i++)
    {
        unsigned long fileID = 0;
        if (!getID(&fileID, m_classes[i].GetHeader()) || fileID == 0) {
            wxLogError("invalid header id: %s", m_classes[i].GetHeader());
            return false;
        }

        // search this file
        wxTypeIdHashMap::const_iterator idx = files.find(fileID);
        if (idx == files.end())
        {
            // this is an error!
            wxLogError("couldn't find file ID '%s'", m_classes[i].GetHeader());
        }
        else
            m_classes[i].SetHeader(idx->second);
    }

    // resolve parent names
    for (i=0; i<m_classes.GetCount(); i++)
    {
        for (unsigned int k=0; k<m_classes[i].GetParentCount(); k++)
        {
            unsigned long id;

            if (!getID(&id, m_classes[i].GetParent(k))) {
                wxLogError("invalid parent class ID for '%s'", m_classes[i].GetName());
                return false;
            }

            wxTypeIdHashMap::const_iterator idx = types.find(id);
            if (idx == types.end())
            {
                // this is an error!
                wxLogError("couldn't find parent class ID '%d'", id);
            }
            else
                // replace k-th parent with its true name:
                m_classes[i].SetParent(k, idx->second);
        }
    }

    // build the list of the wx methods
    child = doc.GetRoot()->GetChildren();
    while (child)
    {
        wxString n = child->GetName(), acc = child->GetAttribute("access");

        // only register public&protected methods
        if ((acc == "public" || acc == "protected") &&
            (n == "Method" || n == "Constructor" || n == "Destructor" || n == "OperatorMethod"))
        {
            unsigned long id = 0;
            if (!getID(&id, child->GetAttribute("id"))) {
                wxLogError("invalid ID for node '%s' with ID '%s'", n, child->GetAttribute("id"));
                return false;
            }

            wxClassMemberIdHashMap::const_iterator it = members.find(id);
            if (it != members.end())
            {
                wxClass *p = it->second;

                // this <Method> node is a method of the i-th class!
                wxMethod newfunc;
                if (!ParseMethod(child, types, newfunc)) {
                    wxLogError("The method '%s' could not be added to class '%s'",
                             child->GetAttribute("demangled"), p->GetName());
                    return false;
                }

                // do some additional check that we can do only here:

                if (newfunc.IsCtor() && !p->IsValidCtorForThisClass(newfunc)) {
                    wxLogError("The method '%s' does not seem to be a ctor for '%s'",
                             newfunc.GetName(), p->GetName());
                    return false;
                }
                if (newfunc.IsDtor() && !p->IsValidDtorForThisClass(newfunc)) {
                    wxLogError("The method '%s' does not seem to be a dtor for '%s'",
                             newfunc.GetName(), p->GetName());
                    return false;
                }

                p->AddMethod(newfunc);
            }
        }

        child = child->GetNext();

        // give feedback to the user about the progress...
        if ((++nodes%PROGRESS_RATE)==0) ShowProgress();
    }

    if (!CheckConsistency())
        return false;       // the check failed

    return true;
}

bool wxXmlGccInterface::ParseMethod(const wxXmlNode *p,
                                    const wxTypeIdHashMap& types,
                                    wxMethod& m)
{
    // get the real name
    wxString name = p->GetAttribute("name").Strip(wxString::both);
    if (p->GetName() == "Destructor")
        name = "~" + name;
    else if (p->GetName() == "OperatorMethod")
        name = "operator" + name;

    // resolve return type
    wxType ret;
    unsigned long retid = 0;
    if (!getID(&retid, p->GetAttribute("returns")) || retid == 0)
    {
        if (p->GetName() != "Destructor" && p->GetName() != "Constructor") {
            wxLogError("Empty return ID for method '%s', with ID '%s'",
                     name, p->GetAttribute("id"));
            return false;
        }
    }
    else
    {
        wxTypeIdHashMap::const_iterator retidx = types.find(retid);
        if (retidx == types.end()) {
            wxLogError("Could not find return type ID '%s'", retid);
            return false;
        }

        ret = wxType(retidx->second);
        if (!ret.IsOk()) {
            wxLogError("Invalid return type '%s' for method '%s', with ID '%s'",
                     retidx->second, name, p->GetAttribute("id"));
            return false;
        }
    }

    // resolve argument types
    wxArgumentTypeArray argtypes;
    wxXmlNode *arg = p->GetChildren();
    while (arg)
    {
        if (arg->GetName() == "Argument")
        {
            unsigned long id = 0;
            if (!getID(&id, arg->GetAttribute("type")) || id == 0) {
                wxLogError("Invalid argument type ID '%s' for method '%s' with ID %s",
                         arg->GetAttribute("type"), name, p->GetAttribute("id"));
                return false;
            }

            wxTypeIdHashMap::const_iterator idx = types.find(id);
            if (idx == types.end()) {
                wxLogError("Could not find argument type ID '%s'", id);
                return false;
            }

            argtypes.Add(wxArgumentType(idx->second,
                                        arg->GetAttribute("default"),
                                        arg->GetAttribute("name")));
        }

        arg = arg->GetNext();
    }

    m.SetReturnType(ret);
    m.SetName(name);
    m.SetArgumentTypes(argtypes);
    m.SetConst(p->GetAttribute("const") == "1");
    m.SetStatic(p->GetAttribute("static") == "1");

    // NOTE: gccxml is smart enough to mark as virtual those functions
    //       which are declared virtual in base classes but don't have
    //       the "virtual" keyword explicitely indicated in the derived
    //       classes... so we don't need any further logic for virtuals

    m.SetVirtual(p->GetAttribute("virtual") == "1");
    m.SetPureVirtual(p->GetAttribute("pure_virtual") == "1");
    m.SetDeprecated(p->GetAttribute("attributes") == "deprecated");

    // decode access specifier
    if (p->GetAttribute("access") == "public")
        m.SetAccessSpecifier(wxMAS_PUBLIC);
    else if (p->GetAttribute("access") == "protected")
        m.SetAccessSpecifier(wxMAS_PROTECTED);
    else if (p->GetAttribute("access") == "private")
        m.SetAccessSpecifier(wxMAS_PRIVATE);

    if (!m.IsOk()) {
        wxLogError("The prototype '%s' is not valid!", m.GetAsString());
        return false;
    }

    return true;
}



// ----------------------------------------------------------------------------
// wxXmlDoxygenInterface global helpers
// ----------------------------------------------------------------------------

static wxString GetTextFromChildren(const wxXmlNode *n)
{
    wxString text;

    // consider the tree
    //
    //  <a><b>this</b> is a <b>string</b></a>
    //
    // <a>
    // |- <b>
    // |   |- this
    // |- is a
    // |- <b>
    //     |- string
    //
    // unlike wxXmlNode::GetNodeContent() which would return " is a "
    // this function returns "this is a string"

    wxXmlNode *ref = n->GetChildren();
    while (ref) {
        if (ref->GetType() == wxXML_ELEMENT_NODE)
            text += ref->GetNodeContent();
        else if (ref->GetType() == wxXML_TEXT_NODE)
            text += ref->GetContent();
        else
            wxLogWarning("Unexpected node type while getting text from '%s' node", n->GetName());

        ref = ref->GetNext();
    }

    return text;
}

static bool HasTextNodeContaining(const wxXmlNode *parent, const wxString& name)
{
    if (!parent)
        return false;

    wxXmlNode *p = parent->GetChildren();
    while (p)
    {
        switch (p->GetType())
        {
            case wxXML_TEXT_NODE:
                if (p->GetContent() == name)
                    return true;
                break;

            case wxXML_ELEMENT_NODE:
                // recurse into this node...
                if (HasTextNodeContaining(p, name))
                    return true;
                break;

            default:
                // skip it
                break;
        }

        p = p->GetNext();
    }

    return false;
}

static const wxXmlNode* FindNodeNamed(const wxXmlNode* parent, const wxString& name)
{
    if (!parent)
        return NULL;

    const wxXmlNode *p = parent->GetChildren();
    while (p)
    {
        if (p->GetName() == name)
            return p;       // found!

        // search recursively in the children of this node
        const wxXmlNode *ret = FindNodeNamed(p, name);
        if (ret)
            return ret;

        p = p->GetNext();
    }

    return NULL;
}

int GetAvailabilityFor(const wxXmlNode *node)
{
    // identify <onlyfor> custom XML tags
    const wxXmlNode* onlyfor = FindNodeNamed(node, "onlyfor");
    if (!onlyfor)
        return wxPORT_UNKNOWN;

    wxArrayString ports = wxSplit(onlyfor->GetNodeContent(), ',');
    int nAvail = wxPORT_UNKNOWN;
    for (unsigned int i=0; i < ports.GetCount(); i++)
    {
        if (!ports[i].StartsWith("wx")) {
            wxLogError("unexpected port ID '%s'", ports[i]);
            return false;
        }

        nAvail |= wxPlatformInfo::GetPortId(ports[i].Mid(2));
    }

    return nAvail;
}


// ----------------------------------------------------------------------------
// wxXmlDoxygenInterface
// ----------------------------------------------------------------------------

bool wxXmlDoxygenInterface::Parse(const wxString& filename)
{
    wxXmlDocument index;
    wxXmlNode *compound;

    wxLogMessage("Parsing %s...", filename);

    if (!index.Load(filename)) {
        wxLogError("can't load %s", filename);
        return false;
    }

    // start processing the index:
    if (index.GetRoot()->GetName() != "doxygenindex") {
        wxLogError("invalid root node for %s", filename);
        return false;
    }

    /*
        NB: we may need in future to do a version-check here if the
            format of the XML generated by doxygen changes.
            For now (doxygen version 1.5.5), this check is not required
            since AFAIK the XML format never changed since it was introduced.
    */

    m_classes.Alloc(ESTIMATED_NUM_CLASSES);

    // process files referenced by this index file
    compound = index.GetRoot()->GetChildren();
    while (compound)
    {
        if (compound->GetName() == "compound" &&
            compound->GetAttribute("kind") == "class")
        {
            wxString refid = compound->GetAttribute("refid");

            wxFileName fn(filename);
            if (!ParseCompoundDefinition(fn.GetPath(wxPATH_GET_SEPARATOR) + refid + ".xml"))
                return false;
        }

        compound = compound->GetNext();
    }
    //wxPrint("\n");

    if (!CheckConsistency())
        return false;       // the check failed

    return true;
}

bool wxXmlDoxygenInterface::ParseCompoundDefinition(const wxString& filename)
{
    wxClassMemberIdHashMap parents;
    wxXmlDocument doc;
    wxXmlNode *child;
    int nodes = 0;

    if (g_verbose)
    {
        wxLogMessage("Parsing %s...", filename);
    }

    if (!doc.Load(filename)) {
        wxLogError("can't load %s", filename);
        return false;
    }

    // start processing this compound definition XML
    if (doc.GetRoot()->GetName() != "doxygen") {
        wxLogError("invalid root node for %s", filename);
        return false;
    }

    // build a list of wx classes
    child = doc.GetRoot()->GetChildren();
    while (child)
    {
        if (child->GetName() == "compounddef" &&
            child->GetAttribute("kind") == "class")
        {
            // parse this class
            wxClass klass;
            wxString absoluteFile, header;

            wxXmlNode *subchild = child->GetChildren();
            while (subchild)
            {
                // NOTE: when documenting functions using the //@{ and //@}
                //       tags to create function groups, doxygen puts the
                //       contained methods into a "user-defined" section
                //       so we _must_ use the "prot" attribute to distinguish
                //       public/protected methods from private ones and cannot
                //       rely on the kind="public" attribute of <sectiondef>
                if (subchild->GetName() == "sectiondef")
                {
                    wxXmlNode *membernode = subchild->GetChildren();
                    while (membernode)
                    {
                        const wxString& accessSpec = membernode->GetAttribute("prot");

                        // parse only public&protected functions:
                        if (membernode->GetName() == "memberdef" &&
                            membernode->GetAttribute("kind") == "function" &&
                            (accessSpec == "public" || accessSpec == "protected"))
                        {
                            wxMethod m;
                            if (!ParseMethod(membernode, m, header)) {
                                wxLogError("The method '%s' could not be added to class '%s'",
                                           m.GetName(), klass.GetName());
                                return false;
                            }

                            if (accessSpec == "public")
                                m.SetAccessSpecifier(wxMAS_PUBLIC);
                            else if (accessSpec == "protected")
                                m.SetAccessSpecifier(wxMAS_PROTECTED);
                            else if (accessSpec == "private")
                                m.SetAccessSpecifier(wxMAS_PRIVATE);

                            if (absoluteFile.IsEmpty())
                                absoluteFile = header;
                            else if (header != absoluteFile)
                            {
                                wxLogError("Found inconsistency in the XML file '%s': "
                                           "the method '%s' is documented in the "
                                           "file '%s' but the other methods of the same "
                                           "class are documented in the file '%s'",
                                            filename, m.GetName(), header, absoluteFile);
                                return false;
                            }

                            klass.AddMethod(m);
                        }

                        membernode = membernode->GetNext();
                    }

                    // all methods of this class were taken from the header "absoluteFile":
                    klass.SetHeader(absoluteFile);
                }
                else if (subchild->GetName() == "compoundname")
                {
                    klass.SetName(subchild->GetNodeContent());
                }
                /*else if (subchild->GetName() == "includes")
                {
                    // NOTE: we'll get the header from the <location> tags
                    //       scattered inside <memberdef> tags instead of
                    //       this <includes> tag since it does not contain
                    //       the absolute path of the header

                    klass.SetHeader(subchild->GetNodeContent());
                }*/
                else if (subchild->GetName() == "detaileddescription")
                {
                    // identify <onlyfor> custom XML tags
                    klass.SetAvailability(GetAvailabilityFor(subchild));
                }
                else if (subchild->GetName() == "basecompoundref")
                {
                    // add the name of this parent to the list of klass' parents
                    klass.AddParent(subchild->GetNodeContent());
                }

                subchild = subchild->GetNext();
            }

            // add a new class
            if (klass.IsOk())
            {
                m_classes.Add(klass);
            }
            else if (g_verbose)
            {
                wxLogWarning("discarding class '%s' with %d methods...",
                           klass.GetName(), klass.GetMethodCount());
            }
        }

        child = child->GetNext();

        // give feedback to the user about the progress...
        if ((++nodes%PROGRESS_RATE)==0) ShowProgress();
    }

    return true;
}

bool wxXmlDoxygenInterface::ParseMethod(const wxXmlNode* p, wxMethod& m, wxString& header)
{
    wxArgumentTypeArray args;
    long line;

    wxXmlNode *child = p->GetChildren();
    while (child)
    {
        if (child->GetName() == "name")
            m.SetName(child->GetNodeContent());
        else if (child->GetName() == "type")
            m.SetReturnType(wxType(GetTextFromChildren(child)));
        else if (child->GetName() == "param")
        {
            wxString typestr, namestr, defstr, arrstr;
            wxXmlNode *n = child->GetChildren();
            while (n)
            {
                if (n->GetName() == "type")
                    // if the <type> node has children, they should be all TEXT and <ref> nodes
                    // and we need to take the text they contain, in the order they appear
                    typestr = GetTextFromChildren(n);
                else if (n->GetName() == "declname")
                    namestr = GetTextFromChildren(n);
                else if (n->GetName() == "defval")
                    defstr = GetTextFromChildren(n).Strip(wxString::both);
                else if (n->GetName() == "array")
                    arrstr = GetTextFromChildren(n);

                n = n->GetNext();
            }

            if (typestr.IsEmpty()) {
                wxLogError("cannot find type node for a param in method '%s'", m.GetName());
                return false;
            }

            wxArgumentType newarg(typestr + arrstr, defstr, namestr);

            // can we use preprocessor output to transform the default value
            // into the same form which gets processed by wxXmlGccInterface?
            wxStringHashMap::const_iterator it = m_preproc.find(defstr);
            if (it != m_preproc.end())
                newarg.SetDefaultValue(defstr, it->second);

            args.Add(newarg);
        }
        else if (child->GetName() == "location")
        {
            line = -1;
            if (child->GetAttribute("line").ToLong(&line))
                m.SetLocation((int)line);
            header = child->GetAttribute("file");
        }
        else if (child->GetName() == "detaileddescription")
        {
            // when a method has a @deprecated tag inside its description,
            // Doxygen outputs somewhere nested inside <detaileddescription>
            // a <xreftitle>Deprecated</xreftitle> tag.
            m.SetDeprecated(HasTextNodeContaining(child, "Deprecated"));

            // identify <onlyfor> custom XML tags
            m.SetAvailability(GetAvailabilityFor(child));
        }

        child = child->GetNext();
    }

    m.SetArgumentTypes(args);
    m.SetConst(p->GetAttribute("const")=="yes");
    m.SetStatic(p->GetAttribute("static")=="yes");

    // NOTE: Doxygen is smart enough to mark as virtual those functions
    //       which are declared virtual in base classes but don't have
    //       the "virtual" keyword explicitely indicated in the derived
    //       classes... so we don't need any further logic for virtuals

    m.SetVirtual(p->GetAttribute("virt")=="virtual");
    m.SetPureVirtual(p->GetAttribute("virt")=="pure-virtual");

    if (!m.IsOk()) {
        wxLogError("The prototype '%s' is not valid!", m.GetAsString());
        return false;
    }

    return true;
}

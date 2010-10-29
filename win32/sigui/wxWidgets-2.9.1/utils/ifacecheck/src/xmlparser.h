/////////////////////////////////////////////////////////////////////////////
// Name:        xmlparser.h
// Purpose:     Parser of the API/interface XML files
// Author:      Francesco Montorsi
// Created:     2008/03/17
// RCS-ID:      $Id$
// Copyright:   (c) 2008 Francesco Montorsi
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////


#ifndef _XMLPARSER_H_
#define _XMLPARSER_H_

#include <wx/txtstrm.h>
#include <wx/dynarray.h>
#include <wx/xml/xml.h>
#include <wx/platinfo.h>
#include <wx/log.h>


/*
    IMPORTANT
    =========

    Any fix aimed to reduce "false positives" which involves
    references to a specific wxWidgets class is marked in
    ifacecheck sources with the string:

    // ADHOC-FIX:
    // ...fix description...
*/

// NOTE: all messages in this way are printed on the stderr
//#define wxLogWarning   wxLogMessage


// ----------------------------------------------------------------------------
// Represents a type with or without const/static/ qualifier
// and with or without & and * operators
// ----------------------------------------------------------------------------
class wxType
{
public:
    wxType() {}
    wxType(const wxString& type)
        { SetTypeFromString(type); }

    void SetTypeFromString(const wxString& t);
    wxString GetAsString() const
        { return m_strType; }

    // returns this type _without_ any decoration,
    // including the & (which indicates this is a reference),
    // the * (which indicates this is a pointer), etc.
    wxString GetAsCleanString() const
        { return m_strTypeClean; }

    bool IsConst() const
        { return m_strType.Contains("const"); }
    bool IsStatic() const
        { return m_strType.Contains("static"); }
    bool IsPointer() const
        { return m_strType.Contains("*"); }
    bool IsReference() const
        { return m_strType.Contains("&"); }

    bool operator==(const wxType& m) const;
    bool operator!=(const wxType& m) const
        { return !(*this == m); }

    bool IsOk() const;

protected:
    wxString m_strType,
             m_strTypeClean;   // m_strType "cleaned" of its attributes
                               // (only for internal use)
};

extern wxType wxEmptyType;
WX_DECLARE_OBJARRAY(wxType, wxTypeArray);


// ----------------------------------------------------------------------------
// Represents a type used as argument for some wxMethod
// ----------------------------------------------------------------------------
class wxArgumentType : public wxType
{
public:
    wxArgumentType() {}
    wxArgumentType(const wxString& type, const wxString& defVal,
                   const wxString& argName = wxEmptyString)
        { SetTypeFromString(type); SetDefaultValue(defVal); m_strArgName = argName; }

    void SetArgumentName(const wxString& name)
        { m_strArgName=name.Strip(wxString::both); }
    wxString GetArgumentName() const
        { return m_strArgName; }

    void SetDefaultValue(const wxString& defval,
                         const wxString& defvalForCmp = wxEmptyString);
    wxString GetDefaultValue() const
        { return m_strDefaultValue; }

    // returns the default value used for comparisons
    wxString GetDefaultCleanValue() const
        { return m_strDefaultValueForCmp; }

    bool HasDefaultValue() const
        { return !m_strDefaultValue.IsEmpty(); }

    bool operator==(const wxArgumentType& m) const;
    bool operator!=(const wxArgumentType& m) const
        { return !(*this == m); }

protected:
    wxString m_strDefaultValue;

    // this string may differ from m_strDefaultValue if there were
    // preprocessor substitutions or other "replacements" done to
    // avoid false errors.
    wxString m_strDefaultValueForCmp;

    // the argument name
    wxString m_strArgName;
};

extern wxArgumentType wxEmptyArgumentType;
WX_DECLARE_OBJARRAY(wxArgumentType, wxArgumentTypeArray);


enum wxMethodAccessSpecifier
{
    wxMAS_PUBLIC,
    wxMAS_PROTECTED,
    wxMAS_PRIVATE
};

// ----------------------------------------------------------------------------
// Represents a single prototype of a class' member.
// ----------------------------------------------------------------------------
class wxMethod
{
public:
    wxMethod()
        { m_bConst=m_bVirtual=m_bPureVirtual=m_bStatic=m_bDeprecated=false;
          m_nLine=-1; m_nAvailability=wxPORT_UNKNOWN; m_access=wxMAS_PUBLIC; }

    wxMethod(const wxType& rettype, const wxString& name,
             const wxArgumentTypeArray& arguments,
             bool isConst, bool isStatic, bool isVirtual)
        : m_retType(rettype), m_strName(name.Strip(wxString::both)),
          m_bConst(isConst), m_bStatic(isStatic), m_bVirtual(isVirtual)
        { SetArgumentTypes(arguments); m_nLine=-1; }


public:     // getters

    // bWithArgumentNames = output argument names?
    // bCleanDefaultValues = output clean argument default values?
    // bDeprecated = output [deprecated] next to deprecated methods?
    // bAccessSpec = output [public], [protected] or [private] next to method?
    //
    // TODO: convert to readable flags this set of bools
    wxString GetAsString(bool bWithArgumentNames = true,
                         bool bCleanDefaultValues = false,
                         bool bDeprecated = false,
                         bool bAccessSpec = false) const;

    // parser of the prototype:
    // all these functions return strings with spaces stripped
    wxType GetReturnType() const
        { return m_retType; }
    wxString GetName() const
        { return m_strName; }
    const wxArgumentTypeArray& GetArgumentTypes() const
        { return m_args; }
    wxArgumentTypeArray& GetArgumentTypes()
        { return m_args; }
    int GetLocation() const
        { return m_nLine; }
    int GetAvailability() const
        { return m_nAvailability; }
    wxMethodAccessSpecifier GetAccessSpecifier() const
        { return m_access; }

    bool IsConst() const
        { return m_bConst; }
    bool IsStatic() const
        { return m_bStatic; }
    bool IsVirtual() const
        { return m_bVirtual; }
    bool IsPureVirtual() const
        { return m_bPureVirtual; }

    bool IsOk() const;
    bool IsCtor() const
        { return m_retType==wxEmptyType && !m_strName.StartsWith("~"); }
    bool IsDtor() const
        { return m_retType==wxEmptyType && m_strName.StartsWith("~"); }
    bool IsOperator() const
        { return m_strName.StartsWith("operator"); }

    bool IsDeprecated() const
        { return m_bDeprecated; }



public:     // setters

    void SetReturnType(const wxType& t)
        { m_retType=t; }
    void SetName(const wxString& name)
        { m_strName=name; }
    void SetArgumentTypes(const wxArgumentTypeArray& arr)
        { m_args=arr; }
    void SetConst(bool c = true)
        { m_bConst=c; }
    void SetStatic(bool c = true)
        { m_bStatic=c; }
    void SetVirtual(bool c = true)
        { m_bVirtual=c; }
    void SetPureVirtual(bool c = true)
        {
            m_bPureVirtual=c;
            if (c) m_bVirtual=c;        // pure virtual => virtual
        }
    void SetDeprecated(bool c = true)
        { m_bDeprecated=c; }
    void SetLocation(int lineNumber)
        { m_nLine=lineNumber; }
    void SetAvailability(int nAvail)
        { m_nAvailability=nAvail; }
    void SetAccessSpecifier(wxMethodAccessSpecifier spec)
        { m_access=spec; }

public:     // misc

    bool operator==(const wxMethod&) const;
    bool operator!=(const wxMethod& m) const
        { return !(*this == m); }

    // this function works like operator== but tests everything:
    // - method name
    // - return type
    // - argument types
    // except for the method attributes (const,static,virtual,pureVirtual,deprecated)
    bool MatchesExceptForAttributes(const wxMethod& m) const;

    // returns true if this is a ctor which has default values for all its
    // argument, thus is able to act also as default ctor
    bool ActsAsDefaultCtor() const;

    // dumps the contents of this class in the given stream
    void Dump(wxTextOutputStream& stream) const;

protected:
    wxType m_retType;
    wxString m_strName;
    wxArgumentTypeArray m_args;

    // misc attributes:
    bool m_bConst;
    bool m_bStatic;
    bool m_bVirtual;
    bool m_bPureVirtual;
    bool m_bDeprecated;

    // m_nLine can be -1 if no location infos are available
    int m_nLine;

    // this is a combination of wxPORT_* flags (see wxPortId) or wxPORT_UNKNOWN
    // if this method should be available for all wxWidgets ports.
    // NOTE: this is not used for comparing wxMethod objects
    //       (gccXML never gives this kind of info).
    int m_nAvailability;

    // the access specifier for this method
    wxMethodAccessSpecifier m_access;
};

WX_DECLARE_OBJARRAY(wxMethod, wxMethodArray);
WX_DEFINE_ARRAY(const wxMethod*, wxMethodPtrArray);


// we need wxClassPtrArray to be defined _before_ wxClass itself,
// since wxClass uses wxClassPtrArray.
class wxClass;
WX_DEFINE_ARRAY(const wxClass*, wxClassPtrArray);

class wxXmlInterface;


// ----------------------------------------------------------------------------
// Represents a class of the wx API/interface.
// ----------------------------------------------------------------------------
class wxClass
{
public:
    wxClass() {}
    wxClass(const wxString& name, const wxString& headername)
        : m_strName(name), m_strHeader(headername) {}


public:     // setters

    void SetHeader(const wxString& header)
        { m_strHeader=header; }
    void SetName(const wxString& name)
        { m_strName=name; }
    void SetAvailability(int nAvail)
        { m_nAvailability=nAvail; }
    void SetParent(unsigned int k, const wxString& name)
        { m_parents[k]=name; }

public:     // getters

    bool IsOk() const
        { return !m_strName.IsEmpty() && !m_methods.IsEmpty(); }

    bool IsValidCtorForThisClass(const wxMethod& m) const;
    bool IsValidDtorForThisClass(const wxMethod& m) const;

    wxString GetName() const
        { return m_strName; }
    wxString GetHeader() const
        { return m_strHeader; }
    wxString GetNameWithoutTemplate() const;

    unsigned int GetMethodCount() const
        { return m_methods.GetCount(); }
    wxMethod& GetMethod(unsigned int n) const
        { return m_methods[n]; }
    wxMethod& GetLastMethod() const
        { return m_methods.Last(); }

    int GetAvailability() const
        { return m_nAvailability; }

    //const wxClass *GetParent(unsigned int i) const
    const wxString& GetParent(unsigned int i) const
        { return m_parents[i]; }
    unsigned int GetParentCount() const
        { return m_parents.GetCount(); }

public:     // misc

    void AddMethod(const wxMethod& func)
        { m_methods.Add(func); }

    void AddParent(const wxString& parent)//wxClass* parent)
        { m_parents.Add(parent); }

    // returns a single result (the first, which is also the only
    // one if CheckConsistency() return true)
    const wxMethod* FindMethod(const wxMethod& m) const;

    // like FindMethod() but this one searches also recursively in
    // the parents of this class.
    const wxMethod* RecursiveUpwardFindMethod(const wxMethod& m,
                                              const wxXmlInterface* allclasses) const;

    // returns an array of pointers to the overloaded methods with the
    // same given name
    wxMethodPtrArray FindMethodsNamed(const wxString& name) const;

    // like FindMethodsNamed() but this one searches also recursively in
    // the parents of this class.
    wxMethodPtrArray RecursiveUpwardFindMethodsNamed(const wxString& name,
                                                     const wxXmlInterface* allclasses) const;

    // dumps all methods to the given output stream
    void Dump(wxTextOutputStream& stream) const;

    // slow check
    bool CheckConsistency() const;

protected:
    wxString m_strName;
    wxString m_strHeader;
    wxMethodArray m_methods;

    // name of the base classes: we store the names and not the pointers
    // because this makes _much_ easier the parsing process!
    // (basically because when parsing class X which derives from Y,
    //  we may have not parsed yet class Y!)
    wxArrayString m_parents;

    // see the wxMethod::m_nAvailability field for more info
    int m_nAvailability;
};

WX_DECLARE_OBJARRAY(wxClass, wxClassArray);



// ----------------------------------------------------------------------------
// wxXmlInterface
// ----------------------------------------------------------------------------
class wxXmlInterface
{
public:
    wxXmlInterface() {}

    const wxClass* FindClass(const wxString& classname) const
        {
            for (unsigned int i=0; i<m_classes.GetCount(); i++)
                if (m_classes[i].GetName() == classname)
                    return &m_classes[i];
            return NULL;
        }

    void Dump(const wxString& filename);

    const wxClassArray& GetClasses() const
        { return m_classes; }

    unsigned int GetClassesCount() const
        { return m_classes.GetCount(); }

    unsigned int GetMethodCount() const
        {
            unsigned int methods = 0;
            for (unsigned i=0; i < m_classes.GetCount(); i++)
                methods += m_classes[i].GetMethodCount();
            return methods;
        }

    // pass a full-path header filename:
    wxClassPtrArray FindClassesDefinedIn(const wxString& headerfile) const;

    void ShowProgress()
        { /*wxFprintf(stderr, ".");*/ }

    // is this interface coherent?
    bool CheckConsistency() const;

protected:
    wxClassArray m_classes;
};

#if 1
// for wxTypeIdHashMap, keys == gccxml IDs  and  values == associated type strings
// e.g. key = "0x123f" and value = "const wxAboutDialogInfo&"
WX_DECLARE_HASH_MAP( unsigned long, wxString,
                     wxIntegerHash, wxIntegerEqual,
                     wxTypeIdHashMap );

WX_DECLARE_STRING_HASH_MAP( wxString, wxStringHashMap );
#else
#include <map>
typedef std::basic_string<char> stlString;
typedef std::map<unsigned long, stlString> wxTypeIdHashMap;
#endif


// ----------------------------------------------------------------------------
// Represents the real interface of wxWidgets
// Loads it from the XML produced by gccXML: http://www.gccxml.org
// ----------------------------------------------------------------------------
class wxXmlGccInterface : public wxXmlInterface
{
public:
    wxXmlGccInterface()
    {
        // FIXME: we should retrieve this from the XML file!
        //        here we suppose the XML was created for the currently-running port
        m_portId = wxPlatformInfo::Get().GetPortId();
    }

    bool Parse(const wxString& filename);
    bool ParseMethod(const wxXmlNode *p,
                     const wxTypeIdHashMap& types,
                     wxMethod& m);

    wxPortId GetInterfacePort() const
        { return m_portId; }

    wxString GetInterfacePortName() const
        { return wxPlatformInfo::GetPortIdName(m_portId, false); }

protected:
    // the port for which the gcc XML was generated
    wxPortId m_portId;
};


// ----------------------------------------------------------------------------
// Represents the interface of the doxygen headers of wxWidgets
// Loads it from the XML produced by Doxygen: http://www.doxygen.org
// ----------------------------------------------------------------------------
class wxXmlDoxygenInterface : public wxXmlInterface
{
public:
    wxXmlDoxygenInterface() {}

    // !!SPEEDUP-TODO!!
    // Using wxXmlDocument::Load as is, the entire XML file is parsed
    // and an entire tree of wxXmlNodes is built in memory.
    // We need however only small portions of the Doxygen-generated XML: to speedup the
    // processing we could detach the expat callbacks when we detect the beginning of a
    // node we're not interested about, or just don't create a wxXmlNode for it!
    // This needs a modification of wxXml API.

    bool Parse(const wxString& filename);
    bool ParseCompoundDefinition(const wxString& filename);
    bool ParseMethod(const wxXmlNode*, wxMethod&, wxString& header);

    // this class can take advantage of the preprocessor output to give
    // a minor number of false positive warnings in the final comparison
    void AddPreprocessorValue(const wxString& name, const wxString& val)
        { m_preproc[name]=val; }

protected:
    wxStringHashMap m_preproc;
};



#endif      // _XMLPARSER_H_


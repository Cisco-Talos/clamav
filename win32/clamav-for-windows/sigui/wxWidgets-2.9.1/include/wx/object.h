/////////////////////////////////////////////////////////////////////////////
// Name:        wx/object.h
// Purpose:     wxObject class, plus run-time type information macros
// Author:      Julian Smart
// Modified by: Ron Lee
// Created:     01/02/97
// RCS-ID:      $Id$
// Copyright:   (c) 1997 Julian Smart
//              (c) 2001 Ron Lee <ron@debian.org>
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#ifndef _WX_OBJECTH__
#define _WX_OBJECTH__

// ----------------------------------------------------------------------------
// headers
// ----------------------------------------------------------------------------

#include "wx/memory.h"

class WXDLLIMPEXP_FWD_BASE wxObject;
class WXDLLIMPEXP_FWD_BASE wxString;

#ifndef wxUSE_EXTENDED_RTTI
#define wxUSE_EXTENDED_RTTI 0
#endif

#define wxDECLARE_CLASS_INFO_ITERATORS()                                     \
    class WXDLLIMPEXP_BASE const_iterator                                    \
    {                                                                        \
        typedef wxHashTable_Node Node;                                       \
    public:                                                                  \
        typedef const wxClassInfo* value_type;                               \
        typedef const value_type& const_reference;                           \
        typedef const_iterator itor;                                         \
        typedef value_type* ptr_type;                                        \
                                                                             \
        Node* m_node;                                                        \
        wxHashTable* m_table;                                                \
    public:                                                                  \
        typedef const_reference reference_type;                              \
        typedef ptr_type pointer_type;                                       \
                                                                             \
        const_iterator(Node* node, wxHashTable* table)                       \
            : m_node(node), m_table(table) { }                               \
        const_iterator() : m_node(NULL), m_table(NULL) { }                   \
        value_type operator*() const;                                        \
        itor& operator++();                                                  \
        const itor operator++(int);                                          \
        bool operator!=(const itor& it) const                                \
            { return it.m_node != m_node; }                                  \
        bool operator==(const itor& it) const                                \
            { return it.m_node == m_node; }                                  \
    };                                                                       \
                                                                             \
    static const_iterator begin_classinfo();                                 \
    static const_iterator end_classinfo()

#if wxUSE_EXTENDED_RTTI
#include "wx/xti.h"
#else

// ----------------------------------------------------------------------------
// conditional compilation
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_FWD_BASE wxClassInfo;
class WXDLLIMPEXP_FWD_BASE wxHashTable;
class WXDLLIMPEXP_FWD_BASE wxObject;
class WXDLLIMPEXP_FWD_BASE wxPluginLibrary;
class WXDLLIMPEXP_FWD_BASE wxHashTable_Node;

// ----------------------------------------------------------------------------
// wxClassInfo
// ----------------------------------------------------------------------------

typedef wxObject *(*wxObjectConstructorFn)(void);

class WXDLLIMPEXP_BASE wxClassInfo
{
    friend class WXDLLIMPEXP_FWD_BASE wxObject;
    friend WXDLLIMPEXP_BASE wxObject *wxCreateDynamicObject(const wxString& name);
public:
    wxClassInfo( const wxChar *className,
                 const wxClassInfo *baseInfo1,
                 const wxClassInfo *baseInfo2,
                 int size,
                 wxObjectConstructorFn ctor )
        : m_className(className)
        , m_objectSize(size)
        , m_objectConstructor(ctor)
        , m_baseInfo1(baseInfo1)
        , m_baseInfo2(baseInfo2)
        , m_next(sm_first)
        {
            sm_first = this;
            Register();
        }

    ~wxClassInfo();

    wxObject *CreateObject() const
        { return m_objectConstructor ? (*m_objectConstructor)() : 0; }
    bool IsDynamic() const { return (NULL != m_objectConstructor); }

    const wxChar       *GetClassName() const { return m_className; }
    const wxChar       *GetBaseClassName1() const
        { return m_baseInfo1 ? m_baseInfo1->GetClassName() : NULL; }
    const wxChar       *GetBaseClassName2() const
        { return m_baseInfo2 ? m_baseInfo2->GetClassName() : NULL; }
    const wxClassInfo  *GetBaseClass1() const { return m_baseInfo1; }
    const wxClassInfo  *GetBaseClass2() const { return m_baseInfo2; }
    int                 GetSize() const { return m_objectSize; }

    wxObjectConstructorFn      GetConstructor() const
        { return m_objectConstructor; }
    static const wxClassInfo  *GetFirst() { return sm_first; }
    const wxClassInfo         *GetNext() const { return m_next; }
    static wxClassInfo        *FindClass(const wxString& className);

        // Climb upwards through inheritance hierarchy.
        // Dual inheritance is catered for.

    bool IsKindOf(const wxClassInfo *info) const
    {
        return info != 0 &&
               ( info == this ||
                 ( m_baseInfo1 && m_baseInfo1->IsKindOf(info) ) ||
                 ( m_baseInfo2 && m_baseInfo2->IsKindOf(info) ) );
    }

    wxDECLARE_CLASS_INFO_ITERATORS();
    
private:
    const wxChar            *m_className;
    int                      m_objectSize;
    wxObjectConstructorFn    m_objectConstructor;

        // Pointers to base wxClassInfos

    const wxClassInfo       *m_baseInfo1;
    const wxClassInfo       *m_baseInfo2;

        // class info object live in a linked list:
        // pointers to its head and the next element in it

    static wxClassInfo      *sm_first;
    wxClassInfo             *m_next;

    static wxHashTable      *sm_classTable;

protected:
    // registers the class
    void Register();
    void Unregister();

    wxDECLARE_NO_COPY_CLASS(wxClassInfo);
};

WXDLLIMPEXP_BASE wxObject *wxCreateDynamicObject(const wxString& name);

// ----------------------------------------------------------------------------
// Dynamic class macros
// ----------------------------------------------------------------------------

#define wxDECLARE_ABSTRACT_CLASS(name)                                        \
    public:                                                                   \
        static wxClassInfo ms_classInfo;                                      \
        virtual wxClassInfo *GetClassInfo() const

#define wxDECLARE_DYNAMIC_CLASS_NO_ASSIGN(name)                               \
    wxDECLARE_NO_ASSIGN_CLASS(name);                                          \
    wxDECLARE_DYNAMIC_CLASS(name)

#define wxDECLARE_DYNAMIC_CLASS_NO_COPY(name)                                 \
    wxDECLARE_NO_COPY_CLASS(name);                                            \
    wxDECLARE_DYNAMIC_CLASS(name)

#define wxDECLARE_DYNAMIC_CLASS(name)                                         \
    wxDECLARE_ABSTRACT_CLASS(name);                                           \
    static wxObject* wxCreateObject()

#define wxDECLARE_CLASS(name)                                                 \
    wxDECLARE_DYNAMIC_CLASS(name)


// common part of the macros below
#define wxIMPLEMENT_CLASS_COMMON(name, basename, baseclsinfo2, func)          \
    wxClassInfo name::ms_classInfo(wxT(#name),                                \
            &basename::ms_classInfo,                                          \
            baseclsinfo2,                                                     \
            (int) sizeof(name),                                               \
            func);                                                            \
                                                                              \
    wxClassInfo *name::GetClassInfo() const                                   \
        { return &name::ms_classInfo; }

#define wxIMPLEMENT_CLASS_COMMON1(name, basename, func)                       \
    wxIMPLEMENT_CLASS_COMMON(name, basename, NULL, func)

#define wxIMPLEMENT_CLASS_COMMON2(name, basename1, basename2, func)           \
    wxIMPLEMENT_CLASS_COMMON(name, basename1, &basename2::ms_classInfo, func)

// -----------------------------------
// for concrete classes
// -----------------------------------

    // Single inheritance with one base class
#define wxIMPLEMENT_DYNAMIC_CLASS(name, basename)                             \
    wxIMPLEMENT_CLASS_COMMON1(name, basename, name::wxCreateObject)           \
    wxObject* name::wxCreateObject()                                          \
        { return new name; }

    // Multiple inheritance with two base classes
#define wxIMPLEMENT_DYNAMIC_CLASS2(name, basename1, basename2)                \
    wxIMPLEMENT_CLASS_COMMON2(name, basename1, basename2,                     \
                              name::wxCreateObject)                           \
    wxObject* name::wxCreateObject()                                          \
        { return new name; }

// -----------------------------------
// for abstract classes
// -----------------------------------

    // Single inheritance with one base class
#define wxIMPLEMENT_ABSTRACT_CLASS(name, basename)                            \
    wxIMPLEMENT_CLASS_COMMON1(name, basename, NULL)

    // Multiple inheritance with two base classes
#define wxIMPLEMENT_ABSTRACT_CLASS2(name, basename1, basename2)               \
    wxIMPLEMENT_CLASS_COMMON2(name, basename1, basename2, NULL)

#define wxIMPLEMENT_CLASS(name, basename)                                     \
    wxIMPLEMENT_ABSTRACT_CLASS(name, basename)
    
#define wxIMPLEMENT_CLASS2(name, basename1, basename2)                        \
    IMPLEMENT_ABSTRACT_CLASS2(name, basename1, basename2)

#endif // !wxUSE_EXTENDED_RTTI


// -----------------------------------
// for pluggable classes
// -----------------------------------

    // NOTE: this should probably be the very first statement
    //       in the class declaration so wxPluginSentinel is
    //       the first member initialised and the last destroyed.

// _DECLARE_DL_SENTINEL(name) wxPluginSentinel m_pluginsentinel;

#if wxUSE_NESTED_CLASSES

#define _DECLARE_DL_SENTINEL(name, exportdecl)  \
class exportdecl name##PluginSentinel {         \
private:                                        \
    static const wxString sm_className;         \
public:                                         \
    name##PluginSentinel();                     \
    ~name##PluginSentinel();                    \
};                                              \
name##PluginSentinel  m_pluginsentinel

#define _IMPLEMENT_DL_SENTINEL(name)                                \
 const wxString name::name##PluginSentinel::sm_className(#name);    \
 name::name##PluginSentinel::name##PluginSentinel() {               \
    wxPluginLibrary *e = (wxPluginLibrary*) wxPluginLibrary::ms_classes.Get(#name);   \
    if( e != 0 ) { e->RefObj(); }                                      \
 }                                                                  \
 name::name##PluginSentinel::~name##PluginSentinel() {            \
    wxPluginLibrary *e = (wxPluginLibrary*) wxPluginLibrary::ms_classes.Get(#name);   \
    if( e != 0 ) { e->UnrefObj(); }                                 \
 }
#else

#define _DECLARE_DL_SENTINEL(name)
#define _IMPLEMENT_DL_SENTINEL(name)

#endif  // wxUSE_NESTED_CLASSES

#define wxDECLARE_PLUGGABLE_CLASS(name) \
 wxDECLARE_DYNAMIC_CLASS(name); _DECLARE_DL_SENTINEL(name, WXDLLIMPEXP_CORE)
#define wxDECLARE_ABSTRACT_PLUGGABLE_CLASS(name)  \
 wxDECLARE_ABSTRACT_CLASS(name); _DECLARE_DL_SENTINEL(name, WXDLLIMPEXP_CORE)

#define wxDECLARE_USER_EXPORTED_PLUGGABLE_CLASS(name, usergoo) \
 wxDECLARE_DYNAMIC_CLASS(name); _DECLARE_DL_SENTINEL(name, usergoo)
#define wxDECLARE_USER_EXPORTED_ABSTRACT_PLUGGABLE_CLASS(name, usergoo)  \
 wxDECLARE_ABSTRACT_CLASS(name); _DECLARE_DL_SENTINEL(name, usergoo)

#define wxIMPLEMENT_PLUGGABLE_CLASS(name, basename) \
 wxIMPLEMENT_DYNAMIC_CLASS(name, basename) _IMPLEMENT_DL_SENTINEL(name)
#define wxIMPLEMENT_PLUGGABLE_CLASS2(name, basename1, basename2)  \
 wxIMPLEMENT_DYNAMIC_CLASS2(name, basename1, basename2) _IMPLEMENT_DL_SENTINEL(name)
#define wxIMPLEMENT_ABSTRACT_PLUGGABLE_CLASS(name, basename) \
 wxIMPLEMENT_ABSTRACT_CLASS(name, basename) _IMPLEMENT_DL_SENTINEL(name)
#define wxIMPLEMENT_ABSTRACT_PLUGGABLE_CLASS2(name, basename1, basename2)  \
 wxIMPLEMENT_ABSTRACT_CLASS2(name, basename1, basename2) _IMPLEMENT_DL_SENTINEL(name)

#define wxIMPLEMENT_USER_EXPORTED_PLUGGABLE_CLASS(name, basename) \
 wxIMPLEMENT_PLUGGABLE_CLASS(name, basename)
#define wxIMPLEMENT_USER_EXPORTED_PLUGGABLE_CLASS2(name, basename1, basename2)  \
 wxIMPLEMENT_PLUGGABLE_CLASS2(name, basename1, basename2)
#define wxIMPLEMENT_USER_EXPORTED_ABSTRACT_PLUGGABLE_CLASS(name, basename) \
 wxIMPLEMENT_ABSTRACT_PLUGGABLE_CLASS(name, basename)
#define wxIMPLEMENT_USER_EXPORTED_ABSTRACT_PLUGGABLE_CLASS2(name, basename1, basename2)  \
 wxIMPLEMENT_ABSTRACT_PLUGGABLE_CLASS2(name, basename1, basename2)

#define wxCLASSINFO(name) (&name::ms_classInfo)

#define wxIS_KIND_OF(obj, className) obj->IsKindOf(&className::ms_classInfo)

// Just seems a bit nicer-looking (pretend it's not a macro)
#define wxIsKindOf(obj, className) obj->IsKindOf(&className::ms_classInfo)

// this cast does some more checks at compile time as it uses static_cast
// internally
//
// note that it still has different semantics from dynamic_cast<> and so can't
// be replaced by it as long as there are any compilers not supporting it
#define wxDynamicCast(obj, className) \
    ((className *) wxCheckDynamicCast( \
        const_cast<wxObject *>(static_cast<const wxObject *>(\
          const_cast<className *>(static_cast<const className *>(obj)))), \
        &className::ms_classInfo))

// The 'this' pointer is always true, so use this version
// to cast the this pointer and avoid compiler warnings.
#define wxDynamicCastThis(className) \
     (IsKindOf(&className::ms_classInfo) ? (className *)(this) : (className *)0)

// FIXME-VC6: dummy argument needed because VC6 doesn't support explicitly
//            choosing the template function to call
template <class T>
inline T *wxCheckCast(const void *ptr, T * = NULL)
{
    wxASSERT_MSG( wxDynamicCast(ptr, T), "wxStaticCast() used incorrectly" );
    return const_cast<T *>(static_cast<const T *>(ptr));
}

#define wxStaticCast(obj, className) wxCheckCast((obj), (className *)NULL)

// ----------------------------------------------------------------------------
// set up memory debugging macros
// ----------------------------------------------------------------------------

/*
    Which new/delete operator variants do we want?

    _WX_WANT_NEW_SIZET_WXCHAR_INT             = void *operator new (size_t size, wxChar *fileName = 0, int lineNum = 0)
    _WX_WANT_DELETE_VOID                      = void operator delete (void * buf)
    _WX_WANT_DELETE_VOID_CONSTCHAR_SIZET      = void operator delete (void *buf, const char *_fname, size_t _line)
    _WX_WANT_DELETE_VOID_WXCHAR_INT           = void operator delete(void *buf, wxChar*, int)
    _WX_WANT_ARRAY_NEW_SIZET_WXCHAR_INT       = void *operator new[] (size_t size, wxChar *fileName , int lineNum = 0)
    _WX_WANT_ARRAY_DELETE_VOID                = void operator delete[] (void *buf)
    _WX_WANT_ARRAY_DELETE_VOID_WXCHAR_INT     = void operator delete[] (void* buf, wxChar*, int )
*/

#if wxUSE_MEMORY_TRACING

// All compilers get this one
#define _WX_WANT_NEW_SIZET_WXCHAR_INT

// Everyone except Visage gets the next one
#ifndef __VISAGECPP__
    #define _WX_WANT_DELETE_VOID
#endif

// Only visage gets this one under the correct circumstances
#if defined(__VISAGECPP__) && __DEBUG_ALLOC__
    #define _WX_WANT_DELETE_VOID_CONSTCHAR_SIZET
#endif

// Only VC++ 6 and CodeWarrior get overloaded delete that matches new
#if (defined(__VISUALC__) && (__VISUALC__ >= 1200)) || \
        (defined(__MWERKS__) && (__MWERKS__ >= 0x2400))
    #define _WX_WANT_DELETE_VOID_WXCHAR_INT
#endif

// Now see who (if anyone) gets the array memory operators
#if wxUSE_ARRAY_MEMORY_OPERATORS

    // Everyone except Visual C++ (cause problems for VC++ - crashes)
    #if !defined(__VISUALC__)
        #define _WX_WANT_ARRAY_NEW_SIZET_WXCHAR_INT
    #endif

    // Everyone except Visual C++ (cause problems for VC++ - crashes)
    #if !defined(__VISUALC__)
        #define _WX_WANT_ARRAY_DELETE_VOID
    #endif

    // Only CodeWarrior 6 or higher
    #if defined(__MWERKS__) && (__MWERKS__ >= 0x2400)
        #define _WX_WANT_ARRAY_DELETE_VOID_WXCHAR_INT
    #endif

#endif // wxUSE_ARRAY_MEMORY_OPERATORS

#endif // wxUSE_MEMORY_TRACING

// ----------------------------------------------------------------------------
// wxRefCounter: ref counted data "manager"
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_BASE wxRefCounter
{
public:
    wxRefCounter() { m_count = 1; }

    int GetRefCount() const { return m_count; }

    void IncRef() { m_count++; }
    void DecRef();

protected:
    // this object should never be destroyed directly but only as a
    // result of a DecRef() call:
    virtual ~wxRefCounter() { }

private:
    // our refcount:
    int m_count;
};

// ----------------------------------------------------------------------------
// wxObjectRefData: ref counted data meant to be stored in wxObject
// ----------------------------------------------------------------------------

typedef wxRefCounter wxObjectRefData;


// ----------------------------------------------------------------------------
// wxObjectDataPtr: helper class to avoid memleaks because of missing calls
//                  to wxObjectRefData::DecRef
// ----------------------------------------------------------------------------

template <class T>
class wxObjectDataPtr
{
public:
    typedef T element_type;

    wxEXPLICIT wxObjectDataPtr(T *ptr = NULL) : m_ptr(ptr) {}

    // copy ctor
    wxObjectDataPtr(const wxObjectDataPtr<T> &tocopy)
        : m_ptr(tocopy.m_ptr)
    {
        if (m_ptr)
            m_ptr->IncRef();
    }

    ~wxObjectDataPtr()
    {
        if (m_ptr)
            m_ptr->DecRef();
    }

    T *get() const { return m_ptr; }

    // test for pointer validity: defining conversion to unspecified_bool_type
    // and not more obvious bool to avoid implicit conversions to integer types
    typedef T *(wxObjectDataPtr<T>::*unspecified_bool_type)() const;
    operator unspecified_bool_type() const
    {
        return m_ptr ? &wxObjectDataPtr<T>::get : NULL;
    }

    T& operator*() const
    {
        wxASSERT(m_ptr != NULL);
        return *(m_ptr);
    }

    T *operator->() const
    {
        wxASSERT(m_ptr != NULL);
        return get();
    }

    void reset(T *ptr)
    {
        if (m_ptr)
            m_ptr->DecRef();
        m_ptr = ptr;
    }

    wxObjectDataPtr& operator=(const wxObjectDataPtr &tocopy)
    {
        if (m_ptr)
            m_ptr->DecRef();
        m_ptr = tocopy.m_ptr;
        if (m_ptr)
            m_ptr->IncRef();
        return *this;
    }

    wxObjectDataPtr& operator=(T *ptr)
    {
        if (m_ptr)
            m_ptr->DecRef();
        m_ptr = ptr;
        return *this;
    }

private:
    T *m_ptr;
};

// ----------------------------------------------------------------------------
// wxObject: the root class of wxWidgets object hierarchy
// ----------------------------------------------------------------------------

class WXDLLIMPEXP_BASE wxObject
{
    wxDECLARE_ABSTRACT_CLASS(wxObject);

public:
    wxObject() { m_refData = NULL; }
    virtual ~wxObject() { UnRef(); }

    wxObject(const wxObject& other)
    {
         m_refData = other.m_refData;
         if (m_refData)
             m_refData->IncRef();
    }

    wxObject& operator=(const wxObject& other)
    {
        if ( this != &other )
        {
            Ref(other);
        }
        return *this;
    }

    bool IsKindOf(const wxClassInfo *info) const;


    // Turn on the correct set of new and delete operators

#ifdef _WX_WANT_NEW_SIZET_WXCHAR_INT
    void *operator new ( size_t size, const wxChar *fileName = NULL, int lineNum = 0 );
#endif

#ifdef _WX_WANT_DELETE_VOID
    void operator delete ( void * buf );
#endif

#ifdef _WX_WANT_DELETE_VOID_CONSTCHAR_SIZET
    void operator delete ( void *buf, const char *_fname, size_t _line );
#endif

#ifdef _WX_WANT_DELETE_VOID_WXCHAR_INT
    void operator delete ( void *buf, const wxChar*, int );
#endif

#ifdef _WX_WANT_ARRAY_NEW_SIZET_WXCHAR_INT
    void *operator new[] ( size_t size, const wxChar *fileName = NULL, int lineNum = 0 );
#endif

#ifdef _WX_WANT_ARRAY_DELETE_VOID
    void operator delete[] ( void *buf );
#endif

#ifdef _WX_WANT_ARRAY_DELETE_VOID_WXCHAR_INT
    void operator delete[] (void* buf, const wxChar*, int );
#endif

    // ref counted data handling methods

    // get/set
    wxObjectRefData *GetRefData() const { return m_refData; }
    void SetRefData(wxObjectRefData *data) { m_refData = data; }

    // make a 'clone' of the object
    void Ref(const wxObject& clone);

    // destroy a reference
    void UnRef();

    // Make sure this object has only one reference
    void UnShare() { AllocExclusive(); }

    // check if this object references the same data as the other one
    bool IsSameAs(const wxObject& o) const { return m_refData == o.m_refData; }

protected:
    // ensure that our data is not shared with anybody else: if we have no
    // data, it is created using CreateRefData() below, if we have shared data
    // it is copied using CloneRefData(), otherwise nothing is done
    void AllocExclusive();

    // both methods must be implemented if AllocExclusive() is used, not pure
    // virtual only because of the backwards compatibility reasons

    // create a new m_refData
    virtual wxObjectRefData *CreateRefData() const;

    // create a new m_refData initialized with the given one
    virtual wxObjectRefData *CloneRefData(const wxObjectRefData *data) const;

    wxObjectRefData *m_refData;
};

inline wxObject *wxCheckDynamicCast(wxObject *obj, wxClassInfo *classInfo)
{
    return obj && obj->GetClassInfo()->IsKindOf(classInfo) ? obj : NULL;
}

#if wxUSE_EXTENDED_RTTI
class WXDLLIMPEXP_BASE wxDynamicObject : public wxObject
{
    friend class WXDLLIMPEXP_FWD_BASE wxDynamicClassInfo ;
public:
    // instantiates this object with an instance of its superclass
    wxDynamicObject(wxObject* superClassInstance, const wxDynamicClassInfo *info) ;
    virtual ~wxDynamicObject();

    void SetProperty (const wxChar *propertyName, const wxxVariant &value);
    wxxVariant GetProperty (const wxChar *propertyName) const ;

    // get the runtime identity of this object
    wxClassInfo *GetClassInfo() const
    {
#ifdef _MSC_VER
        return (wxClassInfo*) m_classInfo;
#else
        wxDynamicClassInfo *nonconst = const_cast<wxDynamicClassInfo *>(m_classInfo);
        return static_cast<wxClassInfo *>(nonconst);
#endif
    }

    wxObject* GetSuperClassInstance() const
    {
        return m_superClassInstance ;
    }
private :
    // removes an existing runtime-property
    void RemoveProperty( const wxChar *propertyName ) ;

    // renames an existing runtime-property
    void RenameProperty( const wxChar *oldPropertyName , const wxChar *newPropertyName ) ;

    wxObject *m_superClassInstance ;
    const wxDynamicClassInfo *m_classInfo;
    struct wxDynamicObjectInternal;
    wxDynamicObjectInternal *m_data;
};
#endif

// ----------------------------------------------------------------------------
// more debugging macros
// ----------------------------------------------------------------------------

#if wxUSE_DEBUG_NEW_ALWAYS
    #define WXDEBUG_NEW new(__TFILE__,__LINE__)

    #if wxUSE_GLOBAL_MEMORY_OPERATORS
        #define new WXDEBUG_NEW
    #elif defined(__VISUALC__)
        // Including this file redefines new and allows leak reports to
        // contain line numbers
        #include "wx/msw/msvcrt.h"
    #endif
#endif // wxUSE_DEBUG_NEW_ALWAYS

// ----------------------------------------------------------------------------
// Compatibility macro aliases
// ----------------------------------------------------------------------------

// deprecated variants _not_ requiring a semicolon after them and without wx prefix.
// (note that also some wx-prefixed macro do _not_ require a semicolon because
//  it's not always possible to force the compire to require it)

#define DECLARE_CLASS_INFO_ITERATORS()                              wxDECLARE_CLASS_INFO_ITERATORS();
#define DECLARE_ABSTRACT_CLASS(n)                                   wxDECLARE_ABSTRACT_CLASS(n);
#define DECLARE_DYNAMIC_CLASS_NO_ASSIGN(n)                          wxDECLARE_DYNAMIC_CLASS_NO_ASSIGN(n);
#define DECLARE_DYNAMIC_CLASS_NO_COPY(n)                            wxDECLARE_DYNAMIC_CLASS_NO_COPY(n);
#define DECLARE_DYNAMIC_CLASS(n)                                    wxDECLARE_DYNAMIC_CLASS(n);
#define DECLARE_CLASS(n)                                            wxDECLARE_CLASS(n);

#define IMPLEMENT_DYNAMIC_CLASS(n,b)                                wxIMPLEMENT_DYNAMIC_CLASS(n,b)
#define IMPLEMENT_DYNAMIC_CLASS2(n,b1,b2)                           wxIMPLEMENT_DYNAMIC_CLASS2(n,b1,b2)
#define IMPLEMENT_ABSTRACT_CLASS(n,b)                               wxIMPLEMENT_ABSTRACT_CLASS(n,b)
#define IMPLEMENT_ABSTRACT_CLASS2(n,b1,b2)                          wxIMPLEMENT_ABSTRACT_CLASS2(n,b1,b2)
#define IMPLEMENT_CLASS(n,b)                                        wxIMPLEMENT_CLASS(n,b)
#define IMPLEMENT_CLASS2(n,b1,b2)                                   wxIMPLEMENT_CLASS2(n,b1,b2)

#define DECLARE_PLUGGABLE_CLASS(n)                                  wxDECLARE_PLUGGABLE_CLASS(n);
#define DECLARE_ABSTRACT_PLUGGABLE_CLASS(n)                         wxDECLARE_ABSTRACT_PLUGGABLE_CLASS(n);
#define DECLARE_USER_EXPORTED_PLUGGABLE_CLASS(n,u)                  wxDECLARE_USER_EXPORTED_PLUGGABLE_CLASS(n,u);
#define DECLARE_USER_EXPORTED_ABSTRACT_PLUGGABLE_CLASS(n,u)         wxDECLARE_USER_EXPORTED_ABSTRACT_PLUGGABLE_CLASS(n,u);

#define IMPLEMENT_PLUGGABLE_CLASS(n,b)                              wxIMPLEMENT_PLUGGABLE_CLASS(n,b)
#define IMPLEMENT_PLUGGABLE_CLASS2(n,b,b2)                          wxIMPLEMENT_PLUGGABLE_CLASS2(n,b,b2)
#define IMPLEMENT_ABSTRACT_PLUGGABLE_CLASS(n,b)                     wxIMPLEMENT_ABSTRACT_PLUGGABLE_CLASS(n,b)
#define IMPLEMENT_ABSTRACT_PLUGGABLE_CLASS2(n,b,b2)                 wxIMPLEMENT_ABSTRACT_PLUGGABLE_CLASS2(n,b,b2)
#define IMPLEMENT_USER_EXPORTED_PLUGGABLE_CLASS(n,b)                wxIMPLEMENT_USER_EXPORTED_PLUGGABLE_CLASS(n,b)
#define IMPLEMENT_USER_EXPORTED_PLUGGABLE_CLASS2(n,b,b2)            wxIMPLEMENT_USER_EXPORTED_PLUGGABLE_CLASS2(n,b,b2)
#define IMPLEMENT_USER_EXPORTED_ABSTRACT_PLUGGABLE_CLASS(n,b)       wxIMPLEMENT_USER_EXPORTED_ABSTRACT_PLUGGABLE_CLASS(n,b)
#define IMPLEMENT_USER_EXPORTED_ABSTRACT_PLUGGABLE_CLASS2(n,b,b2)   wxIMPLEMENT_USER_EXPORTED_ABSTRACT_PLUGGABLE_CLASS2(n,b,b2)

#define CLASSINFO(n)                                wxCLASSINFO(n)

#endif // _WX_OBJECTH__

/////////////////////////////////////////////////////////////////////////////
// Name:        msw/registry.h
// Purpose:     interface of wxRegKey
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxRegKey

    wxRegKey is a class representing the Windows registry (it is only available
    under Windows). One can create, query and delete registry keys using this
    class.

    The Windows registry is easy to understand. There are five registry keys,
    namely:

    @li @c HKEY_CLASSES_ROOT (HKCR)
    @li @c HKEY_CURRENT_USER (HKCU)
    @li @c HKEY_LOCAL_MACHINE (HKLM)
    @li @c HKEY_CURRENT_CONFIG (HKCC)
    @li @c HKEY_USERS (HKU)

    After creating a key, it can hold a value. The values can be:

    @li String Value
    @li Binary Value
    @li DWORD Value
    @li Multi String Value
    @li Expandable String Value

    @onlyfor{wxmsw}

    @b Example:

    @code
    wxRegKey *key = new wxRegKey("HKEY_LOCAL_MACHINE\\Software\\MyKey");

    // Create the key if it does not exist.
    if( !key->Exists() )
        key->Create();

    // Create a new value "MYVALUE" and set it to 12.
    key->SetValue("MYVALUE", 12);

    // Read the value back.
    long value;
    key->QueryValue("MYVALUE", &value);
    wxMessageBox(wxString::Format("%d", value), "Registry Value", wxOK);

    // Get the number of subkeys and enumerate them.
    size_t subkeys;
    key->GetKeyInfo(&subkeys, NULL, NULL, NULL);

    wxString key_name;
    key->GetFirstKey(key_name, 1);
    for(int i = 0; i < subkeys; i++)
    {
        wxMessageBox(key_name, "Subkey Name", wxOK);
        key->GetNextKey(key_name, 1);
    }
    @endcode


    @library{wxbase}
    @category{cfg}
*/
class wxRegKey
{
public:
    /**
        Default constructor, initializes to @c HKEY_CLASSES_ROOT.
    */
    wxRegKey();
    /**
        The constructor to set the full name of the key.
    */
    wxRegKey(const wxString& strKey);
    /**
        The constructor to set the full name of the key using one of the
        standard keys, that is, HKCR, HKCU, HKLM, HKUSR, HKPD, HKCC or HKDD.
    */
    wxRegKey(StdKey keyParent, const wxString& strKey);
    /**
        The constructor to set the full name of the key under a previously created
        parent.
    */
    wxRegKey(const wxRegKey& keyParent, const wxString& strKey);

    /**
        Access modes for wxRegKey.
    */
    enum AccessMode
    {
        Read, ///< Read-only
        Write ///< Read and Write
    };

    /**
        The standard registry key enumerator.
    */
    enum StdKey
    {
    HKCR,  ///< HKEY_CLASSES_ROOT
    HKCU,  ///< HKEY_CURRENT_USER
    HKLM,  ///< HKEY_LOCAL_MACHINE
    HKUSR, ///< HKEY_USERS
    HKPD,  ///< HKEY_PERFORMANCE_DATA (Windows NT and 2K only)
    HKCC,  ///< HKEY_CURRENT_CONFIG
    HKDD,  ///< HKEY_DYN_DATA (Windows 95 and 98 only)
    HKMAX
    };

    /**
        The value type enumerator.
    */
    enum ValueType
    {
    Type_None,                ///< No value type
    Type_String,              ///< Unicode null-terminated string
    Type_Expand_String,       ///< Unicode null-terminated string
                              ///< (with environment variable references)
    Type_Binary,              ///< Free form binary
    Type_Dword,               ///< 32-bit number
    Type_Dword_little_endian, ///< 32-bit number (same as Type_Dword)
    Type_Dword_big_endian,    ///< 32-bit number
    Type_Link,                ///< Symbolic Link (Unicode)
    Type_Multi_String,        ///< Multiple Unicode strings
    Type_Resource_list,       ///< Resource list in the resource map
    Type_Full_resource_descriptor,  ///< Resource list in the hardware description
    Type_Resource_requirements_list ///<
    };

    /**
        Closes the key.
    */
    void Close();

    /**
        Copy the entire contents of the key recursively to another location
        using the name. Returns @true if successful.
    */
    bool Copy(const wxString& szNewName);
    /**
        Copy the entire contents of the key recursively to another location
        using the key. Returns @true if successful.
    */
    bool Copy(wxRegKey& keyDst);

    /**
        Copy the value to another key, possibly changing its name. By default
        it will remain the same. Returns @true if successful.
    */
    bool CopyValue(const wxString& szValue, wxRegKey& keyDst,
                  const wxString& szNewName = wxEmptyString);
    /**
        Creates the key. Will fail if the key already exists and @a bOkIfExists
        is @false. Returns @true if successful.
    */
    bool Create(bool bOkIfExists = true);

    /**
        Deletes the subkey with all its subkeys and values recursively.
    */
    void DeleteKey(const wxString& szKey);

    /**
        Deletes this key and all its subkeys and values recursively.
    */
    void DeleteSelf();

    /**
        Deletes the named value or use an empty string argument to remove the
        default value of the key.
    */
    void DeleteValue(const wxString& szKey);

    /**
        Returns @true if the key exists.
    */
    bool Exists() const;

    /**
        Write the contents of this key and all its subkeys to the given file.
        (The file will not be overwritten; it's an error if it already exists.)
        Note that we export the key in REGEDIT4 format, not RegSaveKey() binary
        format nor the newer REGEDIT5. Returns @true if successful.
    */
    bool Export(const wxString& filename) const;
    /**
        Write the contents of this key and all its subkeys to the opened stream.
        Returns @true if successful.
    */
    bool Export(wxOutputStream& ostr) const;

    /**
        Gets the first key. Returns @true if successful.
    */
    bool GetFirstKey(wxString& strKeyName, long& lIndex);

    /**
        Gets the first value of this key. Returns @true if successful.
    */
    bool GetFirstValue(wxString& strValueName, long& lIndex);

    /**
        Gets information about the key. Returns @true if successful.

        @param pnSubKeys
            The number of subkeys.
        @param pnMaxKeyLen
            The maximum length of the subkey name.
        @param pnValues
            The number of values.
        @param pnMaxValueLen
            The maximum length of a value.
    */
    bool GetKeyInfo(size_t* pnSubKeys, size_t* pnMaxKeyLen,
                    size_t* pnValues, size_t* pnMaxValueLen) const;

    /**
        Gets the name of the registry key.
    */
    wxString GetName(bool bShortPrefix = true) const;

    /**
        Gets the next key. Returns @true if successful.
    */
    bool GetNextKey(wxString& strKeyName, long& lIndex) const;

    /**
        Gets the next key value for this key. Returns @true if successful.
    */
    bool GetNextValue(wxString& strValueName, long& lIndex) const;

    /**
        Gets the value type.
    */
    ValueType GetValueType(const wxString& szValue) const;

    /**
        Returns @true if given subkey exists.
    */
    bool HasSubKey(const wxString& szKey) const;

    /**
        Returns @true if any subkeys exist.
    */
    bool HasSubKeys() const;

    /**
        Returns @true if the value exists.
    */
    bool HasValue(const wxString& szValue) const;

    /**
        Returns @true if any values exist.
    */
    bool HasValues() const;

    /**
        Returns @true if this key is empty, nothing under this key.
    */
    bool IsEmpty() const;

    /**
        Returns @true if the value contains a number.
    */
    bool IsNumericValue(const wxString& szValue) const;

    /**
        Returns @true if the key is opened.
    */
    bool IsOpened() const;

    /**
        Explicitly opens the key. This method also allows the key to be opened
        in read-only mode by passing wxRegKey::Read instead of default
        wxRegKey::Write parameter. Returns @true if successful.
    */
    bool Open(AccessMode mode = Write);

    /**
        Assignment operator to set the default value of the key.
    */
    wxRegKey& operator=(const wxString& strValue);

    /**
        Return the default value of the key.
    */
    wxString QueryDefaultValue() const;

    /**
        Retrieves the raw string value. Returns @true if successful.
        An empty @a szValue queries the default/unnamed key value.
    */
    bool QueryRawValue(const wxString& szValue, wxString& strValue) const;

    /**
        Retrieves the raw or expanded string value. Returns @true if successful.
        An empty @a szValue queries the default/unnamed key value.
    */
    bool QueryValue(const wxString& szValue, wxString& strValue, bool raw) const;

    /**
        Retrieves the numeric value. Returns @true if successful.
        An empty @a szValue queries the default/unnamed key value.
    */
    bool QueryValue(const wxString& szValue, long* plValue) const;

    /**
        Retrieves the binary structure. Returns @true if successful.
        An empty @a szValue queries the default/unnamed key value.
    */
    bool QueryValue(const wxString& szValue, wxMemoryBuffer& buf) const;

    /**
        Renames the key. Returns @true if successful.
    */
    bool Rename(const wxString& szNewName);

    /**
        Renames a value. Returns @true if successful.
    */
    bool RenameValue(const wxString& szValueOld,
                     const wxString& szValueNew);

    /**
        Preallocate some memory for the name. For wxRegConfig usage only.
    */
    void ReserveMemoryForName(size_t bytes);

    /**
        Set or change the HKEY handle.
    */
    void SetHkey(WXHKEY hKey);

    /**
        Set the full key name. The name is absolute. It should start with
        HKEY_xxx.
    */
    void SetName(const wxString& strKey);
    /**
        Set the name relative to the parent key
    */
    void SetName(StdKey keyParent, const wxString& strKey);
    /**
        Set the name relative to the parent key
    */
    void SetName(const wxRegKey& keyParent, const wxString& strKey);

    /**
        Sets the given @a szValue which must be numeric. If the value doesn't
        exist, it is created. Returns @true if successful.
        An empty @a szValue sets the default/unnamed key value.
    */
    bool SetValue(const wxString& szValue, long lValue);
    /**
        Sets the given @a szValue which must be string. If the value doesn't
        exist, it is created. Returns @true if successful.
        An empty @a szValue sets the default/unnamed key value.
    */
    bool SetValue(const wxString& szValue, const wxString& strValue);
    /**
        Sets the given @a szValue which must be binary. If the value doesn't
        exist, it is created. Returns @true if successful.
        An empty @a szValue sets the default/unnamed key value.
    */
    bool SetValue(const wxString& szValue, const wxMemoryBuffer& buf);
};

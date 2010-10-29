/////////////////////////////////////////////////////////////////////////////
// Name:        translation.h
// Purpose:     wxTranslation class
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////


/**
    This class allows to get translations for strings.

    In wxWidgets this class manages message catalogs which contain the
    translations of the strings used to the current language. Unlike wxLocale,
    it isn't bound to locale. It can be used either independently of, or in
    conjunction with wxLocale. In the latter case, you should initialize
    wxLocale (which creates wxTranslations instance) first; in the former, you
    need to create a wxTranslations object and Set() it manually.

    Only one wxTranslations instance is active at a time; it is set with the
    Set() method and obtained using Get().

    Unlike wxLocale, wxTranslations' primary mean of identifying language
    is by its "canonical name", i.e. ISO 639 code, possibly combined with
    ISO 3166 country code and additional modifiers (examples include
    "fr", "en_GB" or "ca@valencia"; see wxLocale::GetCanonicalName() for
    more information). This allows apps using wxTranslations API to use even
    languages not recognized by the operating system or not listed in
    wxLanguage enum.

    @since 2.9.1

    @see wxLocale
 */
class wxTranslations
{
public:
    /// Constructor
    wxTranslations();

    /**
        Returns current translations object, may return NULL.

        You must either call this early in app initialization code, or let
        wxLocale do it for you.
     */
    static wxTranslations *Get();

    /**
        Sets current translations object.

        Deletes previous translation object and takes ownership of @a t.
     */
    static void Set(wxTranslations *t);

    /**
        Changes loader use to read catalogs to a non-default one.

        Deletes previous loader and takes ownership of @a loader.

        @see wxTranslationsLoader, wxFileTranslationsLoader, wxResourceTranslationsLoader
     */
    void SetLoader(wxTranslationsLoader *loader);

    /**
        Sets translations language to use.

        wxLANGUAGE_DEFAULT has special meaning: best suitable translation,
        given user's preference and available translations, will be used.
     */
    void SetLanguage(wxLanguage lang);

    /**
        Sets translations language to use.

        Empty @a lang string has the same meaning as wxLANGUAGE_DEFAULT in
        SetLanguage(wxLanguage): best suitable translation, given user's
        preference and available translations, will be used.
     */
    void SetLanguage(const wxString& lang);

    /**
        Returns list of all translations of @a domain that were found.

        This method can be used e.g. to populate list of application's
        translations offered to the user. To do this, pass the app's main
        catalog as @a domain.
     */
    wxArrayString GetAvailableTranslations(const wxString& domain) const;

    /**
        Add standard wxWidgets catalogs ("wxstd" and possible port-specific
        catalogs).

        @return @true if a suitable catalog was found, @false otherwise

        @see AddCatalog()
     */
    bool AddStdCatalog();

    /**
        Add a catalog for use with the current locale.

        By default, it is searched for in standard places (see
        wxFileTranslationsLoader), but you may also prepend additional
        directories to the search path with
        wxFileTranslationsLoader::AddCatalogLookupPathPrefix().

        All loaded catalogs will be used for message lookup by GetString() for
        the current locale.

        In this overload, @c msgid strings are assumed
        to be in English and written only using 7-bit ASCII characters.
        If you have to deal with non-English strings or 8-bit characters in the
        source code, see the instructions in @ref overview_nonenglish.

        @return
            @true if catalog was successfully loaded, @false otherwise (which might
            mean that the catalog is not found or that it isn't in the correct format).
     */
    bool AddCatalog(const wxString& domain);

    /**
        Same as AddCatalog(const wxString&), but takes an additional argument,
        @a msgIdLanguage.

        @param domain
            The catalog domain to add.

        @param msgIdLanguage
            Specifies the language of "msgid" strings in source code
            (i.e. arguments to GetString(), wxGetTranslation() and the _() macro).
            It is used if AddCatalog() cannot find any catalog for current language:
            if the language is same as source code language, then strings from source
            code are used instead.

        @return
            @true if catalog was successfully loaded, @false otherwise (which might
            mean that the catalog is not found or that it isn't in the correct format).
     */
    bool AddCatalog(const wxString& domain, wxLanguage msgIdLanguage);

    /**
        Same as AddCatalog(const wxString&, wxLanguage), but takes two
        additional arguments, @a msgIdLanguage and @a msgIdCharset.

        This overload is only available in non-Unicode build.

        @param domain
            The catalog domain to add.

        @param msgIdLanguage
            Specifies the language of "msgid" strings in source code
            (i.e. arguments to GetString(), wxGetTranslation() and the _() macro).
            It is used if AddCatalog() cannot find any catalog for current language:
            if the language is same as source code language, then strings from source
            code are used instead.

        @param msgIdCharset
            Lets you specify the charset used for msgids in sources
            in case they use 8-bit characters (e.g. German or French strings).

        @return
            @true if catalog was successfully loaded, @false otherwise (which might
            mean that the catalog is not found or that it isn't in the correct format).
     */
    bool AddCatalog(const wxString& domain,
                    wxLanguage msgIdLanguage,
                    const wxString& msgIdCharset);

    /**
        Check if the given catalog is loaded, and returns @true if it is.

        According to GNU gettext tradition, each catalog normally corresponds to
        'domain' which is more or less the application name.

        @see AddCatalog()
     */
    bool IsLoaded(const wxString& domain) const;

    /**
        Retrieves the translation for a string in all loaded domains unless the @a domain
        parameter is specified (and then only this catalog/domain is searched).

        Returns original string if translation is not available (in this case an
        error message is generated the first time a string is not found; use
        wxLogNull to suppress it).

        @remarks Domains are searched in the last to first order, i.e. catalogs
                 added later override those added before.
    */
    const wxString& GetString(const wxString& origString,
                              const wxString& domain = wxEmptyString) const;

    /**
        Retrieves the translation for a string in all loaded domains unless the @a domain
        parameter is specified (and then only this catalog/domain is searched).

        Returns original string if translation is not available (in this case an
        error message is generated the first time a string is not found; use
        wxLogNull to suppress it).

        This form is used when retrieving translation of string that has different
        singular and plural form in English or different plural forms in some
        other language.
        It takes two extra arguments: @a origString parameter must contain the
        singular form of the string to be converted.

        It is also used as the key for the search in the catalog.
        The @a origString2 parameter is the plural form (in English).

        The parameter @a n is used to determine the plural form.
        If no message catalog is found @a origString is returned if 'n == 1',
        otherwise @a origString2.

        See GNU gettext manual for additional information on plural forms handling.
        This method is called by the wxGetTranslation() function and _() macro.

        @remarks Domains are searched in the last to first order, i.e. catalogs
                 added later override those added before.
    */
    const wxString& GetString(const wxString& origString,
                              const wxString& origString2,
                              unsigned n,
                              const wxString& domain = wxEmptyString) const;

    /**
        Returns the header value for header @a header.
        The search for @a header is case sensitive. If an @a domain is passed,
        this domain is searched. Else all domains will be searched until a
        header has been found.

        The return value is the value of the header if found. Else this will be empty.
    */
    wxString GetHeaderValue(const wxString& header,
                            const wxString& domain = wxEmptyString) const;
};


/**
    Abstraction of translations discovery and loading.

    This interface makes it possible to override wxWidgets' default catalogs
    loading mechanism and load MO files from locations other than the
    filesystem (e.g. embed them in executable).

    Implementations must implement the LoadCatalog() method.

    @see wxFileTranslationsLoader, wxResourceTranslationsLoader

    @since 2.9.1
 */
class wxTranslationsLoader
{
public:
    /// Constructor
    wxTranslationsLoader() {}

    /**
        Called to load requested catalog.

        If the catalog is found, LoadCatalog() should create wxMsgCatalog
        instance with its data and return it. The caller will take ownership
        of the catalog.

        @param domain        Domain to load.
        @param lang          Language to look for. This is "canonical name"
                             (see wxLocale::GetCanonicalName()), i.e. ISO 639
                             code, possibly combined with country code or
                             additional modifiers (e.g. "fr", "en_GB" or
                             "ca@valencia").

        @return Loaded catalog or NULL on failure.
     */
    virtual wxMsgCatalog *LoadCatalog(const wxString& domain,
                                      const wxString& lang) = 0;

    /**
        Implements wxTranslations::GetAvailableTranslations().
     */
    virtual wxArrayString GetAvailableTranslations(const wxString& domain) const = 0;
};

/**
    Standard wxTranslationsLoader implementation.

    This finds catalogs in the filesystem, using the standard Unix layout.
    This is the default unless you change the loader with
    wxTranslations::SetLoader().

    Catalogs are searched for in standard places (current directory first, then
    the system one), but you may also prepend additional directories to the
    search path with AddCatalogLookupPathPrefix().

    @since 2.9.1
 */
class wxFileTranslationsLoader : public wxTranslationsLoader
{
public:
    /**
        Add a prefix to the catalog lookup path: the message catalog files will
        be looked up under prefix/lang/LC_MESSAGES, prefix/lang and prefix
        (in this order).

        This only applies to subsequent invocations of
        wxTranslations::AddCatalog().
    */
    static void AddCatalogLookupPathPrefix(const wxString& prefix);
};

/**
    This loader makes it possible to load translations from Windows
    resources.

    If you wish to store translation MO files in resources, you have to
    enable this loader before calling wxTranslations::AddCatalog() or
    wxLocale::AddCatalog():

    @code
    wxTranslations::Get()->SetLoader(new wxResourceTranslationsLoader);
    @endcode

    Translations are stored in resources as compiled MO files, with type
    set to "MOFILE" (unless you override GetResourceType()) and name
    consisting of the domain, followed by underscore, followed by language
    identification. For example, the relevant part of .rc file would look
    like this:

    @code
    myapp_de     MOFILE   "catalogs/de/myapp.mo"
    myapp_fr     MOFILE   "catalogs/fr/myapp.mo"
    myapp_en_GB  MOFILE   "catalogs/en_GB/myapp.mo"
    @endcode

    This class is only available on Windows.

    @since 2.9.1
 */
class wxResourceTranslationsLoader : public wxTranslationsLoader
{
protected:
    /**
        Returns resource type to use for translations.

        Default type is "MOFILE".
     */
    virtual wxString GetResourceType() const;

    /**
        Returns handle of the module to load resources from.

        By default, the main executable is used.
     */
    virtual WXHINSTANCE GetModule() const;
};


/**
    Represents a loaded translations message catalog.

    This class should only be used directly by wxTranslationsLoader
    implementations.

    @since 2.9.1
 */
class wxMsgCatalog
{
public:
    /**
        Creates catalog loaded from a MO file.

        @param filename  Path to the MO file to load.
        @param domain    Catalog's domain. This typically matches
                         the @a filename.

        @return Successfully loaded catalog or NULL on failure.
     */
    static wxMsgCatalog *CreateFromFile(const wxString& filename,
                                        const wxString& domain);

    /**
        Creates catalog from MO file data in memory buffer.

        @param data      Data in MO file format.
        @param domain    Catalog's domain. This typically matches
                         the @a filename.

        @return Successfully loaded catalog or NULL on failure.
     */
    static wxMsgCatalog *CreateFromData(const wxScopedCharBuffer& data,
                                        const wxString& domain);
};


// ============================================================================
// Global functions/macros
// ============================================================================

/** @addtogroup group_funcmacro_string */
//@{

/**
    This macro is identical to _() but for the plural variant of
    wxGetTranslation().

    @return A const wxString.

    @header{wx/intl.h}
*/
#define wxPLURAL(string, plural, n)

/**
    This macro doesn't do anything in the program code -- it simply expands to
    the value of its argument.

    However it does have a purpose which is to mark the literal strings for the
    extraction into the message catalog created by @c xgettext program. Usually
    this is achieved using _() but that macro not only marks the string for
    extraction but also expands into a wxGetTranslation() call which means that
    it cannot be used in some situations, notably for static array
    initialization.

    Here is an example which should make it more clear: suppose that you have a
    static array of strings containing the weekday names and which have to be
    translated (note that it is a bad example, really, as wxDateTime already
    can be used to get the localized week day names already). If you write:

    @code
    static const char * const weekdays[] = { _("Mon"), ..., _("Sun") };
    ...
    // use weekdays[n] as usual
    @endcode

    The code wouldn't compile because the function calls are forbidden in the
    array initializer. So instead you should do this:

    @code
    static const char * const weekdays[] = { wxTRANSLATE("Mon"), ...,
    wxTRANSLATE("Sun") };
    ...
    // use wxGetTranslation(weekdays[n])
    @endcode

    Note that although the code @b would compile if you simply omit
    wxTRANSLATE() in the above, it wouldn't work as expected because there
    would be no translations for the weekday names in the program message
    catalog and wxGetTranslation() wouldn't find them.

    @return A const wxChar*.

    @header{wx/intl.h}
*/
#define wxTRANSLATE(string)

/**
    This function returns the translation of @a string in the current
    @c locale(). If the string is not found in any of the loaded message
    catalogs (see @ref overview_i18n), the original string is returned. In
    debug build, an error message is logged -- this should help to find the
    strings which were not yet translated.  If @a domain is specified then only
    that domain/catalog is searched for a matching string.  As this function is
    used very often, an alternative (and also common in Unix world) syntax is
    provided: the _() macro is defined to do the same thing as
    wxGetTranslation().

    This function calls wxTranslations::GetString().

    @note This function is not suitable for literal strings in Unicode builds
          since the literal strings must be enclosed into _T() or wxT() macro
          which makes them unrecognised by @c xgettext, and so they are not
          extracted to the message catalog. Instead, use the _() and wxPLURAL()
          macro for all literal strings.

    @see wxGetTranslation(const wxString&, const wxString&, unsigned, const wxString&)

    @header{wx/intl.h}
*/
const wxString& wxGetTranslation(const wxString& string,
                                 const wxString& domain = wxEmptyString);

/**
    This is an overloaded version of
    wxGetTranslation(const wxString&, const wxString&), please see its
    documentation for general information.

    This version is used when retrieving translation of string that has
    different singular and plural forms in English or different plural forms in
    some other language. Like wxGetTranslation(const wxString&,const wxString&),
    the @a string parameter must contain the singular form of the string to be
    converted and is used as the key for the search in the catalog. The
    @a plural parameter is the plural form (in English). The parameter @a n is
    used to determine the plural form. If no message catalog is found,
    @a string is returned if "n == 1", otherwise @a plural is returned.

    See GNU gettext Manual for additional information on plural forms handling:
    <http://www.gnu.org/software/gettext/manual/gettext.html#Plural-forms>
    For a shorter alternative see the wxPLURAL() macro.

    This function calls wxLocale::GetString().

    @header{wx/intl.h}
*/
const wxString& wxGetTranslation(const wxString& string,
                                 const wxString& plural, unsigned n,
                                 const wxString& domain = wxEmptyString);

/**
    This macro expands into a call to wxGetTranslation(), so it marks the
    message for the extraction by @c xgettext just as wxTRANSLATE() does, but
    also returns the translation of the string for the current locale during
    execution.

    Don't confuse this with _T()!

    @header{wx/intl.h}
*/
const wxString& _(const wxString& string);

//@}


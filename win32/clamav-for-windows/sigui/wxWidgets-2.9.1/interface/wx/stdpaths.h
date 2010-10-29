/////////////////////////////////////////////////////////////////////////////
// Name:        stdpaths.h
// Purpose:     interface of wxStandardPaths
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxStandardPaths

    wxStandardPaths returns the standard locations in the file system and should be
    used by applications to find their data files in a portable way.

    In the description of the methods below, the example return values are given
    for the Unix, Windows and Mac OS X systems, however please note that these are
    just the examples and the actual values may differ. For example, under Windows:
    the system administrator may change the standard directories locations, e.g.
    the Windows directory may be named @c "W:\Win2003" instead of
    the default @c "C:\Windows".

    Notice that in the examples below the string @c appinfo may be either just
    the application name (as returned by wxApp::GetAppName()) or a combination
    of the vendor name (wxApp::GetVendorName()) and the application name, with
    a path separator between them. By default, only the application name is
    used, use UseAppInfo() to change this.

    The other placeholders should be self-explanatory: the string @c username
    should be replaced with the value the name of the currently logged in user.
    and @c prefix is only used under Unix and is @c /usr/local by default but
    may be changed using wxStandardPaths::SetInstallPrefix().

    The directories returned by the methods of this class may or may not exist.
    If they don't exist, it's up to the caller to create them, wxStandardPaths doesn't
    do it.

    Finally note that these functions only work with standardly packaged
    applications. I.e. under Unix you should follow the standard installation
    conventions and under Mac you should create your application bundle according
    to the Apple guidelines. Again, this class doesn't help you to do it.

    This class is MT-safe: its methods may be called concurrently from different
    threads without additional locking.

    Note that you don't allocate an instance of class wxStandardPaths, but retrieve the
    global standard paths object using @c wxStandardPaths::Get on which you call the
    desired methods.

    @library{wxbase}
    @category{file}

    @see wxFileConfig
*/
class wxStandardPaths
{
public:
    /**
        MSW-specific function undoing the effect of IgnoreAppSubDir() calls.

        After a call to this function the program directory will be exactly the
        directory containing the main application binary, i.e. it undoes the
        effect of any previous IgnoreAppSubDir() calls including the ones done
        indirectly by IgnoreAppBuildSubDirs() called from the class
        constructor.

        @since 2.9.1
     */
    void DontIgnoreAppSubDir();

    /**
        Returns reference to the unique global standard paths object.
    */
    static wxStandardPaths& Get();

    /**
        Return the directory for the document files used by this application.

        If the application-specific directory doesn't exist, this function
        returns GetDocumentsDir().

        Example return values:
        - Unix: @c ~/appinfo
        - Windows: @c "C:\Documents and Settings\username\My Documents\appinfo"
        - Mac: @c ~/Documents/appinfo

        @since 2.9.0

        @see GetAppDocumentsDir()
     */
    virtual wxString GetAppDocumentsDir() const;

    /**
        Return the directory containing the system config files.
        Example return values:
        - Unix: @c /etc
        - Windows: @c "C:\Documents and Settings\All Users\Application Data"
        - Mac: @c /Library/Preferences

        @see wxFileConfig
    */
    virtual wxString GetConfigDir() const;

    /**
        Return the location of the applications global, i.e. not user-specific,
        data files.

        Example return values:
        - Unix: @c prefix/share/appinfo
        - Windows: the directory where the executable file is located
        - Mac: @c appinfo.app/Contents/SharedSupport bundle subdirectory

        Under Unix (only) it is possible to override the default value returned
        from this function by setting the value of @c WX_APPNAME_DATA_DIR
        environment variable to the directory to use (where @c APPNAME is the
        upper-cased value of wxApp::GetAppName()). This is useful in order to
        be able to run applications using this function without installing them
        as you can simply set this environment variable to the source directory
        location to allow the application to find its files there.

        @see GetLocalDataDir()
    */
    virtual wxString GetDataDir() const;

    /**
        Return the directory containing the current user's documents.

        Example return values:
        - Unix: @c ~ (the home directory)
        - Windows: @c "C:\Documents and Settings\username\My Documents"
        - Mac: @c ~/Documents

        @since 2.7.0

        @see GetAppDocumentsDir()
    */
    virtual wxString GetDocumentsDir() const;

    /**
        Return the directory and the filename for the current executable.
        Example return values:
        - Unix: @c /usr/local/bin/exename
        - Windows: @c "C:\Programs\AppFolder\exename.exe"
        - Mac: @c /Applications/exename.app/Contents/MacOS/exename
    */
    virtual wxString GetExecutablePath() const;

    /**
        Return the program installation prefix, e.g. @c /usr, @c /opt or @c /home/zeitlin.

        If the prefix had been previously by SetInstallPrefix(), returns that
        value, otherwise tries to determine it automatically (Linux only right now)
        and finally returns the default @c /usr/local value if it failed.

        @note This function is only available under Unix.
    */
    wxString GetInstallPrefix() const;

    /**
        Return the location for application data files which are host-specific and
        can't, or shouldn't, be shared with the other machines.

        This is the same as GetDataDir() except under Unix where it returns @c /etc/appinfo.
    */
    virtual wxString GetLocalDataDir() const;

    /**
        Return the localized resources directory containing the resource files of the
        specified category for the given language.

        In general this is just the same as @a lang subdirectory of GetResourcesDir()
        (or @c lang.lproj under Mac OS X) but is something quite different for
        message catalog category under Unix where it returns the standard
        @c prefix/share/locale/lang/LC_MESSAGES directory.

        @since 2.7.0
    */
    virtual wxString GetLocalizedResourcesDir(const wxString& lang,
                                              ResourceCat category) const;

    /**
        Return the directory where the loadable modules (plugins) live.
        Example return values:
        - Unix: @c prefix/lib/appinfo
        - Windows: the directory of the executable file
        - Mac: @c appinfo.app/Contents/PlugIns bundle subdirectory

        @see wxDynamicLibrary
    */
    virtual wxString GetPluginsDir() const;

    /**
        Return the directory where the application resource files are located.

        The resources are the auxiliary data files needed for the application to run
        and include, for example, image and sound files it might use.

        This function is the same as GetDataDir() for all platforms except Mac OS X.
        Example return values:
        - Unix: @c prefix/share/appinfo
        - Windows: the directory where the executable file is located
        - Mac: @c appinfo.app/Contents/Resources bundle subdirectory

        @since 2.7.0

        @see GetLocalizedResourcesDir()
    */
    virtual wxString GetResourcesDir() const;

    /**
        Return the directory for storing temporary files.
        To create unique temporary files, it is best to use wxFileName::CreateTempFileName
        for correct behaviour when multiple processes are attempting to create temporary files.

        @since 2.7.2
    */
    virtual wxString GetTempDir() const;

    /**
        Return the directory for the user config files:
        - Unix: @c ~ (the home directory)
        - Windows: @c "C:\Documents and Settings\username\Application Data"
        - Mac: @c ~/Library/Preferences

        Only use this method if you have a single configuration file to put in this
        directory, otherwise GetUserDataDir() is more appropriate.
    */
    virtual wxString GetUserConfigDir() const;

    /**
        Return the directory for the user-dependent application data files:
        - Unix: @c ~/.appinfo
        - Windows: @c "C:\Documents and Settings\username\Application Data\appinfo"
        - Mac: @c "~/Library/Application Support/appinfo"
    */
    virtual wxString GetUserDataDir() const;

    /**
        Return the directory for user data files which shouldn't be shared with
        the other machines.

        This is the same as GetUserDataDir() for all platforms except Windows where it returns
        @c "C:\Documents and Settings\username\Local Settings\Application Data\appinfo"
    */
    virtual wxString GetUserLocalDataDir() const;

    /**
        MSW-specific function to customize application directory detection.

        This class supposes that data, plugins &c files are located under the
        program directory which is the directory containing the application
        binary itself. But sometimes this binary may be in a subdirectory of
        the main program directory, e.g. this happens in at least the following
        common cases:
         - The program is in "bin" subdirectory of the installation directory.
         - The program is in "debug" subdirectory of the directory containing
           sources and data files during development

        By calling this function you instruct the class to remove the last
        component of the path if it matches its argument. Notice that it may be
        called more than once, e.g. you can call both IgnoreAppSubDir("bin") and
        IgnoreAppSubDir("debug") to take care of both production and development
        cases above but that each call will only remove the last path component.
        Finally note that the argument can contain wild cards so you can also
        call IgnoreAppSubDir("vc*msw*") to ignore all build directories at once
        when using wxWidgets-inspired output directories names.

        @since 2.9.1

        @see IgnoreAppBuildSubDirs()

        @param subdirPattern
            The subdirectory containing the application binary which should be
            ignored when determining the top application directory. The pattern
            is case-insensitive and may contain wild card characters @c '?' and
            @c '*'.
     */
    void IgnoreAppSubDir(const wxString& subdirPattern);

    /**
        MSW-specific function to ignore all common build directories.

        This function calls IgnoreAppSubDir() with all common values for build
        directory, e.g. @c "debug" and @c "release".

        It is called by the class constructor and so the build directories are
        always ignored by default. You may use DontIgnoreAppSubDir() to avoid
        ignoring them if this is inappropriate for your application.

        @since 2.9.1
     */
    void IgnoreAppBuildSubDirs();

    /**
        Returns location of Windows shell special folder.

        This function is, by definition, MSW-specific. It can be used to access
        pre-defined shell directories not covered by the existing methods of
        this class, e.g.:
        @code
        #ifdef __WXMSW__
            // get the location of files waiting to be burned on a CD
            wxString cdburnArea =
                wxStandardPaths::MSWGetShellDir(CSIDL_CDBURN_AREA);
        #endif // __WXMSW__
        @endcode

        @param csidl

        @since 2.9.1
     */
    static wxString MSWGetShellDir(int csidl);

    /**
        Lets wxStandardPaths know about the real program installation prefix on a Unix
        system. By default, the value returned by GetInstallPrefix() is used.

        Although under Linux systems the program prefix may usually be determined
        automatically, portable programs should call this function. Usually the prefix
        is set during program configuration if using GNU autotools and so it is enough
        to pass its value defined in @c config.h to this function.

        @note This function is only available under Unix.
    */
    void SetInstallPrefix(const wxString& prefix);

    /**
        Controls what application information is used when constructing paths that
        should be unique to this program, such as the application data directory, the
        plugins directory on Unix, etc.

        Valid values for @a info are:
            - @c AppInfo_None: don't use neither application nor vendor name in
            the paths.
            - @c AppInfo_AppName: use the application name in the paths.
            - @c AppInfo_VendorName: use the vendor name in the paths, usually
            used combined with AppInfo_AppName, i.e. as @code AppInfo_AppName |
            AppInfo_VendorName @endcode

        By default, only the application name is used.

        @since 2.9.0
    */
    void UseAppInfo(int info);
};


/////////////////////////////////////////////////////////////////////////////
// Name:        wx/fswatcher.h
// Purpose:     wxFileSystemWatcher
// Author:      Bartosz Bekier
// Created:     2009-05-23
// RCS-ID:      $Id$
// Copyright:   (c) 2009 Bartosz Bekier <bartosz.bekier@gmail.com>
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxFileSystemWatcher

    The wxFileSystemWatcher class allows to receive notifications of file
    system changes.

    @note Implementation limitations: this class is currently implemented for
          MSW, OS X and GTK ports but doesn't detect all changes correctly
          everywhere: under MSW accessing the file is not detected (only
          modifying it is) and under OS X neither accessing nor modifying is
          detected (only creating and deleting files is). Moreover, OS X
          version doesn't currently collapse pairs of create/delete events in a
          rename event, unlike the other ones.

    For the full list of change types that are reported see wxFSWFlags.

    There are three different ways to use this class:

     - You may derive a new class from wxFileSystemWatcher and override the
       wxFileSystemWatcher::OnChange member to perform the required action
       when file system change occurrs. Additionally you may also want to
       override wxFileSystemWatcher::OnWarning and
       wxFileSystemWatcher::OnError to be notified when an error condition
       arises.
     - You may use a derived class and the @c EVT_FSWATCHER macro or
       wxEvtHandler::Connect to redirect events to an event handler defined in
       the derived class. If the default constructor is used, the file system
       watcher object will be its own owner object, since it is derived from
       wxEvtHandler.
     - You may redirect the notifications of file system changes as well as of
       error conditions to any wxEvtHandler derived object by using
       wxFileSystemWatcher::SetOwner.
       Then use the @c EVT_FSWATCHER macro or wxEvtHandler::Connect to send the
       events to the event handler which will receive wxFileSystemWatcherEvent.

    For example:

    @code
    class MyWatcher : public wxFileSystemWatcher
    {
    protected:
        void OnChange(int changeType, const wxFileName& path, const wxFileName& newPath)
        {
            // do whatever you like with the event
        }
    };

    class MyApp : public wxApp
    {
    public:
        ...
        void OnEventLoopEnter(wxEventLoopBase* WXUNUSED(loop))
        {
            // you have to construct the watcher here, because it needs an active loop
            m_watcher = new MyWatcher();

            // please notify me when a new log file is created
            m_watcher->Add(wxFileName::DirName("/var/log", wxFSW_EVENT_CREATE);
        }

    private:
        MyWatcher* m_watcher;
    };
    @endcode

    @library{wxbase}
    @category{file}

    @since 2.9.1
 */
class wxFileSystemWatcher: public wxEvtHandler
{
public:
    /**
        Default constructor. If you create file system watcher using it you have
        to either call SetOwner() and connect an event handler or override
        OnChange(), OnWarning() and OnError().
     */
    wxFileSystemWatcher();

    /**
        Destructor. Stops all paths from being watched and frees any system
        resources used by this file system watcher object.
     */
    virtual ~wxFileSystemWatcher();

    /**
        Adds @a path to currently watched files. Optionally a filter can be
        specified to receive only events of particular type.

        Any events concerning this particular path will be sent either to
        connected handler or passed to OnChange(), OnWarning() or OnError().

        @note When adding a directory, immediate children will be watched
        as well.
     */
    virtual bool Add(const wxFileName& path, int events = wxFSW_EVENT_ALL);

    /**
        This is the same as Add(), but recursively adds every file/directory in
        the tree rooted at @a path. Additionally a file mask can be specified to
        include only files matching that particular mask.
     */
    virtual bool AddTree(const wxFileName& path, int events = wxFSW_EVENT_ALL,
                        const wxString& filter = wxEmptyString) = 0;

    /**
        Removes @a path from the list of watched paths.
     */
    virtual bool Remove(const wxFileName& path);

    /**
        Same as Remove(), but also removes every file/directory belonging to
        the tree rooted at @a path.
     */
    virtual bool RemoveTree(const wxFileName& path);

    /**
        Clears the list of currently watched paths.
     */
    virtual bool RemoveAll();

    /**
        Returns the number of watched paths
     */
    int GetWatchedPathCount() const;

    /**
        Retrieves all watched paths and places them in @a paths. Returns
        the number of watched paths, which is also the number of entries added
        to @a paths.
     */
    int GetWatchedPaths(wxArrayString* paths) const;

    /**
        Associates the file system watcher with the given @a handler object.

        Basically this means that all events will be passed to this handler
        object unless you have change the default behaviour by overriding
        OnChange(), OnWarning() or OnError().
     */
    void SetOwner(wxEvtHandler* handler);

protected:
    /**
        You may either connect your event handler to intercept file system
        watcher events or override this member and handle them here.

        Perform whatever action which is to be taken on file system change.
     */
    virtual void OnChange(int changeType, const wxFileName& path,
                                        const wxFileName& newPath);

    /**
        You may either connect your event handler to intercept file system
        watcher events or override this member and handle them here.

        Perform whatever action which is to be taken when a warning condition
        arises.
     */
    virtual void OnWarning(const wxString& errorMessage);

    /**
        You may either connect your event handler to intercept file system
        watcher events or override this member and handle them here.

        Perform whatever action which is to be taken when an error condition
        arises.
     */
    virtual void OnError(const wxString& errorMessage);
};



/**
    @class wxFileSystemWatcherEvent

    A class of events sent when a file system event occurs. Types of events
    reported may vary depending on a platfrom, however all platforms report
    at least creation of new file/directory and access, modification, move
    (rename) or deletion of an existing one.

    @library{wxcore}
    @category{events}

    @see wxFileSystemWatcher
    @see @ref overview_events

    @since 2.9.1
*/
class wxFileSystemWatcherEvent : public wxEvent
{
public:
    /**
        Returns the path at which the event occurred.
     */
    const wxFileName& GetPath() const;

    /**
        Returns the new path of the renamed file/directory if this is a rename
        event.

        Otherwise it returns the same path as GetPath().
     */
    const wxFileName& GetNewPath() const;

    /**
        Returns the type of file system change that occurred. See wxFSWFlags for
        the list of possible file system change types.
     */
    int GetChangeType() const;

    /**
        Returns @c true if this error is an error event

        Error event is an event generated when a warning or error condition
        arises.
     */
    bool IsError() const;

    /**
        Return a description of the warning or error if this is an error event.
     */
    wxString GetErrorDescription() const;

    /**
        Returns a wxString describing an event, useful for logging, debugging
        or testing.
     */
    wxString ToString() const;
};


/**
    These are the possible types of file system change events.
    All of these events are reported on all supported platforms.

    @since 2.9.1
 */
enum wxFSWFlags
{
    wxFSW_EVENT_CREATE = 0x01,  ///< File or directory was created
    wxFSW_EVENT_DELETE = 0x02,  ///< File or directory was deleted
    wxFSW_EVENT_RENAME = 0x04,  ///< File or directory was renamed
    wxFSW_EVENT_MODIFY = 0x08,  ///< File or directory was modified
    wxFSW_EVENT_ACCESS = 0x10,  ///< File or directory was accessed

    wxFSW_EVENT_WARNING = 0x20, ///< A warning condition arose.
    wxFSW_EVENT_ERROR = 0x40,   ///< An error condition arose.

    wxFSW_EVENT_ALL = wxFSW_EVENT_CREATE | wxFSW_EVENT_DELETE |
                         wxFSW_EVENT_RENAME | wxFSW_EVENT_MODIFY |
                         wxFSW_EVENT_ACCESS |
                         wxFSW_EVENT_WARNING | wxFSW_EVENT_ERROR
};


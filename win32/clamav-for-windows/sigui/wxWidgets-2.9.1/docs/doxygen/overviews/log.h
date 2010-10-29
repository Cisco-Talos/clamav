/////////////////////////////////////////////////////////////////////////////
// Name:        log.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_log wxLog Classes Overview

Classes:
@li wxLog
@li wxLogStderr
@li wxLogStream
@li wxLogTextCtrl
@li wxLogWindow
@li wxLogGui
@li wxLogNull
@li wxLogBuffer
@li wxLogChain
@li wxLogInterposer
@li wxLogInterposerTemp
@li wxStreamToTextRedirector

@li @ref overview_log_introduction
@li @ref overview_log_targets
@li @ref overview_log_customize

<hr>


@section overview_log_introduction Introduction

This is a general overview of logging classes provided by wxWidgets. The word
logging here has a broad sense, including all of the program output, not only
non-interactive messages. The logging facilities included in wxWidgets provide
the base wxLog class which defines the standard interface for a @e log target
as well as several standard implementations of it and a family of functions to
use with them.

First of all, no knowledge of wxLog classes is needed to use them. For this,
you should only know about @e wxLogXXX() functions. All of them have the same
syntax as @e printf() or @e vprintf() , i.e. they take the format string as the
first argument and respectively a variable number of arguments or a variable
argument list pointer. Here are all of them:

@li wxLogFatalError which is like wxLogError, but also terminates the program
    with the exit code 3 (using @e abort() standard function). Unlike for all
    the other logging functions, this function can't be overridden by a log
    target.
@li wxLogError is the function to use for error messages, i.e. the messages
    that must be shown to the user. The default processing is to pop up a
    message box to inform the user about it.
@li wxLogWarning for warnings. They are also normally shown to the user, but
    don't interrupt the program work.
@li wxLogMessage is for all normal, informational messages. They also appear in
    a message box by default (but it can be changed, see below).
@li wxLogVerbose is for verbose output. Normally, it is suppressed, but might
    be activated if the user wishes to know more details about the program
    progress (another, but possibly confusing name for the same function is
    wxLogInfo).
@li wxLogStatus is for status messages. They will go into the status bar of the
    active or specified (as the first argument) wxFrame if it has one.
@li wxLogSysError is mostly used by wxWidgets itself, but might be handy for
    logging errors after system call (API function) failure. It logs the
    specified message text as well as the last system error code (@e errno or
    ::GetLastError() depending on the platform) and the corresponding error
    message. The second form of this function takes the error code explicitly
    as the first argument.
@li wxLogDebug is @b the right function for debug output. It only does anything
    at all in the debug mode (when the preprocessor symbol __WXDEBUG__ is
    defined) and expands to nothing in release mode (otherwise).

    @b Tip: under Windows, you must either run the program under debugger or
    use a 3rd party program such as DebugView
    (http://www.microsoft.com/technet/sysinternals/Miscellaneous/DebugView.mspx)
    to actually see the debug output.
@li wxLogTrace as wxLogDebug only does something in debug build. The reason for
    making it a separate function from it is that usually there are a lot of
    trace messages, so it might make sense to separate them from other debug
    messages which would be flooded in them. Moreover, the second version of
    this function takes a trace mask as the first argument which allows to
    further restrict the amount of messages generated.

The usage of these functions should be fairly straightforward, however it may
be asked why not use the other logging facilities, such as C standard stdio
functions or C++ streams. The short answer is that they're all very good
generic mechanisms, but are not really adapted for wxWidgets, while the log
classes are. Some of advantages in using wxWidgets log functions are:

@li @b Portability: It is a common practice to use @e printf() statements or
    cout/cerr C++ streams for writing out some (debug or otherwise)
    information. Although it works just fine under Unix, these messages go
    strictly nowhere under Windows where the stdout of GUI programs is not
    assigned to anything. Thus, you might view wxLogMessage() as a simple
    substitute for @e printf().
    You can also redirect the @e wxLogXXX calls to @e cout by just writing:
    @code
    wxLog* logger = new wxLogStream(&cout);
    wxLog::SetActiveTarget(logger);
    @endcode
    Finally, there is also a possibility to redirect the output sent to @e cout
    to a wxTextCtrl by using the wxStreamToTextRedirector class.
@li @b Flexibility: The output of wxLog functions can be redirected or
    suppressed entirely based on their importance, which is either impossible
    or difficult to do with traditional methods. For example, only error
    messages, or only error messages and warnings might be logged, filtering
    out all informational messages.
@li @b Completeness: Usually, an error message should be presented to the user
    when some operation fails. Let's take a quite simple but common case of a
    file error: suppose that you're writing your data file on disk and there is
    not enough space. The actual error might have been detected inside
    wxWidgets code (say, in wxFile::Write), so the calling function doesn't
    really know the exact reason of the failure, it only knows that the data
    file couldn't be written to the disk. However, as wxWidgets uses
    wxLogError() in this situation, the exact error code (and the corresponding
    error message) will be given to the user together with "high level" message
    about data file writing error.


@section overview_log_enable Log Messages Selection

By default, most log messages are enabled. In particular, this means that
errors logged by wxWidgets code itself (e.g. when it fails to perform some
operation, for instance wxFile::Open() logs an error when it fails to open a
file) will be processed and shown to the user. To disable the logging entirely
you can use wxLog::EnableLogging() method or, more usually, wxLogNull class
which temporarily disables logging and restores it back to the original setting
when it is destroyed.

To limit logging to important messages only, you may use wxLog::SetLogLevel()
with e.g. wxLOG_Warning value -- this will completely disable all logging
messages with the severity less than warnings, so wxLogMessage() output won't
be shown to the user any more.

Moreover, the log level can be set separately for different log components.
Before showing how this can be useful, let us explain what log components are:
they are simply arbitrary strings identifying the component, or module, which
generated the message. They are hierarchical in the sense that "foo/bar/baz"
component is supposed to be a child of "foo". And all components are children
of the unnamed root component.

By default, all messages logged by wxWidgets originate from "wx" component or
one of its subcomponents such as "wx/net/ftp", while the messages logged by
your own code are assigned empty log component. To change this, you need to
define @c wxLOG_COMPONENT to a string uniquely identifying each component, e.g.
you could give it the value "MyProgram" by default and re-define it as
"MyProgram/DB" in the module working with the database and "MyProgram/DB/Trans"
in its part managing the transactions. Then you could use
wxLog::SetComponentLevel() in the following ways:
    @code
        // disable all database error messages, everybody knows databases never
        // fail anyhow
        wxLog::SetComponentLevel("MyProgram/DB", wxLOG_FatalError);

        // but enable tracing for the transactions as somehow our changes don't
        // get committed sometimes
        wxLog::SetComponentLevel("MyProgram/DB/Trans", wxLOG_Trace);

        // also enable tracing messages from wxWidgets dynamic module loading
        // mechanism
        wxLog::SetComponentLevel("wx/base/module", wxLOG_Trace);
    @endcode
Notice that the log level set explicitly for the transactions code overrides
the log level of the parent component but that all other database code
subcomponents inherit its setting by default and so won't generate any log
messages at all.

@section overview_log_targets Log Targets

After having enumerated all the functions which are normally used to log the
messages, and why would you want to use them, we now describe how all this
works.

wxWidgets has the notion of a <em>log target</em>: it is just a class deriving
from wxLog. As such, it implements the virtual functions of the base class
which are called when a message is logged. Only one log target is @e active at
any moment, this is the one used by @e wxLogXXX() functions. The normal usage
of a log object (i.e. object of a class derived from wxLog) is to install it as
the active target with a call to @e SetActiveTarget() and it will be used
automatically by all subsequent calls to @e wxLogXXX() functions.

To create a new log target class you only need to derive it from wxLog and
override one or several of wxLog::DoLogRecord(), wxLog::DoLogTextAtLevel() and
wxLog::DoLogText() in it. The first one is the most flexible and allows you to
change the formatting of the messages, dynamically filter and redirect them and
so on -- all log messages, except for those generated by wxLogFatalError(),
pass by this function. wxLog::DoLogTextAtLevel() should be overridden if you
simply want to redirect the log messages somewhere else, without changing their
formatting. Finally, it is enough to override wxLog::DoLogText() if you only
want to redirect the log messages and the destination doesn't depend on the
message log level.


There are some predefined classes deriving from wxLog and which might be
helpful to see how you can create a new log target class and, of course, may
also be used without any change. There are:

@li wxLogStderr: This class logs messages to a <tt>FILE *</tt>, using stderr by
    default as its name suggests.
@li wxLogStream: This class has the same functionality as wxLogStderr, but uses
    @e ostream and cerr instead of <tt>FILE *</tt> and stderr.
@li wxLogGui: This is the standard log target for wxWidgets applications (it is
    used by default if you don't do anything) and provides the most reasonable
    handling of all types of messages for given platform.
@li wxLogWindow: This log target provides a "log console" which collects all
    messages generated by the application and also passes them to the previous
    active log target. The log window frame has a menu allowing user to clear
    the log, close it completely or save all messages to file.
@li wxLogBuffer: This target collects all the logged messages in an internal
    buffer allowing to show them later to the user all at once.
@li wxLogNull: The last log class is quite particular: it doesn't do anything.
    The objects of this class may be instantiated to (temporarily) suppress
    output of @e wxLogXXX() functions. As an example, trying to open a
    non-existing file will usually provoke an error message, but if for some
    reasons it is unwanted, just use this construction:
    @code
    wxFile file;

    // wxFile.Open() normally complains if file can't be opened, we don't want it
    {
        wxLogNull logNo;
        if ( !file.Open("bar") )
        {
            // ... process error ourselves ...
        }
    } // ~wxLogNull called, old log sink restored

    wxLogMessage("..."); // ok
    @endcode

The log targets can also be combined: for example you may wish to redirect the
messages somewhere else (for example, to a log file) but also process them as
normally. For this the wxLogChain, wxLogInterposer, and wxLogInterposerTemp can
be used.


@section overview_log_customize Logging Customization

To completely change the logging behaviour you may define a custom log target.
For example, you could define a class inheriting from wxLog which shows all the
log messages in some part of your main application window reserved for the
message output without interrupting the user work flow with modal message
boxes.

To use your custom log target you may either call wxLog::SetActiveTarget() with
your custom log object or create a wxAppTraits-derived class and override
CreateLogTarget() virtual method in it and also override wxApp::CreateTraits()
to return an instance of your custom traits object. Notice that in the latter
case you should be prepared for logging messages early during the program
startup and also during program shutdown so you shouldn't rely on existence of
the main application window, for example. You can however safely assume that
GUI is (already/still) available when your log target as used as wxWidgets
automatically switches to using wxLogStderr if it isn't.

The dialog sample illustrates this approach by defining a custom log target
customizing the dialog used by wxLogGui for the single messages.


@section overview_log_mt Logging in Multi-Threaded Applications

Starting with wxWidgets 2.9.1, logging functions can be safely called from any
thread. Messages logged from threads other than the main one will be buffered
until wxLog::Flush() is called in the main thread (which usually happens during
idle time, i.e. after processing all pending events) and will be really output
only then. Notice that the default GUI logger already only output the messages
when it is flushed, so by default messages from the other threads will be shown
more or less at the same moment as usual. However if you define a custom log
target, messages may be logged out of order, e.g. messages from the main thread
with later timestamp may appear before messages with earlier timestamp logged
from other threads. wxLog does however guarantee that messages logged by each
thread will appear in order in which they were logged.

Also notice that wxLog::EnableLogging() and wxLogNull class which uses it only
affect the current thread, i.e. logging messages may still be generated by the
other threads after a call to @c EnableLogging(false).

*/


/////////////////////////////////////////////////////////////////////////////
// Name:        exceptions.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_exceptions C++ Exceptions

@li @ref overview_exceptions_introduction
@li @ref overview_exceptions_strategies
@li @ref overview_exceptions_tech


<hr>


@section overview_exceptions_introduction Introduction

wxWidgets had been started long before the exceptions were introduced in C++ so
it is not very surprising that it is not built around using them as some more
modern C++ libraries are. For instance, the library doesn't throw exceptions to
signal about the errors. Moreover, up to (and including) the version 2.4 of
wxWidgets, even using the exceptions in the user code was dangerous because the
library code wasn't exception-safe and so an exception propagating through it
could result in memory and/or resource leaks, and also not very convenient.

wxWidgets is exception-friendly.
It still doesn't use the exceptions by itself but it should be now safe to use the
exceptions in the user code and the library tries to help you with this. Please
note that making the library exception-safe is still work in progress.


@section overview_exceptions_strategies Strategies for exceptions handling

There are several choice for using the exceptions in wxWidgets programs. First
of all, you may not use them at all. As stated above, the library doesn't throw
any exceptions by itself and so you don't have to worry about exceptions at all
unless your own code throws them. This is, of course, the simplest solution but
may be not the best one to deal with all possible errors.

Another strategy is to use exceptions only to signal truly fatal errors. In
this case you probably don't expect to recover from them and the default
behaviour -- to simply terminate the program -- may be appropriate. If it is
not, you may override wxApp::OnUnhandledException()
in your wxApp-derived class to perform any clean up tasks. Note, however, that
any information about the exact exception type is lost when this function is
called, so if you need you should override wxApp::OnRun() and
add a try/catch clause around the call of the base class version. This would
allow you to catch any exceptions generated during the execution of the main
event loop. To deal with the exceptions which may arise during the program
startup and/or shutdown you should insert try/catch clauses in
wxApp::OnInit() and/or wxApp::OnExit() as well.

Finally, you may also want to continue running even when certain exceptions
occur. If all of your exceptions may happen only in the event handlers of a
single class (or only in the classes derived from it), you may centralize your
exception handling code in wxApp::ProcessEvent
method of this class. If this is impractical, you may also consider overriding
the wxApp::HandleEvent() which allows you to handle
all the exceptions thrown by any event handler.


@section overview_exceptions_tech Technicalities

To use any kind of exception support in the library you need to build it
with @c wxUSE_EXCEPTIONS set to 1. This should be the case by default but
if it isn't, you should edit the @c include/wx/msw/setup.h file under
Windows or run @c configure with @c --enable-exceptions argument
under Unix.

On the other hand, if you do not plan to use exceptions, setting this
flag to 0 or using @c --disable-exceptions could result in a leaner and
slightly faster library.

As for any other library feature, there is a sample (@c except)
showing how to use it. Please look at its sources for further information.

*/

/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/utilsexec.mm
// Purpose:     Execution-related utilities for wxCocoa
// Author:      Ryan Norton
// Modified by:
// Created:     2004-10-05
// RCS-ID:      $Id$
// Copyright:   (c) Ryan Norton
// Licence:     wxWindows licence
// Notes:       This code may be useful on platforms other than Darwin.
//              On Darwin we share the CoreFoundation code with wxMac.
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"

#ifndef WX_PRECOMP
    #include "wx/utils.h"
#endif

#include "wx/unix/execute.h"

#if 0

#ifndef   WX_PRECOMP
    #if wxUSE_STREAMS
        #include  "wx/stream.h"
    #endif // wxUSE_STREAMS
#endif  //WX_PRECOMP

#include "wx/process.h"

#include "wx/cocoa/string.h"

#include "wx/cocoa/objc/objc_uniquifying.h"

#import <Foundation/Foundation.h>
#import <AppKit/NSWorkspace.h>

//
// RN:  This is a prelimenary implementation - simple
// launching and process redirection works,
// but with the piping tests in the exec sample
// SIGPIPE is triggered...
//

class wxPipeInputStream : public wxInputStream
{
public:
    wxPipeInputStream(NSPipe* thePipe) :
            m_thePipe(thePipe),
            m_theHandle([m_thePipe fileHandleForReading])
    {
    }

    ~wxPipeInputStream()
    {
        [m_thePipe release];
    }

protected:
    virtual size_t OnSysRead(void *buffer, size_t size)
    {
        NSData* theData = [m_theHandle readDataOfLength:size];
        memcpy(buffer, [theData bytes], [theData length]);
        return [theData length];
    }


    NSPipe* m_thePipe;
    NSFileHandle* m_theHandle;
};

class wxPipeOutputStream : public wxOutputStream
{
public:
    wxPipeOutputStream(NSPipe* thePipe) :
            m_thePipe(thePipe),
            m_theHandle([m_thePipe fileHandleForWriting])
    {
    }

    ~wxPipeOutputStream()
    {
        [m_thePipe release];
    }

protected:

    virtual size_t OnSysWrite(const void *buffer, size_t bufsize)
    {
        NSData* theData = [NSData dataWithBytesNoCopy:(void*)buffer
                                  length:bufsize];
        [m_theHandle writeData:theData];
        return bufsize;
    }

    NSPipe* m_thePipe;
    NSFileHandle* m_theHandle;
};

@interface wxTaskHandler : NSObject
{
    long m_pid;
    void* m_handle;
}
-(id)init:(void*)handle processIdentifier:(long)pid;
- (void)termHandler:(NSNotification *)aNotification;
@end
WX_DECLARE_GET_OBJC_CLASS(wxTaskHandler,NSObject)

@implementation wxTaskHandler : NSObject

-(id)init:(void*)handle processIdentifier:(long)pid
{
    self = [super init];

    m_handle = handle;
    m_pid = pid;

    [[NSNotificationCenter defaultCenter] addObserver:self
            selector:@selector(termHandler:)
            name:NSTaskDidTerminateNotification
            object:nil];
    return self;
}

- (void)termHandler:(NSNotification *)aNotification
{
    NSTask* theTask = [aNotification object];

    if ([theTask processIdentifier] == m_pid)
    {
        ((wxProcess*)m_handle)->OnTerminate([theTask processIdentifier],
                          [theTask terminationStatus]);

        [self release];
    }
}

@end
WX_IMPLEMENT_GET_OBJC_CLASS(wxTaskHandler,NSObject)

long wxExecute(const wxString& command,
               int sync,
               wxProcess *handle)
{
    NSTask* theTask = [[NSTask alloc] init];

    if (handle && handle->IsRedirected())
    {
        NSPipe* theStdinPipe = [[NSPipe alloc] init];
        NSPipe* theStderrPipe = [[NSPipe alloc] init];
        NSPipe* theStdoutPipe = [[NSPipe alloc] init];

        [theTask setStandardInput:theStdinPipe];
        [theTask setStandardError:theStderrPipe];
        [theTask setStandardOutput:theStdoutPipe];

        handle->SetPipeStreams(new wxPipeInputStream(theStdoutPipe),
                               new wxPipeOutputStream(theStdinPipe),
                               new wxPipeInputStream(theStderrPipe) );
    }

    NSArray* theQuoteArguments =
        [wxNSStringWithWxString(command) componentsSeparatedByString:@"\""];

    NSMutableArray* theSeparatedArguments =
        [NSMutableArray arrayWithCapacity:10];

    for (unsigned i = 0; i < [theQuoteArguments count]; ++i)
    {
        [theSeparatedArguments addObjectsFromArray:
            [[theQuoteArguments objectAtIndex:i] componentsSeparatedByString:@" "]
        ];

        if(++i < [theQuoteArguments count])
            [theSeparatedArguments addObject:[theQuoteArguments objectAtIndex:i]];
    }

    [theTask setLaunchPath:[theSeparatedArguments objectAtIndex:0]];
    [theTask setArguments:theSeparatedArguments];
    [theTask launch];

    if(sync & wxEXEC_ASYNC)
    {
        [[WX_GET_OBJC_CLASS(wxTaskHandler) alloc]init:handle
                              processIdentifier:[theTask processIdentifier]];

        return 0;
    }
    else
    {
        [theTask waitUntilExit];

        return [theTask terminationStatus];
    }
}
#endif //0

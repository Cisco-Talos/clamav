/////////////////////////////////////////////////////////////////////////////
// Name:        sound.cpp
// Purpose:     wxSound class implementation: optional
// Authors:     David Elliott, Ryan Norton
// Modified by: 
// Created:     2004-10-02
// RCS-ID:      $Id$
// Copyright:   (c) 2004 David Elliott, Ryan Norton
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

#include "wx/wxprec.h"
#if wxUSE_SOUND

#ifndef WX_PRECOMP
    #include "wx/app.h"
    #include "wx/log.h"
#endif //ndef WX_PRECOMP
#include "wx/sound.h"
#include "wx/evtloop.h"

#include "wx/cocoa/autorelease.h"
#include "wx/cocoa/string.h"
#include "wx/cocoa/log.h"

#include "wx/cocoa/objc/objc_uniquifying.h"

#import <AppKit/NSSound.h>
#import <Foundation/NSData.h>

static WX_NSSound s_currentSound = nil;
static bool s_loopCurrentSound = false;

// ========================================================================
// wxNSSoundDelegate
// ========================================================================
@interface wxNSSoundDelegate : NSObject
{
}

// Delegate methods
- (void)sound:(NSSound *)theSound didFinishPlaying:(BOOL)finishedPlaying;
@end // interface wxNSSoundDelegate : NSObject
WX_DECLARE_GET_OBJC_CLASS(wxNSSoundDelegate,NSObject)

@implementation wxNSSoundDelegate : NSObject

- (void)sound:(NSSound *)theSound didFinishPlaying:(BOOL)finishedPlaying
{
    // If s_currentSound is not us then some other sound has played.
    // We can safely ignore this as s_currentSound will have been released
    // before being set to a different value.
    if(s_currentSound!=theSound)
        return;
    // If playing finished successfully and we are looping, play again.
    if (finishedPlaying && s_loopCurrentSound)
        [s_currentSound play];
    // Otherwise we are done, there is no more current sound playing.
    else
    {
        if(s_currentSound) wxLogTrace(wxTRACE_COCOA_RetainRelease,wxT("[wxNSSoundDelegate -sound:didFinishPlaying:] [s_currentSound=%p retainCount]=%d (about to release)"),s_currentSound,[s_currentSound retainCount]);
        [s_currentSound release];
        s_currentSound = nil;
        // Make sure we get out of any modal event loops immediately.
        // NOTE: When the sound finishes playing Cocoa normally does have
        // an event so this is probably not necessary.
        wxTheApp->WakeUpIdle();
    }
}

@end // wxNSSoundDelegate
WX_IMPLEMENT_GET_OBJC_CLASS(wxNSSoundDelegate,NSObject)

const wxObjcAutoRefFromAlloc<struct objc_object*> wxSound::sm_cocoaDelegate = [[WX_GET_OBJC_CLASS(wxNSSoundDelegate) alloc] init];

// ------------------------------------------------------------------
//          wxSound
// ------------------------------------------------------------------

wxSound::wxSound(const wxSound& sound)
:   m_cocoaNSSound(sound.m_cocoaNSSound)
{
    [m_cocoaNSSound retain];
}

wxSound::~wxSound()
{
    SetNSSound(nil);
}

bool wxSound::Create(const wxString& fileName, bool isResource)
{
    wxAutoNSAutoreleasePool thePool;

    if (isResource)
        SetNSSound([NSSound soundNamed:wxNSStringWithWxString(fileName)]);
    else
    {
        SetNSSound([[NSSound alloc] initWithContentsOfFile:wxNSStringWithWxString(fileName) byReference:YES]);
        [m_cocoaNSSound release];
    }

    return m_cocoaNSSound;
}

bool wxSound::LoadWAV(const wxUint8 *data, size_t length, bool copyData)
{
    NSData* theData;
    if(copyData)
        theData = [[NSData alloc] initWithBytes:const_cast<wxUint8*>(data) length:length];
    else
        theData = [[NSData alloc] initWithBytesNoCopy:const_cast<wxUint8*>(data) length:length];
    SetNSSound([[NSSound alloc] initWithData:theData]);
    [m_cocoaNSSound release];
    [theData release];
    return m_cocoaNSSound;
}

void wxSound::SetNSSound(WX_NSSound cocoaNSSound)
{
    bool need_debug = cocoaNSSound || m_cocoaNSSound;
    if(need_debug) wxLogTrace(wxTRACE_COCOA_RetainRelease,wxT("wxSound=%p::SetNSSound [m_cocoaNSSound=%p retainCount]=%d (about to release)"),this,m_cocoaNSSound,[m_cocoaNSSound retainCount]);
    [cocoaNSSound retain];
    [m_cocoaNSSound release];
    m_cocoaNSSound = cocoaNSSound;
    [m_cocoaNSSound setDelegate:sm_cocoaDelegate];
    if(need_debug) wxLogTrace(wxTRACE_COCOA_RetainRelease,wxT("wxSound=%p::SetNSSound [cocoaNSSound=%p retainCount]=%d (just retained)"),this,cocoaNSSound,[cocoaNSSound retainCount]);
}

bool wxSound::DoPlay(unsigned flags) const
{
    Stop(); // this releases and nils s_currentSound

    // NOTE: We set s_currentSound to the current sound in all cases so that
    // functions like Stop and IsPlaying can work.  It is NOT necessary for
    // the NSSound to be retained by us for it to continue playing.  Cocoa
    // retains the NSSound when it is played and relases it when finished.

    wxASSERT(!s_currentSound);
    s_currentSound = [m_cocoaNSSound retain];
    wxLogTrace(wxTRACE_COCOA_RetainRelease,wxT("wxSound=%p::DoPlay [s_currentSound=%p retainCount]=%d (just retained)"),this,s_currentSound,[s_currentSound retainCount]);
    s_loopCurrentSound = (flags & wxSOUND_LOOP) == wxSOUND_LOOP;

    if (flags & wxSOUND_ASYNC)
        return [m_cocoaNSSound play];
    else
    {
        wxASSERT_MSG(!s_loopCurrentSound,wxT("It is silly to block waiting for a looping sound to finish.  Disabling looping"));
        // actually, it'd probably work although it's kind of stupid to
        // block here waiting for a sound that's never going to end.
        // Granted Stop() could be called somehow, but again, silly.
        s_loopCurrentSound = false;

        if(![m_cocoaNSSound play])
            return false;

        // Process events until the delegate sets s_currentSound to nil
        // and/or a different sound plays.
        while (s_currentSound==m_cocoaNSSound)
            wxEventLoop::GetActive()->Dispatch();
        return true;
    }
}

bool wxSound::IsPlaying()
{
    // Normally you can send a message to a nil object and it will return
    // nil.  That behavior would probably be okay here but in general it's
    // not recommended to send a message to a nil object if the return
    // value is not an object.  Better safe than sorry.
    if(s_currentSound)
        return [s_currentSound isPlaying];
    else
        return false;
}

void wxSound::Stop()
{
    // Clear the looping flag so that if the sound finishes playing before
    // stop is called the sound will already be released and niled.
    s_loopCurrentSound = false;
    [s_currentSound stop];
    /* It's possible that sound:didFinishPlaying: was called and released
       s_currentSound but it doesn't matter since it will have set it to nil */
    if(s_currentSound) wxLogTrace(wxTRACE_COCOA_RetainRelease,wxT("wxSound::Stop [s_currentSound=%p retainCount]=%d (about to release)"),s_currentSound,[s_currentSound retainCount]);
    [s_currentSound release];
    s_currentSound = nil;
}

#endif //wxUSE_SOUND

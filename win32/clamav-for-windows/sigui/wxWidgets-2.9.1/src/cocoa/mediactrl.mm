/////////////////////////////////////////////////////////////////////////////
// Name:        src/cocoa/mediactrl.cpp
// Purpose:     Built-in Media Backends for Cocoa
// Author:      Ryan Norton <wxprojects@comcast.net>
// Modified by:
// Created:     02/03/05
// RCS-ID:      $Id$
// Copyright:   (c) 2004-2005 Ryan Norton, (c) 2005 David Elliot
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

//===========================================================================
//  DECLARATIONS
//===========================================================================

//---------------------------------------------------------------------------
// Pre-compiled header stuff
//---------------------------------------------------------------------------

// For compilers that support precompilation, includes "wx.h".
#include "wx/wxprec.h"

#ifdef __BORLANDC__
#pragma hdrstop
#endif

//---------------------------------------------------------------------------
// Compilation guard
//---------------------------------------------------------------------------
#if wxUSE_MEDIACTRL

#include "wx/mediactrl.h"

#ifndef WX_PRECOMP
    #include "wx/timer.h"
#endif

//===========================================================================
//  BACKEND DECLARATIONS
//===========================================================================

//---------------------------------------------------------------------------
//
//  wxQTMediaBackend
//
//---------------------------------------------------------------------------

//---------------------------------------------------------------------------
//  QT Includes
//---------------------------------------------------------------------------
#include <QuickTime/QuickTime.h>

#include "wx/cocoa/autorelease.h"
#include "wx/cocoa/string.h"

#import <AppKit/NSMovie.h>
#import <AppKit/NSMovieView.h>


class WXDLLIMPEXP_MEDIA wxQTMediaBackend : public wxMediaBackend
{
public:

    wxQTMediaBackend();
    ~wxQTMediaBackend();

    virtual bool CreateControl(wxControl* ctrl, wxWindow* parent,
                                     wxWindowID id,
                                     const wxPoint& pos,
                                     const wxSize& size,
                                     long style,
                                     const wxValidator& validator,
                                     const wxString& name);

    virtual bool Play();
    virtual bool Pause();
    virtual bool Stop();

    virtual bool Load(const wxString& fileName);
    virtual bool Load(const wxURI& location);

    virtual wxMediaState GetState();

    virtual bool SetPosition(wxLongLong where);
    virtual wxLongLong GetPosition();
    virtual wxLongLong GetDuration();

    virtual void Move(int x, int y, int w, int h);
    wxSize GetVideoSize() const;

    virtual double GetPlaybackRate();
    virtual bool SetPlaybackRate(double dRate);

    void Cleanup();
    void FinishLoad();

    wxSize m_bestSize;              //Original movie size
    Movie m_movie;                  //QT Movie handle/instance
    NSMovieView* m_movieview;       //NSMovieView instance
    wxControl* m_ctrl;              //Parent control
    bool m_bVideo;                  //Whether or not we have video
    class _wxQTTimer* m_timer;      //Timer for streaming the movie

    DECLARE_DYNAMIC_CLASS(wxQTMediaBackend);
};


//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
//
// wxQTMediaBackend
//
//+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

IMPLEMENT_DYNAMIC_CLASS(wxQTMediaBackend, wxMediaBackend);

//Time between timer calls
#define MOVIE_DELAY 100

// --------------------------------------------------------------------------
//          wxQTTimer - Handle Asyncronous Playing
// --------------------------------------------------------------------------
class _wxQTTimer : public wxTimer
{
public:
    _wxQTTimer(Movie movie, wxQTMediaBackend* parent) :
        m_movie(movie), m_bPaused(false), m_parent(parent)
    {
    }

    ~_wxQTTimer()
    {
    }

    bool GetPaused() {return m_bPaused;}
    void SetPaused(bool bPaused) {m_bPaused = bPaused;}

    //-----------------------------------------------------------------------
    // _wxQTTimer::Notify
    //
    // 1) Checks to see if the movie is done, and if not continues
    //    streaming the movie
    // 2) Sends the wxEVT_MEDIA_STOP event if we have reached the end of
    //    the movie.
    //-----------------------------------------------------------------------
    void Notify()
    {
        if (!m_bPaused)
        {
            if(!IsMovieDone(m_movie))
                MoviesTask(m_movie, MOVIE_DELAY);
            else
            {
                wxMediaEvent theEvent(wxEVT_MEDIA_STOP,
                                      m_parent->m_ctrl->GetId());
                m_parent->m_ctrl->ProcessEvent(theEvent);

                if(theEvent.IsAllowed())
                {
                    Stop();
                    m_parent->Stop();
                    wxASSERT(::GetMoviesError() == noErr);

                    //send the event to our child
                    wxMediaEvent theEvent(wxEVT_MEDIA_FINISHED,
                                          m_parent->m_ctrl->GetId());
                    m_parent->m_ctrl->ProcessEvent(theEvent);
                }
            }
        }
    }

protected:
    Movie m_movie;                  //Our movie instance
    bool m_bPaused;                 //Whether we are paused or not
    wxQTMediaBackend* m_parent;     //Backend pointer
};

//---------------------------------------------------------------------------
// wxQTMediaBackend Constructor
//
// Sets m_timer to NULL signifying we havn't loaded anything yet
//---------------------------------------------------------------------------
wxQTMediaBackend::wxQTMediaBackend() : m_timer(NULL)
{
}

//---------------------------------------------------------------------------
// wxQTMediaBackend Destructor
//
// 1) Cleans up the QuickTime movie instance
// 2) Decrements the QuickTime reference counter - if this reaches
//    0, QuickTime shuts down
// 3) Decrements the QuickTime Windows Media Layer reference counter -
//    if this reaches 0, QuickTime shuts down the Windows Media Layer
//---------------------------------------------------------------------------
wxQTMediaBackend::~wxQTMediaBackend()
{
    if(m_timer)
        Cleanup();

    //Note that ExitMovies() is not necessary...
    ExitMovies();
}

//---------------------------------------------------------------------------
// wxQTMediaBackend::CreateControl
//
// 1) Intializes QuickTime
// 2) Creates the control window
//---------------------------------------------------------------------------
bool wxQTMediaBackend::CreateControl(wxControl* inctrl, wxWindow* parent,
                                     wxWindowID wid,
                                     const wxPoint& pos,
                                     const wxSize& size,
                                     long style,
                                     const wxValidator& validator,
                                     const wxString& name)
{
    EnterMovies();

    wxMediaCtrl* ctrl = (wxMediaCtrl*) inctrl;

    //Create the control base
    wxASSERT(ctrl->CreateBase(parent,wid,pos,size,style, validator, name));

    //Create the NSMovieView
    ctrl->SetNSView(NULL);
    NSMovieView* theView = [[NSMovieView alloc] initWithFrame: ctrl->MakeDefaultNSRect(size)];
    ctrl->SetNSView(theView);
    [theView release];

    if (parent)
    {
        parent->AddChild(ctrl);
        parent->CocoaAddChild(ctrl);
        ctrl->SetInitialFrameRect(pos,size);
    }

    [theView showController:false adjustingSize:true];
    m_movieview = theView;
    m_ctrl = ctrl;
    return true;
}

//---------------------------------------------------------------------------
// wxQTMediaBackend::Load (file version)
//
// Calls the URI version
//---------------------------------------------------------------------------
bool wxQTMediaBackend::Load(const wxString& fileName)
{
    return Load(
                wxURI(
                    wxString( wxT("file://") ) + fileName
                     )
               );
}

//---------------------------------------------------------------------------
// wxQTMediaBackend::Load (URL Version)
//
// 1) Build an escaped URI from location
// ...
//---------------------------------------------------------------------------
bool wxQTMediaBackend::Load(const wxURI& location)
{
    if(m_timer)
        Cleanup();

    wxString theURI = location.BuildURI();

    [m_movieview setMovie:[[NSMovie alloc] initWithURL: [NSURL URLWithString: wxNSStringWithWxString(theURI)]
                               byReference: YES ] ];

    m_movie = (Movie) [[m_movieview movie] QTMovie];

    //preroll movie for streaming
    //TODO:Async this using threads?
    TimeValue timeNow;
    Fixed playRate;
    timeNow = GetMovieTime(m_movie, NULL);
    playRate = GetMoviePreferredRate(m_movie);
    PrePrerollMovie(m_movie, timeNow, playRate, NULL, NULL);
    PrerollMovie(m_movie, timeNow, playRate);
    SetMovieRate(m_movie, playRate);

    FinishLoad();

    return ::GetMoviesError() == noErr;
}

//---------------------------------------------------------------------------
// wxQTMediaBackend::FinishLoad
//
// 1) Create the movie timer
// 2) Get real size of movie for GetBestSize/sizers
// 3) See if there is video in the movie, and if so then either
//    SetMovieGWorld if < 10.2 or use Native CreateMovieControl
// 4) Set the movie time scale to something usable so that seeking
//    etc.  will work correctly
// 5) Refresh parent window
//---------------------------------------------------------------------------
void wxQTMediaBackend::FinishLoad()
{
    m_timer = new _wxQTTimer(m_movie, (wxQTMediaBackend*) this);
    wxASSERT(m_timer);

    //get the real size of the movie
    Rect outRect;
    ::GetMovieNaturalBoundsRect (m_movie, &outRect);
    wxASSERT(::GetMoviesError() == noErr);

    m_bestSize.x = outRect.right - outRect.left;
    m_bestSize.y = outRect.bottom - outRect.top;

    //we want millisecond precision
    ::SetMovieTimeScale(m_movie, 1000);
    wxASSERT(::GetMoviesError() == noErr);

    //
    //Here, if the parent of the control has a sizer - we
    //tell it to recalculate the size of this control since
    //the user opened a separate media file
    //
    m_ctrl->InvalidateBestSize();
    m_ctrl->GetParent()->Layout();
    m_ctrl->GetParent()->Refresh();
    m_ctrl->GetParent()->Update();
}

//---------------------------------------------------------------------------
// wxQTMediaBackend::Play
//
// 1) Start the QT movie
// 2) Start the movie loading timer
//---------------------------------------------------------------------------
bool wxQTMediaBackend::Play()
{
    ::StartMovie(m_movie);
    m_timer->SetPaused(false);
    m_timer->Start(MOVIE_DELAY, wxTIMER_CONTINUOUS);
    return ::GetMoviesError() == noErr;
}

//---------------------------------------------------------------------------
// wxQTMediaBackend::Pause
//
// 1) Stop the movie
// 2) Stop the movie timer
//---------------------------------------------------------------------------
bool wxQTMediaBackend::Pause()
{
    ::StopMovie(m_movie);
    m_timer->SetPaused(true);
    m_timer->Stop();
    return ::GetMoviesError() == noErr;
}

//---------------------------------------------------------------------------
// wxQTMediaBackend::Stop
//
// 1) Stop the movie
// 2) Stop the movie timer
// 3) Seek to the beginning of the movie
//---------------------------------------------------------------------------
bool wxQTMediaBackend::Stop()
{
    m_timer->SetPaused(false);
    m_timer->Stop();

    ::StopMovie(m_movie);
    if(::GetMoviesError() != noErr)
        return false;

    ::GoToBeginningOfMovie(m_movie);
    return ::GetMoviesError() == noErr;
}

//---------------------------------------------------------------------------
// wxQTMediaBackend::GetPlaybackRate
//
// 1) Get the movie playback rate from ::GetMovieRate
//---------------------------------------------------------------------------
double wxQTMediaBackend::GetPlaybackRate()
{
    return ( ((double)::GetMovieRate(m_movie)) / 0x10000);
}

//---------------------------------------------------------------------------
// wxQTMediaBackend::SetPlaybackRate
//
// 1) Convert dRate to Fixed and Set the movie rate through SetMovieRate
//---------------------------------------------------------------------------
bool wxQTMediaBackend::SetPlaybackRate(double dRate)
{
    ::SetMovieRate(m_movie, (Fixed) (dRate * 0x10000));
    return ::GetMoviesError() == noErr;
}

//---------------------------------------------------------------------------
// wxQTMediaBackend::SetPosition
//
// 1) Create a time record struct (TimeRecord) with appropriate values
// 2) Pass struct to SetMovieTime
//---------------------------------------------------------------------------
bool wxQTMediaBackend::SetPosition(wxLongLong where)
{
    TimeRecord theTimeRecord;
    memset(&theTimeRecord, 0, sizeof(TimeRecord));
    theTimeRecord.value.lo = where.GetValue();
    theTimeRecord.scale = ::GetMovieTimeScale(m_movie);
    theTimeRecord.base = ::GetMovieTimeBase(m_movie);
    ::SetMovieTime(m_movie, &theTimeRecord);

    if (::GetMoviesError() != noErr)
        return false;

    return true;
}

//---------------------------------------------------------------------------
// wxQTMediaBackend::GetPosition
//
// Calls GetMovieTime
//---------------------------------------------------------------------------
wxLongLong wxQTMediaBackend::GetPosition()
{
    return ::GetMovieTime(m_movie, NULL);
}

//---------------------------------------------------------------------------
// wxQTMediaBackend::GetDuration
//
// Calls GetMovieDuration
//---------------------------------------------------------------------------
wxLongLong wxQTMediaBackend::GetDuration()
{
    return ::GetMovieDuration(m_movie);
}

//---------------------------------------------------------------------------
// wxQTMediaBackend::GetState
//
// Determines the current state - the timer keeps track of whether or not
// we are paused or stopped (if the timer is running we are playing)
//---------------------------------------------------------------------------
wxMediaState wxQTMediaBackend::GetState()
{
    if ( !m_timer || (m_timer->IsRunning() == false &&
                      m_timer->GetPaused() == false) )
        return wxMEDIASTATE_STOPPED;

    if( m_timer->IsRunning() == true )
        return wxMEDIASTATE_PLAYING;
    else
        return wxMEDIASTATE_PAUSED;
}

//---------------------------------------------------------------------------
// wxQTMediaBackend::Cleanup
//
// Diposes of the movie timer, Control if native, and stops and disposes
// of the QT movie
//---------------------------------------------------------------------------
void wxQTMediaBackend::Cleanup()
{
    delete m_timer;
    m_timer = NULL;

    [[m_movieview movie] release];
    [m_movieview setMovie:NULL];
}

//---------------------------------------------------------------------------
// wxQTMediaBackend::GetVideoSize
//
// Returns the actual size of the QT movie
//---------------------------------------------------------------------------
wxSize wxQTMediaBackend::GetVideoSize() const
{
    return m_bestSize;
}

//---------------------------------------------------------------------------
// wxQTMediaBackend::Move
//
// Nothin... cocoa takes care of this for us
//---------------------------------------------------------------------------
void wxQTMediaBackend::Move(int x, int y, int w, int h)
{
}


//in source file that contains stuff you don't directly use
#include "wx/html/forcelnk.h"
FORCE_LINK_ME(basewxmediabackends);

#endif //wxUSE_MEDIACTRL

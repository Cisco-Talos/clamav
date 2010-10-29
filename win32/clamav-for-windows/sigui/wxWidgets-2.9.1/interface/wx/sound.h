/////////////////////////////////////////////////////////////////////////////
// Name:        sound.h
// Purpose:     interface of wxSound
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxSound

    This class represents a short sound (loaded from Windows WAV file), that
    can be stored in memory and played.

    Currently this class is implemented on Windows and Unix (and uses either
    Open Sound System or Simple DirectMedia Layer).

    @library{wxadv}
    @category{media}
*/
class wxSound : public wxObject
{
public:
    /**
        Default ctor.
    */
    wxSound();

    /**
        Constructs a wave object from a file or, under Windows, from a Windows
        resource. Call IsOk() to determine whether this succeeded.

        @param fileName
            The filename or Windows resource.
        @param isResource
            @true if fileName is a resource, @false if it is a filename.
    */
    wxSound(const wxString& fileName, bool isResource = false);

    /**
        Destroys the wxSound object.
    */
    virtual ~wxSound();

    /**
        Constructs a wave object from a file or resource.

        @param fileName
            The filename or Windows resource.
        @param isResource
            @true if fileName is a resource, @false if it is a filename.

        @return @true if the call was successful, @false otherwise.
    */
    bool Create(const wxString& fileName, bool isResource = false);

    /**
        Returns @true if the object contains a successfully loaded file or resource,
        @false otherwise.
    */
    bool IsOk() const;

    /**
        Returns @true if a sound is played at the moment.
        This method is currently not implemented under Windows.
    */
    static bool IsPlaying();

    //@{
    /**
        Plays the sound file. If another sound is playing, it will be interrupted.

        Returns @true on success, @false otherwise. Note that in general it is
        possible to delete the object which is being asynchronously played any time
        after calling this function and the sound would continue playing, however this
        currently doesn't work under Windows for sound objects loaded from memory data.

        The possible values for @a flags are:
        - wxSOUND_SYNC: @c Play will block and wait until the sound is replayed.
        - wxSOUND_ASYNC: Sound is played asynchronously, @c Play returns immediately.
        - wxSOUND_ASYNC|wxSOUND_LOOP: Sound is played asynchronously and loops
                                      until another sound is played, Stop() is
                                      called or the program terminates.

        The static form is shorthand for this code:
        @code
        wxSound(filename).Play(flags);
        @endcode
    */
    bool Play(unsigned flags = wxSOUND_ASYNC) const;
    static bool Play(const wxString& filename,
                     unsigned flags = wxSOUND_ASYNC);
    //@}

    /**
        If a sound is played, this function stops it.
    */
    static void Stop();
};


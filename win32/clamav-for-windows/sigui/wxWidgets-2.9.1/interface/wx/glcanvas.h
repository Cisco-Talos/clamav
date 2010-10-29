/////////////////////////////////////////////////////////////////////////////
// Name:        glcanvas.h
// Purpose:     interface of wxGLContext and wxGLCanvas
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxGLContext

    An instance of a wxGLContext represents the state of an OpenGL state
    machine and the connection between OpenGL and the system.

    The OpenGL state includes everything that can be set with the OpenGL API:
    colors, rendering variables, display lists, texture objects, etc. Although
    it is possible to have multiple rendering contexts share display lists in
    order to save resources, this method is hardly used today any more, because
    display lists are only a tiny fraction of the overall state.

    Therefore, one rendering context is usually used with or bound to multiple
    output windows in turn, so that the application has access to the complete
    and identical state while rendering into each window.

    Binding (making current) a rendering context with another instance of a
    wxGLCanvas however works only if the other wxGLCanvas was created with the
    same attributes as the wxGLCanvas from which the wxGLContext was
    initialized. (This applies to sharing display lists among contexts
    analogously.)

    Note that some wxGLContext features are extremely platform-specific - its
    best to check your native platform's glcanvas header (on windows
    include/wx/msw/glcanvas.h) to see what features your native platform
    provides.
    
    wxHAS_OPENGL_ES is defined on platforms that only have this implementation
    available (eg the iPhone) und don't support the full specification.

    @library{wxgl}
    @category{gl}

    @see wxGLCanvas
*/
class wxGLContext : public wxObject
{
public:
    /**
        Constructor.

        @param win
            The canvas that is used to initialize this context. This parameter
            is needed only temporarily, and the caller may do anything with it
            (e.g. destroy the window) after the constructor returned. @n
            It will be possible to bind (make current) this context to any
            other wxGLCanvas that has been created with equivalent attributes
            as win.
        @param other
            Context to share display lists with or @NULL (the default) for no
            sharing.
    */
    wxGLContext(wxGLCanvas* win, const wxGLContext* other = NULL);

    /**
        Makes the OpenGL state that is represented by this rendering context
        current with the wxGLCanvas @e win.

        @note @a win can be a different wxGLCanvas window than the one that was
              passed to the constructor of this rendering context. If @e RC is
              an object of type wxGLContext, the statements
              @e "RC.SetCurrent(win);" and @e "win.SetCurrent(RC);" are
              equivalent, see wxGLCanvas::SetCurrent().
    */
    virtual bool SetCurrent(const wxGLCanvas& win) const;
};

/**
    @anchor wxGL_FLAGS

    Constants for use with wxGLCanvas.

    @note Not all implementations support options such as stereo, auxiliary
          buffers, alpha channel, and accumulator buffer, use
          wxGLCanvas::IsDisplaySupported() to check for individual attributes
          support.
 */
enum
{
    /// Use true color (the default if no attributes at all are specified);
    /// do not use a palette.
    WX_GL_RGBA = 1,

    /// Specifies the number of bits for buffer if not WX_GL_RGBA.
    WX_GL_BUFFER_SIZE,

    /// Must be followed by 0 for main buffer, >0 for overlay, <0 for underlay.
    WX_GL_LEVEL,

    /// Use double buffering if present (on if no attributes specified).
    WX_GL_DOUBLEBUFFER,

    /// Use stereoscopic display.
    WX_GL_STEREO,

    /// Specifies number of auxiliary buffers.
    WX_GL_AUX_BUFFERS,

    /// Use red buffer with most bits (> MIN_RED bits)
    WX_GL_MIN_RED,

    /// Use green buffer with most bits (> MIN_GREEN bits)
    WX_GL_MIN_GREEN,

    /// Use blue buffer with most bits (> MIN_BLUE bits)
    WX_GL_MIN_BLUE,

    /// Use alpha buffer with most bits (> MIN_ALPHA bits)
    WX_GL_MIN_ALPHA,

    /// Specifies number of bits for Z-buffer (typically 0, 16 or 32).
    WX_GL_DEPTH_SIZE,

    /// Specifies number of bits for stencil buffer.
    WX_GL_STENCIL_SIZE,

    /// Specifies minimal number of red accumulator bits.
    WX_GL_MIN_ACCUM_RED,

    /// Specifies minimal number of green accumulator bits.
    WX_GL_MIN_ACCUM_GREEN,

    /// Specifies minimal number of blue accumulator bits.
    WX_GL_MIN_ACCUM_BLUE,

    /// Specifies minimal number of alpha accumulator bits.
    WX_GL_MIN_ACCUM_ALPHA,

    /// 1 for multisampling support (antialiasing)
    WX_GL_SAMPLE_BUFFERS,

    /// 4 for 2x2 antialising supersampling on most graphics cards
    WX_GL_SAMPLES

};

/**
    @class wxGLCanvas

    wxGLCanvas is a class for displaying OpenGL graphics. It is always used in
    conjunction with wxGLContext as the context can only be made current (i.e.
    active for the OpenGL commands) when it is associated to a wxGLCanvas.

    More precisely, you first need to create a wxGLCanvas window and then
    create an instance of a wxGLContext that is initialized with this
    wxGLCanvas and then later use either SetCurrent() with the instance of the
    wxGLContext or wxGLContext::SetCurrent() with the instance of the
    wxGLCanvas (which might be not the same as was used for the creation of the
    context) to bind the OpenGL state that is represented by the rendering
    context to the canvas, and then finally call SwapBuffers() to swap the
    buffers of the OpenGL canvas and thus show your current output.

    Notice that versions of wxWidgets previous to 2.9 used to implicitly create a
    wxGLContext inside wxGLCanvas itself. This is still supported in the
    current version but is deprecated now and will be removed in the future,
    please update your code to create the rendering contexts explicitly.

    To set up the attributes for the canvas (number of bits for the depth
    buffer, number of bits for the stencil buffer and so on) you should set up
    the correct values of the @e attribList parameter. The values that should
    be set up and their meanings will be described below.

    @note
        On those platforms which use a configure script (e.g. Linux and Mac OS)
        OpenGL support is automatically enabled if the relative headers and
        libraries are found.
        To switch it on under the other platforms (e.g. Windows), you need to edit
        the @c setup.h file and set @c wxUSE_GLCANVAS to @c 1 and then also pass
        @c USE_OPENGL=1 to the make utility. You may also need to add @c opengl32.lib
        and @c glu32.lib to the list of the libraries your program is linked with.

    @library{wxgl}
    @category{gl}

    @see wxGLContext
*/
class wxGLCanvas : public wxWindow
{
public:
    /**
        Creates a window with the given parameters. Notice that you need to
        create and use a wxGLContext to output to this window.

        If @a attribList is not specified, double buffered RGBA mode is used.

        @param parent
            Pointer to a parent window.
        @param id
            Window identifier. If -1, will automatically create an identifier.
        @param pos
            Window position. wxDefaultPosition is (-1, -1) which indicates that
            wxWidgets should generate a default position for the window.
        @param size
            Window size. wxDefaultSize is (-1, -1) which indicates that
            wxWidgets should generate a default size for the window. If no
            suitable size can be found, the window will be sized to 20x20
            pixels so that the window is visible but obviously not correctly
            sized.
        @param style
            Window style.
        @param name
            Window name.
        @param attribList
            Array of integers. With this parameter you can set the device
            context attributes associated to this window. This array is
            zero-terminated: it should be set up using @ref wxGL_FLAGS
            constants. If a constant should be followed by a value, put it in
            the next array position. For example, WX_GL_DEPTH_SIZE should be
            followed by the value that indicates the number of bits for the
            depth buffer, e.g:
            @code
            attribList[n++] = WX_GL_DEPTH_SIZE;
            attribList[n++] = 32;
            attribList[n] = 0; // terminate the list
            @endcode
            If the attribute list is not specified at all, i.e. if this
            parameter is @NULL, the default attributes including WX_GL_RGBA and
            WX_GL_DOUBLEBUFFER are used. But notice that if you do specify some
            attributes you also need to explicitly include these two default
            attributes in the list if you need them.
        @param palette
            Palette for indexed colour (i.e. non WX_GL_RGBA) mode. Ignored
            under most platforms.
    */
    wxGLCanvas(wxWindow* parent, wxWindowID id = wxID_ANY,
               const int* attribList = NULL,
               const wxPoint& pos = wxDefaultPosition,
               const wxSize& size = wxDefaultSize,
               long style = 0,
               const wxString& name = "GLCanvas",
               const wxPalette& palette = wxNullPalette);

    /**
        Determines if a canvas having the specified attributes is available.

        @param attribList
            See @a attribList for wxGLCanvas().

        @return @true if attributes are supported.
    */
    static bool IsDisplaySupported(const int* attribList);

    /**
        Returns true if the extension with given name is supported

        Notice that while this function is implemented for all of GLX, WGL and
        AGL the extensions names are usually not the same for different
        platforms and so the code using it still usually uses conditional
        compilation.
    */
    static bool IsExtensionSupported(const char *extension);

    /**
        Sets the current colour for this window (using @c glcolor3f()), using
        the wxWidgets colour database to find a named colour.
    */
    bool SetColour(const wxString& colour);

    /**
        Makes the OpenGL state that is represented by the OpenGL rendering
        context @a context current, i.e. it will be used by all subsequent
        OpenGL calls.

        This is equivalent to wxGLContext::SetCurrent() called with this window
        as parameter.

        @note This function may only be called when the window is shown on
              screen, in particular it can't usually be called from the
              constructor as the window isn't yet shown at this moment.

        @return @false if an error occurred.
    */
    bool SetCurrent(const wxGLContext& context) const;

    /**
        Swaps the double-buffer of this window, making the back-buffer the
        front-buffer and vice versa, so that the output of the previous OpenGL
        commands is displayed on the window.

        @return @false if an error occurred.
    */
    virtual bool SwapBuffers();
};

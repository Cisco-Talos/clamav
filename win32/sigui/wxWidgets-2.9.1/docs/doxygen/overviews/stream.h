/////////////////////////////////////////////////////////////////////////////
// Name:        stream.h
// Purpose:     stream classes overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_stream Stream classes overview

Classes:
@li wxStreamBase
@li wxStreamBuffer
@li wxInputStream
@li wxOutputStream
@li wxFilterInputStream
@li wxFilterOutputStream
@li wxFileInputStream
@li wxFileOutputStream
@li wxTextInputStream
@li wxTextOutputStream
@li wxDataInputStream
@li wxDataOutputStream

@li @ref overview_stream_intro
@li @ref overview_stream_example

<hr>



@section overview_stream_intro Introduction

@subsection overview_stream_intro_std wxWidgets and Standard Streams

wxWidgets provides its own set of stream classes in order to support platforms
not providing standard C++ streams implementation and also to make it possible
to provide binary versions of wxWidgets application not depending on any
particular standard library version. The wxWidgets stream classes also provide
some functionality not available in the standard library such as support for
several compression formats and possibility to work with sockets or text
controls (for output only in the latter case).

Nevertheless wxWidgets programs can also use standard stream classes and are
encouraged to do so if the above considerations don't apply. Moreover,
wxStdInputStream and wxStdOutputStream classes are provided to provide a degree
of interoperability between the two and make it possible to use any wxWidgets
stream as a standard stream (the converse possibility to use a standard stream
as a wxWidgets stream is planned for a future release).


@subsection overview_stream_intro_overview Stream Classes

wxStream classes are divided in two main groups:

@li The core: wxStreamBase, wxStreamBuffer, wxInputStream, wxOutputStream,
    wxFilterInputStream, wxFilterOutputStream
@li The "IO" classes: wxSocketInputStream, wxSocketOutputStream,
    wxFileInputStream, wxFileOutputStream, ...
@li Classes for reading text or binary data from a particular stream
    such as wxTextInputStream, wxTextOutputStream, wxDataInputStream
    and wxDataOutputStream

wxStreamBase is the base definition of a stream. It defines, for example, the
API of OnSysRead(), OnSysWrite(), OnSysSeek() and OnSysTell(). These functions are
really implemented by the "IO" classes.
wxInputStream and wxOutputStream classes inherit from wxStreamBase and provide
specialized methods for input and output.

wxStreamBuffer is a cache manager for wxStreamBase: it manages a stream buffer
linked to a stream. One stream can have multiple stream buffers but one stream
has always one autoinitialized stream buffer.

wxInputStream is the base class for read-only streams. It implements Read(),
SeekI() (I for Input), and all read or IO generic related functions.
wxOutputStream does the same thing for write-only streams.

wxFilterInputStream and wxFileterOutputStream are the base class definitions for
stream filtering.
Stream filtering means a stream which does no syscall but filters data which
are passed to it and then pass them to another stream.
For example, wxZLibInputStream is an inline stream decompressor.

The "IO" classes implements the specific parts of the stream. This could be
nothing in the case of wxMemoryInputStream and wxMemoryOutputStream which base
themselves on wxStreamBuffer.
This could also be a simple link to the true syscall (for example read(...), write(...)).


@section overview_stream_example Example

Usage is simple. We can take the example of wxFileInputStream and here is some
sample code:

@code
...
// The constructor initializes the stream buffer and open the file descriptor
// associated to the name of the file.
wxFileInputStream in_stream("the_file_to_be_read");

// Ok, read some bytes ... nb_datas is expressed in bytes.
in_stream.Read(data, nb_datas);
if (in_stream.LastError() != wxSTREAM_NOERROR) {
    // Oh oh, something bad happens.
    // For a complete list, look into the documentation at wxStreamBase.
}

// You can also inline all like this.
if (in_stream.Read(data, nb_datas).LastError() != wxSTREAM_NOERROR) {
    // Do something.
}

// You can also get the last number of bytes REALLY put into the buffer.
size_t really_read = in_stream.LastRead();

// Ok, moves to the beginning of the stream. SeekI returns the last position
// in the stream counted from the beginning.
off_t old_position = in_stream.SeekI(0, wxFromBeginning);

// What is my current position ?
off_t position = in_stream.TellI();

// wxFileInputStream will close the file descriptor on destruction.
@endcode

*/


/////////////////////////////////////////////////////////////////////////////
// Name:        datstrm.h
// Purpose:     interface of wxDataInputStream and wxDataOutputStream
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxDataOutputStream

    This class provides functions that write binary data types in a portable
    way. Data can be written in either big-endian or little-endian format,
    little-endian being the default on all architectures.

    If you want to write data to text files (or streams) use wxTextOutputStream
    instead.

    The "<<" operator is overloaded and you can use this class like a standard
    C++ iostream. See wxDataInputStream for its usage and caveats.

    @library{wxbase}
    @category{streams}

    @see wxDataInputStream
*/
class wxDataOutputStream
{
public:
    /**
        Constructs a datastream object from an output stream.
        Only write methods will be available.

        Note that the @a conv parameter is only available in Unicode builds of wxWidgets.

        @param stream
            The output stream.
        @param conv
            Charset conversion object object used to encoding Unicode strings
            before writing them to the stream in Unicode mode (see
            WriteString() for a detailed description). Note that you must not
            destroy @a conv before you destroy this wxDataOutputStream
            instance! It is recommended to use the default value (UTF-8).
    */
    wxDataOutputStream(wxOutputStream& stream,
                       const wxMBConv& conv = wxConvUTF8);

    /**
        Destroys the wxDataOutputStream object.
    */
    ~wxDataOutputStream();

    /**
        If @a be_order is @true, all data will be written in big-endian order,
        e.g. for reading on a Sparc or from Java-Streams (which always use
        big-endian order), otherwise data will be written in little-endian
        order.
    */
    void BigEndianOrdered(bool be_order);
    
    /**
       Returns the current text conversion class used for
       writing strings.
    */
    wxMBConv *GetConv() const;

    /** 
       Sets the text conversion class used for writing strings.
    */
    void SetConv( const wxMBConv &conv );
    
    /**
        Writes the single byte @a i8 to the stream.
    */
    void Write8(wxUint8 i8);
    /**
        Writes an array of bytes to the stream. The amount of bytes to write is
        specified with the @a size variable.
    */
    void Write8(const wxUint8* buffer, size_t size);

    /**
        Writes the 16 bit unsigned integer @a i16 to the stream.
    */
    void Write16(wxUint16 i16);
    /**
        Writes an array of 16 bit unsigned integer to the stream. The amount of
        16 bit unsigned integer to write is specified with the @a size variable.
    */
    void Write16(const wxUint16* buffer, size_t size);

    /**
        Writes the 32 bit unsigned integer @a i32 to the stream.
    */
    void Write32(wxUint32 i32);
    /**
        Writes an array of 32 bit unsigned integer to the stream. The amount of
        32 bit unsigned integer to write is specified with the @a size variable.
    */
    void Write32(const wxUint32* buffer, size_t size);

    /**
        Writes the 64 bit unsigned integer @a i64 to the stream.
    */
    void Write64(wxUint64 i64);
    /**
        Writes an array of 64 bit unsigned integer to the stream. The amount of
        64 bit unsigned integer to write is specified with the @a size variable.
    */
    void Write64(const wxUint64* buffer, size_t size);

    /**
        Writes the double @a f to the stream using the IEEE format.
    */
    void WriteDouble(double f);
    /**
        Writes an array of double to the stream. The amount of double to write is
        specified with the @a size variable.
    */
    void WriteDouble(const double* buffer, size_t size);

    /**
        Writes @a string to the stream. Actually, this method writes the size
        of the string before writing @a string itself.

        In ANSI build of wxWidgets, the string is written to the stream in
        exactly same way it is represented in memory. In Unicode build,
        however, the string is first converted to multibyte representation with
        @e conv object passed to stream's constructor (consequently, ANSI
        applications can read data written by Unicode application, as long as
        they agree on encoding) and this representation is written to the
        stream. UTF-8 is used by default.
    */
    void WriteString(const wxString& string);
};



/**
    @class wxDataInputStream

    This class provides functions that read binary data types in a portable
    way. Data can be read in either big-endian or little-endian format,
    little-endian being the default on all architectures.

    If you want to read data from text files (or streams) use wxTextInputStream
    instead.

    The ">>" operator is overloaded and you can use this class like a standard
    C++ iostream. Note, however, that the arguments are the fixed size types
    wxUint32, wxInt32 etc and on a typical 32-bit computer, none of these match
    to the "long" type (wxInt32 is defined as signed int on 32-bit
    architectures) so that you cannot use long. To avoid problems (here and
    elsewhere), make use of the wxInt32, wxUint32, etc types.

    For example:

    @code
    wxFileInputStream input( "mytext.dat" );
    wxDataInputStream store( input );
    wxUint8 i1;
    float f2;
    wxString line;

    store >> i1;       // read a 8 bit integer.
    store >> i1 >> f2; // read a 8 bit integer followed by float.
    store >> line;     // read a text line
    @endcode

    @library{wxbase}
    @category{streams}

    @see wxDataOutputStream
*/
class wxDataInputStream
{
public:
    /**
        Constructs a datastream object from an input stream.
        Only read methods will be available.

        Note that the @a conv parameter is only available in Unicode builds of wxWidgets.

        @param stream
            The input stream.
        @param conv
            Charset conversion object object used to decode strings in Unicode
            mode (see ReadString() for a detailed description). Note that you
            must not destroy @a conv before you destroy this wxDataInputStream
            instance!
    */
    wxDataInputStream(wxInputStream& stream,
                      const wxMBConv& conv = wxConvUTF8 );

    /**
        Destroys the wxDataInputStream object.
    */
    ~wxDataInputStream();

    /**
        If @a be_order is @true, all data will be read in big-endian order,
        such as written by programs on a big endian architecture (e.g. Sparc)
        or written by Java-Streams (which always use big-endian order).
    */
    void BigEndianOrdered(bool be_order);

    
    /**
       Returns the current text conversion class used for
       reading strings.
    */
    wxMBConv *GetConv() const;
    
    /**
        Reads a single byte from the stream.
    */
    wxUint8 Read8();
    /**
        Reads bytes from the stream in a specified buffer. The amount of bytes
        to read is specified by the @a size variable.
    */
    void Read8(wxUint8* buffer, size_t size);

    /**
        Reads a 16 bit unsigned integer from the stream.
    */
    wxUint16 Read16();
    /**
        Reads 16 bit unsigned integers from the stream in a specified buffer.
        The amount of 16 bit unsigned integers to read is specified by the
        @a size variable.
    */
    void Read16(wxUint16* buffer, size_t size);

    /**
        Reads a 32 bit unsigned integer from the stream.
    */
    wxUint32 Read32();
    /**
        Reads 32 bit unsigned integers from the stream in a specified buffer.
        The amount of 32 bit unsigned integers to read is specified by the
        @a size variable.
    */
    void Read32(wxUint32* buffer, size_t size);

    /**
        Reads a 64 bit unsigned integer from the stream.
    */
    wxUint64 Read64();
    /**
        Reads 64 bit unsigned integers from the stream in a specified buffer.
        The amount of 64 bit unsigned integers to read is specified by the
        @a size variable.
    */
    void Read64(wxUint64* buffer, size_t size);

    /**
        Reads a double (IEEE encoded) from the stream.
    */
    double ReadDouble();
    /**
        Reads double data (IEEE encoded) from the stream in a specified buffer.
        The amount of doubles to read is specified by the @a size variable.
    */
    void ReadDouble(double* buffer, size_t size);

    /**
        Reads a string from a stream. Actually, this function first reads a
        long integer specifying the length of the string (without the last null
        character) and then reads the string.

        In Unicode build of wxWidgets, the fuction first reads multibyte
        (char*) string from the stream and then converts it to Unicode using
        the @e conv object passed to constructor and returns the result as
        wxString. You are responsible for using the same convertor as when
        writing the stream.

        @see wxDataOutputStream::WriteString()
    */
    wxString ReadString();

    /** 
       Sets the text conversion class used for reading strings.
    */
    void SetConv( const wxMBConv &conv );
};


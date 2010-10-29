/////////////////////////////////////////////////////////////////////////////
// Name:        ffile.h
// Purpose:     interface of wxFFile
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////



/**
    Values used for both wxFile and wxFFile.

    @todo make the value names uppercase
*/
enum wxSeekMode
{
  wxFromStart,
  wxFromCurrent,
  wxFromEnd
};

/**
    See wxFFile::GetKind().
*/
enum wxFileKind
{
  wxFILE_KIND_UNKNOWN,
  wxFILE_KIND_DISK,     /**< A file supporting seeking to arbitrary offsets. */
  wxFILE_KIND_TERMINAL, /**< A terminal. */
  wxFILE_KIND_PIPE      /**< A pipe. */
};


/**
    @class wxFFile

    wxFFile implements buffered file I/O.

    This is a very small class designed to minimize the overhead of using it - in fact,
    there is hardly any overhead at all, but using it brings you automatic error checking
    and hides differences between platforms and compilers.

    It wraps inside it a @c FILE * handle used by standard C IO library (also known as @c stdio).

    @library{wxbase}
    @category{file}

    @see wxFFile::IsOpened
*/
class wxFFile
{
public:
    wxFFile();

    /**
        Opens a file with the given file pointer, which has already been opened.

        @param fp
            An existing file descriptor, such as stderr.
    */
    wxFFile(FILE* fp);

    /**
        Opens a file with the given mode.
        As there is no way to return whether the operation was successful or not from
        the constructor you should test the return value of IsOpened() to check that it
        didn't fail.

        @param filename
            The filename.
        @param mode
            The mode in which to open the file using standard C strings.
            Note that you should use "b" flag if you use binary files under Windows
            or the results might be unexpected due to automatic newline conversion done
            for the text files.
    */
    wxFFile(const wxString& filename, const wxString& mode = "r");


    /**
        Destructor will close the file.

        @note it is not virtual so you should @e not derive from wxFFile!
    */
    ~wxFFile();

    /**
        Attaches an existing file pointer to the wxFFile object.

        The descriptor should be already opened and it will be closed by wxFFile object.
    */
    void Attach(FILE* fp, const wxString& name = wxEmptyString);

    /**
        Closes the file and returns @true on success.
    */
    bool Close();

    /**
        Get back a file pointer from wxFFile object -- the caller is responsible for
        closing the file if this descriptor is opened.

        IsOpened() will return @false after call to Detach().
    */
    void Detach();

    /**
        Returns @true if the an attempt has been made to read @e past
        the end of the file.

        Note that the behaviour of the file descriptor based class  wxFile is different as
        wxFile::Eof() will return @true here as soon as the last byte of the file has been read.

        Also note that this method may only be called for opened files and may crash if
        the file is not opened.

        @todo THIS METHOD MAY CRASH? DOESN'T SOUND GOOD

        @see IsOpened()
    */
    bool Eof() const;

    /**
        Returns @true if an error has occurred on this file, similar to the standard
        @c ferror() function.

        Please note that this method may only be called for opened files and may crash
        if the file is not opened.

        @todo THIS METHOD MAY CRASH? DOESN'T SOUND GOOD

        @see IsOpened()
    */
    bool Error() const;

    /**
        Flushes the file and returns @true on success.
    */
    bool Flush();

    /**
        Returns the type of the file.

        @see wxFileKind
    */
    wxFileKind GetKind() const;

    /**
        Returns @true if the file is opened.

        Most of the methods of this class may only be used for an opened file.
    */
    bool IsOpened() const;

    /**
        Returns the length of the file.
    */
    wxFileOffset Length() const;

    /**
        Opens the file, returning @true if successful.

        @param filename
            The filename.
        @param mode
            The mode in which to open the file.
    */
    bool Open(const wxString& filename, const wxString& mode = "r");

    /**
        Reads the specified number of bytes into a buffer, returning the actual number read.

        @param buffer
            A buffer to receive the data.
        @param count
            The number of bytes to read.

        @return The number of bytes read.
    */
    size_t Read(void* buffer, size_t count);

    /**
        Reads the entire contents of the file into a string.

        @param str
            String to read data into.
        @param conv
            Conversion object to use in Unicode build; by default supposes
            that file contents is encoded in UTF-8.

        @return @true if file was read successfully, @false otherwise.
    */
    bool ReadAll(wxString* str, const wxMBConv& conv = wxConvAuto());

    /**
        Seeks to the specified position and returns @true on success.

        @param ofs
            Offset to seek to.
        @param mode
            One of wxFromStart, wxFromEnd, wxFromCurrent.
    */
    bool Seek(wxFileOffset ofs, wxSeekMode mode = wxFromStart);

    /**
        Moves the file pointer to the specified number of bytes before the end of the
        file and returns @true on success.

        @param ofs
            Number of bytes before the end of the file.
    */
    bool SeekEnd(wxFileOffset ofs = 0);

    /**
        Returns the current position.
    */
    wxFileOffset Tell() const;

    /**
        Writes the contents of the string to the file, returns @true on success.

        The second argument is only meaningful in Unicode build of wxWidgets when
        @a conv is used to convert @a str to multibyte representation.
    */
    bool Write(const wxString& str, const wxMBConv& conv = wxConvAuto());

    /**
        Writes the specified number of bytes from a buffer.

        @param buffer
            A buffer containing the data.
        @param count
            The number of bytes to write.

        @return The number of bytes written.
    */
    size_t Write(const void* buffer, size_t count);

    /**
        Returns the file pointer associated with the file.
    */
    FILE* fp() const;
};


/////////////////////////////////////////////////////////////////////////////
// Name:        protocol/http.h
// Purpose:     interface of wxHTTP
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**
    @class wxHTTP

    wxHTTP can be used to establish a connection to an HTTP server.

    wxHTTP can thus be used to create a (basic) HTTP @b client.

    @library{wxnet}
    @category{net}

    @see wxSocketBase, wxURL
*/
class wxHTTP : public wxProtocol
{
public:
    /**
        Default constructor.
    */
    wxHTTP();

    /**
        Destructor will close the connection if connected.
    */
    virtual ~wxHTTP();

    //@{
    /**
        Connect to the HTTP server.

        By default, connection is made to the port 80 of the specified @a host.
        You may connect to a non-default port by specifying it explicitly using
        the second overload.

        Currently wxHTTP only supports IPv4.

        For the overload taking wxSockAddress, the @a wait argument is ignored.
     */
    virtual bool Connect(const wxString& host);
    virtual bool Connect(const wxString& host, unsigned short port);
    virtual bool Connect(const wxSockAddress& addr, bool wait);
    //@}

    /**
        Returns the data attached with a field whose name is specified by @a header.
        If the field doesn't exist, it will return an empty string and not a @NULL string.

        @note
        The header is not case-sensitive, i.e. "CONTENT-TYPE" and "content-type"
        represent the same header.
    */
    wxString GetHeader(const wxString& header) const;

    /**
        Creates a new input stream on the specified path.

        Notice that this stream is unseekable, i.e. SeekI() and TellI() methods
        shouldn't be used.

        Note that you can still know the size of the file you are getting using
        wxStreamBase::GetSize(). However there is a limitation: in HTTP protocol,
        the size is not always specified so sometimes @c (size_t)-1 can returned to
        indicate that the size is unknown.
        In such case, you may want to use wxInputStream::LastRead() method in a loop
        to get the total size.

        @return Returns the initialized stream. You must delete it yourself
                 once you don't use it anymore and this must be done before
                 the wxHTTP object itself is destroyed. The destructor
                 closes the network connection. The next time you will
                 try to get a file the network connection will have to
                 be reestablished, but you don't have to take care of
                 this since wxHTTP reestablishes it automatically.

        @see wxInputStream
    */
    virtual wxInputStream* GetInputStream(const wxString& path);

    /**
        Returns the HTTP response code returned by the server.

        Please refer to RFC 2616 for the list of responses.
    */
    int GetResponse() const;

    /**
        It sets data of a field to be sent during the next request to the HTTP server.

        The field name is specified by @a header and the content by @a h_data.
        This is a low level function and it assumes that you know what you are doing.
    */
    void SetHeader(const wxString& header, const wxString& h_data);

    /**
        Returns the value of a cookie.
    */

    wxString GetCookie(const wxString& cookie) const;

    /**
        Returns @true if there were cookies.
    */
    bool HasCookies() const;

    /**
        Set the data to be posted to the server.

        If a non-empty string is passed to this method, the next request will
        be an HTTP @c POST instead of the default HTTP @c GET and the data from
        @a post_buf will be posted as the body of this request.
     */
    void SetPostBuffer(const wxString& post_buf);
};


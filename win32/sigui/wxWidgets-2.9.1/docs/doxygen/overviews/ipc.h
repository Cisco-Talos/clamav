/////////////////////////////////////////////////////////////////////////////
// Name:        ipc.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_ipc Interprocess Communication

Classes: wxServer, wxConnection, wxClient

@li @ref overview_ipc_datatransfer
@li @ref overview_ipc_examples
@li @ref overview_ipc_dde


<hr>


wxWidgets has a number of different classes to help with interprocess
communication and network programming. This section only discusses one family
of classes -- the DDE-like protocol -- but here's a list of other useful
classes:

@li wxSocketEvent, wxSocketBase, wxSocketClient, wxSocketServer - Classes for
    the low-level TCP/IP API.
@li wxProtocol, wxURL, wxFTP, wxHTTP - Classes for programming popular
    Internet protocols.

wxWidgets' DDE-like protocol is a high-level protocol based on Windows DDE.
There are two implementations of this DDE-like protocol: one using real DDE
running on Windows only, and another using TCP/IP (sockets) that runs on most
platforms. Since the API and virtually all of the behaviour is the same apart
from the names of the classes, you should find it easy to switch between the
two implementations.

Notice that by including @c @<wx/ipc.h@> you may define convenient synonyms for
the IPC classes: wxServer for either wxDDEServer or wxTCPServer depending on
whether DDE-based or socket-based implementation is used and the same thing for
wxClient and wxConnection.

By default, the DDE implementation is used under Windows. DDE works within one
computer only. If you want to use IPC between different workstations you should
define @c wxUSE_DDE_FOR_IPC as 0 before including this header -- this will
force using TCP/IP implementation even under Windows.

The following description refers to wxWidgets, but remember that the equivalent
wxTCP* and wxDDE* classes can be used in much the same way.

Three classes are central to the DDE-like API:

@li wxClient - This represents the client application, and is used only within
    a client program.
@li wxServer - This represents the server application, and is used only within
    a server program.
@li wxConnection - This represents the connection from the client to the
    server. Both the client and the server use an instance of this class, one
    per connection. Most DDE transactions operate on this object.

Messages between applications are usually identified by three variables:
connection object, topic name and item name.  A data string is a fourth element
of some messages. To create a connection (a conversation in Windows parlance),
the client application uses wxClient::MakeConnection to send a message to the
server object, with a string service name to identify the server and a topic
name to identify the topic for the duration of the connection. Under Unix, the
service name may be either an integer port identifier in which case an Internet
domain socket will be used for the communications or a valid file name (which
shouldn't exist and will be deleted afterwards) in which case a Unix domain
socket is created.

<b>SECURITY NOTE:</b> Using Internet domain sockets is extremely insecure for
IPC as there is absolutely no access control for them, use Unix domain sockets
whenever possible!

The server then responds and either vetoes the connection or allows it. If
allowed, both the server and client objects create wxConnection objects which
persist until the connection is closed. The connection object is then used for
sending and receiving subsequent messages between client and server -
overriding virtual functions in your class derived from wxConnection allows you
to handle the DDE messages.

To create a working server, the programmer must:

@li Derive a class from wxConnection, providing handlers for various messages
    sent to the server side of a wxConnection (e.g. OnExecute, OnRequest,
    OnPoke). Only the handlers actually required by the application need to be
    overridden.
@li Derive a class from wxServer, overriding OnAcceptConnection to accept or
    reject a connection on the basis of the topic argument. This member must
    create and return an instance of the derived connection class if the
    connection is accepted.
@li Create an instance of your server object and call Create to activate it,
    giving it a service name.

To create a working client, the programmer must:

@li Derive a class from wxConnection, providing handlers for various messages
    sent to the client side of a wxConnection (e.g. OnAdvise). Only the
    handlers actually required by the application need to be overridden.
@li Derive a class from wxClient, overriding OnMakeConnection to create and
    return an instance of the derived connection class.
@li Create an instance of your client object.
@li When appropriate, create a new connection using wxClient::MakeConnection,
    with arguments host name (processed in Unix only, use 'localhost' for local
    computer), service name, and topic name for this connection. The client
    object will call OnMakeConnection to create a connection object of the
    derived class if the connection is successful.
@li Use the wxConnection member functions to send messages to the server.


@section overview_ipc_datatransfer Data Transfer

These are the ways that data can be transferred from one application to
another. These are methods of wxConnection.

@li <b>Execute:</b> the client calls the server with a data string representing
    a command to be executed. This succeeds or fails, depending on the server's
    willingness to answer. If the client wants to find the result of the
    Execute command other than success or failure, it has to explicitly call
    Request.
@li <b>Request:</b> the client asks the server for a particular data string
    associated with a given item string. If the server is unwilling to reply,
    the return value is @NULL. Otherwise, the return value is a string
    (actually a pointer to the connection buffer, so it should not be
    deallocated by the application).
@li <b>Poke:</b> The client sends a data string associated with an item string
    directly to the server. This succeeds or fails.
@li <b>Advise:</b> The client asks to be advised of any change in data
    associated with a particular item. If the server agrees, the server will
    send an OnAdvise message to the client along with the item and data.

The default data type is wxCF_TEXT (ASCII text), and the default data size is
the length of the null-terminated string. Windows-specific data types could
also be used on the PC.


@section overview_ipc_examples Examples

See the sample programs @e server and @e client in the IPC samples directory.
Run the server, then the client. This demonstrates using the Execute, Request,
and Poke commands from the client, together with an Advise loop: selecting an
item in the server list box causes that item to be highlighted in the client
list box.


@section overview_ipc_dde More DDE Details

A wxClient object initiates the client part of a client-server DDE-like
(Dynamic Data Exchange) conversation (available in both Windows and Unix).

To create a client which can communicate with a suitable server, you need to
derive a class from wxConnection and another from wxClient. The custom
wxConnection class will receive communications in a 'conversation' with a
server.  and the custom wxServer is required so that a user-overridden
wxClient::OnMakeConnection member can return a wxConnection of the required
class, when a connection is made.

For example:

@code
class MyConnection: public wxConnection
{
public:
    MyConnection(void)::wxConnection() { }
    ~MyConnection(void) { }

    bool OnAdvise(const wxString& topic, const wxString& item, char *data,
                  int size, wxIPCFormat format)
    {
        wxMessageBox(topic, data);
    }
};

class MyClient: public wxClient
{
public:
    MyClient(void) { }

    wxConnectionBase* OnMakeConnection(void)
    {
        return new MyConnection;
    }
};
@endcode

Here, @e MyConnection will respond to OnAdvise messages sent by the server by
displaying a message box.

When the client application starts, it must create an instance of the derived
wxClient. In the following, command line arguments are used to pass the host
name (the name of the machine the server is running on) and the server name
(identifying the server process). Calling wxClient::MakeConnection implicitly
creates an instance of @e MyConnection if the request for a connection is
accepted, and the client then requests an @e Advise loop from the server (an
Advise loop is where the server calls the client when data has changed).

@code
wxString server = "4242";
wxString hostName;
wxGetHostName(hostName);

// Create a new client
MyClient *client = new MyClient;
connection = (MyConnection *)client->MakeConnection(hostName, server, "IPC TEST");

if (!connection)
{
    wxMessageBox("Failed to make connection to server", "Client Demo Error");
    return NULL;
}

connection->StartAdvise("Item");
@endcode

*/


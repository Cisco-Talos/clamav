/////////////////////////////////////////////////////////////////////////////
// Name:        archive.h
// Purpose:     topic overview
// Author:      wxWidgets team
// RCS-ID:      $Id$
// Licence:     wxWindows licence
/////////////////////////////////////////////////////////////////////////////

/**

@page overview_archive Archive Formats

The archive classes handle archive formats such as zip, tar, rar and cab.
Currently wxZip and wxTar classes are included.

For each archive type, there are the following classes (using zip here as an
example):

@li wxZipInputStream: Input stream
@li wxZipOutputStream: Output stream
@li wxZipEntry: Holds meta-data for an entry (e.g. filename, timestamp, etc.)

There are also abstract wxArchive classes that can be used to write code that
can handle any of the archive types, see @ref overview_archive_generic.

Also see wxFileSystem for a higher level interface that can handle archive
files in a generic way.

The classes are designed to handle archives on both seekable streams such as
disk files, or non-seekable streams such as pipes and sockets (see
@ref overview_archive_noseek).

See also wxFileSystem.

@li @ref overview_archive_create
@li @ref overview_archive_extract
@li @ref overview_archive_modify
@li @ref overview_archive_byname
@li @ref overview_archive_generic
@li @ref overview_archive_noseek


<hr>


@section overview_archive_create Creating an Archive

Call wxArchiveOutputStream::PutNextEntry() to create each new entry in the
archive, then write the entry's data. Another call to PutNextEntry() closes the
current entry and begins the next. For example:

@code
wxFFileOutputStream out(wxT("test.zip"));
wxZipOutputStream zip(out);
wxTextOutputStream txt(zip);
wxString sep(wxFileName::GetPathSeparator());

zip.PutNextEntry(wxT("entry1.txt"));
txt << wxT("Some text for entry1.txt\n");

zip.PutNextEntry(wxT("subdir") + sep + wxT("entry2.txt"));
txt << wxT("Some text for subdir/entry2.txt\n");
@endcode

The name of each entry can be a full path, which makes it possible to store
entries in subdirectories.


@section overview_archive_extract Extracting an Archive

wxArchiveInputStream::GetNextEntry() returns a pointer to entry object
containing the meta-data for the next entry in the archive (and gives away
ownership).

Reading from the input stream then returns the entry's data. Eof() becomes
@true after an attempt has been made to read past the end of the entry's data.

When there are no more entries, GetNextEntry() returns @NULL and sets Eof().

@code
auto_ptr<wxZipEntry> entry;

wxFFileInputStream in(wxT("test.zip"));
wxZipInputStream zip(in);

while (entry.reset(zip.GetNextEntry()), entry.get() != NULL)
{
    // access meta-data
    wxString name = entry->GetName();
    // read 'zip' to access the entry's data
}
@endcode



@section overview_archive_modify Modifying an Archive

To modify an existing archive, write a new copy of the archive to a new file,
making any necessary changes along the way and transferring any unchanged
entries using wxArchiveOutputStream::CopyEntry().

For archive types which compress entry data, CopyEntry() is likely to be much
more efficient than transferring the data using Read() and Write() since it
will copy them without decompressing and recompressing them.

In general modifications are not possible without rewriting the archive, though
it may be possible in some limited cases. Even then, rewriting the archive is
usually a better choice since a failure can be handled without losing the whole
archive. wxTempFileOutputStream can be helpful to do this.

For example to delete all entries matching the pattern "*.txt":

@code
auto_ptr<wxFFileInputStream> in(new wxFFileInputStream(wxT("test.zip")));
wxTempFileOutputStream out(wxT("test.zip"));

wxZipInputStream inzip(*in);
wxZipOutputStream outzip(out);

auto_ptr<wxZipEntry> entry;

// transfer any meta-data for the archive as a whole (the zip comment
// in the case of zip)
outzip.CopyArchiveMetaData(inzip);

// call CopyEntry for each entry except those matching the pattern
while (entry.reset(inzip.GetNextEntry()), entry.get() != NULL)
    if (!entry->GetName().Matches(wxT("*.txt")))
        if (!outzip.CopyEntry(entry.release(), inzip))
            break;

// close the input stream by releasing the pointer to it, do this
// before closing the output stream so that the file can be replaced
in.reset();

// you can check for success as follows
bool success = inzip.Eof() && outzip.Close() && out.Commit();
@endcode



@section overview_archive_byname Looking Up an Archive Entry by Name

Also see wxFileSystem for a higher level interface that is more convenient for
accessing archive entries by name.

To open just one entry in an archive, the most efficient way is to simply
search for it linearly by calling wxArchiveInputStream::GetNextEntry() until
the required entry is found. This works both for archives on seekable and
non-seekable streams.

The format of filenames in the archive is likely to be different from the local
filename format. For example zips and tars use unix style names, with forward
slashes as the path separator, and absolute paths are not allowed. So if on
Windows the file "C:\MYDIR\MYFILE.TXT" is stored, then when reading the entry
back wxArchiveEntry::GetName() will return "MYDIR\MYFILE.TXT". The conversion
into the internal format and back has lost some information.

So to avoid ambiguity when searching for an entry matching a local name, it is
better to convert the local name to the archive's internal format and search
for that:

@code
auto_ptr<wxZipEntry> entry;

// convert the local name we are looking for into the internal format
wxString name = wxZipEntry::GetInternalName(localname);

// open the zip
wxFFileInputStream in(wxT("test.zip"));
wxZipInputStream zip(in);

// call GetNextEntry() until the required internal name is found
do
{
    entry.reset(zip.GetNextEntry());
}
while (entry.get() != NULL && entry->GetInternalName() != name);

if (entry.get() != NULL)
{
    // read the entry's data...
}
@endcode

To access several entries randomly, it is most efficient to transfer the entire
catalogue of entries to a container such as a std::map or a wxHashMap then
entries looked up by name can be opened using the
wxArchiveInputStream::OpenEntry() method.

@code
WX_DECLARE_STRING_HASH_MAP(wxZipEntry*, ZipCatalog);
ZipCatalog::iterator it;
wxZipEntry *entry;
ZipCatalog cat;

// open the zip
wxFFileInputStream in(wxT("test.zip"));
wxZipInputStream zip(in);

// load the zip catalog
while ((entry = zip.GetNextEntry()) != NULL)
{
    wxZipEntry*& current = cat[entry->GetInternalName()];
    // some archive formats can have multiple entries with the same name
    // (e.g. tar) though it is an error in the case of zip
    delete current;
    current = entry;
}

// open an entry by name
if ((it = cat.find(wxZipEntry::GetInternalName(localname))) != cat.end())
{
    zip.OpenEntry(*it->second);
    // ... now read entry's data
}
@endcode

To open more than one entry simultaneously you need more than one underlying
stream on the same archive:

@code
// opening another entry without closing the first requires another
// input stream for the same file
wxFFileInputStream in2(wxT("test.zip"));
wxZipInputStream zip2(in2);
if ((it = cat.find(wxZipEntry::GetInternalName(local2))) != cat.end())
    zip2.OpenEntry(*it->second);
@endcode



@section overview_archive_generic Generic Archive Programming

Also see wxFileSystem for a higher level interface that can handle archive
files in a generic way.

The specific archive classes, such as the wxZip classes, inherit from the
following abstract classes which can be used to write code that can handle any
of the archive types:

@li wxArchiveInputStream: Input stream
@li wxArchiveOutputStream: Output stream
@li wxArchiveEntry: Holds the meta-data for an entry (e.g. filename)

In order to able to write generic code it's necessary to be able to create
instances of the classes without knowing which archive type is being used.

To allow this there is a class factory for each archive type, derived from
wxArchiveClassFactory, that can create the other classes.

For example, given wxArchiveClassFactory* factory, streams and entries can be
created like this:

@code
// create streams without knowing their type
auto_ptr<wxArchiveInputStream> inarc(factory->NewStream(in));
auto_ptr<wxArchiveOutputStream> outarc(factory->NewStream(out));

// create an empty entry object
auto_ptr<wxArchiveEntry> entry(factory->NewEntry());
@endcode

For the factory itself, the static member wxArchiveClassFactory::Find() can be
used to find a class factory that can handle a given file extension or mime
type. For example, given @e filename:

@code
const wxArchiveClassFactory *factory;
factory = wxArchiveClassFactory::Find(filename, wxSTREAM_FILEEXT);

if (factory)
    stream = factory->NewStream(new wxFFileInputStream(filename));
@endcode

@e Find() does not give away ownership of the returned pointer, so it does not
need to be deleted.

There are similar class factories for the filter streams that handle the
compression and decompression of a single stream, such as wxGzipInputStream.
These can be found using wxFilterClassFactory::Find().

For example, to list the contents of archive @e filename:

@code
auto_ptr<wxInputStream> in(new wxFFileInputStream(filename));

if (in->IsOk())
{
    // look for a filter handler, e.g. for '.gz'
    const wxFilterClassFactory *fcf;
    fcf = wxFilterClassFactory::Find(filename, wxSTREAM_FILEEXT);
    if (fcf)
    {
        in.reset(fcf->NewStream(in.release()));
        // pop the extension, so if it was '.tar.gz' it is now just '.tar'
        filename = fcf->PopExtension(filename);
    }

    // look for a archive handler, e.g. for '.zip' or '.tar'
    const wxArchiveClassFactory *acf;
    acf = wxArchiveClassFactory::Find(filename, wxSTREAM_FILEEXT);
    if (acf)
    {
        auto_ptr<wxArchiveInputStream> arc(acf->NewStream(in.release()));
        auto_ptr<wxArchiveEntry> entry;

        // list the contents of the archive
        while ((entry.reset(arc->GetNextEntry())), entry.get() != NULL)
            std::wcout << entry->GetName().c_str() << "\n";
    }
    else
    {
        wxLogError(wxT("can't handle '%s'"), filename.c_str());
    }
}
@endcode



@section overview_archive_noseek Archives on Non-Seekable Streams

In general, handling archives on non-seekable streams is done in the same way
as for seekable streams, with a few caveats.

The main limitation is that accessing entries randomly using
wxArchiveInputStream::OpenEntry() is not possible, the entries can only be
accessed sequentially in the order they are stored within the archive.

For each archive type, there will also be other limitations which will depend
on the order the entries' meta-data is stored within the archive. These are not
too difficult to deal with, and are outlined below.

@subsection overview_archive_noseek_entrysize PutNextEntry and the Entry Size

When writing archives, some archive formats store the entry size before the
entry's data (tar has this limitation, zip doesn't). In this case the entry's
size must be passed to wxArchiveOutputStream::PutNextEntry() or an error
occurs.

This is only an issue on non-seekable streams, since otherwise the archive
output stream can seek back and fix up the header once the size of the entry is
known.

For generic programming, one way to handle this is to supply the size whenever
it is known, and rely on the error message from the output stream when the
operation is not supported.

@subsection overview_archive_noseek_weak GetNextEntry and the Weak Reference Mechanism

Some archive formats do not store all an entry's meta-data before the entry's
data (zip is an example). In this case, when reading from a non-seekable
stream, wxArchiveInputStream::GetNextEntry() can only return a partially
populated wxArchiveEntry object - not all the fields are set.

The input stream then keeps a weak reference to the entry object and updates it
when more meta-data becomes available. A weak reference being one that does not
prevent you from deleting the wxArchiveEntry object - the input stream only
attempts to update it if it is still around.

The documentation for each archive entry type gives the details of what
meta-data becomes available and when. For generic programming, when the worst
case must be assumed, you can rely on all the fields of wxArchiveEntry being
fully populated when GetNextEntry() returns, with the the following exceptions:

@li wxArchiveEntry::GetSize(): Guaranteed to be available after the entry has
    been read to wxInputStream::Eof(), or wxArchiveInputStream::CloseEntry()
    has been called.
@li wxArchiveEntry::IsReadOnly(): Guaranteed to be available after the end of
    the archive has been reached, i.e. after GetNextEntry() returns @NULL and
    Eof() is @true.

This mechanism allows wxArchiveOutputStream::CopyEntry() to always fully
preserve entries' meta-data. No matter what order order the meta-data occurs
within the archive, the input stream will always have read it before the output
stream must write it.

@subsection overview_archive_noseek_notifier wxArchiveNotifier

Notifier objects can be used to get a notification whenever an input stream
updates a wxArchiveEntry object's data via the weak reference mechanism.

Consider the following code which renames an entry in an archive. This is the
usual way to modify an entry's meta-data, simply set the required field before
writing it with wxArchiveOutputStream::CopyEntry():

@code
auto_ptr<wxArchiveInputStream> arc(factory->NewStream(in));
auto_ptr<wxArchiveOutputStream> outarc(factory->NewStream(out));
auto_ptr<wxArchiveEntry> entry;

outarc->CopyArchiveMetaData(*arc);

while (entry.reset(arc->GetNextEntry()), entry.get() != NULL)
{
    if (entry->GetName() == from)
        entry->SetName(to);
    if (!outarc->CopyEntry(entry.release(), *arc))
        break;
}

bool success = arc->Eof() && outarc->Close();
@endcode

However, for non-seekable streams, this technique cannot be used for fields
such as wxArchiveEntry::IsReadOnly(), which are not necessarily set when
wxArchiveInputStream::GetNextEntry() returns.

In this case a wxArchiveNotifier can be used:

@code
class MyNotifier : public wxArchiveNotifier
{
public:
    void OnEntryUpdated(wxArchiveEntry& entry) { entry.SetIsReadOnly(false); }
};
@endcode

The meta-data changes are done in your notifier's
wxArchiveNotifier::OnEntryUpdated() method, then wxArchiveEntry::SetNotifier()
is called before CopyEntry():

@code
auto_ptr<wxArchiveInputStream> arc(factory->NewStream(in));
auto_ptr<wxArchiveOutputStream> outarc(factory->NewStream(out));
auto_ptr<wxArchiveEntry> entry;
MyNotifier notifier;

outarc->CopyArchiveMetaData(*arc);

while (entry.reset(arc->GetNextEntry()), entry.get() != NULL)
{
    entry->SetNotifier(notifier);
    if (!outarc->CopyEntry(entry.release(), *arc))
        break;
}

bool success = arc->Eof() && outarc->Close();
@endcode

SetNotifier() calls OnEntryUpdated() immediately, then the input stream calls
it again whenever it sets more fields in the entry. Since OnEntryUpdated() will
be called at least once, this technique always works even when it is not
strictly necessary to use it. For example, changing the entry name can be done
this way too and it works on seekable streams as well as non-seekable.

*/


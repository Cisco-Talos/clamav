This is a small Windows client for ClamAV that I hope will turn into
something bigger with time.

Since it's so early I'm only releasing the Debug version (you'll need to
install the MFC Debug libary in \windows\system32 if you don't already
have it) and am yet to release the source code.

You will need a clamd server machine where the clamd daemon is listening
on port 3310. When firing up the Windows client you will be asked to
enter in the hostname/IPv4 address of the clamd server. Once you have done
that simply drag 'n' drop files or folders on to the program, they will
then be scanned for viruses.

I only have an old copy of Visual C/C++ (version 2), so I can only accept
patches compatible with that version.

Nigel Horne njh@bandsman.co.uk

29/01/04

-----------------------------

23/2/04
Version 0.14
Handles the ERROR status from clamd
----------------------------------
10/2/04
The file mfc30d.dll has been removed. Most Windows distributions will already
have it - if not please get it from http://www.clamav.net/w32/mfc30d.zip,
you will need it to run the clamAV windows client
----------------------------------
10/2/04
Version 0.13
Recovers better from errors during scanning such as timeouts sending to clamd
----------------------------------
9/2/04
Version 0.12
The port of the clamd server can now be specified. The default value is 3310.
When running from the CLI use the form server[:port] when specifying the
server.
----------------------------------
5/2/04
Version 0.11
Now integrates with WinZip. To configure WinZip8.1 to use ClamAV as it's
antivirus:
	Open options->configuration->program locations
	In optional virus scanner, enter the full path of clamav.exe
	In the parameters field enter the IP address of the clamd server
----------------------------------
2/2/04
Added a command line interface. This allows the client to be used either
in conjunction with download managers which often ask users to specify
a CLI to a AV system to scan files that have been downloaded. It also
allows a full system scan to be done either manually or via the Windows
scheduler, for example
	clamav.exe 192.168.1.1 eicar.com
	clamav.exe 192.168.1.1 c:\

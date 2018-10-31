# Usage

## Clam daemon

`clamd` is a multi-threaded daemon that uses *libclamav* to scan files for viruses. It may work in one or both modes listening on:

- Unix (local) socket
- TCP socket

The daemon is fully configurable via the `clamd.conf` file \[8\]. `clamd` recognizes the following commands:

- **PING**
    Check the daemon’s state (should reply with "PONG").
- **VERSION**
    Print program and database versions.
- **RELOAD**
    Reload the databases.
- **SHUTDOWN**
    Perform a clean exit.
- **SCAN file/directory**
    Scan file or directory (recursively) with archive support enabled (a full path is required).
- **RAWSCAN file/directory**
    Scan file or directory (recursively) with archive and special file support disabled (a full path is required).
- **CONTSCAN file/directory**
    Scan file or directory (recursively) with archive support enabled and don’t stop the scanning when a virus is found.
- **MULTISCAN file/directory**
    Scan file in a standard way or scan directory (recursively) using multiple threads (to make the scanning faster on SMP machines).
- **ALLMATCHSCAN file/directory**
    ALLMATCHSCAN works just like SCAN except that it sets a mode where, after finding a virus within a file, continues scanning for additional viruses.
- **INSTREAM**
    *It is mandatory to prefix this command with **n** or **z**.* Scan a stream of data. The stream is sent to clamd in chunks, after INSTREAM, on the same socket on which the command was sent. This avoids the overhead of establishing new TCP connections and problems with NAT. The format of the chunk is: `<length><data>` where `<length>` is the size of the following data in bytes expressed as a 4 byte unsigned integer in network byte order and `<data>` is the actual chunk. Streaming is terminated by sending a zero-length chunk. Note: do not exceed StreamMaxLength as defined in clamd.conf, otherwise clamd will reply with *INSTREAM size limit exceeded* and close the connection.
- **FILDES**
    *It is mandatory to newline terminate this command, or prefix with **n** or **z**. This command only works on UNIX domain sockets.* Scan a file descriptor. After issuing a FILDES command a subsequent rfc2292/bsd4.4 style packet (with at least one dummy character) is sent to clamd carrying the file descriptor to be scanned inside the ancillary data. Alternatively the file descriptor may be sent in the same packet, including the extra character.
- **STATS**
    *It is mandatory to newline terminate this command, or prefix with **n** or **z**, it is recommended to only use the **z** prefix.* On this command clamd provides statistics about the scan queue, contents of scan queue, and memory usage. The exact reply format is subject to changes in future releases.
- **IDSESSION, END**
    *It is mandatory to prefix this command with **n** or **z**, also all commands inside **IDSESSION** must be prefixed.* Start/end a clamd session. Within a session multiple SCAN, INSTREAM, FILDES, VERSION, STATS commands can be sent on the same socket without opening new connections. Replies from clamd will be in the form `<id>: <response>` where `<id>` is the request number (in ASCII, starting from 1) and `<response>` is the usual clamd reply. The reply lines have the same delimiter as the corresponding command had. Clamd will process the commands asynchronously, and reply as soon as it has finished processing. Clamd requires clients to read all the replies it sent, before sending more commands to prevent send() deadlocks. The recommended way to implement a client that uses IDSESSION is with non-blocking sockets, and a select()/poll() loop: whenever send would block, sleep in select/poll until either you can write more data, or read more replies. *Note that using non-blocking sockets without the select/poll loop and alternating recv()/send() doesn’t comply with clamd’s requirements.* If clamd detects that a client has deadlocked, it will close the connection. Note that clamd may close an IDSESSION connection too if the client doesn’t follow the protocol’s requirements.
- **STREAM** (deprecated, use **INSTREAM** instead)
    Scan stream: clamd will return a new port number you should connect to and send data to scan.

It’s recommended to prefix clamd commands with the letter **z** (eg. zSCAN) to indicate that the command will be delimited by a NULL character and that clamd should continue reading command data until a NULL character is read. The null delimiter assures that the complete command and its entire argument will be processed as a single command. Alternatively commands may be prefixed with the letter **n** (e.g. nSCAN) to use a newline character as the delimiter. Clamd replies will honour the requested terminator in turn. If clamd doesn’t recognize the command, or the command doesn’t follow the requirements specified below, it will reply with an error message, and close the connection. Clamd can handle the following signals:

- **SIGTERM** - perform a clean exit
- **SIGHUP** - reopen the log file
- **SIGUSR2** - reload the database

Clamd should not be started in the background using the shell operator `&` or external tools. Instead, you should run and wait for clamd to load the database and daemonize itself. After that, clamd is instantly ready to accept connections and perform file scanning.

## Clam**d**scan

`clamdscan` is a simple `clamd` client. In many cases you can use it as a `clamscan` replacement however you must remember that:

- it only depends on `clamd`
- although it accepts the same command line options as `clamscan` most of them are ignored because they must be enabled directly in `clamd`, i.e. `clamd.conf`
- in TCP mode scanned files must be accessible for `clamd`, if you enabled LocalSocket in clamd.conf then clamdscan will try to workaround this limitation by using FILDES

## On-access Scanning

There is a special thread in `clamd` that performs on-access scanning under Linux and shares internal virus database with the daemon. By default, this thread will only notify you when potential threats are discovered. If you turn on prevention via `clamd.conf` then **you must follow some important rules when using it:**

- Always stop the daemon cleanly - using the SHUTDOWN command or the SIGTERM signal. In other case you can lose access to protected files until the system is restarted.
- Never protect the directory your mail-scanner software uses for attachment unpacking. Access to all infected files will be automatically blocked and the scanner (including `clamd`\!) will not be able to detect any viruses. In the result **all infected mails may be delivered.**
- Watch your entire filesystem only using the `clamd.conf` OnAccessMountPath option. While this will disable on-access prevention, it will avoid potential system lockups caused by fanotify’s blocking functionality.
- Using the On-Access Scanner to watch a virtual filesystem will result in undefined behaviour.

For more configuration options, type ’man clamd.conf’ or reference the example clamd.conf. And for additional details on how to use this feature, please reference the [OnAccess usage manual](OnAccess.md).

## Clamdtop

`clamdtop` is a tool to monitor one or multiple instances of clamd. It has a (color) ncurses interface, that shows the jobs in clamd’s queue, memory usage, and information about the loaded signature database. You can specify on the command-line to which clamd(s) it should connect to. By default it will attempt to connect to the local clamd as defined in clamd.conf.

For more detailed help, type ’man clamdtop’ or ’clamdtop –help’.

## Clamscan

`clamscan` is ClamAV’s command line virus scanner. It can be used to scan files and/or directories for viruses. In order for clamscan to work proper, the ClamAV virus database files must be installed on the system you are using clamscan on.

The general usage of clamscan is: clamscan \[options\]
\[file/directory/-\]

For more detailed help, type ’man clamscan’ or ’clamscan –help’.

## ClamBC

`clambc` is Clam Anti-Virus’ bytecode testing tool. It can be used to test files which contain bytecode. For more detailed help, type ’man clambc’ or ’clambc –help’.

## Freshclam

`freshclam` is ClamAV’s virus database update tool and reads it’s configuration from the file ’freshclam.conf’ (this may be overridden by command line options). Freshclam’s default behavior is to attempt to update databases that are paired with downloaded cdiffs. Potentially corrupted databases are not updated and are automatically fully replaced after several failed attempts unless otherwise specified.

Here is a sample usage including cdiffs:

```bash
$ freshclam

ClamAV update process started at Mon Oct  7 08:15:10 2013
main.cld is up to date (version: 55, sigs: 2424225, f-level: 60, builder: neo)
Downloading daily-17945.cdiff [100%]
Downloading daily-17946.cdiff [100%]
Downloading daily-17947.cdiff [100%]
daily.cld updated (version: 17947, sigs: 406951, f-level: 63, builder: neo)
Downloading bytecode-227.cdiff [100%]
Downloading bytecode-228.cdiff [100%]
bytecode.cld updated (version: 228, sigs: 43, f-level: 63, builder: neo)
Database updated (2831219 signatures) from database.clamav.net (IP: 64.6.100.177)
```

For more detailed help, type ’man clamscan’ or ’clamscan –help’.

## Clamconf

`clamconf` is the Clam Anti-Virus configuration utility. It is used for displaying values of configurations options in ClamAV, which will show the contents of clamd.conf (or tell you if it is not properly configured), the contents of freshclam.conf, and display information about software settings, database, platform, and build information. Here is a sample clamconf output:

```bash
$ clamconf

Checking configuration files in /etc/clamav

Config file: clamd.conf
-----------------------
ERROR: Please edit the example config file /etc/clamav/clamd.conf

Config file: freshclam.conf
---------------------------
ERROR: Please edit the example config file /etc/clamav/freshclam.conf

clamav-milter.conf not found

Software settings
-----------------
Version: 0.98.2
Optional features supported: MEMPOOL IPv6 AUTOIT_EA06 BZIP2 RAR JIT

Database information
--------------------
Database directory: /xclam/gcc/release/share/clamav
WARNING: freshclam.conf and clamd.conf point to different database directories
print_dbs: Can't open directory /xclam/gcc/release/share/clamav

Platform information
--------------------
uname: Linux 3.5.0-44-generic #67~precise1-Ubuntu SMP Wed Nov 13 16:20:03 UTC 2013 i686
OS: linux-gnu, ARCH: i386, CPU: i686
Full OS version: Ubuntu 12.04.3 LTS
zlib version: 1.2.3.4 (1.2.3.4), compile flags: 55
Triple: i386-pc-linux-gnu
CPU: i686, Little-endian
platform id: 0x0a114d4d0404060401040604

Build information
-----------------
GNU C: 4.6.4 (4.6.4)
GNU C++: 4.6.4 (4.6.4)
CPPFLAGS:
CFLAGS: -g -O0 -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE
CXXFLAGS:
LDFLAGS:
Configure: '--prefix=/xclam/gcc/release/' '--disable-clamav' '--enable-debug' 'CFLAGS=-g -O0'
sizeof(void*) = 4
Engine flevel: 77, dconf: 77

```

For more detailed help, type ’man clamconf’ or ’clamconf –help’.

## Output format

### clamscan

`clamscan` writes all regular program messages to **stdout** and errors/warnings to **stderr**. You can use the option `--stdout` to redirect all program messages to **stdout**. Warnings and error messages from `libclamav` are always printed to **stderr**. A typical output from `clamscan` looks like this:

```bash
    /tmp/test/removal-tool.exe: Worm.Sober FOUND
    /tmp/test/md5.o: OK
    /tmp/test/blob.c: OK
    /tmp/test/message.c: OK
    /tmp/test/error.hta: VBS.Inor.D FOUND
```

When a virus is found its name is printed between the `filename:` and `FOUND` strings. In case of archives the scanner depends on libclamav and only prints the first virus found within an archive:

```bash
    $ clamscan malware.zip
    malware.zip: Worm.Mydoom.U FOUND
```

When using the –allmatch(-z) flag, clamscan may print multiple virus `FOUND` lines for archives and files.

### clamd

The output format of `clamd` is very similar to `clamscan`.

```bash
    $ telnet localhost 3310
    Trying 127.0.0.1...
    Connected to localhost.
    Escape character is '^]'.
    SCAN /home/zolw/test
    /home/zolw/test/clam.exe: ClamAV-Test-File FOUND
    Connection closed by foreign host.
```

In the **SCAN** mode it closes the connection when the first virus is found.

```bash
    SCAN /home/zolw/test/clam.zip
    /home/zolw/test/clam.zip: ClamAV-Test-File FOUND
```

**CONTSCAN** and **MULTISCAN** don’t stop scanning in case a virus is found. Error messages are printed in the following format:

```bash
    SCAN /no/such/file
    /no/such/file: Can't stat() the file. ERROR
```

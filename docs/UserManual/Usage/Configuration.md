# Configuration

---

<!-- TOC depthFrom:2 depthTo:6 withLinks:1 updateOnSave:1 orderedList:0 -->

- [clamconf](#clamconf)
- [clamd.conf](#clamdconf)
	- [On-Access Scanning](#on-access-scanning)
- [freshclam.conf](#freshclamconf)
- [clamav-milter](#clamav-milter)

<!-- /TOC -->

---

## clamconf

---

`clamconf` is a tool ClamAV provides for checking your entire system configuration, as it relates to your ClamAV installation. When run, it displays values used when configuring ClamAV at compilation time, important OS details, the contents (and validity) of both `clamd.conf` and `freshclam.conf`, along with other important engine, database, platform, and build information.

It can also generate example configuration files for [`clamd.conf`](#clamdconf) and [`freshclam.conf`](#freshclamconf).

To use `clamconf`, and see all the information it provides, simply run the following command:

> `$ clamconf`

For more detailed information on `clamconf`, run:

> `$ man clamconf`

or

> `$ clamconf --help`

---

## clamd.conf

---

Currently, ClamAV requires users to edit their `clamd.conf.example` file before they can run the daemon. At a bare minimum, users will need to comment out the line that reads "Example", else `clamd` will consider the configuration invalid, ala:

<pre>
  7 # Comment or remove the line below.
  8 #Example
</pre>

You will also need to rename `clamd.conf.example` to `clamd.conf` via:

> `$ mv ./clamd.conf.example ./clamd.conf`

If you are setting up a simple, local [`clamd` instance](Scanning.md#clamd) then some other configuration options of interests to you will be as follows:

<pre>
	91 # Path to a local socket file the daemon will listen on.
	92 # Default: disabled (must be specified by a user)
	93 LocalSocket /tmp/clamd.socket

	...

	99 # Sets the permissions on the unix socket to the specified mode.
	100 # Default: disabled (socket is world accessible)
	101 LocalSocketMode 660
</pre>

Beyond that, `clamd.conf` is well commented and configuration should be straightforward.

If needed, you can find out even more about the formatting and options available in `clamd.conf` with the command:

> `man clamd.conf`

---

### On-Access Scanning

---

You can configure On-Access Scanning through `clamd.conf`.  Configuration for On-Access Scanning starts at *line 613* in `clamd.conf.example`.

Please read the [on-access](Usage.md#On-access-Scanning) section of the Usage manual for further details on using On-Access Scanning.

---

## freshclam.conf

---

`freshclam` is the automatic database update tool for Clam AntiVirus. It can be configured to work in two modes:

- interactive - on demand from command line
- daemon - silently in the background

`freshclam` is an advanced tool: it supports scripted updates (instead of transferring the whole CVD file at each update it only transfers the differences between the latest and the current database via a special script), database version checks through DNS, proxy servers (with authentication), digital signatures and various error scenarios.

**Quick test: run freshclam (as superuser) with no parameters and check the output.**

> `$ freshclam`

If everything is OK you may create the log file in /var/log (ensure the directory is owned either by *clamav* or whichever user `freshclam` will be running as):

<pre>
	# touch /var/log/freshclam.log
	# chmod 600 /var/log/freshclam.log
	# chown clamav /var/log/freshclam.log
</pre>

Now you *should* edit the configuration file `freshclam.conf` and point the *UpdateLogFile* directive to the log file. Finally, to run `freshclam` in the daemon mode, execute:

<pre>
	# freshclam -d
</pre>

The other way is to use the *cron* daemon. You have to add the following line to the *crontab* of **root** or **clamav** user:

<pre>
	N * * * *   /usr/local/bin/freshclam --quiet
</pre>

to check for a new database every hour. **N should be a number between 3 and 57 of your choice. Please don’t choose any multiple of 10, because there are already too many clients using those time slots.** Proxy settings are only configurable via the configuration file and `freshclam` will require strict permission settings for the config file when `HTTPProxyPassword` is turned on.

<pre>
	HTTPProxyServer myproxyserver.com
	HTTPProxyPort 1234
	HTTPProxyUsername myusername
	HTTPProxyPassword mypass
</pre>

---

## clamav-milter

---

ClamAV includes a mail filtering tool called `clamav-milter`. This tool interfaces directly with `clamd`, and thus requires a working [`clamd` instance](Scanning.md#clamd) to run. However, `clamav-milter`'s configuration and log files are separate from that of `clamd`.

Ensuring ClamAV compiles with `clamav-milter` must be done at configure time with the command:

> `$ ./configure [options] --enable-milter`

This requires having the milter library installed on your system. If *libmilter* is not installed, `./configure` will exit with this error message:

<pre>
	checking for mi_stop in -lmilter... no
	configure: error: Cannot find libmilter
</pre>

While not necessarily *complicated*, setting up the `clamav-milter` is an involved process. Thus, we recommend consulting your MTA’s manual on how to best connect ClamAV with the `clamav-milter`.

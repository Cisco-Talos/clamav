# Configuration

Before proceeding with the steps below, you should run the ’clamconf’ command, which gives important information about your ClamAV configuration. See section [5.8](#sec:clamconf) for more details.

## clamd

Before you start using the daemon you have to edit the configuration file (in other case `clamd` won’t run):

```bash
    $ clamd
    ERROR: Please edit the example config file /etc/clamd.conf.
```

This shows the location of the default configuration file. The format and options of this file are fully described in the *clamd.conf(5)* manual. The config file is well commented and configuration should be straightforward.

### On-access scanning

One of the interesting features of `clamd` is on-access scanning based on fanotify, included in Linux since kernel 2.6.36. **This is not required to run clamd**. At the moment the fanotify header is only available for Linux.

Configure on-access scanning in `clamd.conf` and read the [on-access](Usage.md#On-access-Scanning) section for on-access scanning usage.

## clamav-milter

ClamAV (v0.95) includes a new, redesigned clamav-milter. The most notable difference is that the internal mode has been dropped and now a working clamd companion is required. The second important difference is that now the milter has got its own configuration and log files.

To compile ClamAV with the clamav-milter just run `./configure --enable-milter` and make as usual. In order to use the `–enable-milter` option with `configure`, your system MUST have the milter library installed. If you use the `–enable-milter` option without the library being installed, you will most likely see output like this during ’configure’:

```bash
        checking for libiconv_open in -liconv... no
        checking for iconv... yes
        checking whether in_port_t is defined... yes
        checking for in_addr_t definition... yes
        checking for mi_stop in -lmilter... no
        checking for library containing strlcpy... no
        checking for mi_stop in -lmilter... no
        configure: error: Cannot find libmilter
```

At which point the ’configure’ script will stop processing.

Please consult your MTA’s manual on how to connect ClamAV with the milter.

## Testing

Try to scan recursively the source directory:

```bash
    $ clamscan -r -l scan.txt clamav-x.yz
```

It should find some test files in the clamav-x.yz/test directory. The scan result will be saved in the `scan.txt` log file \[7\]. To test `clamd`, start it and use `clamdscan` (or instead connect directly to its socket and run the SCAN command):

```bash
    $ clamdscan -l scan.txt clamav-x.yz
```

Please note that the scanned files must be accessible by the user running `clamd` or you will get an error.

## Setting up auto-updating

`freshclam` is the automatic database update tool for Clam AntiVirus. It can work in two modes:

- interactive - on demand from command line
- daemon - silently in the background

`freshclam` is advanced tool: it supports scripted updates (instead of transferring the whole CVD file at each update it only transfers the differences between the latest and the current database via a special script), database version checks through DNS, proxy servers (with authentication), digital signatures and various error scenarios. **Quick test: run freshclam (as superuser) with no parameters and check the output.** If everything is OK you may create the log file in /var/log (owned by *clamav* or another user `freshclam` will be running as):

```bash
    # touch /var/log/freshclam.log
    # chmod 600 /var/log/freshclam.log
    # chown clamav /var/log/freshclam.log
```

Now you *should* edit the configuration file `freshclam.conf` and point the *UpdateLogFile* directive to the log file. Finally, to run `freshclam` in the daemon mode, execute:

```bash
    # freshclam -d
```

The other way is to use the *cron* daemon. You have to add the following line to the crontab of **root** or **clamav** user:

```cron
N * * * *   /usr/local/bin/freshclam --quiet
```

to check for a new database every hour. **N should be a number between 3 and 57 of your choice. Please don’t choose any multiple of 10, because there are already too many clients using those time slots.** Proxy settings are only configurable via the configuration file and `freshclam` will require strict permission settings for the config file when `HTTPProxyPassword` is turned on.

```bash
    HTTPProxyServer myproxyserver.com
    HTTPProxyPort 1234
    HTTPProxyUsername myusername
    HTTPProxyPassword mypass
```

### Closest mirrors

The `DatabaseMirror` directive in the config file specifies the database server `freshclam` will attempt (up to `MaxAttempts` times) to download the database from. The default database mirror is [database.clamav.net](database.clamav.net) but multiple directives are allowed. In order to download the database from the closest mirror you should configure `freshclam` to use [db.xx.clamav.net](db.xx.clamav.net) where xx represents your country code. For example, if your server is in "Ascension Island" you should have the following lines included in `freshclam.conf`:

```bash
    DNSDatabaseInfo current.cvd.clamav.net
    DatabaseMirror db.ac.clamav.net
    DatabaseMirror database.clamav.net
```

The second entry acts as a fallback in case the connection to the first mirror fails for some reason. The full list of two-letters country codes is available at <http://www.iana.org/cctld/cctld-whois.htm>

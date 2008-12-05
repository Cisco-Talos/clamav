#!/usr/bin/perl

use strict;
use warnings;

use Getopt::Long qw(:config gnu_getopt);

sub wwarn {
	my $w = shift;
	warn "WARNING: $w\n";
}

sub tosconf {
	my ($cfg, $v) = @_;
	if($v) {
		my $sep = $v=~/ / ? '"' : '';
		$v = "\n$cfg $sep$v$sep";
	}
	return $v;
}

my $notify = 0;
my $black = 0;
my $report = 0;
my $debug = 0;
my $sign = 0;
my $broad = 0;
my $forge = 0;
my $sanity = 1;
my $blackhole = 0;
my $quarantine = 0;
my $rate = 0;
my $monitor = 0;
my $oninfected = 'Reject';
my $onfail = 'Defer';
my @localnets = ();
my $whitelist = '';
my $config = '';
my $chroot = '';
my $pidfile = '';
my $addheader = 1;
my $tcpclamds = '';
my $localclamd;

GetOptions (
	"from|a:s" => \$notify,
	"bounce|b" => \$notify,
	"headers|H" => \$notify,
	"postmaster|p=s" => \$notify,
	"postmaster-only|P" => \$notify,
	"template-file|t=s" => \$notify,
	"template-headers|1=s" => \$notify,
	"quiet|q" => sub { $notify = 0 },
	"dont-blacklist|K=s" => \$black,
	"blacklist-time|k=i" => \$black,
	"report-phish|r=s" => \$report,
	"report-phish-false-positives|R=s" => \$report,
	"debug-level|x=i" => \$debug,
	"debug|D" => \$debug,
	"sign|S" => \$sign,
	"signature-file|F=s" => \$sign,
	"broadcast|B=s" => \$broad,
	"detect-forged-local-address|L" => \$forge,
	"dont-sanitise|z" => sub { $sanity = 0 },
	"black-hole-mode|2" => \$blackhole,
	"quarantine|Q=s" => \$quarantine,
	"quarantine-dir|U" => \$quarantine,
	"max-children|m=i" => \$rate,
	"dont-wait|w" => \$rate,
	"timeout|T=i" => \$rate,
	"freshclam-monitor|M=i" => \$monitor,
	"external|e" => sub { },
	"no-check-cf" => sub { },
	"sendmail-cf|0=s" => sub { },
	"advisory|A" => sub { $oninfected='Accept'; },
	"noreject|N" => sub { $oninfected='Blackhole'; },
	"dont-scan-on-error|d" => sub { $onfail = 'Accept'; },
	"ignore|I=s" => \@localnets,
	"local|l" => sub { @localnets = (); },
	"force-scan|f" => sub { @localnets = (); },
	"whitelist-file|W=s" => \$whitelist,
	"config-file|c=s" => \$config,
	"chroot|C=s" => \$chroot,
	"pidfile|i=s" => \$pidfile,
	"noxheader|n" => sub { $addheader = 0},
	"outgoing|o" => sub { push(@localnets, 'localhost'); },
	"server|s=s" => \$tcpclamds,
) or die "huh?!";

my %clamds = ();
foreach (split(/:/, $tcpclamds)) {
	$clamds{"tcp:$_:3310"}++;
}

my $user = '';
my $supgrp = '';
my $syslog = '';
my $facility = '';
my $tempdir = '';
my $maxsize = '';

if ($config) {
	my $port = 0;
	my $ip = '';
	my $lsock = '';
	open CFG, "<$chroot/$config" or die "failed to open clamd config file $config";
	while (<CFG>) {
		chomp;
		$port = $1 if /^TCPSocket\s+(.*)$/;
		$ip = $1 if /^TCPAddr\s+(.*)$/;
		$lsock = $1 if /^LocalSocket\s+(.*)$/;
		$user = $1 if /^User\s+(.*)$/;
		$supgrp = $1 if /^AllowSupplementaryGroups\s+(.*)$/;
		$syslog = $1 if /^LogSyslog\s+(.*)$/;
		$facility = $1 if /^LogFacility\s+(.*)$/;
		$tempdir = $1 if /^TemporaryDirectory\s+(.*)$/;
		$maxsize = $1 if /^MaxFileSize\s+(.*)$/;
	}
	close(CFG);
	if ($lsock) {
		$clamds{"unix:$lsock"}++;
	} elsif ($port) {
		if($ip) {
			$clamds{"tcp:$ip:$port"}++;
		} else {
			$clamds{"tcp:localhost:$port"}++;
		}
	}
}

die "FAIL: No socket provided" unless $ARGV[0];
die "FAIL: Unable to determine clamd socket\n" unless scalar keys %clamds;

wwarn "Notifications and bounces are no longer supported.
As a result the following command line options cannot be converted into new config options:
 --from (-a)
 --bounce (-b)
 --headers (-H)
 --postmaster (-p)
 --postmaster-only (-P)
 --template-file (-t)
 --template-headers (-1)
" if $notify;

wwarn "Temporary blacklisting of ip addresses is no longer supported.
As a result the following command line options cannot be converted into new config options:
 --dont-blacklist (-K)
 --blacklist-time (-k)
" if $black;

wwarn "Phising reports are no longer supported.
As a result the following command line options cannot be converted into new config options:
 --report-phish (-r)
 --report-phish-false-positives (-R)
" if $report; 

wwarn "The options --debug (-D) and --debug-level (-x) are no longer supported.
Please set LogVerbose to yes instead
" if $debug;

wwarn "Message scan signatures are no longer supported.
As a result the following command line options cannot be converted into new config options:
 --sign (-S)
 --signature-file (-F)
" if $sign;

wwarn "Broadcasting is no longer supported\n" if $broad;

wwarn "Forgery detection is no longer supported\n" if $forge;

wwarn "Please be aware that email addresses are no longer checked for weird characters like '|' and ';'\n" if $sanity;

wwarn "Blackhole mode is no longer available\nIf you have a lot users aliased to /dev/null you may want to whitelist them instead\n" if $blackhole;

wwarn "Quarantine now achieved via native milter support\nPlease read more about it in the example config file\n" if $quarantine;

wwarn "Rate limiting in the milter is no longer supported.
As a result the following command line options cannot be converted into new config options:
 --max-children (-m)
 --dont-wait (-w)
 --timeout (-T)
Please make use of the native Sendmail / Postfix rate limiting facilities
" if $rate;

wwarn "The option --freshclam-monitor (-M) only made sense in internal mode\nPlease configure freshclam to notify clamd about updates instead\n" if $monitor;

wwarn "Your whitelist file path has been preserved, however please be aware that its syntax is changed\nInstead of a full email address you are now allowed to use regexes. See the example clamav-milter.conf file for more info.\n" if $whitelist;

wwarn "Here is the auto generated config file. Please review:\n";

my $mysock = tosconf('MilterSocket', $ARGV[0]);
$chroot = tosconf('Chroot', $chroot);
$pidfile = tosconf('PidFile', $pidfile);
$oninfected = tosconf('OnInfected', $oninfected);
$onfail = tosconf('OnFail', $onfail);
$whitelist = tosconf('Whitelist', $whitelist);
$addheader = $addheader ? "\nAddHeader Yes" : '';
$user = tosconf('User', $user);
$supgrp = $supgrp ? "\nAllowSupplementaryGroups Yes" : '';
if ($syslog =~ /yes/i) {
	$syslog = "LogSyslog yes";
	$facility = tosconf('LogFacility', $facility);
} else {
	$syslog = '';
	$facility = '';
}
$tempdir = tosconf('TemporaryDirectory', $tempdir);
$maxsize = tosconf('MaxFileSize', $maxsize);

print <<BLOCK1;
##
## Example config file for clamav-milter
## (automatically generated by make-clamav-milter-conf.pl)
##

# Comment or remove the line below.
Example


##
## Main options
##

# Define the interface through which we communicate with sendmail
# This option is mandatory! Possible formats are:
# [[unix|local]:]/path/to/file - to specify a unix domain socket
# inet:port@[hostname|ip-address] - to specify an ipv4 socket
# inet6:port@[hostname|ip-address] - to specify an ipv6 socket
#
# Default: no default
#MilterSocket /tmp/clamav-milter.socket
#MilterSocket inet:7357$mysock

# Remove stale socket after unclean shutdown.
#
# Default: yes
#FixStaleSocket yes

# Run as another user (clamav-milter must be started by root for this option to work)
#
# Default: unset (don't drop privileges)
#User clamav$user

# Initialize supplementary group access (clamd must be started by root).
#
# Default: no
#AllowSupplementaryGroups no$supgrp

# Waiting for data from clamd will timeout after this time (seconds).
# Value of 0 disables the timeout.
#
# Default: 120
#ReadTimeout 300

# Don't fork into background.
#
# Default: no
#Foreground yes

# Chroot to the specified directory.
# Chrooting is performed just after reading the config file and before dropping privileges.
#
# Default: unset (don't chroot)
#Chroot /newroot$chroot

# This option allows you to save a process identifier of the listening
# daemon (main thread).
#
# Default: disabled
#PidFile /var/run/clamd.pid$pidfile

# Optional path to the global temporary directory.
# Default: system specific (usually /tmp or /var/tmp).
#
#TemporaryDirectory /var/tmp$tempdir

##
## Clamd options
##

# Define the clamd socket to connect to for scanning.
# If not set (the default), clamav-milter uses internal mode.
# This option is mandatory! Syntax:
# ClamdSocket unix:path
# ClamdSocket tcp:host:port
# The first syntax specifies a local unix socket (needs an bsolute path) e.g.:
#     ClamdSocket unix:/var/run/clamd/clamd.socket
# The second syntax specifies a tcp local or remote tcp socket: the
# host can be a hostname or an ip address; the ":port" field is only required
# for IPv6 addresses, otherwise it defaults to 3310
#     ClamdSocket tcp:192.168.0.1
#
# This option can be repeated several times with different sockets or even
# with the same socket: clamd servers will be selected in a round-robin fashion.
#
# Default: no default
#ClamdSocket tcp:scanner.mydomain:7357
BLOCK1

print "ClamdSocket \"$_\"\n" foreach (keys %clamds);
print <<BLOCK2;


##
## Exclusions
##

# Messages originating from these hosts/networks will not be scanned
# This option takes a host(name)/mask pair in CIRD notation and can be
# repeated several times. If "/mask" is omitted, a host is assumed.
# To specify a locally orignated, non-smtp, email use the keyword "local"
#
# Default: unset (scan everything regardless of the origin)
#LocalNet local
#LocalNet 192.168.0.0/24
#LocalNet 1111:2222:3333::/48

# This option specifies a file which contains a list of POSIX regular
# expressions. Addresses (sent to or from - see below) matching these regexes
# will not be scanned.  Optionally each line can start with the string "From:"
# or "To:" (note: no whitespace after the colon) indicating if it is, 
# respectively, the sender or recipient that is to be whitelisted.
# If the field is missing, "To:" is assumed.
# Lines starting with #, : or ! are ignored.
#
# Default unset (no exclusion applied)
#Whitelist /etc/whitelisted_addresses$whitelist


##
## Actions
##

# The following group of options controls the delievery process under
# different circumstances.
# The following actions are available:
# - Accept
#   The message is accepted for delievery
# - Reject
#   Immediately refuse delievery (a 5xx error is returned to the peer)
# - Defer
#   Return a temporary failure message (4xx) to the peer
# - Blackhole (not available for OnFail)
#   Like accept but the message is sent to oblivion
# - Quarantine (not available for OnFail)
#   Like accept but message is quarantined instead of being deilievered
#   In sendmail the quarantine queue can be examined via mailq -qQ
#   For Postfix this causes the message to be accepted but placed on hold
# 
# Action to be performed on clean messages (mostly useful for testing)
# Default Accept
#OnClean Accept

# Action to be performed on infected messages
# Default: Quarantine
#OnInfected Quarantine$oninfected

# Action to be performed on error conditions (this includes failure to
# allocate data structures, no scanners available, network timeouts,
# unknown scanner replies and the like)
# Default Defer
#OnFail Defer$onfail

# If this option is set to Yes, an "X-Virus-Scanned" and an "X-Virus-Status"
# headers will be attached to each processed message, possibly replacing
# existing headers. 
# Default: No
#AddHeader Yes$addheader


##
## Logging options
##

# Uncomment this option to enable logging.
# LogFile must be writable for the user running daemon.
# A full path is required.
#
# Default: disabled
#LogFile /tmp/clamav-milter.log

# By default the log file is locked for writing - the lock protects against
# running clamav-milter multiple times.
# This option disables log file locking.
#
# Default: no
#LogFileUnlock yes

# Maximum size of the log file.
# Value of 0 disables the limit.
# You may use 'M' or 'm' for megabytes (1M = 1m = 1048576 bytes)
# and 'K' or 'k' for kilobytes (1K = 1k = 1024 bytes). To specify the size
# in bytes just don't use modifiers.
#
# Default: 1M
#LogFileMaxSize 2M

# Log time with each message.
#
# Default: no
#LogTime yes

# Use system logger (can work together with LogFile).
#
# Default: no
#LogSyslog yes$syslog

# Specify the type of syslog messages - please refer to 'man syslog'
# for facility names.
#
# Default: LOG_LOCAL6
#LogFacility LOG_MAIL$facility

# Enable verbose logging.
#
# Default: no
#LogVerbose yes


##
## Limits
##

# Messages larger than this value won't be scanned.
# Default: 25M
#MaxFileSize 150M$maxsize
BLOCK2



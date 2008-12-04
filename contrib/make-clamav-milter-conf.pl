#!/usr/bin/perl

use strict;
use warnings;

use Getopt::Long qw(:config gnu_getopt);

sub wwarn {
	my $w = shift;
	warn "WARINING: $w";
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
my $whitelist;
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
	"broadcast|B" => \$broad,
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


#!/usr/bin/perl

# ---- Settings ----
# TemporaryDirectory in clamd.conf
my $TMPDIR='/tmp';
# How long to wait for next part of RFC1341 message (seconds)
my $cleanup_interval=3600;

# ---- End of Settings ----

my $partial_dir = "$TMPDIR/clamav-partial";
#  if there is no partial directory, nothing to clean up
opendir(DIR, $partial_dir) || exit 0;

my $cleanup_threshold = time - $cleanup_interval;
while(my $file = readdir(DIR)) {
	next unless $file =~ m/^clamav-partial-([0-9]+)_[0-9a-f]{32}-[0-9]+$/;
	my $filetime = $1;
	unlink "$partial_dir/$file" unless $filetime > $cleanup_threshold;
}
closedir DIR;

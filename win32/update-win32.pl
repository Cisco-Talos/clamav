#!/usr/bin/perl

use strict;
use warnings;
use XML::Twig;
use File::Copy;
use File::Temp 'tempfile';


#########################################################
# HACK HERE  HACK HERE  HACK HERE  HACK HERE  HACK HERE # 
#########################################################

use constant DEBUG => 0;

### CLAMAV-CONFIG.H MACROES ###
# - Set to the proper win32 value or -1 to undef - #
my %CONF = (
    'AC_APPLE_UNIVERSAL_BUILD' => -1,
    'ANONYMOUS_MAP' => -1,
    'BIND_8_COMPAT' => -1,
    'BUILD_CLAMD' => '1',
    'CLAMAVGROUP' => '"clamav"',
    'CLAMAVUSER' => '"clamav"',
    'CLAMUKO' => -1,
    'CL_DEBUG' => -1,
    'CL_BCUNSIGNED' => -1,
    'CL_EXPERIMENTAL' => -1,
    'CL_THREAD_SAFE' => '1',
    'CONFDIR' => '"C:\\\\ClamAV"',
    'CURSES_INCLUDE' => -1,
    'C_AIX' => -1,
    'C_BEOS' => -1,
    'C_BIGSTACK' => -1,
    'C_BSD' => -1,
    'C_DARWIN' => -1,
    'C_GNU_HURD' => -1,
    'C_HPUX' => -1,
    'C_INTERIX' => -1,
    'C_IRIX' => -1,
    'C_KFREEBSD_GNU' => -1,
    'C_LINUX' => -1,
    'C_OS2' => -1,
    'C_OSF' => -1,
    'C_QNX6' => -1,
    'C_SOLARIS' => -1,
    'DATADIR' => '"C:\\\\ClamAV\\\\db"',
    'DEFAULT_FD_SETSIZE' => '1024',
    'FDPASS_NEED_XOPEN' => -1,
    'FILEBUFF' => '8192',
    'FRESHCLAM_DNS_FIX' => -1,
    'FRESHCLAM_NO_CACHE' => -1,
    'HAVE_ARGZ_ADD' => -1,
    'HAVE_ARGZ_APPEND' => -1,
    'HAVE_ARGZ_COUNT' => -1,
    'HAVE_ARGZ_CREATE_SEP' => -1,
    'HAVE_ARGZ_H' => -1,
    'HAVE_ARGZ_INSERT' => -1,
    'HAVE_ARGZ_NEXT' => -1,
    'HAVE_ARGZ_STRINGIFY' => -1,
    'HAVE_ATTRIB_ALIGNED' => -1,
    'HAVE_ATTRIB_PACKED' => -1,
    'HAVE_BZLIB_H' => '1',
    'HAVE_CLOSEDIR' => '1',
    'HAVE_CTIME_R' => '1',
    'HAVE_CTIME_R_2' => '1',
    'HAVE_CTIME_R_3' => -1,
    'HAVE_DECL_CYGWIN_CONV_PATH' => -1,
    'HAVE_DIRENT_H' => '1',
    'HAVE_DLD' => -1,
    'HAVE_DLD_H' => -1,
    'HAVE_DLERROR' => -1,
    'HAVE_DLFCN_H' => '1',
    'HAVE_DL_H' => -1,
    'HAVE_DYLD' => -1,
    'HAVE_ERROR_T' => -1,
    'HAVE_ENABLE_EXTENDED_FILE_STDIO' => -1,
    'HAVE_SYS_TIMES_H' => -1,
    'HAVE_FD_PASSING' => -1,
    'HAVE_FSEEKO' => '1',
    'HAVE_GETADDRINFO' => '1',
    'HAVE_GETPAGESIZE' => '1',
    'HAVE_GRP_H' => -1,
    'HAVE_ICONV' => -1,
    'HAVE_INET_NTOP' => '1',
    'HAVE_INITGROUPS' => -1,
    'HAVE_INTTYPES_H' => -1,
    'HAVE_IN_ADDR_T' => -1,
    'HAVE_IN_PORT_T' => '1',
    'HAVE_LIBCHECK' => -1,
    'HAVE_LIBDL' => '1',
    'HAVE_LIBDLLOADER' => '1',
    'HAVE_LIBMILTER_MFAPI_H' => -1,
    'HAVE_LIBNCURSES' => -1,
    'HAVE_LIBPDCURSES' => -1,
    'HAVE_LIBXML2' => '1',
    'HAVE_LIBZ' => '1',
    'HAVE_LIMITS_H' => '1',
    'HAVE_LTDL' => '1',
    'HAVE_MACH_O_DYLD_H' => -1,
    'HAVE_MADVISE' => -1,
    'HAVE_MALLINFO' => -1,
    'HAVE_MALLOC_H' => '1',
    'HAVE_MEMCPY' => '1',
    'HAVE_MEMORY_H' => '1',
    'HAVE_MKSTEMP' => '1',
    'HAVE_MMAP' => -1,
    'HAVE_NDIR_H' => -1,
    'HAVE_OPENDIR' => '1',
    'HAVE_POLL' => '1',
    'HAVE_POLL_H' => -1,
    'HAVE_PRAGMA_PACK' => '1',
    'HAVE_PRAGMA_PACK_HPPA' => -1,
    'HAVE_PRELOADED_SYMBOLS' => -1,
    'HAVE_PTHREAD_YIELD' => '1',
    'HAVE_PWD_H' => -1,
    'HAVE_READDIR' => '1',
    'HAVE_READDIR_R_2' => -1,
    'HAVE_READDIR_R_3' => -1,
    'HAVE_RECVMSG' => '1',
    'HAVE_RESOLV_H' => '1',
    'HAVE_SAR' => '1',
    'HAVE_SCHED_YIELD' => -1,
    'HAVE_SENDMSG' => '1',
    'HAVE_SETGROUPS' => -1,
    'HAVE_SETSID' => '1',
    'HAVE_SHL_LOAD' => -1,
    'HAVE_SNPRINTF' => '1',
    'HAVE_STDBOOL_H' => -1,
    'HAVE_STDINT_H' => -1,
    'HAVE_STDLIB_H' => '1',
    'HAVE_STRCASESTR' => -1,
    'HAVE_STRERROR_R' => '1',
    'HAVE_STRINGS_H' => -1,
    'HAVE_STRING_H' => '1',
    'HAVE_STRLCAT' => -1,
    'HAVE_STRLCPY' => -1,
    'HAVE_STRNDUP' => -1,
    'HAVE_STRNSTR' => -1,
    'HAVE_SYSCONF_SC_PAGESIZE' => -1,
    'HAVE_SYSTEM_TOMMATH' => -1,
    'HAVE_SYS_DL_H' => -1,
    'HAVE_SYS_FILIO_H' => -1,
    'HAVE_SYS_INTTYPES_H' => -1,
    'HAVE_SYS_INT_TYPES_H' => -1,
    'HAVE_SYS_MMAN_H' => -1,
    'HAVE_SYS_PARAM_H' => -1,
    'HAVE_SYS_SELECT_H' => -1,
    'HAVE_SYS_STAT_H' => '1',
    'HAVE_SYS_TYPES_H' => '1',
    'HAVE_SYS_UIO_H' => -1,
    'HAVE_TERMIOS_H' => -1,
    'HAVE_UNISTD_H' => -1,
    'HAVE_VSNPRINTF' => '1',
    'HAVE_WORKING_ARGZ' => -1,
    'LIBCLAMAV_FULLVER' => '"6.0.4"',
    'LIBCLAMAV_MAJORVER' => '6',
    'LTDL_DLOPEN_DEPLIBS' => -1,
    'LT_DLSEARCH_PATH' => '""',
    'LT_LIBEXT' => '"dll"',
    'LT_MODULE_EXT' => '".dll"',
    'LT_MODULE_PATH_VAR' => '"LD_LIBRARY_PATH"',
    'LT_OBJDIR' => '""',
    'NDEBUG' => '1',
    'NEED_USCORE' => -1,
    'NOBZ2PREFIX' => -1,
    'NO_FD_SET' => -1,
    'PACKAGE' => 'PACKAGE_NAME',
    'PACKAGE_BUGREPORT' => '"https://bugs.clamav.net/"',
    'PACKAGE_NAME' => '"ClamAV"',
    'PACKAGE_STRING' => '"ClamAV devel"',
    'PACKAGE_TARNAME' => '"clamav"',
    'PACKAGE_URL' => '"https://www.clamav.net/"',
    'PACKAGE_VERSION' => '"devel"',
    'SCANBUFF' => '131072',
    'SETPGRP_VOID' => '1',
    'SIZEOF_INT' => '4',
    'SIZEOF_LONG' => '4',
    'SIZEOF_LONG_LONG' => '8',
    'SIZEOF_SHORT' => '2',
    'SIZEOF_VOID_P' => -1,
    'STDC_HEADERS' => '1',
    'SUPPORT_IPv6' => -1,
    'USE_MPOOL' => 1,
    'USE_SYSLOG' => -1,
    'VERSION_SUFFIX' => '""',
    'WORDS_BIGENDIAN' => '0',
    'LT_LIBPREFIX' => '-1',
    '_LARGEFILE_SOURCE' => -1,
    '_POSIX_PII_SOCKET' => -1,
    '_REENTRANT' => '1',
    '_THREAD_SAFE' => -1,
    '__error_t_defined' => -1,
    'const' => -1,
    'error_t' => -1,
    'inline' => '_inline',
    'off_t' => -1,
    'restrict' => -1,
    'socklen_t' => -1,
    'HAVE_UNAME_SYSCALL' => -1,
    'HAVE__INTERNAL__SHA_COLLECT' => -1,
    'FANOTIFY' => -1
    );


### PROJECT FILES ###
# - makefile: path to Makefile.am from the root of the repo
# - sections: section of Makefile.am to parse (without _SOURCES or _la_SOURCES)
# - output: path to the output vcxproj file
# - makefile_only: *optional* regex to allow exclusion of certain files from the vcxproj (use double escapes)
# - vcxproj_only: *optional* regex to allow inclusion of certain files into the vcxproj (use double escapes)

my @PROJECTS = (
    # LIBCLAMAV #
    {makefile => 'libclamav', sections => ['libclamav', 'libclamav_internal_utils'], output => 'win32/libclamav.vcxproj', vcxproj_only => '(3rdparty\\\\|compat\\\\|getopt\\.c|misc\\.c)'},

    # LIBCLAMUNRAR_IFACE #
    {makefile => 'libclamav', sections => ['libclamunrar_iface'], output => 'win32/libclamunrar_iface.vcxproj', vcxproj_only => 'compat\\\\'},

    # LIBCLAMUNRAR #
    {makefile => 'libclamav', sections => ['libclamunrar'], output => 'win32/libclamunrar.vcxproj'},

    # LIBCLAMAVCXX #
    {makefile => 'libclamav/c++', sections => ['libclamavcxx'], output => 'win32/libclamavcxx.vcxproj'},

    # CLAMSCAN #
    {makefile => 'clamscan', sections => ['clamscan'], output => 'win32/clamscan.vcxproj', makefile_only => '(optparser\\.c|getopt\\.c)$'},

    # CLAMDSCAN #
    {makefile => 'clamdscan', sections => ['clamdscan'], output => 'win32/clamdscan.vcxproj', makefile_only => '(optparser\\.c|getopt\\.c)$'},

    # CLAMD #
    {makefile => 'clamd', sections => ['clamd'], output => 'win32/clamd.vcxproj', makefile_only => '(optparser\\.c|getopt\\.c|(daz|clam)uko.*)$'},

    # FRESHCLAM #
    {makefile => 'freshclam', sections => ['freshclam'], output => 'win32/freshclam.vcxproj', makefile_only => '(optparser\\.c|getopt\\.c)$', vcxproj_only => 'compat\\\\'},

    # CLAMCONF #
    {makefile => 'clamconf', sections => ['clamconf'], output => 'win32/clamconf.vcxproj', makefile_only => '(optparser\\.c$|getopt\\.c)$'},

    # CLAMBC #
    {makefile => 'clambc', sections => ['clambc'], output => 'win32/clambc.vcxproj', makefile_only => '(optparser\\.c|getopt\\.c)$'},

    # LLVMsystem #
    {makefile => 'libclamav/c++', sections => ['libllvmsystem'], output => 'win32/LLVMsystem.vcxproj'},

    # LLVMcodegen #
    {makefile => 'libclamav/c++', sections => ['libllvmcodegen'], output => 'win32/LLVMcodegen.vcxproj'},

    # LLVMx86codegen #
    {makefile => 'libclamav/c++', sections => ['libllvmx86codegen'], output => 'win32/LLVMx86codegen.vcxproj'},

    # LLVMjit #
    {makefile => 'libclamav/c++', sections => ['libllvmjit'], output => 'win32/LLVMjit.vcxproj'},

    # sigtool #
    {makefile => 'sigtool', sections => ['sigtool'], output => 'win32/sigtool.vcxproj', makefile_only => '(optparser\\.c|getopt\\.c)$'},

    );

###########################################################
# STOP HACKING HERE  STOP HACKING HERE  STOP HACKING HERE # 
###########################################################




my %ref_files;
my %files;
my $exclude;
my $do_patch = 0;

sub file {
    my ($twig, $file) = @_;
    my $fname = $file->{'att'}->{'Include'};
    return unless $fname =~ /^.*\.c(pp)?$/;
    return if defined($exclude) && $fname =~ /$exclude/;
    $file->delete unless !$do_patch || exists $ref_files{$fname};
    $files{$fname} = 1;
}

$do_patch = $#ARGV == 0 && $ARGV[0] eq '--regen';
die("Usage:\nupdate-win32.pl [--regen]\n\nChecks the win32 build system and regenerates it if --regen is given\n\n") if $#ARGV == 0 && $ARGV[0] eq '--help';
my $BASE_DIR = `git rev-parse --git-dir`;
chomp($BASE_DIR);
die "This script only works in a GIT repository\n" unless $BASE_DIR;
$BASE_DIR = "$BASE_DIR/..";
my $VER = `git describe --always`;
chomp($VER);
die "Cannot determine git version via git-describe\n" unless $VER && !$?;
$VER = "devel-$VER";
my $w = 0;

print "Processing clamav-config.h...\n";

open IN, "< $BASE_DIR/clamav-config.h.in" || die "Cannot find clamav-config.h.in: $!\n";
$do_patch and open OUT, "> $BASE_DIR/win32/clamav-config.h" || die "Cannot open clamav-config.h: $!\n";
$do_patch and  print OUT "/* clamav-config.h.  Generated from clamav-config.h.in by update-win32.  */\n\n";
while(<IN>) {
    if(!/^#\s*undef (.*)/) {
	$do_patch and print OUT $_;
	next;
    }
    if($1 eq 'VERSION') {
	$do_patch and print OUT "#define VERSION \"$VER\"\n";
	next;
    }
    if(!exists($CONF{$1})) {
	warn "Warning: clamav-config.h option '$1' is unknown. Please take a second to update this script.\n";
	$do_patch and print OUT "/* #undef $1 */\n";
	$w++;
	next;
    }
    if($CONF{$1} eq -1) {
	$do_patch and print OUT "/* #undef $1 */\n";
    } else {
	$do_patch and print OUT "#define $1 $CONF{$1}\n";
    }
}
close IN;
if($do_patch) {
    close OUT;
    print "clamav-config.h generated ($w warnings)\n";
} else {
    print "clamav-config.h.in parsed ($w warnings)\n";
}
foreach (@PROJECTS) {
    my %proj = %$_;
    %files = ();
    %ref_files = ();
    my $got = 0;
    $exclude = $proj{'vcxproj_only'};
    print "Parsing $proj{'output'}...\n";
    open IN, "$proj{'makefile'}/Makefile.am" or die "Cannot open $proj{'makefile'}/Makefile.am\n";
    while(<IN>) {
	my ($trail, $fname);
	if($got == 0) {
	    next unless /^(.*?)(?:_la)?_SOURCES\s*\+?=\s*(.*?)\s*(\\)?\s*$/;
	    next unless grep {$_ eq $1} (@{$proj{'sections'}});
	    $got = 1;
	    $trail = $3;
	    $fname = $2;
	} else {
	    /^\s*(.*?)(\s*\\)?$/;
	    $trail = $2;
	    $fname = $1;
	}
	if($fname =~ /\.c(pp)?$/) {
	    if($fname =~ s/^(\$\(top_srcdir\)|\.\.)\///) {
		$fname = "../$fname";
	    } else {
		$fname = "../$proj{'makefile'}/$fname";
	    }
            $fname =~ y/\//\\/;
	    $ref_files{$fname} = 1 unless defined($proj{'makefile_only'}) && $fname =~ /$proj{'makefile_only'}/;
	}
	$got = 0 unless $trail;
    }
    close IN;

    my $xml = XML::Twig->new( keep_encoding => 1, twig_handlers => { 'ItemGroup/ClCompile' => \&file }, pretty_print => 'record' );
    $xml->parsefile("$BASE_DIR/$proj{'output'}");

    my @missing_in_vcxproj = grep ! exists $files{$_}, keys %ref_files;
    my @missing_in_makefile = grep ! exists $ref_files{$_}, keys %files;

    if($do_patch) {
	if($#missing_in_vcxproj >=0) {
	    my $group = $xml->root;
	    while($group = $group->next_elt('ItemGroup')) {
		last if $group->has_child('ClCompile');
	    }
	    if(!defined($group)) {
		$group = $xml->root('ItemGroup');
		$group->paste($xml->root);
	    }
	    foreach (@missing_in_vcxproj) {
		my $addfile = $xml->root->new('ClCompile');
		$addfile->set_att('Include' => $_);
		$addfile->paste($group);
		warn "Warning: File $_ not in $proj{'output'}: added!\n" foreach @missing_in_vcxproj;
	    }
	}
	warn "Warning: File $_ not in $proj{'makefile'}/Makefile.am: deleted!\n" foreach @missing_in_makefile;
	my ($fh, $filename) = tempfile();
	$xml->print($fh);
	close $fh;
	move($filename, "$proj{'output'}");
	print "Regenerated $proj{'output'} (".($#missing_in_vcxproj + $#missing_in_makefile + 2)." changes)\n";
    } else {
	warn "Warning: File $_ not in $proj{'output'}\n" foreach @missing_in_vcxproj;
	warn "Warning: File $_ not in $proj{'makefile'}/Makefile.am\n" foreach @missing_in_makefile;
	print "Parsed $proj{'output'} (".($#missing_in_vcxproj + $#missing_in_makefile + 2)." warnings)\n";
    }
}

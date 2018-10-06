# ClamAV Development
This page aims to provide information useful when developing, debugging, or
profiling ClamAV.

## Building ClamAV for Development
Below are some recommendations for building ClamAV so that it's easy to debug:

### Running ./configure
Suggestions:

- Modify the CFLAGS variable as follows (assuming you're build with gcc):

    - Include gdb debugging information (`-ggdb`).  This will make it easier
      to debug with gdb

    - Disable optimizations (`-O0`).  This will ensure the line numbers you
      see in gdb match up with what is actually being executed.

- Run configure with the following options:

    - ``--prefix=`pwd`/build``: This will cause `make install` to install
      into the specified directory to avoid potentially tainting a release
      install of ClamAV that you may have.

    - `--enable-debug`: This will define *CL_DEBUG*, which mostly just enables
      additional print statements that are useful for debugging

    - `--enable-check`: Enables the unit tests, which can be run with 'make
      check'

    - `--enable-coverage`: If using gcc, sets `-fprofile-arcs -ftest-coverage`
      so that code coverage metrics will get generated when the program is run.
      Note that the code inserted to store program flow data may show up in
      any generated flame graphs or profiling output, so if you don't care
      about code coverage, omit this

    - `--enable-libjson`: Enables libjson, which enables the `--gen-json` option.
      The json output contains additional metadata that might be helpful when
      debugging.

    - `--enable-static --disable-shared`: This will only build libclamav and
      the supporting libraries as static libraries, and will result in the
      clamscan that is built having this code embedded.  This is useful for
      running programs like gprof which don't handle profiling code in shared
      objects.

    - `--with-systemdsystemunitdir=no`: Don't try to register clamd as a
      systemd service

    - You might want to include the following flags also so that the optional
      functionality is enabled: `--enable-experimental --enable-clamdtop
      --enable-libjson --enable-milter --enable-xml --enable-pcre`.
      Note that this may require you to install additional development
      libraries.

    - I ran into problems building with llvm on Ubuntu 18.04, so add
      `--disable-llvm`

Altogether, the following configure command can be used:

```
CFLAGS="-ggdb -O0" ./configure --prefix=`pwd`/built --enable-debug --enable-check --enable-coverage --enable-libjson --enable-static --disable-shared --with-systemdsystemunitdir=no --enable-experimental --enable-clamdtop --enable-libjson --enable-xml --enable-pcre --disable-llvm
```
To satisify all library dependencies, something like this should work
(from Ubuntu 18.04):
```
sudo apt-get install git gcc libxml2-dev libssl-dev make libmilter-dev libcurl4-openssl-dev libjson-c-dev check pkgconf libncurses5-dev libpcre3-dev g++ libtool libbz2-dev
```

### Running make
Run the following to finishing building.  `-j2` in the code below is used to
indicate that the build process should use 2 cores.  Increase this if your
machine is more powerful.
```
make -j2
make install
```
Also, you can run 'make check' to run the unit tests

### Downloading the Official Ruleset
If you plan to use custom rules for testing, you can invoke clamscan via
`./built/bin/clamscan`, specifying your custom rule files via `-d` parameters.

If you want to download the official ruleset to use with clamscan, do the
following:
1. Run `mkdir -p built/share/clamav`
2. Comment out line 8 of etc/freshclam.conf.sample
3. Run `./built/bin/freshclam --config-file etc/freshclam.conf.sample`

## General Debugging
### Useful clamscan Flags
The following are useful flags to include when debugging clamscan:

- `--debug --verbose`: Print lots of helpful debug information

- `--gen-json`: Print some additional debug information in a JSON format

- `--statistics=pcre --statistics=bytecode`:  Print execution statistics on any
  PCRE and bytecode rules that were evaluated

- `--dev-performance`: Print per-file statistics regarding how long scanning
  took and the times spent in various scanning stages

- `--detect-broken`: This will attempt to detect broken executable files.  If
  an executable is determined to be broken, some functionality might not get
  invoked for the sample, and this could be an indication of an issue parsing
  the PE header or file.  This causes those binary to generate an alert instead
  of just continuing on.

- `--max-filesize=2000M --max-scansize=2000M --max-files=2000000
   --max-recursion=2000000 --max-embeddedpe=2000M --max-htmlnormalize=2000000
   --max-htmlnotags=2000000 --max-scriptnormalize=2000000
   --max-ziptypercg=2000000 --max-partitions=2000000 --max-iconspe=2000000
   --max-rechwp3=2000000 --pcre-match-limit=2000000
   --pcre-recmatch-limit=2000000 --pcre-max-filesize=2000M`:
  Effectively disables all file limits and maximums for scanning.  This is
  useful if you'd like to ensure that all files in a set get scanned, and would
  prefer clam to just run slowly or crash rather than skip a file because it
  encounters one of these thresholds

The following are useful flags to include when debugging rules that you're
writing:

- `-d`: Allows you to specify a custom ClamAV rule file from the command line

- `--bytecode-unsigned`: If you are testing custom bytecode rules, you'll need
  this flag so that clamscan actually runs the bytecode signature

- `--all-match`: Allows multiple signatures to match on a file being scanned

- `--leave-temps --tmpdir=/tmp`: By default, ClamAV will attempt to extract
  embedded files that it finds, normalize certain text files before looking
  for matches, and unpack packed executables that it has unpacking support for.
  These flags tell ClamAV to write these intermediate files out to the
  directory specified.  Usually when a file is written, it will mention the
  file name in the --debug output, so you can have some idea at what stage in
  the scanning process a tmp file was created.

- `--dump-certs`: For signed PE files that match a rule, display information
  about the certificates stored within the binary.  Note - sigtool has this
  functionality as well and doesn't require a rule match to view the cert data

### Useful sigtool Flags
sigtool pulls in libclamav and provides shortcuts to doing tasks that clamscan
does behind the scenes.  These can be really useful when writing a signature or
trying to get information about a signature that might be causing FPs or
performance problems.

The following sigtool flags can be useful when debugging:

- `--unpack`: Unpack the specified CVD/CLD file

- `--decode`: Given a ClamAV signature from STDIN, show a more user-friendly
  representation of it

- `--hex-dump`: Given a sequence of bytes from STDIN, print the hex equivalent

- `--mdb`: Generate section hashes of the specified file

- `--imp`: Generate import hashes of the specified file

- `--html-normalise`: Normalize the specified HTML file in the way that
  clamscan will before looking for rule matches.  This makes it either to write
  rules that will actually match.

- `--ascii-normalise`: Normalized the specified ASCII text file in the way that
  clamscan will before looking for rule matches

- `--print-certs`: Print the Authenticode signatures of any PE files specified.
  This is useful when writing signature-based .crb rule files.

- `--vba`: Extract VBA/Word6 macro code

### Using gdb
Given that you might want to pass a lot of arguments to gdb, consider taking
advantage of the `--args` parameter.  For example:
```
gdb --args ./built/bin/clamscan -d /tmp/test.ldb -d /tmp/blacklist.crb -d --dumpcerts --debug --verbose --max-filesize=2000M --max-scansize=2000M --max-files=2000000 --max-recursion=2000000 --max-embeddedpe=2000M --max-iconspe=2000000 f8f101166fec5785b4e240e4b9e748fb6c14fdc3cd7815d74205fc59ce121515
```

When using ClamAV without libclamav statically linked, if you set breakpoints
on libclamav functions by name, you'll need to make sure to indicate that
the breakpoints should be resolved after libraries have been loaded.

For other documentation about how to use gdb, check out the following
resources:
 - [A Guide to gdb](http://www.cabrillo.edu/~shodges/cs19/progs/guide_to_gdb_1.1.pdf)
 - [gdb Quick Reference](http://users.ece.utexas.edu/~adnan/gdb-refcard.pdf)

## Hunting for Memory Leaks
You can easily hunt for memory leaks with valgrind.  Check out this guide to
get started:
 - [Valgrind Quick Start](http://valgrind.org/docs/manual/quick-start.html)
If checking for leaks, be sure to run clamscan with samples that will hit as
many of the unique code paths in the code you are testing.  An example
invocation is as follows:
```
valgrind --leak-check=full ./built/bin/clamscan -d /tmp/test.ldb --leave-temps --tempdir /tmp/test --debug --verbose /tmp/upx-samples/ > /tmp/upx-results-2.txt 2>&1
```
Alternatively, on Linux, you can use glibc's built-in leak checking
functionality:
```
MALLOC_CHECK_=7 ./built/bin/clamscan
```
See the [mallopt man page](http://manpages.ubuntu.com/manpages/trusty/man3/mallopt.3.html) for more details

## Computing Code Coverage
gcov/lcov can be used to produce a code coverage report indicating which lines
of code were executed on a single run or by multiple runs of clamscan.  NOTE:
for these metrics to be collected, ClamAV needs to have been configured with
the `--enable-coverage` option.

First, run the following to zero out all of the performance metrics:
```
lcov -z --directory . --output-file coverage.lcov.data
```
Next, run ClamAV through whatever test cases you have.  Then, run lcov again
to collect the coverage data as follows:
```
lcov -c --directory . --output-file coverage.lcov.data
```
Finally, run the genhtml tool that ships with lcov to produce the code coverage
report:
```
genhtml coverage.lcov.data --output-directory report
```
The report directory will have an index.html page which can be loaded into any
web browser.

For more information, visit the [lcov webpage](http://ltp.sourceforge.net/coverage/lcov.php)

## Profiling - Flame Graphs
[FlameGraph](https://github.com/brendangregg/FlameGraph) is a great tool for
generating interactive flame graphs based collected profiling data.  The github
page has thorough documentation on how to use the tool, but an overview is
presented below:

First, install perf, which on Linux can be done via:
```
apt-get install linux-tools-common linux-tools-generic linux-tools-`uname -r`
```

Modify the system settings to allow perf record to be run by a standard user:
```
$ sudo su
# cat /proc/sys/kernel/perf_event_paranoid 
# echo "1" > /proc/sys/kernel/perf_event_paranoid 
# exit
```

Invoke clamscan via perf record as follows, and run perf script to collect the
profiling data:
```
perf record -F 100 -g -- ./built/bin/clamscan -d /tmp/test.ldb /tmp/2aa6b18d509090c60c3e4ecdd8aeb16e5f149807e3404c86892112710eab576d
perf script > out.perf
```
The '-F' parameter indicates how many samples should be collected during
program execution.  If your scan will take a long time to run, a lower value
should be sufficient.  Otherwise, consider choosing a higher value (on Ubuntu
18.04, 7250 is the max frequency, but it can be increased via
/proc/sys/kernel/perf_event_max_sample_rate.

Check out the FlameGraph project and run the following commands to generate
the flame graph:
```
perl stackcollapse-perf.pl ../clamav-devel/out.perf > /tmp/out.folded
perl flamegraph.pl /tmp/out.folded > /tmp/test.svg
```

The SVG that is generated is interactive, but some viewers don't support this.
Be sure to open it in a web browser like Chrome to be able to take full
advantage of it.

## Profiling - Callgrind
Callgrind is a profiling tool included with valgrind.  This can be done by
prepending `valgrind --tool=callgrind ` to the clamscan command.
[kcachegrind](https://kcachegrind.github.io/html/Home.html)
is a follow-on tool that will graphically present the
profiling data and allow you to explore it visually, although if you don't
already use KDE you'll have to install lots of extra packages to use it.

## System Call Tracing / Fault Injection
strace can be used to track the system calls that are performed and provide the
number of calls / time spent in each system call.  This can be done by
prepending `strace -c ` to a clamscan command.  Results will look something
like this:
```
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 95.04    0.831430          13     62518           read
  3.22    0.028172          14      2053           munmap
  0.69    0.006005           3      2102           mmap
  0.28    0.002420           7       344           pread64
  0.16    0.001415           5       305         1 openat
  0.13    0.001108           3       405           write
  0.11    0.000932          23        40           mprotect
  0.07    0.000632           2       310           close
  0.07    0.000583           9        67        30 access
  0.05    0.000395           1       444           lseek
  0.04    0.000344           2       162           fstat
  0.04    0.000338           1       253           brk
  0.03    0.000262           1       422           fcntl
  0.02    0.000218          16        14           futex
  0.01    0.000119           1       212           getpid
  0.01    0.000086          14         6           getdents
  0.00    0.000043           7         6           dup
  0.00    0.000040           1        31           unlink
  0.00    0.000038          19         2           rt_sigaction
  0.00    0.000037          19         2           rt_sigprocmask
  0.00    0.000029           1        37           stat
  0.00    0.000022          11         2           prlimit64
  0.00    0.000021          21         1           sysinfo
  0.00    0.000020           1        33           clock_gettime
  0.00    0.000019          19         1           arch_prctl
  0.00    0.000018          18         1           set_tid_address
  0.00    0.000018          18         1           set_robust_list
  0.00    0.000013           0        60           lstat
  0.00    0.000011           0        65           madvise
  0.00    0.000002           0        68           geteuid
  0.00    0.000000           0         1           execve
  0.00    0.000000           0         1           uname
  0.00    0.000000           0         1           getcwd
------ ----------- ----------- --------- --------- ----------------
100.00    0.874790                 69970        31 total
```

strace can also be used for cool things like system call fault injection.  For
instance, I was curious whether the 'read' bytecode API call was implemented
in such a way that the underlying read system call could handle EINTR being
returned (which can happen periodically).  To test this, I wrote the following
bytecode rule:
```
VIRUSNAME_PREFIX("BC.Heuristic.Test.Read.Passed")
VIRUSNAMES("")
TARGET(0)

SIGNATURES_DECL_BEGIN
DECLARE_SIGNATURE(zeroes)
SIGNATURES_DECL_END

SIGNATURES_DEF_BEGIN
DEFINE_SIGNATURE(zeroes, "0:0000")
SIGNATURES_DEF_END

bool logical_trigger()
{
    return matches(Signatures.zeroes);
}

#define READ_S(value, size) if (read(value, size) != size) return 0;

int entrypoint(void)
{
    char buffer[65536];
    int i;

    for (i = 0; i < 256; i++)
    {
        debug(i);
        debug("\n");
        READ_S(buffer, sizeof(buffer));
    }

    foundVirus("");
    return 0;
}
```
I compiled the rule, made a test file to match against, and ran it under
strace to determine what underlying read system call was used for the bytecode
read function:
```
clambc-compiler read_test.bc
dd if=/dev/zero of=/tmp/zeroes bs=65535 count=256
strace clamscan -d read_test.cbc --bytecode-unsigned /tmp/zeroes
```
It uses pread64 under the hood, so the following command could be used for fault
injection:
```
strace -e fault=pread64:error=EINTR:when=20+10 clamscan -d read_test.cbc --bytecode-unsigned /tmp/zeroes 
```
This command tells strace to skip the first 20 pread64 calls (these appear to
be used by the loader, which didn't seem to handle EINTR correctly) but to
inject EINTR for every 10th call afterward.  We can see the injection in action
and that the system call is retried successfully:
```
pread64(3, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"..., 65536, 15007744) = 65536
pread64(3, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"..., 65536, 15073280) = 65536
pread64(3, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"..., 65536, 15138816) = 65536
pread64(3, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"..., 65536, 15204352) = 65536
pread64(3, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"..., 65536, 15269888) = 65536
pread64(3, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"..., 65536, 15335424) = 65536
pread64(3, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"..., 65536, 15400960) = 65536
pread64(3, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"..., 65536, 15466496) = 65536
pread64(3, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"..., 65536, 15532032) = 65536
pread64(3, 0x7f6a7ff43000, 65536, 15597568) = -1 EINTR (Interrupted system call) (INJECTED)
pread64(3, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"..., 65536, 15597568) = 65536
```
More documentation on this feature can be found in
[this presentation](https://archive.fosdem.org/2017/schedule/event/failing_strace/attachments/slides/1630/export/events/attachments/failing_strace/slides/1630/strace_fosdem2017_ta_slides.pdf)
from FOSDEM 2017.

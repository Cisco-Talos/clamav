/*
 *  Copyright (C) 2013-2019 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *  Copyright (C) 2008-2013 Sourcefire, Inc.
 *
 *  Author: Tomasz Kojm <tkojm@clamav.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

/*
 * TODO:
 * - clamconf, milter
 * - clamconf: generation/verification/updating of config files and man page entries
 * - automatically generate --help pages (use the first line from the description)
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <ctype.h>

#include "libclamav/clamav.h"
#include "shared/optparser.h"
#include "shared/misc.h"

#include "libclamav/regex/regex.h"
#include "libclamav/default.h"
#include "libclamav/others.h"

#include "getopt.h"

#define MAXCMDOPTS  150

#define MATCH_NUMBER "^[0-9]+$"
#define MATCH_SIZE "^[0-9]+[KM]?$"
#define MATCH_BOOL "^(yes|true|1|no|false|0)$"

#define FLAG_MULTIPLE	1 /* option can be used multiple times */
#define FLAG_REQUIRED	2 /* arg is required, even if there's a default value */
#define FLAG_HIDDEN	4 /* don't print in clamconf --generate-config */
#define FLAG_REG_CASE	8 /* case-sensitive regex matching */

const struct clam_option __clam_options[] = {
    /* name,   longopt, sopt, argtype, regex, num, str, flags, owner, description, suggested */

    /* cmdline only */
    { NULL, "help", 'h', CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_FRESHCLAM | OPT_CLAMSCAN | OPT_CLAMDSCAN | OPT_SIGTOOL | OPT_MILTER | OPT_CLAMCONF | OPT_CLAMDTOP | OPT_CLAMBC, "", "" },
    { NULL, "config-file", 'c', CLOPT_TYPE_STRING, NULL, 0, CONFDIR_CLAMD, FLAG_REQUIRED, OPT_CLAMD | OPT_CLAMDSCAN | OPT_CLAMDTOP, "", "" },
    { NULL, "config-file", 0, CLOPT_TYPE_STRING, NULL, 0, CONFDIR_FRESHCLAM, FLAG_REQUIRED, OPT_FRESHCLAM, "", "" },
    { NULL, "config-file", 'c', CLOPT_TYPE_STRING, NULL, 0, CONFDIR_MILTER, FLAG_REQUIRED, OPT_MILTER, "", "" },
    { NULL, "version", 'V', CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_FRESHCLAM | OPT_CLAMSCAN | OPT_CLAMDSCAN | OPT_SIGTOOL | OPT_MILTER | OPT_CLAMCONF | OPT_CLAMDTOP | OPT_CLAMBC, "", "" },
    { NULL, "debug", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMBC | OPT_CLAMD | OPT_FRESHCLAM | OPT_CLAMSCAN | OPT_SIGTOOL, "", "" },
    { NULL, "gen-json", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN | OPT_SIGTOOL, "", "" },
    { NULL, "verbose", 'v', CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_FRESHCLAM | OPT_CLAMSCAN | OPT_CLAMDSCAN | OPT_SIGTOOL, "", "" },
    { NULL, "dumpcerts", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMSCAN, "Dump authenticode certificate chain.", "" },
    { NULL, "quiet", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_FRESHCLAM | OPT_CLAMSCAN | OPT_CLAMDSCAN | OPT_SIGTOOL, "", "" },
    { NULL, "leave-temps", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMSCAN, "", "" },
    { NULL, "no-warnings", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_FRESHCLAM, "", "" },
    { NULL, "show-progress", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_FRESHCLAM, "", "" },
    { NULL, "stdout", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_FRESHCLAM | OPT_CLAMSCAN | OPT_CLAMDSCAN | OPT_SIGTOOL, "", "" },
    { NULL, "daemon", 'd', CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_FRESHCLAM, "", "" },
    { NULL, "no-dns", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_FRESHCLAM, "", "" },
    { NULL, "list-mirrors", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_FRESHCLAM, "", "" },
    { NULL, "update-db", 0, CLOPT_TYPE_STRING, NULL, -1, NULL, FLAG_MULTIPLE, OPT_FRESHCLAM, "", "" },
    { NULL, "reload", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMDSCAN, "", "" },
    { NULL, "multiscan", 'm', CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMDSCAN, "", "" },
    { NULL, "fdpass", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMDSCAN, "", "" },
    { NULL, "stream", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMDSCAN, "", "" },
    { NULL, "allmatch", 'z', CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMSCAN | OPT_CLAMDSCAN, "", "" },
    { NULL, "normalize", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 1, NULL, 0, OPT_CLAMSCAN, "Perform HTML, script, and text normalization", "" },
    { NULL, "database", 'd', CLOPT_TYPE_STRING, NULL, -1, DATADIR, FLAG_REQUIRED | FLAG_MULTIPLE, OPT_CLAMSCAN, "", "" }, /* merge it with DatabaseDirectory (and fix conflict with --datadir */
    { NULL, "recursive", 'r', CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMSCAN, "", "" },
    { NULL, "gen-mdb", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMSCAN, "Always generate MDB entries for PE sections", "" },
    { NULL, "follow-dir-symlinks", 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, 1, NULL, 0, OPT_CLAMSCAN, "", "" },
    { NULL, "follow-file-symlinks", 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, 1, NULL, 0, OPT_CLAMSCAN, "", "" },
    { NULL, "bell", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMSCAN, "", "" },
    { NULL, "no-summary", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMSCAN | OPT_CLAMDSCAN, "", "" },
    { NULL, "file-list", 'f', CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_CLAMSCAN | OPT_CLAMDSCAN, "", "" },
    { NULL, "infected", 'i', CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMSCAN | OPT_CLAMDSCAN, "", "" },
    { NULL, "suppress-ok-results", 'o', CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMSCAN, "", "" },
    { NULL, "move", 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_CLAMSCAN | OPT_CLAMDSCAN, "", "" },
    { NULL, "copy", 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_CLAMSCAN | OPT_CLAMDSCAN, "", "" },
    { NULL, "remove", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMSCAN | OPT_CLAMDSCAN, "", "" },
    { NULL, "exclude", 0, CLOPT_TYPE_STRING, NULL, -1, NULL, FLAG_MULTIPLE, OPT_CLAMSCAN, "", "" },
    { NULL, "exclude-dir", 0, CLOPT_TYPE_STRING, NULL, -1, NULL, FLAG_MULTIPLE, OPT_CLAMSCAN, "", "" },
    { NULL, "include", 0, CLOPT_TYPE_STRING, NULL, -1, NULL, FLAG_MULTIPLE, OPT_CLAMSCAN, "", "" },
    { NULL, "include-dir", 0, CLOPT_TYPE_STRING, NULL, -1, NULL, FLAG_MULTIPLE, OPT_CLAMSCAN, "", "" },
    { NULL, "structured-ssn-format", 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, 0, NULL, 0, OPT_CLAMSCAN, "", "" },
    { NULL, "hex-dump", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_SIGTOOL, "", "" },
    { NULL, "md5", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_SIGTOOL, "", "" },
    { NULL, "sha1", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_SIGTOOL, "", "" },
    { NULL, "sha256", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_SIGTOOL, "", "" },
    { NULL, "mdb", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_SIGTOOL, "", "" },
    { NULL, "imp", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_SIGTOOL, "", "" },
    { NULL, "print-certs", 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_SIGTOOL, "", "" },
    { NULL, "html-normalise", 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_SIGTOOL, "", "" },
    { NULL, "ascii-normalise", 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_SIGTOOL, "", "" },
    { NULL, "utf16-decode", 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_SIGTOOL, "", "" },
    { NULL, "build", 'b', CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_SIGTOOL, "", "" },
    { NULL, "max-bad-sigs", 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, 3000, NULL, 0, OPT_SIGTOOL, "Maximum number of mismatched signatures when building a CVD. Zero disables this limit.", "3000" },
    { NULL, "flevel", 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, CL_FLEVEL, NULL, 0, OPT_SIGTOOL, "Feature level to put in the CVD", "" },
    { NULL, "cvd-version", 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, 0, NULL, 0, OPT_SIGTOOL, "Version number of the CVD to build", "" },
    { NULL, "unsigned", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_SIGTOOL, "", "" },
    { NULL, "no-cdiff", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_SIGTOOL, "", "" },
    { NULL, "server", 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_SIGTOOL, "", "" },
    { NULL, "unpack", 'u', CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_SIGTOOL, "", "" },
    { NULL, "unpack-current", 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_SIGTOOL, "", "" },
    { NULL, "info", 'i', CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_SIGTOOL, "", "" },
    { NULL, "list-sigs", 'l', CLOPT_TYPE_STRING, NULL, -1, DATADIR, 0, OPT_SIGTOOL, "", "" },
    { NULL, "find-sigs", 'f', CLOPT_TYPE_STRING, NULL, -1, DATADIR, FLAG_REQUIRED, OPT_SIGTOOL, "", "" },
    { NULL, "decode-sigs", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_SIGTOOL, "", "" },
    { NULL, "test-sigs", 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_SIGTOOL, "", "" },
    { NULL, "vba", 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_SIGTOOL, "", "" },
    { NULL, "vba-hex", 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_SIGTOOL, "", "" },
    { NULL, "diff", 'd', CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_SIGTOOL, "", "" },
    { NULL, "compare", 'c', CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_SIGTOOL, "", "" },
    { NULL, "run-cdiff", 'r', CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_SIGTOOL, "", "" },
    { NULL, "verify-cdiff", 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_SIGTOOL, "", "" },
    { NULL, "hybrid", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_SIGTOOL, "Create a hybrid (standard and bytecode) database file", ""},
    { NULL, "defaultcolors", 'd', CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMDTOP, "", "" },

    { NULL, "config-dir", 'c', CLOPT_TYPE_STRING, NULL, 0, CONFDIR, FLAG_REQUIRED, OPT_CLAMCONF, "", "" },
    { NULL, "non-default", 'n', CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMCONF, "", "" },
    { NULL, "generate-config", 'g', CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_CLAMCONF, "", "" },

    { NULL, "force-interpreter", 'f', CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMBC, "Force using the interpreter instead of the JIT", "" },
    { NULL, "trust-bytecode", 't', CLOPT_TYPE_BOOL, MATCH_BOOL, 1, NULL, 0, OPT_CLAMBC, "Trust loaded bytecode (default yes)", ""},
    { NULL, "info", 'i', CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMBC, "Load and print bytecode information without executing", ""},
    { NULL, "printsrc", 'p', CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMBC, "Print source code of bytecode", ""},
    { NULL, "printbcir", 'c', CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMBC, "Print IR of bytecode signature", ""},
    { NULL, "input", 'r', CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_CLAMBC, "Input file to run the bytecode n", ""},
    { NULL, "trace", 'T', CLOPT_TYPE_NUMBER, MATCH_NUMBER, 7, NULL, 0, OPT_CLAMBC, "bytecode trace level",""},
    { NULL, "no-trace-showsource", 's', CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMBC, "Don't show source line during tracing",""},

    { NULL, "archive-verbose", 'a', CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMSCAN, "", ""},

    /* cmdline only - deprecated */
    { NULL, "bytecode-trust-all", 't', CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMSCAN | OPT_DEPRECATED, "", ""},
    { NULL, "http-proxy", 0, CLOPT_TYPE_STRING, NULL, 0, NULL, 0, OPT_FRESHCLAM | OPT_DEPRECATED, "", "" },
    { NULL, "proxy-user", 0, CLOPT_TYPE_STRING, NULL, 0, NULL, 0, OPT_FRESHCLAM | OPT_DEPRECATED, "", "" },
    { NULL, "log-verbose", 0, CLOPT_TYPE_BOOL, NULL, 0, NULL, 0, OPT_FRESHCLAM | OPT_DEPRECATED, "", "" },
    { NULL, "force", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMSCAN | OPT_DEPRECATED, "", "" },
    { NULL, "disable-summary", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMSCAN | OPT_CLAMDSCAN | OPT_DEPRECATED, "", "" },
    { NULL, "disable-archive", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMSCAN | OPT_DEPRECATED, "", "" },
    { NULL, "no-archive", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMSCAN | OPT_DEPRECATED, "", "" },
    { NULL, "no-pe", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMSCAN | OPT_DEPRECATED, "", "" },
    { NULL, "no-elf", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMSCAN | OPT_DEPRECATED, "", "" },
    { NULL, "no-ole2", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMSCAN | OPT_DEPRECATED, "", "" },
    { NULL, "no-pdf", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMSCAN | OPT_DEPRECATED, "", "" },
    { NULL, "no-html", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMSCAN | OPT_DEPRECATED, "", "" },
    { NULL, "no-mail", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMSCAN | OPT_DEPRECATED, "", "" },
    { NULL, "no-phishing-sigs", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMSCAN | OPT_DEPRECATED, "", "" },
    { NULL, "no-phishing-scan-urls", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMSCAN | OPT_DEPRECATED, "", "" },
    { NULL, "no-algorithmic", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMSCAN | OPT_DEPRECATED, "", "" },
    { NULL, "no-phishing-restrictedscan", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMSCAN | OPT_DEPRECATED, "", "" },
    { NULL, "max-ratio", 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, 0, NULL, 0, OPT_CLAMSCAN | OPT_DEPRECATED, "", "" },
    { NULL, "max-space", 0, CLOPT_TYPE_SIZE, MATCH_SIZE, 0, NULL, 0, OPT_CLAMSCAN | OPT_DEPRECATED, "", "" },
    { NULL, "unzip", 0, CLOPT_TYPE_STRING, NULL, -1, "foo", 0, OPT_CLAMSCAN | OPT_DEPRECATED, "", "" },
    { NULL, "unrar", 0, CLOPT_TYPE_STRING, NULL, -1, "foo", 0, OPT_CLAMSCAN | OPT_DEPRECATED, "", "" },
    { NULL, "arj", 0, CLOPT_TYPE_STRING, NULL, -1, "foo", 0, OPT_CLAMSCAN | OPT_DEPRECATED, "", "" },
    { NULL, "unzoo", 0, CLOPT_TYPE_STRING, NULL, -1, "foo", 0, OPT_CLAMSCAN | OPT_DEPRECATED, "", "" },
    { NULL, "lha", 0, CLOPT_TYPE_STRING, NULL, -1, "foo", 0, OPT_CLAMSCAN | OPT_DEPRECATED, "", "" },
    { NULL, "jar", 0, CLOPT_TYPE_STRING, NULL, -1, "foo", 0, OPT_CLAMSCAN | OPT_DEPRECATED, "", "" },
    { NULL, "tar", 0, CLOPT_TYPE_STRING, NULL, -1, "foo", 0, OPT_CLAMSCAN | OPT_DEPRECATED, "", "" },
    { NULL, "tgz", 0, CLOPT_TYPE_STRING, NULL, -1, "foo", 0, OPT_CLAMSCAN | OPT_DEPRECATED, "", "" },
    { NULL, "deb", 0, CLOPT_TYPE_STRING, NULL, -1, "foo", 0, OPT_CLAMSCAN | OPT_DEPRECATED, "", "" },

    /* config file/cmdline options */
    { "AlertExceedsMax", "alert-exceeds-max", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "", "" },

    { "PreludeEnable", "prelude-enable", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD, "Enable prelude"},

    { "PreludeAnalyzerName", "prelude-analyzer-name", 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_CLAMD, "Name of the analyzer as seen in prewikka"},

    { "LogFile", "log", 'l', CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_CLAMD | OPT_MILTER | OPT_CLAMSCAN | OPT_CLAMDSCAN, "Save all reports to a log file.", "/tmp/clamav.log" },

    { "LogFileUnlock", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_MILTER, "By default the log file is locked for writing and only a single\ndaemon process can write to it. This option disables the lock.", "yes" },

    { "LogFileMaxSize", NULL, 0, CLOPT_TYPE_SIZE, MATCH_SIZE, 1048576, NULL, 0, OPT_CLAMD | OPT_FRESHCLAM | OPT_MILTER, "Maximum size of the log file.\nValue of 0 disables the limit.", "5M" },

    { "LogTime", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_FRESHCLAM | OPT_MILTER, "Log time with each message.", "yes" },

    { "LogClean", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD, "Log all clean files.\nUseful in debugging but drastically increases the log size.", "yes" },

    { "LogSyslog", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_FRESHCLAM | OPT_MILTER, "Use the system logger (can work together with LogFile).", "yes" },

    { "LogFacility", NULL, 0, CLOPT_TYPE_STRING, NULL, -1, "LOG_LOCAL6", FLAG_REQUIRED, OPT_CLAMD | OPT_FRESHCLAM | OPT_MILTER, "Type of syslog messages.\nPlease refer to 'man syslog' for the facility names.", "LOG_MAIL" },

    { "LogVerbose", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_FRESHCLAM | OPT_MILTER, "Enable verbose logging.", "yes" },

    { "LogRotate", "log-rotate", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_FRESHCLAM | OPT_MILTER, "Rotate log file. Requires LogFileMaxSize option set prior to this option.", "yes" },

    { "ExtendedDetectionInfo", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD, "Log additional information about the infected file, such as its\nsize and hash, together with the virus name.", "yes" },

    { "PidFile", "pid", 'p', CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_CLAMD | OPT_FRESHCLAM | OPT_MILTER, "Save the process ID to a file.", "/var/run/clam.pid" },

    { "TemporaryDirectory", "tempdir", 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_CLAMD | OPT_MILTER | OPT_CLAMSCAN | OPT_SIGTOOL, "This option allows you to change the default temporary directory.", "/tmp" },

    { "DatabaseDirectory", "datadir", 0, CLOPT_TYPE_STRING, NULL, -1, DATADIR, 0, OPT_CLAMD | OPT_FRESHCLAM | OPT_SIGTOOL, "This option allows you to change the default database directory.\nIf you enable it, please make sure it points to the same directory in\nboth clamd and freshclam.", "/var/lib/clamav" },

    { "OfficialDatabaseOnly", "official-db-only", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "Only load the official signatures published by the ClamAV project.", "no" },

    { "YaraRules", "yara-rules", 0, CLOPT_TYPE_STRING, NULL, 0, NULL, 0, OPT_CLAMSCAN, "By default, yara rules will be loaded. This option allows you to exclude yara rules when scanning and also to scan only using yara rules. Valid options are yes|no|only", "yes"},

    { "LocalSocket", NULL, 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_CLAMD, "Path to a local socket file the daemon will listen on.", "/tmp/clamd.socket" },

    { "LocalSocketGroup", NULL, 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_CLAMD, "Sets the group ownership on the unix socket.", "virusgroup" },

    { "LocalSocketMode", NULL, 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_CLAMD, "Sets the permissions on the unix socket to the specified mode.", "660" },

    { "FixStaleSocket", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 1, NULL, 0, OPT_CLAMD | OPT_MILTER, "Remove a stale socket after unclean shutdown", "yes" },

    { "TCPSocket", NULL, 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, -1, NULL, 0, OPT_CLAMD, "A TCP port number the daemon will listen on.", "3310" },

    /* FIXME: add a regex for IP addr */
    { "TCPAddr", NULL, 0, CLOPT_TYPE_STRING, NULL, -1, NULL, FLAG_MULTIPLE, OPT_CLAMD, "By default clamd binds to INADDR_ANY.\nThis option allows you to restrict the TCP address and provide\nsome degree of protection from the outside world.", "127.0.0.1" },

    { "MaxConnectionQueueLength", NULL, 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, 200, NULL, 0, OPT_CLAMD, "Maximum length the queue of pending connections may grow to.", "30" },

    { "StreamMaxLength", NULL, 0, CLOPT_TYPE_SIZE, MATCH_SIZE, CLI_DEFAULT_MAXFILESIZE, NULL, 0, OPT_CLAMD, "Close the STREAM session when the data size limit is exceeded.\nThe value should match your MTA's limit for the maximum attachment size.", "25M" },

    { "StreamMinPort", NULL, 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, 1024, NULL, 0, OPT_CLAMD, "The STREAM command uses an FTP-like protocol.\nThis option sets the lower boundary for the port range.", "1024" },

    { "StreamMaxPort", NULL, 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, 2048, NULL, 0, OPT_CLAMD, "This option sets the upper boundary for the port range.", "2048" },

    { "MaxThreads", NULL, 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, 10, NULL, 0, OPT_CLAMD | OPT_MILTER, "Maximum number of threads running at the same time.", "20" },

    { "ReadTimeout", NULL, 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, 120, NULL, 0, OPT_CLAMD, "This option specifies the time (in seconds) after which clamd should\ntimeout if a client doesn't provide any data.", "120" },

    { "CommandReadTimeout", NULL, 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, 30, NULL, 0, OPT_CLAMD, "This option specifies the time (in seconds) after which clamd should\ntimeout if a client doesn't provide any initial command after connecting.", "30" },

    { "SendBufTimeout", NULL, 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, 500, NULL, 0, OPT_CLAMD, "This option specifies how long to wait (in milliseconds) if the send buffer\nis full. Keep this value low to prevent clamd hanging.", "200"},

    { "ReadTimeout", NULL, 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, 120, NULL, 0, OPT_MILTER, "Waiting for data from clamd will timeout after this time (seconds).", "300" },

    { "MaxQueue", NULL, 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, 100, NULL, 0, OPT_CLAMD, "Maximum number of queued items (including those being processed by MaxThreads\nthreads). It is recommended to have this value at least twice MaxThreads\nif possible.\nWARNING: you shouldn't increase this too much to avoid running out of file\n descriptors, the following condition should hold:\n MaxThreads*MaxRecursion + MaxQueue - MaxThreads  + 6 < RLIMIT_NOFILE\n (usual max for RLIMIT_NOFILE is 1024)\n", "200" },

    { "IdleTimeout", NULL, 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, 30, NULL, 0, OPT_CLAMD, "This option specifies how long (in seconds) the process should wait\nfor a new job.", "60" },

    { "ExcludePath", NULL, 0, CLOPT_TYPE_STRING, NULL, -1, NULL, FLAG_MULTIPLE, OPT_CLAMD, "Don't scan files/directories whose names match the provided\nregular expression. This option can be specified multiple times.", "^/proc/\n^/sys/" },

    { "MaxDirectoryRecursion", "max-dir-recursion", 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, 15, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "Maximum depth the directories are scanned at.", "15" },

    { "FollowDirectorySymlinks", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD, "Follow directory symlinks.", "no" },

    { "FollowFileSymlinks", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD, "Follow symlinks to regular files.", "no" },

    { "CrossFilesystems", "cross-fs", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 1, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "Scan files and directories on other filesystems.", "yes" },

    { "SelfCheck", NULL, 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, 600, NULL, 0, OPT_CLAMD, "This option specifies the time intervals (in seconds) in which clamd\nshould perform a database check.", "600" },

    { "DisableCache", "disable-cache", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "This option allows you to disable clamd's caching feature.", "no" },

    { "VirusEvent", NULL, 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_CLAMD, "Execute a command when a virus is found. In the command string %v will be\nreplaced with the virus name. Additionally, two environment variables will\nbe defined: $CLAM_VIRUSEVENT_FILENAME and $CLAM_VIRUSEVENT_VIRUSNAME.", "/usr/bin/mailx -s \"ClamAV VIRUS ALERT: %v\" alert < /dev/null" },

    { "ExitOnOOM", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD, "Stop the daemon when libclamav reports an out of memory condition.", "yes" },

    { "AllowAllMatchScan", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 1, NULL, 0, OPT_CLAMD, "Permit use of the ALLMATCHSCAN command.", "yes" },

    { "Foreground", "foreground", 'F', CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_FRESHCLAM | OPT_MILTER, "Don't fork into background.", "no" },

    { "Debug", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_FRESHCLAM, "Enable debug messages in libclamav.", "no" },

    { "LeaveTemporaryFiles", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD, "Don't remove temporary files (for debugging purposes).", "no" },

    { "User", NULL, 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_CLAMD | OPT_MILTER, "Run the daemon as a specified user (the process must be started by root).", "clamav" },

    /* Scan options */
    { "Bytecode", "bytecode", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 1, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "With this option enabled ClamAV will load bytecode from the database. It is highly recommended you keep this option on, otherwise you'll miss detections for many new viruses.", "yes" },

    { "BytecodeSecurity", NULL, 0, CLOPT_TYPE_STRING, "^(TrustSigned|Paranoid)$", -1, "TrustSigned", 0, OPT_CLAMD,
	"Set bytecode security level.\nPossible values:\n\tTrustSigned - trust bytecode loaded from signed .c[lv]d files,\n\t\t insert runtime safety checks for bytecode loaded from other sources\n\tParanoid - don't trust any bytecode, insert runtime checks for all\nRecommended: TrustSigned, because bytecode in .cvd files already has these checks.","TrustSigned"},

    { "BytecodeTimeout", "bytecode-timeout", 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, 5000, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN,
	"Set bytecode timeout in milliseconds.","5000"},

    { "BytecodeUnsigned", "bytecode-unsigned", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN,
	"Allow loading bytecode from outside digitally signed .c[lv]d files.","no"},

    { "BytecodeMode", "bytecode-mode", 0, CLOPT_TYPE_STRING, "^(Auto|ForceJIT|ForceInterpreter|Test)$", -1, "Auto", FLAG_REQUIRED, OPT_CLAMD | OPT_CLAMSCAN,
	"Set bytecode execution mode.\nPossible values:\n\tAuto - automatically choose JIT if possible, fallback to interpreter\nForceJIT - always choose JIT, fail if not possible\nForceInterpreter - always choose interpreter\nTest - run with both JIT and interpreter and compare results. Make all failures fatal.","Auto"},

    { "Statistics", "statistics", 0, CLOPT_TYPE_STRING, "^(none|None|bytecode|Bytecode|pcre|PCRE)$", -1, NULL, FLAG_MULTIPLE, OPT_CLAMSCAN | OPT_CLAMBC, "Collect and print execution statistics.\nPossible values:\n\tBytecode - reports bytecode statistics\nPCRE - reports PCRE execution statistics\nNone - reports no statistics", "None" },

   { "DetectPUA", "detect-pua", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "Detect Potentially Unwanted Applications.", "yes" },

    { "ExcludePUA", "exclude-pua", 0, CLOPT_TYPE_STRING, NULL, -1, NULL, FLAG_MULTIPLE, OPT_CLAMD | OPT_CLAMSCAN, "Exclude a specific PUA category. This directive can be used multiple times.\nSee https://www.clamav.net/documents/potentially-unwanted-applications-pua for the complete list of PUA\ncategories.", "NetTool\nPWTool" },

    { "IncludePUA", "include-pua", 0, CLOPT_TYPE_STRING, NULL, -1, NULL, FLAG_MULTIPLE, OPT_CLAMD | OPT_CLAMSCAN, "Only include a specific PUA category. This directive can be used multiple\ntimes.", "Spy\nScanner\nRAT" },

    { "ScanPE", "scan-pe", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 1, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "PE stands for Portable Executable - it's an executable file format used\nin all 32- and 64-bit versions of Windows operating systems. This option\nallows ClamAV to perform a deeper analysis of executable files and it's also\nrequired for decompression of popular executable packers such as UPX or FSG.\nIf you turn off this option, the original files will still be scanned, but\nwithout additional processing.", "yes" },

    { "ScanELF", "scan-elf", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 1, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "Executable and Linking Format is a standard format for UN*X executables.\nThis option allows you to control the scanning of ELF files.\nIf you turn off this option, the original files will still be scanned, but\nwithout additional processing.", "yes" },

    { "ScanMail", "scan-mail", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 1, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "Enable the built in email scanner.\nIf you turn off this option, the original files will still be scanned, but\nwithout parsing individual messages/attachments.", "yes" },

    { "ScanPartialMessages", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD, "Scan RFC1341 messages split over many emails. You will need to\nperiodically clean up $TemporaryDirectory/clamav-partial directory.\nWARNING: This option may open your system to a DoS attack. Please don't use\nthis feature on highly loaded servers.", "no" },

    { "PhishingSignatures", "phishing-sigs", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 1, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "With this option enabled ClamAV will try to detect phishing attempts by using\nsignatures.", "yes" },

    { "PhishingScanURLs", "phishing-scan-urls", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 1, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "Scan URLs found in mails for phishing attempts using heuristics.", "yes" },

    { "HeuristicAlerts", "heuristic-alerts", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 1, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "In some cases (eg. complex malware, exploits in graphic files, and others),\nClamAV uses special algorithms to provide accurate detection. This option\ncontrols the algorithmic detection.", "yes" },

    { "HeuristicScanPrecedence", "heuristic-scan-precedence", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "Allow heuristic match to take precedence.\nWhen enabled, if a heuristic scan (such as phishingScan) detects\na possible virus/phish it will stop scan immediately. Recommended, saves CPU\nscan-time.\nWhen disabled, virus/phish detected by heuristic scans will be reported only\nat the end of a scan. If an archive contains both a heuristically detected\nvirus/phish, and a real malware, the real malware will be reported.\nKeep this disabled if you intend to handle \"*.Heuristics.*\" viruses\ndifferently from \"real\" malware.\nIf a non-heuristically-detected virus (signature-based) is found first,\nthe scan is interrupted immediately, regardless of this config option.", "yes" },

    { "StructuredDataDetection", "detect-structured", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "Enable the Data Loss Prevention module.", "no" },

    { "StructuredMinCreditCardCount", "structured-cc-count", 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, CLI_DEFAULT_MIN_CC_COUNT, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "This option sets the lowest number of Credit Card numbers found in a file\nto generate a detect.", "5" },

    { "StructuredMinSSNCount", "structured-ssn-count", 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, CLI_DEFAULT_MIN_SSN_COUNT, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "This option sets the lowest number of Social Security Numbers found\nin a file to generate a detect.", "5" },

    { "StructuredSSNFormatNormal", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 1, NULL, 0, OPT_CLAMD, "With this option enabled the DLP module will search for valid\nSSNs formatted as xxx-yy-zzzz.", "yes" },

    { "StructuredSSNFormatStripped", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD, "With this option enabled the DLP module will search for valid\nSSNs formatted as xxxyyzzzz", "no" },

    { "ScanHTML", "scan-html", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 1, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "Perform HTML/JavaScript/ScriptEncoder normalisation and decryption.\nIf you turn off this option, the original files will still be scanned, but\nwithout additional processing.", "yes" },

    { "ScanOLE2", "scan-ole2", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 1, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "This option enables scanning of OLE2 files, such as Microsoft Office\ndocuments and .msi files.\nIf you turn off this option, the original files will still be scanned, but\nwithout additional processing.", "yes" },

    { "AlertBrokenExecutables", "alert-broken", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "With this option enabled clamav will try to detect broken executables\n(both PE and ELF) and alert on them with the Broken.Executable heuristic signature.", "yes" },

    { "AlertEncrypted", "alert-encrypted", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "Alert on encrypted archives and documents (encrypted .zip, .7zip, .rar, .pdf).", "no" },

    { "AlertEncryptedArchive", "alert-encrypted-archive", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "Alert on encrypted archives (encrypted .zip, .7zip, .rar).", "no" },

    { "AlertEncryptedDoc", "alert-encrypted-doc", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "Alert on encrypted documents (encrypted .pdf).", "no" },

    { "AlertOLE2Macros", "alert-macros", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "With this option enabled OLE2 files with VBA macros, which were not\ndetected by signatures will be marked as \"Heuristics.OLE2.ContainsMacros\".", "no" },

    { "AlertPhishingSSLMismatch", "alert-phishing-ssl", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "Alert on SSL mismatches in URLs, even if they're not in the database.\nThis feature can lead to false positives.", "" },

    { "AlertPhishingCloak", "alert-phishing-cloak", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "Alert on cloaked URLs, even if they're not in the database.\nThis feature can lead to false positives.", "no" },

    { "AlertPartitionIntersection", "alert-partition-intersection", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "Alert on raw DMG image files containing partition intersections.", "yes" },

    { "ScanPDF", "scan-pdf", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 1, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "This option enables scanning within PDF files.\nIf you turn off this option, the original files will still be scanned, but\nwithout decoding and additional processing.", "yes" },

    { "ScanSWF", "scan-swf", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 1, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "This option enables scanning within SWF files.\nIf you turn off this option, the original files will still be scanned, but\nwithout decoding and additional processing.", "yes" },

    { "ScanXMLDOCS", "scan-xmldocs", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 1, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "This option enables scanning xml-based document files supported by libclamav.\nIf you turn off this option, the original files will still be scanned, but\nwithout additional processing.", "yes" },

    { "ScanHWP3", "scan-hwp3", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 1, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "This option enables scanning HWP3 files.\nIf you turn off this option, the original files will still be scanned, but\nwithout additional processing.", "yes" },

    { "ScanArchive", "scan-archive", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 1, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "Scan within archives and compressed files.\nIf you turn off this option, the original files will still be scanned, but\nwithout unpacking and additional processing.", "yes" },

    { "ForceToDisk", "force-to-disk", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "This option causes memory or nested map scans to dump the content to disk.\nIf you turn on this option, more data is written to disk and is available\nwhen the leave-temps option is enabled at the cost of more disk writes.", "no" },

    { "MaxScanTime", "max-scantime", 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, 0, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "This option sets the maximum amount of time a scan may take to complete.\nIn this version, this field only affects the scan time of ZIP archives.\nThe value of 0 disables the limit.\nWARNING: disabling this limit or setting it too high may result allow scanning\nof certain files to lock up the scanning process/threads resulting in a Denial of Service.\nThe value is in milliseconds.", "120000"},

    { "MaxScanSize", "max-scansize", 0, CLOPT_TYPE_SIZE, MATCH_SIZE, CLI_DEFAULT_MAXSCANSIZE, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "This option sets the maximum amount of data to be scanned for each input file.\nArchives and other containers are recursively extracted and scanned up to this\nvalue.\nThe value of 0 disables the limit.\nWARNING: disabling this limit or setting it too high may result in severe\ndamage.", "100M" },

    { "MaxFileSize", "max-filesize", 0, CLOPT_TYPE_SIZE, MATCH_SIZE, CLI_DEFAULT_MAXFILESIZE, NULL, 0, OPT_CLAMD | OPT_MILTER | OPT_CLAMSCAN, "Files/messages larger than this limit won't be scanned. Affects the input\nfile itself as well as files contained inside it (when the input file is\nan archive, a document or some other kind of container).\nThe value of 0 disables the limit.\nWARNING: disabling this limit or setting it too high may result in severe\ndamage to the system.", "25M" },

    { "MaxRecursion", "max-recursion", 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, CLI_DEFAULT_MAXRECLEVEL, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "Nested archives are scanned recursively, e.g. if a Zip archive contains a RAR\nfile, all files within it will also be scanned. This option specifies how\ndeeply the process should be continued.\nThe value of 0 disables the limit.\nWARNING: disabling this limit or setting it too high may result in severe\ndamage to the system.", "16" },

    { "MaxFiles", "max-files", 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, CLI_DEFAULT_MAXFILES, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "Number of files to be scanned within an archive, a document, or any other\ncontainer file.\nThe value of 0 disables the limit.\nWARNING: disabling this limit or setting it too high may result in severe\ndamage to the system.", "10000" },

    /* Engine maximums */
    { "MaxEmbeddedPE", "max-embeddedpe", 0, CLOPT_TYPE_SIZE, MATCH_SIZE, CLI_DEFAULT_MAXEMBEDDEDPE, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "This option sets the maximum size of a file to check for embedded PE.\nFiles larger than this value will skip the additional analysis step.\nNegative values are not allowed.\nWARNING: setting this limit too high may result in severe damage or impact performance.", "10M" },

    { "MaxHTMLNormalize", "max-htmlnormalize", 0, CLOPT_TYPE_SIZE, MATCH_SIZE, CLI_DEFAULT_MAXHTMLNORMALIZE, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "This option sets the maximum size of a HTML file to normalize.\nHTML files larger than this value will not be normalized or scanned.\nNegative values are not allowed.\nWARNING: setting this limit too high may result in severe damage or impact performance.", "10M" },

    { "MaxHTMLNoTags", "max-htmlnotags", 0, CLOPT_TYPE_SIZE, MATCH_SIZE, CLI_DEFAULT_MAXHTMLNOTAGS, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "This option sets the maximum size of a normalized HTML file to scan.\nHTML files larger than this value after normalization will not be scanned.\nNegative values are not allowed.\nWARNING: setting this limit too high may result in severe damage or impact performance.", "2M" },

    { "MaxScriptNormalize", "max-scriptnormalize", 0, CLOPT_TYPE_SIZE, MATCH_SIZE, CLI_DEFAULT_MAXSCRIPTNORMALIZE, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "This option sets the maximum size of a script file to normalize.\nScript content larger than this value will not be normalized or scanned.\nNegative values are not allowed.\nWARNING: setting this limit too high may result in severe damage or impact performance.", "5M" },

    { "MaxZipTypeRcg", "max-ziptypercg", 0, CLOPT_TYPE_SIZE, MATCH_SIZE, CLI_DEFAULT_MAXZIPTYPERCG, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "This option sets the maximum size of a ZIP file to reanalyze type recognition.\nZIP files larger than this value will skip the step to potentially reanalyze as PE.\nNegative values are not allowed.\nWARNING: setting this limit too high may result in severe damage or impact performance.", "1M" },

    { "MaxPartitions", "max-partitions", 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, CLI_DEFAULT_MAXPARTITIONS, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "This option sets the maximum number of partitions of a raw disk image to be scanned.\nRaw disk images with more partitions than this value will have up to the value number partitions scanned.\nNegative values are not allowed.\nWARNING: setting this limit too high may result in severe damage or impact performance.", "128" },

    { "MaxIconsPE", "max-iconspe", 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, CLI_DEFAULT_MAXICONSPE, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "This option sets the maximum number of icons within a PE to be scanned.\nPE files with more icons than this value will have up to the value number icons scanned.\nNegative values are not allowed.\nWARNING: setting this limit too high may result in severe damage or impact performance.", "100" },

    { "MaxRecHWP3", "max-rechwp3", 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, CLI_DEFAULT_MAXRECHWP3, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "This option sets the maximum recursive calls to HWP3 parsing function.\nHWP3 files using more than this limit will be terminated and alert the user.\nScans will be unable to scan any HWP3 attachments if the recursive limit is reached.\nNegative values are not allowed.\nWARNING: setting this limit too high may result in severe damage or impact performance.", "16" },

    { "PCREMatchLimit", "pcre-match-limit", 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, CLI_DEFAULT_PCRE_MATCH_LIMIT, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "This option sets the maximum calls to the PCRE match function during an instance of regex matching.\nInstances using more than this limit will be terminated and alert the user but the scan will continue.\nFor more information on match_limit, see the PCRE documentation.\nNegative values are not allowed.\nWARNING: setting this limit too high may severely impact performance.", "100000" },

    { "PCRERecMatchLimit", "pcre-recmatch-limit", 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, CLI_DEFAULT_PCRE_RECMATCH_LIMIT, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "This option sets the maximum recursive calls to the PCRE match function during an instance of regex matching.\nInstances using more than this limit will be terminated and alert the user but the scan will continue.\nFor more information on match_limit_recursion, see the PCRE documentation.\nNegative values are not allowed and values > PCREMatchLimit are superfluous.\nWARNING: setting this limit too high may severely impact performance.", "5000" },

    { "PCREMaxFileSize", "pcre-max-filesize", 0, CLOPT_TYPE_SIZE, MATCH_SIZE, CLI_DEFAULT_PCRE_MAX_FILESIZE, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "This option sets the maximum filesize for which PCRE subsigs will be executed.\nFiles exceeding this limit will not have PCRE subsigs executed unless a subsig is encompassed to a smaller buffer.\nNegative values are not allowed.\nSetting this value to zero disables the limit.\nWARNING: setting this limit too high or disabling it may severely impact performance.", "25M" },

    /* OnAccess settings */
    { "ScanOnAccess", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, -1, NULL, 0, OPT_CLAMD, "This option enables on-access scanning (Linux only)", "no" },

    { "OnAccessMountPath", NULL, 0, CLOPT_TYPE_STRING, NULL, -1, NULL, FLAG_MULTIPLE, OPT_CLAMD, "This option specifies a directory or mount point which should be scanned on access. The mount point specified, or the mount point containing the specified directory will be watched, but only notifications will occur. If any directories are specified, this option will preempt the DDD system. It can also be used multiple times.", "/\n/home/user" },

    { "OnAccessIncludePath", "on-access-include", 0, CLOPT_TYPE_STRING, NULL, -1, NULL, FLAG_MULTIPLE, OPT_CLAMD, "This option specifies a directory (including all files and directories\ninside it), which should be scanned on access. This option can\nbe used multiple times.", "/home\n/students" },

    { "OnAccessExcludePath", NULL, 0, CLOPT_TYPE_STRING, NULL, -1, NULL, FLAG_MULTIPLE, OPT_CLAMD, "This option allows excluding directories from on-access scanning. It can\nbe used multiple times. Only works with DDD system.", "/home/bofh\n/root" },

    { "OnAccessExcludeRootUID", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, -1, NULL, 0, OPT_CLAMD, "Use this option to whitelist the root UID (0) and allow any processes run under root to access all watched files without triggering scans.", "no" },

    { "OnAccessExcludeUID", NULL, 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, -1, NULL, FLAG_MULTIPLE, OPT_CLAMD, "With this option you can whitelist specific UIDs. Processes with these UIDs\nwill be able to access all files.\nThis option can be used multiple times (one per line). Using a value of 0 on any line will disable this option entirely. To whitelist the root UID please enable the OnAccessExcludeRootUID option.", "0" },

    { "OnAccessMaxFileSize", NULL, 0, CLOPT_TYPE_SIZE, MATCH_SIZE, 5242880, NULL, 0, OPT_CLAMD, "Files larger than this value will not be scanned in on access.", "5M" },

    { "OnAccessDisableDDD", "disable-ddd", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD, "This option toggles the dynamic directory determination system for on-access scanning (Linux only).", "no" },

    { "OnAccessPrevention", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD, "This option changes fanotify behavior to prevent access attempts on malicious files instead of simply notifying the user (On Access scan only).", "yes" },

    { "OnAccessExtraScanning", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD, "Enables extra scanning and notification after catching certain inotify events. Only works with the DDD system enabled.", "yes" },

    /* FIXME: mark these as private and don't output into clamd.conf/man */
    { "DevACOnly", "dev-ac-only", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, -1, NULL, FLAG_HIDDEN, OPT_CLAMD | OPT_CLAMSCAN, "", "" },

    { "DevACDepth", "dev-ac-depth", 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, -1, NULL, FLAG_HIDDEN, OPT_CLAMD | OPT_CLAMSCAN, "", "" },

#ifdef HAVE__INTERNAL__SHA_COLLECT
    { "DevCollectHashes", "dev-collect-hashes", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, -1, NULL, FLAG_HIDDEN, OPT_CLAMD | OPT_CLAMSCAN, "", "" },
#endif
    { "DevPerformance", "dev-performance", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, -1, NULL, FLAG_HIDDEN, OPT_CLAMD | OPT_CLAMSCAN, "", "" },
    { "DevLiblog", "dev-liblog", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, -1, NULL, FLAG_HIDDEN, OPT_CLAMD, "", "" },

    /* Freshclam-only entries */

    /* FIXME: drop this entry and use LogFile */
    { "UpdateLogFile", "log", 'l', CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_FRESHCLAM, "Save all reports to a log file.", "/var/log/freshclam.log" },

    { "DatabaseOwner", "user", 'u', CLOPT_TYPE_STRING, NULL, -1, CLAMAVUSER, FLAG_REQUIRED, OPT_FRESHCLAM, "When started by root freshclam will drop privileges and switch to the user\ndefined in this option.", CLAMAVUSER },

    { "Checks", "checks", 'c', CLOPT_TYPE_NUMBER, MATCH_NUMBER, 12, NULL, 0, OPT_FRESHCLAM, "This option defined how many times daily freshclam should check for\na database update.", "24" },

    { "DNSDatabaseInfo", NULL, 0, CLOPT_TYPE_STRING, NULL, -1, "current.cvd.clamav.net", FLAG_REQUIRED, OPT_FRESHCLAM, "Use DNS to verify the virus database version. Freshclam uses DNS TXT records\nto verify the versions of the database and software itself. With this\ndirective you can change the database verification domain.\nWARNING: Please don't change it unless you're configuring freshclam to use\nyour own database verification domain.", "current.cvd.clamav.net" },

    { "DatabaseMirror", NULL, 0, CLOPT_TYPE_STRING, NULL, -1, NULL, FLAG_MULTIPLE, OPT_FRESHCLAM, "DatabaseMirror specifies to which mirror(s) freshclam should connect.\nYou should have at least two entries: db.XY.clamav.net (or db.XY.ipv6.clamav.net\nfor IPv6) and database.clamav.net (in this order). Please replace XY with your\ncountry code (see https://www.iana.org/domains/root/db).\ndatabase.clamav.net is a round-robin record which points to our most reliable\nmirrors. It's used as a fall back in case db.XY.clamav.net is not working.", "db.XY.clamav.net\ndatabase.clamav.net" },

    { "PrivateMirror", NULL, 0, CLOPT_TYPE_STRING, NULL, -1, NULL, FLAG_MULTIPLE, OPT_FRESHCLAM, "This option allows you to easily point freshclam to private mirrors.\nIf PrivateMirror is set, freshclam does not attempt to use DNS\nto determine whether its databases are out-of-date, instead it will\nuse the If-Modified-Since request or directly check the headers of the\nremote database files. For each database, freshclam first attempts\nto download the CLD file. If that fails, it tries to download the\nCVD file. This option overrides DatabaseMirror, DNSDatabaseInfo\nand Scripted Updates. It can be used multiple times to provide\nfall-back mirrors.", "mirror1.mynetwork.com\nmirror2.mynetwork.com" },

    { "MaxAttempts", NULL, 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, 3, NULL, 0, OPT_FRESHCLAM, "This option defines how many attempts freshclam should make before giving up.", "5" },

    { "ScriptedUpdates", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 1, NULL, 0, OPT_FRESHCLAM, "With this option you can control scripted updates. It's highly recommended to keep them enabled.", "yes" },

    { "TestDatabases", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 1, NULL, 0, OPT_FRESHCLAM, "With this option enabled, freshclam will attempt to load new\ndatabases into memory to make sure they are properly handled\nby libclamav before replacing the old ones.", "yes" },

    { "CompressLocalDatabase", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_FRESHCLAM, "By default freshclam will keep the local databases (.cld) uncompressed to\nmake their handling faster. With this option you can enable the compression.\nThe change will take effect with the next database update.", "" },

    { "ExtraDatabase", NULL, 0, CLOPT_TYPE_STRING, NULL, -1, NULL, FLAG_MULTIPLE, OPT_FRESHCLAM, "Download an additional 3rd party signature database distributed through\nthe ClamAV mirrors. This option can be used multiple times.", "dbname1\ndbname2" },

    { "DatabaseCustomURL", NULL, 0, CLOPT_TYPE_STRING, NULL, -1, NULL, FLAG_MULTIPLE, OPT_FRESHCLAM, "With this option you can provide custom sources (http:// or file://) for database files.\nThis option can be used multiple times.", "http://myserver.com/mysigs.ndb\nfile:///mnt/nfs/local.hdb" },

    { "HTTPProxyServer", NULL, 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_FRESHCLAM, "If you're behind a proxy, please enter its address here.", "your-proxy" },

    { "HTTPProxyPort", NULL, 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, -1, NULL, 0, OPT_FRESHCLAM, "HTTP proxy's port", "8080" },

    { "HTTPProxyUsername", NULL, 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_FRESHCLAM, "A user name for the HTTP proxy authentication.", "username" },

    { "HTTPProxyPassword", NULL, 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_FRESHCLAM, "A password for the HTTP proxy authentication.", "pass" },

    { "HTTPUserAgent", NULL, 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_FRESHCLAM, "If your servers are behind a firewall/proxy which does a User-Agent\nfiltering you can use this option to force the use of a different\nUser-Agent header.", "default" },

    { "NotifyClamd", "daemon-notify", 0, CLOPT_TYPE_STRING, NULL, -1, CONFDIR_CLAMD, 0, OPT_FRESHCLAM, "Send the RELOAD command to clamd after a successful update.", "yes" },

    { "OnUpdateExecute", "on-update-execute", 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_FRESHCLAM, "Run a command after a successful database update.", "command" },

    { "OnErrorExecute", "on-error-execute", 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_FRESHCLAM, "Run a command when a database update error occurs.", "command" },

    { "OnOutdatedExecute", "on-outdated-execute", 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_FRESHCLAM, "Run a command when freshclam reports an outdated version.\nIn the command string %v will be replaced with the new version number.", "command" },

    /* FIXME: MATCH_IPADDR */
    { "LocalIPAddress", "local-address", 'a', CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_FRESHCLAM, "With this option you can provide a client address for the database downloading.\nUseful for multi-homed systems.", "aaa.bbb.ccc.ddd" },

    { "ConnectTimeout", NULL, 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, 30, NULL, 0, OPT_FRESHCLAM, "Timeout in seconds when connecting to database server.", "30" },

    { "ReceiveTimeout", NULL, 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, 30, NULL, 0, OPT_FRESHCLAM, "Timeout in seconds when reading from database server.", "30" },

    { "SafeBrowsing", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_FRESHCLAM, "This option enables support for Google Safe Browsing. When activated for\nthe first time, freshclam will download a new database file (safebrowsing.cvd)\nwhich will be automatically loaded by clamd and clamscan during the next\nreload, provided that the heuristic phishing detection is turned on. This\ndatabase includes information about websites that may be phishing sites or\npossible sources of malware. When using this option, it's mandatory to run\nfreshclam at least every 30 minutes.\nFreshclam uses the ClamAV's mirror infrastructure to distribute the\ndatabase and its updates but all the contents are provided under Google's\nterms of use. See https://transparencyreport.google.com/safe-browsing/overview \n and https://www.clamav.net/documents/safebrowsing for more information.", "yes" },

    { "Bytecode", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 1, NULL, 0, OPT_FRESHCLAM, "This option enables downloading of bytecode.cvd, which includes additional\ndetection mechanisms and improvements to the ClamAV engine.", "yes" },

    { "DisableCertCheck", "nocerts", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "Disable authenticode certificate chain verification in PE files.", "no" },

    /* Deprecated options */

    { "TimeLimit", "timelimit", 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, 0, NULL, 0, OPT_CLAMSCAN | OPT_DEPRECATED, "Deprecated option to set the max-scantime.\nThe value is in milliseconds.", "120000"},
    { "DetectBrokenExecutables", "detect-broken", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN | OPT_DEPRECATED, "Deprecated option to alert on broken PE and ELF executable files.", "no" },
    { "AlgorithmicDetection", "algorithmic-detection", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 1, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "Deprecated option to enable heuristic alerts (e.g. \"Heuristics.<sig name>\")", "no" },
    { "BlockMax", "block-max", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "", "" },
    { "PhishingAlwaysBlockSSLMismatch", "phishing-ssl", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "Deprecated option to alert on SSL mismatches in URLs, even if they're not in the database.\nThis feature can lead to false positives.", "no" },
    { "PhishingAlwaysBlockCloak", "phishing-cloak", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "Deprecated option to alert on cloaked URLs, even if they're not in the database.\nThis feature can lead to false positives.", "no" },
    { "PartitionIntersection", "partition-intersection", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "Deprecated option to alert on raw DMG image files containing partition intersections.", "no" },
    { "OLE2BlockMacros", "block-macros", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "With this option enabled OLE2 files with VBA macros, which were not\ndetected by signatures will be marked as \"Heuristics.OLE2.ContainsMacros\".", "no" },
    { "ArchiveBlockEncrypted", "block-encrypted", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN, "Deprecated option to alert on encrypted archives and documents (encrypted .zip, .7zip, .rar, .pdf).", "no" },
    { "MailMaxRecursion", NULL, 0, CLOPT_TYPE_NUMBER, NULL, -1, NULL, 0, OPT_CLAMD | OPT_DEPRECATED, "", "" },
    { "ArchiveMaxScanSize", NULL, 0, CLOPT_TYPE_SIZE, NULL, -1, NULL, 0, OPT_CLAMD | OPT_DEPRECATED, "", "" },
    { "ArchiveMaxRecursion", NULL, 0, CLOPT_TYPE_NUMBER, NULL, -1, NULL, 0, OPT_CLAMD | OPT_DEPRECATED, "", "" },
    { "ArchiveMaxFiles", NULL, 0, CLOPT_TYPE_NUMBER, NULL, -1, NULL, 0, OPT_CLAMD | OPT_DEPRECATED, "", "" },
    { "ArchiveMaxCompressionRatio", NULL, 0, CLOPT_TYPE_NUMBER, NULL, -1, NULL, 0, OPT_CLAMD | OPT_DEPRECATED, "", "" },
    { "ArchiveBlockMax", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, -1, NULL, 0, OPT_CLAMD | OPT_DEPRECATED, "", "" },
    { "ArchiveLimitMemoryUsage", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, -1, NULL, 0, OPT_CLAMD | OPT_DEPRECATED, "", "" },
    { "MailFollowURLs", "mail-follow-urls", 0, CLOPT_TYPE_BOOL, MATCH_BOOL, -1, NULL, 0, OPT_CLAMD | OPT_CLAMSCAN | OPT_DEPRECATED, "", "" },
    { "ClamukoScanOnAccess", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, -1, NULL, 0, OPT_CLAMD | OPT_DEPRECATED, "", "" },
    { "ClamukoScannerCount", NULL, 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, 3, NULL, 0, OPT_CLAMD | OPT_DEPRECATED, "", "" },
    { "ClamukoScanOnOpen", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, -1, NULL, 0, OPT_CLAMD | OPT_DEPRECATED, "", "" },
    { "ClamukoScanOnClose", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, -1, NULL, 0, OPT_CLAMD | OPT_DEPRECATED, "", "" },
    { "ClamukoScanOnExec", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, -1, NULL, 0, OPT_CLAMD | OPT_DEPRECATED, "", "" },
    { "ClamukoIncludePath", NULL, 0, CLOPT_TYPE_STRING, NULL, -1, NULL, FLAG_MULTIPLE, OPT_CLAMD | OPT_DEPRECATED, "", "" },
    { "ClamukoExcludePath", NULL, 0, CLOPT_TYPE_STRING, NULL, -1, NULL, FLAG_MULTIPLE, OPT_CLAMD | OPT_DEPRECATED, "", "" },
    { "ClamukoExcludeUID", NULL, 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, -1, NULL, FLAG_MULTIPLE, OPT_CLAMD | OPT_DEPRECATED, "", "" },
    { "ClamukoMaxFileSize", NULL, 0, CLOPT_TYPE_SIZE, MATCH_SIZE, 5242880, NULL, 0, OPT_CLAMD | OPT_DEPRECATED, "", "" },
    { "AllowSupplementaryGroups", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_CLAMD | OPT_FRESHCLAM | OPT_MILTER | OPT_DEPRECATED, "Initialize a supplementary group access (the process must be started by root).", "no" },

    /* Milter specific options */

    { "ClamdSocket", NULL, 0, CLOPT_TYPE_STRING, NULL, -1, NULL, FLAG_MULTIPLE, OPT_MILTER, "Define the clamd socket to connect to for scanning.\nThis option is mandatory! Syntax:\n  ClamdSocket unix:path\n  ClamdSocket tcp:host:port\nThe first syntax specifies a local unix socket (needs an absolute path) e.g.:\n  ClamdSocket unix:/var/run/clamd/clamd.socket\nThe second syntax specifies a tcp local or remote tcp socket: the\nhost can be a hostname or an ip address; the \":port\" field is only required\nfor IPv6 addresses, otherwise it defaults to 3310\n  ClamdSocket tcp:192.168.0.1\nThis option can be repeated several times with different sockets or even\nwith the same socket: clamd servers will be selected in a round-robin fashion.", "tcp:scanner.mydomain:7357" },

    { "MilterSocket",NULL, 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_MILTER, "Define the interface through which we communicate with sendmail.\nThis option is mandatory! Possible formats are:\n[[unix|local]:]/path/to/file - to specify a unix domain socket;\ninet:port@[hostname|ip-address] - to specify an ipv4 socket;\ninet6:port@[hostname|ip-address] - to specify an ipv6 socket.", "/tmp/clamav-milter.socket\ninet:7357" },

    { "MilterSocketGroup", NULL, 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_MILTER, "Define the group ownership for the (unix) milter socket.", "virusgroup" },

    { "MilterSocketMode", NULL, 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_MILTER, "Sets the permissions on the (unix) milter socket to the specified mode.", "660" },

    { "LocalNet", NULL, 0, CLOPT_TYPE_STRING, NULL, -1, NULL, FLAG_MULTIPLE, OPT_MILTER, "Messages originating from these hosts/networks will not be scanned\nThis option takes a host(name)/mask pair in CIRD notation and can be\nrepeated several times. If \"/mask\" is omitted, a host is assumed.\nTo specify a locally originated, non-smtp, email use the keyword \"local\".", "local\n192.168.0.0/24\n1111:2222:3333::/48" },

    { "OnClean", NULL, 0, CLOPT_TYPE_STRING, "^(Accept|Reject|Defer|Blackhole|Quarantine)$", -1, "Accept", 0, OPT_MILTER, "Action to be performed on clean messages (mostly useful for testing).\nThe following actions are available:\nAccept: the message is accepted for delivery\nReject: immediately refuse delivery (a 5xx error is returned to the peer)\nDefer: return a temporary failure message (4xx) to the peer\nBlackhole: like Accept but the message is sent to oblivion\nQuarantine: like Accept but message is quarantined instead of being delivered", "Accept" },

    { "OnInfected", NULL, 0, CLOPT_TYPE_STRING, "^(Accept|Reject|Defer|Blackhole|Quarantine)$", -1, "Quarantine", 0, OPT_MILTER, "Action to be performed on clean messages (mostly useful for testing).\nThe following actions are available:\nAccept: the message is accepted for delivery\nReject: immediately refuse delivery (a 5xx error is returned to the peer)\nDefer: return a temporary failure message (4xx) to the peer\nBlackhole: like Accept but the message is sent to oblivion\nQuarantine: like Accept but message is quarantined instead of being delivered", "Quarantine" },

    { "OnFail", NULL, 0, CLOPT_TYPE_STRING, "^(Accept|Reject|Defer)$", -1, "Defer", 0, OPT_MILTER, "Action to be performed on error conditions (this includes failure to\nallocate data structures, no scanners available, network timeouts, unknown\nscanner replies and the like.\nThe following actions are available:\nAccept: the message is accepted for delivery;\nReject: immediately refuse delivery (a 5xx error is returned to the peer);\nDefer: return a temporary failure message (4xx) to the peer.", "Defer" },

    { "RejectMsg", NULL, 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_MILTER, "This option allows you to set a specific rejection reason for infected messages\nand it's therefore only useful together with \"OnInfected Reject\"\nThe string \"%v\", if present, will be replaced with the virus name.", "MTA specific" },

    { "AddHeader", NULL, 0, CLOPT_TYPE_STRING, "^(No|Replace|Yes|Add)$", -1, "no", 0, OPT_MILTER, "If this option is set to \"Replace\" (or \"Yes\"), an \"X-Virus-Scanned\" and an\n\"X-Virus-Status\" headers will be attached to each processed message, possibly\nreplacing existing headers.\nIf it is set to Add, the X-Virus headers are added possibly on top of the\nexisting ones.\nNote that while \"Replace\" can potentially break DKIM signatures, \"Add\" may\nconfuse procmail and similar filters.", "Replace" },

    { "ReportHostname", NULL, 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_MILTER, "When AddHeader is in use, this option allows you to set the reported\nhostname. This may be desirable in order to avoid leaking internal names.\nIf unset the real machine name is used.", "my.mail.server.name" },

    { "VirusAction", NULL, 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_MILTER, "Execute a command when an infected message is processed.\nThe following parameters are passed to the invoked program in this order:\nvirus name, queue id, sender, destination, subject, message id, message date.\nNote #1: this requires MTA macroes to be available (see LogInfected below)\nNote #2: the process is invoked in the context of clamav-milter\nNote #3: clamav-milter will wait for the process to exit. Be quick or fork to\navoid unnecessary delays in email delivery", "/usr/local/bin/my_infected_message_handler" },

    { "Chroot", NULL, 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_MILTER, "Chroot to the specified directory.\nChrooting is performed just after reading the config file and before\ndropping privileges.", "/newroot" },

    { "Whitelist", NULL, 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_MILTER, "This option specifies a file which contains a list of basic POSIX regular\nexpressions. Addresses (sent to or from - see below) matching these regexes\nwill not be scanned.  Optionally each line can start with the string \"From:\"\nor \"To:\" (note: no whitespace after the colon) indicating if it is,\nrespectively, the sender or recipient that is to be whitelisted.\nIf the field is missing, \"To:\" is assumed.\nLines starting with #, : or ! are ignored.", "/etc/whitelisted_addresses" },

    { "SkipAuthenticated", NULL, 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_MILTER, "Messages from authenticated SMTP users matching this extended POSIX\nregular expression (egrep-like) will not be scanned.\nAs an alternative, a file containing a plain (not regex) list of names (one\nper line) can be specified using the prefix \"file:\".\ne.g. SkipAuthenticated file:/etc/good_guys\n\nNote: this is the AUTH login name!", "SkipAuthenticated ^(tom|dick|henry)$" },

    { "LogInfected", NULL, 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_MILTER, "This option allows you to tune what is logged when a message is infected.\nPossible values are Off (the default - nothing is logged),\nBasic (minimal info logged), Full (verbose info logged)\nNote:\nFor this to work properly in sendmail, make sure the msg_id, mail_addr,\nrcpt_addr and i macroes are available in eom. In other words add a line like:\nMilter.macros.eom={msg_id}, {mail_addr}, {rcpt_addr}, i\nto your .cf file. Alternatively use the macro:\ndefine(`confMILTER_MACROS_EOM', `{msg_id}, {mail_addr}, {rcpt_addr}, i')\nPostfix should be working fine with the default settings.", "Basic" },

    { "LogClean", NULL, 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_MILTER, "This option allows you to tune what is logged when no threat is found in a scanned message.\nSee LogInfected for possible values and caveats.\nUseful in debugging but drastically increases the log size.", "Basic" },

    { "SupportMultipleRecipients", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, 0, NULL, 0, OPT_MILTER, "This option affects the behaviour of LogInfected, LogClean and VirusAction\nwhen a message with multiple recipients is scanned:\nIf SupportMultipleRecipients is off (the default)\nthen one single log entry is generated for the message and, in case the\nmessage is determined to be malicious, the command indicated by VirusAction\nis executed just once. In both cases only the last recipient is reported.\nIf SupportMultipleRecipients is on:\nthen one line is logged for each recipient and the command indicated\nby VirusAction is also executed once for each recipient.\n\nNote: although it's probably a good idea to enable this option, the default value\nis currently set to off for legacy reasons.", "yes" },

    /* Deprecated milter options */

    { "ArchiveBlockEncrypted", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, -1, NULL, 0, OPT_MILTER | OPT_DEPRECATED, "", "" },
    { "DatabaseDirectory", NULL, 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_MILTER | OPT_DEPRECATED, "", "" },
    { "Debug", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, -1, NULL, 0, OPT_MILTER | OPT_DEPRECATED, "", "" },
    { "DetectBrokenExecutables", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, -1, NULL, 0, OPT_MILTER | OPT_DEPRECATED, "", "" },
    { "LeaveTemporaryFiles", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, -1, NULL, 0, OPT_MILTER | OPT_DEPRECATED, "", "" },
    { "LocalSocket", NULL, 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_MILTER | OPT_DEPRECATED, "", "" },
    { "MailFollowURLs", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, -1, NULL, 0, OPT_MILTER | OPT_DEPRECATED, "", "" },
    { "MaxScanSize", NULL, 0, CLOPT_TYPE_SIZE, MATCH_SIZE, -1, NULL, 0, OPT_MILTER | OPT_DEPRECATED, "", "" },
    { "MaxFiles", NULL, 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, -1, NULL, 0, OPT_MILTER | OPT_DEPRECATED, "", "" },
    { "MaxRecursion", NULL, 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, -1, NULL, 0, OPT_MILTER | OPT_DEPRECATED, "", "" },
    { "PhishingSignatures", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, -1, NULL, 0, OPT_MILTER | OPT_DEPRECATED, "", "" },
    { "ScanArchive", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, -1, NULL, 0, OPT_MILTER | OPT_DEPRECATED, "", "" },
    { "ScanHTML", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, -1, NULL, 0, OPT_MILTER | OPT_DEPRECATED, "", "" },
    { "ScanMail", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, -1, NULL, 0, OPT_MILTER | OPT_DEPRECATED, "", "" },
    { "ScanOLE2", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, -1, NULL, 0, OPT_MILTER | OPT_DEPRECATED, "", "" },
    { "ScanPE", NULL, 0, CLOPT_TYPE_BOOL, MATCH_BOOL, -1, NULL, 0, OPT_MILTER | OPT_DEPRECATED, "", "" },
    { "StreamMaxLength", NULL, 0, CLOPT_TYPE_SIZE, MATCH_SIZE, -1, NULL, 0, OPT_MILTER | OPT_DEPRECATED, "", "" },
    { "TCPAddr", NULL, 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_MILTER | OPT_DEPRECATED, "", "" },
    { "TCPSocket", NULL, 0, CLOPT_TYPE_NUMBER, MATCH_NUMBER, -1, NULL, 0, OPT_MILTER | OPT_DEPRECATED, "", "" },
    { "TemporaryDirectory", NULL, 0, CLOPT_TYPE_STRING, NULL, -1, NULL, 0, OPT_MILTER | OPT_DEPRECATED, "", "" },

    { NULL, NULL, 0, 0, NULL, 0, NULL, 0, 0, NULL, NULL }
};
const struct clam_option *clam_options = __clam_options;

const struct optstruct *optget(const struct optstruct *opts, const char *name)
{
    while(opts) {
	if((opts->name && !strcmp(opts->name, name)) || (opts->cmd && !strcmp(opts->cmd, name)))
	    return opts;
	opts = opts->next;
    }
    return NULL;
}

static struct optstruct *optget_i(struct optstruct *opts, const char *name)
{
    while(opts) {
	if((opts->name && !strcmp(opts->name, name)) || (opts->cmd && !strcmp(opts->cmd, name)))
	    return opts;
	opts = opts->next;
    }
    return NULL;
}

/*
static void optprint(const struct optstruct *opts)
{
	const struct optstruct *h;

    printf("\nOPTIONS:\n\n");

    while(opts) {
	printf("OPT_NAME: %s\n", opts->name);
	printf("OPT_CMD: %s\n", opts->cmd);
	printf("OPT_STRARG: %s\n", opts->strarg ? opts->strarg : "NONE");
	printf("OPT_NUMARG: %d\n", opts->numarg);
	h = opts;
	while((h = h->nextarg)) {
	    printf("SUBARG_OPT_STRARG: %s\n", h->strarg ? h->strarg : "NONE");
	    printf("SUBARG_OPT_NUMARG: %d\n", h->numarg);
	}
	printf("----------------\n");
	opts = opts->next;
    }
}
*/

static int optadd(struct optstruct **opts, struct optstruct **opts_last, const char *name, const char *cmd, const char *strarg, long long numarg, int flags, int idx)
{
	struct optstruct *newnode;


    newnode = (struct optstruct *) malloc(sizeof(struct optstruct));

    if(!newnode)
	return -1;

    if(name) {
	newnode->name = strdup(name);
	if(!newnode->name) {
	    free(newnode);
	    return -1;
	}
    } else {
	newnode->name = NULL;
    }

    if(cmd) {
	newnode->cmd = strdup(cmd);
	if(!newnode->cmd) {
	    free(newnode->name);
	    free(newnode);
	    return -1;
	}
    } else {
	newnode->cmd = NULL;
    }

    if(strarg) {
	newnode->strarg = strdup(strarg);
	if(!newnode->strarg) {
	    free(newnode->cmd);
	    free(newnode->name);
	    free(newnode);
	    return -1;
	}
	newnode->enabled = 1;
    } else {
	newnode->strarg = NULL;
	newnode->enabled = 0;
    }
    newnode->numarg = numarg;
    if(numarg && numarg != -1)
	newnode->enabled = 1;
    newnode->nextarg = NULL;
    newnode->next = NULL;
    newnode->active = 0;
    newnode->flags = flags;
    newnode->idx = idx;
    newnode->filename = NULL;

    if(!*opts_last) {
	newnode->next = *opts;
	*opts = newnode;
	*opts_last = *opts;
    } else {
	(*opts_last)->next = newnode;
	*opts_last = newnode;
    }
    return 0;
}

static int optaddarg(struct optstruct *opts, const char *name, const char *strarg, long long numarg)
{
	struct optstruct *pt, *h, *new;


    if(!(pt = optget_i(opts, name))) {
	fprintf(stderr, "ERROR: optaddarg: Unregistered option %s\n", name);
	return -1;
    }

    if(pt->flags & FLAG_MULTIPLE) {
	if(!pt->active) {
	    if(strarg) {
		free(pt->strarg);
		pt->strarg = strdup(strarg);
	 	if(!pt->strarg) {
		    fprintf(stderr, "ERROR: optaddarg: strdup() failed\n");
		    return -1;
		}
	    }
	    pt->numarg = numarg;
	} else {
	    new = (struct optstruct *) calloc(1, sizeof(struct optstruct));
	    if(!new) {
		fprintf(stderr, "ERROR: optaddarg: malloc() failed\n");
		return -1;
	    }
	    if(strarg) {
		new->strarg = strdup(strarg);
	 	if(!new->strarg) {
		    fprintf(stderr, "ERROR: optaddarg: strdup() failed\n");
		    free(new);
		    return -1;
		}
	    }
	    new->numarg = numarg;
	    h = pt;
	    while(h->nextarg)
		h = h->nextarg;
	    h->nextarg = new;
	}
    } else {
	if(pt->active)
	    return 0;

	if(strarg) {
	    free(pt->strarg);
	    pt->strarg = strdup(strarg);
	    if(!pt->strarg) {
		fprintf(stderr, "ERROR: optaddarg: strdup() failed\n");
		return -1;
	    }
	}
	pt->numarg = numarg;
    }

    pt->active = 1;
    if(pt->strarg || (pt->numarg && pt->numarg != -1))
	pt->enabled = 1;
    else
	pt->enabled = 0;

    return 0;
}

void optfree(struct optstruct *opts)
{
    	struct optstruct *h, *a;
	int i;

    if(opts && opts->filename) {
	for(i = 0; opts->filename[i]; i++)
	    free(opts->filename[i]);
	free(opts->filename);
    }

    while(opts) {
	a = opts->nextarg;
	while(a) {
	    if(a->strarg) {
		free(a->name);
		free(a->cmd);
		free(a->strarg);
		h = a;
		a = a->nextarg;
		free(h);
	    } else {
		a = a->nextarg;
	    }
	}
	free(opts->name);
	free(opts->cmd);
	free(opts->strarg);
	h = opts;
	opts = opts->next;
	free(h);
    }
    return;
}

struct optstruct *optparse(const char *cfgfile, int argc, char **argv, int verbose, int toolmask, int ignore, struct optstruct *oldopts)
{
	FILE *fs = NULL;
	const struct clam_option *optentry;
	char *pt;
	const char *name = NULL, *arg;
	int i, err = 0, lc = 0, sc = 0, opt_index, line = 0, ret;
	struct optstruct *opts = NULL, *opts_last = NULL, *opt;
	char buffer[512], *buff;
	struct option longopts[MAXCMDOPTS];
	char shortopts[MAXCMDOPTS];
	regex_t regex;
	long long numarg, lnumarg;
	int regflags = REG_EXTENDED | REG_NOSUB;


    if(oldopts)
	opts = oldopts;

    shortopts[sc++] = ':';
    for(i = 0; ; i++) {
	optentry = &clam_options[i];
	if(!optentry->name && !optentry->longopt)
	    break;

	if(((optentry->owner & toolmask) && ((optentry->owner & toolmask) != OPT_DEPRECATED)) || (ignore && (optentry->owner & ignore))) {
	    if(!oldopts && optadd(&opts, &opts_last, optentry->name, optentry->longopt, optentry->strarg, optentry->numarg, optentry->flags, i) < 0) {
		fprintf(stderr, "ERROR: optparse: Can't register new option (not enough memory)\n");
		optfree(opts);
		return NULL;
	    }

	    if(!cfgfile) {
		if(optentry->longopt) {
		    if(lc >= MAXCMDOPTS) {
			fprintf(stderr, "ERROR: optparse: longopts[] is too small\n");
			optfree(opts);
			return NULL;
		    }
		    longopts[lc].name = optentry->longopt;
		    if(!(optentry->flags & FLAG_REQUIRED) && (optentry->argtype == CLOPT_TYPE_BOOL || optentry->strarg))
			longopts[lc].has_arg = 2;
		    else
			longopts[lc].has_arg = 1;
		    longopts[lc].flag = NULL;
		    longopts[lc++].val = optentry->shortopt;
		}
		if(optentry->shortopt) {
		    if(sc + 2 >= MAXCMDOPTS) {
			fprintf(stderr, "ERROR: optparse: shortopts[] is too small\n");
			optfree(opts);
			return NULL;
		    }
		    shortopts[sc++] = optentry->shortopt;
		    if(optentry->argtype != CLOPT_TYPE_BOOL) {
			shortopts[sc++] = ':';
			if(!(optentry->flags & FLAG_REQUIRED) && optentry->strarg)
			    shortopts[sc++] = ':';
		    }
		}
	    }
	}
    }

    if(cfgfile) {
	if((fs = fopen(cfgfile, "r")) == NULL) {
	    /* don't print error messages here! */
	    optfree(opts);
	    return NULL;
	}
    } else {
	if(MAX(sc, lc) > MAXCMDOPTS) {
	    fprintf(stderr, "ERROR: optparse: (short|long)opts[] is too small\n");
	    optfree(opts);
	    return NULL;
	}
	shortopts[sc] = 0;
	longopts[lc].name = NULL;
	longopts[lc].flag = NULL;
	longopts[lc].has_arg = longopts[lc].val = 0;
    }

    while(1) {

	if(cfgfile) {
	    if(!fgets(buffer, sizeof(buffer), fs))
		break;

	    buff = buffer;
	    for(i = 0; i < (int) strlen(buff) - 1 && (buff[i] == ' ' || buff[i] == '\t'); i++);
	    buff += i;
	    line++;
	    if(strlen(buff) <= 2 || buff[0] == '#')
		continue;

	    if(!strncmp("Example", buff, 7)) {
		if(verbose)
		    fprintf(stderr, "ERROR: Please edit the example config file %s\n", cfgfile);
		err = 1;
		break;
	    }

	    if(!(pt = strpbrk(buff, " \t"))) {
		if(verbose)
		    fprintf(stderr, "ERROR: Missing argument for option at %s:%d\n", cfgfile, line);
		err = 1;
		break;
	    }
	    name = buff;
	    *pt++ = 0;
	    for(i = 0; i < (int) strlen(pt) - 1 && (pt[i] == ' ' || pt[i] == '\t'); i++);
	    pt += i;
	    for(i = strlen(pt); i >= 1 && (pt[i - 1] == ' ' || pt[i - 1] == '\t' || pt[i - 1] == '\n'); i--);
	    if(!i) {
		if(verbose)
		    fprintf(stderr, "ERROR: Missing argument for option at %s:%d\n", cfgfile, line);
		err = 1;
		break;
	    }
	    pt[i] = 0;
	    arg = pt;
	    if(*arg == '"') {
		arg++; pt++;
		pt = strrchr(pt, '"');
		if(!pt) {
		    if(verbose)
			fprintf(stderr, "ERROR: Missing closing parenthesis in option %s at %s:%d\n", name, cfgfile, line);
		    err = 1;
		    break;
		}
		*pt = 0;
		if(!strlen(arg)) {
		    if(verbose)
			fprintf(stderr, "ERROR: Empty argument for option %s at %s:%d\n", name, cfgfile, line);
		    err = 1;
		    break;
		}
	    }

	} else {
	    opt_index = 0;
	    ret = my_getopt_long(argc, argv, shortopts, longopts, &opt_index);
	    if(ret == -1)
		break;

	    if(ret == ':') {
		fprintf(stderr, "ERROR: Incomplete option passed (missing argument)\n");
		err = 1;
		break;
	    } else if(!ret || strchr(shortopts, ret)) {
		name = NULL;
		if(ret) {
		    for(i = 0; i < lc; i++) {
			if(ret == longopts[i].val) {
			    name = longopts[i].name;
			    break;
			}
		    }
		} else {
		    name = longopts[opt_index].name;
		}
		if(!name) {
		    fprintf(stderr, "ERROR: optparse: No corresponding long name for option '-%c'\n", (char) ret);
		    err = 1;
		    break;
		}
		optarg ? (arg = optarg) : (arg = NULL);
	    } else {
		fprintf(stderr, "ERROR: Unknown option passed\n");
		err = 1;
		break;
	    }
	}

	if(!name) {
	    fprintf(stderr, "ERROR: Problem parsing options (name == NULL)\n");
	    err = 1;
	    break;
	}

	opt = optget_i(opts, name);
	if(!opt) {
	    if(cfgfile) {
		if(verbose)
		    fprintf(stderr, "ERROR: Parse error at %s:%d: Unknown option %s\n", cfgfile, line, name);
	    }
	    err = 1;
	    break;
	}
	optentry = &clam_options[opt->idx];

	if(ignore && (optentry->owner & ignore) && !(optentry->owner & toolmask)) {
	    if(cfgfile) {
		if(verbose)
		    fprintf(stderr, "WARNING: Ignoring unsupported option %s at %s:%d\n", opt->name, cfgfile, line);
	    } else {
		if(verbose) {
		    if(optentry->shortopt)
			fprintf(stderr, "WARNING: Ignoring unsupported option --%s (-%c)\n", optentry->longopt, optentry->shortopt);
		    else
			fprintf(stderr, "WARNING: Ignoring unsupported option --%s\n", optentry->longopt);
		}
	    }
	    continue;
	}

	if(optentry->owner & OPT_DEPRECATED) {
	    if(toolmask & OPT_DEPRECATED) {
		if(optaddarg(opts, name, "foo", 1) < 0) {
		    if(cfgfile)
			fprintf(stderr, "ERROR: Can't register argument for option %s\n", name);
		    else
			fprintf(stderr, "ERROR: Can't register argument for option --%s\n", optentry->longopt);
		    err = 1;
		    break;
		}
	    } else {
		if(cfgfile) {
		    if(verbose)
			fprintf(stderr, "WARNING: Ignoring deprecated option %s at %s:%d\n", opt->name, cfgfile, line);
		} else {
		    if(verbose) {
			if(optentry->shortopt)
			    fprintf(stderr, "WARNING: Ignoring deprecated option --%s (-%c)\n", optentry->longopt, optentry->shortopt);
			else
			    fprintf(stderr, "WARNING: Ignoring deprecated option --%s\n", optentry->longopt);
		    }
		}
	    }
	    continue;
	}

	if(!cfgfile && !arg && optentry->argtype == CLOPT_TYPE_BOOL) {
	    arg = "yes"; /* default to yes */
	} else if(optentry->regex) {
	    if(!(optentry->flags & FLAG_REG_CASE))
		regflags |= REG_ICASE;

	    if(cli_regcomp(&regex, optentry->regex, regflags)) {
		fprintf(stderr, "ERROR: optparse: Can't compile regular expression %s for option %s\n", optentry->regex, name);
		err = 1;
		break;
	    }
	    ret = cli_regexec(&regex, arg, 0, NULL, 0);
	    cli_regfree(&regex);
	    if(ret == REG_NOMATCH) {
		if(cfgfile) {
		    fprintf(stderr, "ERROR: Incorrect argument format for option %s\n", name);
		} else {
		    if(optentry->shortopt)
			fprintf(stderr, "ERROR: Incorrect argument format for option --%s (-%c)\n", optentry->longopt, optentry->shortopt);
		    else
			fprintf(stderr, "ERROR: Incorrect argument format for option --%s\n", optentry->longopt);
		}
		err = 1;
		break;
	    }
	}

	numarg = -1;
	switch(optentry->argtype) {
	    case CLOPT_TYPE_STRING:
		if(!arg)
		    arg = optentry->strarg;
		if(!cfgfile && !strlen(arg)) {
		    if(optentry->shortopt)
			fprintf(stderr, "ERROR: Option --%s (-%c) requires a non-empty string argument\n", optentry->longopt, optentry->shortopt);
		    else
			fprintf(stderr, "ERROR: Option --%s requires a non-empty string argument\n", optentry->longopt);
		    err = 1;
		    break;
		}
		break;

            case CLOPT_TYPE_NUMBER:
                if (arg)
                    numarg = atoi(arg);
                else
                    numarg = 0;
                arg = NULL;
                break;

            case CLOPT_TYPE_SIZE:
                errno = 0;
                if(arg)
                    lnumarg = strtoul(arg, &buff, 0);
                else {
                    numarg = 0;
                    break;
                }
		if(errno != ERANGE) {
		    switch(*buff) {
		    case 'M':
		    case 'm':
			if(lnumarg <= UINT_MAX/(1024*1024)) lnumarg *= 1024*1024;
			else errno = ERANGE;
			break;
		    case 'K':
		    case 'k':
			if(lnumarg <= UINT_MAX/1024) lnumarg *= 1024;
			else errno = ERANGE;
			break;
		    case '\0':
			break;
		    default:
			if(cfgfile) {
			    fprintf(stderr, "ERROR: Can't parse numerical argument for option %s\n", name);
			} else {
			    if(optentry->shortopt)
				fprintf(stderr, "ERROR: Can't parse numerical argument for option --%s (-%c)\n", optentry->longopt, optentry->shortopt);
			    else
				fprintf(stderr, "ERROR: Can't parse numerical argument for option --%s\n", optentry->longopt);
			}
			err = 1;
		    }
		}

		arg = NULL;
		if(err) break;
		if(errno == ERANGE) {
		    if(cfgfile) {
			fprintf(stderr, "WARNING: Numerical value for option %s too high, resetting to 4G\n", name);
		    } else {
			if(optentry->shortopt)
			    fprintf(stderr, "WARNING: Numerical value for option --%s (-%c) too high, resetting to 4G\n", optentry->longopt, optentry->shortopt);
			else
			    fprintf(stderr, "WARNING: Numerical value for option %s too high, resetting to 4G\n", optentry->longopt);
		    }
		    lnumarg = UINT_MAX;
		}

		numarg = lnumarg ? lnumarg : UINT_MAX;
		break;

	    case CLOPT_TYPE_BOOL:
                if(!strcasecmp(arg, "yes") || !strcmp(arg, "1") || !strcasecmp(arg, "true"))
		    numarg = 1;
		else
		    numarg = 0;

		arg = NULL;
		break;
	}

	if(err)
	    break;

	if(optaddarg(opts, name, arg, numarg) < 0) {
	    if(cfgfile)
		fprintf(stderr, "ERROR: Can't register argument for option %s\n", name);
	    else
		fprintf(stderr, "ERROR: Can't register argument for option --%s\n", optentry->longopt);
	    err = 1;
	    break;
	}
    }

    if(fs)
	fclose(fs);

    if(err) {
	optfree(opts);
	return NULL;
    }

    if(!cfgfile && opts && (optind < argc)) {
	opts->filename = (char **) calloc(argc - optind + 1, sizeof(char *));
	if(!opts->filename) {
	    fprintf(stderr, "ERROR: optparse: calloc failed\n");
	    optfree(opts);
	    return NULL;
	}
        for(i = optind; i < argc; i++) {
	    opts->filename[i - optind] = strdup(argv[i]);
	    if(!opts->filename[i - optind]) {
		fprintf(stderr, "ERROR: optparse: strdup failed\n");
		optfree(opts);
		return NULL;
	    }
	}
    }

    /* optprint(opts); */

    return opts;
}

struct optstruct *optadditem(const char *name, const char *arg, int verbose, int toolmask, int ignore,
                            struct optstruct *oldopts)
{
	int i, err = 0, sc = 0, lc=0, ret;
	struct optstruct *opts = NULL, *opts_last = NULL, *opt;
	char *buff;
	regex_t regex;
	long long numarg, lnumarg;
	int regflags = REG_EXTENDED | REG_NOSUB;
    const struct clam_option *optentry = NULL;

    if(oldopts)
        opts = oldopts;


    for(i = 0; ; i++) {
        optentry = &clam_options[i];
        if(!optentry->name && !optentry->longopt)
            break;

        if(((optentry->owner & toolmask) && ((optentry->owner & toolmask) != OPT_DEPRECATED)) || (ignore && (optentry->owner & ignore))) {
            if(!oldopts && optadd(&opts, &opts_last, optentry->name, optentry->longopt, optentry->strarg, optentry->numarg, optentry->flags, i) < 0) {
                fprintf(stderr, "ERROR: optparse: Can't register new option (not enough memory)\n");
                optfree(opts);
                return NULL;
            }

        }
    }

    if(MAX(sc, lc) > MAXCMDOPTS) {
	    fprintf(stderr, "ERROR: optparse: (short|long)opts[] is too small\n");
	    optfree(opts);
	    return NULL;
	}

    while(1) {
        if(!name) {
            fprintf(stderr, "ERROR: Problem parsing options (name == NULL)\n");
            err = 1;
            break;
        }

        opt = optget_i(opts, name);
        if(!opt) {
            if(verbose)
                fprintf(stderr, "ERROR: Parse error: Unknown option %s\n", name);
            err = 1;
            break;
        }
        optentry = &clam_options[opt->idx];

        if(ignore && (optentry->owner & ignore) && !(optentry->owner & toolmask)) {
            if(verbose)
                fprintf(stderr, "WARNING: Ignoring unsupported option %s\n", opt->name);
            continue;
        }

        if(optentry->owner & OPT_DEPRECATED) {
            if(toolmask & OPT_DEPRECATED) {
                if(optaddarg(opts, name, "foo", 1) < 0) {
                    fprintf(stderr, "ERROR: Can't register argument for option %s\n", name);
                    err = 1;
                    break;
                }
            } else {
                if(verbose)
                    fprintf(stderr, "WARNING: Ignoring deprecated option %s\n", opt->name);
            }
            continue;
        }

        if(optentry->regex) {
            if(!(optentry->flags & FLAG_REG_CASE))
                regflags |= REG_ICASE;

            if(cli_regcomp(&regex, optentry->regex, regflags)) {
                fprintf(stderr, "ERROR: optparse: Can't compile regular expression %s for option %s\n", optentry->regex, name);
                err = 1;
                break;
            }
            ret = cli_regexec(&regex, arg, 0, NULL, 0);
            cli_regfree(&regex);
            if(ret == REG_NOMATCH) {
                fprintf(stderr, "ERROR: Incorrect argument format for option %s\n", name);
                err = 1;
                break;
            }
        }

        numarg = -1;
        switch(optentry->argtype) {
            case CLOPT_TYPE_STRING:
                if(!arg)
                    arg = optentry->strarg;

                break;

            case CLOPT_TYPE_NUMBER:
                if (arg)
                    numarg = atoi(arg);
                else
                    numarg = 0;
                arg = NULL;
                break;

            case CLOPT_TYPE_SIZE:
                errno = 0;
                if(arg)
                    lnumarg = strtoul(arg, &buff, 0);
                else {
                    numarg = 0;
                    break;
                }
                if(errno != ERANGE) {
                    switch(*buff) {
                        case 'M':
                        case 'm':
                            if(lnumarg <= UINT_MAX/(1024*1024)) lnumarg *= 1024*1024;
                            else errno = ERANGE;
                            break;
                        case 'K':
                        case 'k':
                            if(lnumarg <= UINT_MAX/1024) lnumarg *= 1024;
                            else errno = ERANGE;
                            break;
                        case '\0':
                            break;
                        default:
                            fprintf(stderr, "ERROR: Can't parse numerical argument for option %s\n", name);
                            err = 1;
                    }
                }

                arg = NULL;
                if(err) break;
                if(errno == ERANGE) {
                    fprintf(stderr, "WARNING: Numerical value for option %s too high, resetting to 4G\n", name);
                    lnumarg = UINT_MAX;
                }

                numarg = lnumarg ? lnumarg : UINT_MAX;
                break;

            case CLOPT_TYPE_BOOL:
                if(!strcasecmp(arg, "yes") || !strcmp(arg, "1") || !strcasecmp(arg, "true"))
                    numarg = 1;
                else
                    numarg = 0;

                arg = NULL;
                break;
        }

        if(err)
            break;

        if(optaddarg(opts, name, arg, numarg) < 0) {
            fprintf(stderr, "ERROR: Can't register argument for option --%s\n", optentry->longopt);
            err = 1;
        }
        break;
    }

    if(err) {
        optfree(opts);
        return NULL;
    }

    return opts;
}

# Features that can be enabled for cmake (see CMakeLists.txt)

if (WIN32)
    set(APP_CONFIG_DIRECTORY
        "${CMAKE_INSTALL_PREFIX}" CACHE STRING
        "App Config directory.")
    set(DATABASE_DIRECTORY
        "${CMAKE_INSTALL_PREFIX}/database" CACHE STRING
        "Database directory.")
else()
    set(APP_CONFIG_DIRECTORY
        "${CMAKE_INSTALL_PREFIX}/etc" CACHE STRING
        "App Config directory.")
    set(DATABASE_DIRECTORY
        "${CMAKE_INSTALL_PREFIX}/share/clamav" CACHE STRING
        "Database directory.")
endif()

set(CLAMAV_USER "clamav" CACHE STRING "ClamAV User")
set(CLAMAV_GROUP "clamav" CACHE STRING "ClamAV Group")

set(MMAP_FOR_CROSSCOMPILING
    0 CACHE STRING
    "Force MMAP support for cross-compiling.")
set(DISABLE_MPOOL
    0 CACHE STRING
    "Disable mpool support entirely.")

set(BYTECODE_RUNTIME
    "interpreter" CACHE STRING
    "Bytecode Runtime, may be: 'llvm', 'interpreter', 'none'.")

option(OPTIMIZE
    "Allow compiler optimizations.  Set to OFF to disable (i.e. to set -O0)."
    ON)

option(ENABLE_WERROR
    "Compile time warnings will cause build failures.")

option(ENABLE_ALL_THE_WARNINGS
    "Enable as many compiler warnings as possible.")

option(ENABLE_DEBUG
    "Turn on extra debug output.")

option(ENABLE_EXPERIMENTAL
    "Turn on experimental features (if any).")

option(ENABLE_FRESHCLAM_DNS_FIX
    "Enable workaround for broken DNS servers.")

option(ENABLE_FRESHCLAM_NO_CACHE
    "Use 'Cache-Control: no-cache' in freshclam.")

option(ENABLE_STRN_INTERNAL
    "Enables explicit use of internal strn functions to support cross-compilation against older libs.")

option(ENABLE_FUZZ
    "Build fuzz targets. Will enable ENABLE_STATIC_LIB for you.")

option(ENABLE_EXTERNAL_MSPACK
    "Use external mspack instead of internal libclammspack.")

option(ENABLE_JSON_SHARED
    "Prefer linking with libjson-c shared library instead of static."
    ON)

option(ENABLE_APP
    "Build applications (clamscan, clamd, clamdscan, clamonacc, sigtool, clambc, clamav-milter, clamdtop, clamsubmit, clamconf)."
    ${ENABLE_APP_DEFAULT})

option(ENABLE_MILTER
    "Build clamav-milter (requires ENABLE_APP))."
    ${ENABLE_MILTER_DEFAULT})

option(ENABLE_CLAMONACC
    "Build clamonacc (Linux-only, requires ENABLE_APP))."
    ${ENABLE_CLAMONACC_DEFAULT})

option(ENABLE_DOCS
    "Generate documentation."
    ${ENABLE_DOCS_DEFAULT})

option(ENABLE_DOXYGEN
    "Generate doxygen HTML documentation for clamav.h, libfreshclam.h."
    ${ENABLE_DOXYGEN_DEFAULT})

option(ENABLE_EXAMPLES
    "Build examples."
    ${ENABLE_EXAMPLES_DEFAULT})

option(ENABLE_LIBCLAMAV_ONLY
    "Build libclamav only. Excludes libfreshclam too!")

option(ENABLE_STATIC_LIB
    "Build libclamav and/or libfreshclam static libraries.")

option(ENABLE_SHARED_LIB
    "Build libclamav and/or libfreshclam shared libraries."
    ON)

option(ENABLE_UNRAR
    "Build & install libclamunrar."
    ${ENABLE_UNRAR_DEFAULT})

option(ENABLE_SYSTEMD
    "Install systemd service files if systemd is found."
    ${ENABLE_SYSTEMD_DEFAULT})

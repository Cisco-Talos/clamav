# Features that can be enabled for cmake (see CMakeLists.txt)

option(OPTIMIZE
    "Allow compiler optimizations.  Set to OFF to disable (i.e. to set -O0)."
    ON)

option(ENABLE_WERROR
    "Compile time warnings will cause build failures.")

option(ENABLE_DEBUG
    "Turn on extra debug output.")

option(ENABLE_EXAMPLES
    "Build examples."
    ${ENABLE_EXAMPLES_DEFAULT})

option(ENABLE_EXPERIMENTAL
    "Turn on experimental features (if any).")

option(ENABLE_MAN_PAGES
    "Generate man pages."
    ${ENABLE_MAN_PAGES_DEFAULT})

option(ENABLE_DOXYGEN
    "Generate doxygen HTML documentation."
    ${ENABLE_DOXYGEN_DEFAULT})

option(ENABLE_TESTS
    "Build/enable tests."
    ${ENABLE_TESTS_DEFAULT})

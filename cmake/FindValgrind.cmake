#
# Find the Valgrind program.
#
# If found, will set: Valgrind_FOUND, Valgrind_VERSION, and Valgrind_EXECUTABLE
#
# If you have a custom install location for Valgrind, you can provide a hint
# by settings -DValgrind_HOME=<directory containing valgrind>
#

find_program(Valgrind_EXECUTABLE valgrind
    HINTS "${Valgrind_HOME}"
    PATH_SUFFIXES "bin"
)
if(Valgrind_EXECUTABLE)
    execute_process(COMMAND "${Valgrind_EXECUTABLE}" --version
        OUTPUT_VARIABLE Valgrind_VERSION_OUTPUT
        ERROR_VARIABLE  Valgrind_VERSION_ERROR
        RESULT_VARIABLE Valgrind_VERSION_RESULT
    )
    if(NOT ${Valgrind_VERSION_RESULT} EQUAL 0)
        message(STATUS "Valgrind not found: Failed to determine version.")
        unset(Valgrind_EXECUTABLE)
    else()
        string(REGEX
            MATCH "[0-9]+\\.[0-9]+(\\.[0-9]+)?(-nightly)?"
            Valgrind_VERSION "${Valgrind_VERSION_OUTPUT}"
        )
        set(Valgrind_VERSION "${Valgrind_VERSION}")
        set(Valgrind_FOUND 1)
        message(STATUS "Valgrind found: ${Valgrind_EXECUTABLE}, ${Valgrind_VERSION}")
    endif()

    mark_as_advanced(Valgrind_EXECUTABLE Valgrind_VERSION)
else()
    message(STATUS "Valgrind not found.")
endif()

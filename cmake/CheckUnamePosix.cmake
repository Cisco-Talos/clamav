#
# Check for POSIX compliant uname(2) sys call.
# This feature reworked from http://www.gnu.org/software/autoconf-archive/ax_check_uname_syscall.html
#

GET_FILENAME_COMPONENT(_selfdir_CheckUnamePosix
    "${CMAKE_CURRENT_LIST_FILE}" PATH)

# Check that the POSIX compliant uname(2) call works properly (HAVE_UNAME_SYSCALL)
try_run(
    # Name of variable to store the run result (process exit status; number) in:
    test_run_result
    # Name of variable to store the compile result (TRUE or FALSE) in:
    test_compile_result
    # Binary directory:
    ${CMAKE_CURRENT_BINARY_DIR}
    # Source file to be compiled:
    ${_selfdir_CheckUnamePosix}/CheckUnamePosix.c
    # Where to store the output produced during compilation:
    COMPILE_OUTPUT_VARIABLE test_compile_output
    # Where to store the output produced by running the compiled executable:
    RUN_OUTPUT_VARIABLE test_run_output )

# Did compilation succeed and process return 0 (success)?
if("${test_compile_result}" AND ("${test_run_result}" EQUAL 0))
    set(HAVE_UNAME_SYSCALL 1)
endif()

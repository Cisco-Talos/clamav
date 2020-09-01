#
# Check for signed right-shift
#

GET_FILENAME_COMPONENT(_selfdir_CheckSignedRightShift
    "${CMAKE_CURRENT_LIST_FILE}" PATH)

# Check for signed right-shift (HAVE_SAR)
try_run(
    # Name of variable to store the run result (process exit status; number) in:
    test_run_result
    # Name of variable to store the compile result (TRUE or FALSE) in:
    test_compile_result
    # Binary directory:
    ${CMAKE_CURRENT_BINARY_DIR}
    # Source file to be compiled:
    ${_selfdir_CheckSignedRightShift}/CheckSignedRightShift.c
    # Where to store the output produced during compilation:
    COMPILE_OUTPUT_VARIABLE test_compile_output
    # Where to store the output produced by running the compiled executable:
    RUN_OUTPUT_VARIABLE test_run_output )

# Did compilation succeed and process return 0 (success)?
if("${test_compile_result}" AND ("${test_run_result}" EQUAL 0))
    set(HAVE_SAR 1)
endif()

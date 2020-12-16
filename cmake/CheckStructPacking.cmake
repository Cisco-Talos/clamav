#
# Check for struct packing features
# This feature reworked from m4/reorganization/code_checks/compiler_attribs.m4
#

GET_FILENAME_COMPONENT(_selfdir_CheckStructPacking
    "${CMAKE_CURRENT_LIST_FILE}" PATH)

# Check if __attribute__((packed)) is available
check_c_source_compiles(
    "
    #ifdef __GNUC__
    struct { int i __attribute__((packed)); } s; int main(){return 0;}
    #else
    #error Only checking for packed attribute on gcc-like compilers
    #endif
    "
    HAVE_ATTRIB_PACKED )
if(NOT HAVE_ATTRIB_PACKED)
    # Check for packing via pragma (HAVE_PRAGMA_PACK)
    try_run(
        # Name of variable to store the run result (process exit status; number) in:
        test_run_result
        # Name of variable to store the compile result (TRUE or FALSE) in:
        test_compile_result
        # Binary directory:
        ${CMAKE_CURRENT_BINARY_DIR}
        # Source file to be compiled:
        ${_selfdir_CheckStructPacking}/CheckStructPacking_PRAGMA_PACK.c
        # Where to store the output produced during compilation:
        COMPILE_OUTPUT_VARIABLE test_compile_output
        # Where to store the output produced by running the compiled executable:
        RUN_OUTPUT_VARIABLE test_run_output )

    # Did compilation succeed and process return 0 (success)?
    if("${test_compile_result}" AND ("${test_run_result}" EQUAL 0))
        set(HAVE_PRAGMA_PACK 1)
    endif()

    if(NOT HAVE_PRAGMA_PACK)
        # Check for packing via hppa/hp-uux pragma (HAVE_PRAGMA_PACK_HPPA)
        try_run(
            # Name of variable to store the run result (process exit status; number) in:
            test_run_result
            # Name of variable to store the compile result (TRUE or FALSE) in:
            test_compile_result
            # Binary directory:
            ${CMAKE_CURRENT_BINARY_DIR}
            # Source file to be compiled:
            ${_selfdir_CheckStructPacking}/CheckStructPacking_PRAGMA_PACK_HPPA.c
            # Where to store the output produced during compilation:
            COMPILE_OUTPUT_VARIABLE test_compile_output
            # Where to store the output produced by running the compiled executable:
            RUN_OUTPUT_VARIABLE test_run_output )

        # Did compilation succeed and process return 0 (success)?
        if("${test_compile_result}" AND ("${test_run_result}" EQUAL 0))
            set(HAVE_PRAGMA_PACK_HPPA 1)
        endif()
    endif()
endif()

# Check if struct __attribute__((aligned)) is available
check_c_source_compiles(
    "
    typedef int cl_aligned_int __attribute__((aligned)); int main(){return 0;}
    "
    HAVE_ATTRIB_ALIGNED )

if (NOT (HAVE_ATTRIB_PACKED OR HAVE_PRAGMA_PACK OR HAVE_PRAGMA_PACK_HPPA))
    message(FATAL_ERROR "Failed to determine how to pack structs with this compiler!")
endif()

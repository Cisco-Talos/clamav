#
# Check if file descriptor passing is supported
# Derived from work submitted by Richard Lyons <frob-clamav@webcentral.com.au>
#

GET_FILENAME_COMPONENT(_selfdir_CheckFDPassing
    "${CMAKE_CURRENT_LIST_FILE}" PATH)

include(CheckSymbolExists)
check_symbol_exists(recvmsg "sys/socket.h" HAVE_RECVMSG)
check_symbol_exists(sendmsg "sys/socket.h" HAVE_SENDMSG)

# Extra -D Compile Definitions for check_c_source_compiles()
set(CMAKE_REQUIRED_DEFINITIONS "")
if(HAVE_SYS_TYPES_H)
    set(CMAKE_REQUIRED_DEFINITIONS "${CMAKE_REQUIRED_DEFINITIONS};-DHAVE_SYS_TYPES_H=1")
endif()
if(HAVE_SYS_UIO_H)
    set(CMAKE_REQUIRED_DEFINITIONS "${CMAKE_REQUIRED_DEFINITIONS};-DHAVE_SYS_UIO_H=1")
endif()

# Check for msg_control field in struct msghdr
check_c_source_compiles(
    "
    #define _XOPEN_SOURCE 500
    #ifdef HAVE_SYS_TYPES_H
    # include <sys/types.h>
    #endif
    #include <sys/socket.h>
    #ifdef HAVE_SYS_UIO_H
    # include <sys/uio.h>
    #endif

    int main(void) {
        #ifdef msg_control
        # error msg_control defined
        #endif

        struct msghdr m;
        m.msg_control = 0;
        return 0;
    }
    "
    HAVE_CONTROL_IN_MSGHDR )

if(HAVE_CONTROL_IN_MSGHDR)
    #
    # Check whether BSD 4.4 / RFC2292 style fd passing works
    #
    set(EXTRA_COMPILE_DEFINITIONS "")
    if(HAVE_SYS_TYPES_H)
        set(EXTRA_COMPILE_DEFINITIONS "${EXTRA_COMPILE_DEFINITIONS} -DHAVE_SYS_TYPES_H=1")
    endif()
    if(HAVE_SYS_UIO_H)
        set(EXTRA_COMPILE_DEFINITIONS "${EXTRA_COMPILE_DEFINITIONS} -DHAVE_SYS_UIO_H=1")
    endif()

    # Try without _XOPEN_SOURCE first
    try_run(
        # Name of variable to store the run result (process exit status; number) in:
        test_run_result
        # Name of variable to store the compile result (TRUE or FALSE) in:
        test_compile_result
        # Binary directory:
        ${CMAKE_CURRENT_BINARY_DIR}
        # Source file to be compiled:
        ${_selfdir_CheckFDPassing}/CheckFDPassing.c
        # Extra -D Compile Definitions
        COMPILE_DEFINITIONS ${EXTRA_COMPILE_DEFINITIONS}
        # Where to store the output produced during compilation:
        COMPILE_OUTPUT_VARIABLE test_compile_output
        # Where to store the output produced by running the compiled executable:
        RUN_OUTPUT_VARIABLE test_run_output )

    # Did compilation succeed and process return 0 (success)?
    if("${test_compile_result}" AND ("${test_run_result}" EQUAL 0))
        set(HAVE_FD_PASSING 1)
    else()
        # Try again, this time with: #define _XOPEN_SOURCE 500
        set(EXTRA_COMPILE_DEFINITIONS "${EXTRA_COMPILE_DEFINITIONS} -D_XOPEN_SOURCE=500")

        try_run(
            # Name of variable to store the run result (process exit status; number) in:
            test_run_result
            # Name of variable to store the compile result (TRUE or FALSE) in:
            test_compile_result
            # Binary directory:
            ${CMAKE_CURRENT_BINARY_DIR}
            # Source file to be compiled:
            ${_selfdir_CheckFDPassing}/CheckFDPassing.c
            # Extra -D Compile Definitions
            COMPILE_DEFINITIONS ${EXTRA_COMPILE_DEFINITIONS}
            # Where to store the output produced during compilation:
            COMPILE_OUTPUT_VARIABLE test_compile_output
            # Where to store the output produced by running the compiled executable:
            RUN_OUTPUT_VARIABLE test_run_output )

        # Did compilation succeed and process return 0 (success)?
        if("${test_compile_result}" AND ("${test_run_result}" EQUAL 0))
            set(HAVE_FD_PASSING 1)
            set(FDPASS_NEED_XOPEN 1)
        endif()
    endif()

endif()

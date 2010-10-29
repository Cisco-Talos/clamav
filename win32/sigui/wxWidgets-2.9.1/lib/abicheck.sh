#!/bin/bash

# Script originally based on GTK+'s own abicheck.sh; it should be run anytime
# there is a change in the stable branch of wxWidgets which could lead to an
# ABI breakage and thus result in a binary-incompatible change (see tech docs).
#
# $Id$


expected_abi_file="expected_abi"
actual_abi_file="actual_abi"

if [[ "$1" == "--generate" ]]; then

    # IMPORTANT: we need a shared build of wxWidgets to proceed
    if [[ $(echo *.so) == "*.so" ]]; then
        echo "No shared objects (*.so) were found... aborting"
        exit 1
    fi

    # generated the "expected ABI" for later comparison
    rm -f $expected_abi_file
    for library in *.so; do
        # NOTE: don't use -C option as otherwise cut won't work correctly
        nm -D -g --defined-only $library | cut -d ' ' -f 3 | sort >>$expected_abi_file
    done

    echo "Expected wxWidgets ABI generated in \"$expected_abi_file\"..."

elif [[ -z "$1" ]]; then

    if [[ ! -f "$expected_abi_file" ]]; then
        echo "The file containing the expected wxWidgets ABI '$expected_abi_file' does not exist!"
        echo "Please generate it first using the '--generate' option"
        exit 1
    fi

    echo "Comparing actual ABI with the expected ABI (loading it from \"$expected_abi_file\")..."

    # IMPORTANT: we need a shared build of wxWidgets to do the check
    if [[ $(echo *.so) == "*.so" ]]; then
        echo "No shared objects (*.so) were found... aborting"
        exit 1
    fi

    rm -f $actual_abi_file
    for library in *.so; do
        # NOTE: don't use -C option as otherwise cut won't work correctly
        nm -D -g --defined-only $library | cut -d ' ' -f 3 | sort >>$actual_abi_file
    done

    result=`diff -u $expected_abi_file $actual_abi_file`

    if [[ -z "$result" ]]; then
        echo "No binary (in)compatible changes were found."
    else
        echo "========================================================="
        echo "WARNING: Possible binary-incompatible changes were found:"
        echo "========================================================="
        echo
        echo "$result"

        # this doesn't necessarly indicate that binary compatibility was surely
        # broken; e.g. adding non-virtual methods will generate a new line in the
        # $actual_abi_file but that's a compatible change.
    fi

else

    echo "Usage: $0 [--generate]"
    echo "When running without options, compares the wxWidgets ABI saved in '$expected_abi_file'"
    echo "with the current ABI of the .so files of the working directory."
    echo "When --generate is given, saves in '$expected_abi_file' the ABI of the .so files"
    echo "(for later comparisons)."

fi


# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

#[=======================================================================[.rst:
FindCURSES
-------

Finds the CURSES library.

Imported Targets
^^^^^^^^^^^^^^^^

This module provides the following imported targets, if found:

``Curses::curses``
  The CURSES library and possibly TINFO library

Result Variables
^^^^^^^^^^^^^^^^

This will define the following variables:

``CURSES_FOUND``
  True if the system has the CURSES library.
``CURSES_VERSION``
  The version of the CURSES library which was found.
``CURSES_INCLUDE_DIRS``
  Include directories needed to use CURSES.
``CURSES_LIBRARIES``
  Libraries needed to link to CURSES.

Cache Variables
^^^^^^^^^^^^^^^

The following cache variables may also be set:

``NCURSES_INCLUDE_DIR``
  The directory containing ``ncurses.h``.
``PDCURSES_INCLUDE_DIR``
  The directory containing ``curses.h``.
``CURSES_LIBRARY``
  The path to the CURSES library.
``TINFO_LIBRARY``
  The path to the TINFO library.

#]=======================================================================]

if(NOT NCURSES_INCLUDE_DIR)
  find_package(PkgConfig QUIET)
  # First try for NCurses
  pkg_search_module (PC_NCurses QUIET ncurses ncursesw)
endif()

find_path(NCURSES_INCLUDE_DIR
    NAMES ncurses.h
    PATHS ${PC_NCurses_INCLUDE_DIRS} ${CURSES_INCLUDE_DIR}
)

string(FIND ${NCURSES_INCLUDE_DIR} "-NOTFOUND" NCURSES_NOT_FOUND)
if(NCURSES_NOT_FOUND EQUAL -1)
    #
    # ncurses WAS found!
    #
    set(HAVE_LIBNCURSES 1)
    set(CURSES_INCLUDE "<ncurses.h>")

    if (DEFINED PC_NCurses_LINK_LIBRARIES)
        set(CURSES_LIBRARY ${PC_NCurses_LINK_LIBRARIES})
    else()
        find_library(CURSES_LIBRARY
            NAMES ncurses ncursesw
            PATHS ${PC_NCurses_LIBRARY_DIRS}
        )
    endif()

    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(CURSES
        FOUND_VAR CURSES_FOUND
        REQUIRED_VARS
            CURSES_LIBRARY
            NCURSES_INCLUDE_DIR
        VERSION_VAR CURSES_VERSION
    )

    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(TINFO
        FOUND_VAR TINFO_FOUND
        REQUIRED_VARS
            TINFO_LIBRARY
            NCURSES_INCLUDE_DIR
        VERSION_VAR CURSES_VERSION
        NAME_MISMATCHED
    )

    set(HAVE_LIBNCURSES 1)
    set(CURSES_INCLUDE "<ncurses.h>")

    if(NOT TINFO_FOUND)
        set(CURSES_LIBRARIES "${CURSES_LIBRARY}")
    else()
        set(CURSES_LIBRARIES "${CURSES_LIBRARY};${TINFO_LIBRARY}")
    endif()

    set(CURSES_INCLUDE_DIRS ${NCURSES_INCLUDE_DIR})
    set(CURSES_DEFINITIONS ${PC_NCurses_CFLAGS_OTHER})

    if (NOT TARGET Curses::curses)
        add_library(Curses::curses INTERFACE IMPORTED)
        set_target_properties(Curses::curses PROPERTIES
            INTERFACE_COMPILE_OPTIONS "${PC_NCurses_CFLAGS_OTHER}"
            INTERFACE_INCLUDE_DIRECTORIES "${CURSES_INCLUDE_DIRS}"
            INTERFACE_LINK_LIBRARIES "${CURSES_LIBRARIES}"
        )
    endif()
else()
    # Try for PDCurses
    pkg_check_modules(PC_PDCurses QUIET curses)

    find_path(PDCURSES_INCLUDE_DIR
        NAMES curses.h
        PATHS ${PC_PDCurses_INCLUDE_DIRS} ${CURSES_INCLUDE_DIR}
    )

    string(FIND ${PDCURSES_INCLUDE_DIR} "-NOTFOUND" PDCURSES_NOT_FOUND)
    if(PDCURSES_NOT_FOUND EQUAL -1)
        #
        # pdcurses WAS found!
        #
        set(HAVE_LIBPDCURSES 1)
        set(CURSES_INCLUDE "<curses.h>")

        find_library(CURSES_LIBRARY
            NAMES curses pdcurses
            PATHS ${PC_PDCurses_LIBRARY_DIRS}
        )

        set(CURSES_VERSION ${PC_PDCurses_VERSION})

        include(FindPackageHandleStandardArgs)
        find_package_handle_standard_args(CURSES
            FOUND_VAR CURSES_FOUND
            REQUIRED_VARS
                CURSES_LIBRARY
                PDCURSES_INCLUDE_DIR
            VERSION_VAR CURSES_VERSION
        )

        set(HAVE_LIBPDCURSES 1)
        set(CURSES_INCLUDE "<curses.h>")

        set(CURSES_LIBRARIES ${CURSES_LIBRARY})
        set(CURSES_INCLUDE_DIRS ${PDCURSES_INCLUDE_DIR})
        set(CURSES_DEFINITIONS ${PC_PDCurses_CFLAGS_OTHER})

        if (NOT TARGET Curses::curses)
            add_library(Curses::curses UNKNOWN IMPORTED)
            set_target_properties(Curses::curses PROPERTIES
                INTERFACE_COMPILE_OPTIONS "${PC_PDCurses_CFLAGS_OTHER}"
                INTERFACE_INCLUDE_DIRECTORIES "${CURSES_INCLUDE_DIRS}"
                IMPORTED_LOCATION "${CURSES_LIBRARIES}"
            )
        endif()
    else()
        message(FATAL_ERROR "Unable to find ncurses or pdcurses")
    endif()
endif()

mark_as_advanced(
    NCURSES_INCLUDE_DIR
    PDCURSES_INCLUDE_DIR
    CURSES_LIBRARY
    TINFO_LIBRARY
)

# FindPDFIUM.cmake
#
# Finds the PDFium library.
#
# Variables set:
#  PDFIUM_FOUND
#  PDFIUM_LIBRARY
#  PDFIUM_INCLUDE_DIR
#
# Imported targets:
#  PDFIUM::pdfium

if(PDFIUM_LIBRARY)
    set(PDFIUM_LIBRARY_FOUND TRUE)
elseif(DEFINED ENV{PDFIUM_LIBRARY})
    set(PDFIUM_LIBRARY "$ENV{PDFIUM_LIBRARY}")
    set(PDFIUM_LIBRARY_FOUND TRUE)
endif()

if(NOT PDFIUM_LIBRARY_FOUND)
    set(_PDFIUM_ROOT "${PDFIUM_ROOT}")
    if(NOT _PDFIUM_ROOT AND DEFINED ENV{PDFIUM_ROOT})
        set(_PDFIUM_ROOT "$ENV{PDFIUM_ROOT}")
    endif()

    find_library(PDFIUM_LIBRARY
        NAMES pdfium
        HINTS "${_PDFIUM_ROOT}"
        PATH_SUFFIXES lib lib64)

    find_path(PDFIUM_INCLUDE_DIR
        NAMES fpdfview.h
        HINTS "${_PDFIUM_ROOT}"
        PATH_SUFFIXES include)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PDFIUM
    FOUND_VAR PDFIUM_FOUND
    REQUIRED_VARS PDFIUM_LIBRARY)

if(PDFIUM_FOUND AND NOT TARGET PDFIUM::pdfium)
    add_library(PDFIUM::pdfium UNKNOWN IMPORTED)
    set_target_properties(PDFIUM::pdfium PROPERTIES
        IMPORTED_LOCATION "${PDFIUM_LIBRARY}")
    if(PDFIUM_INCLUDE_DIR)
        set_target_properties(PDFIUM::pdfium PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES "${PDFIUM_INCLUDE_DIR}")
    endif()
endif()

if(PDFIUM_FOUND)
    set(PDFIUM_LIBRARIES "${PDFIUM_LIBRARY}")
    if(PDFIUM_INCLUDE_DIR)
        set(PDFIUM_INCLUDE_DIRS "${PDFIUM_INCLUDE_DIR}")
    else()
        set(PDFIUM_INCLUDE_DIRS "")
    endif()
    if(DEFINED ENABLE_PDFIUM AND ENABLE_PDFIUM)
        message(STATUS "PDFium library: ${PDFIUM_LIBRARY}")
        if(PDFIUM_INCLUDE_DIR)
            message(STATUS "PDFium include dir: ${PDFIUM_INCLUDE_DIR}")
        endif()
    endif()
endif()

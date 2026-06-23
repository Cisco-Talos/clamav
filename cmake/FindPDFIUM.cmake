# FindPDFIUM.cmake
#
# Finds the PDFium library.
#
# Variables set:
#  PDFIUM_FOUND
#  PDFIUM_LIBRARY
#  PDFIUM_INCLUDE_DIR
#  PDFIUM_EXTRA_LIBRARIES - additional libraries required by static PDFium builds
#
# Imported targets:
#  PDFIUM::pdfium

if(NOT PDFIUM_EXTRA_LIBRARIES AND DEFINED ENV{PDFIUM_EXTRA_LIBRARIES})
    set(PDFIUM_EXTRA_LIBRARIES "$ENV{PDFIUM_EXTRA_LIBRARIES}")
endif()

if(NOT PDFIUM_EXTRA_LIBRARY_DIRS AND DEFINED ENV{PDFIUM_EXTRA_LIBRARY_DIRS})
    set(PDFIUM_EXTRA_LIBRARY_DIRS "$ENV{PDFIUM_EXTRA_LIBRARY_DIRS}")
endif()

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

    set(_PDFIUM_INTERFACE_LIBRARIES)

    if(PDFIUM_LIBRARY MATCHES "\\.a$")
        set_target_properties(PDFIUM::pdfium PROPERTIES
            IMPORTED_LINK_INTERFACE_LANGUAGES "CXX")

        if(APPLE)
            get_filename_component(_PDFIUM_LIBDIR "${PDFIUM_LIBRARY}" DIRECTORY)
            list(APPEND _PDFIUM_INTERFACE_LIBRARIES
                "c++"
                "-framework CoreGraphics")
        elseif(UNIX)
            foreach(_PDFIUM_CXX_LIBRARY IN LISTS CMAKE_CXX_IMPLICIT_LINK_LIBRARIES)
                if(_PDFIUM_CXX_LIBRARY MATCHES "^(stdc\\+\\+|supc\\+\\+|c\\+\\+|c\\+\\+abi)$")
                    list(APPEND _PDFIUM_INTERFACE_LIBRARIES "${_PDFIUM_CXX_LIBRARY}")
                endif()
            endforeach()

            if(NOT _PDFIUM_INTERFACE_LIBRARIES)
                if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" AND CMAKE_CXX_FLAGS MATCHES "(^| )-stdlib=libc\\+\\+")
                    list(APPEND _PDFIUM_INTERFACE_LIBRARIES "c++" "c++abi")
                else()
                    list(APPEND _PDFIUM_INTERFACE_LIBRARIES "stdc++")
                endif()
            endif()
        endif()
    elseif(WIN32 AND PDFIUM_LIBRARY MATCHES "\\.lib$")
        set_target_properties(PDFIUM::pdfium PROPERTIES
            IMPORTED_LINK_INTERFACE_LANGUAGES "CXX")

        get_filename_component(_PDFIUM_LIBDIR "${PDFIUM_LIBRARY}" DIRECTORY)
        set(_PDFIUM_EXTRA_LIBRARY_SEARCH_DIRS "${_PDFIUM_LIBDIR}")
        if(PDFIUM_ROOT)
            list(APPEND _PDFIUM_EXTRA_LIBRARY_SEARCH_DIRS
                "${PDFIUM_ROOT}/lib"
                "${PDFIUM_ROOT}/lib64"
                "${PDFIUM_ROOT}/bin")
        elseif(DEFINED ENV{PDFIUM_ROOT})
            list(APPEND _PDFIUM_EXTRA_LIBRARY_SEARCH_DIRS
                "$ENV{PDFIUM_ROOT}/lib"
                "$ENV{PDFIUM_ROOT}/lib64"
                "$ENV{PDFIUM_ROOT}/bin")
        endif()
        if(PDFIUM_EXTRA_LIBRARY_DIRS)
            list(APPEND _PDFIUM_EXTRA_LIBRARY_SEARCH_DIRS ${PDFIUM_EXTRA_LIBRARY_DIRS})
        endif()

        foreach(_PDFIUM_CXX_LIBRARY_FILE IN ITEMS
                "libc++.lib"
                "c++.lib"
                "libc++_static.lib"
                "c++_static.lib"
                "libc++abi.lib"
                "c++abi.lib"
                "libc++abi_static.lib"
                "c++abi_static.lib"
                "libcxx.lib"
                "cxx.lib"
                "libcxx_static.lib"
                "cxx_static.lib"
                "libcxxabi.lib"
                "cxxabi.lib"
                "libcxxabi_static.lib"
                "cxxabi_static.lib"
                "libunwind.lib"
                "unwind.lib"
                "unwind_static.lib")
            foreach(_PDFIUM_EXTRA_LIBRARY_SEARCH_DIR IN LISTS _PDFIUM_EXTRA_LIBRARY_SEARCH_DIRS)
                set(_PDFIUM_CXX_LIBRARY "${_PDFIUM_EXTRA_LIBRARY_SEARCH_DIR}/${_PDFIUM_CXX_LIBRARY_FILE}")
                if(EXISTS "${_PDFIUM_CXX_LIBRARY}")
                    list(APPEND PDFIUM_EXTRA_LIBRARIES "${_PDFIUM_CXX_LIBRARY}")
                endif()
            endforeach()
        endforeach()

        foreach(_PDFIUM_CXX_LIBRARY_NAME IN ITEMS
                "libc++" "c++" "libc++_static" "c++_static"
                "libc++abi" "c++abi" "libc++abi_static" "c++abi_static"
                "libcxx"
                "cxx"
                "libcxx_static"
                "cxx_static"
                "libcxxabi"
                "cxxabi"
                "libcxxabi_static"
                "cxxabi_static"
                "libunwind"
                "unwind"
                "unwind_static")
            unset(_PDFIUM_CXX_LIBRARY CACHE)
            unset(_PDFIUM_CXX_LIBRARY)
            find_library(_PDFIUM_CXX_LIBRARY
                NAMES "${_PDFIUM_CXX_LIBRARY_NAME}"
                HINTS ${_PDFIUM_EXTRA_LIBRARY_SEARCH_DIRS}
                NO_DEFAULT_PATH)
            if(_PDFIUM_CXX_LIBRARY)
                list(APPEND PDFIUM_EXTRA_LIBRARIES "${_PDFIUM_CXX_LIBRARY}")
            endif()
        endforeach()

        list(APPEND PDFIUM_EXTRA_LIBRARIES
            gdi32
            user32)
    endif()

    if(PDFIUM_EXTRA_LIBRARIES)
        list(REMOVE_DUPLICATES PDFIUM_EXTRA_LIBRARIES)
        list(APPEND _PDFIUM_INTERFACE_LIBRARIES ${PDFIUM_EXTRA_LIBRARIES})
    endif()

    if(_PDFIUM_INTERFACE_LIBRARIES)
        list(REMOVE_DUPLICATES _PDFIUM_INTERFACE_LIBRARIES)
        set_target_properties(PDFIUM::pdfium PROPERTIES
            INTERFACE_LINK_LIBRARIES "${_PDFIUM_INTERFACE_LIBRARIES}")
    endif()

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
        if(PDFIUM_EXTRA_LIBRARIES)
            message(STATUS "PDFium extra libraries: ${PDFIUM_EXTRA_LIBRARIES}")
        endif()
        if(PDFIUM_INCLUDE_DIR)
            message(STATUS "PDFium include dir: ${PDFIUM_INCLUDE_DIR}")
        endif()
    endif()
endif()

#[=======================================================================[.rst:
FindLibUnrar
------------

Finds the RARLab UnRAR library and the public DLL API header ``dll.hpp``.

Imported Targets
^^^^^^^^^^^^^^^^

``ClamAV::libunrar``
  The UnRAR library (shared, or the only one available).
``ClamAV::libunrar_static``
  The UnRAR static archive when found, otherwise the same library as
  ``ClamAV::libunrar``.

Both targets carry the ``UNRAR_EXTERNAL`` compile definition, which tells
``libclamunrar_iface`` that it should expect an external library to be present.

Result Variables
^^^^^^^^^^^^^^^^

``LibUnrar_FOUND``
  True if the system has libunrar and its header.
``LibUnrar_INCLUDE_DIRS``
  Include directories needed to use libunrar.
``LibUnrar_LIBRARIES``
  Libraries needed to link to libunrar.

Cache Variables
^^^^^^^^^^^^^^^

``LIBUNRAR_INCLUDE_DIR``
  The directory containing ``dll.hpp``.
``LIBUNRAR_LIBRARY``
  The path to the libunrar library.
``LIBUNRAR_STATIC_LIBRARY``
  The path to ``libunrar.a``, if one is installed.
#]=======================================================================]

find_path(LIBUNRAR_INCLUDE_DIR
  NAMES dll.hpp
  PATH_SUFFIXES unrar UnRAR
)

find_library(LIBUNRAR_LIBRARY
  NAMES unrar
)

# Find the static archive separately so that static ClamAV builds can use it
# as well. If none is installed, fall back to the library found above.
set(_LibUnrar_saved_suffixes "${CMAKE_FIND_LIBRARY_SUFFIXES}")
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
find_library(LIBUNRAR_STATIC_LIBRARY
  NAMES unrar
)
set(CMAKE_FIND_LIBRARY_SUFFIXES "${_LibUnrar_saved_suffixes}")
unset(_LibUnrar_saved_suffixes)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibUnrar
  FOUND_VAR LibUnrar_FOUND
  REQUIRED_VARS
    LIBUNRAR_LIBRARY
    LIBUNRAR_INCLUDE_DIR
)

if(LibUnrar_FOUND)
  set(LibUnrar_INCLUDE_DIRS "${LIBUNRAR_INCLUDE_DIR}")
  set(LibUnrar_LIBRARIES "${LIBUNRAR_LIBRARY}")

  if(NOT LIBUNRAR_STATIC_LIBRARY)
    set(LIBUNRAR_STATIC_LIBRARY "${LIBUNRAR_LIBRARY}")
  endif()

  if(NOT TARGET ClamAV::libunrar)
    add_library(ClamAV::libunrar UNKNOWN IMPORTED)
    set_target_properties(ClamAV::libunrar PROPERTIES
      IMPORTED_LOCATION "${LIBUNRAR_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES "${LIBUNRAR_INCLUDE_DIR}"
      INTERFACE_COMPILE_DEFINITIONS "UNRAR_EXTERNAL"
    )
  endif()

  if(NOT TARGET ClamAV::libunrar_static)
    add_library(ClamAV::libunrar_static UNKNOWN IMPORTED)
    set_target_properties(ClamAV::libunrar_static PROPERTIES
      IMPORTED_LOCATION "${LIBUNRAR_STATIC_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES "${LIBUNRAR_INCLUDE_DIR}"
      INTERFACE_COMPILE_DEFINITIONS "UNRAR_EXTERNAL"
    )
  endif()
endif()

mark_as_advanced(
  LIBUNRAR_INCLUDE_DIR
  LIBUNRAR_LIBRARY
  LIBUNRAR_STATIC_LIBRARY
)

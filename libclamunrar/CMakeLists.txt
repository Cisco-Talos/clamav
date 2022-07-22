
cmake_minimum_required( VERSION 3.13 )

add_compile_definitions(RARDLL)
add_compile_definitions(WARN_DLOPEN_FAIL)
add_compile_definitions(_FILE_OFFSET_BITS=64)

if(WIN32)
	add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
endif()

# unrar object
add_library( unrar_obj OBJECT )
target_sources( unrar_obj
    PRIVATE
	    "archive.cpp"
	    "arcread.cpp"
	    "blake2s.cpp"
	    "cmddata.cpp"
	    "consio.cpp"
	    "crc.cpp"
	    "crypt.cpp"
	    "dll.cpp"
	    "encname.cpp"
	    "errhnd.cpp"
	    "extinfo.cpp"
	    "extract.cpp"
	    "filcreat.cpp"
	    "file.cpp"
	    "filefn.cpp"
	    "filestr.cpp"
	    "find.cpp"
	    "getbits.cpp"
	    "global.cpp"
	    "hash.cpp"
	    "headers.cpp"
	    "list.cpp"
	    "match.cpp"
	    "options.cpp"
	    "pathfn.cpp"
	    "qopen.cpp"
	    "rar.cpp"
	    "rarvm.cpp"
	    "rawread.cpp"
	    "rdwrfn.cpp"
	    "recvol.cpp"
	    "resource.cpp"
	    "rijndael.cpp"
	    "rs.cpp"
	    "rs16.cpp"
	    "scantree.cpp"
	    "secpassword.cpp"
	    "sha1.cpp"
	    "sha256.cpp"
	    "smallfn.cpp"
	    "strfn.cpp"
	    "strlist.cpp"
	    "system.cpp"
	    "threadpool.cpp"
	    "timefn.cpp"
	    "ui.cpp"
	    "unicode.cpp"
	    "unpack.cpp"
	    "volume.cpp" )
target_include_directories( unrar_obj
    PRIVATE "${CMAKE_BINARY_DIR}"
	PUBLIC  "${CMAKE_CURRENT_SOURCE_DIR}" )

if(NOT WIN32)
	set_target_properties( unrar_obj PROPERTIES
		COMPILE_FLAGS "-Wno-logical-op-parentheses -Wno-switch -Wno-dangling-else")
endif()

# The unrar shared library.
add_library( clamunrar SHARED )
set_target_properties(clamunrar PROPERTIES
    VERSION "5.7.5"
    SOVERSION 5)
target_sources( clamunrar
    PUBLIC
        "rar.hpp"
        "dll.hpp" )
if(WIN32)
    set_target_properties(clamunrar PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()

# Public (forwarded) dependencies.
target_link_libraries( clamunrar
    PUBLIC
        unrar_obj )

if(WIN32)
    install(TARGETS clamunrar DESTINATION ${CMAKE_INSTALL_PREFIX})
else()
    install(TARGETS clamunrar DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif()

add_library( ClamAV::libclamunrar ALIAS clamunrar )

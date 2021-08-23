#
# libclamav features written in Rust
#

# libclamav rust static library
add_rust_library(TARGET clamav_rust WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
if (WIN32)
    target_link_libraries(clamav_rust PUBLIC Userenv)
endif()
add_library(ClamAV::libclamav_rust ALIAS clamav_rust)

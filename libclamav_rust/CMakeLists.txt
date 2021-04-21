#
# libclamav features written in Rust
#

# libclamav rust static library
add_rust_library(TARGET clamav_rust WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
add_library(ClamAV::libclamav_rust ALIAS clamav_rust)

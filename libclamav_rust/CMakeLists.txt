#
# Rust common libs for ClamAV apps
#

# rdiff Rust replacement for cdiff
add_rust_library(TARGET cdiff WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/cdiff")
add_library(ClamAV::cdiff ALIAS cdiff)

#
# clamav certs directory and root CA cert
#

# Create the certs directory. This is where the root CA cert will be installed.
# Then copy the root CA cert to the certs directory.
install(DIRECTORY DESTINATION ${CVD_CERTS_DIRECTORY} COMPONENT programs)
install(
    FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/clamav.crt
    DESTINATION
        ${CVD_CERTS_DIRECTORY}
    COMPONENT programs)

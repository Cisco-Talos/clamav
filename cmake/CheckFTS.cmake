#
# Check for struct packing features
# This feature reworked from m4/reorganization/code_checks/compiler_attribs.m4
#

GET_FILENAME_COMPONENT(_selfdir_CheckFTS
    "${CMAKE_CURRENT_LIST_FILE}" PATH)

# Check if __attribute__((packed)) is available
check_c_source_compiles(
    "
    #include <fts.h>

    int main(void) {
        fts_open((void *)0, FTS_PHYSICAL, (void *)0);

        return 0;
    }
    "
    HAVE_SYSTEM_LFS_FTS )

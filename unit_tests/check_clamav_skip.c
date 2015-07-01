#include <stdio.h>
#include "../libclamav/clamav.h"

int main(int argc, char **argv)
{
    UNUSEDPARAM(argc);
    UNUSEDPARAM(argv);
    puts("\n*** Unit tests disabled in this build\n*** Use ./configure --enable-check to enable them\n");
    /* tell automake the test was skipped */
    return 77;
}

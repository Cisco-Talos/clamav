#include <malloc.h>

int main()
{
    struct mallinfo mi;
    mi = mallinfo();
    return 0;
}

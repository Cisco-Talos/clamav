#include <sys/utsname.h>
int main()
{
    struct utsname unm;
    return uname(&unm);
}

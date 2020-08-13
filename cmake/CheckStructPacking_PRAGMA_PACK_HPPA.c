/* hppa/hp-ux wants pragma outside of function */
#pragma pack 1 /* has to be in column 1 ! */
struct {
    char c;
    long l;
} s;
int main(int argc, char **argv)
{
    return sizeof(s) == sizeof(s.c) + sizeof(s.l) ? 0 : 1;
}

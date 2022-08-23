#include <stdio.h>
#include "extract.h"
#ifdef _WIN32
#include <tlhelp32.h>
#include <winreg.h>
#else
#include <time.h>
#endif

int main(int argc, char **argv)
{
    DROP_AND_EXECUTE()

    printf("%s\n", "CLAMAV_TEST_PRINTF_STRING_" INDICATOR1);
    printf("%s\n", "CLAMAV_TEST_PRINTF_STRING_" INDICATOR2);

    // Do some random stuff to change the .imp hashes and .text MDB/MSB hashes
    // To change the .imp hash (Windows-specific) we actually need to make
    // the exe import new functions, so we need to call interesting APIs.
    //
    // On Linux, we just need to make sure the assembly in the .text section
    // is different
#if INDEX == 1
#ifdef _WIN32

    printf("Enumerating Modules via CreateToolhelp32Snapshot\n");
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (INVALID_HANDLE_VALUE == h) {
        return 1;
    }
    MODULEENTRY32 m;
    if (!Module32First(h, &m)) {
        CloseHandle(h);
        return 1;
    }
    do {
        printf(" - %s\n", m.szModule);
    } while (Module32Next(h, &m));
    CloseHandle(h);

#else

    printf("Listing program name\n - %s\n", argv[0]);

#endif

#elif INDEX == 2
#ifdef _WIN32

    printf("Enumerating Keys in HKEY_CURRENT_USER\n");
    char key[256];
    int index = 0;
    if (ERROR_SUCCESS != RegEnumKeyA(HKEY_CURRENT_USER, index++, (char *)&key, sizeof(key))) {
        return 1;
    }
    do {
        printf(" - %s\n", key);
    } while (ERROR_SUCCESS == RegEnumKeyA(HKEY_CURRENT_USER, index++, (char *)&key, sizeof(key)));

#else

    printf("Listing current time\n - %d\n", (int)time(NULL));

#endif

#else

    printf("Nothing to do!\n");

#endif

    return 0;
}

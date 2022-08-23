#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#ifdef _WIN32
#include <windows.h>
#else
#define O_BINARY 0
#include <sys/wait.h>
#endif

#define DO1(X) X(1)
#define DO2(X) DO1(X) X(2)
#define DO3(X) DO2(X) X(3)
#define DO4(X) DO3(X) X(4)
#define DO5(X) DO4(X) X(5)
#define DO6(X) DO5(X) X(6)
#define DO7(X) DO6(X) X(7)
#define DO8(X) DO7(X) X(8)
#define DO9(X) DO8(X) X(9)
#define DO10(X) DO9(X) X(10)
#define DO11(X) DO10(X) X(11)
#define DO12(X) DO11(X) X(12)
#define DO13(X) DO12(X) X(13)
#define DO14(X) DO13(X) X(14)
#define DO15(X) DO14(X) X(15)
#define DO16(X) DO15(X) X(16)
#define DO17(X) DO16(X) X(17)
#define DO18(X) DO17(X) X(18)
#define DO19(X) DO18(X) X(19)
#define DO20(X) DO19(X) X(20)
#define DO21(X) DO20(X) X(21)
#define DO22(X) DO21(X) X(22)
#define DO23(X) DO22(X) X(23)
#define DO24(X) DO23(X) X(24)
#define DO25(X) DO24(X) X(25)
#define DO26(X) DO25(X) X(26)
#define DO27(X) DO26(X) X(27)
#define DO28(X) DO27(X) X(28)
#define DO29(X) DO28(X) X(29)
#define DO30(X) DO29(X) X(30)
#define DO31(X) DO30(X) X(31)
#define DO32(X) DO31(X) X(32)

#define DO(NUMBER, X) \
    DO##NUMBER(X)

// The following works for GCC producing ELFs, but not with mingw-w64
// producing Windows PEs:
//     extern const char __attribute__((weak)) _binary_exe ## index ## _start[0];
// Luckily using weakref instead works for both, albeit with the difference in
// whether an underscore is prepended.
//
// These symbols will correspond with embedded EXE object files that we create
// with `ld -r -b binary` and then link with.

#ifdef __MINGW32__
#define DEFINE(index)                                                                                      \
    static const char __attribute__((weakref, alias("binary_exe" #index "_start"))) exe##index##_start[0]; \
    static const char __attribute__((weakref, alias("binary_exe" #index "_end"))) exe##index##_end[0];
#else
#define DEFINE(index)                                                                                       \
    static const char __attribute__((weakref, alias("_binary_exe" #index "_start"))) exe##index##_start[0]; \
    static const char __attribute__((weakref, alias("_binary_exe" #index "_end"))) exe##index##_end[0];
#endif

DO(32, DEFINE)

void exec_in_new_process(const char *filename)
{

#ifdef _WIN32
    PROCESS_INFORMATION pi = {0};
    STARTUPINFO si         = {0};
    si.cb                  = sizeof(si);
    BOOL result            = CreateProcess(NULL, (char *)filename, NULL, NULL, TRUE,
                                           NORMAL_PRIORITY_CLASS, NULL, NULL,
                                           &si, &pi);
    if (result) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
#else
    pid_t pid = fork();
    if (0 == pid) {
        char *const args[2] = {(char *)filename, NULL};
        execv(filename, args);
        exit(1);
    } else {
        waitpid(pid, NULL, 0);
    }
#endif
}

#define EXTRACT_EXECUTE_DELETE(index)                                                                      \
    do {                                                                                                   \
        size_t size = exe##index##_end - exe##index##_start;                                               \
        if (!size) break;                                                                                  \
        printf("Extracting file with size %zd\n", size);                                                   \
        /* Linux doesn't care if there is a file extension, but Windows does */                            \
        const char *filename = "exe" #index ".exe";                                                        \
        int fd               = open(filename, O_WRONLY | O_CREAT | O_BINARY, S_IRWXU | S_IRWXG | S_IRWXO); \
        if (-1 == fd) {                                                                                    \
            perror("open");                                                                                \
            break;                                                                                         \
        }                                                                                                  \
        int pos = 0;                                                                                       \
        while (pos < size) {                                                                               \
            int written = write(fd, exe##index##_start + pos, size - pos);                                 \
            if (-1 == written) {                                                                           \
                perror("write");                                                                           \
                break;                                                                                     \
            }                                                                                              \
            pos += written;                                                                                \
        }                                                                                                  \
        close(fd);                                                                                         \
        if (pos == size) {                                                                                 \
            exec_in_new_process(filename);                                                                 \
        }                                                                                                  \
        unlink(filename);                                                                                  \
        printf("Finished extracting and executing\n");                                                     \
    } while (0);

#define DROP_AND_EXECUTE() \
    DO(32, EXTRACT_EXECUTE_DELETE)

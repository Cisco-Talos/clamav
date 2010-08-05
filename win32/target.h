#ifndef TARGET_OS_TYPE
#define TARGET_OS_TYPE "win32"
#endif

#ifndef TARGET_ARCH_TYPE
#ifdef _WIN64
#define TARGET_ARCH_TYPE "x86_64"
#else
#define TARGET_ARCH_TYPE "i386"
#endif
#endif

#ifndef TARGET_CPU_TYPE
#define TARGET_CPU_TYPE TARGET_ARCH_TYPE
#endif

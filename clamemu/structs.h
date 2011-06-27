#ifndef STRUCTS_H
#define STRUCTS_H

#include <stdint.h>

#ifdef _WIN32
/* ugly hack: avoid including windows.h, we should probably just rename all the structs/types
in this file as to not conflict with windows.h, by prefixing them with EMU_ */
#define _WINDOWS_
#define _WINSOCK2API_
#define _WS2TCPIP_H_
#define __W32_ERRNO_H
#define __NET_H
#define NOPAGESIZE
typedef int ssize_t;
#define TRUE 1
#define FALSE 0
int _stdcall lstrcmpiA(LPCSTR, LPCSTR);
//#error "TODO: figure out how to make this work on win32, we obviously can't include both this header file and"
       ////"original windows headers because pointer sizes will be different (on win64 at least)"
#endif

typedef uint64_t UINT64;
typedef int64_t INT64;
typedef uint32_t DWORD, ULONG;
typedef int32_t LONG;
typedef uint16_t WORD, USHORT;
typedef uint16_t WCHAR;
typedef uint8_t BYTE, UCHAR;
typedef UINT64 ULONGLONG;
typedef INT64 LONGLONG;
typedef BYTE BOOLEAN;

typedef union _LARGE_INTEGER {
    struct {
        DWORD    LowPart;
        LONG     HighPart;
    } u;
    LONGLONG QuadPart;
} LARGE_INTEGER;

typedef union _ULARGE_INTEGER {
    struct {
        DWORD    LowPart;
        DWORD    HighPart;
    } u;
    ULONGLONG QuadPart;
} ULARGE_INTEGER;

/* 32-bit pointers, don't make these real pointers or it won't work on 64-bit */
/* all the types must be exactly the same as on 32-bit win32, even if we run on
 * 64-bit OS */
typedef uint32_t PVOID, HANDLE, PPEB_LDR_DATA, PLIST_ENTRY,
	PRTL_USER_PROCESS_PARAMETERS, PRTL_CRITICAL_SECTION, PRTL_BITMAP,
	ULONG_PTR, PUNICODE_STRING, PULONG, PWSTR, PRTL_CRITICAL_SECTION_DEBUG,
	PNT_TIB, PKUSER_SHARED_DATA, LogModuleFunc, PACTIVATION_CONTEXT,
	PACTIVATION_CONTEXT_STACK, PRTL_ACTIVATION_CONTEXT_STACK_FRAME, PPEB,
	PTEB, PEXCEPTION_REGISTRATION_RECORD;
typedef ULONG_PTR HMODULE, SIZE_T;

/* No pointers allowed in this header, replace them with a P*, they
 * must be 32-bit addresses, read through our vmm */
typedef struct {
    uint32_t ExceptionCode;
    uint32_t ExceptionFlags;
    uint32_t ExceptionRecord;
    uint32_t ExceptionAddress;
    uint32_t NumberParameters;
    uint32_t ExceptionInformation[15];
} EXCEPTION_REGISTRATION_RECORD;

typedef struct _FLOATING_SAVE_AREA {
	DWORD	ControlWord;
	DWORD	StatusWord;
	DWORD	TagWord;
	DWORD	ErrorOffset;
	DWORD	ErrorSelector;
	DWORD	DataOffset;
	DWORD	DataSelector;
	BYTE	RegisterArea[80];
	DWORD	Cr0NpxState;
} FLOATING_SAVE_AREA;

typedef struct _CONTEXT {
	DWORD	ContextFlags;
	DWORD	Dr0;
	DWORD	Dr1;
	DWORD	Dr2;
	DWORD	Dr3;
	DWORD	Dr6;
	DWORD	Dr7;
	FLOATING_SAVE_AREA FloatSave;
	DWORD	SegGs;
	DWORD	SegFs;
	DWORD	SegEs;
	DWORD	SegDs;
	DWORD	Edi;
	DWORD	Esi;
	DWORD	Ebx;
	DWORD	Edx;
	DWORD	Ecx;
	DWORD	Eax;
	DWORD	Ebp;
	DWORD	Eip;
	DWORD	SegCs;
	DWORD	EFlags;
	DWORD	Esp;
	DWORD	SegSs;
	BYTE	ExtendedRegisters[512];
} CONTEXT;

struct IMAGE_IMPORT {
    uint32_t OrigThunk;
    uint32_t Time;
    uint32_t Fwd;
    uint32_t DllName;
    uint32_t Thunk;
};

typedef struct _LIST_ENTRY {
  PLIST_ENTRY Flink;
  PLIST_ENTRY Blink;
} LIST_ENTRY;

typedef struct _PEB_LDR_DATA
{
    ULONG               Length;
    BOOLEAN             Initialized;
    PVOID               SsHandle;
    LIST_ENTRY          InLoadOrderModuleList;
    LIST_ENTRY          InMemoryOrderModuleList;
    LIST_ENTRY          InInitializationOrderModuleList;
} PEB_LDR_DATA;

typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    PVOID Handle;
} CURDIR;

typedef struct RTL_DRIVE_LETTER_CURDIR
{
    USHORT              Flags;
    USHORT              Length;
    ULONG               TimeStamp;
    UNICODE_STRING      DosPath;
} RTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_CRITICAL_SECTION_DEBUG
{
  WORD   Type;
  WORD   CreatorBackTraceIndex;
  PRTL_CRITICAL_SECTION CriticalSection;
  LIST_ENTRY ProcessLocksList;
  DWORD EntryCount;
  DWORD ContentionCount;
  DWORD Spare[ 2 ];
} RTL_CRITICAL_SECTION_DEBUG;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG               AllocationSize;
    ULONG               Size;
    ULONG               Flags;
    ULONG               DebugFlags;
    HANDLE              ConsoleHandle;
    ULONG               ConsoleFlags;
    HANDLE              hStdInput;
    HANDLE              hStdOutput;
    HANDLE              hStdError;
    CURDIR              CurrentDirectory;
    UNICODE_STRING      DllPath;
    UNICODE_STRING      ImagePathName;
    UNICODE_STRING      CommandLine;
    PWSTR               Environment;
    ULONG               dwX;
    ULONG               dwY;
    ULONG               dwXSize;
    ULONG               dwYSize;
    ULONG               dwXCountChars;
    ULONG               dwYCountChars;
    ULONG               dwFillAttribute;
    ULONG               dwFlags;
    ULONG               wShowWindow;
    UNICODE_STRING      WindowTitle;
    UNICODE_STRING      Desktop;
    UNICODE_STRING      ShellInfo;
    UNICODE_STRING      RuntimeInfo;
    RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[32];
} RTL_USER_PROCESS_PARAMETERS;

typedef struct _RTL_CRITICAL_SECTION {
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore;
    ULONG_PTR SpinCount;
}  RTL_CRITICAL_SECTION;

typedef struct tagRTL_BITMAP {
    ULONG  SizeOfBitMap;
    PULONG Buffer;
} RTL_BITMAP;

typedef struct _PEB
{
    BOOLEAN                      InheritedAddressSpace;
    BOOLEAN                      ReadImageFileExecOptions;
    BOOLEAN                      BeingDebugged;
    union
    {
        BYTE BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages:1;
            BOOLEAN SpareBits:7;
        };
    };
    HANDLE                       Mutant;
    HMODULE                      ImageBaseAddress;
    PPEB_LDR_DATA                LdrData;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID                        SubSystemData;
    HANDLE                       ProcessHeap;
    PRTL_CRITICAL_SECTION        FastPebLock;
    PVOID                        AtlThunkSListPtr;
    PVOID                        SparePtr2;
    ULONG                        EnvironmentUpdateCount;
    PVOID                        KernelCallbackTable;
    ULONG                        Reserved[2];
    PVOID /*PPEB_FREE_BLOCK*/    FreeList;
    ULONG                        TlsExpansionCounter;
    PRTL_BITMAP                  TlsBitmap;
    ULONG                        TlsBitmapBits[2];

    PVOID                        ReadOnlySharedMemoryBase;
    PVOID                        ReadOnlySharedMemoryHeap;
    PVOID                        ReadOnlyStaticServerData;
    PVOID                        AnsiCodePageData;
    PVOID                        OemCodePageData;
    PVOID                        UnicodeCaseTableData;
    ULONG                        NumberOfProcessors;
    ULONG                        NtGlobalFlag;
    LARGE_INTEGER                CriticalSectionTimeout;
    SIZE_T                       HeapSegmentReserve;
    SIZE_T                       HeapSegmentCommit;
    SIZE_T                       HeapDeCommitTotalFreeThreshold;
    SIZE_T                       HeapDeCommitFreeBlockThreshold;
    ULONG                        NumberOfHeaps;
    ULONG                        MaximumNumberOfHeaps;
    PVOID                        ProcessHeaps;
    PVOID                        GdiSharedHandleTable;
    PVOID                        ProcessStarterHelper;
    PVOID                        GdiDCAttributeList;
    PRTL_CRITICAL_SECTION        LoaderLock;
    ULONG                        OSMajorVersion;
    ULONG                        OSMinorVersion;
    USHORT                       OSBuildNumber;
    USHORT                       OSCSDVersion;
    ULONG                        OSPlatformId;
    ULONG                        ImageSubSystem;
    ULONG                        ImageSubSystemMajorVersion;
    ULONG                        ImageSubSystemMinorVersion;
    ULONG_PTR                    ImageProcessAffinityMask;
    HANDLE                       GdiHandleBuffer[34];
    PVOID                        PostProcessInitRoutine;
    PRTL_BITMAP                  TlsExpansionBitmap;
    ULONG                        TlsExpansionBitmapBits[32];
    ULONG                        SessionId;
    ULARGE_INTEGER               AppCompatFlags;
    ULARGE_INTEGER               AppCompatFlagsUser;
    PVOID                        ShimData;
    PVOID                        AppCompatInfo;
    UNICODE_STRING               CSDVersion;
    PVOID                        ActivationContextData;
    PVOID                        ProcessAssemblyStorageMap;
    PVOID                        SystemDefaultActivationData;
    PVOID                        SystemAssemblyStorageMap;
    SIZE_T                       MinimumStackCommit;
    PVOID                        FlsCallback;
    LIST_ENTRY                   FlsListHead;
    PRTL_BITMAP                  FlsBitmap;
    ULONG                        FlsBitmapBits[4];
    ULONG                        FlsHighIndex;
} PEB;

typedef struct _NT_TIB
{
     PEXCEPTION_REGISTRATION_RECORD ExceptionList;
     PVOID StackBase;
     PVOID StackLimit;
     PVOID SubSystemTib;
     union
     {
          PVOID FiberData;
          ULONG Version;
     };
     PVOID ArbitraryUserPointer;
     PNT_TIB Self;
} NT_TIB;

typedef struct _CLIENT_ID
{
   HANDLE UniqueProcess;
   HANDLE UniqueThread;
} CLIENT_ID;

typedef struct _KSYSTEM_TIME
{
     ULONG LowPart;
     LONG High1Time;
     LONG High2Time;
} KSYSTEM_TIME;

typedef enum _NT_PRODUCT_TYPE
{
    NtProductWinNt      = 1,
    NtProductLanManNt   = 2,
    NtProductServer     = 3
} NT_PRODUCT_TYPE;

typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE
{
    StandardDesign = 0,
    NEC98x86 = 1,
    EndAlternatives = 2
} ALTERNATIVE_ARCHITECTURE_TYPE;

typedef struct _KUSER_SHARED_DATA
{
    ULONG TickCountLowDeprecated;
    ULONG TickCountMultiplier;
    volatile KSYSTEM_TIME InterruptTime;
    volatile KSYSTEM_TIME SystemTime;
    volatile KSYSTEM_TIME TimeZoneBias;
    WORD ImageNumberLow;
    WORD ImageNumberHigh;
    WCHAR NtSystemRoot[260];
    ULONG MaxStackTraceDepth;
    ULONG CryptoExponent;
    ULONG TimeZoneId;
    ULONG LargePageMinimum;
    ULONG Reserved2[7];
    NT_PRODUCT_TYPE NtProductType;
    UCHAR ProductTypeIsValid;
    ULONG NtMajorVersion;
    ULONG NtMinorVersion;
    UCHAR ProcessorFeatures[64];
    ULONG Reserved1;
    ULONG Reserved3;
    ULONG TimeSlip;
    ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;
    LARGE_INTEGER SystemExpirationDate;
    ULONG SuiteMask;
    UCHAR KdDebuggerEnabled;
    ULONG ActiveConsoleId;
    ULONG DismountCount;
    ULONG ComPlusPackage;
    ULONG LastSystemRITEventTickCount;
    ULONG NumberOfPhysicalPages;
    UCHAR SafeBootMode;
    ULONG TraceLogging;
    UINT64 TestRetInstruction;
    ULONG SystemCall;
    ULONG SystemCallReturn;
    UINT64 SystemCallPad[3];
    union
    {
        struct _KSYSTEM_TIME TickCount;
        UINT64 TickCountQuad;
    };
    ULONG   Cookie;
    ULONG Wow64SharedInformation[16];
} KUSER_SHARED_DATA;

typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME
{
    PRTL_ACTIVATION_CONTEXT_STACK_FRAME Previous;
    PACTIVATION_CONTEXT                 ActivationContext;
    ULONG                               Flags;
} RTL_ACTIVATION_CONTEXT_STACK_FRAME;

typedef struct _ACTIVATION_CONTEXT_STACK
{
    ULONG                               Flags;
    ULONG                               NextCookieSequenceNumber;
    PRTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
    LIST_ENTRY                          FrameListCache;
} ACTIVATION_CONTEXT_STACK;

typedef struct _GDI_TEB_BATCH
{
    ULONG  Offset;
    ULONG  HDC;
    ULONG  Buffer[310];
} GDI_TEB_BATCH;

typedef struct _GUID
{
    ULONG Data1;
    WORD Data2;
    WORD Data3;
    UCHAR Data4[8];
} GUID;

typedef struct _TEB {
    NT_TIB                       NtTib;
    PVOID                        EnvironmentPointer;
    CLIENT_ID                    ClientId;
    PVOID                        ActiveRpcHandle;
    PVOID                        ThreadLocalStoragePointer;
    PPEB                         Peb;
    ULONG                        LastErrorValue;
    ULONG                        CountOfOwnedCriticalSections;
    PVOID                        CsrClientThread;
    PVOID                        Win32ThreadInfo;
    ULONG                        User32Reserved[26];                // used for user32 private data in Wine
    PKUSER_SHARED_DATA           SharedUserData;
    LogModuleFunc                LogModule;
    ULONG                        UserReserved[3];                   // was ULONG[5], added SharedUserData and LogModule, beware PVOID vs ULONG*/
    PVOID                        WOW32Reserved;
    ULONG                        CurrentLocale;
    ULONG                        FpSoftwareStatusRegister;
    PVOID                        SystemReserved1[54];               // used for kernel32 private data in Wine
    LONG                         ExceptionCode;
    PACTIVATION_CONTEXT_STACK    ActivationContextStack;
    BYTE                         SpareBytes1[36];
    ULONG                        TxFsContext;
    GDI_TEB_BATCH                GdiTebBatch;
    CLIENT_ID                    RealClientId;
    HANDLE                       GdiCachedProcessHandle;
    ULONG                        GdiClientPID;
    ULONG                        GdiClientTID;
    PVOID                        GdiThreadLocaleInfo;
    ULONG_PTR                    Win32ClientInfo[62];
    PVOID                        glDispachTable[233];
    PVOID                        glReserved1[29];
    PVOID                        glReserved2;
    PVOID                        glSectionInfo;
    PVOID                        glSection;
    PVOID                        glTable;
    PVOID                        glCurrentRC;
    PVOID                        glContext;
    ULONG                        LastStatusValue;
    UNICODE_STRING               StaticUnicodeString;
    WCHAR                        StaticUnicodeBuffer[261];
    PVOID                        DeallocationStack;
    PVOID                        TlsSlots[64];
    LIST_ENTRY                   TlsLinks;
    PVOID                        Vdm;
    PVOID                        ReservedForNtRpc;
    PVOID                        DbgSsReserved[2];
    ULONG                        HardErrorMode;
    PVOID                        Instrumentation[9]; // 14 - guid
    GUID                         ActivityId;
    PVOID                        SubProcessTag;
    PVOID                        EtwLocalData;
    PVOID                        EtwTraceData;
    PVOID                        WinSockData;
    ULONG                        GdiBatchCount;
    BOOLEAN                      InDbgPrint;
    BOOLEAN                      FreeStackOnTermination;
    BOOLEAN                      HasFiberData;
    BOOLEAN                      IdealProcessor;
    ULONG                        GuaranteedStackBytes; // Should be zero
    PVOID                        ReservedForPerfLog;
    PVOID                        ReservedForOle;
    ULONG                        WaitingOnLoaderLock;
    PVOID                        SavedPriorityState;
    PVOID                        SoftPatchPtr1;
    PVOID                        ThreadPoolData;
    PVOID                        TlsExpansionSlots;
    ULONG                        ImpersonationLocale;
    ULONG                        IsImpersonating;
    PVOID                        NlsCache;
    PVOID                        pShimData;
    ULONG                        HeapVirtualAffinity;
    PVOID                        CurrentTransactionHandle;
    PVOID                        ActiveFrame;
    PVOID                        FlsData;
    BOOLEAN                      SafeThunkCall;
    BOOLEAN                      BooleanSpare[3];
} TEB;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    WORD LoadCount;
    WORD TlsIndex;
    PVOID Reserved5[1];
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY;
#define INVALID_HANDLE_VALUE ((HANDLE)-1)
#define PARAMS_ALREADY_NORMALIZED 1
#define HANDLE_HEAP             (HANDLE)(0x1337)
#define DLL_PROCESS_ATTACH 1
#define DLL_THREAD_ATTACH 2
#endif
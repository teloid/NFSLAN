typedef unsigned char   undefined;

typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
float10
typedef unsigned long long    GUID;
typedef pointer32 ImageBaseOffset32;

typedef long long    longlong;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef unsigned short    wchar16;
typedef short    wchar_t;
typedef unsigned short    word;
#define unkbyte9   unsigned long long
#define unkbyte10   unsigned long long
#define unkbyte11   unsigned long long
#define unkbyte12   unsigned long long
#define unkbyte13   unsigned long long
#define unkbyte14   unsigned long long
#define unkbyte15   unsigned long long
#define unkbyte16   unsigned long long

#define unkuint9   unsigned long long
#define unkuint10   unsigned long long
#define unkuint11   unsigned long long
#define unkuint12   unsigned long long
#define unkuint13   unsigned long long
#define unkuint14   unsigned long long
#define unkuint15   unsigned long long
#define unkuint16   unsigned long long

#define unkint9   long long
#define unkint10   long long
#define unkint11   long long
#define unkint12   long long
#define unkint13   long long
#define unkint14   long long
#define unkint15   long long
#define unkint16   long long

#define unkfloat1   float
#define unkfloat2   float
#define unkfloat3   float
#define unkfloat5   double
#define unkfloat6   double
#define unkfloat7   double
#define unkfloat9   long double
#define unkfloat11   long double
#define unkfloat12   long double
#define unkfloat13   long double
#define unkfloat14   long double
#define unkfloat15   long double
#define unkfloat16   long double

#define BADSPACEBASE   void
#define code   void

typedef struct _s_HandlerType _s_HandlerType, *P_s_HandlerType;

typedef struct _s_HandlerType HandlerType;

typedef struct TypeDescriptor TypeDescriptor, *PTypeDescriptor;

typedef int ptrdiff_t;

struct TypeDescriptor {
    void *pVFTable;
    void *spare;
    char name[0];
};

struct _s_HandlerType {
    uint adjectives;
    struct TypeDescriptor *pType;
    ptrdiff_t dispCatchObj;
    void *addressOfHandler;
};

typedef struct _s_TryBlockMapEntry _s_TryBlockMapEntry, *P_s_TryBlockMapEntry;

typedef int __ehstate_t;

struct _s_TryBlockMapEntry {
    __ehstate_t tryLow;
    __ehstate_t tryHigh;
    __ehstate_t catchHigh;
    int nCatches;
    HandlerType *pHandlerArray;
};

typedef struct _s_FuncInfo _s_FuncInfo, *P_s_FuncInfo;

typedef struct _s_UnwindMapEntry _s_UnwindMapEntry, *P_s_UnwindMapEntry;

typedef struct _s_UnwindMapEntry UnwindMapEntry;

typedef struct _s_TryBlockMapEntry TryBlockMapEntry;

struct _s_FuncInfo {
    uint magicNumber_and_bbtFlags;
    __ehstate_t maxState;
    UnwindMapEntry *pUnwindMap;
    uint nTryBlocks;
    TryBlockMapEntry *pTryBlockMap;
    uint nIPMapEntries;
    void *pIPToStateMap;
};

struct _s_UnwindMapEntry {
    __ehstate_t toState;
    void (*action)(void);
};

typedef struct type_info type_info, *Ptype_info;

struct type_info { // PlaceHolder Class Structure
};

typedef struct CLIENT_ID CLIENT_ID, *PCLIENT_ID;

struct CLIENT_ID {
    void *UniqueProcess;
    void *UniqueThread;
};

typedef struct _s_FuncInfo FuncInfo;

typedef struct _cpinfo _cpinfo, *P_cpinfo;

typedef uint UINT;

typedef uchar BYTE;

struct _cpinfo {
    UINT MaxCharSize;
    BYTE DefaultChar[2];
    BYTE LeadByte[12];
};

typedef struct _cpinfo *LPCPINFO;

typedef ulong DWORD;

typedef DWORD LCTYPE;

typedef struct _SYSTEM_INFO _SYSTEM_INFO, *P_SYSTEM_INFO;

typedef struct _SYSTEM_INFO *LPSYSTEM_INFO;

typedef union _union_530 _union_530, *P_union_530;

typedef void *LPVOID;

typedef ulong ULONG_PTR;

typedef ULONG_PTR DWORD_PTR;

typedef ushort WORD;

typedef struct _struct_531 _struct_531, *P_struct_531;

struct _struct_531 {
    WORD wProcessorArchitecture;
    WORD wReserved;
};

union _union_530 {
    DWORD dwOemId;
    struct _struct_531 s;
};

struct _SYSTEM_INFO {
    union _union_530 u;
    DWORD dwPageSize;
    LPVOID lpMinimumApplicationAddress;
    LPVOID lpMaximumApplicationAddress;
    DWORD_PTR dwActiveProcessorMask;
    DWORD dwNumberOfProcessors;
    DWORD dwProcessorType;
    DWORD dwAllocationGranularity;
    WORD wProcessorLevel;
    WORD wProcessorRevision;
};

typedef struct _OVERLAPPED _OVERLAPPED, *P_OVERLAPPED;

typedef union _union_518 _union_518, *P_union_518;

typedef void *HANDLE;

typedef struct _struct_519 _struct_519, *P_struct_519;

typedef void *PVOID;

struct _struct_519 {
    DWORD Offset;
    DWORD OffsetHigh;
};

union _union_518 {
    struct _struct_519 s;
    PVOID Pointer;
};

struct _OVERLAPPED {
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    union _union_518 u;
    HANDLE hEvent;
};

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef int BOOL;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef struct _TIME_ZONE_INFORMATION _TIME_ZONE_INFORMATION, *P_TIME_ZONE_INFORMATION;

typedef struct _TIME_ZONE_INFORMATION *LPTIME_ZONE_INFORMATION;

typedef long LONG;

typedef wchar_t WCHAR;

typedef struct _SYSTEMTIME _SYSTEMTIME, *P_SYSTEMTIME;

typedef struct _SYSTEMTIME SYSTEMTIME;

struct _SYSTEMTIME {
    WORD wYear;
    WORD wMonth;
    WORD wDayOfWeek;
    WORD wDay;
    WORD wHour;
    WORD wMinute;
    WORD wSecond;
    WORD wMilliseconds;
};

struct _TIME_ZONE_INFORMATION {
    LONG Bias;
    WCHAR StandardName[32];
    SYSTEMTIME StandardDate;
    LONG StandardBias;
    WCHAR DaylightName[32];
    SYSTEMTIME DaylightDate;
    LONG DaylightBias;
};

typedef struct _WIN32_FIND_DATAA _WIN32_FIND_DATAA, *P_WIN32_FIND_DATAA;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME FILETIME;

typedef char CHAR;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

struct _WIN32_FIND_DATAA {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD dwReserved0;
    DWORD dwReserved1;
    CHAR cFileName[260];
    CHAR cAlternateFileName[14];
};

typedef DWORD (*PTHREAD_START_ROUTINE)(LPVOID);

typedef PTHREAD_START_ROUTINE LPTHREAD_START_ROUTINE;

typedef struct _OVERLAPPED *LPOVERLAPPED;

typedef struct _SECURITY_ATTRIBUTES *LPSECURITY_ATTRIBUTES;

typedef struct _STARTUPINFOA _STARTUPINFOA, *P_STARTUPINFOA;

typedef CHAR *LPSTR;

typedef BYTE *LPBYTE;

struct _STARTUPINFOA {
    DWORD cb;
    LPSTR lpReserved;
    LPSTR lpDesktop;
    LPSTR lpTitle;
    DWORD dwX;
    DWORD dwY;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwXCountChars;
    DWORD dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD wShowWindow;
    WORD cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
};

typedef struct _WIN32_FIND_DATAA *LPWIN32_FIND_DATAA;

typedef struct _STARTUPINFOA *LPSTARTUPINFOA;

typedef struct _RTL_CRITICAL_SECTION _RTL_CRITICAL_SECTION, *P_RTL_CRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION *PRTL_CRITICAL_SECTION;

typedef PRTL_CRITICAL_SECTION LPCRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION_DEBUG _RTL_CRITICAL_SECTION_DEBUG, *P_RTL_CRITICAL_SECTION_DEBUG;

typedef struct _RTL_CRITICAL_SECTION_DEBUG *PRTL_CRITICAL_SECTION_DEBUG;

typedef struct _LIST_ENTRY _LIST_ENTRY, *P_LIST_ENTRY;

typedef struct _LIST_ENTRY LIST_ENTRY;

struct _RTL_CRITICAL_SECTION {
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore;
    ULONG_PTR SpinCount;
};

struct _LIST_ENTRY {
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
};

struct _RTL_CRITICAL_SECTION_DEBUG {
    WORD Type;
    WORD CreatorBackTraceIndex;
    struct _RTL_CRITICAL_SECTION *CriticalSection;
    LIST_ENTRY ProcessLocksList;
    DWORD EntryCount;
    DWORD ContentionCount;
    DWORD Flags;
    WORD CreatorBackTraceIndexHigh;
    WORD SpareWORD;
};

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

typedef LONG (*PTOP_LEVEL_EXCEPTION_FILTER)(struct _EXCEPTION_POINTERS *);

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, *P_EXCEPTION_RECORD;

typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

typedef EXCEPTION_RECORD *PEXCEPTION_RECORD;

typedef struct _CONTEXT _CONTEXT, *P_CONTEXT;

typedef struct _CONTEXT CONTEXT;

typedef CONTEXT *PCONTEXT;

typedef struct _FLOATING_SAVE_AREA _FLOATING_SAVE_AREA, *P_FLOATING_SAVE_AREA;

typedef struct _FLOATING_SAVE_AREA FLOATING_SAVE_AREA;

struct _FLOATING_SAVE_AREA {
    DWORD ControlWord;
    DWORD StatusWord;
    DWORD TagWord;
    DWORD ErrorOffset;
    DWORD ErrorSelector;
    DWORD DataOffset;
    DWORD DataSelector;
    BYTE RegisterArea[80];
    DWORD Cr0NpxState;
};

struct _CONTEXT {
    DWORD ContextFlags;
    DWORD Dr0;
    DWORD Dr1;
    DWORD Dr2;
    DWORD Dr3;
    DWORD Dr6;
    DWORD Dr7;
    FLOATING_SAVE_AREA FloatSave;
    DWORD SegGs;
    DWORD SegFs;
    DWORD SegEs;
    DWORD SegDs;
    DWORD Edi;
    DWORD Esi;
    DWORD Ebx;
    DWORD Edx;
    DWORD Ecx;
    DWORD Eax;
    DWORD Ebp;
    DWORD Eip;
    DWORD SegCs;
    DWORD EFlags;
    DWORD Esp;
    DWORD SegSs;
    BYTE ExtendedRegisters[512];
};

struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD *ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
};

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

typedef struct _SYSTEMTIME *LPSYSTEMTIME;

typedef PTOP_LEVEL_EXCEPTION_FILTER LPTOP_LEVEL_EXCEPTION_FILTER;

typedef struct _MEMORY_BASIC_INFORMATION _MEMORY_BASIC_INFORMATION, *P_MEMORY_BASIC_INFORMATION;

typedef ULONG_PTR SIZE_T;

struct _MEMORY_BASIC_INFORMATION {
    PVOID BaseAddress;
    PVOID AllocationBase;
    DWORD AllocationProtect;
    SIZE_T RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
};

typedef union _LARGE_INTEGER _LARGE_INTEGER, *P_LARGE_INTEGER;

typedef struct _struct_19 _struct_19, *P_struct_19;

typedef struct _struct_20 _struct_20, *P_struct_20;

typedef double LONGLONG;

struct _struct_20 {
    DWORD LowPart;
    LONG HighPart;
};

struct _struct_19 {
    DWORD LowPart;
    LONG HighPart;
};

union _LARGE_INTEGER {
    struct _struct_19 s;
    struct _struct_20 u;
    LONGLONG QuadPart;
};

typedef union _LARGE_INTEGER LARGE_INTEGER;

typedef WCHAR *LPWSTR;

typedef WCHAR *PCNZWCH;

typedef WCHAR *LPWCH;

typedef WCHAR *LPCWSTR;

typedef CHAR *LPCSTR;

typedef struct _MEMORY_BASIC_INFORMATION *PMEMORY_BASIC_INFORMATION;

typedef LONG *PLONG;

typedef CHAR *LPCH;

typedef struct _OSVERSIONINFOA _OSVERSIONINFOA, *P_OSVERSIONINFOA;

struct _OSVERSIONINFOA {
    DWORD dwOSVersionInfoSize;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    DWORD dwPlatformId;
    CHAR szCSDVersion[128];
};

typedef struct _OSVERSIONINFOA *LPOSVERSIONINFOA;

typedef DWORD LCID;

typedef CHAR *PCNZCH;

typedef struct IMAGE_DOS_HEADER IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

struct IMAGE_DOS_HEADER {
    char e_magic[2]; // Magic number
    word e_cblp; // Bytes of last page
    word e_cp; // Pages in file
    word e_crlc; // Relocations
    word e_cparhdr; // Size of header in paragraphs
    word e_minalloc; // Minimum extra paragraphs needed
    word e_maxalloc; // Maximum extra paragraphs needed
    word e_ss; // Initial (relative) SS value
    word e_sp; // Initial SP value
    word e_csum; // Checksum
    word e_ip; // Initial IP value
    word e_cs; // Initial (relative) CS value
    word e_lfarlc; // File address of relocation table
    word e_ovno; // Overlay number
    word e_res[4][4]; // Reserved words
    word e_oemid; // OEM identifier (for e_oeminfo)
    word e_oeminfo; // OEM information; e_oemid specific
    word e_res2[10][10]; // Reserved words
    dword e_lfanew; // File address of new exe header
    byte e_program[64]; // Actual DOS program
};

typedef struct tm tm, *Ptm;

struct tm {
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
};

typedef uint UINT_PTR;

typedef struct DotNetPdbInfo DotNetPdbInfo, *PDotNetPdbInfo;

struct DotNetPdbInfo {
    char signature[4];
    GUID guid;
    dword age;
    char pdbpath[57];
};

typedef struct _strflt _strflt, *P_strflt;

struct _strflt {
    int sign;
    int decpt;
    int flag;
    char *mantissa;
};

typedef struct _flt _flt, *P_flt;

struct _flt {
    int flags;
    int nbytes;
    long lval;
    double dval;
};

typedef struct _strflt *STRFLT;

typedef enum enum_3272 {
    INTRNCVT_OK=0,
    INTRNCVT_OVERFLOW=1,
    INTRNCVT_UNDERFLOW=2
} enum_3272;

typedef enum enum_3272 INTRNCVT_STATUS;

typedef struct _flt *FLT;

typedef struct _FILETIME *LPFILETIME;

typedef int (*FARPROC)(void);

typedef uchar UCHAR;

typedef UCHAR *PUCHAR;

typedef WORD *LPWORD;

typedef DWORD *LPDWORD;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

struct HINSTANCE__ {
    int unused;
};

typedef DWORD *PDWORD;

typedef BOOL *LPBOOL;

typedef struct HINSTANCE__ *HINSTANCE;

typedef void *LPCVOID;

typedef HINSTANCE HMODULE;

typedef struct IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY {
    ImageBaseOffset32 VirtualAddress;
    dword Size;
};

struct IMAGE_OPTIONAL_HEADER32 {
    word Magic;
    byte MajorLinkerVersion;
    byte MinorLinkerVersion;
    dword SizeOfCode;
    dword SizeOfInitializedData;
    dword SizeOfUninitializedData;
    ImageBaseOffset32 AddressOfEntryPoint;
    ImageBaseOffset32 BaseOfCode;
    ImageBaseOffset32 BaseOfData;
    pointer32 ImageBase;
    dword SectionAlignment;
    dword FileAlignment;
    word MajorOperatingSystemVersion;
    word MinorOperatingSystemVersion;
    word MajorImageVersion;
    word MinorImageVersion;
    word MajorSubsystemVersion;
    word MinorSubsystemVersion;
    dword Win32VersionValue;
    dword SizeOfImage;
    dword SizeOfHeaders;
    dword CheckSum;
    word Subsystem;
    word DllCharacteristics;
    dword SizeOfStackReserve;
    dword SizeOfStackCommit;
    dword SizeOfHeapReserve;
    dword SizeOfHeapCommit;
    dword LoaderFlags;
    dword NumberOfRvaAndSizes;
    struct IMAGE_DATA_DIRECTORY DataDirectory[16];
};

typedef struct IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef union Misc Misc, *PMisc;

typedef enum SectionFlags {
    IMAGE_SCN_TYPE_NO_PAD=8,
    IMAGE_SCN_RESERVED_0001=16,
    IMAGE_SCN_CNT_CODE=32,
    IMAGE_SCN_CNT_INITIALIZED_DATA=64,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA=128,
    IMAGE_SCN_LNK_OTHER=256,
    IMAGE_SCN_LNK_INFO=512,
    IMAGE_SCN_RESERVED_0040=1024,
    IMAGE_SCN_LNK_REMOVE=2048,
    IMAGE_SCN_LNK_COMDAT=4096,
    IMAGE_SCN_GPREL=32768,
    IMAGE_SCN_MEM_16BIT=131072,
    IMAGE_SCN_MEM_PURGEABLE=131072,
    IMAGE_SCN_MEM_LOCKED=262144,
    IMAGE_SCN_MEM_PRELOAD=524288,
    IMAGE_SCN_ALIGN_1BYTES=1048576,
    IMAGE_SCN_ALIGN_2BYTES=2097152,
    IMAGE_SCN_ALIGN_4BYTES=3145728,
    IMAGE_SCN_ALIGN_8BYTES=4194304,
    IMAGE_SCN_ALIGN_16BYTES=5242880,
    IMAGE_SCN_ALIGN_32BYTES=6291456,
    IMAGE_SCN_ALIGN_64BYTES=7340032,
    IMAGE_SCN_ALIGN_128BYTES=8388608,
    IMAGE_SCN_ALIGN_256BYTES=9437184,
    IMAGE_SCN_ALIGN_512BYTES=10485760,
    IMAGE_SCN_ALIGN_1024BYTES=11534336,
    IMAGE_SCN_ALIGN_2048BYTES=12582912,
    IMAGE_SCN_ALIGN_4096BYTES=13631488,
    IMAGE_SCN_ALIGN_8192BYTES=14680064,
    IMAGE_SCN_LNK_NRELOC_OVFL=16777216,
    IMAGE_SCN_MEM_DISCARDABLE=33554432,
    IMAGE_SCN_MEM_NOT_CACHED=67108864,
    IMAGE_SCN_MEM_NOT_PAGED=134217728,
    IMAGE_SCN_MEM_SHARED=268435456,
    IMAGE_SCN_MEM_EXECUTE=536870912,
    IMAGE_SCN_MEM_READ=1073741824,
    IMAGE_SCN_MEM_WRITE=2147483648
} SectionFlags;

union Misc {
    dword PhysicalAddress;
    dword VirtualSize;
};

struct IMAGE_SECTION_HEADER {
    char Name[8];
    union Misc Misc;
    ImageBaseOffset32 VirtualAddress;
    dword SizeOfRawData;
    dword PointerToRawData;
    dword PointerToRelocations;
    dword PointerToLinenumbers;
    word NumberOfRelocations;
    word NumberOfLinenumbers;
    enum SectionFlags Characteristics;
};

typedef struct IMAGE_DIRECTORY_ENTRY_EXPORT IMAGE_DIRECTORY_ENTRY_EXPORT, *PIMAGE_DIRECTORY_ENTRY_EXPORT;

struct IMAGE_DIRECTORY_ENTRY_EXPORT {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    ImageBaseOffset32 Name;
    dword Base;
    dword NumberOfFunctions;
    dword NumberOfNames;
    ImageBaseOffset32 AddressOfFunctions;
    ImageBaseOffset32 AddressOfNames;
    ImageBaseOffset32 AddressOfNameOrdinals;
};

typedef struct IMAGE_DEBUG_DIRECTORY IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

struct IMAGE_DEBUG_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword Type;
    dword SizeOfData;
    dword AddressOfRawData;
    dword PointerToRawData;
};

typedef struct IMAGE_FILE_HEADER IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

struct IMAGE_FILE_HEADER {
    word Machine; // 332
    word NumberOfSections;
    dword TimeDateStamp;
    dword PointerToSymbolTable;
    dword NumberOfSymbols;
    word SizeOfOptionalHeader;
    word Characteristics;
};

typedef struct IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

struct IMAGE_NT_HEADERS32 {
    char Signature[4];
    struct IMAGE_FILE_HEADER FileHeader;
    struct IMAGE_OPTIONAL_HEADER32 OptionalHeader;
};

typedef struct IMAGE_LOAD_CONFIG_DIRECTORY32 IMAGE_LOAD_CONFIG_DIRECTORY32, *PIMAGE_LOAD_CONFIG_DIRECTORY32;

struct IMAGE_LOAD_CONFIG_DIRECTORY32 {
    dword Size;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword GlobalFlagsClear;
    dword GlobalFlagsSet;
    dword CriticalSectionDefaultTimeout;
    dword DeCommitFreeBlockThreshold;
    dword DeCommitTotalFreeThreshold;
    pointer32 LockPrefixTable;
    dword MaximumAllocationSize;
    dword VirtualMemoryThreshold;
    dword ProcessHeapFlags;
    dword ProcessAffinityMask;
    word CsdVersion;
    word DependentLoadFlags;
    pointer32 EditList;
    pointer32 SecurityCookie;
    pointer32 SEHandlerTable;
    dword SEHandlerCount;
};

typedef struct _iobuf _iobuf, *P_iobuf;

struct _iobuf {
    char *_ptr;
    int _cnt;
    char *_base;
    int _flag;
    int _file;
    int _charbuf;
    int _bufsiz;
    char *_tmpfname;
};

typedef struct _iobuf FILE;

typedef char *va_list;

typedef uint uintptr_t;

typedef ulong u_long;

typedef struct WSAData WSAData, *PWSAData;

typedef struct WSAData WSADATA;

struct WSAData {
    WORD wVersion;
    WORD wHighVersion;
    char szDescription[257];
    char szSystemStatus[129];
    ushort iMaxSockets;
    ushort iMaxUdpDg;
    char *lpVendorInfo;
};

typedef ushort u_short;

typedef UINT_PTR SOCKET;

typedef WSADATA *LPWSADATA;

typedef struct sockaddr sockaddr, *Psockaddr;

struct sockaddr {
    u_short sa_family;
    char sa_data[14];
};

typedef struct fd_set fd_set, *Pfd_set;

typedef uint u_int;

struct fd_set {
    u_int fd_count;
    SOCKET fd_array[64];
};

typedef struct timeval timeval, *Ptimeval;

struct timeval {
    long tv_sec;
    long tv_usec;
};

typedef struct hostent hostent, *Phostent;

struct hostent {
    char *h_name;
    char **h_aliases;
    short h_addrtype;
    short h_length;
    char **h_addr_list;
};

typedef struct _tiddata _tiddata, *P_tiddata;

typedef struct _tiddata *_ptiddata;

typedef struct threadmbcinfostruct threadmbcinfostruct, *Pthreadmbcinfostruct;

typedef struct threadmbcinfostruct *pthreadmbcinfo;

typedef struct threadlocaleinfostruct threadlocaleinfostruct, *Pthreadlocaleinfostruct;

typedef struct threadlocaleinfostruct *pthreadlocinfo;

typedef struct setloc_struct setloc_struct, *Psetloc_struct;

typedef struct setloc_struct _setloc_struct;

typedef struct localerefcount localerefcount, *Plocalerefcount;

typedef struct localerefcount locrefcount;

typedef struct lconv lconv, *Plconv;

typedef struct __lc_time_data __lc_time_data, *P__lc_time_data;

typedef struct _is_ctype_compatible _is_ctype_compatible, *P_is_ctype_compatible;

struct lconv {
    char *decimal_point;
    char *thousands_sep;
    char *grouping;
    char *int_curr_symbol;
    char *currency_symbol;
    char *mon_decimal_point;
    char *mon_thousands_sep;
    char *mon_grouping;
    char *positive_sign;
    char *negative_sign;
    char int_frac_digits;
    char frac_digits;
    char p_cs_precedes;
    char p_sep_by_space;
    char n_cs_precedes;
    char n_sep_by_space;
    char p_sign_posn;
    char n_sign_posn;
    wchar_t *_W_decimal_point;
    wchar_t *_W_thousands_sep;
    wchar_t *_W_int_curr_symbol;
    wchar_t *_W_currency_symbol;
    wchar_t *_W_mon_decimal_point;
    wchar_t *_W_mon_thousands_sep;
    wchar_t *_W_positive_sign;
    wchar_t *_W_negative_sign;
};

struct _is_ctype_compatible {
    ulong id;
    int is_clike;
};

struct setloc_struct {
    wchar_t *pchLanguage;
    wchar_t *pchCountry;
    int iLocState;
    int iPrimaryLen;
    BOOL bAbbrevLanguage;
    BOOL bAbbrevCountry;
    UINT _cachecp;
    wchar_t _cachein[131];
    wchar_t _cacheout[131];
    struct _is_ctype_compatible _Loc_c[5];
    wchar_t _cacheLocaleName[85];
};

struct threadmbcinfostruct {
    int refcount;
    int mbcodepage;
    int ismbcodepage;
    ushort mbulinfo[6];
    uchar mbctype[257];
    uchar mbcasemap[256];
    wchar_t *mblocalename;
};

struct localerefcount {
    char *locale;
    wchar_t *wlocale;
    int *refcount;
    int *wrefcount;
};

struct threadlocaleinfostruct {
    int refcount;
    uint lc_codepage;
    uint lc_collate_cp;
    uint lc_time_cp;
    locrefcount lc_category[6];
    int lc_clike;
    int mb_cur_max;
    int *lconv_intl_refcount;
    int *lconv_num_refcount;
    int *lconv_mon_refcount;
    struct lconv *lconv;
    int *ctype1_refcount;
    ushort *ctype1;
    ushort *pctype;
    uchar *pclmap;
    uchar *pcumap;
    struct __lc_time_data *lc_time_curr;
    wchar_t *locale_name[6];
};

struct _tiddata {
    ulong _tid;
    uintptr_t _thandle;
    int _terrno;
    ulong _tdoserrno;
    uint _fpds;
    ulong _holdrand;
    char *_token;
    wchar_t *_wtoken;
    uchar *_mtoken;
    char *_errmsg;
    wchar_t *_werrmsg;
    char *_namebuf0;
    wchar_t *_wnamebuf0;
    char *_namebuf1;
    wchar_t *_wnamebuf1;
    char *_asctimebuf;
    wchar_t *_wasctimebuf;
    void *_gmtimebuf;
    char *_cvtbuf;
    uchar _con_ch_buf[5];
    ushort _ch_buf_used;
    void *_initaddr;
    void *_initarg;
    void *_pxcptacttab;
    void *_tpxcptinfoptrs;
    int _tfpecode;
    pthreadmbcinfo ptmbcinfo;
    pthreadlocinfo ptlocinfo;
    int _ownlocale;
    ulong _NLG_dwCode;
    void *_terminate;
    void *_unexpected;
    void *_translator;
    void *_purecall;
    void *_curexception;
    void *_curcontext;
    int _ProcessingThrow;
    void *_curexcspec;
    void *_pFrameInfoChain;
    _setloc_struct _setloc_data;
    void *_reserved1;
    void *_reserved2;
    void *_reserved3;
    void *_reserved4;
    void *_reserved5;
    int _cxxReThrow;
    ulong __initDomain;
    int _initapartment;
};

struct __lc_time_data {
    char *wday_abbr[7];
    char *wday[7];
    char *month_abbr[12];
    char *month[12];
    char *ampm[2];
    char *ww_sdatefmt;
    char *ww_ldatefmt;
    char *ww_timefmt;
    int ww_caltype;
    int refcount;
    wchar_t *_W_wday_abbr[7];
    wchar_t *_W_wday[7];
    wchar_t *_W_month_abbr[12];
    wchar_t *_W_month[12];
    wchar_t *_W_ampm[2];
    wchar_t *_W_ww_sdatefmt;
    wchar_t *_W_ww_ldatefmt;
    wchar_t *_W_ww_timefmt;
    wchar_t *_W_ww_locale_name;
};

typedef struct _NCB _NCB, *P_NCB;

typedef struct _NCB *PNCB;

struct _NCB {
    UCHAR ncb_command;
    UCHAR ncb_retcode;
    UCHAR ncb_lsn;
    UCHAR ncb_num;
    PUCHAR ncb_buffer;
    WORD ncb_length;
    UCHAR ncb_callname[16];
    UCHAR ncb_name[16];
    UCHAR ncb_rto;
    UCHAR ncb_sto;
    void (*ncb_post)(struct _NCB *);
    UCHAR ncb_lana_num;
    UCHAR ncb_cmd_cplt;
    UCHAR ncb_reserve[10];
    HANDLE ncb_event;
};

typedef struct EHRegistrationNode EHRegistrationNode, *PEHRegistrationNode;

struct EHRegistrationNode { // PlaceHolder Structure
};

typedef struct _s_CatchableType _s_CatchableType, *P_s_CatchableType;

struct _s_CatchableType { // PlaceHolder Structure
};

typedef enum _EXCEPTION_DISPOSITION {
} _EXCEPTION_DISPOSITION;

typedef struct PMD PMD, *PPMD;

struct PMD { // PlaceHolder Structure
};

typedef struct EHExceptionRecord EHExceptionRecord, *PEHExceptionRecord;

struct EHExceptionRecord { // PlaceHolder Structure
};

typedef struct TranslatorGuardRN TranslatorGuardRN, *PTranslatorGuardRN;

struct TranslatorGuardRN { // PlaceHolder Structure
};

typedef struct FrameInfo FrameInfo, *PFrameInfo;

struct FrameInfo { // PlaceHolder Structure
};

typedef struct _s_ThrowInfo _s_ThrowInfo, *P_s_ThrowInfo;

struct _s_ThrowInfo { // PlaceHolder Structure
};

typedef struct _LDBL12 _LDBL12, *P_LDBL12;

struct _LDBL12 {
    uchar ld12[12];
};

typedef struct _CRT_FLOAT _CRT_FLOAT, *P_CRT_FLOAT;

struct _CRT_FLOAT {
    float f;
};

typedef struct _CRT_DOUBLE _CRT_DOUBLE, *P_CRT_DOUBLE;

struct _CRT_DOUBLE {
    double x;
};

typedef int (*_onexit_t)(void);

typedef uint size_t;

typedef long __time32_t;

typedef int errno_t;

typedef struct localeinfo_struct localeinfo_struct, *Plocaleinfo_struct;

struct localeinfo_struct {
    pthreadlocinfo locinfo;
    pthreadmbcinfo mbcinfo;
};

typedef int intptr_t;

typedef struct localeinfo_struct *_locale_t;

typedef longlong __time64_t;

typedef __time64_t time_t;




void StopServer(void);
bool IsServerRunning(void);
void FUN_100010c0(void);
void Catch@100014af(void);
void __cdecl FUN_10001520(SIZE_T param_1);
void __cdecl FUN_10001540(LPVOID param_1);
undefined4 FUN_10001560(undefined4 param_1,int param_2);
uint __cdecl StartServer(char *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4);
void __cdecl FUN_10001640(PUCHAR param_1);
undefined4 FUN_10001710(void);
void __cdecl FUN_10001750(int param_1,undefined4 *param_2);
undefined4 FUN_10001880(void);
void __cdecl FUN_100018a0(int param_1);
void __cdecl FUN_10001910(int param_1,int param_2,int param_3);
void __cdecl FUN_10001980(int *param_1,char *param_2,char *param_3,char *param_4);
void __cdecl FUN_10001a80(int param_1,int param_2,int param_3);
undefined4 * FUN_10001aa0(void);
void __cdecl FUN_10001ae0(LPVOID param_1);
void FUN_10001b00(void);
void FUN_10001b30(void);
void FUN_10001b70(void);
void __fastcall FUN_10001ba0(int param_1);
undefined4 * __cdecl FUN_10001bf0(undefined4 *param_1);
uint __cdecl FUN_10001d40(int *param_1);
byte * __cdecl FUN_10001de0(byte *param_1,int param_2,byte *param_3,int param_4);
undefined4 __fastcall FUN_10001fb0(char *param_1);
undefined1 __cdecl FUN_10001fe0(char param_1);
void __cdecl FUN_10002000(byte *param_1,byte param_2);
int __cdecl FUN_100020b0(char *param_1,int param_2,char *param_3);
byte * __cdecl FUN_100020f0(byte *param_1,byte *param_2);
void __cdecl FUN_100021f0(byte *param_1,byte *param_2,byte *param_3);
void __cdecl FUN_100022d0(byte *param_1,undefined4 param_2,undefined4 param_3);
char * __cdecl FUN_10002330(char *param_1);
void __cdecl FUN_10002370(byte *param_1,int param_2,byte *param_3,uint param_4);
int __cdecl FUN_10002480(char *param_1,int param_2);
int __cdecl FUN_100024f0(byte *param_1,int param_2,byte *param_3,uint param_4);
uint __cdecl FUN_100025a0(char *param_1,uint param_2);
void __cdecl FUN_100025e0(byte *param_1,int param_2,byte *param_3,uint param_4);
uint __cdecl FUN_10002780(byte *param_1,uint param_2);
void __cdecl FUN_100027d0(byte *param_1,int param_2,byte *param_3,uint param_4);
uint __cdecl FUN_10002930(byte *param_1,uint param_2);
int __cdecl FUN_10002a30(byte *param_1,byte *param_2,int param_3,byte *param_4);
int __cdecl FUN_10002b70(byte *param_1,int param_2,byte *param_3,byte *param_4,int param_5);
byte * __cdecl FUN_10002c10(char *param_1,byte *param_2,int param_3);
int __cdecl FUN_10002d30(byte *param_1,int param_2,byte *param_3,uint *param_4,int param_5,byte *param_6);
void __cdecl FUN_10002fe0(byte *param_1,uint *param_2,int param_3,byte *param_4);
void __cdecl FUN_10003240(byte *param_1,int param_2,byte *param_3,int param_4);
void __cdecl FUN_10003320(char *param_1,int param_2);
undefined4 __cdecl FUN_10003510(char *param_1,int *param_2,int *param_3,undefined4 *param_4,undefined4 *param_5,undefined4 *param_6,undefined4 *param_7);
float10 __cdecl FUN_100035a0(byte *param_1,float param_2);
char * __cdecl FUN_10003660(char *param_1);
int __cdecl FUN_10003680(byte *param_1,byte *param_2,int param_3,byte *param_4,int param_5,int param_6);
int __cdecl FUN_10003810(char *param_1,char *param_2,int param_3);
byte * __cdecl FUN_100038b0(byte *param_1,byte *param_2,int param_3);
void __cdecl FUN_10003940(byte *param_1,int param_2,int param_3);
undefined4 __cdecl FUN_10003a20(byte *param_1,byte *param_2);
undefined4 __cdecl FUN_10003ac0(byte *param_1,int param_2,byte *param_3);
int __cdecl FUN_10003c50(byte *param_1,int param_2,byte *param_3,byte *param_4);
int __cdecl FUN_10003cf0(byte *param_1,int param_2,byte *param_3,byte *param_4);
int __cdecl FUN_10003e20(byte *param_1,size_t param_2,byte *param_3);
void FUN_10004060(void);
int __fastcall FUN_100040e0(int param_1);
undefined4 FUN_10004150(void);
void FUN_100041f0(undefined4 *param_1);
void FUN_10004290(void);
void FUN_100042f0(void);
void FUN_100043c0(void);
void __cdecl FUN_10004540(int param_1);
undefined4 * __cdecl FUN_10004620(int param_1,int param_2,int param_3);
undefined4 __cdecl FUN_100046f0(int param_1);
int __cdecl FUN_10004720(int param_1,sockaddr *param_2,int param_3);
void __cdecl FUN_10004770(DWORD *param_1,byte *param_2,int param_3,undefined4 param_4,int param_5,int param_6);
int __cdecl FUN_10004840(int param_1,char *param_2,uint param_3,undefined4 param_4,sockaddr *param_5,int *param_6);
undefined4 __cdecl FUN_100049b0(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5);
void __cdecl FUN_100049e0(undefined4 *param_1,uint param_2,sockaddr *param_3,uint param_4);
void FUN_10004bd0(void);
void FUN_10004c80(void);
void __fastcall FUN_10004d20(undefined4 param_1,byte *param_2);
void __fastcall FUN_10004d60(undefined4 param_1,int param_2);
void __cdecl FUN_10004dd0(undefined4 param_1,undefined4 param_2,DWORD *param_3);
undefined4 __thiscall FUN_100051d0(void *this,DWORD *param_1,char *param_2,char *param_3,char *param_4,char *param_5,int param_6);
int __cdecl FUN_10005450(DWORD *param_1,int param_2,int param_3);
void __cdecl FUN_100054c0(int param_1);
void __cdecl FUN_10005650(DWORD *param_1);
DWORD GetTickCount(void);
void __cdecl FUN_10005700(undefined4 *param_1);
void __cdecl FUN_10005730(undefined4 *param_1);
undefined4 __cdecl FUN_10005750(DWORD *param_1);
void __cdecl FUN_100057a0(DWORD *param_1);
void __cdecl FUN_10005830(undefined4 *param_1);
void __cdecl FUN_10005860(int param_1,int param_2);
void __cdecl FUN_10005890(int param_1,int param_2);
void FUN_100058f0(void);
void FUN_10005930(void);
void __cdecl FUN_10005a50(int param_1);
void FUN_10005af0(void);
void FUN_10005b50(void);
char * __cdecl FUN_10005b60(int param_1,char *param_2,int param_3);
void __cdecl FUN_10005ca0(char *param_1,size_t param_2,char *param_3);
void __cdecl FUN_10005cd0(byte *param_1,byte *param_2);
int __cdecl FUN_10005d10(byte *param_1,byte *param_2,uint param_3);
char * __cdecl FUN_10005d70(char *param_1,char *param_2,size_t param_3);
undefined4 __cdecl FUN_10005de0(undefined4 param_1,int param_2);
undefined4 __cdecl FUN_10006020(undefined4 *param_1,int param_2);
void FUN_10006270(void);
int __cdecl FUN_100062b0(byte *param_1);
undefined4 FUN_10006300(void);
void __cdecl FUN_10006460(int param_1);
void FUN_10006570(void);
undefined4 __cdecl FUN_100065e0(byte *param_1,byte *param_2);
void __cdecl FUN_100066d0(void *param_1);
undefined4 __cdecl FUN_10007440(int param_1,int param_2,int *param_3);
void __cdecl FUN_10007740(int param_1,int param_2);
undefined4 FUN_10007a60(void);
void __cdecl FUN_10007bf0(int *param_1,int param_2,int param_3);
void __cdecl FUN_10007ca0(int param_1,int param_2,int *param_3);
void __cdecl FUN_10007e90(int param_1);
void __cdecl FUN_10008010(undefined4 param_1,undefined4 param_2,int param_3);
void __cdecl FUN_100081a0(undefined4 param_1,int param_2);
char __cdecl FUN_10008210(int param_1,int param_2,int param_3);
void __cdecl FUN_10008330(int param_1);
undefined4 __cdecl FUN_10008430(int param_1);
undefined4 __cdecl FUN_100085a0(byte *param_1);
undefined4 __cdecl FUN_10008850(int param_1);
int __cdecl FUN_10008900(int param_1);
uint __cdecl FUN_10008a00(int param_1,int param_2,int *param_3);
uint __cdecl FUN_10008d80(int param_1,int param_2,int param_3);
undefined4 __cdecl FUN_10008f40(int param_1,int param_2,int param_3);
uint __cdecl FUN_100091c0(int param_1);
undefined4 __cdecl FUN_100092c0(int param_1);
undefined4 __cdecl FUN_100093d0(int param_1);
uint __cdecl FUN_10009540(int param_1,int param_2);
uint __cdecl FUN_10009610(int param_1);
uint __fastcall FUN_10009700(int param_1);
int __cdecl FUN_10009ce0(int param_1,byte *param_2,int param_3,undefined4 *param_4,int *param_5,uint *param_6,undefined4 param_7,int param_8,int param_9,undefined4 param_10);
void __cdecl FUN_10009ef0(int param_1);
void __cdecl FUN_1000a090(int param_1,byte *param_2,undefined2 param_3);
void __cdecl FUN_1000a580(int param_1);
void __cdecl FUN_1000a660(int param_1,int param_2,char *param_3,int param_4);
void __cdecl FUN_1000a750(int param_1,int param_2,char *param_3,int param_4);
void __cdecl FUN_1000a830(undefined4 param_1,char *param_2);
void __cdecl FUN_1000a8e0(undefined4 param_1,char *param_2);
void __cdecl FUN_1000aad0(int param_1,int param_2,int param_3,int param_4);
void __cdecl FUN_1000ac40(int param_1,int param_2,int param_3,int param_4);
void __cdecl FUN_1000ada0(int param_1);
uint __cdecl FUN_1000adf0(int param_1);
undefined4 __cdecl FUN_1000aeb0(int param_1,int param_2);
undefined4 __cdecl FUN_1000af70(int param_1,int param_2,int param_3);
void __cdecl FUN_1000b700(int param_1,int *param_2,int *param_3,int param_4,int param_5);
undefined1 __thiscall FUN_1000bb40(void *this,int param_1,int param_2,int param_3,int param_4);
void __cdecl FUN_1000dd30(undefined4 param_1,int param_2);
void FUN_1000e430(void);
void FUN_1000e570(void);
void __cdecl FUN_1000e580(undefined4 param_1,undefined4 param_2,int param_3);
void __cdecl FUN_1000e670(undefined4 param_1,undefined4 param_2,int param_3);
void __cdecl FUN_1000e760(undefined4 param_1,undefined4 param_2,int param_3);
void __cdecl FUN_1000e830(undefined4 param_1,int param_2);
void __cdecl FUN_1000e8a0(undefined4 param_1,int param_2);
void __cdecl FUN_1000ea10(int param_1);
undefined4 __cdecl FUN_1000ebf0(byte *param_1);
undefined4 __cdecl FUN_1000ed20(int param_1);
undefined4 __cdecl FUN_1000ee60(byte *param_1);
undefined4 __cdecl FUN_1000ef90(int *param_1,byte *param_2);
undefined4 __cdecl FUN_1000f550(byte *param_1);
undefined4 __cdecl FUN_1000f680(byte *param_1);
int FUN_1000f7a0(void);
void __cdecl FUN_1000f9f0(int param_1);
undefined4 FUN_1000fb00(void);
undefined4 __cdecl FUN_1000fc50(int param_1);
uint FUN_1000fdb0(void);
uint __fastcall FUN_1000fe70(int param_1);
undefined4 __fastcall FUN_1000fef0(int param_1);
undefined4 __cdecl FUN_1000ff60(int param_1);
undefined4 __cdecl FUN_10010110(uint *param_1);
undefined4 __cdecl FUN_100101c0(int param_1);
undefined4 __cdecl FUN_100103a0(uint *param_1);
uint __fastcall FUN_10010450(int param_1);
uint __fastcall FUN_10010500(int param_1);
undefined4 __cdecl FUN_10010590(int param_1,int param_2);
uint FUN_100107a0(void);
uint __fastcall FUN_10010830(undefined4 param_1,int param_2);
uint FUN_100108a0(void);
uint __fastcall FUN_10010a00(int param_1,int param_2);
undefined4 __cdecl FUN_10010d10(int param_1);
void __cdecl FUN_10010db0(int param_1,uint param_2,uint param_3,uint param_4,char *param_5,char *param_6);
void __cdecl FUN_10010eb0(int param_1);
void __cdecl FUN_10010f20(int param_1,uint param_2,char *param_3,char *param_4);
void __cdecl FUN_10010fe0(int param_1,uint param_2,char *param_3);
int * __cdecl FUN_10011030(int param_1,uint *param_2,uint param_3);
void __cdecl FUN_10011140(undefined4 param_1,byte *param_2);
void __cdecl FUN_10011ef0(int *param_1);
void __cdecl FUN_100122b0(int *param_1,int param_2,byte *param_3);
uint __thiscall FUN_10012940(void *this,int param_1);
void __cdecl FUN_100129d0(int param_1,int param_2,uint *param_3,uint param_4);
void __cdecl FUN_10012e60(int param_1);
void __fastcall FUN_10012f10(int param_1);
void __fastcall FUN_10012ff0(undefined4 param_1,int param_2);
undefined4 FUN_10013090(void);
undefined4 __cdecl FUN_10013190(int param_1,uint *param_2);
char __cdecl FUN_10013620(int param_1,int param_2,uint param_3);
undefined4 __cdecl FUN_10013ac0(int param_1,int param_2,int param_3);
undefined4 __thiscall FUN_10013b90(void *this,int param_1,int param_2,int param_3);
undefined4 __cdecl FUN_10013c40(int param_1,int param_2,int param_3);
int __cdecl FUN_10013e70(int param_1);
void FUN_10013ec0(int *param_1);
void __cdecl FUN_10013fe0(undefined4 param_1,undefined4 param_2,undefined4 *param_3);
void __cdecl FUN_100140a0(undefined4 *param_1,int param_2);
void __cdecl FUN_100141b0(int *param_1);
uint __cdecl FUN_100141d0(int param_1,int param_2);
undefined4 * __cdecl FUN_10014240(int param_1,int param_2,int param_3);
void __cdecl FUN_100142e0(int param_1,int param_2,int param_3);
void __cdecl FUN_10014310(int param_1,int param_2);
uint __cdecl FUN_10014340(int param_1,uint param_2);
uint __cdecl FUN_10014370(int param_1,uint param_2);
void __cdecl FUN_100143a0(undefined4 param_1,undefined4 param_2,int *param_3);
char * __cdecl FUN_10014430(undefined4 param_1,int param_2,undefined4 param_3,undefined4 param_4,char *param_5,char *param_6);
undefined1 * __cdecl FUN_10014600(int param_1,byte *param_2);
void __cdecl FUN_10014630(int param_1,undefined1 param_2);
void FUN_10014640(undefined4 *param_1);
void __cdecl FUN_10014650(int param_1,int param_2,uint param_3);
void FUN_10014790(void);
void FUN_10014810(void);
void __cdecl FUN_10014820(undefined4 param_1,int param_2,int param_3);
void __cdecl FUN_10014850(uint param_1,int param_2);
undefined4 __cdecl FUN_100149a0(int param_1,int param_2);
undefined4 * __cdecl FUN_10014b50(byte *param_1,byte *param_2);
undefined4 __cdecl FUN_10014c10(int *param_1,char *param_2,char *param_3);
void __cdecl FUN_100152c0(int *param_1,char param_2);
undefined4 * __cdecl FUN_100153c0(undefined4 param_1);
void __cdecl FUN_10015660(void *param_1);
undefined4 __cdecl FUN_10015680(int param_1,int param_2);
undefined4 FUN_100156a0(void);
undefined4 __cdecl FUN_100156b0(int param_1,byte *param_2,int param_3,int param_4);
uint __cdecl FUN_100157f0(undefined4 param_1,byte *param_2,byte *param_3,int param_4);
undefined4 FUN_100159c0(void);
undefined4 __cdecl FUN_100159d0(int param_1,char *param_2,size_t param_3);
undefined * FUN_10015a10(void);
undefined1 FUN_10015a20(void);
void __cdecl FUN_10015a30(undefined4 param_1,byte *param_2,int param_3,char *param_4,int param_5);
undefined4 FUN_10015c60(void);
char __cdecl FUN_10015d10(undefined4 param_1,int param_2,int param_3);
void __cdecl FUN_10015d60(undefined4 param_1,byte *param_2,int param_3,int *param_4,undefined4 param_5,int param_6);
void __fastcall FUN_10015e30(undefined4 param_1,int param_2);
char * __cdecl FUN_10015f20(char *param_1,int param_2);
void __cdecl FUN_10015f70(void *param_1);
undefined4 __cdecl FUN_10015f90(undefined4 param_1);
bool __cdecl FUN_10015fa0(int param_1,int param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,undefined4 param_6,undefined4 param_7,char *param_8,undefined4 param_9,undefined4 param_10,char *param_11,char *param_12);
char * __cdecl FUN_10016110(int param_1,undefined4 param_2,int param_3,char *param_4);
bool __cdecl FUN_100161b0(int param_1);
undefined4 __cdecl FUN_100161d0(int param_1);
void __cdecl FUN_100161e0(int param_1,int param_2);
void __cdecl FUN_10016200(int param_1,int param_2,int param_3);
void __cdecl FUN_10016250(int param_1,int param_2);
void __cdecl FUN_10016290(int param_1,int param_2,uint param_3);
void __thiscall FUN_10016340(void *this,undefined4 param_1,undefined4 param_2);
void FUN_10016350(uint param_1,undefined4 param_2);
void __cdecl FUN_10016410(uint param_1);
void __cdecl FUN_10016450(uint param_1);
void __cdecl FUN_10016490(uint param_1);
void __cdecl FUN_100164d0(uint param_1,char *param_2);
undefined4 * __cdecl FUN_10016560(undefined4 *param_1);
undefined4 __fastcall FUN_100166b0(undefined4 param_1,int param_2);
undefined4 __fastcall FUN_10016700(int param_1,int param_2);
undefined4 __fastcall FUN_10016740(int param_1,uint param_2,uint param_3);
int __fastcall FUN_10016800(int param_1,int param_2,int param_3,byte param_4);
undefined4 __cdecl FUN_10016860(char *param_1,char *param_2);
int __cdecl FUN_10016a50(byte *param_1,int param_2,byte *param_3);
void __cdecl FUN_10016ae0(char *param_1,uint param_2,byte param_3);
char * __cdecl FUN_10016bc0(char *param_1);
undefined4 __cdecl FUN_10016c00(char *param_1,undefined4 param_2);
undefined4 __cdecl FUN_10016d40(char *param_1);
undefined4 __cdecl FUN_10016f90(char *param_1,undefined4 param_2,byte *param_3);
void __cdecl FUN_10017110(char *param_1,undefined4 param_2,undefined4 param_3);
undefined4 __cdecl FUN_10017150(char *param_1,undefined4 param_2);
undefined4 __cdecl FUN_100171e0(char *param_1,byte *param_2);
char * __cdecl FUN_10017330(char *param_1,uint param_2,char *param_3,int param_4);
void __cdecl FUN_10017770(undefined4 *param_1);
undefined4 __cdecl FUN_100177b0(int param_1,undefined4 param_2);
void __cdecl FUN_100177f0(int *param_1,char *param_2);
void __cdecl FUN_10017a50(int param_1,int param_2,int param_3,int param_4);
int * __cdecl FUN_10017b10(undefined4 param_1);
void __cdecl FUN_10017c60(undefined4 *param_1);
byte * __cdecl FUN_10017ca0(int *param_1,byte *param_2,undefined4 param_3);
int __cdecl FUN_10017d30(int *param_1,byte *param_2,undefined4 param_3,char *param_4,size_t param_5);
void __thiscall FUN_10017ff0(void *this,byte *param_1,byte *param_2,byte *param_3,undefined1 param_4);
undefined1 __thiscall FUN_100180c0(void *this,uint param_1);
void __thiscall FUN_10018110(void *this,int param_1);
void __cdecl FUN_10018990(int param_1);
void __cdecl FUN_100189c0(char *param_1,char *param_2,uint param_3);
void __cdecl FUN_10018a70(void *param_1,undefined1 *param_2,int param_3);
undefined4 __cdecl FUN_10019ed0(undefined4 param_1,int param_2,int param_3);
undefined4 __cdecl FUN_10019fa0(int param_1,int param_2,int param_3);
undefined4 __cdecl FUN_1001a120(int param_1,int param_2,int param_3);
int __cdecl FUN_1001a880(char *param_1);
void __thiscall FUN_1001a960(void *this,undefined4 *param_1,int param_2,undefined4 param_3,undefined4 *param_4);
undefined4 __cdecl FUN_1001ab10(int param_1,undefined4 param_2);
undefined4 __cdecl FUN_1001ab40(int param_1);
undefined4 __cdecl FUN_1001aba0(int param_1,int param_2,int param_3);
undefined4 __cdecl FUN_1001ad90(int param_1,int param_2,int param_3);
undefined4 __cdecl FUN_1001aee0(int param_1,int param_2,int param_3);
undefined4 __cdecl FUN_1001af80(int param_1,int param_2,int param_3);
undefined4 __cdecl FUN_1001b2d0(int param_1,int param_2,int param_3);
undefined4 __cdecl FUN_1001b470(int param_1,int param_2,int param_3);
undefined4 __cdecl FUN_1001b7b0(undefined4 param_1,int param_2,int param_3);
undefined4 __cdecl FUN_1001b930(int param_1,int param_2,int param_3);
undefined4 __cdecl FUN_1001cab0(int param_1,int param_2,int param_3);
undefined4 __cdecl FUN_1001cce0(int param_1,int param_2,int param_3);
undefined4 __cdecl FUN_1001d000(undefined4 param_1,int param_2,int param_3);
undefined4 __cdecl FUN_1001d060(int param_1,int param_2,int param_3);
undefined4 __cdecl FUN_1001d160(int param_1,int param_2,int param_3);
undefined4 __cdecl FUN_1001d2a0(undefined4 param_1,int param_2,int param_3);
undefined4 __cdecl FUN_1001d300(int param_1,int param_2,int param_3);
undefined4 __cdecl FUN_1001d3d0(int param_1,int param_2,int param_3);
undefined4 __cdecl FUN_1001d8a0(int param_1,int param_2,int param_3);
undefined4 __cdecl FUN_1001dd40(int param_1,int param_2,int param_3);
void __cdecl FUN_1001df20(void *param_1,int param_2,int param_3);
int __cdecl FUN_1001e440(int param_1,uint param_2,size_t param_3,uint *param_4,int *param_5,int *param_6,size_t *param_7,int *param_8);
undefined4 __cdecl FUN_1001ec50(int param_1,int param_2,int param_3);
undefined4 __cdecl FUN_1001ee20(int param_1,int param_2,int param_3);
undefined4 __cdecl FUN_1001f450(void *param_1,int param_2);
undefined4 __cdecl FUN_1001ff60(int param_1,int param_2);
undefined4 __cdecl FUN_100201c0(int param_1,int param_2,int param_3);
int __cdecl FUN_10020410(int param_1,int param_2,uint param_3,uint param_4,uint param_5,uint param_6,int param_7,int param_8,int param_9,char *param_10,undefined4 param_11);
void __cdecl FUN_100204b0(int param_1,int param_2,int param_3);
undefined4 __cdecl FUN_10020560(int param_1,int param_2,int param_3);
void __cdecl FUN_10020d80(int param_1,int param_2,undefined4 param_3,char *param_4,undefined4 *param_5);
undefined4 * __cdecl FUN_10020e00(int param_1,int param_2,int param_3,undefined4 param_4,char param_5);
void __cdecl FUN_10020fe0(void *param_1);
void FUN_10021020(int *param_1);
int __cdecl FUN_100210a0(int param_1,uint param_2);
int __cdecl FUN_10021150(int *param_1,uint param_2,byte *param_3,int *param_4);
void __cdecl FUN_10021610(int *param_1,byte *param_2);
undefined4 __cdecl FUN_10021630(int param_1);
int __cdecl FUN_10021640(int param_1);
undefined4 __cdecl FUN_10021660(int param_1);
int __cdecl FUN_10021670(int param_1);
bool __cdecl FUN_10021680(int param_1);
int __cdecl FUN_10021690(int param_1,int param_2,uint *param_3,int *param_4,int *param_5);
int __cdecl FUN_10021710(int param_1,int *param_2,int *param_3,undefined4 *param_4,uint *param_5,int *param_6);
bool __cdecl FUN_100217c0(int param_1,FILE *param_2);
undefined4 __cdecl FUN_10021850(int *param_1,LPCSTR param_2);
int __cdecl FUN_10021940(int param_1,byte *param_2);
int __cdecl FUN_100219e0(int param_1,byte *param_2);
void FUN_10021a40(void);
void FUN_10021b00(void);
void FUN_10021c40(void);
void FUN_10021ec0(void);
void __cdecl FUN_10021ee0(undefined4 param_1,undefined4 param_2,undefined4 *param_3);
void FUN_10021f00(void);
undefined4 * __cdecl FUN_10022030(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4);
void __cdecl FUN_100220d0(void *param_1);
uint __cdecl FUN_10022130(int param_1,int param_2);
undefined4 __cdecl FUN_100221c0(int param_1,u_long param_2,u_short param_3);
int __cdecl FUN_10022240(int param_1,size_t param_2,int param_3);
int __cdecl FUN_10022340(int param_1,undefined4 *param_2,undefined4 *param_3,undefined4 *param_4);
uint __cdecl FUN_100223d0(int param_1,undefined4 *param_2,undefined4 *param_3,undefined4 *param_4,uint param_5);
void __cdecl FUN_10022440(undefined4 *param_1);
undefined4 __cdecl FUN_10022490(undefined4 *param_1,int param_2,undefined4 param_3,char *param_4,char *param_5);
void __cdecl FUN_100225a0(int param_1,byte *param_2,size_t param_3);
void __cdecl FUN_10022630(byte *param_1,undefined4 *param_2);
void __cdecl FUN_10022830(void *param_1);
void __cdecl FUN_10022870(undefined4 *param_1);
int __cdecl FUN_100228c0(int param_1,int param_2);
int __cdecl FUN_10022920(int *param_1);
undefined4 __cdecl FUN_10022980(undefined4 *param_1);
undefined4 __fastcall FUN_10022990(undefined4 param_1,byte *param_2,int param_3);
undefined4 __thiscall FUN_100229d0(void *this,int *param_1,byte *param_2,int param_3);
undefined4 __thiscall FUN_10022a40(void *this,int param_1,byte *param_2);
int __thiscall FUN_10022a90(void *this,int *param_1,byte *param_2);
undefined4 __cdecl FUN_10022b00(int *param_1,int param_2,int param_3);
undefined4 __cdecl FUN_10022b70(int param_1,int param_2,undefined4 param_3);
undefined4 __cdecl FUN_10022bb0(int param_1,int param_2);
int __cdecl FUN_10022bf0(int *param_1,int param_2);
void __cdecl FUN_10022c50(int param_1);
undefined4 __cdecl FUN_10022c60(int param_1,undefined4 *param_2);
undefined4 * __cdecl FUN_10022cd0(int param_1,int param_2);
void __fastcall FUN_10022d60(int param_1);
void __fastcall FUN_10022d80(undefined4 *param_1);
void __fastcall FUN_10022de0(int *param_1);
void __thiscall FUN_10022ec0(void *this,char param_1);
void __thiscall FUN_10022f10(void *this,undefined4 param_1,undefined4 param_2);
void __fastcall FUN_10022f30(int param_1);
void __thiscall FUN_100230b0(void *this,uint param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4);
void __thiscall FUN_100230e0(void *this,int param_1);
undefined4 __cdecl FUN_100230f0(undefined4 param_1);
undefined4 * __thiscall FUN_10023100(void *this,int param_1,int param_2);
undefined4 * __thiscall FUN_10023220(void *this,byte param_1);
undefined4 __thiscall FUN_10023240(void *this,int param_1,byte *param_2,int param_3,int *param_4);
void __cdecl FUN_100232a0(int *param_1,byte *param_2,int param_3,undefined4 param_4);
void __cdecl FUN_100234a0(int param_1,int param_2,uint param_3);
void __cdecl FUN_100234e0(undefined4 param_1);
undefined * FUN_10023500(void);
void FUN_10023510(void);
void FUN_10023520(void);
int FUN_10023540(void);
int FUN_100235c0(void);
int __cdecl FUN_10023610(undefined4 param_1,int param_2,undefined4 param_3,char param_4);
undefined1 FUN_10023680(void);
undefined * __cdecl FUN_10023690(undefined4 param_1,int *param_2,int param_3,byte *param_4);
int * __thiscall FUN_100236d0(void *this,int param_1,int param_2);
void __fastcall FUN_10023700(int param_1);
byte * __thiscall FUN_10023710(void *this,byte *param_1);
void FUN_100237c0(int *param_1,int *param_2);
undefined1 __thiscall FUN_10023a60(void *this,float *param_1);
void __thiscall FUN_10023b40(void *this,char *param_1,undefined4 param_2,undefined4 param_3);
void __thiscall FUN_10023b49(void *this,undefined4 param_1,int param_2,undefined4 param_3,undefined4 param_4);
int __thiscall FUN_10023ca0(void *this,int param_1,int param_2);
uint __thiscall FUN_10023db0(void *this,float *param_1);
undefined4 __thiscall FUN_10023eb0(void *this,float *param_1);
undefined4 __thiscall FUN_10024110(void *this,float *param_1);
void __thiscall FUN_10024220(void *this,float param_1);
void __thiscall FUN_100244d0(void *this,char *param_1,byte *param_2,int param_3);
undefined4 * __cdecl FUN_10024600(int param_1);
int * __cdecl FUN_100246e0(int *param_1);
undefined4 __thiscall FUN_10024770(void *this,byte param_1);
void __cdecl FUN_10024830(int param_1,int param_2,int param_3,int param_4,int param_5);
void __cdecl FUN_100248e0(int param_1,int param_2,int param_3,int param_4);
void __fastcall FUN_10024950(undefined4 param_1,int *param_2);
void __cdecl FUN_10024a20(int param_1,int param_2);
void FUN_10024a80(void);
void __fastcall FUN_10024bb0(undefined4 param_1,int param_2);
void FUN_10024c10(void);
void __cdecl FUN_10024ca0(void *param_1);
void __cdecl FUN_10024ce0(undefined4 *param_1,byte *param_2);
int __cdecl FUN_10024d30(undefined4 *param_1,byte *param_2);
uint __cdecl FUN_10025120(int *param_1,byte *param_2);
int __cdecl FUN_100254c0(undefined4 param_1,byte *param_2);
undefined4 * FUN_10025550(void);
int __cdecl FUN_10025580(char *param_1,char *param_2);
undefined4 __cdecl FUN_100255d0(char *param_1,char *param_2);
undefined4 * __cdecl FUN_10025650(int param_1);
void __cdecl FUN_100256b0(void *param_1);
void __cdecl FUN_10025700(int param_1,int *param_2);
undefined1 __cdecl FUN_10025740(int param_1,int *param_2);
void __cdecl FUN_100257e0(int *param_1,int param_2);
void __cdecl FUN_100258c0(int param_1,undefined4 *param_2);
void __cdecl FUN_100258f0(int param_1,int param_2,int *param_3,char param_4);
void __cdecl FUN_10025aa0(byte *param_1,size_t param_2,int param_3);
void __cdecl FUN_10025b00(byte *param_1,int param_2,int param_3);
void __cdecl FUN_10025b80(int param_1,int *param_2,int *param_3);
uint __cdecl FUN_10025c90(int param_1,int param_2);
undefined4 __cdecl FUN_10025d10(int param_1,char *param_2);
void __cdecl FUN_10025d70(byte *param_1,int param_2,byte *param_3,uint *param_4);
void __cdecl FUN_10025dc0(byte *param_1,byte *param_2,uint *param_3);
int FUN_10025e10(void);
undefined4 * __cdecl FUN_10025f60(int param_1,int param_2,undefined4 param_3,undefined4 param_4);
void __cdecl FUN_10026000(void *param_1);
int __cdecl FUN_10026030(int *param_1,int param_2,undefined4 param_3);
undefined4 __cdecl FUN_100260e0(int param_1,int param_2);
undefined4 __cdecl FUN_100261a0(int param_1,int param_2);
undefined4 __cdecl FUN_10026280(int param_1,int param_2);
undefined4 __cdecl FUN_100262c0(int param_1);
undefined4 __cdecl FUN_100262d0(int param_1);
undefined4 __cdecl FUN_100262e0(int param_1,int *param_2,undefined4 *param_3);
void __cdecl FUN_10026400(uint *param_1,uint *param_2,int param_3);
void FUN_10026570(void);
void __cdecl FUN_100265c0(void *param_1,undefined4 param_2,int param_3,int param_4,byte *param_5,size_t param_6,undefined *param_7,undefined4 param_8,char param_9,char param_10,char param_11,char param_12);
void __cdecl FUN_100269a0(byte *param_1,int param_2,uint *param_3);
void __cdecl FUN_10026a90(byte *param_1,uint *param_2);
void __cdecl FUN_10026b80(undefined4 param_1,int param_2,undefined1 *param_3,int param_4);
void __cdecl FUN_10026c10(undefined4 param_1);
void __cdecl FUN_10026c30(int param_1,int param_2);
int __cdecl FUN_10026c80(int param_1,int param_2);
void __cdecl FUN_10026d60(void *param_1,undefined4 param_2,byte *param_3,size_t param_4,uint *param_5,int param_6,undefined *param_7,undefined4 param_8,char param_9);
int __thiscall FUN_10026e10(void *this,uint param_1);
void __thiscall FUN_10026e80(void *this,undefined4 param_1);
void __fastcall FUN_10026fa0(int param_1);
void __thiscall FUN_10027010(void *this,undefined4 param_1,byte *param_2);
void __thiscall FUN_100273b0(void *this,int param_1);
void FUN_10027430(byte *param_1,size_t param_2);
void __thiscall FUN_10027500(void *this,undefined4 param_1,byte *param_2,size_t param_3,int param_4);
void FUN_100275b0(char *param_1,size_t param_2);
void __cdecl FUN_100275e0(char *param_1,undefined1 *param_2,int param_3,char *param_4,size_t param_5);
int __cdecl FUN_10027670(int param_1,byte *param_2);
void __cdecl FUN_100276f0(int param_1,uint param_2);
int * __thiscall FUN_10027740(void *this,int *param_1,int *param_2,int param_3,int param_4);
void __thiscall FUN_10027bb0(void *this,int param_1);
int * __thiscall FUN_10027ee0(void *this,int param_1);
void __fastcall FUN_10027f20(int param_1);
void __thiscall FUN_10027f90(void *this,byte *param_1,char *param_2);
void __fastcall FUN_10028080(int param_1);
void __fastcall FUN_100280d0(undefined1 *param_1);
uint __thiscall FUN_10028100(void *this,char *param_1,byte *param_2,char *param_3,int param_4,undefined4 param_5);
void __thiscall FUN_10028260(void *this,byte *param_1);
void __thiscall FUN_100282a0(void *this,byte *param_1,int param_2);
int __thiscall FUN_10028350(void *this,int param_1);
undefined * __thiscall FUN_10028370(void *this,int param_1);
void __thiscall FUN_100283f0(void *this,int param_1,char *param_2,size_t param_3);
void __thiscall FUN_100284c0(void *this,int param_1,char *param_2);
int * __cdecl FUN_100285e0(int param_1);
void __cdecl FUN_10028640(int *param_1);
undefined4 * __cdecl FUN_10028690(int *param_1,size_t param_2);
u_long __cdecl FUN_10028700(u_long param_1);
u_long FUN_100287e0(void);
void __cdecl FUN_10028860(undefined4 *param_1);
undefined4 __cdecl FUN_10028ba0(uint param_1);
int __cdecl FUN_10028c00(char *param_1);
int FUN_10029010(void);
void __cdecl FUN_10029070(undefined4 *param_1);
void __fastcall FUN_10029550(int param_1);
undefined4 __cdecl FUN_10029630(int param_1,byte *param_2);
undefined4 * __cdecl FUN_10029690(int param_1,char *param_2);
void __cdecl FUN_10029700(int param_1);
void __cdecl FUN_10029760(int param_1,undefined1 param_2);
void __cdecl FUN_10029800(int param_1,char *param_2);
void FUN_10029830(void);
int FUN_10029910(void);
int __cdecl FUN_100299a0(byte *param_1,int param_2,int param_3);
int __cdecl FUN_10029a00(undefined4 param_1,int param_2);
int __cdecl FUN_10029af0(int param_1,char *param_2);
int __cdecl FUN_1002a1c0(int param_1);
undefined4 * FUN_1002a210(void);
void __cdecl FUN_1002a260(uint *param_1);
void __cdecl FUN_1002a320(uint *param_1,undefined4 param_2,char *param_3);
void __cdecl FUN_1002a360(uint *param_1);
void __cdecl FUN_1002a400(uint *param_1);
uint * __cdecl FUN_1002a4b0(uint *param_1);
undefined1 * __cdecl FUN_1002a500(uint *param_1,byte *param_2);
undefined1 * __cdecl FUN_1002a540(uint *param_1,int param_2,undefined4 *param_3);
uint __cdecl FUN_1002a570(uint *param_1,int param_2,uint param_3);
void __cdecl FUN_1002a5b0(int param_1,byte *param_2,char *param_3);
undefined4 __cdecl FUN_1002a630(uint *param_1);
void __cdecl FUN_1002a660(undefined4 param_1);
void __cdecl FUN_1002a690(void *param_1,char param_2);
undefined4 * __cdecl FUN_1002a6e0(undefined4 param_1,int param_2);
void __cdecl FUN_1002a710(int param_1,int param_2);
void __cdecl FUN_1002a740(int *param_1,int param_2);
int __cdecl FUN_1002a780(int param_1);
void __cdecl FUN_1002a7a0(int *param_1);
void __cdecl FUN_1002a7f0(int *param_1,int param_2,char param_3);
undefined4 * __cdecl FUN_1002a860(undefined4 *param_1);
int __cdecl FUN_1002a870(undefined4 param_1,int param_2);
void __cdecl FUN_1002a880(void *param_1);
undefined4 __cdecl FUN_1002a930(int param_1,int param_2,int param_3);
void __cdecl FUN_1002aa70(int param_1,byte *param_2);
void FUN_1002aa90(void);
byte * __cdecl FUN_1002aae0(int param_1,byte *param_2,int *param_3,uint *param_4,char param_5);
int FUN_1002acf0(void);
void __fastcall FUN_1002ad30(int param_1);
void FUN_1002ae40(void);
void FUN_1002b150(void);
void FUN_1002b2a0(void);
int * __cdecl FUN_1002b470(int param_1,int param_2,int *param_3);
void __cdecl FUN_1002b6d0(int param_1,int param_2);
void __cdecl FUN_1002b860(int param_1,undefined4 param_2,byte *param_3);
undefined4 __cdecl FUN_1002be20(int param_1,int param_2);
undefined4 __cdecl FUN_1002c0b0(int param_1);
undefined4 __cdecl FUN_1002c870(int param_1,int param_2);
undefined4 __cdecl FUN_1002cd00(void *param_1);
void __cdecl FUN_1002d3a0(int param_1,char *param_2,size_t param_3);
undefined4 __cdecl FUN_1002d440(int param_1,int param_2,int param_3);
char __cdecl FUN_1002d750(undefined4 param_1,int param_2,int param_3);
void __cdecl FUN_1002d7c0(byte *param_1,int param_2);
void __cdecl FUN_1002d850(void *param_1,int *param_2);
void __cdecl FUN_1002da50(int param_1);
undefined4 __cdecl FUN_1002dbd0(void *param_1,byte *param_2);
undefined4 __cdecl FUN_1002dd60(int param_1);
void __cdecl FUN_1002e610(int param_1,byte *param_2);
void __fastcall FUN_1002ea00(int *param_1);
undefined4 __cdecl FUN_1002ead0(int param_1,int param_2);
undefined4 __cdecl FUN_1002ee70(int param_1,int param_2);
undefined4 __cdecl FUN_1002f010(int param_1,int param_2);
undefined4 __cdecl FUN_1002f370(int param_1,byte *param_2);
undefined4 __cdecl FUN_1002f410(int param_1,int param_2);
undefined4 __thiscall FUN_1002f870(void *this,int param_1,int *param_2);
int __fastcall FUN_1002fcb0(undefined4 param_1,int param_2);
void __fastcall FUN_1002fcd0(int param_1);
undefined4 __cdecl FUN_1002fd70(int param_1,int param_2);
int __cdecl FUN_1002fec0(int param_1,char *param_2);
void __cdecl FUN_100301c0(char *param_1,undefined4 param_2);
void FUN_10030270(void);
undefined4 __cdecl FUN_10030350(char *param_1);
void __cdecl FUN_10030410(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,char *param_5,undefined4 param_6,char *param_7,char param_8);
void __cdecl FUN_100305a0(int param_1);
undefined4 __cdecl FUN_10030740(undefined4 param_1,undefined4 param_2,char param_3);
undefined1 __cdecl FUN_10030860(int param_1,int *param_2,int *param_3);
undefined4 __cdecl FUN_10030960(void *param_1,int *param_2);
undefined4 __cdecl FUN_10030cd0(int param_1,int param_2);
void __thiscall FUN_100311a0(void *this,int param_1,int *param_2);
void __cdecl FUN_10031220(int param_1,int *param_2);
void __cdecl FUN_100312f0(int param_1,int *param_2);
void __cdecl FUN_100313f0(int param_1,int *param_2);
void __cdecl FUN_10031470(int param_1,int *param_2);
uint __thiscall FUN_100314e0(void *this,int param_1);
void __cdecl FUN_10031510(int param_1,char param_2);
void __cdecl FUN_10031750(int param_1,int *param_2);
void FUN_10031970(void);
int __cdecl FUN_10031a90(int param_1,int *param_2,char param_3,undefined4 *param_4);
int __cdecl FUN_10032440(int param_1);
undefined4 __cdecl FUN_100332b0(int param_1,int param_2);
undefined4 __cdecl FUN_10033410(int param_1,int param_2);
undefined4 __cdecl FUN_10033860(int param_1,int param_2);
void __cdecl FUN_10033e30(int param_1);
undefined4 __cdecl FUN_10034010(int param_1,uint param_2);
undefined4 __fastcall FUN_10034530(int param_1);
undefined4 __cdecl FUN_100347d0(int param_1,int param_2);
undefined4 __cdecl FUN_10034c90(int param_1,int param_2);
void __cdecl FUN_10034dd0(int param_1);
uint * __cdecl FUN_10035370(int param_1,uint *param_2,char param_3);
undefined4 __cdecl FUN_10035400(int param_1,int param_2);
undefined4 FUN_10035ab0(int param_1,uint param_2);
undefined4 __cdecl FUN_10036a10(int param_1,int param_2);
undefined4 __cdecl FUN_100371f0(int param_1);
void __cdecl FUN_100373c0(int param_1,int param_2);
void __cdecl FUN_10037630(int param_1,int param_2);
void __cdecl FUN_10037720(void *param_1,int *param_2);
undefined4 __cdecl FUN_10037870(void *param_1,int param_2);
undefined4 * FUN_10038510(void);
void __cdecl FUN_10038540(void *param_1);
void __cdecl FUN_10038560(int param_1);
int __cdecl FUN_10038590(int param_1);
void __cdecl FUN_100385d0(int param_1,int param_2);
int * __cdecl FUN_10038610(int param_1);
void __cdecl FUN_10038670(int param_1,int param_2);
int __cdecl FUN_10038730(int param_1,char *param_2);
undefined4 __cdecl FUN_100387a0(int param_1,int *param_2,int param_3,undefined4 param_4,int param_5,char *param_6);
void __cdecl FUN_10038830(int param_1,undefined4 param_2,int param_3,undefined4 param_4,byte *param_5);
byte * __thiscall FUN_10038930(void *this,byte *param_1,char *param_2);
char * __thiscall FUN_100389c0(void *this,char *param_1,char *param_2);
void __fastcall FUN_10038a10(int param_1);
int __thiscall FUN_10038a50(void *this,byte *param_1);
byte * __thiscall thunk_FUN_10038930(void *this,byte *param_1,char *param_2);
void __thiscall FUN_10038a90(void *this,byte *param_1);
void __fastcall FUN_10038ac0(int param_1);
undefined4 __thiscall FUN_10038ad0(void *this,undefined4 *param_1,undefined1 *param_2,char *param_3,size_t param_4);
void __thiscall FUN_10038be0(void *this,int param_1);
void FUN_10038c00(void);
undefined4 __cdecl FUN_10038c70(int param_1,byte *param_2);
void __cdecl FUN_10038d80(char *param_1);
char FUN_10038dd0(void);
undefined4 __cdecl FUN_10038e70(int param_1,byte *param_2);
undefined4 FUN_10038ef0(void);
int FUN_10038f30(void);
undefined4 * FUN_10038f80(void);
void __cdecl FUN_10038fa0(undefined4 *param_1,byte *param_2);
void __cdecl FUN_100391b0(void *param_1);
int __cdecl FUN_100391f0(int *param_1,int param_2,byte *param_3);
void __cdecl FUN_100394a0(int *param_1,char *param_2,size_t param_3);
undefined4 __cdecl FUN_100396f0(int param_1);
void __cdecl FUN_10039770(undefined4 param_1,int param_2,int param_3);
void FUN_100397d0(void *param_1);
uint __cdecl FUN_10039830(uint *param_1,int param_2);
uint __cdecl FUN_10039900(int *param_1,int param_2,uint param_3);
void __cdecl FUN_10039930(int *param_1,int param_2);
void __cdecl FUN_10039970(int *param_1,int param_2);
undefined4 __cdecl FUN_10039aa0(int *param_1,int param_2,int param_3,int param_4);
int __cdecl FUN_10039bb0(int *param_1,int param_2,char *param_3,int param_4);
undefined4 __cdecl FUN_10039c20(int *param_1,int param_2);
undefined2 __cdecl FUN_10039c50(int *param_1,int param_2);
u_long __cdecl FUN_10039c80(int *param_1,int param_2);
void __cdecl FUN_10039cf0(int param_1);
void __cdecl FUN_10039d40(int param_1);
void __cdecl FUN_10039d80(int param_1,int param_2,undefined4 param_3);
void __cdecl FUN_10039ef0(undefined4 param_1,SOCKET param_2,undefined4 param_3,u_long param_4);
int * __cdecl FUN_1003a0d0(int *param_1,int param_2,undefined2 param_3,int param_4,int param_5,int param_6,int param_7);
undefined4 * __thiscall FUN_1003a3d0(void *this,int param_1,int param_2);
void __fastcall FUN_1003a410(undefined4 *param_1);
undefined4 __thiscall FUN_1003a420(void *this,DWORD param_1);
undefined4 * __thiscall FUN_1003a6a0(void *this,byte param_1);
void __cdecl FUN_1003a700(undefined4 param_1,int param_2);
void * FUN_1003a710(undefined4 param_1,char *param_2,size_t *param_3);
void __cdecl FUN_1003a7d0(undefined4 param_1,void *param_2);
void __cdecl FUN_1003ab30(int param_1,int param_2,int param_3);
void __cdecl FUN_1003b510(int param_1,int param_2);
void __cdecl FUN_1003b900(int param_1,int param_2,uint param_3);
undefined4 __cdecl FUN_1003be40(int param_1,int param_2,int param_3);
undefined4 __cdecl FUN_1003bfa0(int param_1,int param_2,int param_3);
undefined4 __cdecl FUN_1003c0a0(undefined4 param_1,int param_2);
undefined4 __cdecl FUN_1003c0d0(int param_1,int param_2,int param_3);
undefined4 __cdecl FUN_1003c180(int param_1,int param_2,int param_3);
undefined4 __cdecl FUN_1003c2a0(int param_1,int param_2,int param_3);
undefined4 __cdecl FUN_1003c680(int param_1,int param_2,int param_3);
undefined4 __cdecl FUN_1003cab0(int param_1,int param_2,int param_3);
void __cdecl FUN_1003cbd0(int param_1,int param_2);
void __cdecl FUN_1003d1d0(int param_1,int param_2,int param_3);
void __cdecl FUN_1003d4d0(int param_1,int param_2,int param_3);
void __cdecl FUN_1003d590(int param_1,int param_2,int param_3);
void __cdecl FUN_1003d8a0(undefined4 param_1,int param_2,int param_3);
void __cdecl FUN_1003da30(undefined4 param_1,int param_2,int param_3);
bool __cdecl FUN_1003dbe0(byte *param_1,byte *param_2);
int __cdecl FUN_1003dc50(char *param_1,size_t param_2,char *param_3,undefined4 param_4,char *param_5,char *param_6);
void __cdecl FUN_1003dd40(int param_1,char *param_2,int param_3,int param_4);
void __cdecl FUN_1003de40(int param_1,byte *param_2,int param_3);
undefined4 __cdecl FUN_1003dee0(char *param_1,int param_2,int param_3,char *param_4,int param_5,int param_6);
void __fastcall FUN_1003dfa0(int param_1);
undefined4 * __thiscall FUN_1003dfb0(void *this,uint param_1,int param_2,uint param_3,undefined4 param_4,undefined4 param_5,undefined4 param_6);
undefined4 __fastcall FUN_1003e050(int param_1);
void __fastcall FUN_1003e060(int param_1);
int __thiscall FUN_1003e080(void *this,int param_1);
int * __thiscall FUN_1003e0e0(void *this,int param_1);
void __cdecl FUN_1003e160(int param_1,undefined4 param_2);
void __cdecl FUN_1003e170(int *param_1);
int FUN_1003e1b0(undefined4 *param_1,int param_2);
undefined4 __cdecl FUN_1003e220(int param_1,char *param_2,char *param_3,char *param_4,uint param_5);
int __cdecl FUN_1003e4f0(int param_1,undefined4 param_2);
undefined4 * __cdecl FUN_1003e530(int param_1,int param_2);
int FUN_1003e5a0(void);
int __fastcall FUN_1003e600(undefined4 *param_1);
byte * __cdecl FUN_1003e670(int param_1,byte *param_2);
byte * __cdecl FUN_1003e7b0(int param_1,byte *param_2);
byte * __cdecl FUN_1003e900(undefined4 *param_1,byte *param_2);
byte * __cdecl FUN_1003ea10(undefined4 *param_1,byte *param_2);
byte * __cdecl FUN_1003ed40(undefined4 *param_1,byte *param_2);
byte * __cdecl FUN_1003ee30(undefined4 *param_1,byte *param_2);
byte * __cdecl FUN_1003ef20(undefined4 *param_1,byte *param_2);
byte * __cdecl FUN_1003f010(undefined4 *param_1,byte *param_2);
void __fastcall FUN_1003f0e0(undefined4 *param_1);
int __cdecl FUN_1003f120(undefined4 param_1,undefined4 param_2,byte *param_3,char *param_4,int param_5);
undefined4 * __cdecl FUN_1003f280(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,undefined4 param_6,undefined4 param_7);
void __cdecl FUN_1003f310(undefined4 *param_1);
void __cdecl FUN_1003f370(undefined4 *param_1);
void __cdecl FUN_1003f390(int *param_1);
uint __cdecl FUN_1003f3e0(uint *param_1,uint *param_2);
int WSAGetLastError(void);
void WSACreateEvent(void);
int setsockopt(SOCKET s,int level,int optname,char *optval,int optlen);
int ioctlsocket(SOCKET s,long cmd,u_long *argp);
SOCKET socket(int af,int type,int protocol);
void WSACloseEvent(void);
void WSARecv(void);
void WSARecvFrom(void);
void WSAResetEvent(void);
void WSAWaitForMultipleEvents(void);
void WSAGetOverlappedResult(void);
int WSAStartup(WORD wVersionRequired,LPWSADATA lpWSAData);
int closesocket(SOCKET s);
int shutdown(SOCKET s,int how);
void WSASetEvent(void);
int bind(SOCKET s,sockaddr *addr,int namelen);
int connect(SOCKET s,sockaddr *name,int namelen);
int sendto(SOCKET s,char *buf,int len,int flags,sockaddr *to,int tolen);
int send(SOCKET s,char *buf,int len,int flags);
int recv(SOCKET s,char *buf,int len,int flags);
int recvfrom(SOCKET s,char *buf,int len,int flags,sockaddr *from,int *fromlen);
int getsockname(SOCKET s,sockaddr *name,int *namelen);
hostent * gethostbyname(char *name);
int gethostname(char *name,int namelen);
void WSAIoctl(void);
int WSACleanup(void);
int __WSAFDIsSet(SOCKET param_1,fd_set *param_2);
float10 __cdecl FUN_1003f5a2(int param_1,int param_2);
__time32_t __cdecl FID_conflict:__time32(__time32_t *_Time);
void FUN_1003f5ed(void);
void __cdecl __fpmath(int param_1);
void __thiscall type_info::~type_info(type_info *this);
void FUN_1003f680(void);
void * __thiscall type_info::`scalar_deleting_destructor'(type_info *this,uint param_1);
int __cdecl _sprintf(char *_Dest,char *_Format,...);
void _JumpToContinuation(void *param_1,EHRegistrationNode *param_2);
void FID_conflict:_CallMemberFunction1(undefined4 param_1,undefined *UNRECOVERED_JUMPTABLE);
void _UnwindNestedFrames(EHRegistrationNode *param_1,EHExceptionRecord *param_2);
undefined4 __cdecl ___CxxFrameHandler(EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4);
int __cdecl _CallSETranslator(EHExceptionRecord *param_1,EHRegistrationNode *param_2,void *param_3,void *param_4,_s_FuncInfo *param_5,int param_6,EHRegistrationNode *param_7);
_EXCEPTION_DISPOSITION __cdecl TranslatorGuardHandler(EHExceptionRecord *param_1,TranslatorGuardRN *param_2,void *param_3,void *param_4);
_s_TryBlockMapEntry * __cdecl _GetRangeOfTrysToCheck(_s_FuncInfo *param_1,int param_2,int param_3,uint *param_4,uint *param_5);
FrameInfo * __cdecl _CreateFrameInfo(FrameInfo *param_1,void *param_2);
int __cdecl IsExceptionObjectToBeDestroyed(void *param_1);
void __cdecl _FindAndUnlinkFrame(FrameInfo *param_1);
void * __cdecl _CallCatchBlock2(EHRegistrationNode *param_1,_s_FuncInfo *param_2,void *param_3,int param_4,ulong param_5);
void __cdecl report_failure(void);
void __fastcall FUN_1003fb09(int param_1);
void __cdecl __global_unwind2(PVOID param_1);
void __cdecl __local_unwind2(int param_1,int param_2);
int __cdecl __abnormal_termination(void);
void __fastcall __NLG_Notify1(undefined4 param_1);
void FUN_1003fbee(void);
ulonglong FUN_1003fc08(void);
void __CxxThrowException@8(undefined4 param_1,undefined4 param_2);
char * __cdecl _strncpy(char *_Dest,char *_Source,size_t _Count);
undefined4 __CRT_INIT@12(undefined4 param_1,int param_2);
int entry(undefined4 param_1,int param_2,undefined4 param_3);
void __cdecl __amsg_exit(int param_1);
char * __cdecl _strchr(char *_Str,int _Val);
char * __cdecl _strstr(char *_Str,char *_SubStr);
longlong __allmul(uint param_1,int param_2,uint param_3,int param_4);
int __cdecl __snprintf(char *_Dest,size_t _Count,char *_Format,...);
tm * __cdecl _localtime(time_t *_Time);
tm * __cdecl _gmtime(time_t *_Time);
int __cdecl _strncmp(char *_Str1,char *_Str2,size_t _MaxCount);
void __chkstk(void);
int __cdecl __vsnprintf(char *_Dest,size_t _Count,char *_Format,va_list _Args);
uint __thiscall ___tolower_mt(void *this,int param_1,uint param_2);
int __cdecl _tolower(int _C);
void * __cdecl __heap_alloc(size_t _Size);
void FUN_1004075f(void);
void * __cdecl __nh_malloc(size_t _Size,int _NhFlag);
void * __cdecl _malloc(size_t _Size);
void __cdecl _free(void *_Memory);
void FUN_100407f9(void);
void __cdecl _free(void *_Memory);
void * __cdecl operator_new(uint param_1);
int __cdecl __fclose_lk(FILE *param_1);
int __cdecl _fclose(FILE *_File);
void FUN_100408bf(void);
char * __cdecl _fgets(char *_Buf,int _MaxCount,FILE *_File);
void FUN_10040945(void);
FILE * __cdecl __fsopen(char *_Filename,char *_Mode,int _ShFlag);
void FUN_1004099f(void);
void __cdecl FUN_100409a9(char *param_1,char *param_2);
long __cdecl _atol(char *_Str);
long __cdecl _atol(char *_Str);
void * __cdecl _realloc(void *_Memory,size_t _NewSize);
void FUN_10040bb1(void);
void __cdecl shortsort(undefined1 *param_1,int param_2,undefined *param_3);
void __cdecl _qsort(void *_Base,size_t _NumOfElements,size_t _SizeOfElements,_PtFuncCompare *_PtFuncCompare);
int __cdecl _strcmp(char *_Str1,char *_Str2);
int __cdecl __flush(FILE *_File);
int __cdecl __fflush_lk(FILE *param_1);
int __cdecl flsall(int param_1);
void FUN_100410b3(void);
void FUN_100410df(void);
int __cdecl _fflush(FILE *_File);
void FUN_1004112e(void);
void __cdecl __lock_file(FILE *_File);
void __cdecl __lock_file2(int _Index,void *_File);
void __cdecl __unlock_file(FILE *_File);
void __cdecl __unlock_file2(int _Index,void *_File);
int __cdecl _fprintf(FILE *_File,char *_Format,...);
void FUN_100412f6(void);
int __cdecl _sscanf(char *_Src,char *_Format,...);
void * __cdecl _memmove(void *_Dst,void *_Src,size_t _Size);
int __cdecl _vfprintf(FILE *_File,char *_Format,va_list _ArgList);
void FUN_100416d0(void);
uint __cdecl __fwrite_lk(char *param_1,uint param_2,uint param_3,FILE *param_4);
size_t __cdecl _fwrite(void *_Str,size_t _Size,size_t _Count,FILE *_File);
void FUN_10041823(void);
uint __cdecl __fread_lk(undefined1 *param_1,uint param_2,uint param_3,FILE *param_4);
size_t __cdecl _fread(void *_DstBuf,size_t _ElementSize,size_t _Count,FILE *_File);
void FUN_10041958(void);
undefined4 __cdecl FUN_10041962(LPCSTR param_1,LPCSTR param_2);
undefined4 __cdecl FUN_10041990(LPCSTR param_1);
double __cdecl _strtod(char *_Str,char **_EndPtr);
uint __cdecl strtoxl(byte *param_1,undefined4 *param_2,uint param_3,uint param_4);
long __cdecl _strtol(char *_Str,char **_EndPtr,int _Radix);
int __cdecl _isdigit(int _C);
int __cdecl _isxdigit(int _C);
int __cdecl _isspace(int _C);
char * __cdecl _strerror(char *_ErrMsg);
int * FUN_10041d35(void);
ulong * FUN_10041d3e(void);
void __cdecl __dosmaperr(ulong param_1);
int __cdecl __ftell_lk(uint *param_1);
long __cdecl _ftell(FILE *_File);
void FUN_10041f53(void);
int __cdecl __fseek_lk(FILE *param_1,int param_2,int param_3);
int __cdecl _fseek(FILE *_File,long _Offset,int _Origin);
void FUN_1004202b(void);
char * __cdecl _strrchr(char *_Str,int _Ch);
undefined8 __aulldiv(uint param_1,uint param_2,uint param_3,uint param_4);
void __cdecl __forcdecpt(char *_Buf);
void __cdecl __fassign(int flag,char *argument,char *number);
void __shift(void);
void __cdecl __cftoe2(int param_1,int param_2,char param_3);
errno_t __cdecl __cftoe(double *_Value,char *_Buf,size_t _SizeInBytes,int _Dec,int _Caps);
undefined1 * __cdecl __cftof2(undefined1 *param_1,size_t param_2,char param_3);
errno_t __cdecl __cftof(double *_Value,char *_Buf,size_t _SizeInBytes,int _Dec);
void __cdecl __cftog(double *param_1,undefined1 *param_2,size_t param_3,int param_4);
errno_t __cdecl __cfltcvt(double *arg,char *buffer,size_t sizeInBytes,int format,int precision,int caps);
void __setdefaultprecision(void);
undefined4 __ms_p5_test_fdiv(void);
void __ms_p5_mp_test_fdiv(void);
int __cdecl __mtinitlocks(void);
void __cdecl __mtdeletelocks(void);
void __cdecl FUN_100425f0(int param_1);
int __cdecl __mtinitlocknum(int _LockNum);
void FUN_1004269c(void);
void __cdecl __lock(int _File);
void __cdecl __SEH_prolog(undefined4 param_1,int param_2);
void __SEH_epilog(void);
void FUN_10042812(int param_1);
int __cdecl __flsbuf(int _Ch,FILE *_File);
void __cdecl write_char(void);
void __cdecl write_multi_char(undefined4 param_1,int param_2);
void __cdecl write_string(int param_1);
void __cdecl __output(undefined4 param_1,byte *param_2,wchar_t *param_3);
int __cdecl TypeMatch(_s_HandlerType *param_1,_s_CatchableType *param_2,_s_ThrowInfo *param_3);
void __cdecl ___FrameUnwindToState(int param_1,undefined4 param_2,int param_3,int param_4);
void FUN_100432ee(void);
void __cdecl ___DestructExceptionObject(int param_1);
void * __cdecl AdjustPointer(void *param_1,PMD *param_2);
void * __cdecl CallCatchBlock(EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,_s_FuncInfo *param_4,void *param_5,int param_6,ulong param_7);
void FUN_100434c2(void);
void __cdecl BuildCatchObject(EHExceptionRecord *param_1,void *param_2,_s_HandlerType *param_3,_s_CatchableType *param_4);
void __cdecl CatchIt(EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4,_s_FuncInfo *param_5,_s_HandlerType *param_6,_s_CatchableType *param_7,_s_TryBlockMapEntry *param_8,int param_9,EHRegistrationNode *param_10,uchar param_11);
void __cdecl FindHandlerForForeignException(EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4,_s_FuncInfo *param_5,int param_6,int param_7,EHRegistrationNode *param_8);
void __cdecl FindHandler(EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4,_s_FuncInfo *param_5,uchar param_6,int param_7,EHRegistrationNode *param_8);
undefined4 __cdecl ___InternalCxxFrameHandler(EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4,_s_FuncInfo *param_5,int param_6,EHRegistrationNode *param_7,uchar param_8);
void FUN_10043a78(void);
void __cdecl __mtterm(void);
void __cdecl __initptd(_ptiddata _Ptd,pthreadlocinfo _Locale);
_ptiddata __cdecl __getptd(void);
void __freefls@4(void *param_1);
void FUN_10043c54(void);
void FUN_10043c60(void);
void __cdecl __freeptd(_ptiddata _Ptd);
int __cdecl __mtinit(void);
void __cdecl terminate(void);
void __cdecl _inconsistency(void);
void __CallSettingFrame@12(undefined4 param_1,undefined4 param_2,int param_3);
void __cdecl ___security_init_cookie(void);
void ___security_error_handler(int param_1);
long __CxxUnhandledExceptionFilter(_EXCEPTION_POINTERS *param_1);
void __cdecl ___crtExitProcess(int param_1);
void FUN_10044088(void);
void FUN_10044091(void);
void __cdecl __initterm(undefined4 *param_1);
int __cdecl __cinit(int param_1);
void __cdecl doexit(UINT param_1,int param_2,int param_3);
void FUN_100441cb(void);
void __cdecl __exit(int _Code);
void __cdecl __cexit(void);
void * __cdecl _calloc(size_t _Count,size_t _Size);
void FUN_100442a9(void);
int __cdecl __ioinit(void);
void __cdecl __ioterm(void);
int __cdecl __setenvp(void);
void __cdecl parse_cmdline(undefined4 *param_1,int *param_2);
int __cdecl __setargv(void);
LPVOID __cdecl ___crtGetEnvironmentStringsA(void);
void __RTC_Initialize(void);
undefined4 ___heap_select(void);
int __cdecl __heap_init(void);
void __cdecl __heap_term(void);
int __cdecl __XcptFilter(ulong _ExceptionNum,_EXCEPTION_POINTERS *_ExceptionPtr);
void __cdecl __NMSG_WRITE(int param_1);
void __cdecl __FF_MSGBANNER(void);
void __tzset_lk(void);
void FUN_10044fb7(void);
int __cdecl cvtdate(int param_1,int param_2,int param_3,int param_4,int param_5,int param_6,int param_7,int param_8,int param_9);
bool __isindst_lk(void);
void __cdecl ___tzset(void);
void FUN_100453c6(void);
int __cdecl __isindst(tm *_Time);
void FUN_10045404(void);
int __cdecl ___crtLCMapStringA(_locale_t _Plocinfo,LPCWSTR _LocaleName,DWORD _DwMapFlag,LPCSTR _LpSrcStr,int _CchSrc,LPSTR _LpDestStr,int _CchDest,int _Code_page,BOOL _BError);
uint __thiscall ___isctype_mt(void *this,int param_1,int param_2,uint param_3);
void __cdecl ___freetlocinfo(void *param_1);
int ___updatetlocinfo_lk(void);
pthreadlocinfo __cdecl ___updatetlocinfo(void);
void FUN_10045a03(void);
undefined4 ___sbh_heap_init(undefined4 param_1);
uint __cdecl ___sbh_find_block(int param_1);
void __cdecl ___sbh_free_block(uint *param_1,int param_2);
undefined4 * ___sbh_alloc_new_region(void);
int __cdecl ___sbh_alloc_new_group(int param_1);
undefined4 __cdecl ___sbh_resize_block(uint *param_1,int param_2,int param_3);
int * __cdecl ___sbh_alloc_block(uint *param_1);
int __cdecl __callnewh(size_t _Size);
undefined4 __cdecl __close_lk(uint param_1);
int __cdecl __close(int _FileHandle);
void FUN_10046644(void);
void __cdecl __freebuf(FILE *_File);
int __cdecl __filbuf(FILE *_File);
FILE * __cdecl __openfile(char *_Filename,char *_Mode,int _ShFlag,FILE *_File);
FILE * __cdecl __getstream(void);
void FUN_100469f5(void);
void * __cdecl _memcpy(void *_Dst,void *_Src,size_t _Size);
void __cdecl __write_lk(uint param_1,char *param_2,uint param_3);
int __cdecl __write(int _FileHandle,void *_Buf,uint _MaxCharCount);
void FUN_10046f92(void);
int __cdecl __commit(int _FileHandle);
void FUN_10047056(void);
int __cdecl __stbuf(FILE *_File);
void __cdecl __ftbuf(int _Flag,FILE *_File);
uint __fastcall __inc(undefined4 param_1,FILE *param_2);
void __cdecl __input(FILE *param_1,byte *param_2,undefined4 *param_3);
size_t __cdecl _strlen(char *_Str);
int __cdecl __read_lk(uint param_1,char *param_2,char *param_3);
int __cdecl __read(int _FileHandle,void *_DstBuf,uint _MaxCharCount);
void FUN_1004824d(void);
FLT __cdecl __fltin2(FLT _Flt,char *_Str,_locale_t _Locale);
uint * __cdecl FUN_10048310(uint *param_1,uint *param_2);
uint * __cdecl FUN_10048320(uint *param_1,uint *param_2);
DWORD __cdecl __lseek_lk(uint param_1,LONG param_2,DWORD param_3);
long __cdecl __lseek(int _FileHandle,long _Offset,int _Origin);
void FUN_10048503(void);
undefined4 __cdecl __ZeroTail(int param_1,int param_2);
void __cdecl __IncMan(int param_1,int param_2);
undefined4 __cdecl __RoundMan(int param_1,int param_2);
void __cdecl __CopyMan(int param_1,undefined4 *param_2);
undefined4 __cdecl __IsZeroMan(int param_1);
void __cdecl __ShrMan(int param_1,int param_2);
undefined4 __cdecl __ld12cvt(ushort *param_1,uint *param_2,int *param_3);
INTRNCVT_STATUS __cdecl __ld12tod(_LDBL12 *_Ifp,_CRT_DOUBLE *_D);
INTRNCVT_STATUS __cdecl __ld12tof(_LDBL12 *_Ifp,_CRT_FLOAT *_F);
int __cdecl FID_conflict:__atodbl(_CRT_FLOAT *_Result,char *_Str);
int __cdecl FID_conflict:__atodbl(_CRT_FLOAT *_Result,char *_Str);
errno_t __cdecl __fptostr(char *_Buf,size_t _SizeInBytes,int _Digits,STRFLT _PtFlt);
void __cdecl ___dtold(uint *param_1,uint *param_2);
STRFLT __cdecl __fltout2(_CRT_DOUBLE _Dbl,STRFLT _Flt,char *_ResultStr,size_t _SizeInBytes);
void * __cdecl _memset(void *_Dst,int _Val,size_t _Size);
void __cdecl __fptrap(void);
uint __abstract_cw(void);
uint __hw_cw(void);
uint __cdecl __control87(uint _NewValue,uint _Mask);
uint __cdecl __controlfp(uint _NewValue,uint _Mask);
undefined4 ___crtInitCritSecNoSpinCount@8(LPCRITICAL_SECTION param_1);
void __cdecl ___crtInitCritSecAndSpinCount(undefined4 param_1,undefined4 param_2);
undefined4 __cdecl __ValidateEH3RN(void *param_1);
void __cdecl __getbuf(FILE *_File);
int __cdecl __isatty(int _FileHandle);
int __cdecl ___wctomb_mt(int param_1,LPSTR param_2,WCHAR param_3);
int __cdecl _wctomb(char *_MbCh,wchar_t _WCh);
undefined8 __aulldvrm(uint param_1,uint param_2,uint param_3,uint param_4);
int __cdecl _ValidateRead(void *param_1,uint param_2);
int __cdecl _ValidateWrite(void *param_1,uint param_2);
int __cdecl _ValidateExecute(_func_int *param_1);
undefined4 _CPtoLCID(void);
void __cdecl setSBCS(void);
void __cdecl setSBUpLow(void);
pthreadmbcinfo __cdecl ___updatetmbcinfo(void);
void FUN_1004932f(void);
void __cdecl __setmbcp_lk(UINT param_1);
int __cdecl __setmbcp(int _CodePage);
void FUN_1004960f(void);
undefined4 ___initmbctable(void);
void __cdecl _abort(void);
int __cdecl ___crtMessageBoxA(LPCSTR _LpText,LPCSTR _LpCaption,UINT _UType);
void __onexit_lk(void);
_onexit_t __cdecl __onexit(_onexit_t _Func);
void FUN_10049821(void);
int __cdecl _atexit(_func_4879 *param_1);
int __cdecl __getenv_lk(uchar *param_1);
void __cdecl ___ansicp(LCID param_1);
void __cdecl ___convertcp(UINT param_1,UINT param_2,char *param_3,size_t *param_4,LPSTR param_5,int param_6);
int __cdecl __resetstkoflw(void);
BOOL __cdecl ___crtGetStringTypeA(_locale_t _Plocinfo,DWORD _DWInfoType,LPCSTR _LpSrcStr,int _CchSrc,LPWORD _LpCharType,int _Code_page,BOOL _BError);
void __cdecl ___free_lc_time(undefined4 *param_1);
void __cdecl ___free_lconv_num(undefined4 *param_1);
void __cdecl ___free_lconv_mon(int param_1);
size_t __cdecl _strcspn(char *_Str,char *_Control);
char * __cdecl _strpbrk(char *_Str,char *_Control);
int __cdecl __set_osfhnd(int param_1,intptr_t param_2);
int __cdecl __free_osfhnd(int param_1);
intptr_t __cdecl __get_osfhandle(int _FileHandle);
int __cdecl __lock_fhandle(int _Filehandle);
void FUN_1004a353(void);
void __cdecl __unlock_fhandle(int _Filehandle);
int __cdecl __alloc_osfhnd(void);
void FUN_1004a457(void);
void FUN_1004a4f1(void);
uint __thiscall __tsopen_lk(void *this,undefined4 *param_1,uint *param_2,LPCSTR param_3,uint param_4,byte param_5);
int __cdecl __sopen(char *_Filename,int _OpenFlag,int _ShareFlag,...);
void FUN_1004a826(void);
undefined8 __cdecl __lseeki64_lk(uint param_1,LONG param_2,LONG param_3,DWORD param_4);
uint __cdecl __ungetc_lk(uint param_1,FILE *param_2);
undefined4 __cdecl ___mbtowc_mt(int param_1,LPWSTR param_2,byte *param_3,uint param_4);
int __cdecl _mbtowc(wchar_t *_DstCh,char *_SrcCh,size_t _SrcSizeInBytes);
uint __cdecl ___strgtold12(_LDBL12 *pld12,char **p_end_ptr,char *str,int mult12,int scale,int decpt,int implicit_E);
undefined4 __cdecl ___addl(uint param_1,uint param_2,uint *param_3);
void __cdecl ___add_12(uint *param_1,uint *param_2);
void __cdecl ___shl_12(uint *param_1);
void __cdecl ___shr_12(uint *param_1);
void __cdecl ___mtold12(char *param_1,int param_2,uint *param_3);
void __cdecl$I10_OUTPUT(int param_1,uint param_2,uint param_3,int param_4,byte param_5,short *param_6);
void __cdecl siglookup(void);
int __cdecl _raise(int _SigNum);
void __fastcall FUN_1004b3f3(int param_1);
size_t __cdecl __msize(void *_Memory);
void FUN_1004b49e(void);
int __cdecl __mbsnbicoll(uchar *_Str1,uchar *_Str2,size_t _MaxCount);
int __cdecl ___wtomb_environ(void);
int __cdecl ___ascii_stricmp(char *_Str1,char *_Str2);
int __cdecl __stricmp(char *_Str1,char *_Str2);
void __cdecl __chsize_lk(uint param_1,int param_2);
void __cdecl ___ld12mul(int *param_1,int *param_2);
void __cdecl ___multtenpow12(int *param_1,uint param_2,int param_3);
size_t __cdecl _strncnt(char *_String,size_t _Cnt);
int __cdecl ___crtCompareStringA(_locale_t _Plocinfo,LPCWSTR _LocaleName,DWORD _DwCmpFlags,LPCSTR _LpString1,int _CchCount1,LPCSTR _LpString2,int _CchCount2,int _Code_page);
int __cdecl findenv(uchar *param_1);
int * __cdecl copy_environ(void);
int __cdecl ___crtsetenv(char **_POption,int _Primary);
int __cdecl ___ascii_strnicmp(char *_Str1,char *_Str2,size_t _MaxCount);
int __cdecl __setmode_lk(uint param_1,int param_2);
char * __cdecl __strdup(char *_Src);
uchar * __cdecl __mbschr(uchar *_Str,uint _Ch);
UCHAR Netbios(PNCB pncb);
void RtlUnwind(PVOID TargetFrame,PVOID TargetIp,PEXCEPTION_RECORD ExceptionRecord,PVOID ReturnValue);
int __cdecl __mbsicmp(uchar *_Str1,uchar *_Str2);
uchar * __cdecl __mbsrchr(uchar *_Str,uint _Ch);
int __cdecl ___loctotime_t(int param_1,int param_2,int param_3,int param_4,int param_5,int param_6,int param_7);
char * __cdecl __fullpath(char *_FullPath,char *_Path,size_t _SizeInBytes);
uint __cdecl __mbctolower(uint _Ch);
char * __cdecl ___mbspbrk_mt(int param_1,byte *param_2,byte *param_3);
int __cdecl __validdrive(uint param_1);
void __cdecl __getdcwd_lk(uint param_1,uint *param_2,size_t param_3);
char * __cdecl __getcwd(char *_DstBuf,int _SizeInBytes);
void FUN_1004cd3b(void);
uint __thiscall ___toupper_mt(void *this,int param_1,uint param_2);
void Unwind@1004ce40(void);
void Unwind@1004ce60(void);
void Unwind@1004ce80(void);
void Unwind@1004cea0(void);
void Unwind@1004ceae(void);
void Unwind@1004ced0(void);
void Unwind@1004cef0(void);
void Unwind@1004cf10(void);
void Unwind@1004cf30(void);
void Unwind@1004cf50(void);
void Unwind@1004cf70(void);


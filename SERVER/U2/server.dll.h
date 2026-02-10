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

typedef DWORD (*PTHREAD_START_ROUTINE)(LPVOID);

typedef PTHREAD_START_ROUTINE LPTHREAD_START_ROUTINE;

typedef struct _OVERLAPPED *LPOVERLAPPED;

typedef struct _SECURITY_ATTRIBUTES *LPSECURITY_ATTRIBUTES;

typedef struct _STARTUPINFOA _STARTUPINFOA, *P_STARTUPINFOA;

typedef char CHAR;

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
    char pdbpath[90];
};

typedef struct _strflt _strflt, *P_strflt;

struct _strflt {
    int sign;
    int decpt;
    int flag;
    char *mantissa;
};

typedef enum enum_3272 {
    INTRNCVT_OK=0,
    INTRNCVT_OVERFLOW=1,
    INTRNCVT_UNDERFLOW=2
} enum_3272;

typedef enum enum_3272 INTRNCVT_STATUS;

typedef struct _strflt *STRFLT;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME *LPFILETIME;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

typedef int (*FARPROC)(void);

typedef uchar UCHAR;

typedef UCHAR *PUCHAR;

typedef WORD *LPWORD;

typedef DWORD *LPDWORD;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

struct HINSTANCE__ {
    int unused;
};

typedef struct _FILETIME FILETIME;

typedef DWORD *PDWORD;

typedef BOOL *LPBOOL;

typedef struct HINSTANCE__ *HINSTANCE;

typedef void *LPCVOID;

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ *HWND;

struct HWND__ {
    int unused;
};

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

typedef UINT_PTR SOCKET;

typedef ushort u_short;

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
void Catch@100014ad(void);
void __cdecl FUN_10001510(SIZE_T param_1);
void __cdecl FUN_10001530(LPVOID param_1);
undefined4 FUN_10001550(undefined4 param_1,int param_2);
uint __cdecl StartServer(char *param_1,int param_2,undefined4 param_3,undefined4 param_4);
void __cdecl FUN_10001640(PUCHAR param_1);
undefined4 FUN_10001710(void);
void __cdecl FUN_10001750(int param_1,undefined4 *param_2);
undefined4 FUN_10001850(void);
void __cdecl FUN_10001870(int param_1);
void __cdecl FUN_100018d0(int param_1,int param_2,int param_3);
void __cdecl FUN_10001940(int *param_1,char *param_2,char *param_3,char *param_4);
void __cdecl FUN_10001a40(int param_1);
undefined4 * FUN_10001a60(void);
void __cdecl FUN_10001aa0(LPVOID param_1);
void FUN_10001ac0(void);
void FUN_10001b20(void);
void __fastcall FUN_10001b40(int param_1);
undefined4 * __cdecl FUN_10001b90(undefined4 *param_1);
uint __cdecl FUN_10001ce0(int *param_1);
int __cdecl FUN_10001d70(int param_1);
int __cdecl FUN_10001dc0(byte *param_1,int param_2,byte *param_3);
undefined1 __cdecl FUN_10001ff0(undefined1 param_1);
byte * __cdecl FUN_10002000(byte *param_1,byte *param_2);
void __cdecl FUN_100020d0(byte *param_1,byte *param_2,byte *param_3);
undefined4 __cdecl FUN_100021b0(byte *param_1,byte *param_2);
int __cdecl FUN_10002230(char *param_1,int param_2,char *param_3);
int __cdecl FUN_10002270(char *param_1,char *param_2,int param_3);
void __cdecl FUN_10002310(byte *param_1,int param_2,byte *param_3,int param_4);
void __cdecl FUN_100023e0(byte *param_1,int param_2,byte *param_3,uint param_4);
void __cdecl FUN_10002490(byte *param_1,int param_2,byte *param_3,uint param_4);
void __cdecl FUN_10002620(byte *param_1,int param_2,byte *param_3,byte *param_4);
void __cdecl FUN_100027a0(byte *param_1,int param_2,char *param_3,byte *param_4,int param_5);
void __cdecl FUN_10002880(byte *param_1,int param_2,byte *param_3,uint *param_4,int param_5,byte *param_6);
void __cdecl FUN_10002ad0(byte *param_1,int param_2,byte *param_3,int param_4);
void __cdecl FUN_10002bb0(byte *param_1,int param_2,byte *param_3,byte *param_4);
int __cdecl FUN_10002bf0(byte *param_1,int param_2,byte *param_3);
int __cdecl FUN_10002c50(byte *param_1,byte *param_2,byte *param_3);
int __cdecl FUN_10002e80(byte *param_1,int param_2);
uint __cdecl FUN_10002ed0(char *param_1,uint param_2);
uint __cdecl FUN_10002f10(byte *param_1,uint param_2);
int __cdecl FUN_10002f60(byte *param_1,byte *param_2,int param_3,byte *param_4,int param_5,uint param_6);
int __cdecl FUN_100030f0(byte *param_1,byte *param_2,int param_3,byte *param_4);
int __cdecl FUN_10003280(char *param_1,int param_2,int param_3);
void __cdecl FUN_10003360(byte *param_1,uint *param_2,int param_3,byte *param_4);
void __cdecl FUN_100035f0(char *param_1,int param_2);
undefined4 __cdecl FUN_100037e0(char *param_1,int *param_2,int *param_3,undefined4 *param_4,undefined4 *param_5,undefined4 *param_6,undefined4 *param_7);
void FUN_100038f0(void);
int FUN_10003970(void);
void FUN_100039c0(undefined4 *param_1);
void __cdecl FUN_10003a60(int param_1);
undefined4 * __cdecl FUN_10003ae0(int param_1,int param_2,int param_3);
undefined4 __cdecl FUN_10003b90(int *param_1);
int __cdecl FUN_10003c20(int param_1,sockaddr *param_2,int param_3);
void __cdecl FUN_10003c90(uint param_1,byte *param_2,int param_3,undefined4 param_4,int param_5,int param_6);
int __cdecl FUN_10003da0(int param_1,char *param_2,int param_3,byte param_4,sockaddr *param_5,int *param_6);
undefined4 __cdecl FUN_10003e30(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5);
void __cdecl FUN_10003e60(undefined4 *param_1,uint param_2,sockaddr *param_3,uint param_4);
void FUN_10004050(void);
void FUN_100040a0(void);
void __fastcall FUN_10004140(undefined4 param_1,byte *param_2);
void __fastcall FUN_10004180(undefined4 param_1,int param_2);
void __cdecl FUN_100041f0(undefined4 param_1,undefined4 param_2,DWORD *param_3);
undefined4 __thiscall FUN_100045e0(void *this,DWORD *param_1,char *param_2,char *param_3,char *param_4,char *param_5,int param_6);
int __cdecl FUN_10004860(DWORD *param_1,int param_2,int param_3);
void __cdecl FUN_100048d0(int param_1);
void __cdecl FUN_10004a60(DWORD *param_1);
DWORD GetTickCount(void);
void __cdecl FUN_10004b10(undefined4 *param_1);
void __cdecl FUN_10004b40(undefined4 *param_1);
undefined4 __cdecl FUN_10004b60(DWORD *param_1);
void __cdecl FUN_10004bb0(DWORD *param_1);
void __cdecl FUN_10004c40(undefined4 *param_1);
void __cdecl FUN_10004c70(int param_1,int param_2);
void __cdecl FUN_10004ca0(int param_1,int param_2);
void FUN_10004d00(void);
void FUN_10004d40(void);
void __cdecl FUN_10004e60(int param_1);
void FUN_10004f00(void);
void FUN_10004f60(void);
char * __cdecl FUN_10004f70(int param_1,char *param_2,int param_3);
undefined4 __cdecl FUN_10005110(undefined4 param_1,int param_2);
undefined4 __cdecl FUN_10005210(undefined4 param_1,int param_2);
undefined4 __cdecl FUN_10005360(undefined4 *param_1,int param_2);
void FUN_10005420(void);
void FUN_10005570(void);
int __cdecl FUN_100055b0(char *param_1);
undefined4 __cdecl FUN_10005600(byte *param_1,byte *param_2);
void __cdecl FUN_100056f0(void *param_1);
undefined4 __cdecl FUN_100060e0(int param_1,int param_2,int *param_3);
undefined4 FUN_100064c0(void);
void __cdecl FUN_100065e0(int *param_1,int param_2,int param_3);
void __cdecl FUN_10006690(int param_1,int param_2,int *param_3);
char __cdecl FUN_10006840(int param_1,int param_2,int param_3);
void FUN_10006960(void);
undefined4 __cdecl FUN_10006a50(int param_1);
undefined4 __cdecl FUN_10006b70(int *param_1);
undefined4 __cdecl FUN_10006d70(int *param_1);
int __cdecl FUN_10006e20(int param_1);
undefined4 * __cdecl FUN_10006f10(int param_1,undefined4 param_2,undefined4 param_3,byte *param_4,byte *param_5);
void __cdecl FUN_100073b0(void *param_1);
void __cdecl FUN_10007680(int param_1,undefined4 param_2,byte *param_3);
undefined4 __cdecl FUN_10007a20(int param_1,int param_2,int param_3,int *param_4,int *param_5,undefined4 *param_6,undefined4 param_7,undefined4 *param_8,undefined4 param_9,undefined4 param_10);
void __cdecl FUN_10007bc0(int param_1);
void __cdecl FUN_10007d00(int param_1,byte *param_2,undefined2 param_3);
void __cdecl FUN_10008100(int param_1);
void __cdecl FUN_10008190(byte *param_1,int param_2,int param_3,int param_4);
void __cdecl FUN_10009ad0(int param_1,int param_2,char *param_3,int param_4);
void __cdecl FUN_10009fd0(int param_1,int param_2,int param_3,int param_4);
void __cdecl FUN_1000a130(int param_1,int param_2);
void __cdecl FUN_1000a180(byte *param_1,int param_2,undefined4 *param_3);
void __cdecl FUN_1000b920(int param_1);
undefined4 __thiscall FUN_1000bae0(void *this,byte *param_1);
undefined4 __cdecl FUN_1000bbf0(int param_1);
undefined4 __cdecl FUN_1000bcf0(int param_1,byte *param_2);
undefined4 __cdecl FUN_1000be00(int *param_1);
undefined4 FUN_1000c0c0(void);
undefined4 __cdecl FUN_1000c180(int *param_1);
int FUN_1000c2a0(void);
void __cdecl FUN_1000c3b0(int param_1);
undefined4 __cdecl FUN_1000c480(undefined4 param_1,int param_2);
undefined4 __cdecl FUN_1000c5f0(int param_1,int param_2);
undefined4 __cdecl FUN_1000c9b0(int param_1);
void __cdecl FUN_1000ca40(int param_1,uint param_2,uint param_3,uint param_4,char *param_5,char *param_6);
void __cdecl FUN_1000cb40(int param_1,int param_2);
void __cdecl FUN_1000cbb0(int param_1,undefined4 param_2,char *param_3,int param_4,int param_5);
void __cdecl FUN_1000cc00(int param_1);
void __cdecl FUN_1000cc90(int param_1,uint param_2,char *param_3,byte *param_4);
void __cdecl FUN_1000cd80(int param_1,uint param_2,char *param_3,char *param_4);
void __cdecl FUN_1000cde0(int param_1,uint param_2,char *param_3);
int * __cdecl FUN_1000ce30(int param_1,uint *param_2,uint param_3);
int * __cdecl FUN_1000cf40(int param_1,int param_2,undefined4 param_3,byte *param_4,byte *param_5);
void __cdecl FUN_1000d4d0(int *param_1,int param_2,byte *param_3);
void __cdecl FUN_1000f020(uint param_1);
void __cdecl FUN_1000f090(int *param_1);
void __cdecl FUN_1000f300(int param_1);
void __fastcall FUN_1000f3b0(int param_1);
void __fastcall FUN_1000f460(int param_1);
void __fastcall FUN_1000f550(undefined4 param_1,int param_2);
undefined4 FUN_1000f5d0(void);
undefined4 __cdecl FUN_1000f6a0(uint *param_1,uint *param_2);
char __cdecl FUN_1000fb50(int param_1,int *param_2,uint param_3);
undefined4 __cdecl FUN_1000ff40(int param_1,int *param_2,int param_3);
undefined4 __thiscall FUN_10010010(void *this,int param_1,int *param_2,int param_3);
undefined4 __cdecl FUN_100100c0(int param_1,int *param_2,int param_3);
int __cdecl FUN_100102e0(int param_1);
void FUN_10010330(void *param_1);
void __cdecl FUN_10010420(int param_1,byte *param_2);
void __cdecl FUN_10010510(int param_1);
uint __cdecl FUN_10010520(uint *param_1,int param_2);
undefined4 * __cdecl FUN_100105b0(int param_1,int param_2,int param_3);
void __cdecl FUN_10010640(int param_1,int param_2,int param_3);
void __cdecl FUN_10010670(uint *param_1,int param_2);
uint __cdecl FUN_100106a0(uint *param_1,uint param_2);
uint __cdecl FUN_100106d0(uint *param_1,uint param_2);
uint __cdecl FUN_10010700(uint *param_1);
void FUN_10010a10(int param_1,SOCKET *param_2);
char * __cdecl FUN_10010a30(undefined4 param_1,int param_2,undefined4 param_3,undefined4 param_4,char *param_5,char *param_6);
undefined1 * __cdecl FUN_10010c00(int param_1,char *param_2);
void __cdecl FUN_10010c30(int param_1,undefined1 param_2);
undefined4 * __cdecl FUN_10010e80(byte *param_1,byte *param_2);
undefined4 __cdecl FUN_10010f50(int *param_1,char *param_2,char *param_3);
undefined4 * __cdecl FUN_10011500(undefined4 param_1);
void __cdecl FUN_10011550(void *param_1);
undefined4 __cdecl FUN_10011580(int param_1,int param_2);
undefined4 FUN_100115d0(void);
undefined4 FUN_100116e0(void);
undefined * FUN_100116f0(void);
void __cdecl FUN_10011700(undefined4 param_1,byte *param_2,undefined4 param_3,int param_4);
undefined4 FUN_100117d0(void);
undefined1 FUN_100117e0(void);
void __fastcall FUN_10011870(undefined4 param_1,int param_2);
char * __cdecl FUN_10011960(char *param_1,int param_2);
void __cdecl FUN_100119c0(void *param_1);
undefined4 __cdecl FUN_100119e0(undefined4 param_1);
bool __cdecl FUN_100119f0(int param_1,int param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,undefined4 param_6,undefined4 param_7,char *param_8,undefined4 param_9,undefined4 param_10,char *param_11,char *param_12);
char * __cdecl FUN_10011b60(int param_1,undefined4 param_2,int param_3,char *param_4);
bool __cdecl FUN_10011c00(int param_1);
undefined4 __cdecl FUN_10011c20(int param_1);
void __cdecl FUN_10011c30(int param_1,int param_2);
void __cdecl FUN_10011c50(int param_1,int param_2,int param_3);
void __cdecl FUN_10011ca0(int param_1,int param_2);
void __cdecl FUN_10011ce0(int param_1,int param_2,uint param_3);
void __cdecl FUN_10011d90(undefined4 *param_1);
undefined4 __cdecl FUN_10011dd0(char *param_1,char *param_2,char *param_3);
void __cdecl FUN_10011e30(int *param_1,undefined1 *param_2);
void __cdecl FUN_10011eb0(int param_1,int param_2,int param_3,int param_4);
int * __cdecl FUN_10011f70(undefined4 param_1);
void __cdecl FUN_100120c0(undefined4 *param_1);
byte * __cdecl FUN_10012100(undefined4 *param_1,byte *param_2,char *param_3,char *param_4);
char * __cdecl FUN_10012190(char *param_1,int param_2,int param_3);
void __cdecl FUN_100122c0(char *param_1);
void __cdecl FUN_10012300(char *param_1,char *param_2,uint param_3);
void __cdecl FUN_100123b0(char *param_1,char *param_2,byte *param_3);
void __cdecl FUN_10012570(char *param_1);
void __cdecl FUN_100125c0(int param_1);
void __cdecl FUN_10012e70(undefined4 *param_1);
void __cdecl FUN_10012ea0(uint *param_1,char *param_2,int param_3);
void __cdecl FUN_10012f00(uint *param_1,undefined1 *param_2,int param_3);
undefined4 * __cdecl FUN_10012fe0(undefined4 param_1);
undefined * FUN_10013010(void);
undefined4 FUN_10013040(void);
undefined1 * FUN_10013050(void);
undefined1 FUN_10013080(void);
void __cdecl FUN_10013090(undefined4 param_1,undefined4 *param_2,int param_3,byte *param_4);
int __cdecl FUN_100130c0(char *param_1);
void __thiscall FUN_100131a0(void *this,undefined4 *param_1,int param_2,undefined4 param_3,undefined4 *param_4);
int * __cdecl FUN_10013350(undefined4 param_1,int param_2,int param_3);
undefined4 __cdecl FUN_10013510(int param_1,int param_2,int param_3);
undefined4 __cdecl FUN_10014510(int param_1,int param_2,int param_3);
undefined4 __cdecl FUN_10014ca0(int param_1,int param_2,int param_3);
undefined4 __cdecl FUN_100151b0(int param_1,int param_2,int param_3);
undefined4 __cdecl FUN_10015530(int param_1,int param_2);
undefined4 __cdecl FUN_10015600(int param_1,int param_2,int param_3);
void __cdecl FUN_100157e0(void *param_1,int param_2,int param_3);
undefined4 __cdecl FUN_10016500(int param_1,int param_2,int param_3);
undefined4 __cdecl FUN_10016b00(void *param_1,int param_2);
undefined4 __cdecl FUN_100174a0(int param_1,int param_2,int param_3);
undefined4 __cdecl FUN_10017620(int param_1,int param_2,int param_3);
undefined4 __cdecl FUN_10017870(int param_1,int param_2,uint param_3,uint param_4,uint param_5,uint param_6,int param_7,int param_8,int param_9,char *param_10,undefined4 param_11);
void FUN_10017d20(void);
undefined4 * __cdecl FUN_10017d30(undefined4 param_1);
void __cdecl FUN_10017da0(SOCKET *param_1);
uint __cdecl FUN_10017df0(int param_1,int param_2);
undefined4 __cdecl FUN_10017e90(int *param_1,u_long param_2,u_short param_3);
void __cdecl FUN_10017f00(SOCKET *param_1);
int __cdecl FUN_10018370(int param_1,size_t param_2,int param_3);
undefined4 __cdecl FUN_10018470(SOCKET *param_1,undefined4 param_2,undefined4 param_3,char *param_4,char *param_5);
int __cdecl FUN_10018550(SOCKET *param_1,undefined4 *param_2,undefined4 *param_3,undefined4 *param_4);
uint __cdecl FUN_10018610(SOCKET *param_1,undefined4 *param_2,undefined4 *param_3,undefined4 *param_4,uint param_5);
void __cdecl FUN_10018680(void *param_1);
int __cdecl FUN_100186c0(int param_1,int param_2);
int __cdecl FUN_10018720(int *param_1);
undefined4 __cdecl FUN_10018780(undefined4 *param_1);
undefined4 __fastcall FUN_10018790(undefined4 param_1,byte *param_2,int param_3);
undefined4 __thiscall FUN_10018820(void *this,int *param_1,byte *param_2,int param_3);
undefined4 __thiscall FUN_10018890(void *this,int param_1,byte *param_2);
int __thiscall FUN_100188e0(void *this,int *param_1,byte *param_2);
undefined4 __cdecl FUN_10018940(int *param_1,int param_2,int param_3);
undefined4 __cdecl FUN_100189b0(int param_1,int param_2,undefined4 param_3);
undefined4 __cdecl FUN_100189f0(int param_1,int param_2);
int __cdecl FUN_10018a30(int *param_1,int param_2);
void __cdecl FUN_10018a80(int param_1);
undefined4 __cdecl FUN_10018a90(int param_1,undefined4 *param_2);
undefined4 * __cdecl FUN_10018b00(int param_1,int param_2);
undefined4 * __cdecl FUN_10018b90(int param_1);
int * __cdecl FUN_10018c70(int *param_1);
void __cdecl FUN_10018d00(byte param_1);
void __cdecl FUN_10018da0(int param_1,int param_2,int param_3,int param_4,int param_5);
void __cdecl FUN_10018e50(int param_1,int param_2,int param_3,int param_4);
void __fastcall FUN_10018ec0(undefined4 param_1,int *param_2);
void __cdecl FUN_10018f90(int param_1,int param_2);
void FUN_10018ff0(void);
void __fastcall FUN_10019120(undefined4 param_1,int param_2);
void FUN_10019180(void);
void __cdecl FUN_10019210(void *param_1);
void __cdecl FUN_10019250(undefined4 *param_1,byte *param_2);
int __cdecl FUN_100192a0(undefined4 *param_1,byte *param_2);
int __cdecl FUN_100195a0(int *param_1,byte *param_2);
int __cdecl FUN_10019870(undefined4 param_1,byte *param_2);
undefined4 * FUN_10019900(void);
int * __cdecl FUN_10019930(int param_1);
void __cdecl FUN_10019990(int *param_1);
undefined4 * __cdecl FUN_100199e0(int *param_1,size_t param_2);
void __cdecl FUN_10019a50(undefined4 param_1);
void __cdecl FUN_10019a80(void *param_1,char param_2);
undefined4 * __cdecl FUN_10019ad0(undefined4 param_1,int param_2);
void __cdecl FUN_10019b00(int param_1,int param_2);
void __cdecl FUN_10019b30(int *param_1,int param_2);
int __cdecl FUN_10019b70(int param_1);
void __cdecl FUN_10019b90(int *param_1);
void __cdecl FUN_10019be0(int *param_1,int param_2,char param_3);
undefined4 * __cdecl FUN_10019c50(undefined4 *param_1);
int __cdecl FUN_10019c60(undefined4 param_1,int param_2);
int __cdecl FUN_10019c70(char *param_1,char *param_2);
undefined4 __cdecl FUN_10019cc0(char *param_1,char *param_2);
int FUN_10019d40(void);
undefined4 * __cdecl FUN_10019e90(int param_1,int param_2);
void __cdecl FUN_10019f20(void *param_1);
int __cdecl FUN_10019f50(int *param_1,int param_2,undefined4 param_3);
undefined4 __cdecl FUN_1001a010(int param_1,int param_2);
undefined4 __cdecl FUN_1001a0d0(int param_1,int param_2);
undefined4 __cdecl FUN_1001a190(int param_1,int param_2);
undefined4 __cdecl FUN_1001a1d0(int param_1);
undefined4 __cdecl FUN_1001a1e0(int param_1);
undefined4 __cdecl FUN_1001a1f0(int param_1,int *param_2,undefined4 *param_3);
void FUN_1001a300(void);
void FUN_1001a340(void);
void __cdecl FUN_1001a3b0(int param_1,int param_2);
void __cdecl FUN_1001a3f0(int param_1,int param_2);
u_long __cdecl FUN_1001a430(u_long param_1);
u_long FUN_1001a510(void);
void __cdecl FUN_1001a590(undefined4 *param_1);
undefined4 __cdecl FUN_1001a8d0(int param_1);
int __cdecl FUN_1001a930(char *param_1);
int FUN_1001ad40(void);
void __cdecl FUN_1001ada0(undefined4 *param_1);
void __fastcall FUN_1001b280(int param_1);
undefined4 __cdecl FUN_1001b360(int param_1,char *param_2);
undefined4 * __cdecl FUN_1001b3c0(int param_1,char *param_2);
void __cdecl FUN_1001b430(int param_1);
void __cdecl FUN_1001b490(int param_1,undefined1 param_2);
void __cdecl FUN_1001b530(int param_1,char *param_2);
void FUN_1001b560(void);
int FUN_1001b5f0(void);
int __cdecl FUN_1001b680(byte *param_1,int param_2,int param_3);
int __cdecl FUN_1001b6e0(undefined4 param_1,int param_2);
int __cdecl FUN_1001b7d0(int param_1,char *param_2);
int __cdecl FUN_1001bea0(int param_1);
undefined4 * FUN_1001bef0(void);
void __cdecl FUN_1001bf40(uint *param_1);
void __cdecl FUN_1001c000(uint *param_1,undefined4 param_2,char *param_3);
void __cdecl FUN_1001c040(uint *param_1);
void __cdecl FUN_1001c0e0(uint *param_1);
uint * __cdecl FUN_1001c190(uint *param_1);
undefined1 * __cdecl FUN_1001c1e0(uint *param_1,char *param_2);
undefined1 * __cdecl FUN_1001c220(uint *param_1,int param_2,undefined4 *param_3);
uint __cdecl FUN_1001c250(uint *param_1);
void __cdecl FUN_1001c270(int param_1,char *param_2,char *param_3);
undefined4 __cdecl FUN_1001c2f0(uint *param_1);
void __fastcall FUN_1001c320(undefined4 param_1,byte *param_2);
undefined4 * __cdecl FUN_1001c350(int param_1,int param_2,int param_3,int param_4,undefined4 param_5,int param_6);
void __cdecl FUN_1001c510(void *param_1);
void FUN_1001c550(int *param_1);
int __cdecl FUN_1001c5e0(int param_1,int param_2);
int __cdecl FUN_1001c690(int *param_1,int param_2,int param_3,int *param_4);
void __cdecl FUN_1001cd80(int *param_1,int *param_2);
int __cdecl FUN_1001cda0(int param_1);
undefined4 __cdecl FUN_1001cdc0(int param_1);
undefined4 __cdecl FUN_1001cdd0(int param_1);
int __cdecl FUN_1001cde0(int param_1,int param_2,undefined4 *param_3,int *param_4);
int __cdecl FUN_1001ce60(int param_1,int *param_2,int *param_3,undefined4 *param_4,undefined4 *param_5);
bool __cdecl FUN_1001cf00(int param_1,FILE *param_2);
int __cdecl FUN_1001d090(int param_1,char *param_2);
undefined4 __cdecl FUN_1001d140(int param_1,char *param_2);
undefined1 * FUN_1001d190(void);
undefined4 * __cdecl FUN_1001d1c0(int param_1);
void __cdecl FUN_1001d220(void *param_1);
void __cdecl FUN_1001d270(int param_1,int *param_2);
bool __cdecl FUN_1001d2b0(int param_1,int *param_2);
void __cdecl FUN_1001d2f0(int param_1,undefined4 *param_2);
void __cdecl FUN_1001d320(int param_1,int param_2,int *param_3);
void __cdecl FUN_1001d490(byte *param_1,byte *param_2);
void __cdecl FUN_1001d4d0(byte *param_1,int param_2,int param_3);
void __cdecl FUN_1001d550(int param_1,int *param_2,int *param_3);
uint __cdecl FUN_1001d610(int param_1,int param_2);
void FUN_1001d640(void);
void __cdecl FUN_1001d690(int param_1,undefined4 param_2,byte *param_3,int param_4,byte *param_5,byte *param_6,undefined *param_7,undefined4 param_8,char param_9);
void __cdecl FUN_1001da50(byte *param_1,int param_2,uint *param_3);
void __cdecl FUN_1001db40(byte *param_1,uint *param_2);
void __cdecl FUN_1001dc30(undefined4 param_1,int param_2,undefined1 *param_3,int param_4,int param_5);
void __cdecl FUN_1001dcc0(undefined4 param_1);
void __cdecl FUN_1001dce0(int param_1,int param_2);
int __cdecl FUN_1001dd10(int param_1,int param_2);
void __cdecl FUN_1001ddf0(int param_1,undefined4 param_2,byte *param_3,byte *param_4,uint *param_5,int param_6,undefined *param_7,undefined4 param_8);
void __cdecl FUN_1001de90(void *param_1);
undefined4 * __cdecl FUN_1001df20(undefined4 *param_1);
undefined4 __fastcall FUN_1001e070(undefined4 param_1,int param_2);
undefined4 __fastcall FUN_1001e0c0(int param_1,int param_2);
undefined4 __fastcall FUN_1001e100(int param_1,uint param_2,uint param_3);
int __fastcall FUN_1001e1c0(int param_1,int param_2,int param_3,byte param_4);
undefined4 __cdecl FUN_1001e220(char *param_1,char *param_2);
int __cdecl FUN_1001e410(byte *param_1,int param_2,byte *param_3);
void __cdecl FUN_1001e4a0(char *param_1,uint param_2,byte param_3);
undefined4 __cdecl FUN_1001e580(char *param_1,undefined4 param_2);
undefined4 __cdecl FUN_1001e6c0(char *param_1);
undefined4 __cdecl FUN_1001e910(char *param_1,undefined4 param_2,byte *param_3);
undefined4 __cdecl FUN_1001ea90(char *param_1,undefined4 param_2);
undefined4 __cdecl FUN_1001eb20(char *param_1,byte *param_2);
char * __cdecl FUN_1001ec70(char *param_1,uint param_2,char *param_3,int param_4);
void __cdecl FUN_1001f0b0(char *param_1,uint param_2,char *param_3);
undefined4 __thiscall FUN_1001f0d0(void *this,int param_1,byte *param_2,int param_3,int *param_4);
void __cdecl FUN_1001f130(int *param_1,byte *param_2,int param_3,undefined4 param_4);
void __cdecl FUN_1001f330(int param_1,int param_2,uint param_3);
void __thiscall FUN_1001f370(void *this,int param_1);
undefined4 __cdecl FUN_1001f3e0(int param_1,int param_2);
undefined4 __cdecl FUN_1001f730(int param_1,int param_2);
undefined4 __cdecl FUN_1001f8b0(int param_1,int param_2);
undefined4 __cdecl FUN_1001fc00(int param_1,byte *param_2);
void __cdecl FUN_1001fca0(int param_1,undefined4 *param_2,int *param_3);
undefined4 __cdecl FUN_1001fce0(int param_1,int param_2);
undefined4 __cdecl FUN_1001fe30(int param_1,int param_2);
void __cdecl FUN_10020120(char *param_1,undefined4 param_2);
void __cdecl FUN_10020270(int param_1,int param_2);
void FUN_10020330(void);
uint FUN_10020390(void);
void __cdecl FUN_10020460(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4);
uint __cdecl FUN_10020560(int param_1,int param_2);
undefined4 __cdecl FUN_10020630(int param_1,int param_2);
undefined4 __cdecl FUN_10021720(int param_1,int param_2);
undefined4 __cdecl FUN_10021fa0(int param_1,int param_2);
void __thiscall FUN_100225c0(void *this,int param_1,int *param_2,int *param_3);
void __cdecl FUN_10022650(int param_1,int *param_2,char param_3,int *param_4);
undefined4 __cdecl FUN_100226f0(int param_1,int param_2);
int FUN_10022940(void);
void __cdecl FUN_10022980(int param_1);
void FUN_10022ac0(void);
void __cdecl FUN_10022e00(int param_1);
void __cdecl FUN_10022f60(int param_1);
int * __cdecl FUN_10023140(int param_1,int *param_2,int *param_3);
undefined4 __cdecl FUN_100234b0(int param_1,byte *param_2);
undefined4 __cdecl FUN_10023bb0(int param_1);
undefined4 __cdecl FUN_10023d00(int param_1,int param_2);
undefined4 __cdecl FUN_10024270(int param_1,int param_2);
undefined4 __cdecl FUN_10024640(int param_1);
void FUN_10024d20(void);
undefined4 __cdecl FUN_10024f50(int param_1,int param_2,int param_3);
char __cdecl FUN_10025240(undefined4 param_1,int param_2,int param_3);
void __cdecl FUN_100252b0(byte *param_1,int param_2);
undefined4 * __cdecl FUN_10025340(int param_1,int param_2);
void __cdecl FUN_10025c00(int param_1,int param_2,int param_3,char param_4);
undefined4 __cdecl FUN_10025de0(int param_1,int param_2);
undefined4 __cdecl FUN_10026370(int param_1,int param_2);
undefined4 __cdecl FUN_100264f0(void *param_1,uint param_2);
undefined4 __cdecl FUN_10026dd0(int param_1,int param_2);
undefined4 __cdecl FUN_10027290(int param_1,int param_2);
void FUN_100273d0(void);
void FUN_10027540(void);
undefined4 __cdecl FUN_10028610(int param_1);
void __cdecl FUN_100287e0(int param_1,int param_2);
void __cdecl FUN_10028a50(int param_1,int *param_2,char param_3);
void __cdecl FUN_10028ac0(int param_1,int *param_2,char param_3);
undefined4 __cdecl FUN_10028c60(int param_1,int param_2);
void FUN_100296d0(void);
undefined4 __cdecl FUN_10029730(int param_1,byte *param_2);
void __cdecl FUN_10029840(char *param_1);
char FUN_10029890(void);
undefined4 __cdecl FUN_10029930(int param_1,byte *param_2);
undefined4 FUN_100299b0(void);
undefined4 * FUN_100299f0(void);
void __cdecl FUN_10029a10(int *param_1,byte *param_2);
void __cdecl FUN_10029b90(void *param_1);
undefined4 __cdecl FUN_10029bc0(int *param_1,int param_2,byte *param_3);
void __cdecl FUN_10029df0(int *param_1,char *param_2,int param_3);
undefined1 __cdecl FUN_1002a030(int param_1);
undefined4 * FUN_1002a040(void);
void __cdecl FUN_1002a070(void *param_1);
void __cdecl FUN_1002a090(int param_1);
int __cdecl FUN_1002a0c0(int param_1);
void __cdecl FUN_1002a100(int param_1,int param_2);
int __cdecl FUN_1002a140(int param_1);
void __cdecl FUN_1002a1a0(int param_1,int param_2);
int __cdecl FUN_1002a1d0(int param_1,char *param_2);
uint __cdecl FUN_1002a230(int param_1,int *param_2,int param_3,undefined4 param_4,int param_5,char *param_6);
void __cdecl FUN_1002a2b0(int param_1,undefined4 param_2,int param_3,undefined4 param_4,byte *param_5);
void FUN_1002a370(void *param_1);
uint __cdecl FUN_1002a3e0(uint *param_1,int param_2);
int FUN_1002a4b0(void);
undefined4 __cdecl FUN_1002a630(int param_1,SOCKET *param_2);
uint __cdecl FUN_1002a6f0(int *param_1,int param_2,uint param_3);
void __cdecl FUN_1002a7a0(int *param_1,int param_2);
void __cdecl FUN_1002a7e0(int *param_1,int param_2);
undefined4 __cdecl FUN_1002a870(int *param_1,int param_2,int param_3,int param_4);
int __cdecl FUN_1002a950(int *param_1,int param_2,char *param_3,int param_4);
undefined4 __cdecl FUN_1002aa10(int *param_1,int param_2);
undefined2 __cdecl FUN_1002aa40(int *param_1,int param_2);
u_long __cdecl FUN_1002aa70(int *param_1,int param_2);
void __cdecl FUN_1002aae0(int param_1);
void __cdecl FUN_1002ab30(int param_1);
int * __cdecl FUN_1002ab70(int param_1,undefined2 param_2,int param_3,int param_4,int param_5,int param_6);
undefined4 __cdecl FUN_1002ada0(int param_1,SOCKET *param_2);
void * FUN_1002aee0(undefined4 param_1,char *param_2,size_t *param_3);
void __cdecl FUN_1002afa0(undefined4 param_1,void *param_2);
size_t __cdecl FUN_1002afb0(undefined4 param_1,char *param_2,char *param_3,size_t param_4,int param_5);
bool __cdecl FUN_1002b050(byte *param_1,byte *param_2);
int __cdecl FUN_1002b0c0(char *param_1,int param_2,char *param_3,undefined4 param_4,char *param_5,char *param_6);
void __cdecl FUN_1002b1c0(int param_1,char *param_2,int param_3,int param_4);
void __cdecl FUN_1002b2c0(int param_1,byte *param_2,int param_3);
undefined4 __cdecl FUN_1002b360(char *param_1,int param_2,int param_3,char *param_4,int param_5,int param_6);
uint __cdecl FUN_1002b420(uint *param_1,uint *param_2);
int FUN_1002b540(void);
int __fastcall FUN_1002b5a0(undefined4 *param_1);
byte * __cdecl FUN_1002b610(int param_1,byte *param_2);
byte * __cdecl FUN_1002b750(int param_1,byte *param_2);
byte * __cdecl FUN_1002b8a0(undefined4 *param_1,byte *param_2);
byte * __cdecl FUN_1002b9b0(undefined4 *param_1,byte *param_2);
byte * __cdecl FUN_1002bce0(undefined4 *param_1,byte *param_2);
byte * __cdecl FUN_1002bdc0(undefined4 *param_1,byte *param_2);
byte * __cdecl FUN_1002be90(undefined4 *param_1,byte *param_2);
byte * __cdecl FUN_1002bf80(undefined4 *param_1,byte *param_2);
void __fastcall FUN_1002c050(undefined4 *param_1);
int __cdecl FUN_1002c090(undefined4 param_1,undefined4 param_2,byte *param_3,char *param_4,int param_5);
void __cdecl FUN_1002c1c0(int param_1,undefined4 param_2);
void __cdecl FUN_1002c1d0(int *param_1);
int FUN_1002c210(undefined4 *param_1,int param_2);
undefined4 __cdecl FUN_1002c280(int param_1,char *param_2,char *param_3,char *param_4,uint param_5);
undefined4 __cdecl FUN_1002c550(int param_1,undefined4 param_2);
int __cdecl FUN_1002c7c0(int param_1,undefined4 param_2);
undefined4 * __cdecl FUN_1002c800(int param_1,int param_2);
void __cdecl FUN_1002c870(int *param_1);
undefined4 * __cdecl FUN_1002cab0(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4);
int WSAGetLastError(void);
int WSAStartup(WORD wVersionRequired,LPWSADATA lpWSAData);
int setsockopt(SOCKET s,int level,int optname,char *optval,int optlen);
int ioctlsocket(SOCKET s,long cmd,u_long *argp);
SOCKET socket(int af,int type,int protocol);
int closesocket(SOCKET s);
int shutdown(SOCKET s,int how);
int bind(SOCKET s,sockaddr *addr,int namelen);
int connect(SOCKET s,sockaddr *name,int namelen);
int sendto(SOCKET s,char *buf,int len,int flags,sockaddr *to,int tolen);
int send(SOCKET s,char *buf,int len,int flags);
int recvfrom(SOCKET s,char *buf,int len,int flags,sockaddr *from,int *fromlen);
int recv(SOCKET s,char *buf,int len,int flags);
int getsockname(SOCKET s,sockaddr *name,int *namelen);
hostent * gethostbyname(char *name);
int gethostname(char *name,int namelen);
void WSAIoctl(void);
int WSACleanup(void);
float10 __cdecl FUN_1002cee0(int param_1,int param_2);
__time32_t __cdecl FID_conflict:__time32(__time32_t *_Time);
void FUN_1002cf2b(void);
void __cdecl __fpmath(int param_1);
void __thiscall type_info::~type_info(type_info *this);
void FUN_1002cfbe(void);
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
void __fastcall FUN_1002d447(int param_1);
void __cdecl __global_unwind2(PVOID param_1);
void __cdecl __local_unwind2(int param_1,int param_2);
int __cdecl __abnormal_termination(void);
void __fastcall __NLG_Notify1(undefined4 param_1);
void FUN_1002d52e(void);
ulonglong FUN_1002d548(void);
void __CxxThrowException@8(undefined4 param_1,undefined4 param_2);
char * __cdecl _strncpy(char *_Dest,char *_Source,size_t _Count);
undefined4 __CRT_INIT@12(undefined4 param_1,int param_2);
int entry(undefined4 param_1,int param_2,undefined4 param_3);
void __cdecl __amsg_exit(int param_1);
char * __cdecl _strchr(char *_Str,int _Val);
char * __cdecl _strstr(char *_Str,char *_SubStr);
void * __cdecl _memmove(void *_Dst,void *_Src,size_t _Size);
void __chkstk(void);
tm * __cdecl _localtime(time_t *_Time);
tm * __cdecl _gmtime(time_t *_Time);
int __cdecl _strncmp(char *_Str1,char *_Str2,size_t _MaxCount);
void * __cdecl __heap_alloc(size_t _Size);
void FUN_1002e1db(void);
void * __cdecl __nh_malloc(size_t _Size,int _NhFlag);
void * __cdecl _malloc(size_t _Size);
void __cdecl _free(void *_Memory);
void FUN_1002e275(void);
int __cdecl _printf(char *_Format,...);
void FUN_1002e2ee(void);
int __cdecl __fclose_lk(FILE *param_1);
int __cdecl _fclose(FILE *_File);
void FUN_1002e38e(void);
char * __cdecl _fgets(char *_Buf,int _MaxCount,FILE *_File);
void FUN_1002e414(void);
FILE * __cdecl __fsopen(char *_Filename,char *_Mode,int _ShFlag);
void FUN_1002e46e(void);
void __cdecl FUN_1002e478(char *param_1,char *param_2);
int __cdecl _strcmp(char *_Str1,char *_Str2);
int __cdecl _fprintf(FILE *_File,char *_Format,...);
void FUN_1002e56c(void);
void __cdecl __lock_file(FILE *_File);
void __cdecl __lock_file2(int _Index,void *_File);
void __cdecl __unlock_file(FILE *_File);
void __cdecl __unlock_file2(int _Index,void *_File);
long __cdecl _atol(char *_Str);
long __cdecl _atol(char *_Str);
void * __cdecl _realloc(void *_Memory,size_t _NewSize);
void FUN_1002e8cc(void);
int __cdecl __vsnprintf(char *_Dest,size_t _Count,char *_Format,va_list _Args);
int __cdecl __flush(FILE *_File);
int __cdecl __fflush_lk(FILE *param_1);
int __cdecl flsall(int param_1);
void FUN_1002ea92(void);
void FUN_1002eabe(void);
int __cdecl _fflush(FILE *_File);
void FUN_1002eb0d(void);
int __cdecl __snprintf(char *_Dest,size_t _Count,char *_Format,...);
int __cdecl _fputs(char *_Str,FILE *_File);
void FUN_1002ebde(void);
int __cdecl _puts(char *_Str);
void FUN_1002ec7e(void);
int __cdecl _isdigit(int _C);
int __cdecl _isspace(int _C);
uint __cdecl __fread_lk(undefined1 *param_1,uint param_2,uint param_3,FILE *param_4);
size_t __cdecl _fread(void *_DstBuf,size_t _ElementSize,size_t _Count,FILE *_File);
void FUN_1002ee28(void);
uint __thiscall ___tolower_mt(void *this,int param_1,uint param_2);
int __cdecl _tolower(int _C);
uint __cdecl __fwrite_lk(char *param_1,uint param_2,uint param_3,FILE *param_4);
size_t __cdecl _fwrite(void *_Str,size_t _Size,size_t _Count,FILE *_File);
void FUN_1002f065(void);
int __cdecl __ftell_lk(uint *param_1);
long __cdecl _ftell(FILE *_File);
void FUN_1002f236(void);
int __cdecl __fseek_lk(FILE *param_1,int param_2,int param_3);
int __cdecl _fseek(FILE *_File,long _Offset,int _Origin);
void FUN_1002f30e(void);
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
void __cdecl FUN_1002f8d0(int param_1);
int __cdecl __mtinitlocknum(int _LockNum);
void FUN_1002f97c(void);
void __cdecl __lock(int _File);
void __cdecl __SEH_prolog(undefined4 param_1,int param_2);
void __SEH_epilog(void);
void FUN_1002faf2(int param_1);
void __cdecl _free(void *_Memory);
int __cdecl __flsbuf(int _Ch,FILE *_File);
void __cdecl write_char(void);
void __cdecl write_multi_char(undefined4 param_1,int param_2);
void __cdecl write_string(int param_1);
void __cdecl __output(undefined4 param_1,byte *param_2,wchar_t *param_3);
int __cdecl TypeMatch(_s_HandlerType *param_1,_s_CatchableType *param_2,_s_ThrowInfo *param_3);
void __cdecl ___FrameUnwindToState(int param_1,undefined4 param_2,int param_3,int param_4);
void FUN_100305d3(void);
void __cdecl ___DestructExceptionObject(int param_1);
void * __cdecl AdjustPointer(void *param_1,PMD *param_2);
void * __cdecl CallCatchBlock(EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,_s_FuncInfo *param_4,void *param_5,int param_6,ulong param_7);
void FUN_100307a7(void);
void __cdecl BuildCatchObject(EHExceptionRecord *param_1,void *param_2,_s_HandlerType *param_3,_s_CatchableType *param_4);
void __cdecl CatchIt(EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4,_s_FuncInfo *param_5,_s_HandlerType *param_6,_s_CatchableType *param_7,_s_TryBlockMapEntry *param_8,int param_9,EHRegistrationNode *param_10,uchar param_11);
void __cdecl FindHandlerForForeignException(EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4,_s_FuncInfo *param_5,int param_6,int param_7,EHRegistrationNode *param_8);
void __cdecl FindHandler(EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4,_s_FuncInfo *param_5,uchar param_6,int param_7,EHRegistrationNode *param_8);
undefined4 __cdecl ___InternalCxxFrameHandler(EHExceptionRecord *param_1,EHRegistrationNode *param_2,_CONTEXT *param_3,void *param_4,_s_FuncInfo *param_5,int param_6,EHRegistrationNode *param_7,uchar param_8);
void FUN_10030d5d(void);
void __cdecl __mtterm(void);
void __cdecl __initptd(_ptiddata _Ptd,pthreadlocinfo _Locale);
_ptiddata __cdecl __getptd(void);
void __freefls@4(void *param_1);
void FUN_10030f39(void);
void FUN_10030f45(void);
void __cdecl __freeptd(_ptiddata _Ptd);
int __cdecl __mtinit(void);
void __cdecl terminate(void);
void __cdecl _inconsistency(void);
void __CallSettingFrame@12(undefined4 param_1,undefined4 param_2,int param_3);
void __cdecl ___security_init_cookie(void);
void ___security_error_handler(int param_1);
long __CxxUnhandledExceptionFilter(_EXCEPTION_POINTERS *param_1);
void __cdecl ___crtExitProcess(int param_1);
void FUN_10031368(void);
void FUN_10031371(void);
void __cdecl __initterm(undefined4 *param_1);
int __cdecl __cinit(int param_1);
void __cdecl doexit(UINT param_1,int param_2,int param_3);
void FUN_100314ab(void);
void __cdecl __exit(int _Code);
void __cdecl __cexit(void);
void * __cdecl _calloc(size_t _Count,size_t _Size);
void FUN_10031589(void);
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
void FUN_10032297(void);
int __cdecl cvtdate(int param_1,int param_2,int param_3,int param_4,int param_5,int param_6,int param_7,int param_8,int param_9);
bool __isindst_lk(void);
void __cdecl ___tzset(void);
void FUN_100326a6(void);
int __cdecl __isindst(tm *_Time);
void FUN_100326e4(void);
undefined4 ___sbh_heap_init(undefined4 param_1);
uint __cdecl ___sbh_find_block(int param_1);
void __cdecl ___sbh_free_block(uint *param_1,int param_2);
undefined4 * ___sbh_alloc_new_region(void);
int __cdecl ___sbh_alloc_new_group(int param_1);
undefined4 __cdecl ___sbh_resize_block(uint *param_1,int param_2,int param_3);
int * __cdecl ___sbh_alloc_block(uint *param_1);
int __cdecl __callnewh(size_t _Size);
int __cdecl __stbuf(FILE *_File);
void __cdecl __ftbuf(int _Flag,FILE *_File);
undefined4 __cdecl __close_lk(uint param_1);
int __cdecl __close(int _FileHandle);
void FUN_100333d7(void);
void __cdecl __freebuf(FILE *_File);
int __cdecl __filbuf(FILE *_File);
FILE * __cdecl __openfile(char *_Filename,char *_Mode,int _ShFlag,FILE *_File);
int * FUN_1003366f(void);
ulong * FUN_10033678(void);
void __cdecl __dosmaperr(ulong param_1);
FILE * __cdecl __getstream(void);
void FUN_1003380d(void);
uint __thiscall ___isctype_mt(void *this,int param_1,int param_2,uint param_3);
void __cdecl ___freetlocinfo(void *param_1);
int ___updatetlocinfo_lk(void);
pthreadlocinfo __cdecl ___updatetlocinfo(void);
void FUN_10033aeb(void);
void * __cdecl _memcpy(void *_Dst,void *_Src,size_t _Size);
void __cdecl __write_lk(uint param_1,char *param_2,uint param_3);
int __cdecl __write(int _FileHandle,void *_Buf,uint _MaxCharCount);
void FUN_100340d2(void);
int __cdecl __commit(int _FileHandle);
void FUN_10034196(void);
size_t __cdecl _strlen(char *_Str);
int __cdecl __read_lk(uint param_1,char *param_2,char *param_3);
int __cdecl __read(int _FileHandle,void *_DstBuf,uint _MaxCharCount);
void FUN_100344ad(void);
int __cdecl ___crtLCMapStringA(_locale_t _Plocinfo,LPCWSTR _LocaleName,DWORD _DwMapFlag,LPCSTR _LpSrcStr,int _CchSrc,LPSTR _LpDestStr,int _CchDest,int _Code_page,BOOL _BError);
DWORD __cdecl __lseek_lk(uint param_1,LONG param_2,DWORD param_3);
long __cdecl __lseek(int _FileHandle,long _Offset,int _Origin);
void FUN_10034988(void);
undefined4 __cdecl __ZeroTail(int param_1,int param_2);
void __cdecl __IncMan(int param_1,int param_2);
undefined4 __cdecl __RoundMan(int param_1,int param_2);
void __cdecl __CopyMan(int param_1,undefined4 *param_2);
undefined4 __cdecl __IsZeroMan(int param_1);
void __cdecl __ShrMan(int param_1,int param_2);
undefined4 __cdecl __ld12cvt(ushort *param_1,uint *param_2,int *param_3);
INTRNCVT_STATUS __cdecl FID_conflict:__ld12tod(_LDBL12 *_Ifp,_CRT_DOUBLE *_D);
INTRNCVT_STATUS __cdecl FID_conflict:__ld12tod(_LDBL12 *_Ifp,_CRT_DOUBLE *_D);
int __cdecl FID_conflict:__atodbl(_CRT_FLOAT *_Result,char *_Str);
int __cdecl FID_conflict:__atodbl(_CRT_FLOAT *_Result,char *_Str);
uint * __cdecl FUN_10034d50(uint *param_1,uint *param_2);
uint * __cdecl FUN_10034d60(uint *param_1,uint *param_2);
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
void FUN_100358af(void);
void __cdecl __setmbcp_lk(UINT param_1);
int __cdecl __setmbcp(int _CodePage);
void FUN_10035b8f(void);
undefined4 ___initmbctable(void);
void __cdecl _abort(void);
int __cdecl ___crtMessageBoxA(LPCSTR _LpText,LPCSTR _LpCaption,UINT _UType);
void __onexit_lk(void);
_onexit_t __cdecl __onexit(_onexit_t _Func);
void FUN_10035da1(void);
int __cdecl _atexit(_func_4879 *param_1);
int __cdecl __getenv_lk(uchar *param_1);
int __cdecl __set_osfhnd(int param_1,intptr_t param_2);
int __cdecl __free_osfhnd(int param_1);
intptr_t __cdecl __get_osfhandle(int _FileHandle);
int __cdecl __lock_fhandle(int _Filehandle);
void FUN_1003600d(void);
void __cdecl __unlock_fhandle(int _Filehandle);
int __cdecl __alloc_osfhnd(void);
void FUN_10036111(void);
void FUN_100361ab(void);
uint __thiscall __tsopen_lk(void *this,undefined4 *param_1,uint *param_2,LPCSTR param_3,uint param_4,byte param_5);
int __cdecl __sopen(char *_Filename,int _OpenFlag,int _ShareFlag,...);
void FUN_100364e0(void);
BOOL __cdecl ___crtGetStringTypeA(_locale_t _Plocinfo,DWORD _DWInfoType,LPCSTR _LpSrcStr,int _CchSrc,LPWORD _LpCharType,int _Code_page,BOOL _BError);
void __cdecl ___free_lc_time(undefined4 *param_1);
void __cdecl ___free_lconv_num(undefined4 *param_1);
void __cdecl ___free_lconv_mon(int param_1);
size_t __cdecl _strcspn(char *_Str,char *_Control);
char * __cdecl _strpbrk(char *_Str,char *_Control);
undefined8 __cdecl __lseeki64_lk(uint param_1,LONG param_2,LONG param_3,DWORD param_4);
void __cdecl ___ansicp(LCID param_1);
void __cdecl ___convertcp(UINT param_1,UINT param_2,char *param_3,size_t *param_4,LPSTR param_5,int param_6);
int __cdecl __resetstkoflw(void);
undefined4 __cdecl ___addl(uint param_1,uint param_2,uint *param_3);
void __cdecl ___add_12(uint *param_1,uint *param_2);
void __cdecl ___shl_12(uint *param_1);
void __cdecl ___shr_12(uint *param_1);
void __cdecl ___mtold12(char *param_1,int param_2,uint *param_3);
uint __cdecl ___strgtold12(_LDBL12 *pld12,char **p_end_ptr,char *str,int mult12,int scale,int decpt,int implicit_E);
void __cdecl$I10_OUTPUT(int param_1,uint param_2,uint param_3,int param_4,byte param_5,short *param_6);
void __cdecl siglookup(void);
int __cdecl _raise(int _SigNum);
void __fastcall FUN_10037825(int param_1);
size_t __cdecl __msize(void *_Memory);
void FUN_100378d0(void);
int __cdecl __mbsnbicoll(uchar *_Str1,uchar *_Str2,size_t _MaxCount);
int __cdecl ___wtomb_environ(void);
void __cdecl __chsize_lk(uint param_1,int param_2);
int __cdecl ___ascii_stricmp(char *_Str1,char *_Str2);
int __cdecl __stricmp(char *_Str1,char *_Str2);
int __cdecl __strnicmp(char *_Str1,char *_Str2,size_t _MaxCount);
void __cdecl ___ld12mul(int *param_1,int *param_2);
void __cdecl ___multtenpow12(int *param_1,uint param_2,int param_3);
size_t __cdecl _strncnt(char *_String,size_t _Cnt);
int __cdecl ___crtCompareStringA(_locale_t _Plocinfo,LPCWSTR _LocaleName,DWORD _DwCmpFlags,LPCSTR _LpString1,int _CchCount1,LPCSTR _LpString2,int _CchCount2,int _Code_page);
int __cdecl findenv(uchar *param_1);
int * __cdecl copy_environ(void);
int __cdecl ___crtsetenv(char **_POption,int _Primary);
int __cdecl __setmode_lk(uint param_1,int param_2);
int __cdecl ___ascii_strnicmp(char *_Str1,char *_Str2,size_t _MaxCount);
char * __cdecl __strdup(char *_Src);
uchar * __cdecl __mbschr(uchar *_Str,uint _Ch);
UCHAR Netbios(PNCB pncb);
void RtlUnwind(PVOID TargetFrame,PVOID TargetIp,PEXCEPTION_RECORD ExceptionRecord,PVOID ReturnValue);


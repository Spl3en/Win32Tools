// --- Author	: Moreau Cyril - Spl3en
// --- File		: Win32Tools.h
// --- Date		: 2012-03-02-03.09.54
// --- Version	: 1.0
/*
	A lot of the implementation has not been written by me - specially those manipulating PE format deeply :)
	Please apologize for the lake of references and credits
*/

#ifndef Win32Tools_H_INCLUDED
#define Win32Tools_H_INCLUDED

// ---------- Includes ------------
#include <stdlib.h>
#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0500

#include <windows.h>
#include <tlhelp32.h>
#include <time.h>
#include <psapi.h>
#include <wincon.h>
#include <subauth.h>
#include <ntdef.h>

#include "../Ztring/Ztring.h"
#include "../Utils/Utils.h"

// ---------- Defines -------------
typedef struct InjectionInfo
{
	HANDLE proc;
	char *procName;
	LPVOID dll;
	DWORD pid;
	char *dllPath;

} InjectionInfo;


/**
* MODULE_ENTRY contains basic information about a module
*/
typedef struct _MODULE_ENTRY
{
	UNICODE_STRING BaseName; // BaseName of the module
	UNICODE_STRING FullName; // FullName of the module
	ULONG SizeOfImage; // Size in bytes of the module
	PVOID BaseAddress; // Base address of the module
	PVOID EntryPoint; // Entrypoint of the module
	BOOLEAN IsSystemModule; // TRUE if the module is a system module
} MODULE_ENTRY, *PMODULE_ENTRY;

/**
* MODULE_INFORMATION_TABLE contains basic information about all the modules of a given process
*/
typedef struct _MODULE_INFORMATION_TABLE
{
	ULONG Pid; // PID of the process
	ULONG ModuleCount; // Modules count for the above pointer
	PMODULE_ENTRY Modules; // Pointer to 0...* modules
	PMODULE_ENTRY ImageModule; // Pointer to the current executable module
	PMODULE_ENTRY NtdllModule; // Pointer to the ntdll module
} MODULE_INFORMATION_TABLE, *PMODULE_INFORMATION_TABLE;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	UCHAR Reserved1[16];
	PVOID Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

//
// Loader Data Table Entry
//
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union {
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union {
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	PVOID EntryPointActivationContext;
	PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;


typedef struct _SYSTEM_MODULE_ENTRY
{
	ULONG Unused;
	ULONG Always0;
	PVOID ModuleBaseAddress;
	ULONG ModuleSize;
	ULONG Unknown;
	ULONG ModuleEntryIndex;
	USHORT ModuleNameLength;
	USHORT ModuleNameOffset;
	CHAR ModuleName [256];
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG ModulesCount;
	SYSTEM_MODULE_ENTRY Modules[0];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _RTL_BITMAP
{
     ULONG SizeOfBitMap;
     ULONG * Buffer;
} RTL_BITMAP, *PRTL_BITMAP;


typedef struct _PROCESS_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PVOID PebBaseAddress;
	ULONG AffinityMask;
	ULONG BasePriority;
	ULONG UniqueProcessId;
	ULONG InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;


typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation,
	ProcessQuotaLimits,
	ProcessIoCounters,
	ProcessVmCounters,
	ProcessTimes,
	ProcessBasePriority,
	ProcessRaisePriority,
	ProcessDebugPort,
	ProcessExceptionPort,
	ProcessAccessToken,
	ProcessLdtInformation,
	ProcessLdtSize,
	ProcessDefaultHardErrorMode,
	ProcessIoPortHandlers,          // Note: this is kernel mode only
	ProcessPooledUsageAndLimits,
	ProcessWorkingSetWatch,
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup,
	ProcessPriorityClass,
	MaxProcessInfoClass
} PROCESSINFOCLASS;

NTSTATUS WINAPI NtQueryInformationProcess (
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
);

#pragma pack(push, 1)
typedef struct _PEB
{
	BOOLEAN InheritedAddressSpace; /* 00 */
	BOOLEAN ReadImageFileExecOptions; /* 01 */
	BOOLEAN BeingDebugged; /* 02 */
	BOOLEAN SpareBool; /* 03 */
	HANDLE Mutant; /* 04 */
	HMODULE ImageBaseAddress; /* 08 */
	PPEB_LDR_DATA LdrData; /* 0c */
	RTL_USER_PROCESS_PARAMETERS *ProcessParameters; /* 10 */
	PVOID SubSystemData; /* 14 */
	HANDLE ProcessHeap; /* 18 */
	PRTL_CRITICAL_SECTION FastPebLock; /* 1c */
	PVOID /*PPEBLOCKROUTINE*/ FastPebLockRoutine; /* 20 */
	PVOID /*PPEBLOCKROUTINE*/ FastPebUnlockRoutine; /* 24 */
	ULONG EnvironmentUpdateCount; /* 28 */
	PVOID KernelCallbackTable; /* 2c */
	PVOID EventLogSection; /* 30 */
	PVOID EventLog; /* 34 */
	PVOID /*PPEB_FREE_BLOCK*/ FreeList; /* 38 */
	ULONG TlsExpansionCounter; /* 3c */
	PRTL_BITMAP TlsBitmap; /* 40 */
	ULONG TlsBitmapBits[2]; /* 44 */
	PVOID ReadOnlySharedMemoryBase; /* 4c */
	PVOID ReadOnlySharedMemoryHeap; /* 50 */
	PVOID *ReadOnlyStaticServerData; /* 54 */
	PVOID AnsiCodePageData; /* 58 */
	PVOID OemCodePageData; /* 5c */
	PVOID UnicodeCaseTableData; /* 60 */
	ULONG NumberOfProcessors; /* 64 */
	ULONG NtGlobalFlag; /* 68 */
	BYTE Spare2[4]; /* 6c */
	LARGE_INTEGER CriticalSectionTimeout; /* 70 */
	ULONG HeapSegmentReserve; /* 78 */
	ULONG HeapSegmentCommit; /* 7c */
	ULONG HeapDeCommitTotalFreeThreshold; /* 80 */
	ULONG HeapDeCommitFreeBlockThreshold; /* 84 */
	ULONG NumberOfHeaps; /* 88 */
	ULONG MaximumNumberOfHeaps; /* 8c */
	PVOID *ProcessHeaps; /* 90 */
	PVOID GdiSharedHandleTable; /* 94 */
	PVOID ProcessStarterHelper; /* 98 */
	PVOID GdiDCAttributeList; /* 9c */
	PVOID LoaderLock; /* a0 */
	ULONG OSMajorVersion; /* a4 */
	ULONG OSMinorVersion; /* a8 */
	ULONG OSBuildNumber; /* ac */
	ULONG OSPlatformId; /* b0 */
	ULONG ImageSubSystem; /* b4 */
	ULONG ImageSubSystemMajorVersion; /* b8 */
	ULONG ImageSubSystemMinorVersion; /* bc */
	ULONG ImageProcessAffinityMask; /* c0 */
	ULONG GdiHandleBuffer[34]; /* c4 */
	ULONG PostProcessInitRoutine; /* 14c */
	PRTL_BITMAP TlsExpansionBitmap; /* 150 */
	ULONG TlsExpansionBitmapBits[32]; /* 154 */
	ULONG SessionId; /* 1d4 */
} PEB, *PPEB;

#define CREATE_THREAD_ACCESS (PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ)

#define make_ptr(cast, ptr, offset) (cast)((DWORD)(ptr) + (DWORD)(offset))

#define GetImgDirEntryRVA(pNTHdr, IDE) \
	(pNTHdr->OptionalHeader.DataDirectory[IDE].VirtualAddress)

#define warning(msg, ...) \
	do {_warning("[?] (%s) " msg "\n", __FUNCTION__, ##__VA_ARGS__);} while(0)

#define error(msg, ...) \
	do {_error("[!] (%s) " msg "\n", __FUNCTION__, ##__VA_ARGS__); system("pause");} while(0)

#define fatal_error(msg, ...) \
	do {_error("[!] (%s) " msg "\n", __FUNCTION__, ##__VA_ARGS__); exit(-1);} while(0)

#define important(msg, ...) \
	do {_error("[!] " msg "\n", ##__VA_ARGS__);} while(0)

#define info(msg, ...) \
	do {_info("[+] " msg "\n", ##__VA_ARGS__);} while(0)

#ifdef DEBUG_ACTIVATED
#define debug(msg, ...) \
	do {_debug("[+] " msg "\n", ##__VA_ARGS__);} while(0)
#else
#define debug(msg, ...) ;
#endif

#define debugb(msg, ...) \
	do {_debug("[+] " msg, ##__VA_ARGS__);} while(0)

#define infob(msg, ...) \
	do {_info("[+] " msg, ##__VA_ARGS__);} while(0)

#define infobn(msg, ...) \
	do {_info(msg, ##__VA_ARGS__);} while(0)


#ifdef BOOL
#define bool BOOL
#endif

#ifndef bool
#define bool char
#endif

#ifdef TRUE
#ifndef true
#define true TRUE
#endif
#endif

#ifdef FALSE
#ifndef false
#define false FALSE
#endif
#endif

#define PUSH_POS 	0
#define POP_POS 	1

#define COMPILE_GDI 0

// ----------- Methods ------------

typedef LONG (WINAPI * NtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);


void
exec_file (char *file_path, LPVOID mem_file);

LPVOID
file_to_mem (char *filename);

DWORD
get_pid_by_name (char *proc_name);

HANDLE
get_handle_from_pid (DWORD pid);

HANDLE
get_handle_by_name (char *proc_name);

BOOL enable_debug_privileges ();

int
set_privilege (HANDLE hToken, LPCTSTR lpszPrivilege, int bEnablePrivilege);

void
exit_process (HANDLE handle);

void
kill_process_by_name (char *filename);

InjectionInfo *
injectDLL (char *process_name, char *lpszDLLPath);

BOOL
EjectDLL (char *process_name, char *dllPath);

int
dump_eat (char *file_path);

LPVOID
map_file(char *file_path);

int
is_pe (LPVOID mapping);

void
dump_iat (char *filename);

DWORD
get_baseaddr (char *module_name);

MODULEENTRY32 *
get_module_entry (char *process_name, DWORD pid, HWND window);

void
get_section_address (HANDLE process);

int
hex_to_dec (char* hex);

int
compare_pattern (const unsigned char *buffer, const unsigned char *pattern, const char *mask);

DWORD
find_pattern_mask (HANDLE process, DWORD start, DWORD end, char *raw_pattern, char *mask);

char *
create_mask_from_file (char *filename);

int
find_pattern (const unsigned char *buffer, DWORD size, unsigned char *pattern, char *mask);

DWORD
find_pattern_process (HANDLE process, DWORD start, DWORD end, unsigned char *pattern, char* mask);

int
read_memory_as_int (HANDLE process, DWORD address);

int
write_memory_as_int (HANDLE process, DWORD address, unsigned int value);

float
read_memory_as_float (HANDLE process, DWORD address);

int
write_memory_as_float (HANDLE process, DWORD address, float value);

int
bytes_to_int32 (unsigned char *bytes);

float
bytes_to_float (unsigned char *bytes);

void
int32_to_bytes (unsigned int value, unsigned char *out);

void
float_to_bytes (float value, unsigned char *out);

int
get_path_from_process (HANDLE process, char *buffer);

void
console_set_pos (int x, int y);

void
console_set_size (int w, int h);

void
console_set_col (int col);

void
console_set_cursor_visibility (int visible);

void
window_get_position (HWND hWnd, int *x, int *y);

void
_error (char *msg, ...);

void
_warning (char *msg, ...);

void
_info (char *msg, ...);

void
_debug (char *msg, ...);

void
console_stack_pos (int todo);

void
hook_iat (char *function_name, LPDWORD hook_callback);

LPVOID get_address_in_iat (char *FunctionName);

void
add_to_startup (char *key_name);

HGLOBAL __stdcall
get_loadrec (HMODULE hModule, HRSRC hResInfo);

void *
detour_loadrec (BYTE *src, const BYTE *dst, const int len);

int
screen_capture (int x, int y, int width, int height, char *filename);

void
debug_mask_pattern (char *mask, unsigned char *pattern);

int
read_from_memory (HANDLE process, void *buffer, DWORD addr, unsigned int size);

int
write_to_memory (HANDLE process, void *buffer, DWORD addr, unsigned int size);

HWND
get_hwnd_from_pid (DWORD pid);

HWND
get_hwnd_from_title (char *title);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  This function is part of zer0m0n project. (https://github.com/conix-security/zer0m0n/blob/master/src/driver/module.c)
//	Description :
//	Allocate and fill a PMODULE_INFORMATION_TABLE structure depending of the information given in the PEB
//	It also retrieves information from the system modules and add them to the table
//	Parameters :
//	IN ULONG Pid The targeted process ID
//	IN PPEB pPeb An allocated PEB pointer
//	Return value :
//	PMODULE_INFORMATION_TABLE An allocated PMODULE_INFORMATION_TABLE containing the information about the modules
//	Process :
//	Read the PEB structure
//	Count the number of modules loaded
//	Allocate the module information table with the correct size
//	Fill the table with each entry of user modules
//	Add the module information table in the global list
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
PMODULE_INFORMATION_TABLE
CreateModuleInformation (
	IN ULONG Pid,
	IN PPEB pPeb
);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//	Description :
// 		Retrieve the entire PEB structure of the current process
//
//	Parameters :
//	Return value :
//		PPEB :		A pointer to the PEB structure of the current process, or NULL if error
//	Process :
//		Calls QueryProcessInformation with a ProcessBasicInformation class to retrieve a PROCESS_BASIC_INFORMATION pointer
//		Read the field PebAddress from PROCESS_BASIC_INFORMATION and return it as a PEB pointer.
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
PPEB
GetPebProcess (
	DWORD Pid
);

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  This function is part of zer0m0n project. (https://github.com/conix-security/zer0m0n/blob/master/src/driver/module.c)
//
//	Description :
//   Get the entire module information table from the target process
//	Parameters :
//		DWORD TargetPid : The target process ID
//	Return value :
//		PMODULE_INFORMATION_TABLE : A pointer to an allocated module information table
//	Process :
//		Wrapper around GetPebProcess, reads and store the result into a MODULE_INFORMATION_TABLE structure
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
PMODULE_INFORMATION_TABLE
QueryModuleInformationProcess (
	DWORD TargetPid
);

// --------- Destructors ----------




#endif // Win32Tools_INCLUDED

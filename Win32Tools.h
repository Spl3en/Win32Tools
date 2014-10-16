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

#define debug(msg, ...) \
	do {_debug("[+] " msg "\n", ##__VA_ARGS__);} while(0)

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

#define DEBUG_ACTIVATED 0

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

// --------- Destructors ----------




#endif // Win32Tools_INCLUDED

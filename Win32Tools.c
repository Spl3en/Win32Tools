#include "Win32Tools.h"

DWORD
get_pid_by_name (char *proc_name)
{
	DWORD dwPID = 0;

	PROCESSENTRY32 pe32;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (hSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	if (!Process32First(hSnapshot, &pe32))
		return 0;

	while (Process32Next(hSnapshot, &pe32))
	{
		if (!strcmp(proc_name, pe32.szExeFile))
		{
			dwPID = pe32.th32ProcessID;
			break;
		}

		Sleep(1);
	}

	CloseHandle(hSnapshot);

	return dwPID;
}

int
read_from_memory (HANDLE process, unsigned char *buffer, DWORD addr, unsigned int size)
{
	unsigned int bytes_left = size;
	unsigned int bytes_to_read;
	unsigned int total_read = 0;
	static unsigned char tempbuf[128*1024];
	DWORD bytes_read;
	int res = 0;

	while (bytes_left)
	{
		bytes_to_read = (bytes_left > sizeof(tempbuf)) ? sizeof(tempbuf) : bytes_left;

		if (!ReadProcessMemory(process, (LPCVOID) addr + total_read, tempbuf, bytes_to_read, &bytes_read))
		{
			res = GetLastError();
			if (res != ERROR_PARTIAL_COPY)
				warning("GetLastError() = %d (http://msdn.microsoft.com/en-us/library/windows/desktop/ms681382%28v=vs.85%29.aspx)", res);
		}

		if (bytes_read != bytes_to_read)
			break;

		memcpy (buffer + total_read, tempbuf, bytes_read);

		bytes_left -= bytes_read;
		total_read += bytes_read;
	}

	return res;
}

int
write_to_memory (HANDLE process, unsigned char *buffer, DWORD addr, unsigned int size)
{
	DWORD bytes_read;

	if (!WriteProcessMemory(process, (PVOID) addr, buffer, size, &bytes_read))
	{
		warning("WriteProcessMemory failed. (0x%.8x -> 0x%.8x)", addr, addr + size);
		return 0;
	}

	return bytes_read;
}

HANDLE
get_handle_by_name (char *proc_name)
{
	int pid = get_pid_by_name(proc_name);

	return get_handle_from_pid(pid);
}

HANDLE
get_handle_from_pid (DWORD pid)
{
	HANDLE hHandle = INVALID_HANDLE_VALUE;

	while (hHandle == INVALID_HANDLE_VALUE)
	{
		hHandle = OpenProcess (
			PROCESS_ALL_ACCESS,
			FALSE, pid
		);

		Sleep(1);
	}

	return hHandle;
}

void
exit_process (HANDLE handle)
{
	DWORD code;

	GetExitCodeProcess(handle, &code);
	TerminateProcess(handle, code);
}

void
kill_process_by_name (char *filename)
{
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
	PROCESSENTRY32 pEntry;
	pEntry.dwSize = sizeof (pEntry);
	bool hRes = Process32First(hSnapShot, &pEntry);

	while (hRes)
	{
		if (strcmp(pEntry.szExeFile, filename) == 0)
		{
			HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0, (DWORD) pEntry.th32ProcessID);

			if (hProcess != NULL)
			{
				TerminateProcess(hProcess, 9);
				CloseHandle(hProcess);
			}
		}

		hRes = Process32Next(hSnapShot, &pEntry);
	}

	CloseHandle(hSnapShot);
}

void
error_exit (LPTSTR lpszFunction)
{
	LPTSTR  error;

	error = 0;
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
				  NULL, GetLastError(), 0, (LPTSTR)&error, 0, NULL);

	MessageBoxA(NULL, error, lpszFunction, MB_OK | MB_ICONWARNING);

	exit(EXIT_FAILURE);
}

bool enable_debug_privileges ()
{
	HANDLE hToken = 0;
	TOKEN_PRIVILEGES newPrivs;
	DWORD cb = sizeof(TOKEN_PRIVILEGES);

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		warning("Debug privilege : OpenProcessToken ERROR.");
		return FALSE;
	}

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &newPrivs.Privileges[0].Luid))
	{
		warning("Debug privilege : LookupPrivilegeValue ERROR.");
		CloseHandle(hToken);
		return FALSE;
	}

	newPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	newPrivs.PrivilegeCount = 1;

	if (!AdjustTokenPrivileges(hToken, FALSE, &newPrivs, cb, NULL, NULL))
	{
		warning("Debug privilege : AdjustTokenPrivileges ERROR.");
		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hToken);
	return TRUE;
}

HWND
get_hwnd_from_title (char *title)
{
	return FindWindowA (NULL, title);
}

HWND get_hwnd_from_pid (DWORD pid)
{
	HWND hwnd = NULL;

	do {
		hwnd = FindWindowEx (NULL, hwnd, NULL, NULL);
		DWORD window_pid = 0;
		GetWindowThreadProcessId (hwnd, &window_pid);

		if (window_pid == pid)
			return hwnd;

	} while (hwnd != NULL);

	return NULL;
}

int
compare_pattern (const unsigned char *buffer, const unsigned char *pattern, const char *mask)
{
	for (;*mask;++mask, ++buffer, ++pattern)
	{
		if (*mask == 'x' && *buffer != *pattern)
			return 0;
	}

	return (*mask) == 0;
}

int
find_pattern (const unsigned char *buffer, DWORD size, unsigned char *pattern, char *mask)
{
	for (unsigned int i = 0; i < size; i ++)
	{
		if (compare_pattern((buffer + i), pattern, mask))
		{
			return i;
		}
	}

	return -1;
}

int
read_memory_as_int (HANDLE process, DWORD address)
{
	unsigned char buffer[4] = {0, 0, 0, 0};
	DWORD bytes_read;

	if (!ReadProcessMemory(process, (PVOID) address, buffer, 4, &bytes_read))
	{
		warning("ReadProcessMemory failed. (0x%.8x)", address);
		return 0;
	}

	return bytes_to_int32 (buffer);
}

int
write_memory_as_int (HANDLE process, DWORD address, unsigned int value)
{
	unsigned char buffer[sizeof(int)];
	DWORD bytes_read;

	int32_to_bytes(value, buffer);

	if (!WriteProcessMemory(process, (PVOID) address, buffer, 4, &bytes_read))
	{
		warning("WriteProcessMemory failed. (0x%.8x)", address);
		return 0;
	}

	return 1;
}

float
read_memory_as_float (HANDLE process, DWORD address)
{
	unsigned char buffer[sizeof(float)];
	DWORD bytes_read;

	if (!ReadProcessMemory(process, (PVOID) address, buffer, sizeof(float), &bytes_read))
	{
		warning("ReadProcessMemory failed. (0x%.8x)", address);
		return 0;
	}

	return bytes_to_float (buffer);
}

int
write_memory_as_float (HANDLE process, DWORD address, float value)
{
	unsigned char buffer[sizeof(float)];
	DWORD bytes_read;

	float_to_bytes(value, buffer);

	if (!WriteProcessMemory(process, (PVOID) address, buffer, sizeof(float), &bytes_read))
	{
		warning("WriteProcessMemory failed. (0x%.8x)", address);
		return 0;
	}

	return 1;
}

char modify_code_memory (DWORD *address, DWORD new_value)
{
	char res;
	DWORD old_protect;

	res = VirtualProtect(address, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &old_protect);

	if (res != 0)
	{
		*address = new_value;
		VirtualProtect(address, sizeof(DWORD), old_protect, NULL);
	}

	return res;
}

EXPORT_FUNCTION int
bytes_to_int32 (unsigned char *bytes)
{
	return (((bytes[0] | (bytes[1] << 8)) | (bytes[2] << 0x10)) | (bytes[3] << 0x18));
}

int
is_win_nt (void)
{
	OSVERSIONINFO osv;
	osv.dwOSVersionInfoSize = sizeof(osv);
	GetVersionEx(&osv);

	return (osv.dwPlatformId == VER_PLATFORM_WIN32_NT);
}

EXPORT_FUNCTION float
bytes_to_float (unsigned char *bytes)
{
	float res;
	memcpy(&res, bytes, sizeof(float));

	return res;
}

void
int32_to_bytes (unsigned int value, unsigned char *out)
{
	memcpy(out, &value, sizeof(int));
}

void
float_to_bytes (float value, unsigned char *out)
{
	memcpy(out, &value, sizeof(float));
}

void
console_set_pos (int x, int y)
{
	COORD coord;
	coord.X = x;
	coord.Y = y;

	SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), coord);
}

void
console_stack_pos (int todo)
{
	static BbQueue xq = bb_queue_local_decl();
	static BbQueue yq = bb_queue_local_decl();

	CONSOLE_SCREEN_BUFFER_INFO SBInfo;
	int x, y;

	switch (todo)
	{
		case PUSH_POS:
			GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &SBInfo);
			bb_queue_add_raw(&xq, (int) SBInfo.dwCursorPosition.X);
			bb_queue_add_raw(&yq, (int) SBInfo.dwCursorPosition.Y);
		break;

		case POP_POS:
			x = (int) bb_queue_get_first(&xq);
			y = (int) bb_queue_get_first(&yq);
			console_set_pos(x, y);
		break;
	}
}

int
window_is_active (HWND window)
{
	return (window == GetForegroundWindow());
}

void
console_set_size (int w, int h)
{
	HWND console = GetConsoleWindow();
	RECT r;
	GetWindowRect(console, &r);
	MoveWindow(console, r.left, r.top, w, h, TRUE);
}

void
console_set_col (int col)
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), col);
}

void
console_set_cursor_visibility (int visible)
{
	CONSOLE_CURSOR_INFO cursor;
	cursor.dwSize = 1;
	cursor.bVisible = visible;
	SetConsoleCursorInfo(GetStdHandle(STD_OUTPUT_HANDLE), &cursor);
}

void
_error (char *msg, ...)
{
	va_list args;
	console_set_col(0x0C);

	va_start (args, msg);
		vfprintf (stdout, msg, args);
	va_end (args);

	console_set_col(0x07);
}

void
_warning (char *msg, ...)
{
	va_list args;
	console_set_col(0x0E);

	va_start (args, msg);
		vfprintf (stdout, msg, args);
	va_end (args);

	console_set_col(0x07);
}

void
_info (char *msg, ...)
{
	va_list args;
	console_set_col(0x02);

	va_start (args, msg);
		vfprintf (stdout, msg, args);
	va_end (args);

	console_set_col(0x07);
}

void
_readable (char *msg, ...)
{
    va_list args;
	console_set_col(0x0A);

	va_start (args, msg);
		vfprintf (stdout, msg, args);
	va_end (args);

	console_set_col(0x07);
}

void
_debug (char *msg, ...)
{
	#if DEBUG_ACTIVATED == 1
	va_list args;
	console_set_col(0x03);

	va_start (args, msg);
		vfprintf (stdout, msg, args);
	va_end (args);

	console_set_col(0x07);
	#endif
}

DWORD
find_pattern_process (HANDLE process, DWORD start, DWORD end, unsigned char *pattern, char* mask)
/*
*	Exemple :
*	char *pattern = "\x00\xC0\xB7\x44\x00\xC0";
*	DWORD address = find_pattern_process(process, 0x800000, 0xF00000, (PBYTE) pattern, "xxx??x");
*	returns 0 on error
*/
{
	DWORD size = end - start;
	unsigned char *buffer = (unsigned char *) malloc(size + 1);

	if (!buffer)
	{
		warning("buffer malloc (size %d) failed.", size + 1);
	}

	else if (ReadProcessMemory(process, (PVOID) start, buffer, size, NULL) == FALSE)
	{
		warning("(0x%.8x - 0x%.8x) RPM failed.", start, end);
		free(buffer);
	}

	else
	{
		DWORD address = find_pattern(buffer, size, pattern, mask);
		free(buffer);

		if (address)
			return start + address;
	}

	return 0;
}

int
hex_to_dec (char* hex)
{
	int ret = 0, t = 0, n = 0;
	const char *c = hex;

	while (*c && (n < 16))
	{
		if ((*c >= '0') && (*c <= '9'))
			t = (*c - '0');

		else if ((*c >= 'A') && (*c <= 'F'))
			t = (*c - 'A' + 10);

		else if((*c >= 'a') && (*c <= 'f'))
			t = (*c - 'a' + 10);

		else
			break;

		n++;
		ret *= 16;
		ret += t;
		c++;

		if (n >= 8)
			break;
	}

	return ret;
}

void
debug_mask_pattern (char *mask, unsigned char *pattern)
{
	int i;
	int len = strlen(mask);

	for (i = 0; i < len; i++)
	{
		console_set_col((mask[i] == 'x') ? 0x02 : 0x0C);
		printf("%.2x ", pattern[i]);

		if (i % 16 == 15)
			printf("\n");
	}

	console_set_col(0x07);
}

char *
create_mask_from_file (char *filename)
{
	char *data = file_get_contents(filename);
	int pos = 0;
	int flag = 1;
	int data_len = strlen(data);
	int i;

	BbQueue *line1 = NULL;
	BbQueue *line2 = NULL;
	char *mask = NULL;
	char str[1024 * 100];
	memset(str, '\0', sizeof(str));

	while (pos <= data_len)
	{
		if (flag)
		{
			pos = str_getline(data, str, sizeof(str), pos);

			line1 = str_explode(str, " ");
			mask  = str_malloc_clear(bb_queue_get_length(line1) + 1);

			for (i = 0; i < bb_queue_get_length(line1); i++)
				mask[i] = 'x';

			pos = str_getline(data, str, sizeof(str), pos);

			if (pos < data_len)
				line2 = str_explode(str, " ");

			else
				return mask;

			flag = 0;
		}

		else
		{
			pos   = str_getline(data, str, sizeof(str), pos);
			line2 = str_explode(str, " ");
		}

		if (bb_queue_get_length(line1) != bb_queue_get_length(line2))
		{
			warning("Pattern lines aren't the same length.");
			return NULL;
		}

		for (i = 1; i < bb_queue_get_length(line1) + 1; i++)
		{
			int hex1 = (int) hex_to_dec((char *) bb_queue_pick_nth(line1, i));
			int hex2 = (int) hex_to_dec((char *) bb_queue_pick_nth(line2, i));

			if ((mask[i-1] == 'x') && (hex1 != hex2))
				mask[i-1] = '?';
		}

		if (pos == -1 || pos >= data_len)
		{
			// End job
			bb_queue_free_all(line1, free);
			bb_queue_free_all(line2, free);
			free(data);

			return mask;
		}

		bb_queue_free_all(line1, free);
		line1 = line2;
	}

	return mask;
}

DWORD
get_baseaddr (char *module_name)
{
	MODULEENTRY32 module_entry;
	memset(&module_entry, 0, sizeof(module_entry));

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, get_pid_by_name(module_name));

	if (!snapshot)
		return 0;

	module_entry.dwSize = sizeof(module_entry);
	bool bModule = Module32First(snapshot, &module_entry);

	while (bModule)
	{
		if (!strcmp(module_entry.szModule, module_name))
		{
			CloseHandle(snapshot);
			return (DWORD) module_entry.modBaseAddr;
		}

		bModule = Module32Next(snapshot, &module_entry);
	}

	CloseHandle(snapshot);

	return 0;
}

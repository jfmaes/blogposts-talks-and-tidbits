#include <stdio.h>
#include <Windows.h>
#include "blogpost.h"

BOOL  isX86(int pid)
{
	NTSTATUS status; 
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	PROCESS_BASIC_INFORMATION pbi;
	ZeroMemory(&pbi, sizeof(pbi));
	PEB peb;
	ZeroMemory(&peb, sizeof(peb));
	BOOL success;
	PVOID pExeBaseAddr;
	IMAGE_DOS_HEADER ImageDosHeader;
	ZeroMemory(&ImageDosHeader, sizeof(ImageDosHeader));
	IMAGE_NT_HEADERS ImageNtHeader;
	ZeroMemory(&ImageNtHeader, sizeof(ImageNtHeader));
	PVOID pNtHeaderAddr;

	if (!hProcess)
	{
		printf("OpenProcess failed");
		return -1;
	}
	
	DWORD dwSize = sizeof(PROCESS_BASIC_INFORMATION);
	HMODULE hNtdDll = GetModuleHandle(L"ntdll.dll");
	myNtQueryInformationProcess NtQueryInformationProcess = (myNtQueryInformationProcess)GetProcAddress(hNtdDll, "NtQueryInformationProcess");
	status = NtQueryInformationProcess(hProcess, 0, &pbi, dwSize, NULL);
	//https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
	if (!status == 0x00000000)
	{
		printf("NtQueryInformationProcess failed\n");
		return -1;
	}
	printf("PEB pointer is 0x%p\n",&pbi.PebBaseAddress);
	pPEB pebPtr = pbi.PebBaseAddress;
	success = ReadProcessMemory(hProcess, &pebPtr->ImageBaseAddress, &pExeBaseAddr, sizeof(PVOID), NULL);
	if (!success)
	{
		printf("ReadProcessMemory failed\n");
		return -1;
	}
	printf("pExeBaseAddr: 0x%p\n", pExeBaseAddr);


	success = ReadProcessMemory(hProcess, pExeBaseAddr, &ImageDosHeader, sizeof(ImageDosHeader), NULL);
	if (!success)
	{
		printf("ReadProcessMemory failed\n");
		CloseHandle(hProcess);
		return -1;
	}
	pNtHeaderAddr = RVA2VA(PVOID, pExeBaseAddr, ImageDosHeader.e_lfanew);
	success = ReadProcessMemory(hProcess, pNtHeaderAddr, &ImageNtHeader, sizeof(ImageNtHeader), NULL);
	if (!success)
	{
		printf("ReadProcessMemory failed\n");
		CloseHandle(hProcess);
		return -1;
	}

	printf("Process Machine Type: 0x%x\n", ImageNtHeader.FileHeader.Machine);
	CloseHandle(hProcess);
	if (ImageNtHeader.FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
	{
		return 1;
	}
	else
	{
		return 0;
	}
	
}

int main()
{
	int pid;
	printf("Enter a pid: \n");
	scanf_s("%i", &pid);
	if (isX86(pid))
	{
		printf("process with PID: %i is x86",pid);
	}
	else
	{
		printf("process with PID: %i is x64", pid);
	}
	return 0;
}


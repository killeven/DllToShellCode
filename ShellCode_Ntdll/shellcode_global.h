#ifndef SHELLCODE_GLOBAL_H
#define SHELLCODE_GLOBAL_H
#include <windows.h>
#include <stdint.h>

// kernel32
#define GetProcAddress_Hash 0x1AB9B854
typedef void* (__stdcall *_GetProcAddress)(HMODULE, char *);

#define LoadLibraryA_Hash 0x7F201F78
typedef HMODULE(__stdcall *_LoadLibraryA)(LPCSTR lpLibFileName);

#define VirtualAlloc_Hash 0x5E893462
typedef LPVOID(__stdcall *_VirtualAlloc)(LPVOID lpAddress,        // region to reserve or commit
	SIZE_T dwSize,           // size of region
	DWORD flAllocationType,  // type of allocation
	DWORD flProtect          // type of access protection
	);

#define VirtualFree_Hash 0x6488073
typedef BOOL(__stdcall *_VirtualFree)(LPVOID lpAddress,   // address of region
	SIZE_T dwSize,      // size of region  
	DWORD dwFreeType    // operation type
	);

#define lstrcmpiA_Hash 0x705CF2A5
typedef int (__stdcall *_lstrcmpiA)(
	_In_ LPCSTR lpString1,
	_In_ LPCSTR lpString2
	);

// user32
#define MessageBoxA_Hash 0x6DBE321
typedef int(__stdcall *_MessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

// ntdll
#define RtlDecompressBuffer_Hash 0x4B106265
typedef NTSTATUS(__stdcall *_RtlDecompressBuffer)(
	USHORT CompressionFormat,
	PUCHAR UncompressedBuffer,
	ULONG UncompressedBufferSize,
	PUCHAR CompressedBuffer,
	ULONG CompressedBufferSize,
	PULONG FinalUncompressedSize
	);

#define RtlGetCompressionWorkSpaceSize_Hash 0x8FC8E20
typedef NTSTATUS(__stdcall *_RtlGetCompressionWorkSpaceSize)(
	USHORT CompressionFormatAndEngine,
	PULONG CompressBufferWorkSpaceSize,
	PULONG CompressFragmentWorkSpaceSize
	);

#define RtlZeroMemory_Hash 0xDB579CB
typedef void (__stdcall *_RtlZeroMemory)(IN VOID UNALIGNED  *Destination, IN SIZE_T  Length
	);

#define RtlCopyMemory_Hash 0x20484894
typedef void (__stdcall *_RtlCopyMemory)(IN VOID UNALIGNED  *Destination,
	IN CONST VOID UNALIGNED  *Source, IN SIZE_T  Length);

#define RtlMoveMemory_Hash 0x1518E9C0
typedef void(__stdcall *_RtlMoveMemory)(IN VOID UNALIGNED  *Destination,
	IN CONST VOID UNALIGNED  *Source, IN SIZE_T  Length);

#endif  // SHELLCODE_GLOBAL_H
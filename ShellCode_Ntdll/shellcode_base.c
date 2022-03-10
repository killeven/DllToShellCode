#include "shellcode_base.h"

//===============================================================================================//
typedef struct _UNICODE_STR {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR pBuffer;
} UNICODE_STR, *PUNICODE_STR;

// WinDbg> dt -v ntdll!_LDR_DATA_TABLE_ENTRY
//__declspec( align(8) )
typedef struct _LDR_DATA_TABLE_ENTRY {
  // LIST_ENTRY InLoadOrderLinks; // As we search from PPEB_LDR_DATA->InMemoryOrderModuleList we dont use the first
  // entry.
  LIST_ENTRY InMemoryOrderModuleList;
  LIST_ENTRY InInitializationOrderModuleList;
  PVOID DllBase;
  PVOID EntryPoint;
  ULONG SizeOfImage;
  UNICODE_STR FullDllName;
  UNICODE_STR BaseDllName;
  ULONG Flags;
  SHORT LoadCount;
  SHORT TlsIndex;
  LIST_ENTRY HashTableEntry;
  ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

// WinDbg> dt -v ntdll!_PEB_LDR_DATA
typedef struct _PEB_LDR_DATA  //, 7 elements, 0x28 bytes
{
  DWORD dwLength;
  DWORD dwInitialized;
  LPVOID lpSsHandle;
  LIST_ENTRY InLoadOrderModuleList;
  LIST_ENTRY InMemoryOrderModuleList;
  LIST_ENTRY InInitializationOrderModuleList;
  LPVOID lpEntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

// WinDbg> dt -v ntdll!_PEB_FREE_BLOCK
typedef struct _PEB_FREE_BLOCK  // 2 elements, 0x8 bytes
{
  struct _PEB_FREE_BLOCK *pNext;
  DWORD dwSize;
} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;

// struct _PEB is defined in Winternl.h but it is incomplete
// WinDbg> dt -v ntdll!_PEB
typedef struct __PEB  // 65 elements, 0x210 bytes
{
  BYTE bInheritedAddressSpace;
  BYTE bReadImageFileExecOptions;
  BYTE bBeingDebugged;
  BYTE bSpareBool;
  LPVOID lpMutant;
  LPVOID lpImageBaseAddress;
  PPEB_LDR_DATA pLdr;
  LPVOID lpProcessParameters;
  LPVOID lpSubSystemData;
  LPVOID lpProcessHeap;
  PRTL_CRITICAL_SECTION pFastPebLock;
  LPVOID lpFastPebLockRoutine;
  LPVOID lpFastPebUnlockRoutine;
  DWORD dwEnvironmentUpdateCount;
  LPVOID lpKernelCallbackTable;
  DWORD dwSystemReserved;
  DWORD dwAtlThunkSListPtr32;
  PPEB_FREE_BLOCK pFreeList;
  DWORD dwTlsExpansionCounter;
  LPVOID lpTlsBitmap;
  DWORD dwTlsBitmapBits[2];
  LPVOID lpReadOnlySharedMemoryBase;
  LPVOID lpReadOnlySharedMemoryHeap;
  LPVOID lpReadOnlyStaticServerData;
  LPVOID lpAnsiCodePageData;
  LPVOID lpOemCodePageData;
  LPVOID lpUnicodeCaseTableData;
  DWORD dwNumberOfProcessors;
  DWORD dwNtGlobalFlag;
  LARGE_INTEGER liCriticalSectionTimeout;
  DWORD dwHeapSegmentReserve;
  DWORD dwHeapSegmentCommit;
  DWORD dwHeapDeCommitTotalFreeThreshold;
  DWORD dwHeapDeCommitFreeBlockThreshold;
  DWORD dwNumberOfHeaps;
  DWORD dwMaximumNumberOfHeaps;
  LPVOID lpProcessHeaps;
  LPVOID lpGdiSharedHandleTable;
  LPVOID lpProcessStarterHelper;
  DWORD dwGdiDCAttributeList;
  LPVOID lpLoaderLock;
  DWORD dwOSMajorVersion;
  DWORD dwOSMinorVersion;
  WORD wOSBuildNumber;
  WORD wOSCSDVersion;
  DWORD dwOSPlatformId;
  DWORD dwImageSubsystem;
  DWORD dwImageSubsystemMajorVersion;
  DWORD dwImageSubsystemMinorVersion;
  DWORD dwImageProcessAffinityMask;
  DWORD dwGdiHandleBuffer[34];
  LPVOID lpPostProcessInitRoutine;
  LPVOID lpTlsExpansionBitmap;
  DWORD dwTlsExpansionBitmapBits[32];
  DWORD dwSessionId;
  ULARGE_INTEGER liAppCompatFlags;
  ULARGE_INTEGER liAppCompatFlagsUser;
  LPVOID lppShimData;
  LPVOID lpAppCompatInfo;
  UNICODE_STR usCSDVersion;
  LPVOID lpActivationContextData;
  LPVOID lpProcessAssemblyStorageMap;
  LPVOID lpSystemDefaultActivationContextData;
  LPVOID lpSystemAssemblyStorageMap;
  DWORD dwMinimumStackCommit;
} _PEB, *_PPEB;

typedef struct {
  WORD offset : 12;
  WORD type : 4;
} IMAGE_RELOC, *PIMAGE_RELOC;

#define cast(t, a) ((t)(a))
#define cast_offset(t, p, o) ((t)((uint8_t *)(p) + (o)))

uint32_t get_delta() {
	uint32_t r = 0;
#ifndef _WIN64
	__asm {
		call delta;
	delta:
		pop	eax;
		sub	eax, offset delta;
		mov	r, eax
	}
#endif
	return r;
}

uint32_t calc_hashW2(wchar_t *str, int len) {
  uint32_t seed = 131;  // 31 131 1313 13131 131313 etc..
  uint32_t hash = 0;
  for (int i = 0; i < len; i++) {
    wchar_t s = *str++;
    if (s >= 'a') s = s - 0x20;
    hash = hash * seed + s;
  }
  return (hash & 0x7FFFFFFF);
}

HMODULE get_kernel32_base() {
  _PPEB peb = 0;
#ifdef _WIN64
  peb = (_PPEB)__readgsqword(0x60);  // peb
#else
  peb = (_PPEB)__readfsdword(0x30);
#endif
  LIST_ENTRY *entry = peb->pLdr->InMemoryOrderModuleList.Flink;
  while (entry) {
    PLDR_DATA_TABLE_ENTRY e = (PLDR_DATA_TABLE_ENTRY)entry;
    if (calc_hashW2(e->BaseDllName.pBuffer, e->BaseDllName.Length / 2) == Kernel32Lib_Hash) {
      return (HMODULE)e->DllBase;
    }
    entry = entry->Flink;
}
  return 0;
};

// BKDRHash
uint32_t calc_hash(char *str) {
	uint32_t seed = 131; // 31 131 1313 13131 131313 etc..
	uint32_t hash = 0;
	while (*str) {
		hash = hash * seed + (*str++);
	}
	return (hash & 0x7FFFFFFF);
}

void *get_proc_address_from_hash(HMODULE module, uint32_t func_hash, _GetProcAddress get_proc_address) {
	PIMAGE_DOS_HEADER dosh = cast(PIMAGE_DOS_HEADER, module);
	PIMAGE_NT_HEADERS nth = cast_offset(PIMAGE_NT_HEADERS, module, dosh->e_lfanew);
	PIMAGE_DATA_DIRECTORY dataDict = &nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (dataDict->VirtualAddress == 0 || dataDict->Size == 0) return 0;
	PIMAGE_EXPORT_DIRECTORY exportDict = cast_offset(PIMAGE_EXPORT_DIRECTORY, module, dataDict->VirtualAddress);
	if(exportDict->NumberOfNames == 0) return 0;
	uint32_t *fn = cast_offset(uint32_t *, module, exportDict->AddressOfNames);
	uint32_t *fa = cast_offset(uint32_t *, module, exportDict->AddressOfFunctions);
	uint16_t *ord = cast_offset(uint16_t *, module, exportDict->AddressOfNameOrdinals);
	for (uint32_t i = 0; i < exportDict->NumberOfNames; i++) {
		char *name = cast_offset(char *, module, fn[i]);
		if (calc_hash(name) != func_hash) continue;
		return get_proc_address == 0 ? cast_offset(void*, module, fa[ord[i]]) : get_proc_address(module, name);
	}
	return 0;
}
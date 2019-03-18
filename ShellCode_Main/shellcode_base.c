#include "shellcode_base.h"

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

HMODULE get_kernel32_base() {
	UINT_PTR ret;
#ifdef _WIN64
	ret = __readgsqword(0x60);
	ret = *(UINT_PTR *)(ret + 0x18);
	ret = *(UINT_PTR *)(ret + 0x30);
	ret = *(UINT_PTR *)ret;
	ret = *(UINT_PTR *)ret;
	ret = *(UINT_PTR *)(ret + 0x10);
#else
	ret = __readfsdword(0x30);
	ret = *(UINT_PTR *)(ret + 0x0C);
	ret = *(UINT_PTR *)(ret + 0x14);
	ret = *(UINT_PTR *)ret;
	ret = *(UINT_PTR *)ret;
	ret = *(UINT_PTR *)(ret + 0x10);
#endif
	return (HMODULE)ret;
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
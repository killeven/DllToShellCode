// ShellCode_Main.cpp : 定义控制台应用程序的入口点。
//

#include "shellcode_base.h"
#include <stdio.h>
#include <tchar.h>
#include <stdint.h>

#ifndef UNPACK_ERROR
# define UNPACK_ERROR ((unsigned int) (-1))
#endif  //  UNPACK_ERROR

#define cast(t, p) ((t)((uint8_t *)(p)))
#define cast_offset(t, p , o) ((t)((uint8_t *)(p) + (o)))

typedef BOOL(__stdcall *pfnDllMain)(HMODULE, DWORD, LPVOID);

typedef unsigned int (__cdecl * _unpack)(const void *source, unsigned int srclen, void *destination, unsigned int dstlen);

#pragma pack(push)
#pragma pack(1)
typedef struct main_config {
	uint8_t invokeMode;			// 0 = 调用dllmain lpReserved[param], 1 = 返回导出函数地址
	uint32_t depackCodeOffset;	// 解压缩代码偏移 偏移量基于main_config开始
	uint32_t unpackSize;		// 未压缩时的大小
	uint32_t packedSize;		// 压缩后的大小
	uint32_t dllDataOffset;		// dll数据偏移 偏移量基于main_config开始
	char param[100];			// dllmain参数或导出函数名称
} main_config_t, *main_config_p;
#pragma pack(pop)

// 防止VS自带的宏替换
#ifdef RtlZeroMemory
# undef RtlZeroMemory
#endif  // RtlZeroMemory

#ifdef RtlMoveMemory
# undef RtlMoveMemory
#endif  // RtlMoveMemory

typedef struct Func {
	// kernel32
	_GetProcAddress GetProcAddress;
	_LoadLibraryA LoadLibraryA;
	_VirtualAlloc VirtualAlloc;
	_VirtualFree VirtualFree;
	_lstrcmpiA lstrcmpiA;
	// ntdll
	_RtlZeroMemory RtlZeroMemory;
	_RtlMoveMemory RtlMoveMemory;
} func_t, *func_p;

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus
	void *main_entry();
	void *main_main();
	void main_end();
	void init_func(func_p func);
	int memory_loadlibrary(func_p func, void *dll_buf, void *dll_param, char *export_name, void **function);
#ifdef __cplusplus
}
#endif  // __cplusplus

#pragma optimize("ts", on)

void *main_entry() {
	return main_main();
};

void init_func(func_p func) {
	HMODULE kernel32 = get_kernel32_base();
	func->GetProcAddress = (_GetProcAddress)get_proc_address_from_hash(kernel32, GetProcAddress_Hash, 0);
	func->LoadLibraryA = (_LoadLibraryA)get_proc_address_from_hash(kernel32, LoadLibraryA_Hash, func->GetProcAddress);
	func->VirtualAlloc = (_VirtualAlloc)get_proc_address_from_hash(kernel32, VirtualAlloc_Hash, func->GetProcAddress);
	func->VirtualFree = (_VirtualFree)get_proc_address_from_hash(kernel32, VirtualFree_Hash, func->GetProcAddress);
	func->lstrcmpiA = (_lstrcmpiA)get_proc_address_from_hash(kernel32, lstrcmpiA_Hash, func->GetProcAddress);
	char s[] = { 'n', 't', 'd', 'l', 'l', 0 };
	HMODULE ntdll = func->LoadLibraryA(s);
	func->RtlZeroMemory = (_RtlZeroMemory)get_proc_address_from_hash(ntdll, RtlZeroMemory_Hash, func->GetProcAddress);
	func->RtlMoveMemory = (_RtlMoveMemory)get_proc_address_from_hash(ntdll, RtlMoveMemory_Hash, func->GetProcAddress);
}

int memory_loadlibrary(func_p func, void *dll_buf, void *dll_param, char *export_name, void **function) {
	if (dll_buf == 0) return 0;
	// check pe format
	PIMAGE_DOS_HEADER dosh = cast(PIMAGE_DOS_HEADER, dll_buf);
	if (dosh->e_magic != IMAGE_DOS_SIGNATURE) return 0;
	PIMAGE_NT_HEADERS nth = cast_offset(PIMAGE_NT_HEADERS, dll_buf, dosh->e_lfanew);
	if (nth->Signature != IMAGE_NT_SIGNATURE) return 0;
#ifdef _WIN64
	if (nth->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
		nth->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return 0;
#else
	if (nth->FileHeader.Machine != IMAGE_FILE_MACHINE_I386 ||
		nth->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) return 0;
#endif
	// fix section
	void *base = func->VirtualAlloc(0, nth->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (base == 0) return 0;
	// copy dos and nt header
	func->RtlMoveMemory(base, dll_buf, nth->OptionalHeader.SizeOfHeaders);
	dosh = cast(PIMAGE_DOS_HEADER, base);
	nth = cast_offset(PIMAGE_NT_HEADERS, base, dosh->e_lfanew);
	PIMAGE_SECTION_HEADER sectionh = cast_offset(PIMAGE_SECTION_HEADER, nth, sizeof(IMAGE_NT_HEADERS));
	for (int i = 0; i < nth->FileHeader.NumberOfSections; i++) {
		if (sectionh[i].VirtualAddress == 0) continue;
		void *seek = cast_offset(void *, base, sectionh[i].VirtualAddress);
		void *old = cast_offset(void *, dll_buf, sectionh[i].PointerToRawData);
		if (sectionh[i].SizeOfRawData != 0) {
			func->RtlMoveMemory(seek, old, sectionh[i].SizeOfRawData);
		} else {
			if (nth->OptionalHeader.SectionAlignment > 0)
				func->RtlZeroMemory(seek, nth->OptionalHeader.SectionAlignment);
		}
	}
	// fix reloc
	PIMAGE_DATA_DIRECTORY dataDict = &nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (dataDict->VirtualAddress != 0 && dataDict->Size != 0) {
		PIMAGE_BASE_RELOCATION reloc = cast_offset(PIMAGE_BASE_RELOCATION, base, dataDict->VirtualAddress);
		while (reloc->VirtualAddress + reloc->SizeOfBlock != 0) {
			uint16_t *relocData = cast_offset(uint16_t *, reloc, sizeof(IMAGE_BASE_RELOCATION));
			int relocCount = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
			for (int i = 0; i < relocCount; i++) {
				if ((relocData[i] >> 12) == IMAGE_REL_BASED_HIGHLOW) {
					uint32_t *address = (uint32_t *)((uint8_t *)base + reloc->VirtualAddress + (relocData[i] & 0x0FFF));
					*address += (uint32_t)base - (uint32_t)nth->OptionalHeader.ImageBase;
				}
#ifdef _WIN64
				if ((relocData[i] >> 12) == IMAGE_REL_BASED_DIR64) {
					uint64_t *address = (uint64_t *)((uint8_t *)base + reloc->VirtualAddress + (relocData[i] & 0x0FFF));
					*address += (uint64_t)base - (uint64_t)nth->OptionalHeader.ImageBase;
				}
#endif
			}
			reloc = cast_offset(PIMAGE_BASE_RELOCATION, reloc, reloc->SizeOfBlock);
		}
	}
	// fix import table
	dataDict = &nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (dataDict->VirtualAddress != 0 && dataDict->Size != 0) {
		PIMAGE_IMPORT_DESCRIPTOR importDesc = cast_offset(PIMAGE_IMPORT_DESCRIPTOR, base, dataDict->VirtualAddress);
		for (; importDesc->Name != 0; importDesc++) {
			char *dllname = cast_offset(char *, base, importDesc->Name);
			HMODULE dllHandle = func->LoadLibraryA(dllname);
			if (dllHandle == 0) {
				func->VirtualFree(base, nth->OptionalHeader.SizeOfImage, MEM_DECOMMIT);
				return 0;
			}
			PIMAGE_THUNK_DATA orignThunk = cast_offset(PIMAGE_THUNK_DATA, base,
				importDesc->OriginalFirstThunk != 0 ? importDesc->OriginalFirstThunk : importDesc->FirstThunk);
			PIMAGE_THUNK_DATA iatThunk = cast_offset(PIMAGE_THUNK_DATA, base, importDesc->FirstThunk);
			for (; orignThunk->u1.AddressOfData != 0; orignThunk++, iatThunk++) {
				void *function = 0;
				char *funcName = 0;
				if (IMAGE_SNAP_BY_ORDINAL(orignThunk->u1.Ordinal)) {
					funcName = (char *)IMAGE_ORDINAL(orignThunk->u1.Ordinal);
				} else {
					PIMAGE_IMPORT_BY_NAME iba = cast_offset(PIMAGE_IMPORT_BY_NAME, base, orignThunk->u1.AddressOfData);
					funcName = iba->Name;
				}
				function = func->GetProcAddress(dllHandle, funcName);
#ifdef _WIN64
				iatThunk->u1.Function = (uint64_t)function;
#else
				iatThunk->u1.Function = (uint32_t)function;
#endif
			}
		}
	}
	// invoke tls callback
	dataDict = &nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	if (dataDict->VirtualAddress != 0) {
		PIMAGE_TLS_DIRECTORY tls = cast_offset(PIMAGE_TLS_DIRECTORY, base, dataDict->VirtualAddress);
		PIMAGE_TLS_CALLBACK *callback = (PIMAGE_TLS_CALLBACK *)tls->AddressOfCallBacks;
		while (callback != 0) {
			(*callback)(base, DLL_PROCESS_ATTACH, 0);
			callback++;
		}
	}
	// call entry
	pfnDllMain dllmain = cast_offset(pfnDllMain, base, nth->OptionalHeader.AddressOfEntryPoint);
	if (dllmain != 0) {
		dllmain(base, DLL_PROCESS_ATTACH, dll_param);
	}
	// get export function address
	if (export_name == 0 || function == 0) return 1;
	*function = 0;
	dataDict = &nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (dataDict->VirtualAddress != 0 && dataDict->Size != 0) {
		PIMAGE_EXPORT_DIRECTORY exportDict = cast_offset(PIMAGE_EXPORT_DIRECTORY, base, dataDict->VirtualAddress);
		if (exportDict->NumberOfNames == 0) return 1;
		uint32_t *fn = cast_offset(uint32_t *, base, exportDict->AddressOfNames);
		uint32_t *fa = cast_offset(uint32_t *, base, exportDict->AddressOfFunctions);
		uint16_t *ord = cast_offset(uint16_t *, base, exportDict->AddressOfNameOrdinals);
		for (uint32_t i = 0; i < exportDict->NumberOfFunctions; i++) {
			char *name = cast_offset(char *, base, fn[i]);
			if (func->lstrcmpiA(name, export_name) == 0) {
				*function = cast_offset(void *, base, fa[ord[i]]);
				break;
			}
		}
	}
	return 1;
}

void *main_main() {
	func_t func;
	init_func(&func);
	
	main_config_p config = (main_config_p)(get_delta() + (uint8_t *)main_end);
	
	void *dllData = (void *)((uint8_t *)config + config->dllDataOffset);
	void *function = 0;
	int needFree = 0;
	// 解压
	if (config->depackCodeOffset != 0) {
		_unpack unpack = (_unpack)((uint8_t *)config + config->depackCodeOffset);
		void *unpackedData = func.VirtualAlloc(0, config->unpackSize, MEM_COMMIT, PAGE_READWRITE);
		if (unpackedData == 0) return 0;
		unsigned int ret = unpack(dllData, config->packedSize, unpackedData, config->unpackSize);
		if (ret == UNPACK_ERROR || ret != config->unpackSize) {
			func.VirtualFree(unpackedData, config->unpackSize, MEM_DECOMMIT);
			return 0;
		}
		dllData = unpackedData;
		needFree = 1;
	}
	if (config->invokeMode == 0) {
		memory_loadlibrary(&func, dllData, config->param, 0, &function);
	} else {
		memory_loadlibrary(&func, dllData, 0, config->param, &function);
	}
	if (needFree != 0)
		func.VirtualFree(dllData, config->unpackSize, MEM_DECOMMIT);
	return function;
};

void main_end() {
};

#pragma optimize("ts", off)

#ifdef _WIN64
# define OUT_FILE_NAME "main_x64.bin"
#else
# define OUT_FILE_NAME "main_x86.bin"
#endif

#define HASH(x) printf("#define %s_Hash 0x%X\n", x, calc_hash(x))

int _tmain(int argc, _TCHAR* argv[])
{
	//HASH("RtlZeroMemory");
	//HASH("RtlCopyMemory");
	//HASH("lstrcmpiA");
	//HASH("RtlMoveMemory");
	uint8_t *start = (uint8_t *)main_entry;
	uint8_t *end = (uint8_t *)main_end;
	size_t size = end - start;
	printf("[*] main shellcode start = %p, end = %p, size = %d\n", start, end, size);

	FILE *file = 0;
	fopen_s(&file, OUT_FILE_NAME, "wb");
	if (file == 0) {
		printf("[!] create out file error. file name = %s\n", OUT_FILE_NAME);
		return 0;
	}
	fwrite(start, 1, size, file);
	fflush(file);
	fclose(file);
	printf("[*] generate main shellcode sucess.\n");
	return 0;
}
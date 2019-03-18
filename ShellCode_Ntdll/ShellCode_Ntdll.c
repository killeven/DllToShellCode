// ShellCode_Ntdll.cpp : 定义控制台应用程序的入口点。
//
#include "shellcode_base.h"
#include <stdio.h>
#include <tchar.h>
#include <stdint.h>

#ifndef NTLIB_ERROR
# define NTLIB_ERROR ((unsigned int) (-1))
#endif  // NTLIB_ERROR

#define NT_SUCCESS(x) ((x) >= 0)

typedef struct Func {
	// kernel32
	_GetProcAddress GetProcAddress;
	_LoadLibraryA LoadLibraryA;
	// ntdll
	_RtlDecompressBuffer RtlDecompressBuffer;
} func_t, *func_p;

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus
	unsigned int __cdecl ntdll_entry(const void *source, unsigned int srclen, void *destination, unsigned int dstlen);
	unsigned int ntdll_main(const void *source, unsigned int srclen, void *destination, unsigned int dstlen);
	void ntdll_end();
	void init_func(func_p func);
#ifdef __cplusplus
}
#endif  // __cplusplus

#pragma optimize("ts", off)

unsigned int ntdll_entry(const void *source, unsigned int srclen, void *destination, unsigned int dstlen) {
	return ntdll_main(source, srclen, destination, dstlen);
};

void init_func(func_p func) {
	HMODULE kernel32 = get_kernel32_base();
	func->GetProcAddress = (_GetProcAddress)get_proc_address_from_hash(kernel32, GetProcAddress_Hash, 0);
	func->LoadLibraryA = (_LoadLibraryA)get_proc_address_from_hash(kernel32, LoadLibraryA_Hash, func->GetProcAddress);
	char s[] = { 'n', 't', 'd', 'l', 'l', 0 };
	HMODULE ntdll = func->LoadLibraryA(s);
	func->RtlDecompressBuffer = (_RtlDecompressBuffer)get_proc_address_from_hash(ntdll, RtlDecompressBuffer_Hash,
		func->GetProcAddress);
}

unsigned int ntdll_main(const void *source, unsigned int srclen, void *destination, unsigned int dstlen) {
	func_t func;
	init_func(&func);
	ULONG finalLen;
	NTSTATUS status = func.RtlDecompressBuffer(COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM,
		(PUCHAR)destination,
		dstlen,
		(PUCHAR)source,
		srclen,
		&finalLen);
	if (!NT_SUCCESS(status) || finalLen != dstlen) return NTLIB_ERROR;
	return dstlen;
};

void ntdll_end() {
};

#pragma optimize("ts", on)

#ifdef _WIN64
# define OUT_FILE_NAME "ntdll_x64.bin"
#else
# define OUT_FILE_NAME "ntdll_x86.bin"
#endif

#define HASH(x) printf("#define %s_Hash 0x%X\n", x, calc_hash(x))

int _tmain(int argc, _TCHAR* argv[])
{
	//HASH("VirtualAlloc");
	//HASH("VirtualFree");
	uint8_t *start = (uint8_t *)ntdll_entry;
	uint8_t *end = (uint8_t *)ntdll_end;
	size_t size = end - start;
	printf("[*] ntdll shellcode start = %p, end = %p, size = %d\n", start, end, size);

	FILE *file = 0;
	fopen_s(&file, OUT_FILE_NAME, "wb");
	if (file == 0) {
		printf("[!] create out file error. file name = %s\n", OUT_FILE_NAME);
		return 0;
	}
	fwrite(start, 1, size, file);
	fflush(file);
	fclose(file);
	printf("[*] generate ntdll shellcode sucess.\n");
	return 0;
}
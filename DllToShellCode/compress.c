#include "compress.h"
#include "aplib.h"
#include <stdio.h>
#include <windows.h>

#ifdef _WIN64
# pragma comment(lib, "aplib_x64.lib")
#else
# pragma comment(lib, "aplib_x86.lib")
#endif  // _WIN64

#ifndef NT_SUCCESS
# define NT_SUCCESS(s) ((NTSTATUS)(s)>=0)
#endif  // NT_SUCCESS

typedef NTSTATUS(__stdcall *_RtlCompressBuffer)(
	USHORT CompressionFormatAndEngine,
	PUCHAR UncompressedBuffer,
	ULONG UncompressedBufferSize,
	PUCHAR CompressedBuffer,
	ULONG CompressedBufferSize,
	ULONG UncompressedChunkSize,
	PULONG FinalCompressedSize,
	PVOID WorkSpace
	);

typedef NTSTATUS(__stdcall *_RtlGetCompressionWorkSpaceSize)(
	USHORT CompressionFormatAndEngine,
	PULONG CompressBufferWorkSpaceSize,
	PULONG CompressFragmentWorkSpaceSize
	);

unsigned int nt_compress(void *src, unsigned int srclen, void *dest, unsigned int destlen) {
	HMODULE ntdll = GetModuleHandle("ntdll");
	_RtlGetCompressionWorkSpaceSize xRtlGetCompressionWorkSpaceSize = (_RtlGetCompressionWorkSpaceSize)GetProcAddress(ntdll, "RtlGetCompressionWorkSpaceSize");
	_RtlCompressBuffer xRtlCompressBuffer = (_RtlCompressBuffer)GetProcAddress(ntdll, "RtlCompressBuffer");
	if (xRtlCompressBuffer == 0 || xRtlCompressBuffer == 0) {
		printf("get compress function error.\n");
		return COMPRESS_ERROR;
	}
	ULONG compressWorkSpaceSize = 0, compressFragmentSpaceSize;
	NTSTATUS ret = xRtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM,
		&compressWorkSpaceSize,
		&compressFragmentSpaceSize);
	if (!NT_SUCCESS(ret)) {
		printf("get compression work space size error.\n");
		return COMPRESS_ERROR;
	}
	void *compressWorkSpace = malloc(compressWorkSpaceSize);
	if (compressWorkSpace == 0) {
		printf("malloc work space error.\n");
		return COMPRESS_ERROR;
	}
	ULONG compressedSize;
	ret = xRtlCompressBuffer(COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM,
		(PUCHAR)src,
		srclen,
		(PUCHAR)dest,
		destlen,
		0,
		&compressedSize,
		compressWorkSpace);
	free(compressWorkSpace);
	if (!NT_SUCCESS(ret)) {
		printf("compress buffer error.\n");
		return COMPRESS_ERROR;
	}
	return (unsigned int)compressedSize;
};

unsigned int aplib_compress(void *src, unsigned int srclen, void *dest, unsigned int destlen) {
	void *workMemory = malloc(aP_workmem_size(srclen));
	if (workMemory == 0) {
		printf("get compression work space size error.\n");
		return COMPRESS_ERROR;
	}
	unsigned int ret = aP_pack(src, dest, srclen, workMemory, 0, 0);
	free(workMemory);
	return ret;
};
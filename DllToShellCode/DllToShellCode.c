// DllToShellCode.cpp : 定义控制台应用程序的入口点。
//

#include <stdio.h>
#include <stdint.h>
#include <windows.h>
#include "compress.h"
#include "shellcode_data.h"

#pragma pack(push)
#pragma pack(1)
typedef struct main_config {
	uint8_t invokeMode;			    // 0 = 调用dllmain lpReserved[param], 1 = 返回导出函数地址
	uint32_t depackCodeOffset;	// 解压缩代码偏移 偏移量基于main_config开始
	uint32_t unpackSize;		    // 未压缩时的大小
	uint32_t packedSize;		    // 压缩后的大小
	uint32_t dllDataOffset;		  // dll数据偏移 偏移量基于main_config开始
	char param[100];			      // dllmain参数或导出函数名称
} main_config_t, *main_config_p;
#pragma pack(pop)

static void show_syntax() {
	printf("DllToShellCode v0.1 [killeven]\n"
		"  Syntax\n\n"
		"	BinToHex:         DllToShellCode b <in_file> <out_file>\n"
    "	Compress File:    DllToShellCode c <mode> <in_file> <out_file>\n"
    "	Dll To ShellCode: DllToShellCode d <shellcode_mode> <param> <compress_mode> <in_file> <out_file>\n\n"
		"	Compress File mode\n"
		"	\t0 = compress with ntdll\n"
		"	\t1 = compress with aplib\n"
		"	DllToShellCode shellcode_mode\n"
		"	\t0 = only call dllmain, <param> is the dllmain param lpReserved\n"
		"	\t1 = return export address, <param> is the export name\n"
		"	DllToShellCode compress_mode\n"
		"	\t0 = no compress\n"
		"	\t1 = compress with ntdll\n"
		"	\t2 = compress with aplib\n");
}

#define EXIT_SHOW_SYNTAX { show_syntax(); return -1; }

static int bin_to_hex(char *infile, char *outfile) {
	FILE *in, *out;
	fopen_s(&in, infile, "rb");
	if (in == 0) {
		printf("[-] open input file error. file name = %s.\n", infile);
		return -1;
	}
	fopen_s(&out, outfile, "w");
	if (out == 0) {
		_fcloseall();
		printf("[-] create output file error. file name = %s.\n", infile);
		return -1;
	}
	fseek(in, 0, SEEK_END);
	size_t fileSize = ftell(in);
	fseek(in, 0, SEEK_SET);
  if (fileSize == -1) {
    printf("[-] get file size error. file name = %s.\n", infile);
    return -1;
  }
	size_t loop = fileSize / 30;
  size_t rest = fileSize % 30;
	char buf[30];
	fprintf_s(out, "char ShellCode[%ld] = {\n", fileSize);
  for (size_t i = 0; i < loop; i++) {
		fread(buf, 1, 30, in);
		fputs("\t\"", out);
		for (int j = 0; j < 30; j++) {
			fprintf_s(out, "\\x%02x", buf[j] & 0xFF);
		}
		fputs("\"\n", out);
	}
	if (rest > 0) {
		fputs("\t\"", out);
		fread(buf, 1, rest, in);
    for (size_t j = 0; j < rest; j++) {
			fprintf_s(out, "\\x%02x", buf[j] & 0xFF);
		}
		fputs("\"\n", out);
	}
	fputs("};", out);
	fflush(out);
	_fcloseall();
	return 0;
}

/* mode 1 = nt compress, 2 = aplib compress */
static int compress_file(char mode, char *in_file, char *out_file) {
	if (mode != '1' && mode != '2') {
		printf("[-] unknow mode.\n");
		EXIT_SHOW_SYNTAX;
	}
	FILE *in = 0, *out = 0;
	fopen_s(&in, in_file, "rb");
	if (in == 0) {
		printf("[-] open input file error.\n");
		return -1;
	}
	fopen_s(&out, out_file, "wb");
	if (out == 0) {
		_fcloseall();
		printf("[-] open output file error.\n");
		return -1;
	}
	fseek(in, 0, SEEK_END);
	int fileSize = (int)ftell(in);
	fseek(in, 0, SEEK_SET);
  if (fileSize == -1) {
    printf("[-] get file size error.\n");
    return -1;
  }
	void *fileBuf = malloc(fileSize);
	void *compressedBuf = malloc(fileSize);
	if (fileBuf == 0 || compressedBuf == 0) {
		_fcloseall();
		printf("[-] malloc memory error.\n");
		return -1;
	}
	fread(fileBuf, 1, fileSize, in);
	unsigned int ret = COMPRESS_ERROR;
	if (mode == '1') {
		printf("[*] using nt compress flag.\n");
		ret = nt_compress(fileBuf, fileSize, compressedBuf, fileSize);
	}
	else if (mode == '2') {
		printf("[*] using aplib compress flag.\n");
		ret = aplib_compress(fileBuf, fileSize, compressedBuf, fileSize);
	}
	if (ret != COMPRESS_ERROR) {
		printf("[*] compress success orign size = %d, compressed size = %d.\n", fileSize, ret);
		fwrite(compressedBuf, 1, ret, out);
	} else {
		printf("[-] compress error.\n");
	}
	fflush(out);
	_fcloseall();
	free(fileBuf);
	free(compressedBuf);
	return 0;
}

static PIMAGE_NT_HEADERS get_nt_header(void *buf) {
	PIMAGE_DOS_HEADER dh = (PIMAGE_DOS_HEADER)buf;
	if (IsBadReadPtr(buf, sizeof(IMAGE_DOS_HEADER))) return 0;
	if (dh->e_magic != IMAGE_DOS_SIGNATURE) return 0;
	PIMAGE_NT_HEADERS nh = (PIMAGE_NT_HEADERS)((uint8_t *)buf + dh->e_lfanew);
	if (IsBadReadPtr(nh, sizeof(IMAGE_NT_HEADERS))) return 0;
	if (nh->Signature != IMAGE_NT_SIGNATURE) return 0;
	if ((nh->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0) return 0;
	return nh;
}

static int is_dll(PIMAGE_NT_HEADERS nh) {
	return (nh->FileHeader.Characteristics & IMAGE_FILE_DLL) > 0 ? 1 : 0;
}

static int is_x64(PIMAGE_NT_HEADERS nh) {
	if (nh->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
		nh->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) 
		return 0;
	return 1;
}

/*
	shellcode_mode
		0 = only call dllmain, <param> is the dllmain param lpReserved
		1 = return export address, <param> is the export name
	compress_mode
		0 = no compress
		1 = compress with ntdll
		2 = compress with aplib
*/
static int dll_to_shellcode(char shellcode_mode, char *param, char compress_mode, char *in_file, char *out_file) {
	if (shellcode_mode != '0' && shellcode_mode != '1') {
		printf("[-] unknow shellcode mode.\n");
		EXIT_SHOW_SYNTAX;
	}
	if (compress_mode != '0' && compress_mode != '1' && compress_mode != '2') {
		printf("[-] unknow compress mode.\n");
		EXIT_SHOW_SYNTAX;
	}
	FILE *in = 0, *out = 0;
	if (fopen_s(&in, in_file, "rb") != 0) {
		printf("[-] can't open input file!\n");
		return -1;
	}
	if (fopen_s(&out, out_file, "wb") != 0) {
		_fcloseall();
		printf("[-] can't create output file!\n");
		return -1;
	}
	fseek(in, 0, SEEK_END);
	int inFileSize = (int)ftell(in);
	fseek(in, 0, SEEK_SET);
  if (inFileSize == -1) {
    printf("[-] get file size error.\n");
    return -1;
  }
	void *fileBuf = malloc(inFileSize);
	if (fileBuf == 0) {
		_fcloseall();
		printf("[-] malloc file buf error.\n");
		return -1;
	}
	fread(fileBuf, 1, inFileSize, in);
	PIMAGE_NT_HEADERS nh = get_nt_header(fileBuf);
	if (nh == 0) {
		_fcloseall();
		free(fileBuf);
		printf("[-] invalid pe file, can't find pe header.\n");
		return -1;
	}
	if (is_dll(nh) == 0) {
		_fcloseall();
		free(fileBuf);
		printf("[-] pe file is not a dll.\n");
		return -1;
	}
	size_t paramLen = strlen(param);
	if (paramLen > 100) {
		printf("[-] param only can receive 99 length char.\n");
		return -1;
	}
	main_config_t config;
	memset(&config, 0, sizeof(config));
	strcpy_s(config.param, sizeof(config.param), param);
	config.invokeMode = shellcode_mode == '0' ? 0 : 1;
	config.unpackSize = inFileSize;
	int x64 = is_x64(nh);
	printf("[*] pe file paltform: %s\n", x64 == 1 ? "x64" : "x86");
	int mainCodeSize = 0;
	void *mainCode = get_shellcode_main(x64, &mainCodeSize);
	if (compress_mode == '0') {
		printf("[*] writing main shellcode to file, size = %d.\n", mainCodeSize);
		fwrite(mainCode, 1, mainCodeSize, out);
		fflush(out);
		config.depackCodeOffset = 0;
		config.packedSize = inFileSize;
		config.dllDataOffset = sizeof(config);
		printf("[*] writing config data to file, size = %d.\n", sizeof(config));
		fwrite(&config, 1, sizeof(config), out);
		printf("[*] writing dll data to file, size = %d.\n", inFileSize);
		fwrite(fileBuf, 1, inFileSize, out);
		printf("[+] gen shellcode success, total size = %d.\n", mainCodeSize + sizeof(config) + inFileSize);
		fflush(out);
		_fcloseall();
		free(fileBuf);
		return 0;
	}
	void *compressed = malloc(inFileSize);
	unsigned int compressedSize = 0;
	if (compressed == 0) {
		_fcloseall();
		free(fileBuf);
		printf("[-] malloc compressed data error.\n");
		return -1;
	}
	int decompressCodeSize = 0;
	void *decompressCode = 0;
	if (compress_mode == '1') {
		decompressCode = get_shellcode_ntdll(x64, &decompressCodeSize);
		compressedSize = nt_compress(fileBuf, inFileSize, compressed, inFileSize);
	} else if (compress_mode == '2') {
		decompressCode = get_shellcode_aplib(x64, &decompressCodeSize);
		compressedSize = aplib_compress(fileBuf, inFileSize, compressed, inFileSize);
	} else {
		exit(-1);
	}
	if (compressedSize == COMPRESS_ERROR) {
		printf("[-] compress file data error.\n");
		_fcloseall();
		free(fileBuf);
		free(compressed);
		return -1;
	}
	printf("[*] writing main shellcode to file, size = %d.\n", mainCodeSize);
	fwrite(mainCode, 1, mainCodeSize, out);
	config.depackCodeOffset = sizeof(config);
	config.packedSize = compressedSize;
	config.dllDataOffset = sizeof(config) + decompressCodeSize;
	printf("[*] writing config data to file, size = %d.\n", sizeof(config));
	fwrite(&config, 1, sizeof(config), out);
	printf("[*] writing decompress code to file, size = %d.\n", decompressCodeSize);
	fwrite(decompressCode, 1, decompressCodeSize, out);
	printf("[*] write compressed data to file, size = %d.\n", compressedSize);
	fwrite(compressed, 1, compressedSize, out);
	printf("[+] gen shellcode success, total size = %d.\n", mainCodeSize + sizeof(config) + decompressCodeSize + compressedSize);
	fflush(out);
	_fcloseall();
	free(fileBuf);
	free(compressed);
	return 0;
}

#define CHECK_PARAM(a) { if (a[0] == 0 || a[1] != 0) EXIT_SHOW_SYNTAX; }

int main(int argc, char* argv[])
{
	if (argc == 4) {
		CHECK_PARAM(argv[1]);
		if (toupper(argv[1][0]) != 'B') EXIT_SHOW_SYNTAX;
		printf("[BinToHex Mode]\n\tinput = %s, output = %s .\n", argv[2], argv[3]);
		return bin_to_hex(argv[2], argv[3]);
	}
	else if (argc == 5) {
		CHECK_PARAM(argv[1]);
		if (toupper(argv[1][0]) != 'C') EXIT_SHOW_SYNTAX;
		printf("[Compress Mode]\n\t"
			"mode = %c, input = %s, output = %s.\n", argv[2][0], argv[3], argv[4]);
		return compress_file(argv[2][0], argv[3], argv[4]);
	}
	if (argc == 7) {
		CHECK_PARAM(argv[1]);
		CHECK_PARAM(argv[2]);
		CHECK_PARAM(argv[4]);
		if (toupper(argv[1][0]) != 'D') EXIT_SHOW_SYNTAX;
		printf("[DlltoShellCode Mode]\n\t"
			"shellcode_mode = %c, param = %s, compress_mode = %c, input = %s, output = %s.\n",
			argv[2][0], argv[3], argv[4][0], argv[5], argv[6]);
		return dll_to_shellcode(argv[2][0], argv[3], argv[4][0], argv[5], argv[6]);
	}
	EXIT_SHOW_SYNTAX;
	return 0;
}
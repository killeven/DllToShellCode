#ifndef SHELLCODE_BASE_H
#define SHELLCODE_BASE_H
#include "shellcode_global.h"

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus
	uint32_t get_delta();
	HMODULE get_kernel32_base();
	uint32_t calc_hash(char *str);
	void *get_proc_address_from_hash(HMODULE module, uint32_t func_hash, _GetProcAddress get_proc_address);
#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // SHELLCODE_BASE_H
#ifndef SHELLCODE_DATA_H
#define SHELLCODE_DATA_H

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus
	// can't modify return pointer
	void *get_shellcode_main(int is_x64, int *osize);
	void *get_shellcode_aplib(int is_x64, int *osize);
	void *get_shellcode_ntdll(int is_x64, int *osize);
#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // SHELLCODE_DATA_H
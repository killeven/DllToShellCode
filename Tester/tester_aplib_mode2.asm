format PE

entry start

section '.text' code readable executable

tester:
	file	'main_x86.bin'

param_data:
	invokeMode			db 1
	depackCodeOffset	dd aplib_unpack_code - param_data
	unpackSize			dd 179712
	packedSize			dd dll_data_end - dll_data_start
	dllDataOffset		dd dll_data_start - param_data
	param				db 'Test'
	reserved			rb 100 - 4
	
start:
	call	tester
	call	eax
	ret
	
aplib_unpack_code:
	file	'aplib_x86.bin'
	
dll_data_start:
	file	'TestDll_aplib.dll'

dll_data_end:
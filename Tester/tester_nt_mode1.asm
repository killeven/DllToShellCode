format PE

entry start

section '.text' code readable executable

tester:
	file	'main_x86.bin'

param_data:
	invokeMode			db 0
	depackCodeOffset	dd nt_unpack_code - param_data
	unpackSize			dd 179712
	packedSize			dd dll_data_end - dll_data_start
	dllDataOffset		dd dll_data_start - param_data
	param				db 'Tester'
	reserved			rb 100 - 6
	
start:
	call	tester
	ret
	
nt_unpack_code:
	file	'ntdll_x86.bin'
	
dll_data_start:
	file	'TestDll_nt.dll'

dll_data_end:
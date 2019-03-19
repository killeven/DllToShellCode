format PE

entry start

section '.text' code readable executable

tester:
	file	'main_x86.bin'

param_data:
	invokeMode			db 0
	depackCodeOffset	dd 0
	unpackSize			dd dll_data_end - dll_data_start
	packedSize			dd dll_data_end - dll_data_start
	dllDataOffset		dd dll_data_start - param_data
	param				db 'Tester'
	reserved			rb 100 - 6
	
start:
	call	tester
	ret
dll_data_start:
	file	'TestDll.dll'

dll_data_end:
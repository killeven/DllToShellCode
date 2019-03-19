del aplib_x86.bin
del ntdll_x86.bin
del main_x86.bin
del aplib_x86.h
del ntdll_x86.h
del main_x86.h
del TestDll_aplib.dll
del TestDll_nt.dll
ShellCode_Aplib.exe
ShellCode_Ntdll.exe
ShellCode_Main.exe
DllToShellCode.exe c 1 TestDll.dll TestDll_nt.dll
DllToShellCode.exe c 2 TestDll.dll TestDll_aplib.dll
DllToShellCode.exe b aplib_x86.bin aplib_x86.h
DllToShellCode.exe b ntdll_x86.bin ntdll_x86.h
DllToShellCode.exe b main_x86.bin main_x86.h
fasm tester_main_mode1.asm
fasm tester_main_mode2.asm
fasm tester_aplib_mode1.asm
fasm tester_aplib_mode2.asm
fasm tester_nt_mode1.asm
fasm tester_nt_mode2.asm
@pause
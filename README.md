# DllToShellCode
Fast Conversion Windows Dynamic Link Library To ShellCode
##  Features
* Support 32-bits and 64-bits
* Support Compression(using ntdll RtlCompressBuffer function or aplib)
* Support two modes
  * Direct invoke dllmain(lpReserved as parameter),if you don't want using the dll internal functions
  * Invoke the shellcode will return the address of export function, so you can use it in anywhere
## OverView
>Few Assembly used, alomost all code are developed in C language(only use assembly language in 32-bits self-delta)

##  Usage
        BinToHex:         DllToShellCode b <in_file> <out_file>
        Compress File:    DllToShellCode c mode <in_file> <out_file>
        Dll To ShellCode: DllToShellCode d shellcode_mode <param> compress_mode
        Compress File mode
                0 = compress with ntdll
                1 = compress with aplib
        DllToShellCode shellcode_mode
                0 = only call dllmain, <param> is the dllmain param lpReserved
                1 = return export address, <param> is the export name
        DllToShellCode compress_mode
                0 = no compress
                1 = compress with ntdll
                2 = compress with aplib

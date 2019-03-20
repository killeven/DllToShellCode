// ShellCode_Aplib.cpp : 定义控制台应用程序的入口点。
//

#include <stdio.h>
#include <tchar.h>
#include <stdint.h>

#ifndef APLIB_ERROR
# define APLIB_ERROR ((unsigned int) (-1))
#endif  // APLIB_ERROR


/* aplib v 1.1.1*/

/* internal data structure */
struct APDSTATE {
	const unsigned char *source;
	unsigned char *destination;
	unsigned int tag;
	unsigned int bitcount;
};


#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus
	unsigned int __cdecl aplib_entry(const void *source, unsigned int srclen, void *destination, unsigned int dstlen);
	unsigned int aplib_main(const void *source, unsigned int srclen, void *destination, unsigned int dstlen);
	void aplib_end();
#ifdef __cplusplus
}
#endif  // __cplusplus

#pragma optimize("ts", on)

unsigned int __cdecl aplib_entry(const void *source, unsigned int srclen, void *destination, unsigned int dstlen) {
	return aplib_main(source, srclen, destination, dstlen);
}

static unsigned int aP_getbit(struct APDSTATE *ud)
{
	unsigned int bit;

	/* check if tag is empty */
	if (!ud->bitcount--) {
		/* load next tag */
		ud->tag = *ud->source++;
		ud->bitcount = 7;
	}

	/* shift bit out of tag */
	bit = (ud->tag >> 7) & 0x01;
	ud->tag <<= 1;

	return bit;
}

static unsigned int aP_getgamma(struct APDSTATE *ud)
{
	unsigned int result = 1;

	/* input gamma2-encoded bits */
	do {
		result = (result << 1) + aP_getbit(ud);
	} while (aP_getbit(ud));

	return result;
}

unsigned int aplib_main(const void *source, unsigned int srclen, void *destination, unsigned int dstlen) {
	struct APDSTATE ud;
	unsigned int offs, len, R0, LWM;
	int done;
	int i;

	ud.source = (const unsigned char *)source;
	ud.destination = (unsigned char *)destination;
	ud.bitcount = 0;

	R0 = (unsigned int)-1;
	LWM = 0;
	done = 0;

	/* first byte verbatim */
	*ud.destination++ = *ud.source++;

	/* main decompression loop */
	while (!done) {
		if (aP_getbit(&ud)) {
			if (aP_getbit(&ud)) {
				if (aP_getbit(&ud)) {
					offs = 0;

					for (i = 4; i; i--) {
						offs = (offs << 1) + aP_getbit(&ud);
					}

					if (offs) {
						*ud.destination = *(ud.destination - offs);
						ud.destination++;
					}
					else {
						*ud.destination++ = 0x00;
					}

					LWM = 0;
				}
				else {
					offs = *ud.source++;

					len = 2 + (offs & 0x0001);

					offs >>= 1;

					if (offs) {
						for (; len; len--) {
							*ud.destination = *(ud.destination - offs);
							ud.destination++;
						}
					}
					else {
						done = 1;
					}

					R0 = offs;
					LWM = 1;
				}
			}
			else {
				offs = aP_getgamma(&ud);

				if ((LWM == 0) && (offs == 2)) {
					offs = R0;

					len = aP_getgamma(&ud);

					for (; len; len--) {
						*ud.destination = *(ud.destination - offs);
						ud.destination++;
					}
				}
				else {
					if (LWM == 0) {
						offs -= 3;
					}
					else {
						offs -= 2;
					}

					offs <<= 8;
					offs += *ud.source++;

					len = aP_getgamma(&ud);

					if (offs >= 32000) {
						len++;
					}
					if (offs >= 1280) {
						len++;
					}
					if (offs < 128) {
						len += 2;
					}

					for (; len; len--) {
						*ud.destination = *(ud.destination - offs);
						ud.destination++;
					}

					R0 = offs;
				}

				LWM = 1;
			}
		}
		else {
			*ud.destination++ = *ud.source++;
			LWM = 0;
		}
	}

	return (unsigned int)(ud.destination - (unsigned char *)destination);
}

void aplib_end() {
}

#pragma optimize("ts", off)

#ifdef _WIN64
# define OUT_FILE_NAME "aplib_x64.bin"
#else
# define OUT_FILE_NAME "aplib_x86.bin"
#endif

int _tmain(int argc, _TCHAR* argv[]) {
	uint8_t *start = (uint8_t *)aplib_entry;
	uint8_t *end = (uint8_t *)aplib_end;
	size_t size = end - start;
	printf("[*] aplib shellcode start = %p, end = %p, size = %d\n", start, end, size);

	FILE *file = 0;
	fopen_s(&file, OUT_FILE_NAME, "wb");
	if (file == 0) {
		printf("[!] create out file error. file name = %s\n", OUT_FILE_NAME);
		return 0;
	}
	fwrite(start, 1, size, file);
	fflush(file);
	fclose(file);
	printf("[*] generate aplib shellcode sucess.\n");
	return 0;
}
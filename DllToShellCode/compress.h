#ifndef COMPRESS_H
#define COMPRESS_H

#ifndef COMPRESS_ERROR
# define COMPRESS_ERROR ((unsigned int)-1)
#endif  // COMPRESS_ERROR

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus
	unsigned int nt_compress(void *src, unsigned int srclen, void *dest, unsigned int destlen);
	unsigned int aplib_compress(void *src, unsigned int srclen, void *dest, unsigned int destlen);
#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // COMPRESS_H
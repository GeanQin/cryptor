#include "sm4.h"

static uint8_t iv[16] = {
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00
};

static uint8_t *key;

#ifdef __cplusplus
extern "C" {
#endif

int encrypt_file(uint8_t *key, char *path);
int decrypt_file(uint8_t *key, char *path);

#ifdef __cplusplus
}
#endif

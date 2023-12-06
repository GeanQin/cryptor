#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SM4_EN
#define BASE64_EN
#define RSA_EN

#ifdef SM4_EN
#include "sm4.h"
static uint8_t sm4_iv[16] = {
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00};
#endif

#ifdef BASE64_EN
#include "base64.h"
#endif

#ifdef RSA_EN
#include "rsa.h"
#define RSA_PRIVATE_KEY "rsa_key/private_key.pem"
#define RSA_PUBLIC_KEY "rsa_key/public_key.pem"
#endif

int main(int argc, char **argv)
{
#ifdef SM4_EN
    sm4_data_t sm4_data;
    char *sm4_key = "1234567887654321";
    uint8_t *sm4_buff = NULL;
    uint32_t sm4_buff_len = 0;
    uint8_t *sm4_decrypt_buff = NULL;
    uint32_t sm4_decrypt_len = 0;

#endif

#ifdef BASE64_EN
    char *base64_buff = NULL;
    int base64_buff_len = 0;
    char *base64_decrypt_buff = NULL;
    int base64_decrypt_len = 0;
#endif

#ifdef RSA_EN
    char *rsa_buff = NULL;
    int rsa_buff_len = 0;
    char *rsa_decrypt_buff = NULL;
    int rsa_decrypt_len = 0;
#endif

    if (argc < 2)
    {
        fprintf(stderr, "usage: %s [str]\n", argv[0]);
        return -1;
    }

#ifdef SM4_EN
    printf("will sm4 encrypt %s\n", argv[1]);

    if (sm4_data_init(&sm4_data, SM4_MODE_CBC))
    {
        printf("cannot init sm4 data\n");
        return -2;
    }
    sm4_data.key = sm4_key;
    sm4_data.iv = sm4_iv;

    sm4_buff = (uint8_t *)malloc(strlen(argv[1]) + 32);
    sm4_encrypt_data(&sm4_data, argv[1], strlen(argv[1]) + 1, sm4_buff, &sm4_buff_len);
    if (sm4_buff_len < 0)
    {
        printf("sm4 cannot encrypt data\n");
        return -3;
    }

    printf("sm4 encrypt ok, start decrypt\n");

    sm4_decrypt_buff = (uint8_t *)malloc(strlen(argv[1]) + 32);
    sm4_decrypt_data(&sm4_data, sm4_buff, sm4_buff_len, sm4_decrypt_buff, &sm4_decrypt_len);
    if(sm4_decrypt_len < 0)
	{
		printf("sm4 cannot decrypt data\n");
		return -4;
	}

    printf("sm4 decrypt ok str=[%s]\n", sm4_decrypt_buff);

    free(sm4_buff);
    free(sm4_decrypt_buff);
    sm4_data_exit(&sm4_data);
#endif

#ifdef BASE64_EN
    printf("will base64 encrypt %s\n", argv[1]);

    base64_buff = (char *)malloc(strlen(argv[1]) + 32);
    base64_buff_len = base64_encode(argv[1], strlen(argv[1]) + 1, base64_buff);
    if (base64_buff_len < 0)
    {
        printf("base64 cannot encrypt data\n");
        return -5;
    }
    printf("base64 encrypt ok, base64_str=%sstart decrypt\n", base64_buff);

    base64_decrypt_buff = (char *)malloc(strlen(argv[1]) + 32);
    base64_decrypt_len = base64_decode(base64_buff, base64_buff_len, base64_decrypt_buff);
    if (base64_decrypt_len <= 0)
    {
        printf("base64 cannot decrypt data\n");
        return -6;
    }
    printf("base64 decrypt ok str=[%s]\n", base64_decrypt_buff);

    free(base64_buff);
    free(base64_decrypt_buff);
#endif

#ifdef RSA_EN
    printf("will rsa encrypt %s\n", argv[1]);

    rsa_buff = (char *)malloc(strlen(argv[1]) + 128);
    rsa_encrypt(argv[1], strlen(argv[1]) + 1, rsa_buff, &rsa_buff_len, RSA_PRIVATE_KEY);
    if (rsa_buff_len < 0)
    {
        printf("rsa cannot encrypt data\n");
        return -5;
    }
    printf("rsa encrypt ok, len=%d, start decrypt\n", rsa_buff_len);

    rsa_decrypt_buff = (char *)malloc(strlen(argv[1]) + 1024);
    rsa_decrypt(rsa_buff, rsa_buff_len, rsa_decrypt_buff, &rsa_decrypt_len, RSA_PUBLIC_KEY);
    if (rsa_decrypt_len <= 0)
    {
        printf("rsa cannot decrypt data\n");
        return -6;
    }
    printf("rsa decrypt ok str=[%s]\n", rsa_decrypt_buff);

    free(rsa_buff);
    free(rsa_decrypt_buff);
#endif

    return 0;
}
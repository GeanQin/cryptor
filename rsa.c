#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "rsa.h"

int rsa_encrypt(const char *input, int input_len, char *output, int *output_len, const char *pri_key_fn)
{
    RSA *p_rsa = NULL;
    FILE *file = NULL;
    int ret = 0;

    if ((file = fopen(pri_key_fn, "rb")) == NULL)
    {
        ret = -1;
        goto End;
    }

    if ((p_rsa = PEM_read_RSAPrivateKey(file, NULL, NULL, NULL)) == NULL)
    {
        ret = -2;
        goto End;
    }

    if ((*output_len = RSA_private_encrypt(input_len, (unsigned char *)input, (unsigned char *)output, p_rsa, RSA_PKCS1_PADDING)) < 0)
    {
        ret = -4;
        goto End;
    }

End:
    if (p_rsa != NULL)
        RSA_free(p_rsa);
    if (file != NULL)
        fclose(file);

    return ret;
}

// 解密
int rsa_decrypt(const char *input, int input_len, char *output, int *output_len, const char *pri_key_fn)
{
    RSA *p_rsa = NULL;
    FILE *file = NULL;
    int ret = 0;

    file = fopen(pri_key_fn, "rb");
    if (!file)
    {
        ret = -1;
        goto End;
    }

    if ((p_rsa = PEM_read_RSA_PUBKEY(file, NULL, NULL, NULL)) == NULL)
    {
        ret = -2;
        goto End;
    }

    if ((*output_len = RSA_public_decrypt(input_len, (unsigned char *)input, (unsigned char *)output, p_rsa, RSA_PKCS1_PADDING)) < 0)
    {
        ret = -3;
        goto End;
    }
End:
    if (p_rsa != NULL)
        RSA_free(p_rsa);
    if (file != NULL)
        fclose(file);

    return ret;
}
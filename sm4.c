#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <stdio.h>
#include <stdlib.h>

#include "sm4.h"

static void sm4_show_openssl_error(int8_t* title)
{
	int8_t buf[1024];

	ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
	printf("%s: %s\n", title, buf);
}


static const EVP_CIPHER *sm4_get_mode(int8_t *mode)
{
	switch (*mode) {
	case '0':
		return EVP_sm4_ecb();
	case '1':
		return EVP_sm4_cbc();
	case '2':
		return EVP_sm4_cfb128();
	default:
		return NULL;
	}
}

static int32_t sm4_get_rand(uint8_t *out, uint32_t len)
{   
    BIGNUM *rnd;
    uint8_t buf[32];
    uint32_t idx;
    
    rnd = BN_new();
    if (NULL == rnd) {
        return -1;
    }
    
    if (!BN_rand(rnd, 256, 1, 1)) {
        return -1;
    }
    
    if (BN_bn2binpad(rnd, buf, 32) != 32) {
        return -1;
    }
    BN_free(rnd);
    //show_hex("rand", buf, 32);
    
    for (idx = 0; idx < len; idx++) {
        idx = idx >= 32 ? 0 : idx;
        *out++ = buf[idx];
    }
    
    return 0;
}

int32_t sm4_gen_key(sm4_data_t *data, uint8_t *key, uint32_t length)
{
    if (sm4_get_rand(key, length)) {
        return -1;
    }
	data->key = key;

	return 0;
}

int32_t sm4_gen_iv(sm4_data_t *data, uint8_t *iv, uint32_t length)
{
    if (sm4_get_rand(iv, length)) {
        return -1;
    }
	data->iv = iv;

	return 0;
}

int32_t sm4_encrypt_data(sm4_data_t *data, void *in, uint32_t ilen, void *out, uint32_t *olen)
{
	EVP_CIPHER_CTX *ctx = data->ctx;
	const EVP_CIPHER *mode = sm4_get_mode(data->mode);
	int32_t len = 0, pad = 0;

	EVP_EncryptInit_ex(ctx, mode, NULL, data->key, data->iv);

	if (ilen % SM4_BLOCK_SIZE != 0) {
		pad = 1;
	}
	EVP_CIPHER_CTX_set_padding(ctx, pad);

	if (!EVP_EncryptUpdate(ctx, out, &len, in, ilen)) {
		return -1;
	}
	*olen = len;
	len = 0;

	if (!EVP_EncryptFinal_ex(ctx, out + *olen, &len)) {
		return -1;
	}

	*olen += len;

	return 0;
}

int32_t sm4_decrypt_data(sm4_data_t *data, void *in, uint32_t ilen, void *out, uint32_t *olen)
{
	EVP_CIPHER_CTX *ctx = data->ctx;
	const EVP_CIPHER *mode = sm4_get_mode(data->mode);
	int32_t len = 0;

	EVP_DecryptInit_ex(ctx, mode, NULL, data->key, data->iv);
	EVP_CIPHER_CTX_set_padding(ctx, 0);

	if (!EVP_DecryptUpdate(ctx, out, &len, in, ilen)) {
		return -1;
	}
	*olen = len;
	len = 0;

	if (EVP_DecryptFinal_ex(ctx, out + *olen, &len)) {
		return -1;
	}
	*olen += len;

	return 0;
}

int32_t sm4_data_init(sm4_data_t *data, void *mode)
{
	EVP_CIPHER_CTX *ctx;

	ctx = EVP_CIPHER_CTX_new();
	if (NULL == ctx) {
		return -1;
	}	

	data->mode = mode;
	data->ctx = ctx;

	return 0;
}

int32_t sm4_data_exit(sm4_data_t *data)
{
	EVP_CIPHER_CTX_free(data->ctx);

	return 0;
}

#ifndef __RSA_H__
#define __RSA_H__

int rsa_encrypt(const char *input, int input_len, char *output, int *output_len, const char *pri_key_fn);
int rsa_decrypt(const char *input, int input_len, char *output, int *output_len, const char *pri_key_fn);

#endif


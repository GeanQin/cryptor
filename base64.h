#ifndef __BASE64_H__
#define __BASE64_H__

int base64_encode(char *in_str, int in_len, char *out_str);
int base64_decode(char *in_str, int in_len, char *out_str);

#endif


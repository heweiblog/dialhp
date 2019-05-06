#ifndef __AES_H__
#define __AES_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>

int dialhp_aes_encode(const unsigned char *key, unsigned char *src, int srcLen, unsigned char *dest, int destLen);
int dialhp_aes_decode(const unsigned char *key, unsigned char *src, int srcLen, unsigned char *dest, int destLen);
void dialhp_print_binary(char *help, unsigned char *s, int len);

#endif

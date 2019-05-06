#include "aes.h"

void dialhp_print_binary(char *help, unsigned char *s, int len)
{
    int i = 0;
    printf(help);
    for(i = 0; i < len; i ++) {

        if(i%16 == 0) printf("\n");
        printf("%02x", s[i]);
    }

    printf("\n");
}

int dialhp_aes_encode(const unsigned char *key, unsigned char *src, int srcLen, unsigned char *dest, int destLen)
{
    AES_KEY aes;
    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv,0x00,sizeof(iv));

    if(AES_set_encrypt_key((unsigned char *)key, 128, &aes) < 0){

        return -1;
    }

    int total = (srcLen/AES_BLOCK_SIZE + 1)*AES_BLOCK_SIZE;
    unsigned char buf_in[total], buf_out[total];
    memcpy(buf_in,src,srcLen);
    memset(buf_in + srcLen, total - srcLen, total - srcLen); //do PKCS#5 padding
    AES_cbc_encrypt(buf_in, buf_out, total, &aes, iv, AES_ENCRYPT);
    memcpy(dest, buf_out, total);

    return total;
}

int dialhp_aes_decode(const unsigned char *key, unsigned char *src, int srcLen, unsigned char *dest, int destLen)
{
    AES_KEY aes;
    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv,0x00,sizeof(iv));

    if(AES_set_decrypt_key((unsigned char *)key, 128, &aes) < 0){

        return -1;
    }

    int total = srcLen;
    if(total % 16 != 0) {
        return -1;
    }

    unsigned char buf_in[total], buf_out[total];
    memcpy(buf_in,src,srcLen);
    AES_cbc_encrypt(buf_in, buf_out, total, &aes, iv, AES_DECRYPT);

    int ret = total;
    int padding = buf_out[total-1];
    if(padding > AES_BLOCK_SIZE){

        return -1;
    }
    ret = total - padding;
    memcpy(dest, buf_out, total - padding);
    
    return ret;
}

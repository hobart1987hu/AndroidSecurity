//
// Created by huzeyin on 2017/9/1.
//

#include "crypt.h"

void aesEncrypt(char *aes_key, char *in, char *out) {

    AES_KEY aes;

    int bits = 0;

    const int keyLen = strlen(aes_key);

    ////  128 <16 byte 192 <24byte,256 <32byte
    if (keyLen == 16) {
        bits = 128;
    } else if (keyLen == 24) {
        bits = 192;
    } else if (keyLen == 32) {
        bits = 256;
    }
    if (AES_set_encrypt_key((unsigned char *) aes_key, bits, &aes) < 0) {
        free(out);
        out = NULL;
        return;
    }

    int length = strlen(in);
    int i = 0;
    while (i < length) {
        AES_encrypt((unsigned char *) in, (unsigned char *) out, &aes);
        in += AES_BLOCK_SIZE;
        out += AES_BLOCK_SIZE;
        i += AES_BLOCK_SIZE;
    }
}

//AES encrypt use the given key
void _AES_Encrypt(char *key, char *in, char *out) {

    if (NULL == key) {
        key = AES_DEFAULT_KEY;
    }
    aesEncrypt(key, in, out);
}

void aesDecrypt(char *aes_key, char *in, char *out, const int length) {


    int bits = 0;

    const int keyLen = strlen(aes_key);

    // 128 <16 byte 192 <24byte,256 <32byte
    if (keyLen == 16) {
        bits = 128;
    } else if (keyLen == 24) {
        bits = 192;
    } else if (keyLen == 32) {
        bits = 256;
    }

    AES_KEY aes;

    if (AES_set_decrypt_key((unsigned char *) aes_key, bits, &aes) < 0) {
        free(out);
        out = NULL;
        return;
    }

    int i = 0;
    while (i < length) {
        AES_decrypt((unsigned char *) in, (unsigned char *) out, &aes);
        in += AES_BLOCK_SIZE;
        out += AES_BLOCK_SIZE;
        i += AES_BLOCK_SIZE;
    }
}

void _AES_Decrypt(char *key, char *in, char *out, const int length) {

    if (NULL == key) {
        key = AES_DEFAULT_KEY;
    }
    aesDecrypt(key, in, out, length);
}

void md5(char *in, char *out) {
    MD5(in, strlen(in), out);
}












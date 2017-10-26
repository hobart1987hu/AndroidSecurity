//
// Created by huzeyin on 2017/9/1.
//

#ifndef ANDROIDSECURITY_CRYPT_H
#define ANDROIDSECURITY_CRYPT_H

#include "../base64/base64.h"
#include "../openssl/aes/aes.h"
#include "../openssl/md5/md5.h"
#include "../constant.h"


void _AES_Encrypt(char *key, char *in, char *out);

void _AES_Decrypt(char *key, char *in, char *out, const int length);

void md5(char *in, char *out);

#endif //ANDROIDSECURITY_CRYPT_H

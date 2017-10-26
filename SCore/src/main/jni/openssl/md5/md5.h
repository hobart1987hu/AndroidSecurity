/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

//this implement Professor Rivest http://userpages.umbc.edu/~mabzug1/cs/md5/md5.html
#ifndef HEADER_MD5_H
# define HEADER_MD5_H

#include <stddef.h>
#include <string.h>
/*
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * ! MD5_LONG has to be at least 32 bits wide.                     !
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 */
# define MD5_LONG unsigned int
# define MD32_REG_T long

# define MD5_CBLOCK      64

# define MD5_LBLOCK      (MD5_CBLOCK/4)

# define MD5_DIGEST_LENGTH 16


#define HOST_c2l(c, l)   (l =(((unsigned long)(*((c)++)))    ),          \
                         l|=(((unsigned long)(*((c)++)))<< 8),          \
                         l|=(((unsigned long)(*((c)++)))<<16),          \
                         l|=(((unsigned long)(*((c)++)))<<24)           )


#define HOST_l2c(l, c)   (*((c)++)=(unsigned char)(((l)    )&0xff),      \
                         *((c)++)=(unsigned char)(((l)>> 8)&0xff),      \
                         *((c)++)=(unsigned char)(((l)>>16)&0xff),      \
                         *((c)++)=(unsigned char)(((l)>>24)&0xff),      \
                         l)


#define DATA_ORDER_IS_LITTLE_ENDIAN

#define HASH_MAKE_STRING(c, s)   do {    \
        unsigned long ll;               \
        ll=(c)->A; (void)HOST_l2c(ll,(s));      \
        ll=(c)->B; (void)HOST_l2c(ll,(s));      \
        ll=(c)->C; (void)HOST_l2c(ll,(s));      \
        ll=(c)->D; (void)HOST_l2c(ll,(s));      \
        } while (0)

/*-
#define F(x,y,z)        (((x) & (y))  |  ((~(x)) & (z)))
#define G(x,y,z)        (((x) & (z))  |  ((y) & (~(z))))
*/

/*
 * As pointed out by Wei Dai <weidai@eskimo.com>, the above can be simplified
 * to the code below.  Wei attributes these optimizations to Peter Gutmann's
 * SHS code, and he attributes it to Rich Schroeppel.
 */
#define F(b, c, d)        ((((c) ^ (d)) & (b)) ^ (d))
#define G(b, c, d)        ((((b) ^ (c)) & (d)) ^ (c))
#define H(b, c, d)        ((b) ^ (c) ^ (d))
#define I(b, c, d)        (((~(d)) | (b)) ^ (c))
#define ROTATE(a, n)     (((a)<<(n))|(((a)&0xffffffff)>>(32-(n))))

#define R0(a, b, c, d, k, s, t) { \
        a+=((k)+(t)+F((b),(c),(d))); \
        a=ROTATE(a,s); \
        a+=b; };\

#define R1(a, b, c, d, k, s, t) { \
        a+=((k)+(t)+G((b),(c),(d))); \
        a=ROTATE(a,s); \
        a+=b; };

#define R2(a, b, c, d, k, s, t) { \
        a+=((k)+(t)+H((b),(c),(d))); \
        a=ROTATE(a,s); \
        a+=b; };

#define R3(a, b, c, d, k, s, t) { \
        a+=((k)+(t)+I((b),(c),(d))); \
        a=ROTATE(a,s); \
        a+=b; };


typedef struct MD5state_st {
    MD5_LONG A, B, C, D;
    MD5_LONG Nl, Nh;
    MD5_LONG data[MD5_LBLOCK];
    unsigned int num;
} MD5_CTX;


void md5_block_data_order(MD5_CTX *c, const void *p, size_t num);

#define HASH_BLOCK_DATA_ORDER   md5_block_data_order


int MD5_Init(MD5_CTX *c);

int MD5_Update(MD5_CTX *c, const void *data, size_t len);

int MD5_Final(unsigned char *md, MD5_CTX *c);

unsigned char *MD5(const unsigned char *d, size_t n, unsigned char *md);

void MD5_Transform(MD5_CTX *c, const unsigned char *b);

#endif

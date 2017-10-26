//
// Created by 胡泽银 on 2017/8/31.
//

#ifndef ANDROIDSECURITY_BASE64_H
#define ANDROIDSECURITY_BASE64_H

int Base64decode(unsigned char *bufplain, const char *bufcoded);

int Base64encode(char *encoded, const char *string, int len);

int Base64decode_len(const char *bufcoded);

int Base64encode_len(int len);

#endif //ANDROIDSECURITY_BASE64_H

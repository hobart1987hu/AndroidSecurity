//
// Created by 胡泽银 on 2017/8/24.
//常量存放位置
//
#ifndef ANDROIDSECURITY_CONSTANT_H
#define ANDROIDSECURITY_CONSTANT_H

#include <android/log.h>

#define TAG "Security"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)

//app sign check result success
static const VERIFY_SUCCESS = 0;
//app sign check result failure
static const VERIFY_FAILURE = -1;

static const int SUCCESS = 1;

static const int FAILURE = 0;

//please put the release app sign array here ,
static const char *APP_SIGN_ARRAY[] = {
        //TODO:
};
// 密钥 128 <16个字节 192 <24,256 <32个字节
//如果是256位的，那么位数就是32位
static const char *AES_DEFAULT_KEY = "googleandroidsecurityaeshulaodaa";
//AES default bits 256
static const int AES_DEFAULT_BITS = 256;

#endif //ANDROIDSECURITY_CONSTANT_H

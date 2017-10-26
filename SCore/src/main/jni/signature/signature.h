//
// Created by 胡泽银 on 2017/8/26.
//

#ifndef ANDROIDSECURITY_SIGNATURE_H_H
#define ANDROIDSECURITY_SIGNATURE_H_H

#include <jni.h>
#include "../constant.h"

//check the app signature is validate
// if verify success  return 0
// if verify failure  return -1

int verify_sign(JNIEnv *env);

#endif //ANDROIDSECURITY_SIGNATURE_H_H

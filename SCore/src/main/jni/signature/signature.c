//
// Created by 胡泽银 on 2017/8/26.
//

#include <stdio.h>
#include <string.h>
#include "signature.h"

//get the current app of application for java object
static jobject getApplication(JNIEnv *env) {

    jobject application = NULL;
    jclass activity_thread_clz = (*env)->FindClass(env, "android/app/ActivityThread");
    if (activity_thread_clz != NULL) {
        jmethodID currentApplication = (*env)->GetStaticMethodID(env, activity_thread_clz,
                                                                 "currentApplication",
                                                                 "()Landroid/app/Application;");
        if (currentApplication != NULL) {
            application = (*env)->CallStaticObjectMethod(env, activity_thread_clz,
                                                         currentApplication);
        }
        else {
            LOGE("Cannot find method: currentApplication() in ActivityThread.");
        }
        (*env)->DeleteLocalRef(env, activity_thread_clz);
    }
    else {
        LOGE("Cannot find class: android.app.ActivityThread");
    }

    return application;
}

//check the current app sign is validate
int verify_sign(JNIEnv *env) {

    // Application object
    jobject application = getApplication(env);
    if (application == NULL) {
        return VERIFY_FAILURE;
    }
    // Context(ContextWrapper) class
    jclass context_clz = (*env)->GetObjectClass(env, application);
    // getPackageManager()
    jmethodID getPackageManager = (*env)->GetMethodID(env, context_clz, "getPackageManager",
                                                      "()Landroid/content/pm/PackageManager;");
    // android.content.pm.PackageManager object
    jobject package_manager = (*env)->CallObjectMethod(env, application, getPackageManager);
    // PackageManager class
    jclass package_manager_clz = (*env)->GetObjectClass(env, package_manager);
    // getPackageInfo()
    jmethodID getPackageInfo = (*env)->GetMethodID(env, package_manager_clz, "getPackageInfo",
                                                   "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    // context.getPackageName()
    jmethodID getPackageName = (*env)->GetMethodID(env, context_clz, "getPackageName",
                                                   "()Ljava/lang/String;");
    // call getPackageName() and cast from jobject to jstring
    jstring package_name = (jstring) ((*env)->CallObjectMethod(env, application, getPackageName));
    // PackageInfo object
    jobject package_info = (*env)->CallObjectMethod(env, package_manager, getPackageInfo,
                                                    package_name, 64);
    // class PackageInfo
    jclass package_info_clz = (*env)->GetObjectClass(env, package_info);
    // field signatures
    jfieldID signatures_field = (*env)->GetFieldID(env, package_info_clz, "signatures",
                                                   "[Landroid/content/pm/Signature;");
    jobject signatures = (*env)->GetObjectField(env, package_info, signatures_field);
    jobjectArray signatures_array = (jobjectArray) signatures;
    jobject signature0 = (*env)->GetObjectArrayElement(env, signatures_array, 0);
    jclass signature_clz = (*env)->GetObjectClass(env, signature0);

    jmethodID toCharsString = (*env)->GetMethodID(env, signature_clz, "toCharsString",
                                                  "()Ljava/lang/String;");
    // call toCharsString()
    jstring signature_str = (jstring) ((*env)->CallObjectMethod(env, signature0, toCharsString));

    // release
    (*env)->DeleteLocalRef(env, application);
    (*env)->DeleteLocalRef(env, context_clz);
    (*env)->DeleteLocalRef(env, package_manager);
    (*env)->DeleteLocalRef(env, package_manager_clz);
    (*env)->DeleteLocalRef(env, package_name);
    (*env)->DeleteLocalRef(env, package_info);
    (*env)->DeleteLocalRef(env, package_info_clz);
    (*env)->DeleteLocalRef(env, signatures);
    (*env)->DeleteLocalRef(env, signature0);
    (*env)->DeleteLocalRef(env, signature_clz);

    const char *sign = (*env)->GetStringUTFChars(env, signature_str, NULL);
    if (sign == NULL) {
        LOGE("can't get sign");
        return VERIFY_FAILURE;
    }

    LOGD("sign：%s", sign);
    int length;
    length = sizeof(APP_SIGN_ARRAY) / sizeof(APP_SIGN_ARRAY[0]);
    int i;
    for (i = 0; i < length; i++) {
        int result = strcmp(sign, APP_SIGN_ARRAY[i]);
        // sign pass
        if (result == 0) {
            (*env)->ReleaseStringUTFChars(env, signature_str, sign);
            (*env)->DeleteLocalRef(env, signature_str);
            return VERIFY_SUCCESS;
        }
    }
    (*env)->ReleaseStringUTFChars(env, signature_str, sign);
    (*env)->DeleteLocalRef(env, signature_str);
    LOGE("The signature does not match!");
    return VERIFY_FAILURE;
}
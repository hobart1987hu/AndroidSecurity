//
// Created by huzeyin on 2017/8/26.
//
#include "security.h"
#include "signature/signature.h"

// the string contract
char *str_contact(const char *str1, const char *str2) {
    char *result;
    result = (char *) malloc(strlen(str1) + strlen(str2) + 1);
    if (!result) {
        printf("Error: malloc failed in concat! \n");
        exit(EXIT_FAILURE);
    }
    strcpy(result, str1);
    strcat(result, str2);
    return result;
}

JNIEXPORT jint  JNICALL Java_security_score_Security_verifySign(JNIEnv *env, jclass object) {
    return verify_sign(env);
}

jstring AESEncrypt(JNIEnv *env, jstring data, jstring keyStr) {


    char *key = NULL;

    if (NULL != keyStr) {
        key = (*env)->GetStringUTFChars(env, keyStr, JNI_FALSE);
    } else {
        key = AES_DEFAULT_KEY;
    }

    LOGD("AESEncrypt key %s\n", key);

    char *input = (*env)->GetStringUTFChars(env, data, JNI_FALSE);

    const int length = strlen(input);

    const int encryptLen = ((length / AES_BLOCK_SIZE) * AES_BLOCK_SIZE) + AES_BLOCK_SIZE;

    char *encrypt = (char *) malloc(encryptLen);

    if (NULL == encrypt) {
        LOGD("malloc encrypt failure...");
        (*env)->ReleaseStringUTFChars(env, data, input);
        if (NULL != keyStr)(*env)->ReleaseStringUTFChars(env, keyStr, key);
        return NULL;
    }

    memset(encrypt, 0, encryptLen);

    _AES_Encrypt(key, input, encrypt);

    if (NULL == encrypt) {
        LOGD("aes encrypt failure...");
        (*env)->ReleaseStringUTFChars(env, data, input);
        if (NULL != keyStr)(*env)->ReleaseStringUTFChars(env, keyStr, key);
        return NULL;
    }

    LOGD("encrypt result ->%s\n", encrypt);

    int base64EncodeLen = Base64encode_len(strlen(encrypt));

    char *encode = (char *) malloc(base64EncodeLen);

    if (NULL == encode) {
        LOGD("aes malloc encode failure...");
        (*env)->ReleaseStringUTFChars(env, data, input);
        if (NULL != keyStr)(*env)->ReleaseStringUTFChars(env, keyStr, key);
        free(encrypt);
        encrypt = NULL;
        return NULL;
    }

    memset(encode, 0, base64EncodeLen);

    Base64encode(encode, encrypt, strlen(encrypt));

    char addEncryptLenStr[encryptLen + 1];

    sprintf(addEncryptLenStr, "%d_", encryptLen);

    LOGD("addEncryptLenStr ->%s\n", addEncryptLenStr);

    char *encodeWithEncryptLenStr = str_contact(addEncryptLenStr, encode);

    jstring result = (*env)->NewStringUTF(env, encodeWithEncryptLenStr);
    LOGD("---Java_security_score_Security_AESEncrypt->start free all data ----\n");
    free(encodeWithEncryptLenStr);
    encodeWithEncryptLenStr = NULL;
    free(encode);
    encode = NULL;
    free(encrypt);
    encrypt = NULL;
    (*env)->ReleaseStringUTFChars(env, data, input);
    if (NULL != keyStr)(*env)->ReleaseStringUTFChars(env, keyStr, key);
    LOGD("---Java_security_score_Security_AESEncrypt->finish free all data ----\n");
    return result;
}

JNIEXPORT jstring  JNICALL Java_security_score_Security_AESEncrypt(JNIEnv *env, jclass object,
                                                                   jstring data) {
    return AESEncrypt(env, data, NULL);

}

jstring AESDecrypt(JNIEnv *env, jstring data, jstring keyStr) {

    char *input = (*env)->GetStringUTFChars(env, data, JNI_FALSE);

    char *key = NULL;

    if (NULL != keyStr) {
        key = (*env)->GetStringUTFChars(env, keyStr, JNI_FALSE);
    } else {
        key = AES_DEFAULT_KEY;
    }

    LOGD("AESDecrypt key %s\n", key);

    char encode[strlen(input)];
    char encryptLenStr[5];

    sscanf(input, "%[0-9]_%[^.]", encryptLenStr, encode);

    int encryptLen = atoi(encryptLenStr);

    LOGD("Java_security_score_Security_AESDecrypt encode value %s\n", encode);

    int base64DecodeLen = Base64decode_len(encode);

    char *decode = (char *) malloc(base64DecodeLen);

    if (NULL == decode) {
        LOGD("malloc decode failure...");
        (*env)->ReleaseStringUTFChars(env, data, input);
        if (NULL != keyStr)(*env)->ReleaseStringUTFChars(env, keyStr, key);
        return NULL;
    }

    memset(decode, 0, base64DecodeLen);

    Base64decode(decode, encode);

    LOGD("decode value %s\n", decode);

    char *decrypt = (char *) malloc(encryptLen);

    if (NULL == decrypt) {
        LOGD("malloc aesDecryptStr failure...");
        free(decode);
        decode = NULL;
        (*env)->ReleaseStringUTFChars(env, data, input);
        if (NULL != keyStr)(*env)->ReleaseStringUTFChars(env, keyStr, key);
        return NULL;
    }

    memset(decrypt, 0, encryptLen);

    _AES_Decrypt(key, decode, decrypt, encryptLen);

    LOGD("decrypt value ->%s\n", decrypt);

    if (NULL == decrypt) {
        free(decode);
        decode = NULL;
        (*env)->ReleaseStringUTFChars(env, data, input);
        if (NULL != keyStr)(*env)->ReleaseStringUTFChars(env, keyStr, key);
        return NULL;
    }

    jstring result = (*env)->NewStringUTF(env, decrypt);

    LOGD("---Java_security_score_Security_AESDecrypt->start free all data ----\n");
    free(decode);
    decode = NULL;
    free(decrypt);
    decrypt = NULL;
    (*env)->ReleaseStringUTFChars(env, data, input);
    if (NULL != keyStr)(*env)->ReleaseStringUTFChars(env, keyStr, key);
    LOGD("---Java_security_score_Security_AESDecrypt->finish free all data ----\n");
    return result;
}

JNIEXPORT jstring JNICALL Java_security_score_Security_AESDecrypt(JNIEnv *env, jclass object,
                                                                  jstring data) {
    return AESDecrypt(env, data, NULL);

}

JNIEXPORT jstring JNICALL Java_security_score_Security_AESEncryptWithKey(JNIEnv *env, jclass object,
                                                                         jstring keyStr,
                                                                         jstring data) {
    return AESEncrypt(env, data, keyStr);

}

JNIEXPORT jstring JNICALL Java_security_score_Security_AESDecryptWithKey(JNIEnv *env, jclass object,
                                                                         jstring keyStr,
                                                                         jstring data) {
    return AESDecrypt(env, data, keyStr);
}

JNIEXPORT jstring JNICALL Java_security_score_Security_md5(JNIEnv *env, jclass object,
                                                           jstring data) {

    char *input = (*env)->GetStringUTFChars(env, data, JNI_FALSE);

    //this you can set md5 key
    // example char * md5_key="qwertyadqwe";
    //char* in  = str_contact(input,md5);
    unsigned char decrypt[16] = {0};

    md5(input, decrypt);

//    MD5_CTX context = {0};
//    MD5_Init(&context);
//    MD5_Update(&context, input, strlen(input));
//    MD5_Final(decrypt, &context);

    (*env)->ReleaseStringUTFChars(env, data, input);
    int i = 0;
    char md5Value[1024] = {0};
    for (i = 0; i < 16; i++) {
        sprintf(md5Value, "%s%02x", md5Value, decrypt[i]);
    }
    return (*env)->NewStringUTF(env, md5Value);
}



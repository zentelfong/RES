#ifndef _RES_H
#define _RES_H
#include <stdint.h>

//随机加密标准算法
uint32_t ResEncryptedLength(uint32_t len);//获取加密后字节数
uint32_t ResDecryptedLength(uint32_t len);//获取解密后的字节数
uint32_t ResEncrypt(const uint8_t* inBuf,uint32_t inBufLen,uint8_t* outBuf);
uint32_t ResDecrypt(const uint8_t* inBuf,uint32_t inBufLen,uint8_t* outBuf);


#endif
#ifndef _RES_H
#define _RES_H
#include <stdint.h>

//������ܱ�׼�㷨
uint32_t ResEncryptedLength(uint32_t len);//��ȡ���ܺ��ֽ���
uint32_t ResDecryptedLength(uint32_t len);//��ȡ���ܺ���ֽ���
uint32_t ResEncrypt(const uint8_t* inBuf,uint32_t inBufLen,uint8_t* outBuf);
uint32_t ResDecrypt(const uint8_t* inBuf,uint32_t inBufLen,uint8_t* outBuf);


#endif
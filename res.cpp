#include "res.h"
#include "aes.h"
#include <string.h>
#include <stdlib.h>


struct ResHeader{
	uint32_t seed:28;
	uint32_t padding:4;//表示补0的长度，使其满足16字节的倍数，范围0~15
};

//生成随机数
uint32_t ResGenRandomKey()
{
	/* See "Numerical Recipes in C", second edition, p. 284 */
	uint8_t buf[4];
	for (int i=0;i<4;++i)
	{
		unsigned int num = rand() * 1664525L + 1013904223L;//1013904223L
		buf[i]=(uint8_t) (num >> 24);
	}
	return *(uint32_t*)buf; 
}


uint32_t ResEncryptedLength(uint32_t len)
{
	if (len%16==0)
	{
		//不需补0
		return len+sizeof(ResHeader);
	}
	else
	{
		return (len/16+1)*16+sizeof(ResHeader);
	}
}


uint32_t ResDecryptedLength(uint32_t len)
{
	if(len>sizeof(ResHeader))
		return len-sizeof(ResHeader);
	else
		return 0;
}


void ResKeyFromSeed(uint32_t seed,uint32_t key[4])
{
	uint32_t encKey[4]={0x39FE2F96,0x4D2149AB,0x36FD6E09,0x8B4FBCFD};
	for (int i=0;i<4;++i)
	{
		key[i]=encKey[i]*seed;
	}
}


uint32_t ResEncrypt(const uint8_t* inBuf,uint32_t inBufLen,uint8_t* outBuf)
{
	ResHeader header;
	header.seed=ResGenRandomKey();
	if (inBufLen%16==0)
	{
		header.padding=0;
	}
	else
	{
		header.padding=16 - inBufLen%16;
	}

	uint32_t key[4];
	ResKeyFromSeed(header.seed,key);

	aes_context aes;
	aes_set_key(&aes,(uint8_t*)key,sizeof(key)*8);

	memcpy(outBuf,&header,sizeof(header));
	outBuf+=sizeof(header);

	int round=inBufLen/16;

	for (int i=0;i<round;++i)
	{
		aes_encrypt(&aes,(uint8_t*)inBuf+i*16,outBuf+i*16);
	}

	//后面还有不足16字节的需要加密
	if (round*16<inBufLen)
	{
		uint32_t left=inBufLen-round*16;
		uint8_t buf[16];
		memset(buf,0,sizeof(buf));
		memcpy(buf,inBuf+round*16,left);
		aes_encrypt(&aes,buf,outBuf+round*16);
		return (round+1)*16+sizeof(ResHeader);
	}
	else
		return round*16+sizeof(ResHeader);
}

uint32_t ResDecrypt(const uint8_t* inBuf,uint32_t inBufLen,uint8_t* outBuf)
{
	ResHeader* header=(ResHeader*)inBuf;
	uint32_t key[4];
	aes_context aes;

	if (!inBuf || inBufLen<sizeof(ResHeader))
	{
		return 0;
	}

	ResKeyFromSeed(header->seed,key);
	aes_set_key(&aes,(uint8_t*)key,sizeof(key)*8);

	inBuf+=sizeof(ResHeader);
	inBufLen-=sizeof(ResHeader);
	int round=inBufLen/16;
	for (int i=0;i<round;++i)
	{
		aes_decrypt(&aes,(uint8_t*)inBuf+i*16,outBuf+i*16);
	}
	return inBufLen-header->padding;
}





#include <windows.h>
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
#include "openssl/aes.h"

BOOL AES_Enc(const unsigned char* Key, char* InputData, DWORD DataLen, char* EncryptData, DWORD* OutDataLen)
{
	int SetDataLen;
	AES_KEY AesKey;
	unsigned char ivec[AES_BLOCK_SIZE] = "";
	memset(&AesKey, 0, sizeof(AES_KEY));
	if (AES_set_encrypt_key(Key, 128, &AesKey) < 0)
	{
		return FALSE;
	}
	SetDataLen = 0;
	if ((DataLen % AES_BLOCK_SIZE) == 0)
	{
		SetDataLen = DataLen;
	}
	else
	{
		SetDataLen = ((DataLen / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
	}

	//加密  
	AES_cbc_encrypt((unsigned char *)InputData, (unsigned char *)EncryptData, SetDataLen, &AesKey, ivec, AES_ENCRYPT);

	*OutDataLen = DataLen;
	return TRUE;
}

BOOL AES_Dec(const unsigned char* Key, char* InputData, DWORD DataLen, char* DecryptData, DWORD* OutDataLen)
{
	int SetDataLen;
	AES_KEY AesKey;
	unsigned char ivec[AES_BLOCK_SIZE] = "";
	memset(&AesKey, 0, sizeof(AES_KEY));
	if (AES_set_decrypt_key(Key, 128, &AesKey) < 0)
	{
		return FALSE;
	}
	SetDataLen = 0;
	if ((DataLen % AES_BLOCK_SIZE) == 0)
	{
		SetDataLen = DataLen;
	}
	else
	{
		SetDataLen = ((DataLen / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
	}

	//解密  
	AES_cbc_encrypt((unsigned char *)InputData, (unsigned char *)DecryptData, SetDataLen, &AesKey, ivec, AES_DECRYPT);

	*OutDataLen = DataLen;
	return TRUE;
}

int main(int argc, char **argv)
{
	char Source[1024];
	char *InputData = NULL;
	char EncryptData[1024] = "";
	char DecryptData[1024] = "";

	unsigned char Key[] = "0123456789abcdefghijklmn";

	int DataLen;

	memset(Source, 0, sizeof(Source));
	strcpy_s(Source, "123456789abcdefghijklmn");	//要加密的数据  
	DataLen = strlen(Source) + 1;

	DWORD OutDataLen = 0;
	BOOL bRet = FALSE;
	bRet = AES_Enc(Key, Source, DataLen, EncryptData, &OutDataLen);

	bRet = AES_Dec(Key, EncryptData, OutDataLen, DecryptData, &OutDataLen);

	return 0;
}


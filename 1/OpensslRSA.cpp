

#include <windows.h>
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
#include <openssl/engine.h>

RSA* RSA_MakeKey(int nbits)
{
	return RSA_generate_key(nbits, RSA_F4, NULL, NULL);
}

//这里nbits的长度选择4096，小于1024的nbits长度都是不安全的，容易被破解
RSA* RSA_MakeKey(int nbits, unsigned int number)
{
	RSA* rsa = NULL;
	rsa = RSA_new();
	if (rsa == NULL)
	{
		return NULL;
	}

	BIGNUM* exponent = BN_new();
	if (exponent == NULL)
	{
		return NULL;
	}

	if (0 == BN_set_word(exponent, number))	//	64661    //65537
	{
		BN_free(exponent);
		return NULL;
	}

	if (0 == RSA_generate_key_ex(rsa, nbits, exponent, NULL))
	{
		BN_free(exponent);
		return NULL;
	}
	BN_free(exponent);

	return rsa;
}

RSA *RSA_LoadPublicKey(char *szKey)
{
	BIO *pBio = BIO_new_mem_buf(szKey, -1);
	if (pBio == NULL)
	{
		return NULL;
	}
	RSA *pRsa = PEM_read_bio_RSAPublicKey(pBio, NULL, NULL, NULL);
	if (pRsa == NULL)
	{
		return NULL;
	}
	return pRsa;
}

RSA *RSA_LoadPrivateKey(char *szKey)
{
	BIO *pBio = BIO_new_mem_buf(szKey, -1);
	if (pBio == NULL)
	{
		return NULL;
	}
	RSA *pRsa = PEM_read_bio_RSAPrivateKey(pBio, NULL, NULL, NULL);
	if (pRsa == NULL)
	{
		return NULL;
	}
	return pRsa;
}

void RSA_SavePublicKey(RSA *pRsa, const char *szPublicKey)
{
	BIO *pBio = BIO_new_file(szPublicKey, "wb");
	if (pBio == NULL)
	{
		return;
	}
	if (PEM_write_bio_RSAPublicKey(pBio, pRsa) == 0)
	{
		return;
	}
	BIO_free_all(pBio);
}

void RSA_SavePrivateKey(RSA *pRsa, const char *szPrivateKey)
{
	BIO *pBio = BIO_new_file(szPrivateKey, "wb");
	if (pBio == NULL)
	{
		return;
	}
	if (PEM_write_bio_RSAPrivateKey(pBio, pRsa, NULL, NULL, 0, NULL, NULL) == 0)
	{
		return;
	}
	BIO_free_all(pBio);
}

int RSA_PublicEnc(RSA *pRsa, char *in, int inLen, char *out, int *outLen)
{
	*outLen = RSA_public_encrypt(
		(RSA_size(pRsa) - 11) > inLen ? inLen : RSA_size(pRsa) - 11,
		(unsigned char *)in,
		(unsigned char *)out,
		pRsa,
		RSA_PKCS1_PADDING);
	if (*outLen >= 0)
		return 0;
	return -1;
}

int RSA_PublicEnc(const char *szPublicKey, char *in, int inLen, char *out, int *outLen)
{
	BIO *pBio = BIO_new_file(szPublicKey, "rb");
	RSA *pRsa = PEM_read_bio_RSAPublicKey(pBio, NULL, NULL, NULL);
	BIO_free_all(pBio);
	*outLen = RSA_public_encrypt(
		(RSA_size(pRsa) - 11) > inLen ? inLen : RSA_size(pRsa) - 11,
		(unsigned char *)in,
		(unsigned char *)out,
		pRsa,
		RSA_PKCS1_PADDING);
	//RSA_free(pRsa);  
	if (*outLen >= 0)
		return 0;
	return -1;
}

int RSA_PrivateDec(RSA *pRsa, char *in, int inLen, char *out, int *outLen)
{
	*outLen = RSA_private_decrypt(
		inLen,
		(unsigned char *)in,
		(unsigned char *)out,
		pRsa,
		RSA_PKCS1_PADDING);
	if (*outLen >= 0)
		return 0;
	return -1;
}

int RSA_PrivateDec(const char *szPrivateKey, char *in, int inLen, char *out, int *outLen)
{
	BIO *pBio = BIO_new_file(szPrivateKey, "rb");
	RSA *pRsa = PEM_read_bio_RSAPrivateKey(pBio, NULL, NULL, NULL);
	BIO_free_all(pBio);
	*outLen = RSA_private_decrypt(
		inLen,
		(unsigned char *)in,
		(unsigned char *)out,
		pRsa,
		RSA_PKCS1_PADDING);
	//RSA_free(pRsa);
	if (*outLen >= 0)
		return 0;
	return -1;
}

void RSA_Close(RSA* pRsa)
{
	RSA_free(pRsa);
}


int main()
{
	RSA *rsa = RSA_MakeKey(4096, 65537);

	RSA_SavePublicKey(rsa, "PublicKey");

	RSA_SavePrivateKey(rsa, "PrivateKey");

	char szStr1[1024] = "0123456789";
	char szStr2[1024];
	char szStr3[1024];
	int nStrLen1 = 0;
	int nStrLen2 = 0;
	//////////////////////////////////////////////////////////////////////////

	memset(szStr1, 0, sizeof(szStr1));
	memset(szStr2, 0, sizeof(szStr2));
	memset(szStr3, 0, sizeof(szStr3));
	strcpy_s(szStr1, "0123456789");

	RSA_PublicEnc("PublicKey", szStr1, 11, szStr2, &nStrLen1);

	RSA_PrivateDec(rsa, szStr2, nStrLen1, szStr3, &nStrLen2);

	printf("szStr1 = %s \n", szStr1);
	printf("szStr3 = %s \n", szStr3);
	//////////////////////////////////////////////////////////////////////////

	memset(szStr1, 0, sizeof(szStr1));
	memset(szStr2, 0, sizeof(szStr2));
	memset(szStr3, 0, sizeof(szStr3));
	strcpy_s(szStr1, "0123456789");

	RSA_PublicEnc(rsa, szStr1, 11, szStr2, &nStrLen1);

	RSA_PrivateDec("PrivateKey", szStr2, nStrLen1, szStr3, &nStrLen2);

	printf("szStr1 = %s \n", szStr1);
	printf("szStr3 = %s \n", szStr3);
	//////////////////////////////////////////////////////////////////////////

	memset(szStr1, 0, sizeof(szStr1));
	memset(szStr2, 0, sizeof(szStr2));
	memset(szStr3, 0, sizeof(szStr3));
	strcpy_s(szStr1, "0123456789");

	RSA_PublicEnc("PublicKey", szStr1, 11, szStr2, &nStrLen1);

	RSA_PrivateDec("PrivateKey", szStr2, nStrLen1, szStr3, &nStrLen2);

	printf("szStr1 = %s \n", szStr1);
	printf("szStr3 = %s \n", szStr3);
	//////////////////////////////////////////////////////////////////////////

	memset(szStr1, 0, sizeof(szStr1));
	memset(szStr2, 0, sizeof(szStr2));
	memset(szStr3, 0, sizeof(szStr3));
	strcpy_s(szStr1, "0123456789");

	RSA_PublicEnc(rsa, szStr1, 11, szStr2, &nStrLen1);

	RSA_PrivateDec(rsa, szStr2, nStrLen1, szStr3, &nStrLen2);

	printf("szStr1 = %s \n", szStr1);
	printf("szStr3 = %s \n", szStr3);


	RSA_Close(rsa);


	return 0;
}


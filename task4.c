#include<stdio.h>
#include<openssl/bn.h>

void printBN(char *msg,BIGNUM *a)
{
	char* number_str=BN_bn2hex(a);
	printf("%s %s\n",msg,number_str);
	OPENSSL_free(number_str);
}

int main()
{
	BN_CTX *ctx=BN_CTX_new();
	BIGNUM *M=BN_new();//明文
	BIGNUM *n=BN_new();
	BIGNUM *res=BN_new();//签名了的消息
	BIGNUM *d=BN_new();

	BN_hex2bn(&M,"49206f776520796f752024333030302e");
	BN_hex2bn(&n,"DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	BN_hex2bn(&d,"74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

	//签名
	BN_mod_exp(res,M,d,n,ctx);

	printBN("签名后:",res);

	return 0;
}
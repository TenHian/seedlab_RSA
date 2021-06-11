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
	BIGNUM *S=BN_new();//签名
	BIGNUM *n=BN_new();
	BIGNUM *e=BN_new();
	BIGNUM *M=BN_new();//明文16进制
	BIGNUM *Mi=BN_new();//验证

	BN_hex2bn(&M,"4c61756e63682061206d697373696c652e");
	BN_hex2bn(&n,"AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
	BN_hex2bn(&S,"643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");
	BN_hex2bn(&e,"010001");

	printBN("M原文:",M);

	//验证	S^e mod n
	BN_mod_exp(Mi,S,e,n,ctx);
	printBN("Mi验证:",Mi);

	if(BN_cmp(Mi,M)==0)
	{
		printf("Alice签名\n");
	}
	else
	{
		printf("非Alice签名\n");
	}

	return 0;
}
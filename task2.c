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
	BIGNUM *e=BN_new();
	BIGNUM *n=BN_new();
	BIGNUM *Eres=BN_new();//密文
	BIGNUM *Dres=BN_new();//解密之后明文
	BIGNUM *p=BN_new();
	BIGNUM *q=BN_new();
	BIGNUM *d=BN_new();

	//赋值m e p q
	BN_hex2bn(&M,"4120746f702073656372657421");
	BN_hex2bn(&e,"0D88C3");
	BN_hex2bn(&p,"F7E75FDC469067FFDC4E847C51F452DF");
	BN_hex2bn(&q,"E85CED54AF57E53E092113E62F436F4F");

	//n=p*q
	BN_mul(n,p,q,ctx);
	printBN("n:\n",n);

	//d我们在task1已求出
	BN_hex2bn(&d,"3587A24598E5F2A21DB007D89D18CC50ABA5075BA19A33890FE7C28A9B496AEB");

	//加密 M^e mod n
	BN_mod_exp(Eres,M,e,n,ctx);
	printBN("密文:",Eres);

	//解密 Eres^d mod n
	BN_mod_exp(Dres,Eres,d,n,ctx);
	printBN("明文:",Dres);

	return 0;
}
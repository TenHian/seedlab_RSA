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
	BIGNUM *p=BN_new();
	BIGNUM *p1=BN_new();
	BIGNUM *q=BN_new();
	BIGNUM *q1=BN_new();
	BIGNUM *e=BN_new();
	BIGNUM *x=BN_new();
	BIGNUM *d=BN_new();
	BIGNUM *one=BN_new();

	//赋值p q e
	BN_hex2bn(&p,"F7E75FDC469067FFDC4E847C51F452DF");
	BN_hex2bn(&q,"E85CED54AF57E53E092113E62F436F4F");
	BN_hex2bn(&e,"0D88C3");

	//one这个变量是1
	BN_hex2bn(&one,"1");

	//p1=p-1
	BN_sub(p1,p,one);
	//q1=q-1
	BN_sub(q1,q,one);

	//x=p1*q1
	BN_mul(x,p1,q1,ctx);

	//e*d mod x = 1
	BN_mod_inverse(d,e,x,ctx);

	printBN("私钥d:",d);

	return 0;
}
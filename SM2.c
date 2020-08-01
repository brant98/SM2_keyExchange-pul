#include <stdio.h>
#include <time.h>
#include<string.h>
#include "miracl.h"
#include"mirdef.h"
#include "SM2.h"
// ECC椭圆曲线参数（SM2标准推荐参数）
static unsigned char SM2_p[32] = {
	0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
static unsigned char SM2_a[32] = {
	0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC };
static unsigned char SM2_b[32] = {
	0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34, 0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
	0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92, 0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93 };
static unsigned char SM2_n[32] = {
	0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0x72, 0x03, 0xDF, 0x6B, 0x21, 0xC6, 0x05, 0x2B, 0x53, 0xBB, 0xF4, 0x09, 0x39, 0xD5, 0x41, 0x23 };
static unsigned char SM2_Gx[32] = {
	0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19, 0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
	0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1, 0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7 };
static unsigned char SM2_Gy[32] = {
	0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C, 0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
	0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40, 0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0 };
static unsigned char SM2_h[32] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };

big para_p, para_a, para_b, para_n, para_Gx, para_Gy, para_h;
epoint* G;
miracl* mip;
/*
功能：SM2算法椭圆曲线参数初始化
输入：无
输出：无
返回：0失败  1成功
*/
int SM2_init(void)
{
	epoint* nG;
	mip = mirsys(10000, 16);
	mip->IOBASE = 16;
	para_p = mirvar(0);
	para_a = mirvar(0);
	para_b = mirvar(0);
	para_n = mirvar(0);
	para_Gx = mirvar(0);
	para_Gy = mirvar(0);
	para_h = mirvar(0);

	G = epoint_init();
	nG = epoint_init();

	bytes_to_big(32, SM2_p, para_p);  // 32=256/8
	bytes_to_big(32, SM2_a, para_a);
	bytes_to_big(32, SM2_b, para_b);
	bytes_to_big(32, SM2_n, para_n);
	bytes_to_big(32, SM2_Gx, para_Gx);
	bytes_to_big(32, SM2_Gy, para_Gy);
	bytes_to_big(256, SM2_h, para_h);

	/*Initialises GF(p) elliptic curve.(MR_PROJECTIVE specifying projective coordinates)*/
	ecurve_init(para_a, para_b, para_p, MR_PROJECTIVE);

	/*initialise point G*/
	if (!epoint_set(para_Gx, para_Gy, 0, G))
		return 0;

	ecurve_mult(para_n, G, nG);

	/*test if the order of the point is n*/
	if (!point_at_infinity(nG))
		return 0;
	printf("Init successed!\n");
	return 1;             //成功运行到最后则返回1.若返回的是0则表示初始化不正确
}
int isInRange(big num) //判断d是否在规定范围内  1至n-1的闭区间
{
	big one, decr_n;
	one = mirvar(0);
	decr_n = mirvar(0);

	convert(1, one);
	decr(para_n, 1, decr_n);

	if ((mr_compare(num, one) > 0) && (mr_compare(num, decr_n) < 0)) //compare(x,y)  x>y +1   x=y 0  x<y -1
		return 1;//返回1表示在适合范围
	return 0;//返回0表示不在适合的范围
}
int SM2_creat_key(big* d, epoint** pub)
{

	*d = mirvar(0);
	*pub = epoint_init();
	irand(time(NULL));
	bigrand(para_n, *d);  // d私钥 d应在1至n-2之间，包括两端
	while (isInRange(*d) != 1)
	{
		bigrand(para_n, *d);
	}
	ecurve_mult(*d, G, *pub);//pub中存放公钥
	printf("creat key done!\n");
	return 1; //成功返回1
}
/*
KDF密钥派生函数
 key derivation function
*Z是比特串，klen表示要获得的密钥数据的比特长度
*k是存放输出的，z是输入
*/
int KDF(unsigned char Z[], int zlen, unsigned char K[], int klen)
{
	int  i, j = 0, t;
	int bit_klen;
	unsigned char Ha[32] = { 0 }; //摘要 及其长度为32
	unsigned char ct[4] = { 0,0,0,1 };

	bit_klen = klen * 8;//有多少位  也可以用字节。
	sha256 sha_256;

	if (bit_klen % 256)
		t = bit_klen / 256 + 1;
	else
		t = bit_klen / 256;
	//K= Ha1 || Ha2 || ...
	for (i = 1; i < t; i++)//因为后面有i-1  且最后一个Ha要单独求
	{
		//Ha1=Hv(Z|| ct )
		shs256_init(&sha_256);
		for (j = 0; j < zlen; j++)
			shs256_process(&sha_256, Z[j]);
		for (j = 0; j < 4; j++)
			shs256_process(&sha_256, ct[j]);
		shs256_hash(&sha_256, Ha);

		memcpy((K + 32 * (i - 1)), Ha, 32);

		//ct++  注意进位,大小端
		if (ct[3] == 0xff)
		{
			ct[3] = 0;
			if (ct[2] == 0xff)
			{
				ct[2] = 0;
				if (ct[1] == 0xff)
				{
					ct[1] = 0;
					ct[0]++;
				}
				else
					ct[1]++;
			}
			else
				ct[2]++;
		}
		else
			ct[3]++;
	}
	shs256_init(&sha_256);
	for (j = 0; j < zlen; j++)
		shs256_process(&sha_256, Z[j]);
	for (j = 0; j < 4; j++)
		shs256_process(&sha_256, ct[j]);
	shs256_hash(&sha_256, Ha);

	//若klen/v是整数
	if (bit_klen % 256) //或者字节能否被32整除
	{
		j = klen - 32 * (klen / 32);
		memcpy((K + 32 * (t - 1)), Ha, j);
	}
	else
	{
		memcpy((K + 32 * (t - 1)), Ha, 32);
	}
	return 1;//返回1成功
}

void SM2_ZA(epoint* A, unsigned char IDA[], unsigned char ZA[])//生成用户标识
{
	unsigned char pubx[32], puby[32];
	big X, Y;
	X = mirvar(0);
	Y = mirvar(0);
	epoint_get(A, X, Y);
	big_to_bytes(32, X, pubx, 1);
	big_to_bytes(32, Y, puby, 1);

	unsigned char ENTLA[2] = { 0x00, 0x80 }; //签名者的具有长度为entlenA比特的可辨别标识IDA，记ENTLA是由整数entlenA转换而成的两个字节
	//unsigned char IDA[16] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };//用户标识
	unsigned char Msg[210];	//210 = size of IDA + 2 + 32 * 6(a,b,Gx,Gy,pubx,puby)  =210字节

	//ZA = Hash(ENTLA || IDA || a || b || Gx || Gy || xpub|| ypub)
	memcpy(Msg, ENTLA, 2);
	memcpy(Msg + 2, IDA, sizeof(IDA));
	memcpy(Msg + 2 + sizeof(IDA), SM2_a, 32);
	memcpy(Msg + 2 + sizeof(IDA) + 32, SM2_b, 32);
	memcpy(Msg + 2 + sizeof(IDA) + 32 * 2, SM2_Gx, 32);
	memcpy(Msg + 2 + sizeof(IDA) + 32 * 3, SM2_Gy, 32);
	memcpy(Msg + 2 + sizeof(IDA) + 32 * 4, pubx, 32);
	memcpy(Msg + 2 + sizeof(IDA) + 32 * 5, puby, 32);
	//此处使用的是hash256,当然最标准的应该是使用SM3进行杂凑
	sha256 sha_256;
	shs256_init(&sha_256);
	for (int i = 0; i < 210; i++)
	{
		shs256_process(&sha_256, Msg[i]);
	}
	shs256_hash(&sha_256, ZA);
	//printf("ZA done!\n");
}

/*************
------密钥交换---
*************/
//以下为SM2密钥交换部分的函数

//用户A为发起方，B为请求响应方

//RA，即步骤A1-A3
int cal_RA_RB(epoint** RA, big* rA)//RA为一个点，rA为随机数
{
	//A1: 产生随机数ra在1至n-1范围内
	*rA = mirvar(0);
	*RA = epoint_init();
	while (isInRange(*rA) == 0)
	{
		bigrand(para_n, *rA);
	}

	//A2:计算RA=[rA]G；
	ecurve_mult(*rA, G, *RA);

	//A3:将RA发送给B
	return 1;//返回1表示成功
}

//测试点是否在这条椭圆曲线上
int pointIsOn(epoint* point)
{
	big x, y, x_3, tmp;

	x = mirvar(0);
	y = mirvar(0);
	x_3 = mirvar(0);
	tmp = mirvar(0);

	//测试 y^2 = x^3 + ax + b 是否成立
	epoint_get(point, x, y);
	power(x, 3, para_p, x_3);	//x_3 = x^3 mod p
	multiply(x, para_a, x); 	//x = a * x
	divide(x, para_p, tmp); 	//x = a * x mod p, tmp = a * x / p
	add(x_3, x, x);				//x = x^3 + ax
	add(x, para_b, x);			//x = x^3 + ax + b
	divide(x, para_p, tmp);		//x = x^3 + ax + b mod p
	power(y, 2, para_p, y);		//y = y^2 mod p

	if (mr_compare(x, y) != 0)
		return 0;//返回0表示不在这条椭圆曲线上

	return 1;//返回1表示在
}

//响应方B,首先进行的系列操作
//K里面放的KB     hash里面放的Sb(选项)
int B1(epoint**V,epoint* RA, epoint* RB, epoint* pA, epoint* pB, big dB, big  rB, unsigned char ZA[], unsigned char ZB[], unsigned char K[], unsigned char SB[])
{
	big x1, y1, x2, y2, x1_, y1_, x2_, y2_, Vx, Vy, temp;
	
	int lenK = sizeof(K);
	int i = 0;
	int w = 0;
	*V = epoint_init();
	x1 = mirvar(0);
	y1 = mirvar(0);
	x2 = mirvar(0);
	y2 = mirvar(0);
	x1_ = mirvar(0);
	y1_ = mirvar(0);
	Vx = mirvar(0);
	Vy = mirvar(0);
	temp = mirvar(0);
	x2_ = mirvar(0);
	y2_ = mirvar(0);
	unsigned char x1y1_char[64] = { 0 };
	unsigned char x2y2_char[64] = { 0 };
	unsigned char Z[128] = { 0 };  //128=VX, VY, ZA, ZB=32*4


	unsigned char fr[1] = { 0x02 };
	sha256 sha_256;

	//B2: 计算RB
	epoint_get(RB, x2, y2);
	//将x2 y2放数组中，方便后续进行杂凑，同时x2 y2就可以用作变量存放其他值。
	big_to_bytes(32, x2, x2y2_char, 1);
	big_to_bytes(32, y2, x2y2_char + 32, 1);

	//B3:计算w,x2_=2^w + x2 & (2^w - 1)
	w = logb2(para_n);
	expb2(w, temp);//temp=2^w
	if (mr_compare(para_n, temp) == 1)
		w++;
	if ((w % 2) == 0)
		w = w / 2 - 1;
	else
		w = (w + 1) / 2 - 1;

	//大数不方便直接进行与操作，采用模运算的方式实现与操作
	expb2(w, x2_);   //x2_=2^w
	divide(x2, x2_, temp);//x2里面放的是余数，即就是模2^w后的值
	// 此处考虑用mod的方式实现一下
	add(x2, x2_, x2_);   //x2_=2^w + x2 & (2^w - 1)
	//divide(x2_, para_n, temp);	//x2_ = n mod q  这句代码查看是否需要

	//B4：tB = (dB + x2_ * rB) mod n
	multiply(x2_, rB, x2_);
	add(dB, x2_, x2_);     //现在的x2_=(dB + x2_ * rB)
	divide(x2_, para_n, temp);   //x2_即就是tB

	//B5:验证RA是否满足椭圆曲线，并计算x1_,单独将测试点是否在椭圆曲线上写成一个函数，使代码更加简洁
	//先测试
	if (pointIsOn(RA) == 0)
	{
		printf("RA is not on the curve!\n");
		return 0;
	}
	//后计算x1_
	epoint_get(RA, x1, y1);
	big_to_bytes(32, x1, x1y1_char, 1);
	big_to_bytes(32, y1, x1y1_char + 32, 1);
	expb2(w, x1_);		//x1_ = 2^w
	divide(x1, x1_, temp);	//x1 = x1 mod x1_ = x1 & (2^w - 1)
	add(x1_, x1, x1_);
	//divide(x1_, para_n, temp);	//x1_ = n mod q   这里需要注意一下  有和无的区别

	//B6:计算点V，V是否为无穷远点？V = [h * tB](PA + [x1_]RA)
	ecurve_mult(x1_, RA,*V);//V=[x1_]RA
	epoint_get(*V, Vx, Vy);

	ecurve_add(pA, *V);//V=PA+[x1_]RA
	epoint_get(*V, Vx, Vy);

	multiply(para_h, x2_, temp);//temp=tB * h
	ecurve_mult(temp, *V, *V);

	if (point_at_infinity(*V) == 1)
	{
		printf("V is at infinity!\n");
		return 0;
	}
	epoint_get(*V, Vx, Vy);

	//B7:计算KB
	big_to_bytes(32, Vx, Z, 1);
	big_to_bytes(32, Vy, Z + 32, 1);//Z=Vx||Vy
	memcpy(Z + 64, ZA, 32);//Z=Vx||Vy||ZA
	memcpy(Z + 96, ZB, 32);//Z=Vx||Vy||ZA||ZB
	KDF(Z, 128, K, lenK); //K中放的KB

	//进行杂凑
	shs256_init(&sha_256);
	for (i = 0; i < 32; i++)
	{
		shs256_process(&sha_256, Z[i]);  //hash(Vx)
	}
	for (i = 0; i < 32; i++)
	{
		shs256_process(&sha_256, ZA[i]);  //hash(Vx||ZA)
	}
	for (i = 0; i < 32; i++)
	{
		shs256_process(&sha_256, ZB[i]);  //hash(Vx||ZA||ZB)
	}
	for (i = 0; i < 64; i++)
	{
		shs256_process(&sha_256, x1y1_char[i]);  //hash(Vx||ZA||ZB||x1||y1)
	}
	for (i = 0; i < 64; i++)
	{
		shs256_process(&sha_256, x2y2_char[i]);  //hash(Vx||ZA||ZB||x1||y1||x2||y2)
	}
	shs256_hash(&sha_256, SB);


	shs256_init(&sha_256);
	shs256_process(&sha_256, fr[0]);  //hash(0x02)
	for (i = 0; i < 32; i++)
	{
		shs256_process(&sha_256, Z[i + 32]);//hash(0x02||Vy)
	}

	//B8-B9: hash存放的即 SB选项   SB和RB发送给用户A
	for (i = 0; i < 32; i++)
	{
		shs256_process(&sha_256, SB[i]);//hash(0x02||Vy||hash(Vx||ZA||ZB||x1||y1||x2||y2))
	}
	shs256_hash(&sha_256,SB);

	return 1;//成功返回1,否则为失败

}
int A2(epoint* RA, big rA, big dA, epoint* RB, epoint* pB, unsigned char ZA[], unsigned char ZB[], unsigned char KA[], unsigned char SB[], unsigned char SA[])
{
	big x1, y1, x1_, x2, y2, x2_, temp, tA, Ux, Uy;
	x1 = mirvar(0);
	y1 = mirvar(0);
	x1_ = mirvar(0);
	x2 = mirvar(0);
	x2_ = mirvar(0);
	y2 = mirvar(0);
	temp = mirvar(0);
	tA = mirvar(0);
	Ux = mirvar(0);
	Uy = mirvar(0);

	sha256  sha_256;
	unsigned char x1y1_char[64] = { 0 };
	unsigned char x2y2_char[64] = { 0 };
	unsigned char Z[128] = { 0 };
	unsigned char hash[32] = { 0 };
	unsigned char S1[32] = { 0 };
	int w = 0, i = 0;
	epoint* U;
	U = epoint_init();
	unsigned char fr[2] = { 0x02,0x03 };
	//计算w
	w = logb2(para_n);
	expb2(w, temp);  //temp=2^w
	if (mr_compare(para_n, temp) == 1)
		w++;
	if ((w % 2) == 0)
		w = w / 2 - 1;
	else
		w = (w + 1) / 2 - 1;
	//A4: x1_ = 2^w + x2 & (2^w - 1)
	epoint_get(RA, x1, y1);
	big_to_bytes(32, x1, x1y1_char, 1);
	big_to_bytes(32, y1, x1y1_char + 32, 1);

	expb2(w, x1_);		//x1_ = 2^w
	divide(x1, x1_, temp);	//x1 = x1 mod x1_ = x1 & (2^w - 1)
	add(x1_, x1, x1_);
	//divide(x1_, para_n, temp);   //注意这里需要不要


	//A5:计算tA=(dA + x1_ * rA) mod n
	multiply(x1_, rA, tA);
	divide(tA, para_n, temp);
	add(tA, dA, tA);
	divide(tA, para_n, temp);

	//A6:验证RB，计算x2_
	if (point_at_infinity(RB) == 1)
	{
		printf("RB is at infinity!\n");
		return 0;
	}

	epoint_get(RB, x2, y2);
	big_to_bytes(32, x2, x2y2_char, 1);
	big_to_bytes(32, y2, x2y2_char + 32, 1);

	expb2(w, x2_);		//x2_ = 2^w
	divide(x2, x2_, temp);	//x2 = x2 mod x2_ = x2 & (2^w - 1)
	add(x2_, x2, x2_);
	divide(x2_, para_n, temp);  //注意这里是否需要

	//A7:计算点U，并判断是否为无穷远点
	ecurve_mult(x2_, RB, U);	//U = [x2_]RB
	epoint_get(U, Ux, Uy);

	ecurve_add(pB, U);	//U = pB +[x2_]RB
	epoint_get(U, Ux, Uy);

	multiply(para_h, tA, tA); 	//tA = tA * h 
	divide(tA, para_n, temp);   //注意这里是否需要

	ecurve_mult(tA, U, U); //U = [h * tA](PB + [x2_]RB)

	if (point_at_infinity(U) == 1)
	{
		printf("U is at infinity!\n");
		return 0;
	}
	epoint_get(U, Ux, Uy);
	big_to_bytes(32, Ux, Z, 1);
	big_to_bytes(32, Uy, Z + 32, 1);

	//A8: KDF  计算KA
	memcpy(Z + 64, ZA, 32, 1);
	memcpy(Z + 96, ZB, 32, 1);
	KDF(Z, 128, KA, 32);

	//A9:计算S1=Hash(0x02 || Uy || Hash(Ux || ZA || ZB || x1 || y1 || x2 || y2))
	shs256_init(&sha_256);
	for (i = 0; i < 32; i++)
	{
		shs256_process(&sha_256, Z[i]);
	}
	for (i = 0; i < 32; i++)
	{
		shs256_process(&sha_256, ZA[i]);
	}
	for (i = 0; i < 32; i++)
	{
		shs256_process(&sha_256, ZB[i]);
	}
	for (i = 0; i < 64; i++)
	{
		shs256_process(&sha_256, x1y1_char[i]);
	}
	for (i = 0; i < 64; i++)
	{
		shs256_process(&sha_256, x2y2_char[i]);
	}
	shs256_hash(&sha_256, hash);


	shs256_init(&sha_256);
	shs256_process(&sha_256, fr[0]);  //Hash(0x02)
	for (i = 0; i < 32; i++)
	{
		shs256_process(&sha_256, Z[i + 32]);//Hash(0x02 || Uy)
	}
	for (i = 0; i < 32; i++)
	{
		shs256_process(&sha_256, hash[i]);//Hash(0x02 || Uy|| Hash(xU || ZA || ZB || x1 || y1 || x2 || y2)))
	}
	shs256_hash(&sha_256, S1);

	if (memcmp(S1, SB, 32) != 0)
	{
		printf("B->A,Failed!S1 ！= SB\n");
		return 0;
	}

	//A10: 计算SA= Hash(0x03 || yU || Hash(xU || ZA || ZB || x1 || y1 || x2 || y2))
	printf("B->A,Success!\n");
	shs256_init(&sha_256);
	
	shs256_process(&sha_256, fr[1]); //hash(0x03)
	for (i = 0; i < 32; i++)
	{
		shs256_process(&sha_256, Z[i + 32]);//Hash(0x03 || Uy)
	}
	for (i = 0; i < 32; i++)
	{
		shs256_process(&sha_256, hash[i]);//Hash(0x03|| Uy|| Hash(xU || ZA || ZB || x1 || y1 || x2 || y2)))
	}
	shs256_hash(&sha_256, SA);
	return 1;//成功返回1
}


int B2(epoint* V,epoint*RA,epoint*RB, unsigned char ZA[], unsigned char ZB[], unsigned char SA[])
{
	// B10:计算S2=Hash(0x03 || Vy || Hash(Vx || ZA || ZB || x1 || y1 || x2 || y2))
	unsigned char fr[1] = { 0x03 };
	unsigned char x1y1_char[64] = { 0 };
	unsigned char x2y2_char[64] = { 0 };
	unsigned char Vxy_char[64] = { 0 };
	unsigned char hash[32] = { 0 };
	unsigned char S2[64] = { 0 };
	
	int i = 0;
	big x1, y1, x2, y2,Vx,Vy;
	x1 = mirvar(0);
	y1 = mirvar(0);
	x2 = mirvar(0);
	y2 = mirvar(0);
	Vx = mirvar(0);
	Vy = mirvar(0);

	epoint_get(RA, x1, y1);
	epoint_get(RB, x2, y2);
	epoint_get(V, Vx, Vy);

	big_to_bytes(32, Vx, Vxy_char, 1);
	big_to_bytes(32, Vy, Vxy_char+32, 1);
	big_to_bytes(32, x1, x1y1_char, 1);
	big_to_bytes(32, y1, x1y1_char + 32, 1);
	big_to_bytes(32, x2, x2y2_char, 1);
	big_to_bytes(32, y2, x2y2_char +32, 1);

	sha256  sha_256;
	shs256_init(&sha_256);
	for (i = 0; i < 32; i++)
	{
		shs256_process(&sha_256, Vxy_char[i]);  //Hash(Vx)
	}
	for (i = 0; i < 32; i++)
	{
		shs256_process(&sha_256, ZA[i]);  //Hash(Vx||ZA)
	}
	for (i = 0; i < 32; i++)
	{
		shs256_process(&sha_256, ZA[i]);  //Hash(Vx||ZA||ZB)
	}
	for (i = 0; i < 64; i++)
	{
		shs256_process(&sha_256, x1y1_char[i]);  //Hash(Vx||ZA||x1||y1)
	}
	for (i = 0; i < 64; i++)
	{
		shs256_process(&sha_256, x2y2_char[i]);  //Hash(Vx||ZA||x1||y1||x2||y2)
	}
	shs256_hash(&sha_256, hash);

	shs256_init(&sha_256);
	shs256_process(&sha_256, fr[0]);  //Hash(0x03)
	for (i = 0; i < 32; i++)
	{
		shs256_process(&sha_256, Vxy_char[i+32]);  //Hash(0x03||Vy)
	}
	for (i = 0; i < 32; i++)
	{
		shs256_process(&sha_256, hash[i]);  //Hash(0x03||VyHash(Vx || ZA || ZB || x1 || y1 || x2 || y2))
	}
	shs256_hash(&sha_256, S2);

	if (memcmp(S2, SA, 32) != 0)
	{
		printf("A->B,Failed!\n");
		return 0;
	}
	printf("A->B,Success!\n");
	return 1;//成功返回1
}
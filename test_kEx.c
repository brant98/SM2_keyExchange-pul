#include"SM2.h"
#include"miracl.h"
int test_kEx(void)
{
	unsigned char IDA[16] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };//用户可辩别标识IDA=1234567812345678
	unsigned char IDB[16] = { 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32 };//用户可辩别标识IDB=8765432198765432
	unsigned char K[32] = {0};
	unsigned char hash[32] = { 0 };
	unsigned char ZA[32] = { 0 };
	unsigned char ZB[32] = { 0 };
	unsigned char KA[32] = { 0 };

	epoint* RA,*RB,*pA,*pB;  //公钥
	big rA,rB,dA, dB;
	
	SM2_init();//椭圆曲线初始化
	SM2_creat_key(&dA, &pA); //创建AB的公、私钥
	SM2_creat_key(&dB, &pB);
	
	//计算RA 
	cal_RA_RB(&RA, &rA);
	cal_RA_RB(&RB,&rB);

	SM2_ZA(pA, IDA, ZA);//计算用户A、B的标识
	SM2_ZA(pB, IDB, ZB);

	//发起者   K中放的SB
	B1(RA, RB, pA, pB, dB, rB, IDA, IDB, K, hash);
	A2(RA, rA, dA, RB, pB, ZA, ZB, KA, K);

	return 1;//返回1表示成功
}
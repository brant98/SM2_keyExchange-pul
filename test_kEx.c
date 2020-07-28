#include"SM2.h"
#include"miracl.h"
int test_kEx(void)
{
	epoint* RA,*RB,*pA,*pB;  //公钥
	RA = epoint_init();
	RB = epoint_init();
	pA = epoint_init();
	pB = epoint_init();
	unsigned char IDA[16] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };//用户可辩别标识IDA=1234567812345678
	unsigned char IDB[16] = { 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32 };//用户可辩别标识IDB=8765432198765432
	unsigned char K[32] = {0};
	unsigned char hash[32];
	SM2_init();//椭圆曲线初始化
	big rA,rB,dA, dB;
	dA = mirvar(0);
	dB = mirvar(0);
	SM2_creat_key(&dA, &pA);
	SM2_creat_key(&dB, &pB);
	//计算RA 
	cal_RA_RB(&RA,&rA);
	
	//A：发起者
	B1(RA, RB, pA, pB, dB, &rB, IDA, IDB, K, hash);

	return 1;//返回1表示成功
}
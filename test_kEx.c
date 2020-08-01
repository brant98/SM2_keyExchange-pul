#include<time.h>
#include"SM2.h"
#include"miracl.h"
int test_kEx(void)
{
	unsigned char IDA[16] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };//用户可辩别标识IDA=1234567812345678
	unsigned char IDB[16] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };//用户可辩别标识IDB=1234567812345678
	//unsigned char IDB[16] = { 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32 };//用户可辩别标识IDB=8765432198765432
	unsigned char KB[32] = {0};
	unsigned char SA[32] = { 0 };
	unsigned char SB[32] = { 0 };
	unsigned char ZA[32] = { 0 };
	unsigned char ZB[32] = { 0 };
	unsigned char KA[32] = { 0 };
	int i = 0;
	epoint* RA,*RB,*pA,*pB,*V;  //公钥
	big rA,rB,dA, dB;
	clock_t start, finish;//计算运行时间用
	start = clock();
	SM2_init();//椭圆曲线初始化
	SM2_creat_key(&dA, &pA); //创建AB的公、私钥
	SM2_creat_key(&dB, &pB);
	
	
	//计算RA  RB rA rB
	

	cal_RA_RB(&RA, &rA);
	cal_RA_RB(&RB,&rB);

	//计算ZA ZB
	SM2_ZA(pA, IDA, ZA);//计算用户A、B的标识
	SM2_ZA(pB, IDB, ZB);

	//发起者   hash中放的SB
	for (i = 0; i < 1000; i++)
	{
	B1(&V,RA, RB, pA, pB, dB, rB, ZA, ZB, KB, SB);
	A2(RA, rA, dA, RB, pB, ZA, ZB, KA, SB,SA);
	B2(V, RA, RB, ZA, ZB, SA);

	}



	
	finish = clock();
	printf("Test of this algorithm finished\n");
	printf("Start at  %f s\n", (double)start / CLOCKS_PER_SEC);
	printf("End at %f s\n", (double)finish / CLOCKS_PER_SEC);
	printf("1000 times tests  used %f seconds in total.\n", (double)difftime(finish, start) / CLOCKS_PER_SEC);
	printf("The algorithm runs once used %f seconds on average.\n", (double)difftime(finish, start) / CLOCKS_PER_SEC / 1000);
	return 1;//返回1表示成功
}
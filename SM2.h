#include"miracl.h"
int SM2_init(void);//椭圆曲线
int isInRange(big num);//判断d是否在规定范围内  1至n-1的闭区间
int SM2_creat_key(big* d, epoint** pub);     //生成公、私钥
int KDF(unsigned char Z[], int zlen, unsigned char K[], int klen);   //密钥派生函数
int pointIsOn(epoint* point);

void SM2_ZA(epoint* A, unsigned char IDA[], unsigned char ZA[]);//生成用户标识
int cal_RA_RB(epoint** RA, big* rA);
int B1(epoint** V,epoint* RA, epoint* RB, epoint* pA, epoint* pB, big dB, big  rB, unsigned char ZA[], unsigned char ZB[], unsigned char K[], unsigned char hash[]);
int A2(epoint* RA, big rA, big dA, epoint* RB, epoint* pB, unsigned char ZA[], unsigned char ZB[], unsigned char KA[], unsigned char SB[], unsigned char SA[]);
int B2(epoint* V, epoint* RA, epoint* RB, unsigned char ZA[], unsigned char ZB[], unsigned char SA[]);
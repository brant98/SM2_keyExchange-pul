#include"miracl.h"
int SM2_init(void);//��Բ����
int isInRange(big num);//�ж�d�Ƿ��ڹ涨��Χ��  1��n-1�ı�����
int SM2_creat_key(big* d, epoint** pub);     //���ɹ���˽Կ
int KDF(unsigned char Z[], int zlen, unsigned char K[], int klen);   //��Կ��������
int pointIsOn(epoint* point);

void SM2_ZA(epoint* A, unsigned char IDA[], unsigned char ZA[]);//�����û���ʶ
int cal_RA_RB(epoint** RA, big* rA);
int B1(epoint** V,epoint* RA, epoint* RB, epoint* pA, epoint* pB, big dB, big  rB, unsigned char ZA[], unsigned char ZB[], unsigned char K[], unsigned char hash[]);
int A2(epoint* RA, big rA, big dA, epoint* RB, epoint* pB, unsigned char ZA[], unsigned char ZB[], unsigned char KA[], unsigned char SB[], unsigned char SA[]);
int B2(epoint* V, epoint* RA, epoint* RB, unsigned char ZA[], unsigned char ZB[], unsigned char SA[]);
#include"SM2.h"
#include"miracl.h"
int test_kEx(void)
{
	unsigned char IDA[16] = { 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38 };//�û��ɱ���ʶIDA=1234567812345678
	unsigned char IDB[16] = { 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32 };//�û��ɱ���ʶIDB=8765432198765432
	unsigned char K[32] = {0};
	unsigned char hash[32];
	epoint* RA,*RB,*pA,*pB;  //��Կ
	/*RA = epoint_init();
	RB = epoint_init();
	pA = epoint_init();
	pB = epoint_init();*/
	big rA,rB,dA, dB;
	
	SM2_init();//��Բ���߳�ʼ��
	SM2_creat_key(&dA, &pA); //����AB�Ĺ���˽Կ
	SM2_creat_key(&dB, &pB);
	//����RA 
	cal_RA_RB(&RA, &rA);
	cal_RA_RB(&RB,&rB);
	//A��������
	B1(RA, RB, pA, pB, dB, rB, IDA, IDB, K, hash);

	return 1;//����1��ʾ�ɹ�
}
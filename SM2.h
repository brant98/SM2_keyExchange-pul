#include"miracl.h"
int SM2_init(void);//��Բ����
int isInRange(big num);//�ж�d�Ƿ��ڹ涨��Χ��  1��n-1�ı�����
int SM2_creat_key(big* d, epoint** pub);     //���ɹ���˽Կ
int KDF(unsigned char Z[], int zlen, unsigned char K[], int klen);   //��Կ��������

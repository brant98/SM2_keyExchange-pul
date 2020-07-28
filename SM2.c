#include <stdio.h>
#include <time.h>
#include<string.h>
#include "miracl.h"
#include"mirdef.h"
#include "SM2.h"
// ECC��Բ���߲�����SM2��׼�Ƽ�������
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
���ܣ�SM2ǩ���㷨��Բ���߲�����ʼ��
���룺��
�������
���أ�0ʧ��  1�ɹ�
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
	//bytes_to_big(256, SM2_h, para_h);

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
	return 1;             //�ɹ����е�����򷵻�1.�����ص���0���ʾ��ʼ������ȷ
}
int isInRange(big num) //�ж�d�Ƿ��ڹ涨��Χ��  1��n-1�ı�����
{
	big one, decr_n;
	one = mirvar(0);
	decr_n = mirvar(0);

	convert(1, one);
	decr(para_n, 1, decr_n);

	if ((mr_compare(num, one) > 0) && (mr_compare(num, decr_n) < 0))//compare(x,y)  x>y +1   x=y 0  x<y -1
		return 1;//����1��ʾ���ʺϷ�Χ
	return 0;//����0��ʾ�����ʺϵķ�Χ
}
int SM2_creat_key(big* d, epoint** pub)
{

	*d = mirvar(0);
	*pub = epoint_init();
	irand(time(NULL));
	bigrand(para_n, *d);  // d˽Կ dӦ��1��n-2֮�䣬��������
	while (isInRange(*d) != 1)
	{
		bigrand(para_n, *d);
	}
	ecurve_mult(*d, G, *pub);//pub�д�Ź�Կ
	printf("creat key done!\n");
	return 1; //�ɹ�����1
}
/*
KDF��Կ��������
 key derivation function
*Z�Ǳ��ش���klen��ʾҪ��õ���Կ���ݵı��س���
*k�Ǵ������ģ�z������
*/
int KDF(unsigned char Z[], int zlen, unsigned char K[], int klen)
{
	int  i, j = 0, t;
	int bit_klen;
	unsigned char Ha[32] = { 0 }; //ժҪ ���䳤��Ϊ32
	unsigned char ct[4] = { 0,0,0,1 };

	bit_klen = klen * 8;//�ж���λ  Ҳ�������ֽڡ�
	sha256 sha_256;

	if (bit_klen % 256)
		t = bit_klen / 256 + 1;
	else
		t = bit_klen / 256;
	//K= Ha1 || Ha2 || ...
	for (i = 1; i < t; i++)//��Ϊ������i-1  �����һ��HaҪ������
	{
		//Ha1=Hv(Z|| ct )
		shs256_init(&sha_256);
		for (j = 0; j < zlen; j++)
			shs256_process(&sha_256, Z[j]);
		for (j = 0; j < 4; j++)
			shs256_process(&sha_256, ct[j]);
		shs256_hash(&sha_256, Ha);

		memcpy((K + 32 * (i - 1)), Ha, 32);

		//ct++  ע���λ,��С��
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

	//��klen/v������
	if (bit_klen % 256) //�����ֽ��ܷ�32����
	{
		j = klen - 32 * (klen / 32);
		memcpy((K + 32 * (t - 1)), Ha, j);
	}
	else
	{
		memcpy((K + 32 * (t - 1)), Ha, 32);
	}
	return 1;//����1�ɹ�
}
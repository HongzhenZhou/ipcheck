
/*
 * ^tcpopt.c
 * */

#include <windows.h>

#include "pcap.h"
#include "Packet32.h"
#include "Ntddndis.h"

#include "pub.h"
#include "misc.h"
#include "tcpopt.h"

int do_tcpopt(struct sf_task *task, unsigned char *buf, unsigned int pad)
{
	unsigned int ipl = 0, iphl = 0x14, len = 0;
	unsigned char *ip = buf + 14 + pad, ipla[2];
       	unsigned char tcphl = 0;
       	unsigned char *tcp = ip + 20;
	DWORD arpip = (task->hop[3] << 24) + (task->hop[2] << 16) +
		(task->hop[1] << 8) + task->hop[0];
	int ind, i; 
	signed int n;

	for (ind = 0; ; ind++) {
		if (100 < ind) 
			ind = 0;

		switch (WaitForSingleObject(task->stop, 0)) {
		case WAIT_TIMEOUT:
			win_ndebug("timeout");
			break;
		case WAIT_OBJECT_0:
			win_ndebug("WAIT_OBJECT_0");
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

		do { 
			ip[2] = (0x05 * rand()) / RAND_MAX;
			ip[3] = (0xff * rand()) / RAND_MAX;
			tcphl = (0xfc * rand()) / RAND_MAX;
			if (0x05 == ip[2] && 0xdc < ip[3])
				ip[3] = 0xdc;
			ip[3] &= 0xfc;
			ipla[0] = ip[2];
			ipla[1] = ip[3];
			ipl = (ip[2] << 8) + ip[3];
		} while (ipl < 44 || tcphl < 24 || tcphl > 60 || ipl < tcphl + 20);

		len = 14 + pad + ipl;

		for (i = 0; ipl > i; i++)
			ip[i] = (0xff * rand()) / RAND_MAX;

		ip[0] = 0x45;
		ip[1] &= 0xfc;
		ip[2] = ipla[0];
		ip[3] = ipla[1];
		ip[6] &= 0x00/*0x7f*/;
		ip[7] = 0x00;
		ip[9] = 0x06;

		if (task->fake) {
			ip[12] = (task->lnet[0] | (task->rmark[0] & ip[12]));
			ip[13] = (task->lnet[1] | (task->rmark[1] & ip[13]));
			ip[14] = (task->lnet[2] | (task->rmark[2] & ip[14]));
			ip[15] = (task->lnet[3] | (task->rmark[3] & ip[15]));
		} else
			memcpy(ip + 12, task->lip, 4);

		memcpy(ip + 16, task->dip, 4);

		if ((task->dport[0] || task->dport[1]) && (ipl - iphl > 20)) {
			tcp[2] = task->dport[0];
			tcp[3] = task->dport[1];
		}

		tcp[12] = (tcphl << 2);

		switch (ind % 14) {
		case 0:
			ip[1] = (0xff * rand()) / RAND_MAX;
			break;
		case 1: case 2: 
			for (i = 0; tcphl - 20 > i; i++)
				tcp[0x14 + i] = (0x20 * rand()) / RAND_MAX;
			tcp[18] = 0x00;
			tcp[19] = 0x00;
		default:
			tcp[18] = 0x00;
			tcp[19] = 0x00;
			tcp[13] = 0x02;
			break;
		case 5: case 6:
			tcp[13] = 0x22;
			break;
		case 7:
			tcp[13] = 0x04;
			tcp[18] = 0x00;
			tcp[19] = 0x00;
			break;
		case 10:
			tcp[13] = 0x24;
			break;
		}

		do_csum(ip, ip + 10, iphl, ip + iphl, ip + iphl + 16, 
			ipl - iphl, 1);

		if (0 >= (n = spy_kernel(task, buf, len, arpip)))
			return abs(n);
	}
}

/*
 * tcpopt.c$
 * */


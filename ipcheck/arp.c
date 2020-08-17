
/*
 * ^arp.c
 * */

#include <windows.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <stdlib.h>

#include "pcap.h"
#include "Packet32.h"
#include "Ntddndis.h"

#include "pub.h"
#include "arp.h"

const unsigned char broadmac[6] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

const unsigned char arpq_type_10[10] = {
	0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01
};

const unsigned char arpp_type_10[10] = {
	0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02
};

static int man_arp(struct sf_task *task, unsigned char *buf, unsigned int pad) 
{
	unsigned char *pbuf = 0;
	struct pcap_pkthdr *pph = 0;
	int i = 0, j, ret = 1;
	unsigned char tmp1[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	unsigned char tmp2[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

#ifdef DO_DEBUG
	if (0 == task)
		win_return("send_arp_req(): 0 == task!", 1);

	if (0 == buf)
		win_return("send_arp_req(): 0 == buf!", 1);

	if (0 == task->hwnd)
		win_return("send_arp_req(): 0 == task->hwnd!", 1);

	if (0 == task->f)
	       win_return("send_arp_req(): 0 == task->f!", 1);	
#endif /* DO_DEBUG */

again:
	if (pcap_sendpacket(task->f, buf, 60)) {
		win_debug("pcap_sendpacket() failed!");
		return 1;
	}

	switch (pcap_next_ex(task->f, &pph, &pbuf)) {
	case 1:
		if (0 == pph || 0 == pbuf) {
			win_debug("0 == pph || 0 == pbuf");
			break;
		}

		if (60 != pph->caplen) 
			break;

		if (memcmp(pbuf + 6, pbuf + 22 + pad, 6)) 
			break;

		if (pad) {
			if (0x81 != buf[12] || 0x00 != buf[13] ||
				buf[14] != (0x0f & task->dport[0]) ||
				buf[15] != task->dport[1])
				break;
		}

		if (memcmp(arpp_type_10, pbuf + 12 + pad, 10)) 
			break;

		if (0 == memcmp(pbuf + 22 + pad, tmp1, 6)) 
			break;

		if (0 == memcmp(pbuf + 22 + pad, tmp2, 6)) 
			break;

		if (memcmp(task->hop, pbuf + 28 + pad, 4)) 
			break;

		if (memcmp(task->lip, pbuf + 38 + pad, 4)) 
			break;

		if (memcmp(task->lmac, pbuf + 32 + pad, 6)) 
			break;

		if (memcmp(pbuf, pbuf + 32 + pad, 4)) 
			break;

		memcpy(task->dmac, pbuf + 6, 6);

		win_ndebug("OK");
		return 0;
	case 0:
		i++;
		win_debug("TIMEOUT");
		break;
	case -1:
		win_exit(task->hwnd, "man_arp:-1 == pcap_next_ex()", 1);
	case -2:
		win_error("man_arp(): -2 == pcap_next_ex()");
	default:
		win_error("man_arp(): default == pcap_next_ex()");
		return 2;
	}

	if (5 > i)
		goto again;

	return 1;
}

int get_mac(struct sf_task *task)
{
	unsigned char buf[60];
	unsigned char tmp[32];
	unsigned int mask = 0xffffffff;
	unsigned int pad = 0;
	struct bpf_program fp;
	unsigned char *p = 0;
	int i;

#ifdef DO_DEBUG
	if (0 == task)
		win_return("get_mac(): 0 == task!", 1);

	if (0 == task->hwnd)
		win_return("get_mac(): 0 == task->hwnd!", 1);

	if (0 == task->f)
		win_exit(task->hwnd, "get_mac(): 0 == task->f!", 1);
#endif /* DO_DEBUG */

	if (1 == task->lan && 1 == task->broad) {
		win_ndebug("broad lan");
		memset(task->dmac, 0xff, 6);
		return 0;
	}

	snprintf(tmp, 31, "arp dst host %d.%d.%d.%d", 
		task->lip[0], task->lip[1], task->lip[2], task->lip[3]);
	win_ndebug(tmp);

	if (0 > pcap_compile(task->f, &fp, tmp, 1, mask)) 
		win_exit(task->hwnd, "pcap_compile() arp failed!", 1);

	if (0 > pcap_setfilter(task->f, &fp)) {
		pcap_freecode(&fp);
		win_exit(task->hwnd, "pcap_setfilter() failed!", 1);
	}

	if (TYPE_VRAND == task->type || TYPE_VUNIA == task->type) 
		pad = 4;

	memset(buf, 0, 60);

	memcpy(buf, broadmac, 6);

	memcpy(buf + 6, task->lmac, 6);
	if (pad) {
		buf[12] = 0x81;
		buf[13] = 0x00;
		buf[14] = (0x0f & task->dport[0]);
		buf[15] = task->dport[1];
	}
	memcpy(buf + 12 + pad, arpq_type_10, 10);
	memcpy(buf + 22 + pad, task->lmac, 6);
	memcpy(buf + 28 + pad, task->lip, 4);
	memset(buf + 32 + pad, 0, 6);
	memcpy(buf + 38 + pad, task->hop, 4);

#if 0
	{
#define BUF_SIZE_L 32
		unsigned char *p1, *p2;
		unsigned char errbuf[BUF_SIZE_L];

		snprintf(errbuf, BUF_SIZE_L, "NONE: %d.%d.%d.%d\r\n"
			"-> %d.%d.%d.%d\r\n",	
			buf[28], buf[29], buf[30], buf[31], 
			buf[38], buf[39], buf[40], buf[41]);
		win_debug(errbuf);
#undef BUF_SIZE_L
	}
#endif

	if (man_arp(task, buf, pad)) {
		pcap_freecode(&fp);
		win_dreturn("get_mac(): man_arp() failed!", 1);
	}

	pcap_freecode(&fp);

	return 0;
}

/*
 * arp.c$
 * */


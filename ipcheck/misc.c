
/*
 * ^misc.c
 * */

#include <windows.h>
#include <shellapi.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <stdlib.h>

#include "pcap.h"
#include "Packet32.h"
#include "Ntddndis.h"

#include "pub.h"
#include "misc.h"

int check_alive_3_lan(struct sf_task *task)
{
	int ret = 1, yep = 1, i, j;
	IPAddr dip, sip;
	unsigned long mac[4];
	unsigned long al = 0;
	unsigned char *p = (unsigned char *)mac; 
	DWORD r;
	unsigned char ipa[80];

	/*
	snprintf(ipa, 79, "%d.%d.%d.%d", task->hop[0], task->hop[1], 
		task->hop[2], task->hop[3]);
	dip = inet_addr(ipa);
	*/
	dip = (task->hop[3] << 24) + (task->hop[2] << 16) + 
		(task->hop[1] << 8) + task->hop[0];

	sip = (task->lip[3] << 24) + (task->lip[2] << 16) + 
		(task->lip[1] << 8) + task->lip[0];

	for (i = 0; 2 > i; i++) {
		memset(mac, 0xff, sizeof(mac));
		al = 6;

		if (NO_ERROR != (r = SendARP(dip, sip, mac, &al))) {
#ifdef DO_DEBUG
			LPVOID buf;

			FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | 
				FORMAT_MESSAGE_FROM_SYSTEM,
				0, r,
				MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
				(LPTSTR) &buf, 0, 0); 
			win_ndebug(buf);
			LocalFree(buf);

			win_ndebug("SendARP() failed");
#endif /* DO_DEBUG */
			goto out;
		}

		if (6 != al) {
			win_debug("6 != al");
			goto out;
		}

		yep = 1;

		for (j = 0; 6 > j; j++) {
			if (task->dmac[j] != p[j]) {
				win_debug("SendARP(): task->dmac[j] != p[j]");
				yep = 1;
				break;
			}
		}
	
		if (1 == yep) {
			win_ndebug("OK");
			ret = 0;
			goto out;
		}
	}
	
out:
	return ret;
}

/****************************************************************************/

int do_csum(unsigned char *ip, unsigned char *icsum, 
	unsigned short isize, unsigned char *tcp, unsigned char *tcsum, 
	unsigned short tsize, int type)
{
	unsigned short ssize = tsize;
	unsigned int sum = 0;
	unsigned char *p = 0;

	if (!(ip && icsum && isize))
		win_return("do_csum(): !(ip && icsum && isize)\n", 1);

	if (!((tcp && tcsum && tsize) || 
		(0 == tcp && 0 == tcsum && 0 == tsize)))
		win_return("do_scum() : !((tcp && tcsum && tsize) || ..)\n", 1);

	memset(icsum, 0, 2);

	p = ip;
	while(isize > 1) {
		sum += (p[0] << 8) + p[1];
		p += 2;
		isize -= 2;
	}

	if (isize) 
		sum += *p;

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	icsum[0] = (((unsigned short)(~sum)) >> 8);
	icsum[1] = ((((unsigned short)(~sum)) << 8) >> 8);

	if (0 == tcp)
		return 0;

	memset(tcsum, 0, 2);
	sum = 0;

	p = tcp;
	while (tsize > 1) {
		sum += (p[0] << 8) + p[1];
		p += 2;
		tsize -= 2;
	}

	if (type) {
		sum += (ip[12] << 8) + ip[13]; 
		sum += (ip[14] << 8) + ip[15];

		sum += (ip[16] << 8) + ip[17]; 
		sum += (ip[18] << 8) + ip[19];

		sum += ip[9];
		sum += ssize;
	}

	if (tsize)
		sum += *p;

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	tcsum[0] = (((unsigned short)(~sum)) >> 8);
	tcsum[1] = ((((unsigned short)(~sum)) << 8) >> 8);

	return 0;
}

/****************************************************************************/

void print_pkt(unsigned char *buf, unsigned int len)
{
	unsigned int i, j;
	unsigned char str[8192];
	unsigned char cmd[8250];

	for (i = 0, j = 0; i < len; i++) 
		j += sprintf(str + j, "%02X:", buf[i]);
	
	str[j] = '\0';
	win_error(str);
	
	sprintf(cmd, "echo  ");
	memcpy(cmd + 5, str, j);
	sprintf(cmd + j + 5, "  > c:\\pkt.txt");
	system(cmd);
}

/****************************************************************************/

int get_route(struct sf_task *task)
{
	SOCKET s;
	DWORD n;
	struct sockaddr_in ai;
	struct sockaddr_in ao;
	unsigned int dip;
	MIB_IPFORWARDROW mib;
	unsigned char *p;
#ifdef DO_DEBUG
	unsigned char str[32];
#endif /* DO_DEBUG */

#ifdef DO_DEBUG
	if (0 == task)
		win_return("get_route(): 0 == task!", 1);

	if (0 == task->hwnd) 
		win_return("get_route(): 0 == task->hwnd!", 1);
#endif /* DO_DEBUG */

	dip = (task->dip[3] << 24) + (task->dip[2] << 16) + 
		(task->dip[1] << 8) + task->dip[0];

	memset(&mib, 0, sizeof(MIB_IPFORWARDROW));
	memset(&ao, 0, sizeof(struct sockaddr_in));
	memset(&ai, 0, sizeof(struct sockaddr_in));
	ai.sin_family = AF_INET;
	ai.sin_addr.s_addr = dip;

	if (INVALID_SOCKET == (s = socket(AF_INET, SOCK_STREAM, 0))) {
		switch (WSAGetLastError()) {
		case WSAENETDOWN:
			win_return("Net is down!", 1);
		default:
			win_exit(task->hwnd, "INVALID_SOCKET == socket()", 1);
		}
	}
	
	if (WSAIoctl(s, SIO_ROUTING_INTERFACE_QUERY, (void *)&ai, 
		sizeof(struct sockaddr_in), (void *)&ao, 
		sizeof(struct sockaddr_in), &n, 0, 0)) {
		DWORD re = WSAGetLastError();

		switch(re) {
		case WSAENETUNREACH:
		case WSAENETDOWN:
		case WSAEHOSTUNREACH:
		case WSAEHOSTDOWN:
			closesocket(s);
			win_return("Net is unreachable!", 1);
		case WSAEFAULT:
			closesocket(s);
			win_exit(task->hwnd, "WSAEFAULT == WSAIoctl()!", 1);
		default:
			closesocket(s);
			win_exit(task->hwnd, "default == WSAIoctl()!", 1);
		}
	}

	closesocket(s);

	p = (unsigned char *)&(ao.sin_addr.s_addr);
	task->lip[0] = p[0];
	task->lip[1] = p[1];
	task->lip[2] = p[2];
	task->lip[3] = p[3];

#ifdef DO_DEBUG
	{
		unsigned char str[32];

		snprintf(str, 31, "route if: %d.%d.%d.%d", p[0], p[1], p[2], p[3]);
		win_ndebug(str);
	}
#endif /* DO_DEBUG */
					
	if (127 == p[0])
		win_return("Can NOT check yourself!", 1);

	if (NO_ERROR != GetBestRoute(dip, ao.sin_addr.s_addr, &mib))
		win_exit(task->hwnd, "GetBestRoute() failed!", 1);

	switch (mib.dwForwardType) {
	case 3:
		memcpy(task->hop, task->dip, 4);
		task->index = mib.dwForwardIfIndex;
		break;
	case 4:
		p = (unsigned char *)&(mib.dwForwardNextHop);
		task->index = mib.dwForwardIfIndex;
		task->hop[0] = p[0];
		task->hop[1] = p[1];
		task->hop[2] = p[2];
		task->hop[3] = p[3];

		break;
	case 2:
		win_exit(task->hwnd, "2 == mib.dwForwardType!", 1);
	case 1:
		win_exit(task->hwnd, "1 == mib.dwForwardType!", 1);
	default:
		win_exit(task->hwnd, "shit", 1);
	}

#ifdef DO_DEBUG
	snprintf(str, 31, "next hop: %d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	win_ndebug(str);
#endif /* DO_DEBUG */

	return 0;
}

/****************************************************************************/

int get_if(struct sf_task *task)
{
	pcap_if_t *dev = 0, *alldevs = 0;
	PACKET_OID_DATA *pod = 0;
	LPADAPTER la = 0;
	pcap_addr_t *addr = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	unsigned char *p;
	int ret = 1;
	unsigned int dip;
	unsigned int lip, hop;
	unsigned int lmark;
	int thisdev = 0, thislan = 0, first = 1;

#ifdef DO_DEBUG
	if (0 == task) 
		win_goto("get_if(): 0 == task!", out);
#endif /* DO_DEBUG */

	task->f = 0;

	if (-1 == pcap_findalldevs(&alldevs, errbuf)) 
		win_goto("-1 == pcap_findalldevs()!", out);

angle:
	for (dev = alldevs; dev; dev = dev->next) {
		if (0 == dev->name)
			continue;

#if 0
		if (0 == (task->f = pcap_open(dev->name, 1500, 
			0/*PCAP_OPENFLAG_PROMISCUOUS*/, 1000, 0, errbuf))) 
			win_goto("0 == pcap_open()!", zero);
#else
		if (0 == (task->f = pcap_open_live(dev->name, 1500, 
			0/*PCAP_OPENFLAG_PROMISCUOUS*/, 1000, errbuf))) 
			win_goto("0 == pcap_open()!", zero);
#endif

		if (DLT_EN10MB != pcap_datalink(task->f)) {
			pcap_close(task->f);
			task->f = 0;
			continue;
		}

		thisdev = 0;
		thislan = 0;

kill:
		for (addr = dev->addresses; addr; addr = addr->next) {
			if (0 == addr->addr || 0 == addr->netmask ||
				AF_INET != addr->addr->sa_family) 
				break;

			lip = ((struct sockaddr_in *)(addr->addr))
				->sin_addr.s_addr & 
				((struct sockaddr_in *)(addr->netmask))
				->sin_addr.s_addr;

			dip = ((task->dip[3] << 24) + (task->dip[2] << 16) +
				(task->dip[1] << 8) + task->dip[0]) &
				((struct sockaddr_in *)(addr->netmask))
				->sin_addr.s_addr;

			hop = ((task->hop[3] << 24) + (task->hop[2] << 16) +
				(task->hop[1] << 8) + task->hop[0]) &
				((struct sockaddr_in *)(addr->netmask))
				->sin_addr.s_addr;

			if (lip == dip) {
				thislan = 1;
				win_debug("host on lan!");
#if 0
				memcpy(task->hop, task->dip, 4);
#endif
			} else {
				if (lip == hop)
					thislan = 1;
				win_debug("remote host!");
			}

			p = (unsigned char *)&(((struct sockaddr_in *)
				(addr->addr))->sin_addr.s_addr);

#ifdef DO_DEBUG
			{
				unsigned char str[32];

				snprintf(str, 31, "%d.%d.%d.%d", 
					p[0], p[1], p[2], p[3]);
				win_debug(str);
			}
#endif /* DO_DEBUG */
					
			if (p[0] != task->lip[0] || 
				p[1] != task->lip[1] ||
				p[2] != task->lip[2] || 
				p[3] != task->lip[3]) {
				if (lip != dip && lip != hop) {
					win_debug("not lan, continue");
					continue;
				} else if (0 == thisdev) {
					win_debug("lan, but not this dev");
					continue;
				} else {
					task->lip[0] = p[0];
					task->lip[1] = p[1];
					task->lip[2] = p[2];
					task->lip[3] = p[3];

					win_debug("lan, not this ip, copy ok");
				}
			} else {
				thisdev = 1;

				if (lip == dip || lip == hop)
					;
				else if (1 == thislan) {
					win_debug("thislan, goto kill");
					goto kill;
				} else if (0 == thislan && first) {
					win_debug("first, continue");
					continue;
				}
			}

			win_debug("ok");

			pod = (PACKET_OID_DATA *)errbuf;
			pod->Oid = OID_802_3_CURRENT_ADDRESS;
			pod->Length = PCAP_ERRBUF_SIZE;

			if (0 == (la = PacketOpenAdapter(dev->name))) 
				win_goto("PacketOpenAdapter() failed!", one);

			if (FALSE == PacketRequest(la, FALSE, pod)) 
				win_goto("PacketRequest() failed!", two);
						
			p = (unsigned char *)&(((struct sockaddr_in *)
				(addr->netmask))->sin_addr.s_addr);
			task->lnet[0] = (task->lip[0] & p[0]);
			task->lnet[1] = (task->lip[1] & p[1]);
			task->lnet[2] = (task->lip[2] & p[2]);
			task->lnet[3] = (task->lip[3] & p[3]);
			task->rmark[0] = ~p[0];
			task->rmark[1] = ~p[1];
			task->rmark[2] = ~p[2];
			task->rmark[3] = ~p[3];

			if (lip == dip) {
				task->lan = 1;

				if (addr->broadaddr) {
					unsigned int daddr;
					unsigned int baddr;
					unsigned int taddr;

					daddr = (task->dip[3] << 24) + 
						(task->dip[2] << 16) +
						(task->dip[1] << 8) + 
						task->dip[0];

					taddr = ((struct sockaddr_in *)
						(addr->addr))
						->sin_addr.s_addr & 
						((struct sockaddr_in *)
						 (addr->netmask))
						->sin_addr.s_addr;

					baddr =	~(((struct sockaddr_in *)
						 (addr->netmask))
						->sin_addr.s_addr);

					baddr |= taddr;

					if (daddr == baddr)
						task->broad = 1;

					win_ndebug("broad addr");
				}
			}

			memcpy(task->lmac, pod->Data, 6);

			PacketCloseAdapter(la);

			ret = 0;

			goto zero;
		}

		pcap_close(task->f);
		task->f = 0;
	}

	if (ret && 1 == first) {
		first = 0;
		goto angle;
	}

two:
	if (la) 
		PacketCloseAdapter(la);

one:
	if (task->f) {
		pcap_close(task->f);
		task->f = 0;
	}

zero:
	if (alldevs) 
		pcap_freealldevs(alldevs);

out:
	return ret;
}

/****************************************************************************/

signed int spy_kernel(struct sf_task *task, unsigned char *buf, 
	unsigned int len, DWORD arpip)
{
	win_ndebug("before");
	pcap_sendpacket(task->f, buf, len); 
	win_ndebug("after");

	if (0 == isnot_admin && 1 == task->lan && 1 != task->broad) {
		int i = 0;

		win_ndebug("sky_kernel() for");

		for (i = 0; 3 > i; i++) {
			if (0 == check_alive_3_lan(task)) {
				MIB_IPNETROW minr;

				memset(&minr, 0, sizeof(MIB_IPNETROW));
				minr.dwIndex = task->index;
				minr.dwAddr = arpip;
				DeleteIpNetEntry(&minr);

				break;
			} else {
				switch (WaitForSingleObject(task->stop, 1000)) {
				case WAIT_TIMEOUT:
					break;
				case WAIT_OBJECT_0:
					win_ndebug("WAIT_OBJECT_0");
					return 0;
				default:
					win_error("case default!");
					return -1;
				}
			}
		}

		if (3 <= i) {
			unsigned char str[65];

			snprintf(str, 31, "%d.%d.%d.%d maybe DOWN!", 
				task->hop[0], task->hop[1], 
				task->hop[2], task->hop[3]);
			win_error(str);

			if (1 == task->print)
				print_pkt(buf, len);

			return 0;
		}
	}

	return 1;
}

/*
 * misc.c$
 * */


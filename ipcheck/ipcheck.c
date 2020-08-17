
/*
 * ^ipcheck.c
 * */

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <shellapi.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <stdlib.h>

#include "resource.h"

#include "pcap.h"
#include "Packet32.h"
#include "Ntddndis.h"

#include "pub.h"
#include "misc.h"
#include "arp.h"
#include "rand.h"
#include "ipopt.h"
#include "tcpopt.h"
#include "frag.h"

enum {
	WM_SF_END=WM_USER + 100,
	WM_SF_TOOLBAR
};

signed int isnot_admin = 1;

/****************************************************************************/

static DWORD WINAPI do_check(LPVOID param)
{
	DWORD ret = 1;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct sf_task *task = (struct sf_task *)param;
	unsigned char buf[2000];
	unsigned char *p, mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	unsigned int len = 0x3c;

#ifdef DO_DEBUG
	if (0 == task) 
		win_goto("do_check(): 0 == task!", out);

	if (0 == task->hwnd) 
		win_goto("do_check(): 0 == task->hwnd!", out);

	if (0 == task->stop)
		win_goto("do_check(): 0 == task->stop!", zero);

	if (0 == task->f)
		win_goto("do_check(): 0 == task->f!", zero);
#endif /* DO_DEBUG */

	pcap_setnonblock(task->f, 0, errbuf);

	/*
	if (0 == task->dport[0] && 0 == task->dport[1] && 
		TYPE_TCPOPT == task->type)
		win_goto("do_check(): 0 == dport && tcpopt == type!", one);
	*/

	if (0 == task->dip[0] && 0 == task->dip[1] && 
		0 == task->dip[2] && 0 == task->dip[3]) 
		win_goto("do_check(): 0 == dip!", one);

#ifdef DO_DEBUG 
	if (0 == task->lip[0] && 0 == task->lip[1] && 
		0 == task->lip[2] && 0 == task->lip[3]) 
		win_goto("do_check(): 0 == lip!", one);

	if (0 == task->lnet[0] && 0 == task->lnet[1] && 
		0 == task->lnet[2] && 0 == task->lnet[3]) 
		win_goto("do_check(): 0 == lnet!", one);

	if (0 == task->rmark[0] && 0 == task->rmark[1] && 
		0 == task->rmark[2] && 0 == task->rmark[3]) 
		win_goto("do_check(): 0 == rmark!", one);

	if (0 == task->lmac[0] && 0 == task->lmac[1] && 0 == task->lmac[2] &&
		0 == task->lmac[3] && 0 == task->lmac[4] && 0 == task->lmac[5]) 
		win_goto("do_check(): 0 == lmac!", one);
#endif /* DO_DEBUG */

	if (0 == task->dmac[0] && 0 == task->dmac[1] && 0 == task->dmac[2] &&
		0 == task->dmac[3] && 0 == task->dmac[4] && 0 == task->dmac[5]) 
		win_goto("do_check(): 0 == dmac!", one);

	memset(buf, 0, sizeof(buf));
	memcpy(buf, task->dmac, 6);
	buf[6] = 0x00;
	buf[7] = 0x01;
	buf[12] = 0x08;
	buf[13] = 0x00;

	if (0 == task->fake) {
		memcpy(buf + 6, task->lmac, 6);
		memcpy(buf + 14 + 12 + 
			((TYPE_VRAND == task->type || 
			TYPE_VUNIA == task->type) ?
			4 : 0), task->lip, 4);
	}

#if 0
	if (memcmp(task->smac, mac, 6)) {
		memcpy(buf + 6, task->smac, 6); /* source mac */
		fake = 0;
	}
#endif

	srand((unsigned int)time(0));

	switch (WaitForSingleObject(task->stop,  (4000 * rand()) / RAND_MAX +
		1000 * (((unsigned int)GetCurrentProcessId()) % 4) +
		1000 * (((unsigned int)GetCurrentThreadId()) % 3))) {
	case WAIT_TIMEOUT:
		break;
	case WAIT_OBJECT_0:
		win_ndebug("WAIT_OBJECT_0");
		goto two;
	default:
		win_error("case default!");
		goto one;
	}

	switch (task->type) {
	case TYPE_RAND:
	case TYPE_UNIT:
	case TYPE_UNIU:
	case TYPE_UNII:
	case TYPE_UNIA:
	case TYPE_UNIO:
		if (do_rand(task, buf, 0))
			goto one;
		break;
	case TYPE_VRAND:
	case TYPE_VUNIA:
		buf[12] = 0x81;
		buf[13] = 0x00;
		buf[14] = (0x0f & task->dport[0]);
		buf[15] = task->dport[1];
		buf[16] = 0x08;
		buf[17] = 0x00;
		if (do_rand(task, buf, 4))
			goto one;
		break;
	case TYPE_FRAG:
		do_frag(task, buf, 0);
		break;
	case TYPE_IPOPT:
	case TYPE_IPOPT_ICMP:
#if 0
	case TYPE_IPOPT_UDP:
#endif
		do_ipopt(task, buf, 0, task->type);
		break;
	case TYPE_TCPOPT:
		do_tcpopt(task, buf, 0);
		break;
	default:
		win_debug("do_check(): type unknown\n");
		break;
	}

two:
	ret = 0;

one:
half:
	if (task->f) {
		/*
		pcap_setnonblock(task->f, 0, errbuf);
		*/
		pcap_close(task->f);
	}

zero:
	if (0 == SendNotifyMessage(task->hwnd, WM_SF_END, 0, (LPARAM)ret)) {
		win_error("SendNotifyMessage() failed!");
		ExitProcess(3); /* FIXME */
	}

out:
	return ret;
}

/****************************************************************************/

static int get_ip(struct sf_task *task)
{
	HWND dip_wd, dport_wd, type_wd, smac_wd;
	unsigned int dip;
	unsigned char addr[161], *p;
	int i = 0, n;
	unsigned int dport;
	unsigned int type;

#ifdef DO_DEBUG 
	if (0 == task)
		win_return("get_ip(): 0 == task!", 1);

	if (0 == task->hwnd) 
		win_return("get_ip(): 0 == task->hwnd!", 1);
#endif /* DO_DEBUG */

	/* dip */
	if (0 == (dip_wd = GetDlgItem(task->hwnd, IDC_DIP)))
		win_exit(task->hwnd, "0 == GetDlgItem(DIP)!", 1);

	if (0 == (n = GetWindowText(dip_wd, addr, 80))) {
		if (ERROR_SUCCESS == GetLastError()) 
			win_return("dip can NOT be NULL", 1);

		win_exit(task->hwnd, "0 == GetWindowText(IDC_DIP)!", 1);
	}

	addr[160] = '\0';
	if (INADDR_NONE	== (dip = inet_addr(addr)))
		win_return("Dest ip address is NOT valid!", 1);

	p = (unsigned char *)&dip;
	task->dip[0] = p[0];
	task->dip[1] = p[1];
	task->dip[2] = p[2];
	task->dip[3] = p[3];

#if 0
	if (192 == task->dip[0] && 168 == task->dip[1] && 
		112 == task->dip[2] && 
		(108 == task->dip[3] || 125 == task->dip[3]))
		win_return("Sorry, it's my lord!", 1);
#endif

#ifdef DO_DEBUG 
	snprintf(addr, 80, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	win_ndebug(addr);
#endif /* DO_DEBUG */

	task->fake = 1;

	/* type */
	if (0 == (type_wd = GetDlgItem(task->hwnd, IDC_TYPE)))
		win_exit(task->hwnd, "0 == GetDlgItem(TYPE)!", 1);

	if (0 == (n = GetWindowText(type_wd, addr, 80))) {
		if (ERROR_SUCCESS != GetLastError()) 
			win_exit(task->hwnd, "0 == GetWindowText(IDC_TYPE)!", 1);

		task->fake = 1;
		task->type = TYPE_RAND;
	} else {
		type = atoi(addr);

		if (type >= TYPE_RAND && type < TYPE_MAX) {
			task->fake = 1;
			task->type = type;
		} else if (type >= TYPE_FAKE && type <  TYPE_MAX + TYPE_FAKE) {
			task->fake = 0;
			task->type = type - TYPE_FAKE;
		} else if (type >= TYPE_PRINT && type < TYPE_MAX + TYPE_PRINT) {
			task->fake = 1;
			task->print = 1;
			task->type = type - TYPE_PRINT;
		} else if (type >= TYPE_MAX && 
			(type < TYPE_FAKE || type >=  TYPE_MAX + TYPE_FAKE) &&
			(type < TYPE_PRINT || type >= TYPE_MAX + TYPE_PRINT)) 
			win_return("Type is NOT valid!", 1);
	}

#ifdef DO_DEBUG 
	snprintf(addr, 80, "%d", task->type);
	win_ndebug(addr);
#endif /* DO_DEBUG */

	/* dport */
	if (0 == (dport_wd = GetDlgItem(task->hwnd, IDC_DPORT)))
		win_exit(task->hwnd, "0 == GetDlgItem(DPORT)!", 1);

	if (0 == (n = GetWindowText(dport_wd, addr, 80))) {
		if (ERROR_SUCCESS != GetLastError()) 
			win_exit(task->hwnd, "0 == GetWindowText(IDC_TYPE)!", 1);
		
		/*
		else if (TYPE_TCPOPT == task->type)
			win_return("Port can NOT be NULL for type tcp option!\n", 1);
		*/
	} else {
		if (0 == (dport = atoi(addr)))
			win_return("Dest port is NOT valid!", 1);

		if (65535 <= dport)
			win_return("Dest port is NOT valid!", 1);

		task->dport[0] = ((dport << 16) >> 24);
		task->dport[1] = ((dport << 24) >> 24);

#ifdef DO_DEBUG 
		snprintf(addr, 80, "%d + %d", task->dport[0], task->dport[1]);
		win_ndebug(addr);
#endif /* DO_DEBUG */
	}

	return 0;
}
	
/****************************************************************************/

static int ip_check(struct sf_task *task)
{
	HANDLE handle;
	DWORD dw;

#ifdef DO_DEBUG 
	if (0 == task)
		win_return("ip_check(): 0 == task!", 1);

	if (0 == task->hwnd) 
		win_return("ip_check(): 0 == task->hwnd!", 1);
#endif /* DO_DEBUG */

	if (get_ip(task)) /* dip, dport, type */
		win_dreturn("Can NOT get IP information!", 1);
	
	if (get_route(task)) /* lip, hop */
		win_dreturn("Can NOT get route information!", 1);

	if (get_if(task)) { /* lmac, f */
#ifdef DO_DEBUG 
		if (task->f)
			win_debug("ip_check(): task->f!");
#endif /* DO_DEBUG */

		win_exit(task->hwnd, "Can NOT get NIC information!", 1);
	}

#ifdef DO_DEBUG 
	if (0 == task->f)
		win_exit(task->hwnd, "ip_check(): 0==task->f!", 1);
#endif /* DO_DEBUG */

	if (get_mac(task)) { /* dmac */
		pcap_close(task->f);
		task->f = 0;
		win_return("Can NOT get dest mac information!", 1);
	}

	handle = CreateThread(0, 0, do_check, task, 0, &dw);
	if (0 == handle) {
		pcap_close(task->f);
		task->f = 0;
		win_exit(task->hwnd, "CreateThread() failed!", 1);
	}

	return 0;
}

static INT_PTR WINAPI dlg_proc(HWND hwnd, UINT id, WPARAM wp, LPARAM lp)
{
	static int running = 0;
	static struct sf_task task;
	unsigned long dip, sip;
	unsigned char smac[6];
	INT_PTR ret = TRUE;
	NOTIFYICONDATA nid;
	HINSTANCE inst = 0;
	HICON hi = 0;
	
	switch (id) {
	case WM_INITDIALOG:
		memset(&task, 0, sizeof(struct sf_task));

		inst = (HINSTANCE)GetWindowLong(hwnd, GWL_HINSTANCE);

		if (0 == inst || 0 == (hi = LoadIcon(inst, MAKEINTRESOURCE(IPCHECK_ICON)))) {
			win_error("LoadIcon(IPCHECK_ICON) failed!");
#if 0
			EndDialog(hwnd, 0);
			break;
#endif
		}

		nid.cbSize = sizeof(NOTIFYICONDATA);
		nid.hWnd = hwnd;
		nid.uID = ID_TB_ICON;
		nid.uFlags = NIF_MESSAGE | (hi ? NIF_ICON : 0) | NIF_TIP;
		nid.uCallbackMessage = WM_SF_TOOLBAR;
		nid.hIcon = hi;
		lstrcpyn(nid.szTip, TEXT("IpCheck"), 
			sizeof(TEXT("IpCheck")) / sizeof((TEXT("IpCheck"))[0]));
		
		Shell_NotifyIcon(NIM_ADD, &nid);

		if (hi)
			DestroyIcon(hi);

		ShowWindow(hwnd, SW_MINIMIZE);

		break;
	case WM_SF_TOOLBAR:
		if (ID_TB_ICON == wp) {
			switch (lp) {
				LONG l;
			case WM_LBUTTONDOWN:
			case WM_RBUTTONDOWN:
#if 0
				ShowWindow(hwnd, SW_RESTORE);
#endif
				break;
			case WM_LBUTTONDBLCLK:
				if (IsIconic(hwnd)) 
					ShowWindow(hwnd, SW_RESTORE);
				else
					ShowWindow(hwnd, SW_MINIMIZE);
				break;
			default:
				ret = FALSE;
				break;
			}
		}

		break;
	case WM_SF_END:
		if (lp) {
			win_error("WM_SF_END: lp!");
			EndDialog(hwnd, 0);
			break;
		}

		if (task.stop) {
			if (0 == CloseHandle(task.stop)) {
				win_error("0 == CloseHandle()");
				EndDialog(hwnd, 0);
				break;
			}

			task.stop = 0;
		}

		running = 0;

		if (0 == SetWindowText((HWND)GetDlgItem(hwnd, IDC_START), 
			TEXT("Start"))) {
			win_error("WM_SF_END: 0 == SetWindowText(Start)!");
			EndDialog(hwnd, 0);
			break;
		}

		break;
	case WM_SIZE:
		if (IsIconic(hwnd)) {
			LONG l;
			
			ShowWindow(hwnd, SW_HIDE);
			l = GetWindowLong(hwnd, GWL_EXSTYLE);
			l &= (~(WS_EX_APPWINDOW));
			l |= WS_EX_TOOLWINDOW;
			SetWindowLong(hwnd, GWL_EXSTYLE, l);
			ShowWindow(hwnd, SW_SHOW);
		} else {
			LONG l;
			
			ShowWindow(hwnd, SW_HIDE);
			l = GetWindowLong(hwnd, GWL_EXSTYLE);
			l &= (~(WS_EX_TOOLWINDOW));
			l |= WS_EX_APPWINDOW;
			SetWindowLong(hwnd, GWL_EXSTYLE, l);
			ShowWindow(hwnd, SW_SHOW);
		}

		break;
	case WM_COMMAND:
		switch (HIWORD(wp)) {
		case BN_CLICKED:
			switch (LOWORD(wp)) {
			case IDCANCEL:
				nid.cbSize = sizeof(NOTIFYICONDATA);
				nid.hWnd = hwnd;
				nid.uID = ID_TB_ICON;

				if (running)
					SetEvent(task.stop);

				Shell_NotifyIcon(NIM_DELETE, &nid);
				EndDialog(hwnd, 0);

				break;
			case IDC_START: 
				if (running) {
					if (0 == task.stop) {
						win_debug("dump!");
					       	break;
					}
				
					if (0 == SetEvent(task.stop)) {
						win_error("0 == SetEvent()!");
						EndDialog(hwnd, 0);
					}

					break;
				}
			
				if (task.stop) {
					win_error("task.stop!");
					/*
					EndDialog(hwnd, 0);
					*/
					break;
				}

				memset(&task, 0, sizeof(struct sf_task));
				task.hwnd = hwnd;
				task.stop = CreateEvent(0, FALSE, FALSE, 0);

				if (0 == task.stop) {
					win_error("WM_INITDIALOG: 0 == stop!");
					EndDialog(hwnd, 0);
					break;
				}

				running = 1;

				if (0 == SetWindowText((HWND)lp, 
					TEXT("Stop"))) {
					CloseHandle(task.stop);
					task.stop = 0;
					running = 0;
					win_error("0 == SetWindowText(Start)!");
					EndDialog(hwnd, 0);
					break;
				}

				if (ip_check(&task)) {
					if (0 == CloseHandle(task.stop)) {
						win_error("0 == CloseHandle()");
						EndDialog(hwnd, 0);
						break;
					}

					task.stop = 0;

					running = 0;

					if (0 == SetWindowText((HWND)lp, 
						TEXT("Start"))) {
						CloseHandle(task.stop);
						task.stop = 0;
						win_error("0 == SetWindow"
							"Text(Start)!");
						EndDialog(hwnd, 0);
						break;
					}

					win_debug("ip_check() failed!");
					break;
				}

				running = 1;

				break;
			default:
				ret = FALSE;
				break;
			}

			break;
		default:
			ret = FALSE;
			break;
		}

		break;
	default:
		ret = FALSE;
		break;
	}

	return ret;
}

/****************************************************************************/

static signed int check_gsid()
{
	DWORD i;
	signed int ret = -1;
	HANDLE token = 0, heap = 0;
	DWORD rl = 0;
	void *buf = 0;
	PTOKEN_GROUPS ptg = 0;
	PSID psid = 0;
	SID_IDENTIFIER_AUTHORITY sia = { SECURITY_NT_AUTHORITY };

	if (0 == AllocateAndInitializeSid(&sia, 2, SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &psid)) 
		win_goto("AllocateAndInitializeSid() failed", out);

	if (0 == psid)
		win_goto("AllocateAndInitializeSid() return NULL", out);
	
	if (0 == IsValidSid(psid)) 
		win_goto("SID is NOT valid", clean_sid);

	if (0 == OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
		win_goto("OpenProcessToken() failed", clean_sid);

	if (0 == (heap = GetProcessHeap()))
		win_goto("GetProcessHeap() failed", clean_token);

	for (i = 0; 9 > i; i++) {
		if (0 == GetTokenInformation(token, TokenGroups, 0, 0, &rl)) {
			if (ERROR_INSUFFICIENT_BUFFER != GetLastError())
				win_goto("GetTokenInformation() failed", 
					clean_token);
		}

		if (0 == (buf = HeapAlloc(heap, HEAP_ZERO_MEMORY, rl)))
			win_goto("HeapAlloc() failed", clean_token);

		if (0 == GetTokenInformation(token, TokenGroups, buf, rl, &rl)) {
			if (TRUE != HeapFree(heap, 0, buf)) {
				ret = -2;
				win_goto("HeapFree() failed", clean_token);
			}

			buf = 0;
			rl = 0;

			if (ERROR_INSUFFICIENT_BUFFER != GetLastError())
				win_goto("GetTokenInformation() failed", 
					clean_token);

			continue;
		}
		
		ptg = (PTOKEN_GROUPS)buf;

		for (i = 0; i < ptg->GroupCount; i++) {
			if (EqualSid(ptg->Groups[i].Sid, psid)) {
				ret = 0;
				win_ndebug("Admins!");
				goto clean_buf;
			}
		}

		ret = 1;
		win_ndebug("NOT Admins!");
		break;
	}

clean_buf:
	if (buf) {
		if (TRUE != HeapFree(heap, 0, buf))
			ret = -2;
	}

clean_token:
	CloseHandle(token);

clean_sid:
	if (psid)
		FreeSid(psid);

out:
	return ret;
}

/****************************************************************************/

int WINAPI WinMain(HINSTANCE inst, HINSTANCE prev, PSTR param, int show)
{
	int ret = 1;
	WORD ver = MAKEWORD(2, 2);
	WSADATA data;

	srand((unsigned int)time(0));

	if (WSAStartup(ver, &data)) 
		win_goto("WSAStartup() failed!", out);

	if (0 > (isnot_admin = check_gsid())) 
		goto clean;
	else if (1 != isnot_admin && 0 != isnot_admin)
		win_goto("isnot_admin is not (0|1)!", clean);

	if (-1 == DialogBox(inst, MAKEINTRESOURCE(IPCHECK_DLG), 0, dlg_proc)) {
		char errbuf[80];
		DWORD dw;

		dw = GetLastError();
		snprintf(errbuf, 79, "DialogBox() failed: %u", dw);
		win_error(errbuf);
	} else
		ret = 0;

clean:
	WSACleanup();
out:
	return ret;
}

/*
 * ipcheck.c$
 * */


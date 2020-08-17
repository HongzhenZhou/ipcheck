
/*
 * ^pub.h
 * */

#ifndef PUB_H
#define PUB_H

enum {
	TYPE_RAND=0,
	TYPE_UNIT,
	TYPE_UNIU,
	TYPE_UNIA,
	TYPE_FRAG,
	TYPE_IPOPT,
	TYPE_TCPOPT,
	TYPE_VRAND,
	TYPE_VUNIA,
	TYPE_UNII,
	TYPE_IPOPT_ICMP,
#if 0
	TYPE_IPOPT_UDP,
#endif
	TYPE_UNIO,
	TYPE_MAX,
	TYPE_FAKE=50,
	TYPE_PRINT=100
};

struct sf_task {
	HANDLE stop;
	HWND hwnd;
	pcap_t *f;
	unsigned int index;
	unsigned int type;
	unsigned int lan;
	unsigned int broad;
	unsigned int fake;
	unsigned int print;
	unsigned char dip[4];
	unsigned char dport[2];
	unsigned char dmac[6];
	unsigned char hop[4];
	unsigned char smac[6];
	unsigned char lip[4];
	unsigned char lnet[4];
	unsigned char rmark[4];
	unsigned char lmac[6];
};

extern signed int isnot_admin;

extern const unsigned char broadmac[6];
extern const unsigned char arpq_type_10[10];
extern const unsigned char arpp_type_10[10];

#ifdef DO_DEBUG
#define win_debug(s) MessageBox(0, TEXT(s), "debug", MB_ICONINFORMATION | MB_OK)

#define win_dreturn(s, i) if (1) {\
	MessageBox(0, TEXT(s), 0, MB_ICONERROR | MB_OK);\
	return i;\
} else


#else /* !DO_DEBUG */
#define win_debug(s)
#define win_dreturn(s, i) return i
#endif /* DO_DEBUG */

#define win_ndebug(s)
/*
#define win_error(s) MessageBox(0, TEXT(s), 0, MB_ICONERROR | MB_OK)
*/
#define win_error(s) MessageBox(0, TEXT(s), 0, MB_ICONINFORMATION | MB_OK)

#define win_return(s, i) if (1) {\
	MessageBox(0, TEXT(s), 0, MB_ICONERROR | MB_OK);\
	return i;\
} else


#define win_goto(s, i) if (1) {\
	MessageBox(0, TEXT(s), 0, MB_ICONERROR | MB_OK);\
	goto i;\
} else


#define win_exit(hwnd, s, i) if (1) {\
	MessageBox(0, TEXT(s), 0, MB_ICONERROR | MB_OK);\
	EndDialog(hwnd, 0);\
	return i;\
} else


#endif /* PUB_H */

/*
 * pub.h$
 * */


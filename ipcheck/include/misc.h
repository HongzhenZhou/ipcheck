
/*
 * ^misc.h
 * */

#ifndef MISC_H
#define MISC_H

int check_alive_3_lan(struct sf_task *task);
void print_pkt(unsigned char *buf, unsigned int len);
int get_route(struct sf_task *task);
int get_if(struct sf_task *task);
int do_csum(unsigned char *ip, unsigned char *icsum, 
	unsigned short isize, unsigned char *tcp, unsigned char *tcsum, 
	unsigned short tsize, int type);
signed int spy_kernel(struct sf_task *task, unsigned char *buf, 
	unsigned int len, DWORD arpip);

#endif /* MISC_H */

/*
 * misc.h$
 * */


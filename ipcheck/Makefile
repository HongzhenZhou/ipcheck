
CC=lcc
LINK=lcclnk
RC=lrc
RM=del
MD5=md5

INCLUDE=-I.\include -If:\lcc\include -Iz:\down\WpdPack\include 

CFLAG=-ansic $(INCLUDE) -DWPCAP -DHAVE_REMOTE #-DDO_DEBUG
LFLAG=-subsystem windows
RCFLAG=$(INCLUDE)
RMFLAG=/Q

OBJS=.\obj\ipcheck.obj .\obj\frag.obj .\obj\arp.obj .\obj\misc.obj .\obj\ipopt.obj .\obj\tcpopt.obj .\obj\rand.obj .\obj\ipcheck.res 
LIBS=shell32.lib wsock32.lib ws2_32.lib iphlpapi.lib wpcap.lib Packet.lib

all: ipcheck.exe md5

ipcheck.exe: $(OBJS)
	$(LINK) -o ipcheck.exe $(LFLAG) $(OBJS) $(LIBS)

.\obj\ipcheck.obj: ipcheck.c
	$(CC) -Fo.\obj\ipcheck.obj $(CFLAG) ipcheck.c

.\obj\arp.obj: arp.c
	$(CC) -Fo.\obj\arp.obj $(CFLAG) arp.c

.\obj\misc.obj: misc.c
	$(CC) -Fo.\obj\misc.obj $(CFLAG) misc.c

.\obj\ipopt.obj: ipopt.c
	$(CC) -Fo.\obj\ipopt.obj $(CFLAG) ipopt.c

.\obj\tcpopt.obj: tcpopt.c
	$(CC) -Fo.\obj\tcpopt.obj $(CFLAG) tcpopt.c

.\obj\rand.obj: rand.c
	$(CC) -Fo.\obj\rand.obj $(CFLAG) rand.c

.\obj\frag.obj: frag.c
	$(CC) -Fo.\obj\frag.obj $(CFLAG) frag.c

.\obj\ipcheck.res: ipcheck.rc
	$(RC) -fo.\obj\ipcheck.res $(RCFLAG) ipcheck.rc

md5:
	$(MD5) ipcheck.exe > ipcheck.md5

clean:
	$(RM) $(RMFLAG) $(OBJS) ipcheck.exe


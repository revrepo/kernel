#
# Makefile for the Rev Software TCP/IP Congestion Control Algorithm
#
obj-m := tcp_revsw.o
ccflags-y += -DTCP_REVSW_MAJOR=$(TCP_REVSW_MAJOR) -DTCP_REVSW_MINOR=$(TCP_REVSW_MINOR) -DTCP_REVSW_SUBLEVEL=$(TCP_REVSW_SUBLEVEL)
tcp_revsw-objs := tcp_revsw_sysctl.o tcp_revsw_session_db.o tcp_revsw_std.o \
		tcp_revsw_rbe.o tcp_revsw_dummy.o tcp_revsw_wrapper.o

default :
	make ARCH=x86_64 -C /lib/modules/`uname -r`/build M=$$PWD
clean :
	rm -f modules.order Module.symvers *.o *.ko *.mod.*


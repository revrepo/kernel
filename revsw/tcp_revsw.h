/*
 *   tcp_revsw.h
 *
 *   RevSw TCP Congestion Control Algorithm Wrapper
 *
 * RevSw has two congestion control algorithms that can be used
 * depending on various paramters: who initiated the connection,
 * what TCP parameters are supported on the connection, etc.  This
 * module provides a means to automatically determine which CCA
 * should be used and provides the mechanism to call the appropriate
 * CCA specific APIs when necessary.
 *
 * Copyright 2014 - RevSw
 *
 */
#ifndef __TCP_REVSW_H__
#define __TCP_REVSW_H__

#define TCP_REVSW_LOCALHOST 0x100007f

#define REVSW_LARGE_RWND_SIZE		65535
#define TCP_REVSW_RBE_LOG_DEFAULT	0

#define REVSW_PACKET_SIZE_MIN		300
#define REVSW_PACKET_SIZE_MAX		2000
#define REVSW_PACKET_SIZE_DEFAULT	1024

#define REVSW_ACTIVE_SCALE_MIN		0
#define REVSW_ACTIVE_SCALE_MAX		100
#define REVSW_ACTIVE_SCALE_DEFAULT	50

#define REVSW_INIT_CWND_MAX		100

#define REVSW_RWIN_SCALE_MIN		0
#define REVSW_RWIN_SCALE_MAX		sizeof(int)

#define REVSW_CL_ENTRIES_MIN	1
#define REVSW_CL_ENTRIES_MAX	10000
#define REVSW_CL_ENTRIES_DEFAULT 3000

struct tcp_revsw_sysctl_data {
	int sm_rcv_wnd;
	int lrg_rcv_wnd;
	int cong_wnd;
	int packet_size;
	int active_scale;
	int max_init_cwnd;
	int rwin_scale;
	int disable_nagle_mss;
	int rbe_loglevel;
	int test_tcp_snd_wnd;
	int cl_entries;
	int cn_entries;
	int fc_entries;
	int max_cl_entries;
};

extern struct ctl_table revsw_ctl_table[];
extern struct tcp_revsw_sysctl_data tcp_revsw_sysctls;

#endif /* __TCP_REVSW_H__ */

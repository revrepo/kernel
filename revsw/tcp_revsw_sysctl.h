/*
 *
 *   RevSw TCP Sysctl Support
 *
 * This module provides the sysctls that the various RevSw
 * congestion control algortihms and session database require.
 *
 * Copyright (c) 2013-2014, Rev Software, Inc.
 * All Rights Reserved.
 * This code is confidential and proprietary to Rev Software, Inc
 * and may only be used under a license from Rev Software Inc.
 */
#ifndef __TCP_REVSW_SYSCTL_H__
#define __TCP_REVSW_SYSCTL_H__

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

extern struct tcp_revsw_sysctl_data tcp_revsw_sysctls;

#endif /* __TCP_REVSW_SYSCTL_H__ */


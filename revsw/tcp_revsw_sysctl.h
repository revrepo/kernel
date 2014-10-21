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

#define TCP_SESSION_TTL_MAX		259200
#define TCP_SESSION_TTL_DEFAULT		10800

#define REVSW_LARGE_RWND_SIZE		65535
#define REVSW_RRE_LOG_DEFAULT		0

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

extern int revsw_sm_rcv_wnd;
extern int revsw_lrg_rcv_wnd;
extern int revsw_cong_wnd;
extern int revsw_tcp_session_ttl;
extern int revsw_tcp_rre_loglevel;
extern int revsw_tcp_test_snd_wnd;
extern int revsw_packet_size;
extern int revsw_active_scale;
extern int revsw_max_init_cwnd;
extern int revsw_rwin_scale;
extern int revsw_disable_nagle_mss;

extern int revsw_cl_entries;
extern int revsw_cn_entries;
extern int revsw_fc_entries;
extern int revsw_max_cl_entries;

#endif /* __TCP_REVSW_SYSCTL_H__ */


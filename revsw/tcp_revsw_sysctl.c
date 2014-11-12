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
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/inet_diag.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <net/tcp.h>
#include "tcp_revsw_wrapper.h"
#include "tcp_revsw_session_db.h"

#define REVSW_RWND_MPLR_MIN		1
#define REVSW_RWND_MPLR_MAX		5
#define REVSW_RWND_MPLR_DEFAULT		3
#define REVSW_LARGE_RWND_MPLR		2

/*
 * Initial Congestion Window
 * Default of 0 means that the system will determine the
 * initial cwnd based on the RWND and MTU.  Otherwise is
 * will take what the user has set.
 */
#define REVSW_CONG_WND_MIN      0
#define REVSW_CONG_WND_MAX      REVSW_INIT_CWND_MAX
#define REVSW_CONG_WND_DEFAULT  REVSW_CONG_WND_MIN

#define REVSW_INIT_CWND_DEFAULT	60

static int revsw_rwnd_mplr_min __read_mostly = REVSW_RWND_MPLR_MIN;
static int revsw_rwnd_mplr_max __read_mostly = REVSW_RWND_MPLR_MAX;

static int revsw_cong_wnd_min __read_mostly = REVSW_CONG_WND_MIN;
static int revsw_cong_wnd_max __read_mostly = REVSW_CONG_WND_MAX;

static int revsw_packet_size_min = REVSW_PACKET_SIZE_MIN;
static int revsw_packet_size_max = REVSW_PACKET_SIZE_MAX;

static int revsw_active_scale_min = REVSW_ACTIVE_SCALE_MIN;
static int revsw_active_scale_max = REVSW_ACTIVE_SCALE_MAX;

static int revsw_init_cwnd_min = TCP_INIT_CWND;
static int revsw_init_cwnd_max = REVSW_INIT_CWND_MAX;

static int revsw_rwin_scale_min = REVSW_RWIN_SCALE_MIN;
static int revsw_rwin_scale_max = REVSW_RWIN_SCALE_MAX;

static int revsw_cl_entries_min = REVSW_CL_ENTRIES_MIN;
static int revsw_cl_entries_max = REVSW_CL_ENTRIES_MAX;

struct tcp_revsw_sysctl_data tcp_revsw_sysctls = {
	.sm_rcv_wnd = REVSW_RWND_MPLR_DEFAULT,
	.lrg_rcv_wnd = REVSW_LARGE_RWND_MPLR,
	.cong_wnd = REVSW_CONG_WND_DEFAULT,
	.packet_size = REVSW_PACKET_SIZE_DEFAULT,
	.active_scale = REVSW_ACTIVE_SCALE_DEFAULT,
	.max_init_cwnd = REVSW_INIT_CWND_DEFAULT,
	.rwin_scale = 0,
	.disable_nagle_mss = 0,
	.rbe_loglevel = TCP_REVSW_RBE_LOG_DEFAULT,
	.test_tcp_snd_wnd = 0,
	.cl_entries = 0,
	.cn_entries = 0,
	.fc_entries = 0,
	.max_cl_entries = 0,
	.supported_cca = (1 << TCP_REVSW_CCA_STANDARD),
};
EXPORT_SYMBOL_GPL(tcp_revsw_sysctls);

struct ctl_table revsw_ctl_table[] = {
	{
		.procname = "revsw_sm_rcv_wnd",
		.maxlen = sizeof(int),
		.mode = 0644,
		.data = &tcp_revsw_sysctls.sm_rcv_wnd,
		.proc_handler = &proc_dointvec_minmax,
		.extra1 = &revsw_rwnd_mplr_min,
		.extra2 = &revsw_rwnd_mplr_max,
	},
	{
		.procname = "revsw_lrg_rcv_wnd",
		.maxlen = sizeof(int),
		.mode = 0644,
		.data = &tcp_revsw_sysctls.lrg_rcv_wnd,
		.proc_handler = &proc_dointvec_minmax,
		.extra1 = &revsw_rwnd_mplr_min,
		.extra2 = &revsw_rwnd_mplr_max,
	},
	{
		.procname = "revsw_cong_wnd",
		.maxlen = sizeof(int),
		.mode = 0644,
		.data = &tcp_revsw_sysctls.cong_wnd,
		.proc_handler = &proc_dointvec_minmax,
		.extra1 = &revsw_cong_wnd_min,
		.extra2 = &revsw_cong_wnd_max,
	},
	{
		.procname = "revsw_packet_size",
		.maxlen = sizeof(int),
		.mode = 0644,
		.data = &tcp_revsw_sysctls.packet_size,
		.proc_handler = &proc_dointvec_minmax,
		.extra1 = &revsw_packet_size_min,
		.extra2 = &revsw_packet_size_max,
	},
	{
		.procname = "revsw_active_scale",
		.maxlen = sizeof(int),
		.mode = 0644,
		.data = &tcp_revsw_sysctls.active_scale,
		.proc_handler = &proc_dointvec_minmax,
		.extra1 = &revsw_active_scale_min,
		.extra2 = &revsw_active_scale_max,
	},
	{
		.procname = "revsw_max_init_cwnd",
		.maxlen = sizeof(int),
		.mode = 0644,
		.data = &tcp_revsw_sysctls.max_init_cwnd,
		.proc_handler = &proc_dointvec_minmax,
		.extra1 = &revsw_init_cwnd_min,
		.extra2 = &revsw_init_cwnd_max,
	},
	{
		.procname = "revsw_rwin_scale",
		.maxlen = sizeof(int),
		.mode = 0644,
		.data = &tcp_revsw_sysctls.rwin_scale,
		.proc_handler = &proc_dointvec,
		.extra1 = &revsw_rwin_scale_min,
		.extra2 = &revsw_rwin_scale_max,
	},
	{
		.procname = "revsw_disable_nagle_mss",
		.maxlen = sizeof(int),
		.mode = 0644,
		.data = &tcp_revsw_sysctls.disable_nagle_mss,
		.proc_handler = &proc_dointvec,
	},
	{
		.procname = "revsw_rbe_loglevel",
		.maxlen = sizeof(int),
		.mode = 0644,
		.data = &tcp_revsw_sysctls.rbe_loglevel,
		.proc_handler = &proc_dointvec,
	},
	{
		.procname = "revsw_tcp_test_snd_wnd",
		.maxlen = sizeof(int),
		.mode = 0644,
		.data = &tcp_revsw_sysctls.test_tcp_snd_wnd,
		.proc_handler = &proc_dointvec,
	},
	{
		.procname = "revsw_cl_entries",
		.maxlen = sizeof(int),
		.mode = 0444,
		.data = &tcp_revsw_sysctls.cl_entries,
		.proc_handler = &proc_dointvec,
	},
	{
		.procname = "revsw_cn_entries",
		.maxlen = sizeof(int),
		.mode = 0444,
		.data = &tcp_revsw_sysctls.cn_entries,
		.proc_handler = &proc_dointvec,
	},
	{
		.procname = "revsw_fc_entries",
		.maxlen = sizeof(int),
		.mode = 0444,
		.data = &tcp_revsw_sysctls.fc_entries,
		.proc_handler = &proc_dointvec,
	},
	{
		.procname = "revsw_max_cl_entries",
		.maxlen = sizeof(int),
		.mode = 0644,
		.data = &tcp_revsw_sysctls.max_cl_entries,
		.proc_handler = &proc_dointvec,
		.extra1 = &revsw_cl_entries_min,
		.extra2 = &revsw_cl_entries_max,
	},
	{
		.procname = "revsw_supported_cca",
		.maxlen = sizeof(int),
		.mode = 0644,
		.data = &tcp_revsw_sysctls.supported_cca,
		.proc_handler = &proc_dointvec,
	},

	{}
};

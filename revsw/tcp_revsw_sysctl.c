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
#include "tcp_revsw_sysctl.h"

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

int revsw_sm_rcv_wnd __read_mostly = REVSW_RWND_MPLR_DEFAULT;
EXPORT_SYMBOL_GPL(revsw_sm_rcv_wnd);

int revsw_lrg_rcv_wnd __read_mostly = REVSW_LARGE_RWND_MPLR;
EXPORT_SYMBOL_GPL(revsw_lrg_rcv_wnd);

static int revsw_cong_wnd_min __read_mostly = REVSW_CONG_WND_MIN;
static int revsw_cong_wnd_max __read_mostly = REVSW_CONG_WND_MAX;
int revsw_cong_wnd __read_mostly = REVSW_CONG_WND_DEFAULT;
EXPORT_SYMBOL_GPL(revsw_cong_wnd);

static int revsw_tcp_session_ttl_min __read_mostly = 1;
static int revsw_tcp_session_ttl_max __read_mostly = TCP_SESSION_TTL_MAX;
int revsw_tcp_session_ttl __read_mostly = TCP_SESSION_TTL_DEFAULT;
EXPORT_SYMBOL_GPL(revsw_tcp_session_ttl);

int tcp_revsw_rbe_loglevel __read_mostly = TCP_REVSW_RBE_LOG_DEFAULT;
EXPORT_SYMBOL_GPL(tcp_revsw_rbe_loglevel);

int revsw_tcp_test_snd_wnd __read_mostly;
EXPORT_SYMBOL_GPL(revsw_tcp_test_snd_wnd);

static int revsw_packet_size_min = REVSW_PACKET_SIZE_MIN;
static int revsw_packet_size_max = REVSW_PACKET_SIZE_MAX;
int revsw_packet_size __read_mostly = REVSW_PACKET_SIZE_DEFAULT;
EXPORT_SYMBOL_GPL(revsw_packet_size);

static int revsw_active_scale_min = REVSW_ACTIVE_SCALE_MIN;
static int revsw_active_scale_max = REVSW_ACTIVE_SCALE_MAX;
int revsw_active_scale __read_mostly = REVSW_ACTIVE_SCALE_DEFAULT;
EXPORT_SYMBOL_GPL(revsw_active_scale);

static int revsw_init_cwnd_min = TCP_INIT_CWND;
static int revsw_init_cwnd_max = REVSW_INIT_CWND_MAX;
int revsw_max_init_cwnd = REVSW_INIT_CWND_DEFAULT;
EXPORT_SYMBOL_GPL(revsw_max_init_cwnd);

static int revsw_rwin_scale_min = REVSW_RWIN_SCALE_MIN;
static int revsw_rwin_scale_max = REVSW_RWIN_SCALE_MAX;
int revsw_rwin_scale __read_mostly;
EXPORT_SYMBOL_GPL(revsw_rwin_scale);

int revsw_disable_nagle_mss __read_mostly;
EXPORT_SYMBOL_GPL(revsw_disable_nagle_mss);

int revsw_cl_entries __read_mostly;
EXPORT_SYMBOL_GPL(revsw_cl_entries);

int revsw_cn_entries __read_mostly;
EXPORT_SYMBOL_GPL(revsw_cn_entries);

int revsw_fc_entries __read_mostly;
EXPORT_SYMBOL_GPL(revsw_fc_entries);

static int revsw_cl_entries_min = REVSW_CL_ENTRIES_MIN;
static int revsw_cl_entries_max = REVSW_CL_ENTRIES_MAX;
int revsw_max_cl_entries __read_mostly = REVSW_CL_ENTRIES_DEFAULT;
EXPORT_SYMBOL_GPL(revsw_max_cl_entries);

static struct ctl_table_header *revsw_ctl_table_hdr;

static struct ctl_table revsw_ctl_table[] = {
	{
		.procname = "revsw_sm_rcv_wnd",
		.maxlen = sizeof(int),
		.mode = 0644,
		.data = &revsw_sm_rcv_wnd,
		.proc_handler = &proc_dointvec_minmax,
		.extra1 = &revsw_rwnd_mplr_min,
		.extra2 = &revsw_rwnd_mplr_max,
	},
	{
		.procname = "revsw_lrg_rcv_wnd",
		.maxlen = sizeof(int),
		.mode = 0644,
		.data = &revsw_lrg_rcv_wnd,
		.proc_handler = &proc_dointvec_minmax,
		.extra1 = &revsw_rwnd_mplr_min,
		.extra2 = &revsw_rwnd_mplr_max,
	},
	{
		.procname = "revsw_cong_wnd",
		.maxlen = sizeof(int),
		.mode = 0644,
		.data = &revsw_cong_wnd,
		.proc_handler = &proc_dointvec_minmax,
		.extra1 = &revsw_cong_wnd_min,
		.extra2 = &revsw_cong_wnd_max,
	},
	{
		.procname = "revsw_tcp_session_ttl",
		.data = &revsw_tcp_session_ttl,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = proc_dointvec_minmax,
		.extra1	= &revsw_tcp_session_ttl_min,
		.extra2	= &revsw_tcp_session_ttl_max,
	},
	{
		.procname = "tcp_revsw_rbe_loglevel",
		.maxlen = sizeof(int),
		.mode = 0644,
		.data = &tcp_revsw_rbe_loglevel,
		.proc_handler = &proc_dointvec,
	},
	{
		.procname = "revsw_tcp_test_snd_wnd",
		.maxlen = sizeof(int),
		.mode = 0644,
		.data = &revsw_tcp_test_snd_wnd,
		.proc_handler = &proc_dointvec,
	},
	{
		.procname = "revsw_packet_size",
		.maxlen = sizeof(int),
		.mode = 0644,
		.data = &revsw_packet_size,
		.proc_handler = &proc_dointvec_minmax,
		.extra1 = &revsw_packet_size_min,
		.extra2 = &revsw_packet_size_max,
	},
	{
		.procname = "revsw_active_scale",
		.maxlen = sizeof(int),
		.mode = 0644,
		.data = &revsw_active_scale,
		.proc_handler = &proc_dointvec_minmax,
		.extra1 = &revsw_active_scale_min,
		.extra2 = &revsw_active_scale_max,
	},
	{
		.procname = "revsw_max_init_cwnd",
		.maxlen = sizeof(int),
		.mode = 0644,
		.data = &revsw_max_init_cwnd,
		.proc_handler = &proc_dointvec_minmax,
		.extra1 = &revsw_init_cwnd_min,
		.extra2 = &revsw_init_cwnd_max,
	},
	{
		.procname = "revsw_rwin_scale",
		.maxlen = sizeof(int),
		.mode = 0644,
		.data = &revsw_rwin_scale,
		.proc_handler = &proc_dointvec,
		.extra1 = &revsw_rwin_scale_min,
		.extra2 = &revsw_rwin_scale_max,
	},
	{
		.procname = "revsw_disable_nagle_mss",
		.maxlen = sizeof(int),
		.mode = 0644,
		.data = &revsw_disable_nagle_mss,
		.proc_handler = &proc_dointvec,
	},
	{
		.procname = "revsw_cl_entries",
		.maxlen = sizeof(int),
		.mode = 0444,
		.data = &revsw_cl_entries,
		.proc_handler = &proc_dointvec,
	},
	{
		.procname = "revsw_cn_entries",
		.maxlen = sizeof(int),
		.mode = 0444,
		.data = &revsw_cn_entries,
		.proc_handler = &proc_dointvec,
	},
	{
		.procname = "revsw_fc_entries",
		.maxlen = sizeof(int),
		.mode = 0444,
		.data = &revsw_fc_entries,
		.proc_handler = &proc_dointvec,
	},
	{
		.procname = "revsw_max_cl_entries",
		.maxlen = sizeof(int),
		.mode = 0644,
		.data = &revsw_max_cl_entries,
		.proc_handler = &proc_dointvec,
		.extra1 = &revsw_cl_entries_min,
		.extra2 = &revsw_cl_entries_max,
	},

	{}
};

static int __init tcp_revsw_sysctl_register(void)
{
	revsw_ctl_table_hdr = register_sysctl("revsw", revsw_ctl_table);
	if (!revsw_ctl_table_hdr)
		return -EFAULT;

	return 0;
}

static void __exit tcp_revsw_sysctl_unregister(void)
{
	unregister_sysctl_table(revsw_ctl_table_hdr);
}

module_init(tcp_revsw_sysctl_register);
module_exit(tcp_revsw_sysctl_unregister);

MODULE_AUTHOR("Tom Kavanagh");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP RevSw Sysctl");

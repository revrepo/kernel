/*
 *   Dummy RevSw TCP Congestion Control Algorithm
 *
 * This CCA is a dummy CCA to generate logs if for any reason
 * the wrapper could not figure out the sockets CCA
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

/*
 * @tcp_revsw_dummy_init
 */
static void tcp_revsw_dummy_init(struct sock *sk)
{
	pr_err("%s: %p CCA invocation error\n", __func__, sk);
}

/*
 * @tcp_revsw_dummy_release
 */
static void tcp_revsw_dummy_release(struct sock *sk)
{
	pr_err("%s: %p CCA invocation error\n", __func__, sk);
}

/*
 * @tcp_revsw_dummy_ssthresh
 */
static u32 tcp_revsw_dummy_ssthresh(struct sock *sk)
{
	pr_err("%s: %p CCA invocation error\n", __func__, sk);
	return 0;
}

/*
 * @tcp_revsw_dummy_cong_avoid
 */
static void tcp_revsw_dummy_cong_avoid(struct sock *sk, u32 ack, u32 acked, u32 in_flight)
{
	pr_err("%s: %p CCA invocation error\n", __func__, sk);
}

/*
 * @tcp_revsw_dummy_min_cwnd
 */
static u32 tcp_revsw_dummy_min_cwnd(const struct sock *sk)
{
	pr_err("%s: %p CCA invocation error\n", __func__, sk);
	return 0;
}

/*
 * @tcp_revsw_dummy_state
 */
static void tcp_revsw_dummy_state(struct sock *sk, u8 new_state)
{
	pr_err("%s: %p CCA invocation error State(%d)\n", __func__, sk, new_state);
}

/*
 * @tcp_revsw_dummy_event
 */
static void tcp_revsw_dummy_event(struct sock *sk, enum tcp_ca_event event)
{
	pr_err("%s: %p CCA invocation error Event (%d)\n", __func__, sk, event);
}

/*
 * @tcp_revsw_dummy_info
 * Extract info for TCP socket info provided via netlink.
 */
static void tcp_revsw_dummy_info(struct sock *sk, u32 ext,
							   struct sk_buff *skb)
{
	pr_err("%s: %p CCA invocation error\n", __func__, sk);
}

/*
 * @tcp_revsw_dummy_pkts_acked
 */
static void tcp_revsw_dummy_pkts_acked(struct sock *sk, u32 cnt, s32 rtt)
{
	pr_err("%s: %p CCA invocation error\n", __func__, sk);
}

/*
 * @tcp_revsw_syn_post_config
 */
static void tcp_revsw_dummy_syn_post_config(struct sock *sk)
{
	pr_err("%s: %p CCA invocation error\n", __func__, sk);
}

/*
 * @tcp_revsw_dummy_set_nwin_size
 */
static void tcp_revsw_dummy_set_nwin_size(struct sock *sk, u32 nwin)
{
	pr_err("%s: %p CCA invocation error\n", __func__, sk);
}

/*
 * @tcp_revsw_dummy_get_cwnd_quota
 */
static int tcp_revsw_dummy_get_cwnd_quota(struct sock *sk, const struct sk_buff *skb)
{
	pr_err("%s: %p CCA invocation error\n", __func__, sk);
	return 0;
}

/*
 * @tcp_revsw_dummy_handle_nagle_test
 */
static bool
tcp_revsw_dummy_handle_nagle_test(struct sock *sk, struct sk_buff *skb,
								  unsigned int mss_now, int nonagle)
{
	pr_err("%s: %p CCA invocation error\n", __func__, sk);

	return false;
}

static struct tcp_congestion_ops tcp_revsw_dummy __read_mostly = {
	.flags		= TCP_CONG_RTT_STAMP,
	.init		= tcp_revsw_dummy_init,
	.release	= tcp_revsw_dummy_release,
	.ssthresh	= tcp_revsw_dummy_ssthresh,
	.cong_avoid	= tcp_revsw_dummy_cong_avoid,
	.min_cwnd	= tcp_revsw_dummy_min_cwnd,
	.set_state	= tcp_revsw_dummy_state,
	.cwnd_event	= tcp_revsw_dummy_event,
	.get_info	= tcp_revsw_dummy_info,
	.pkts_acked	= tcp_revsw_dummy_pkts_acked,
	.syn_post_config = tcp_revsw_dummy_syn_post_config,
	.set_nwin_size = tcp_revsw_dummy_set_nwin_size,
	.handle_nagle_test = tcp_revsw_dummy_handle_nagle_test,
	.get_session_info = tcp_session_get_info,
	.get_cwnd_quota = tcp_revsw_dummy_get_cwnd_quota,
};

struct tcp_revsw_cca_entry tcp_revsw_dummy_cca  __read_mostly = {
	.revsw_cca = TCP_REVSW_CCA_UNKNOWN,
	.cca_ops = &tcp_revsw_dummy,
};

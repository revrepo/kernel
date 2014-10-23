/*
 *
 *   RevSw TCP Congestion Control Algorithm
 *
 * Starting off RevSw will be utilizing the Westwood CCA with
 * some minor tweaks to get better throughput and congestion
 * control.
 *
 * Copyright (c) 2013-2014, Rev Software, Inc.
 * All Rights Reserved.
 * This code is confidential and proprietary to Rev Software, Inc
 * and may only be used under a license from Rev Software Inc.
 */
#ifndef __TCP_REVSW_H__
#define __TCP_REVSW_H__

#include "tcp_revsw_sysctl.h"
#include "tcp_revsw_session_db.h"

#define TCP_REVSW_LOCALHOST 0x100007f

#define TCP_REVSW_RTT_MIN   (HZ/20)     /* 50ms */
#define TCP_REVSW_INIT_RTT  (20*HZ)     /* maybe too conservative?! */
#define BICTCP_BETA_SCALE    1024	/* Scale factor beta calculation
					 * max_cwnd = snd_cwnd * beta
					 */

#define BICTCP_HZ     10  /* BIC HZ 2^10 = 1024 */

/* Two methods of hybrid slow start */
#define HYSTART_ACK_TRAIN		0x1
#define HYSTART_DELAY			0x2

static inline bool
tcp_revsw_handle_nagle_test(struct sock *sk, struct sk_buff *skb,
			    unsigned int mss_now, int nonagle)
{
	struct tcp_sock *tp = tcp_sk(sk);
	bool minscheck;
	unsigned int mss = mss_now;

	if (nonagle & TCP_NAGLE_PUSH)
		return true;

	/* Don't use the nagle rule for urgent data (or for the final FIN). */
	if ((tp->snd_una != tp->snd_up) ||
	    (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN))
		return true;

	minscheck = after(tp->snd_sml, tp->snd_una) &&
		    !after(tp->snd_sml, tp->snd_nxt);

	if (tcp_revsw_sysctls.disable_nagle_mss)
		mss = tcp_revsw_sysctls.packet_size;

	if (!((skb->len < mss) && ((nonagle & TCP_NAGLE_CORK) ||
	    (!nonagle && tp->packets_out && minscheck))))
		return true;

	return false;
}

static void tcp_revsw_initial_rwn(struct sock *sk, u8 bko_level)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 rwn = tp->snd_wnd;
	u32 multiplier = 1;

	if (rwn < REVSW_LARGE_RWND_SIZE)
		multiplier = tcp_revsw_sysctls.sm_rcv_wnd;
	else if (rwn < (REVSW_LARGE_RWND_SIZE * 2))
		multiplier = tcp_revsw_sysctls.lrg_rcv_wnd;

	if (bko_level)
		multiplier = 1;

	tp->snd_wnd = rwn * multiplier;
}

static void tcp_revsw_initial_cwn(struct sock *sk, u8 bko_level)
{
	const struct inet_sock *inet = inet_sk(sk);
	int act_cnt = tcp_session_get_act_cnt(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	u32 rwn = tp->snd_wnd;
	u32 cwn;

	if (tcp_revsw_sysctls.cong_wnd == 0)
		cwn = rwn / tcp_revsw_sysctls.packet_size;
	else
		cwn = tcp_revsw_sysctls.cong_wnd;

	/*
	 * Ensure that the initial congestion window is not larger
	 * than the configured maximum.
	 */
	if (cwn > tcp_revsw_sysctls.max_init_cwnd)
		cwn = tcp_revsw_sysctls.max_init_cwnd;

	/*
	 * Make sure to not include this session in the active count
	 */
	if (act_cnt)
		act_cnt--;

	/*
	 * If there are existing active connections to the same IP
	 * address then reduce the initial congestion window by the
	 * configured percentage.  Applies to all ip addresses except
	 * the TCP_REVSW_LOCALHOST address.
	 */
	if (act_cnt && (inet->inet_daddr != TCP_REVSW_LOCALHOST) &&
	    tcp_revsw_sysctls.active_scale)
		cwn = (cwn * tcp_revsw_sysctls.active_scale) / 100;

	if (bko_level)
		cwn /= bko_level;

	/*
	 * Make sure we have an initial congestion window no less than
	 * standard TCP.
	 */
	if (cwn < TCP_INIT_CWND)
		cwn = TCP_INIT_CWND;

	tp->snd_cwnd = cwn;
}

static inline void tcp_revsw_syn_post_config(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u8 cca_bko = tcp_session_get_backoff_level(sk);
	int sndmem = SKB_TRUESIZE(tp->rx_opt.mss_clamp + MAX_TCP_HEADER);

	tcp_revsw_initial_rwn(sk, cca_bko);
	tcp_revsw_initial_cwn(sk, cca_bko);

	sndmem *= tp->snd_cwnd;
	if (sk->sk_sndbuf < sndmem)
		sk->sk_sndbuf = min(sndmem, sysctl_tcp_wmem[2]);
}

#endif /* __TCP_REVSW_H__ */

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

/*
 * @tcp_revsw_division
 * This function provides a means of performing integer division 
 * without using the division operator.  This is to be used in 
 * function where we may experience bugs complaining about attempts
 * to schedule functions during an atomic action.
 */
static inline u32 tcp_revsw_division(u32 dividend, u32 divisor)
{
	u32 denom = divisor;
	u32 tmp = 1;
	u32 answer = 0;

	if (denom > dividend)
		return 0;

	if (denom == dividend)
		return 1;

	while (denom <= dividend) {
		denom <<= 1;
		tmp <<= 1;
	}

	denom >>= 1;
	tmp >>= 1;

	while (tmp != 0) {
		if (dividend >= denom) {
			dividend -= denom;
			answer |= tmp;
		}
		tmp >>= 1;
		denom >>= 1;
	}

	return answer;
}

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
	if ((tp->snd_una != tp->snd_up) || (TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN))
		return true;

	minscheck = after(tp->snd_sml, tp->snd_una) &&
		    !after(tp->snd_sml, tp->snd_nxt);

	if (revsw_disable_nagle_mss)
		mss = revsw_packet_size;

	if (!((skb->len < mss) && ((nonagle & TCP_NAGLE_CORK) ||
	    (!nonagle && tp->packets_out && minscheck))))
		return true;

	return false;
}

static inline void tcp_revsw_syn_post_config(struct sock *sk)
{
	int act_cnt = tcp_session_get_act_cnt(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	const struct inet_sock *inet = inet_sk(sk);

	if (tp->snd_wnd < REVSW_LARGE_RWND_SIZE)
		tp->snd_wnd *= revsw_sm_rcv_wnd;
	else if (tp->snd_wnd < (REVSW_LARGE_RWND_SIZE * 2))
		tp->snd_wnd *= revsw_lrg_rcv_wnd;

 	if (revsw_cong_wnd == 0)
		tp->snd_cwnd = tcp_revsw_division(tp->snd_wnd,
						  revsw_packet_size);
 	else
		tp->snd_cwnd = revsw_cong_wnd;

	/*
	 * Ensure that the initial congestion window is not larger
	 * than the configured maximum.
	 */
	if (tp->snd_cwnd > revsw_max_init_cwnd)
		tp->snd_cwnd = revsw_max_init_cwnd;

	/*
	 * If there are existing active connections to the same IP 
	 * address then reduce the initial congestion window by the
	 * configured percentage.  Applies to all ip addresses except
	 * the TCP_REVSW_LOCALHOST address.
	 */
	if (act_cnt && (inet->inet_daddr != TCP_REVSW_LOCALHOST) &&
	    revsw_active_scale) 
		tp->snd_cwnd = (tp->snd_cwnd * revsw_active_scale) / 100;

	/*
	 * Make sure we have an initial congestion window no less than
	 * standard TCP.
	 */
	if (tp->snd_cwnd < TCP_INIT_CWND)
		tp->snd_cwnd = TCP_INIT_CWND;

	sk->sk_sndbuf = 3 * tp->snd_wnd;
}

#endif /* __TCP_REVSW_H__ */

/*
 *
 *   RevSw TCP Congestion Control Algorithm
 *
 * Starting off RevSw will be utilizing the Westwood CCA with
 * some minor tweaks to get better throughput and congestion
 * control.
 *
 */
#ifndef __TCP_REVSW_H__
#define __TCP_REVSW_H__

#include "tcp_revsw_sysctl.h"
#include "tcp_revsw_session_db.h"

/* TCP RevSw structure */
struct revsw {
	u32 cca_type;
	u32 bw_ns_est;  /* first bandwidth estimation..not smoothed 8) */
	u32 bw_est;     /* bandwidth estimate */
	u32 rtt_win_sx; /* here starts a new evaluation... */
	u32 bk;
	u32 snd_una;    /* used for evaluating the number of acked bytes */
	u32 cumul_ack;
	u32 accounted;
	u32 rtt;
	u32 rtt_min;    /* minimum observed RTT */
	u8 first_ack;   /* flag which infers that this is the first ack */
	u8 reset_rtt_min; /* Reset RTT min to next RTT sample*/
#define ACK_RATIO_SHIFT	4
#define ACK_RATIO_LIMIT (32u << ACK_RATIO_SHIFT)
	u32 cnt;        /* increase cwnd by 1 after ACKs */
	u32 ack_cnt;
	u32 last_cwnd;
	u32 last_time;
	u32 delay_min;
	u32 epoch_start;
	u32 bic_K;
	u32 bic_origin_point;
	u32 last_max_cwnd;
	u32 tcp_cwnd;
	u16 delayed_ack;
};

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
	u32 tmp;

	if (tp->snd_wnd < REVSW_LARGE_RWND_SIZE)
		tp->snd_wnd *= revsw_sm_rcv_wnd;
	else if (tp->snd_wnd < (REVSW_LARGE_RWND_SIZE * 2))
		tp->snd_wnd *= revsw_lrg_rcv_wnd;

 	if (revsw_cong_wnd == 0)
		tp->snd_cwnd = tcp_revsw_division(tp->snd_wnd,
						  revsw_packet_size);
 	else
		tp->snd_cwnd = revsw_cong_wnd;

	if (act_cnt) {
		tmp = tcp_revsw_division(100, revsw_active_scale);
		tp->snd_cwnd = tcp_revsw_division(tp->snd_wnd, tmp); 
	}

	/*
	 * Make sure we have an initial congestion window no less than
	 * standard TCP but also not too large so as to always result
	 * in SACKs and retransmissions.
	 */
	if (tp->snd_cwnd < REVSW_INIT_CWND_MIN)
		tp->snd_cwnd = REVSW_INIT_CWND_MIN;
	else if (tp->snd_cwnd > revsw_max_init_cwnd)
		tp->snd_cwnd = revsw_max_init_cwnd;

	sk->sk_sndbuf = 3 * tp->snd_wnd;
}

#endif /* __TCP_REVSW_H__ */

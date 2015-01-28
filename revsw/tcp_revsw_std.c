/*
 *
 *   Standard RevSw TCP Congestion Control Algorithm
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
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/inet_diag.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <net/tcp.h>
#include "tcp_revsw_wrapper.h"
#include "tcp_revsw_session_db.h"

#define TCP_REVSW_RTT_MIN   (HZ/20)	/* 50ms */
#define TCP_REVSW_INIT_RTT  (20*HZ)	/* maybe too conservative?! */
#define BICTCP_BETA_SCALE    1024	/* Scale factor beta calculation
									 * max_cwnd = snd_cwnd * beta
									 */

#define BICTCP_HZ     10  /* BIC HZ 2^10 = 1024 */


/* TCP RevSw structure */
struct revsw_std {
	u32 bw_ns_est;  /* first bandwidth estimation..not smoothed 8) */
	u32 bw_est;     /* bandwidth estimate */
	u32 rtt_win_sx; /* here starts a new evaluation... */
	u32 bk;
	u32 snd_una;    /* used for evaluating the number of acked bytes */
	u32 cumul_ack;
	u32 accounted;
	u32 rtt;
	u32 rtt_min;    /* minimum observed RTT */
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
	u8 first_ack;   /* flag which infers that this is the first ack */
	u8 reset_rtt_min; /* Reset RTT min to next RTT sample*/
};

static int fast_convergence __read_mostly = 1;
static int beta __read_mostly = 717;
static int bic_scale __read_mostly = 41;
static int tcp_friendliness __read_mostly = 1;

static u32 cube_rtt_scale __read_mostly;
static u32 beta_scale __read_mostly;
static u64 cube_factor __read_mostly;

/*
 * @tcp_revsw_std_get_ca
 *
 * The congestion control data stored within the sock is of
 * type struct tcp_revsw_cca_data.  Need to convert this to
 * the revsw_std type.
 */
static struct revsw_std *tcp_revsw_std_get_ca(const struct sock *sk)
{
	return (struct revsw_std *)tcp_session_get_cca_priv(sk);
}

/*
 * @tcp_revsw_std_init
 * This function initializes fields used in TCP Westwood+,
 * it is called after the initial SYN, so the sequence numbers
 * are correct but new passive connections we have no
 * information about RTTmin at this time so we simply set it to
 * TCP_REVSW_INIT_RTT. This value was chosen to be too conservative
 * since in this way we're sure it will be updated in a consistent
 * way as soon as possible. It will reasonably happen within the first
 * RTT period of the connection lifetime.
 */
static void tcp_revsw_std_init(struct sock *sk)
{
	struct revsw_std *ca;

	/*
	 * Make sure to add the session before initializing the data
	 * otherwise we will end up with a NULL pointer exception.
	 */
	tcp_session_add(sk, TCP_REVSW_CCA_STANDARD);

	ca = tcp_revsw_std_get_ca(sk);

	ca->bk = 0;
	ca->bw_ns_est = 0;
	ca->bw_est = 0;
	ca->accounted = 0;
	ca->cumul_ack = 0;
	ca->reset_rtt_min = 1;
	ca->rtt_min = ca->rtt = TCP_REVSW_INIT_RTT;
	ca->rtt_win_sx = tcp_time_stamp;
	ca->snd_una = tcp_sk(sk)->snd_una;
	ca->first_ack = 1;
	ca->cnt = 0;
	ca->last_max_cwnd = 0;
	ca->last_cwnd = 0;
	ca->last_time = 0;
	ca->bic_origin_point = 0;
	ca->bic_K = 0;
	ca->delay_min = 0;
	ca->epoch_start = 0;
	ca->delayed_ack = 2 << ACK_RATIO_SHIFT;
	ca->ack_cnt = 0;
	ca->tcp_cwnd = 0;
}

/*
 * @tcp_revsw_std_release
 *
 * This function setups up the deletion of the session database entry used by
 * this connection.
 */
static void tcp_revsw_std_release(struct sock *sk)
{
	tcp_session_delete(sk);
}

/*
 * @tcp_revsw_std_bw_rtt
 * Here limit is evaluated as Bw estimation*RTTmin (for obtaining it
 * in packets we use mss_cache). Rttmin is guaranteed to be >= 2
 * so avoids ever returning 0.
 */
static u32 tcp_revsw_std_bw_rtt(const struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct revsw_std *ca = tcp_revsw_std_get_ca(sk);
	u32 rtt;
	u32 tmp;

	/* Rev, go with RTT instead of RTT_min */
	rtt = ca->rtt;

	tmp = (ca->bw_est * rtt) / tp->mss_cache;

	return max_t(u32, tmp, 2);
}

/*
 * @tcp_revsw_std_ssthresh
 */
static u32 tcp_revsw_std_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct revsw_std *ca = tcp_revsw_std_get_ca(sk);
	u32 ssthresh_more;
	u32 ssthresh;

	ca->epoch_start = 0;

	/* Wmax and fast convergence */
	if (tp->snd_cwnd < ca->last_max_cwnd && fast_convergence) {
		ca->last_max_cwnd = tp->snd_cwnd * (BICTCP_BETA_SCALE + beta) /
				     (2 * BICTCP_BETA_SCALE);
	} else
		ca->last_max_cwnd = tp->snd_cwnd;

	/*
	 * Set High Threshold always
	 *
	 * (tp->snd_cwnd >> 1U) + (tp->snd_cwnd >> 2U); // 75%
	 */
	ssthresh_more = (tp->snd_cwnd * 90) / 100;
	ssthresh = tcp_revsw_std_bw_rtt(sk);

	return max(ssthresh, ssthresh_more);
}

/* 
 * @tcp_revsw_std_cubic_root
 * calculate the cubic root of x using a table lookup followed by one
 * Newton-Raphson iteration.
 * Avg err ~= 0.195%
 */
static u32 tcp_revsw_std_cubic_root(u64 a)
{
	u32 x;
	u32 b;
	u32 shift;

	/*
	 * cbrt(x) MSB values for x MSB values in [0..63].
	 * Precomputed then refined by hand - Willy Tarreau
	 *
	 * For x in [0..63],
	 *   v = cbrt(x << 18) - 1
	 *   cbrt(x) = (v[x] + 10) >> 6
	 */
	static const u8 v[] = {
		/* 0x00 */    0,   54,   54,   54,  118,  118,  118,  118,
		/* 0x08 */  123,  129,  134,  138,  143,  147,  151,  156,
		/* 0x10 */  157,  161,  164,  168,  170,  173,  176,  179,
		/* 0x18 */  181,  185,  187,  190,  192,  194,  197,  199,
		/* 0x20 */  200,  202,  204,  206,  209,  211,  213,  215,
		/* 0x28 */  217,  219,  221,  222,  224,  225,  227,  229,
		/* 0x30 */  231,  232,  234,  236,  237,  239,  240,  242,
		/* 0x38 */  244,  245,  246,  248,  250,  251,  252,  254,
	};

	b = fls64(a);
	if (b < 7) {
		/* a in [0..63] */
		return ((u32)v[(u32)a] + 35) >> 6;
	}

	b = ((b * 84) >> 8) - 1;
	shift = (a >> (b * 3));

	x = ((u32)(((u32)v[shift] + 10) << b)) >> 6;

	/*
	 * Newton-Raphson iteration
	 *                         2
	 * x    = ( 2 * x  +  a / x  ) / 3
	 *  k+1          k         k
	 */
	x = (2 * x + (u32)div64_u64(a, (u64)x * (u64)(x - 1)));
	x = ((x * 341) >> 10);
	return x;
}

/*
 * @tcp_revsw_std_cubic_growth
 * Compute congestion window to use.
 */
static void tcp_revsw_std_cubic_growth(struct revsw_std *ca, u32 cwnd)
{
	u32 delta, bic_target, max_cnt;
	u64 offs, t;

	ca->ack_cnt++;

	if (ca->last_cwnd == cwnd &&
	    (s32)(tcp_time_stamp - ca->last_time) <= HZ / 32)
		return;

	ca->last_cwnd = cwnd;
	ca->last_time = tcp_time_stamp;

	if (ca->epoch_start == 0) {
		ca->epoch_start = tcp_time_stamp;
		ca->ack_cnt = 1;
		ca->tcp_cwnd = cwnd;

		if (ca->last_max_cwnd <= cwnd) {
			ca->bic_K = 0;
			ca->bic_origin_point = cwnd;
		} else {
			/* Compute new K based on
			 * (wmax-cwnd) * (srtt>>3 / HZ) / c * 2^(3*bictcp_HZ)
			 */
			ca->bic_K = tcp_revsw_std_cubic_root(cube_factor
						* (ca->last_max_cwnd - cwnd));
			ca->bic_origin_point = ca->last_max_cwnd;
		}
	}

	/* cubic function - calc*/
	/* calculate c * time^3 / rtt,
	 *  while considering overflow in calculation of time^3
	 * (so time^3 is done by using 64 bit)
	 * and without the support of division of 64bit numbers
	 * (so all divisions are done by using 32 bit)
	 *  also NOTE the unit of those veriables
	 *	  time  = (t - K) / 2^bictcp_HZ
	 *	  c = bic_scale >> 10
	 * rtt  = (srtt >> 3) / HZ
	 * !!! The following code does not have overflow problems,
	 * if the cwnd < 1 million packets !!!
	 */

	t = (s32)(tcp_time_stamp - ca->epoch_start);
	t += msecs_to_jiffies(ca->delay_min >> 3);
	/* change the unit from HZ to bictcp_HZ */
	t <<= BICTCP_HZ;
	do_div(t, HZ);

	if (t < ca->bic_K)		/* t - K */
		offs = ca->bic_K - t;
	else
		offs = t - ca->bic_K;

	/* c/rtt * (t-K)^3 */
	delta = (cube_rtt_scale * offs * offs * offs) >> (10+3*BICTCP_HZ);
	if (t < ca->bic_K)
		bic_target = ca->bic_origin_point - delta;
	else
		bic_target = ca->bic_origin_point + delta;

	/* cubic function - calc bictcp_cnt*/
	if (bic_target > cwnd)
		ca->cnt = cwnd / (bic_target - cwnd);
	else
		ca->cnt = 100 * cwnd;

	/*
	 * The initial growth of cubic function may be too conservative
	 * when the available bandwidth is still unknown.
	 */
	if (ca->last_max_cwnd == 0 && ca->cnt > 20)
		ca->cnt = 20;	/* increase cwnd 5% per RTT */

	/* TCP Friendly */
	if (!tcp_friendliness) {
		u32 scale = beta_scale;
		delta = (cwnd * scale) >> 3;
		while (ca->ack_cnt > delta) {
			ca->ack_cnt -= delta;
			ca->tcp_cwnd++;
		}

		if (ca->tcp_cwnd > cwnd) {
			delta = ca->tcp_cwnd - cwnd;
			max_cnt = cwnd / delta;
			if (ca->cnt > max_cnt)
				ca->cnt = max_cnt;
		}
	}

	ca->cnt = (ca->cnt << ACK_RATIO_SHIFT) / ca->delayed_ack;
	if (ca->cnt == 0)
		ca->cnt = 1;
}

/*
 * @tcp_revsw_std_cong_avoid_ai
 * In theory Linear increase is
 * tp->snd_cwnd += 1 / tp->snd_cwnd (or alternative w)
 */
static void tcp_revsw_std_cong_avoid_ai(struct tcp_sock *tp, u32 w)
{
	if (tp->snd_cwnd_cnt >= w) {
		if (tp->snd_cwnd < tp->snd_cwnd_clamp)
			tp->snd_cwnd++;
		tp->snd_cwnd_cnt = 0;
	} else {
		tp->snd_cwnd_cnt += 1;
	}
}

static int tcp_revsw_slow_start(struct tcp_sock *tp, u32 acked)
{
	u8 multiplier = tcp_session_get_rwin((const struct sock *)tp) + 1;
	u32 cwnd = tp->snd_cwnd + (acked * multiplier);

	if (cwnd > tp->snd_ssthresh)
		cwnd = tp->snd_ssthresh + 1;

	acked -= cwnd - tp->snd_cwnd;
	tp->snd_cwnd = min(cwnd, tp->snd_cwnd_clamp);
	return acked;
}

/*
 * @tcp_revsw_std_cong_avoid
 */
static void tcp_revsw_std_cong_avoid(struct sock *sk, u32 ack, u32 acked, u32 in_flight)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct revsw_std *ca = tcp_revsw_std_get_ca(sk);

	if (!tcp_is_cwnd_limited(sk, in_flight))
		return;

	if (tp->snd_cwnd <= tp->snd_ssthresh)
		tcp_revsw_slow_start(tp, acked);
	else {
		tcp_revsw_std_cubic_growth(ca, tp->snd_cwnd);
		tcp_revsw_std_cong_avoid_ai(tp, ca->cnt);
	}
}

/*
 * @tcp_revsw_std_min_cwnd
 */
static u32 tcp_revsw_std_min_cwnd(const struct sock *sk)
{
	return tcp_revsw_std_bw_rtt(sk);
}

/*
 * @tcp_revsw_std_state
 */
static void tcp_revsw_std_state(struct sock *sk, u8 new_state)
{
	if (new_state == TCP_CA_Loss) {
		if ((tcp_time_stamp - tcp_sk(sk)->retrans_stamp) >
		    (tcp_sk(sk)->srtt >> 3)) {
			/*
			 * There has not been any loss in last RTT,
			 * cwnd need not be one.
			 *
			 * TODO: or call tcp_revsw_std_bw_rtt ?
			 */
			tcp_sk(sk)->snd_cwnd = max(tcp_sk(sk)->snd_ssthresh/2, 2U);
		} else {
			/* Must be really bad. */
			tcp_sk(sk)->snd_cwnd = 1;
		}
	}
}

/*
 * @tcp_revsw_std_do_filter
 * Low-pass filter. Implemented using constant coefficients.
 */
static inline u32 tcp_revsw_std_do_filter(u32 a, u32 b)
{
	return ((7 * a) + b) >> 3;
}

/*
 * @tcp_revsw_std_filter
 */
static void tcp_revsw_std_filter(struct revsw_std *ca, u32 delta)
{
	/*
	 * If the filter is empty fill it with the first
	 * sample of bandwidth
	 */
	if (ca->bw_ns_est == 0 && ca->bw_est == 0) {
		ca->bw_ns_est = ca->bk / delta;
		ca->bw_est = ca->bw_ns_est;
	} else {
		ca->bw_ns_est = tcp_revsw_std_do_filter(ca->bw_ns_est, ca->bk / delta);
		ca->bw_est = tcp_revsw_std_do_filter(ca->bw_est, ca->bw_ns_est);
	}
}

/*
 * @tcp_revsw_std_pkts_acked
 * Called after processing group of packets.
 * but all revsw needs is the last sample of srtt.
 */
static void tcp_revsw_std_pkts_acked(struct sock *sk, u32 cnt, s32 rtt)
{
	struct revsw_std *ca = tcp_revsw_std_get_ca(sk);

	if (rtt > 0)
		ca->rtt = usecs_to_jiffies(rtt);
}

/*
 * @tcp_revsw_std_update_window
 * It updates RTT evaluation window if it is the right moment to do
 * it. If so it calls filter for evaluating bandwidth.
 */
static void tcp_revsw_std_update_window(struct sock *sk)
{
	struct revsw_std *ca = tcp_revsw_std_get_ca(sk);
	struct tcp_session_info *info;

	s32 delta = tcp_time_stamp - ca->rtt_win_sx;

	/* Initialize ca->snd_una with the first acked sequence number in order
	 * to fix mismatch between tp->snd_una and ca->snd_una for the first
	 * bandwidth sample
	 */
	if (ca->first_ack) {
		ca->snd_una = tcp_sk(sk)->snd_una;
		ca->first_ack = 0;
	}

	/*
	 * See if a RTT-window has passed.
	 * Be careful since if RTT is less than
	 * 50ms we don't filter but we continue 'building the sample'.
	 * This minimum limit was chosen since an estimation on small
	 * time intervals is better to avoid...
	 * Obviously on a LAN we reasonably will always have
	 * right_bound = left_bound + REVSW_RTT_MIN
	 */
	if (ca->rtt && delta > max_t(u32, ca->rtt, TCP_REVSW_RTT_MIN)) {
		tcp_revsw_std_filter(ca, delta);

		ca->bk = 0;
		ca->rtt_win_sx = tcp_time_stamp;

		info = tcp_session_get_info_ptr(sk);
		if (info) {
			info->latency = ca->rtt;
			info->bandwidth = ca->bw_est;
		}
	}
}

/*
 * @tcp_revsw_std_update_rtt_min
 */
static void tcp_revsw_std_update_rtt_min(struct revsw_std *ca)
{
	if (ca->reset_rtt_min) {
		ca->rtt_min = ca->rtt;
		ca->reset_rtt_min = 0;
	} else
		ca->rtt_min = min(ca->rtt, ca->rtt_min);
}

/*
 * @tcp_revsw_std_acked_count
 * This function evaluates cumul_ack for evaluating bk in case of
 * delayed or partial acks.
 */
static u32 tcp_revsw_std_acked_count(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct revsw_std *ca = tcp_revsw_std_get_ca(sk);

	ca->cumul_ack = tp->snd_una - ca->snd_una;

	/* If cumul_ack is 0 this is a dupack since it's not moving
	 * tp->snd_una.
	 */
	if (!ca->cumul_ack) {
		ca->accounted += tp->mss_cache;
		ca->cumul_ack = tp->mss_cache;
	}

	if (ca->cumul_ack > tp->mss_cache) {
		/* Partial or delayed ack */
		if (ca->accounted >= ca->cumul_ack) {
			ca->accounted -= ca->cumul_ack;
			ca->cumul_ack = tp->mss_cache;
		} else {
			ca->cumul_ack -= ca->accounted;
			ca->accounted = 0;
		}
	}

	ca->snd_una = tp->snd_una;

	return ca->cumul_ack;
}

/*
 * @tcp_revsw_std_event
 */
static void tcp_revsw_std_event(struct sock *sk, enum tcp_ca_event event)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct revsw_std *ca = tcp_revsw_std_get_ca(sk);
	u32 ssthresh;

	switch (event) {
	case CA_EVENT_FAST_ACK:
			tcp_revsw_std_update_window(sk);

			ca->bk += tp->snd_una - ca->snd_una;
			ca->snd_una = tp->snd_una;
			tcp_revsw_std_update_rtt_min(ca);
		break;

	case CA_EVENT_COMPLETE_CWR:
			ssthresh = tcp_revsw_std_bw_rtt(sk);
			if (tp->snd_ssthresh < ssthresh)
				tp->snd_cwnd = tp->snd_ssthresh = ssthresh;
		break;

	case CA_EVENT_LOSS:
			ssthresh = tcp_revsw_std_bw_rtt(sk);
			tp->snd_ssthresh = max(ssthresh,
					       ((tp->snd_cwnd >> 1U) +
						(tp->snd_cwnd >> 2U)));

			/* Update RTT_min when next ack arrives */
			ca->reset_rtt_min = 1;
		break;

	case CA_EVENT_SLOW_ACK:
			tcp_revsw_std_update_window(sk);
			ca->bk += tcp_revsw_std_acked_count(sk);
			tcp_revsw_std_update_rtt_min(ca);
		break;

	default:
		/* don't care */
		break;
	}
}

/* 
 * @tcp_revsw_std_info
 * Extract info for TCP socket info provided via netlink. 
 */
static void tcp_revsw_std_info(struct sock *sk, u32 ext,
			      struct sk_buff *skb)
{
	const struct revsw_std *ca = tcp_revsw_std_get_ca(sk);

	if (ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
		struct tcpvegas_info info = {
			.tcpv_enabled = 1,
			.tcpv_rtt = jiffies_to_usecs(ca->rtt),
			.tcpv_minrtt = jiffies_to_usecs(ca->rtt_min),
		};

		nla_put(skb, INET_DIAG_VEGASINFO, sizeof(info), &info);
	}
}

/*
 * @tcp_revsw_std_set_nwin_size
 */
static void tcp_revsw_std_set_nwin_size(struct sock *sk, u32 nwin)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_session_info *info;

	info = tcp_session_get_info_ptr(sk);

	if ((info && info->quota_reached) || (nwin == 0) ||
	    (nwin > tp->snd_wnd))
		tp->snd_wnd = nwin;
}

/*
 * @tcp_revsw_std_get_cwnd_quota
 */
static int tcp_revsw_std_get_cwnd_quota(struct sock *sk, const struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_session_info *info;
	u32 in_flight, cwnd;
	u32 quota = 0;

	/* Don't be strict about the congestion window for the final FIN.  */
	if ((TCP_SKB_CB(skb)->tcp_flags & TCPHDR_FIN) &&
	    tcp_skb_pcount(skb) == 1) {
		quota = 1;
		goto exit;
	}

	in_flight = tcp_packets_in_flight(tp);
	cwnd = tp->snd_cwnd;
	if (in_flight < cwnd) {
		quota = cwnd - in_flight;
		goto exit;
	}

	info = tcp_session_get_info_ptr(sk);
	if (info)
		info->quota_reached = 1;

exit:
	return quota;
}

static struct tcp_congestion_ops tcp_revsw_std __read_mostly = {
	.flags		= TCP_CONG_RTT_STAMP,
	.init		= tcp_revsw_std_init,
	.release	= tcp_revsw_std_release,
	.ssthresh	= tcp_revsw_std_ssthresh,
	.cong_avoid	= tcp_revsw_std_cong_avoid,
	.min_cwnd	= tcp_revsw_std_min_cwnd,
	.set_state	= tcp_revsw_std_state,
	.cwnd_event	= tcp_revsw_std_event,
	.get_info	= tcp_revsw_std_info,
	.pkts_acked	= tcp_revsw_std_pkts_acked,
	.syn_post_config = tcp_revsw_generic_syn_post_config,
	.set_nwin_size = tcp_revsw_std_set_nwin_size,
	.handle_nagle_test = tcp_revsw_generic_handle_nagle_test,
	.get_cwnd_quota = tcp_revsw_std_get_cwnd_quota,
};

static void __init tcp_revsw_std_cca_init(void)
{
	BUILD_BUG_ON(sizeof(struct revsw_std) > TCP_CCA_PRIV_SIZE);

	beta_scale = 8 * (BICTCP_BETA_SCALE + beta) / 3 /
	(BICTCP_BETA_SCALE - beta);

	cube_rtt_scale = (bic_scale * 10);	/* 1024*c/rtt */

	/* calculate the "K" for (wmax-cwnd) = c/rtt * K^3
	 *  so K = cubic_root( (wmax-cwnd)*rtt/c )
	 * the unit of K is bictcp_HZ=2^10, not HZ
	 *
	 *  c = bic_scale >> 10
	 *  rtt = 100ms
	 *
	 * the following code has been designed and tested for
	 * cwnd < 1 million packets
	 * RTT < 100 seconds
	 * HZ < 1,000,00  (corresponding to 10 nano-second)
	 */

	/* 1/c * 2^2*bictcp_HZ * srtt */
	cube_factor = 1ull << (10+3*BICTCP_HZ); /* 2^40 */

	/* divide by bic_scale and by constant Srtt (100ms) */
	do_div(cube_factor, bic_scale * 10);
}

struct tcp_revsw_cca_entry tcp_revsw_std_cca  __read_mostly = {
	.revsw_cca = TCP_REVSW_CCA_STANDARD,
	.cca_init = tcp_revsw_std_cca_init,
	.cca_ops = &tcp_revsw_std,
	.session_ops = NULL,
};

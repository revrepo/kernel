/*
 *
 *   RevSw TCP Congestion Control Algorithm
 *
 * Starting off RevSw will be utilizing the Westwood CCA with
 * some minor tweaks to get better throughput and congestion
 * control.
 *
 */
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/inet_diag.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <net/tcp.h>
#include "tcp_revsw.h"
#include "tcp_revsw_sysctl.h"
#include "tcp_revsw_session_db.h"

static int fast_convergence __read_mostly = 1;
static int beta __read_mostly = 717;
static int bic_scale __read_mostly = 41;
static int tcp_friendliness __read_mostly = 1;

static u32 cube_rtt_scale __read_mostly;
static u32 beta_scale __read_mostly;
static u64 cube_factor __read_mostly;

/*
 * @tcp_revsw_init
 * This function initializes fields used in TCP Westwood+,
 * it is called after the initial SYN, so the sequence numbers
 * are correct but new passive connections we have no
 * information about RTTmin at this time so we simply set it to
 * TCP_REVSW_INIT_RTT. This value was chosen to be too conservative
 * since in this way we're sure it will be updated in a consistent
 * way as soon as possible. It will reasonably happen within the first
 * RTT period of the connection lifetime.
 */
static void tcp_revsw_init(struct sock *sk)
{
	struct revsw *w = inet_csk_ca(sk);

	w->bk = 0;
	w->bw_ns_est = 0;
	w->bw_est = 0;
	w->accounted = 0;
	w->cumul_ack = 0;
	w->reset_rtt_min = 1;
	w->rtt_min = w->rtt = TCP_REVSW_INIT_RTT;
	w->rtt_win_sx = tcp_time_stamp;
	w->snd_una = tcp_sk(sk)->snd_una;
	w->first_ack = 1;
	w->cnt = 0;
	w->last_max_cwnd = 0;
	w->last_cwnd = 0;
	w->last_time = 0;
	w->bic_origin_point = 0;
	w->bic_K = 0;
	w->delay_min = 0;
	w->epoch_start = 0;
	w->delayed_ack = 2 << ACK_RATIO_SHIFT;
	w->ack_cnt = 0;
	w->tcp_cwnd = 0;

	tcp_session_start(sk);
}

/*
 * @tcp_revsw_release
 *
 * This function setups up the deletion of the session database entry used by
 * this connection.
 */
static void tcp_revsw_release(struct sock *sk)
{
	tcp_session_delete(sk);
}

/*
 * TCP Westwood
 * Here limit is evaluated as Bw estimation*RTTmin (for obtaining it
 * in packets we use mss_cache). Rttmin is guaranteed to be >= 2
 * so avoids ever returning 0.
 */
static u32 tcp_revsw_bw_rtt(const struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct revsw *w = inet_csk_ca(sk);
	u32 rtt;

	/* Rev, go with RTT instead of RTT_min */
	rtt = w->rtt;

	return max_t(u32, (w->bw_est * rtt) / tp->mss_cache, 2);
}

static u32 tcp_revsw_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct revsw *ca = inet_csk_ca(sk);
	u32 ssthresh_more;
	u32 ssthresh;

	ca->epoch_start = 0;

	/* Wmax and fast convergence */
	if (tp->snd_cwnd < ca->last_max_cwnd && fast_convergence)
		ca->last_max_cwnd = (tp->snd_cwnd * (BICTCP_BETA_SCALE + beta))
		/ (2 * BICTCP_BETA_SCALE);
	else
		ca->last_max_cwnd = tp->snd_cwnd;

	/*
	 * Set High Threshold always
	 *
	 * (tp->snd_cwnd >> 1U) + (tp->snd_cwnd >> 2U); // 75%
	 */
	ssthresh_more = (tp->snd_cwnd * 0.9);
	ssthresh = tcp_revsw_bw_rtt(sk);

	return max(ssthresh, ssthresh_more);
}

/* calculate the cubic root of x using a table lookup followed by one
 * Newton-Raphson iteration.
 * Avg err ~= 0.195%
 */
static u32 tcp_revsw_cubic_root(u64 a)
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
 * Compute congestion window to use.
 */
static inline void tcp_revsw_cubic_growth(struct revsw *ca, u32 cwnd)
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
			ca->bic_K = tcp_revsw_cubic_root(cube_factor
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
 * In theory Linear increase is
 * tp->snd_cwnd += 1 / tp->snd_cwnd (or alternative w)
 */
void tcp_revsw_cong_avoid_ai(struct tcp_sock *tp, u32 w)
{
	if (tp->snd_cwnd_cnt >= w) {
		if (tp->snd_cwnd < tp->snd_cwnd_clamp)
			tp->snd_cwnd++;
		tp->snd_cwnd_cnt = 0;
	} else {
		tp->snd_cwnd_cnt += 1;
	}
}

static void tcp_revsw_increase_cwin(struct sock *sk, u32 ack, u32 in_flight)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct revsw *ca = inet_csk_ca(sk);

	if (!tcp_is_cwnd_limited(sk, in_flight))
		return;

	/* In "safe" area, increase. */
	if (tp->snd_cwnd <= tp->snd_ssthresh)
		tcp_slow_start(tp);
	/* In dangerous area, increase slowly. */
	else {
		tcp_revsw_cubic_growth(ca, tp->snd_cwnd);
		tcp_revsw_cong_avoid_ai(tp, ca->cnt);
	}
}

static void tcp_revsw_cong_avoid(struct sock *sk, u32 ack, u32 in_flight)
{
	tcp_revsw_increase_cwin(sk, ack, in_flight);
}

u32 tcp_revsw_min_cwnd(const struct sock *sk)
{
	return tcp_revsw_bw_rtt(sk);
}

static void tcp_revsw_state(struct sock *sk, u8 new_state)
{
	if (new_state == TCP_CA_Loss) {
		if ((tcp_time_stamp - tcp_sk(sk)->retrans_stamp) >
		    (tcp_sk(sk)->srtt >> 3)) {
			/*
			 * There has not been any loss in last RTT,
			 * cwnd need not be one.
			 *
			 * TODO: or call tcp_revsw_bw_rtt ?
			 */
			tcp_sk(sk)->snd_cwnd = max(tcp_sk(sk)->snd_ssthresh/2,
						   2U);
		} else {
			/* Must be really bad. */
			tcp_sk(sk)->snd_cwnd = 1;
		}
	}
}

/*
 * @revsw_do_filter
 * Low-pass filter. Implemented using constant coefficients.
 */
static inline u32 tcp_revsw_do_filter(u32 a, u32 b)
{
	return ((7 * a) + b) >> 3;
}

static void tcp_revsw_filter(struct revsw *w, u32 delta)
{
	/*
	 * If the filter is empty fill it with the first
	 * sample of bandwidth
	 */
	if (w->bw_ns_est == 0 && w->bw_est == 0) {
		w->bw_ns_est = w->bk / delta;
		w->bw_est = w->bw_ns_est;
	} else {
		w->bw_ns_est = tcp_revsw_do_filter(w->bw_ns_est, w->bk / delta);
		w->bw_est = tcp_revsw_do_filter(w->bw_est, w->bw_ns_est);
	}
}

/*
 * @revsw_pkts_acked
 * Called after processing group of packets.
 * but all revsw needs is the last sample of srtt.
 */
static void tcp_revsw_pkts_acked(struct sock *sk, u32 cnt, s32 rtt)
{
	struct revsw *w = inet_csk_ca(sk);

	if (rtt > 0)
		w->rtt = usecs_to_jiffies(rtt);
}

/*
 * @revsw_update_window
 * It updates RTT evaluation window if it is the right moment to do
 * it. If so it calls filter for evaluating bandwidth.
 */
static void tcp_revsw_update_window(struct sock *sk)
{
	struct revsw *w = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_session_entry *session = tp->session_info;

	s32 delta = tcp_time_stamp - w->rtt_win_sx;

	/* Initialize w->snd_una with the first acked sequence number in order
	 * to fix mismatch between tp->snd_una and w->snd_una for the first
	 * bandwidth sample
	 */
	if (w->first_ack) {
		w->snd_una = tcp_sk(sk)->snd_una;
		w->first_ack = 0;
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
	if (w->rtt && delta > max_t(u32, w->rtt, TCP_REVSW_RTT_MIN)) {
		tcp_revsw_filter(w, delta);

		w->bk = 0;
		w->rtt_win_sx = tcp_time_stamp;

		if (session) {
			session->info.latency = w->rtt;
			session->info.bandwidth = w->bw_est;
		}
	}
}

static inline void tcp_revsw_update_rtt_min(struct revsw *w)
{
	if (w->reset_rtt_min) {
		w->rtt_min = w->rtt;
		w->reset_rtt_min = 0;
	} else
		w->rtt_min = min(w->rtt, w->rtt_min);
}

/*
 * @revsw_fast_bw
 * It is called when we are in fast path. In particular it is called when
 * header prediction is successful. In such case in fact update is
 * straight forward and doesn't need any particular care.
 */
static inline void tcp_revsw_fast_bw(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct revsw *w = inet_csk_ca(sk);

	tcp_revsw_update_window(sk);

	w->bk += tp->snd_una - w->snd_una;
	w->snd_una = tp->snd_una;
	tcp_revsw_update_rtt_min(w);
}

/*
 * @revsw_acked_count
 * This function evaluates cumul_ack for evaluating bk in case of
 * delayed or partial acks.
 */
static inline u32 tcp_revsw_acked_count(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct revsw *w = inet_csk_ca(sk);

	w->cumul_ack = tp->snd_una - w->snd_una;

	/* If cumul_ack is 0 this is a dupack since it's not moving
	 * tp->snd_una.
	 */
	if (!w->cumul_ack) {
		w->accounted += tp->mss_cache;
		w->cumul_ack = tp->mss_cache;
	}

	if (w->cumul_ack > tp->mss_cache) {
		/* Partial or delayed ack */
		if (w->accounted >= w->cumul_ack) {
			w->accounted -= w->cumul_ack;
			w->cumul_ack = tp->mss_cache;
		} else {
			w->cumul_ack -= w->accounted;
			w->accounted = 0;
		}
	}

	w->snd_una = tp->snd_una;

	return w->cumul_ack;
}

static void tcp_revsw_event(struct sock *sk, enum tcp_ca_event event)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct revsw *w = inet_csk_ca(sk);
	u32 ssthresh;

	switch (event) {
	case CA_EVENT_FAST_ACK:
		tcp_revsw_fast_bw(sk);
		break;

	case CA_EVENT_COMPLETE_CWR:
			ssthresh = tcp_revsw_bw_rtt(sk);
			if (tp->snd_ssthresh < ssthresh)
				tp->snd_cwnd = tp->snd_ssthresh = ssthresh;
		break;

	case CA_EVENT_LOSS:
			ssthresh = tcp_revsw_bw_rtt(sk);
			tp->snd_ssthresh = max(ssthresh,
					       ((tp->snd_cwnd >> 1U) +
						(tp->snd_cwnd >> 2U)));

			/* Update RTT_min when next ack arrives */
			w->reset_rtt_min = 1;
		break;

	case CA_EVENT_SLOW_ACK:
			tcp_revsw_update_window(sk);
			w->bk += tcp_revsw_acked_count(sk);
			tcp_revsw_update_rtt_min(w);
		break;

	default:
		/* don't care */
		break;
	}
}


/* Extract info for Tcp socket info provided via netlink. */
static void tcp_revsw_info(struct sock *sk, u32 ext,
			      struct sk_buff *skb)
{
	const struct revsw *ca = inet_csk_ca(sk);
	if (ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
		struct tcpvegas_info info = {
			.tcpv_enabled = 1,
			.tcpv_rtt = jiffies_to_usecs(ca->rtt),
			.tcpv_minrtt = jiffies_to_usecs(ca->rtt_min),
		};

		nla_put(skb, INET_DIAG_VEGASINFO, sizeof(info), &info);
	}
}

static void tcp_revsw_set_nwin_size(struct sock *sk, u32 nwin)
{
	struct tcp_session_entry *session;
 	struct tcp_sock *tp = tcp_sk(sk);
 
	session = tp->session_info;

	if ((session && session->info.quota_reached) || (nwin == 0) ||
	    (nwin > tp->snd_wnd))
		tp->snd_wnd = nwin;
}

static int tcp_revsw_get_cwnd_quota(struct sock *sk, const struct sk_buff *skb)
{
	struct tcp_session_entry *session;
	struct tcp_sock *tp = tcp_sk(sk);
	u32 in_flight, cwnd;
	u32 quota = 0;

	session = tp->session_info;

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

	if (session)
		session->info.quota_reached = 1;

exit:
	return quota;
}

static struct tcp_congestion_ops tcp_revsw __read_mostly = {
	.flags		= TCP_CONG_RTT_STAMP,
	.init		= tcp_revsw_init,
	.release	= tcp_revsw_release,
	.ssthresh	= tcp_revsw_ssthresh,
	.cong_avoid	= tcp_revsw_cong_avoid,
	.min_cwnd	= tcp_revsw_min_cwnd,
	.set_state	= tcp_revsw_state,
	.cwnd_event	= tcp_revsw_event,
	.get_info	= tcp_revsw_info,
	.pkts_acked	= tcp_revsw_pkts_acked,
	.syn_post_config = tcp_revsw_syn_post_config,
	.set_nwin_size = tcp_revsw_set_nwin_size,
	.handle_nagle_test = tcp_revsw_handle_nagle_test,
	.get_session_info = tcp_session_get_info,
	.get_cwnd_quota = tcp_revsw_get_cwnd_quota,

	.owner		= THIS_MODULE,
	.name		= "revsw"
};

static int __init tcp_revsw_register(void)
{
	BUILD_BUG_ON(sizeof(struct revsw) > ICSK_CA_PRIV_SIZE);

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

	return tcp_register_congestion_control(&tcp_revsw);
}

static void __exit tcp_revsw_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_revsw);
}

module_init(tcp_revsw_register);
module_exit(tcp_revsw_unregister);

MODULE_AUTHOR("Tom Kavanagh");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP RevSw");

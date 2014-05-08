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

#include <net/tcp.h>

/* TCP RevSw SYSCTL support */
#define REVSW_RCV_WND_MIN	6000
#define REVSW_RCV_WND_MAX	393216
#define REVSW_RCV_WND_DEFAULT	131072
#define REVSW_CONG_WND_MIN	10
#define REVSW_CONG_WND_MAX	200
#define REVSW_CONG_WND_DEFAULT	100
#define REVSW_RTO_DEFAULT	63

static int revsw_rcv_wnd_min __read_mostly = REVSW_RCV_WND_MIN;
static int revsw_rcv_wnd_max __read_mostly = REVSW_RCV_WND_MAX;
static int revsw_rcv_wnd __read_mostly = REVSW_RCV_WND_DEFAULT;

static int revsw_cong_wnd_min __read_mostly = REVSW_CONG_WND_MIN;
static int revsw_cong_wnd_max __read_mostly = REVSW_CONG_WND_MAX;
static int revsw_cong_wnd __read_mostly = REVSW_CONG_WND_DEFAULT;

static int revsw_rto __read_mostly __read_mostly = REVSW_RTO_DEFAULT;

static struct ctl_table_header *revsw_ctl_table_hdr;

static struct ctl_table revsw_ctl_table[] = {
	{
		.procname = "revsw_rcv_wnd",
		.maxlen = sizeof(int),
		.mode = 0644,
		.data = &revsw_rcv_wnd,
		.proc_handler = &proc_dointvec_minmax,
		.extra1 = &revsw_rcv_wnd_min,
		.extra2 = &revsw_rcv_wnd_max,
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
		.procname = "revsw_rto",
		.maxlen = sizeof(int),
		.mode = 0644,
		.data = &revsw_rto,
		.proc_handler = &proc_dointvec_ms_jiffies,
	},
	{}
};

/* TCP RevSw structure */
struct revsw {
	u32    bw_ns_est;  /* first bandwidth estimation..not too smoothed 8) */
	u32    bw_est;     /* bandwidth estimate */
	u32    rtt_win_sx; /* here starts a new evaluation... */
	u32    bk;
	u32    snd_una;    /* used for evaluating the number of acked bytes */
	u32    cumul_ack;
	u32    accounted;
	u32    rtt;
	u32    rtt_min;    /* minimum observed RTT */
	u8     first_ack;  /* flag which infers that this is the first ack */
	u8     reset_rtt_min; /* Reset RTT min to next RTT sample*/
};


/* TCP RevSw functions and constants */
#define TCP_REVSW_RTT_MIN   (HZ/20)	/* 50ms */
#define TCP_REVSW_INIT_RTT  (20*HZ)	/* maybe too conservative?! */

/*
 * @tcp_revsw_create
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
}

/*
 * @revsw_do_filter
 * Low-pass filter. Implemented using constant coefficients.
 */
static inline u32 revsw_do_filter(u32 a, u32 b)
{
	return ((7 * a) + b) >> 3;
}

static void revsw_filter(struct revsw *w, u32 delta)
{
	/* If the filter is empty fill it with the first sample of bandwidth  */
	if (w->bw_ns_est == 0 && w->bw_est == 0) {
		w->bw_ns_est = w->bk / delta;
		w->bw_est = w->bw_ns_est;
	} else {
		w->bw_ns_est = revsw_do_filter(w->bw_ns_est, w->bk / delta);
		w->bw_est = revsw_do_filter(w->bw_est, w->bw_ns_est);
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
static void revsw_update_window(struct sock *sk)
{
	struct revsw *w = inet_csk_ca(sk);
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
		revsw_filter(w, delta);

		w->bk = 0;
		w->rtt_win_sx = tcp_time_stamp;
	}
}

static inline void update_rtt_min(struct revsw *w)
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
static inline void revsw_fast_bw(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct revsw *w = inet_csk_ca(sk);

	revsw_update_window(sk);

	w->bk += tp->snd_una - w->snd_una;
	w->snd_una = tp->snd_una;
	update_rtt_min(w);
}

/*
 * @revsw_acked_count
 * This function evaluates cumul_ack for evaluating bk in case of
 * delayed or partial acks.
 */
static inline u32 revsw_acked_count(struct sock *sk)
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


/*
 * TCP Westwood
 * Here limit is evaluated as Bw estimation*RTTmin (for obtaining it
 * in packets we use mss_cache). Rttmin is guaranteed to be >= 2
 * so avoids ever returning 0.
 */
static u32 tcp_revsw_bw_rttmin(const struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct revsw *w = inet_csk_ca(sk);
	return max_t(u32, (w->bw_est * w->rtt_min) / tp->mss_cache, 2);
}

static void tcp_revsw_event(struct sock *sk, enum tcp_ca_event event)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct revsw *w = inet_csk_ca(sk);

	switch (event) {
	case CA_EVENT_FAST_ACK:
		revsw_fast_bw(sk);
		break;

	case CA_EVENT_COMPLETE_CWR:
		tp->snd_cwnd = tp->snd_ssthresh = tcp_revsw_bw_rttmin(sk);
		break;

	case CA_EVENT_LOSS:
		tp->snd_ssthresh = tcp_revsw_bw_rttmin(sk);
		/* Update RTT_min when next ack arrives */
		w->reset_rtt_min = 1;
		break;

	case CA_EVENT_SLOW_ACK:
		revsw_update_window(sk);
		w->bk += revsw_acked_count(sk);
		update_rtt_min(w);
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

static void tcp_revsw_syn_post_config(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	/*
	 * Modify the congestion and send windows.  Also fix the
	 * sndbuf size.  Will be changed to use sysctls when they
	 * are available.
	 */
	tp->snd_wnd = revsw_rcv_wnd;
	tp->snd_cwnd = revsw_cong_wnd;
	sk->sk_sndbuf = 3 * tp->snd_wnd;
}

static void tcp_revsw_set_nwin_size(struct sock *sk, u32 nwin)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if ((nwin > revsw_cong_wnd) || (nwin == 0))
		tp->snd_wnd = nwin;
}

static bool 
tcp_revsw_handle_nagle_test(struct sock *sk, struct sk_buff *skb, 
			    unsigned int mss_now, int nonagle)
{
	return true;
}

static struct tcp_congestion_ops tcp_revsw __read_mostly = {
	.init		= tcp_revsw_init,
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= tcp_reno_cong_avoid,
	.min_cwnd	= tcp_revsw_bw_rttmin,
	.cwnd_event	= tcp_revsw_event,
	.get_info	= tcp_revsw_info,
	.pkts_acked	= tcp_revsw_pkts_acked,
	.syn_post_config = tcp_revsw_syn_post_config,
	.set_nwin_size = tcp_revsw_set_nwin_size,
	.handle_nagle_test = tcp_revsw_handle_nagle_test,

	.owner		= THIS_MODULE,
	.name		= "revsw"
};

static int __init tcp_revsw_register(void)
{
	BUILD_BUG_ON(sizeof(struct revsw) > ICSK_CA_PRIV_SIZE);

	revsw_ctl_table_hdr = register_sysctl("revsw", revsw_ctl_table);
	if (!revsw_ctl_table_hdr)
		return -EFAULT;

	return tcp_register_congestion_control(&tcp_revsw);
}

static void __exit tcp_revsw_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_revsw);
	unregister_sysctl_table(revsw_ctl_table_hdr);
}

module_init(tcp_revsw_register);
module_exit(tcp_revsw_unregister);

MODULE_AUTHOR("Tom Kavanagh");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP RevSw");

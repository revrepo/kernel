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

/********************************************************************
 *
 * RevSw sysctl support
 *
 ********************************************************************/
static int revsw_rcv_wnd_min __read_mostly = REVSW_RCV_WND_MIN;
static int revsw_rcv_wnd_max __read_mostly = REVSW_RCV_WND_MAX;
static int revsw_rcv_wnd __read_mostly = REVSW_RCV_WND_DEFAULT;

static int revsw_cong_wnd_min __read_mostly = REVSW_CONG_WND_MIN;
static int revsw_cong_wnd_max __read_mostly = REVSW_CONG_WND_MAX;
static int revsw_cong_wnd __read_mostly = REVSW_CONG_WND_DEFAULT;

static int revsw_tcp_session_ttl_min __read_mostly = 1;
static int revsw_tcp_session_ttl_max __read_mostly = TCP_SESSION_TTL_MAX;
static int revsw_tcp_session_ttl __read_mostly = TCP_SESSION_TTL_DEFAULT;

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
	{
		.procname       = "revsw_tcp_session_ttl",
		.data           = &revsw_tcp_session_ttl,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &revsw_tcp_session_ttl_min,
		.extra2		= &revsw_tcp_session_ttl_max,
	},
	{}
};
/********************************************************************
 * End RevSw sysctl support
 ********************************************************************/

/********************************************************************
 *
 * RevSw TCP Session Database
 *
 ********************************************************************/
static spinlock_t tcpsi_hash_lock;
static struct tcp_session_info_hash *tcpsi_hash;

static int tcp_session_hash_init(void)
{
	__u64 i;

	spin_lock_init(&tcpsi_hash_lock);

	tcpsi_hash = kzalloc(TCP_SESSION_HASH_SIZE * sizeof(*tcpsi_hash),
			     GFP_KERNEL);
	if (!tcpsi_hash)
		return -ENOMEM;

	for (i = 0; i < TCP_SESSION_HASH_SIZE; i++) {
		spin_lock_init(&tcpsi_hash[i].lock);
		INIT_HLIST_HEAD(&tcpsi_hash[i].hlist);
	}

	return 0;
}

static void tcp_session_hash_cleanup(void)
{
	__u64 i;
	struct tcp_session_info_hash *thash;
	struct tcp_session_entry *session;
	struct hlist_node *tmp;

	for (i = 0; i < TCP_SESSION_HASH_SIZE; i++) {
		thash = &tcpsi_hash[i];
		if (hlist_empty(&thash->hlist))
			continue;

		spin_lock_bh(&thash->lock);

		hlist_for_each_entry_safe(session, tmp, &thash->hlist, node) {
			hlist_del(&session->node);
			cancel_delayed_work_sync(&session->work);
			kfree(session);
		}

		spin_unlock_bh(&thash->lock);
	}

	kfree(tcpsi_hash);
}

static void tcp_session_delete_work_handler(struct work_struct *work)
{
	struct tcp_session_entry *session = container_of(to_delayed_work(work),
						struct tcp_session_entry,
						work);
	struct tcp_session_info_hash *thash;
	__u32 hash;

	if (hlist_unhashed(&session->node))
		return;

	hash = hash_32((session->addr & TCP_SESSION_KEY_BITMASK),
			TCP_SESSION_HASH_BITS);

	thash = &tcpsi_hash[hash];

	spin_lock_bh(&thash->lock);
	hlist_del(&session->node);
	spin_unlock_bh(&thash->lock);
	kfree(session);
}

static void tcp_session_add(struct tcp_sock *tp)
{
	struct sock *sk = (struct sock *)tp;
	const struct inet_sock *inet = inet_sk(sk);
	__u32 addr = (__force __u32)inet->inet_daddr;
	__u16 port = (__force __u16)inet->inet_dport;
	struct tcp_session_info_hash *thash;
	struct tcp_session_entry *session;
	__u32 hash;

	session = kzalloc(sizeof(*session), GFP_KERNEL);
	if (!session)
		return;

	session->addr = addr;
	session->port = port;
	session->info.latency = TCP_SESSION_DEFAULT_LATENCY;
	session->info.bandwidth = TCP_SESSION_DEFAULT_BW;
	INIT_DELAYED_WORK(&session->work, tcp_session_delete_work_handler);

	hash = hash_32((addr & TCP_SESSION_KEY_BITMASK), TCP_SESSION_HASH_BITS);
	thash = &tcpsi_hash[hash];

	spin_lock_bh(&thash->lock);
	hlist_add_head(&session->node, &thash->hlist);
	spin_unlock_bh(&thash->lock);

	tp->session_info = (void *)session;
}

static void tcp_session_add_work_handler(struct work_struct *work)
{
	struct tcp_sock *tp = container_of(to_delayed_work(work),
					   struct tcp_sock,
					   session_work);

	tcp_session_add(tp);
}

static void tcp_session_start(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	INIT_DELAYED_WORK(&tp->session_work, tcp_session_add_work_handler);

	mod_delayed_work(system_wq, &tp->session_work, 0);
}

static void tcp_session_delete(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct tcp_session_entry *session = tp->session_info;

	if (!session)
		return;

	schedule_delayed_work(&session->work,
			      msecs_to_jiffies(revsw_tcp_session_ttl * 1000));
}

static int tcp_get_session_info(struct sock *sk, unsigned char *data, int *len)
{
	const struct inet_sock *inet = inet_sk(sk);
	__u32 addr = (__force __u32)(inet->inet_daddr);
	__u32 hash = hash_32((addr & TCP_SESSION_KEY_BITMASK),
			     TCP_SESSION_HASH_BITS);
	struct tcp_session_info_hash *thash = &tcpsi_hash[hash];
	struct tcp_session_entry *session;
	struct tcp_session_info info;
	struct hlist_node *tmp;

	info.version = TCP_SESSION_INFO_VERSION;
	info.cookie = 0;
	info.latency = TCP_SESSION_DEFAULT_LATENCY;
	info.bandwidth = TCP_SESSION_DEFAULT_BW;

	if (hlist_empty(&thash->hlist))
		return -1;

	spin_lock_bh(&thash->lock);

	hlist_for_each_entry_safe(session, tmp, &thash->hlist, node) {
		if (session->addr == addr) {
			if ((session->info.latency <= info.latency) &&
				(session->info.bandwidth >= info.bandwidth)) {
				info.latency = session->info.latency;
				info.bandwidth = session->info.bandwidth;
			}
		}
	}

	spin_unlock_bh(&thash->lock);

	*len = min(*len, sizeof(info));

	memcpy(data, &info, *len);

	return 0;
}
/********************************************************************
 * End RevSw TCP Session Database
 ********************************************************************/
/********************************************************************
 *
 * RevSw Congestion Control Algorithm
 *
 ********************************************************************/

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
		revsw_filter(w, delta);

		w->bk = 0;
		w->rtt_win_sx = tcp_time_stamp;

		session->info.latency = w->rtt;
		session->info.bandwidth = w->bw_est;
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
	.flags		= TCP_CONG_RTT_STAMP,
	.init		= tcp_revsw_init,
	.release	= tcp_revsw_release,
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= tcp_reno_cong_avoid,
	.min_cwnd	= tcp_revsw_bw_rttmin,
	.cwnd_event	= tcp_revsw_event,
	.get_info	= tcp_revsw_info,
	.pkts_acked	= tcp_revsw_pkts_acked,
	.syn_post_config = tcp_revsw_syn_post_config,
	.set_nwin_size = tcp_revsw_set_nwin_size,
	.handle_nagle_test = tcp_revsw_handle_nagle_test,
	.get_session_info = tcp_get_session_info,

	.owner		= THIS_MODULE,
	.name		= "revsw"
};

static int __init tcp_revsw_register(void)
{
	BUILD_BUG_ON(sizeof(struct revsw) > ICSK_CA_PRIV_SIZE);

	revsw_ctl_table_hdr = register_sysctl("revsw", revsw_ctl_table);
	if (!revsw_ctl_table_hdr)
		return -EFAULT;

	tcp_session_hash_init();

	return tcp_register_congestion_control(&tcp_revsw);
}

static void __exit tcp_revsw_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_revsw);
	unregister_sysctl_table(revsw_ctl_table_hdr);
	tcp_session_hash_cleanup();
}

module_init(tcp_revsw_register);
module_exit(tcp_revsw_unregister);

MODULE_AUTHOR("Tom Kavanagh");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP RevSw");

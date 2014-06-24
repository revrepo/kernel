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
#include "tcp_rre.h"

#include <linux/debugfs.h>
#include <linux/kernel.h>


/********************************************************************
 *
 * RevSw sysctl support
 *
 ********************************************************************/
static int rre_revsw_rcv_wnd_min __read_mostly = REVSW_RCV_WND_MIN;
static int rre_revsw_rcv_wnd_max __read_mostly = REVSW_RCV_WND_MAX;
static int rre_revsw_rcv_wnd __read_mostly = REVSW_RCV_WND_DEFAULT;

static int rre_revsw_cong_wnd_min __read_mostly = REVSW_CONG_WND_MIN;
static int rre_revsw_cong_wnd_max __read_mostly = REVSW_CONG_WND_MAX;
static int rre_revsw_cong_wnd __read_mostly = REVSW_CONG_WND_DEFAULT;

static int rre_revsw_tcp_session_ttl_min __read_mostly = 1;
static int rre_revsw_tcp_session_ttl_max __read_mostly = TCP_SESSION_TTL_MAX;
static int rre_revsw_tcp_session_ttl __read_mostly = TCP_SESSION_TTL_DEFAULT;

static int rre_revsw_rto __read_mostly = REVSW_RTO_DEFAULT;
static int rre_revsw_tcp_rre_loglevel __read_mostly = REVSW_RRE_LOG_NOLOG;


static struct ctl_table_header *revsw_ctl_table_hdr;

static struct ctl_table revsw_ctl_table[] = {
	{
		.procname = "rre_revsw_rcv_wnd",
		.maxlen = sizeof(int),
		.mode = 0644,
		.data = &rre_revsw_rcv_wnd,
		.proc_handler = &proc_dointvec_minmax,
		.extra1 = &rre_revsw_rcv_wnd_min,
		.extra2 = &rre_revsw_rcv_wnd_max,
	},
	{
		.procname = "rre_revsw_cong_wnd",
		.maxlen = sizeof(int),
		.mode = 0644,
		.data = &rre_revsw_cong_wnd,
		.proc_handler = &proc_dointvec_minmax,
		.extra1 = &rre_revsw_cong_wnd_min,
		.extra2 = &rre_revsw_cong_wnd_max,
	},
	{
		.procname = "rre_revsw_rto",
		.maxlen = sizeof(int),
		.mode = 0644,
		.data = &rre_revsw_rto,
		.proc_handler = &proc_dointvec_ms_jiffies,
	},
	{
		.procname       = "rre_revsw_tcp_session_ttl",
		.data           = &rre_revsw_tcp_session_ttl,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &rre_revsw_tcp_session_ttl_min,
		.extra2		= &rre_revsw_tcp_session_ttl_max,
	},
	{
		.procname		= "rre_revsw_tcp_rre_loglevel",
		.maxlen =		sizeof(int),
		.mode = 		0644,
		.data = 		&rre_revsw_tcp_rre_loglevel,
		.proc_handler = &proc_dointvec,
	},
	{}
};
/********************************************************************
 * End RevSw sysctl support
 ********************************************************************/

/********************************************************************
 *
 * RevSw TCP RRE
 *
 ********************************************************************/

#define ASSERTMSG(expr,string)  if (!(expr)) {\
							           printk ("Assertion failed: \n" string );\
				                 while (1);}

#define LOG_IT(loglevel, format, ...) \
	if(rre_revsw_tcp_rre_loglevel && rre_revsw_tcp_rre_loglevel >= loglevel)  { \
		if(loglevel == REVSW_RRE_LOG_ERR)	\
			printk("****** ERR ->");	\
		else if(loglevel == REVSW_RRE_LOG_INFO)	\
			printk("INFO ->");	\
		printk(format, ## __VA_ARGS__);	\
	}

#define TCP_RRE_SET_STATE(rre, state) \
	LOG_IT(REVSW_RRE_LOG_INFO, "Setting State from %u to %u\n", rre->rev_rre_state, state);	\
	rre->rev_rre_state = state;

/* Assumptuion: receiver tick is same as sender tick */
static u32 rev_rre_receive_rate(struct tcp_sock *tp, struct revsw_rre *rre, u32 ack)
{
	unsigned long r_rate;
	u32 acked_data, ticks_delta, time_in_milisecs, sacked_bytes = 0;

	if (tp->sacked_out > rre->rev_last_sacked_out) {
		sacked_bytes = (tp->sacked_out - rre->rev_last_sacked_out) * tp->mss_cache;
		rre->rev_last_sacked_out = tp->sacked_out;
	}

	acked_data = (ack - rre->rev_rre_ack_r1) + sacked_bytes;
	ticks_delta = tp->rx_opt.rcv_tsval - rre->rev_rre_ts_r1;
	time_in_milisecs = jiffies_to_msecs(ticks_delta);
	if (time_in_milisecs == 0) {
		LOG_IT(REVSW_RRE_LOG_ERR, "%s: ZERO miliseconds past?????\n\n", __func__);
		return 0;
	}
	r_rate = (unsigned long) ((1000*acked_data)/time_in_milisecs); // bytes/sec
	ewma_add(&tp->rev_rre_receiving_rate, r_rate);

	LOG_IT(REVSW_RRE_LOG_VERBOSE, "ackd_bytes %u in %u msecs. ack %u. r_rate %lu, r_ewma %lu. snd_r = %u\n",
				acked_data, time_in_milisecs, ack, r_rate,
				ewma_read(&tp->rev_rre_receiving_rate), rre->rev_sending_rate);

	LOG_IT(REVSW_RRE_LOG_VERBOSE, "ack %u ; r_rate %lu, avg %lu. snd_r = %u\n",
				ack, r_rate,
				ewma_read(&tp->rev_rre_receiving_rate), rre->rev_sending_rate);

	return (u32) r_rate;

}

static __inline__ void rev_rre_fill_buffer(struct tcp_sock *tp, struct revsw_rre *rre)
{
	u32 srtt_msecs;
	// temp variable
	u32 delta_sending_rate = 0;

	srtt_msecs = jiffies_to_msecs(tp->srtt >> 3);
	delta_sending_rate = ((1000 *(rre->rev_rre_Bmax - rre->rev_rre_t)) / srtt_msecs);
	rre->rev_sending_rate = (u32) ewma_read(&tp->rev_rre_receiving_rate) + delta_sending_rate;
	rre->rev_rre_state = TCP_REV_RRE_STATE_FILL;

	LOG_IT(REVSW_RRE_LOG_VERBOSE, "delta_sending_rate %u and sending_rate = %u\n",
						delta_sending_rate, rre->rev_sending_rate);
	return;
}

static __inline__ void rev_rre_drain_buffer(struct tcp_sock *tp, struct revsw_rre *rre)
{
	u32 srtt_msecs;
	// temp variable
	u32 delta_sending_rate = 0;

	srtt_msecs = jiffies_to_msecs(tp->srtt >> 3);
	delta_sending_rate = (1000 * (rre->rev_rre_t - rre->rev_rre_Bmin) / srtt_msecs);
	rre->rev_sending_rate = (u32) ewma_read(&tp->rev_rre_receiving_rate) - delta_sending_rate;
	if(rre->rev_rre_state == TCP_REV_RRE_STATE_FORCE_DRAIN) {
		TCP_RRE_SET_STATE(rre, TCP_REV_RRE_STATE_SACK);
	}
	else {
		TCP_RRE_SET_STATE(rre, TCP_REV_RRE_STATE_DRAIN);
	}

	LOG_IT(REVSW_RRE_LOG_VERBOSE, "delta_sending_rate %u and sending_rate = %u\n",
						delta_sending_rate, rre->rev_sending_rate);
	return;
}

static void rev_rre_process_mode_bm(struct tcp_sock *tp, struct revsw_rre *rre, u32 ack)
{
	int tbuff, RD;

	// temp variables
	int network_buffer_capacity = 0;
	u32 acks_since_last_copy;

	RD = tp->rx_opt.rcv_tsval - tp->rx_opt.rcv_tsecr;

	if (RD < rre->rev_rre_RDmin) {
		rre->rev_rre_RDmin = RD;
	}

	tbuff = RD - rre->rev_rre_RDmin;
	rev_rre_receive_rate(tp, rre, ack);

	// TODO: We may not need these asserts
	ASSERTMSG(tbuff >=0, "tbuff can not be < 0");
	ASSERTMSG(ewma_read(&tp->rev_rre_receiving_rate) > 0,"Divide by zero check");
	
	network_buffer_capacity = ((rre->rev_rre_t * 1000 )/ (u32) ewma_read(&tp->rev_rre_receiving_rate));

	if(rre->rev_rre_state == TCP_REV_RRE_STATE_FORCE_DRAIN) {
		rev_rre_drain_buffer(tp, rre);
	} else if(rre->rev_rre_state != TCP_REV_RRE_STATE_SACK) {
		if(jiffies_to_msecs(tbuff) < network_buffer_capacity)
			rev_rre_fill_buffer(tp, rre);
		else
			rev_rre_drain_buffer(tp, rre);
	}

	// TODO: for "pass-time", note we are using ticks from client.  make sure we know the tick granularity accurately.
	// TODO: If possible use local timestamp for this.
	// TODO: Include SACKs in this calculation

	acks_since_last_copy = (rre->rev_rre_ack_r2 + tp->mss_cache * 30);
	if ((ack > acks_since_last_copy)) {
		rre->rev_rre_ts_r1 	= rre->rev_rre_ts_r2;
		rre->rev_rre_ack_r1 = rre->rev_rre_ack_r2;		
		rre->rev_rre_ts_r2 	= tp->rx_opt.rcv_tsval;
		rre->rev_rre_ack_r2 = ack;
		LOG_IT(REVSW_RRE_LOG_INFO, "r1 r2, sr %u and %u / %u\n", 
							rre->rev_sending_rate, ack, acks_since_last_copy);
	}
	
	LOG_IT(REVSW_RRE_LOG_VERBOSE, "(BM) tbuff = %d, network_buffer_capacity = %d, rtt-min %u.\n",
			jiffies_to_msecs(tbuff), network_buffer_capacity, rre->rev_rtt_min);

}

#define TCP_RRE_PACKETS_REQ_CALC_RATE	30

static void rev_rre_process_mode_init (struct tcp_sock *tp, struct revsw_rre *rre, u32 ack)
{
	int enter_BM_mode;

	if (rre->rev_rre_ack_r1 == 0) {
		LOG_IT(REVSW_RRE_LOG_INFO, "\nFirst valid ACK %u\n", ack);
		rre->rev_rre_ts_r1 		= tp->rx_opt.rcv_tsval;
		rre->rev_rre_ack_r1 	= ack;
		rre->rev_rre_RDmin 		= (int) (tp->rx_opt.rcv_tsval - tp->rx_opt.rcv_tsecr);
		rre->rev_rre_ts_r2 		= tp->rx_opt.rcv_tsecr;
		LOG_IT(REVSW_RRE_LOG_INFO, "rtt: %u, HS tsval %u\n", 
				rre->rev_rre_first_rtt, tp->rev_rre_hs_tsval);
	} else if (ack >= rre->rev_rre_ack_r2 + (tp->mss_cache * TCP_RRE_PACKETS_REQ_CALC_RATE /*rre->rev_init_cwnd * 0.8*/)) { // after we get ack for > 80% CWND packets

		if(((tp->rx_opt.rcv_tsecr - rre->rev_rre_ts_r2) /* + ((tp->srtt >> 3)/2)*/) < (tp->rx_opt.rcv_tsval - rre->rev_rre_ts_r1)) {
			/*
			 * If we receive TCP_RRE_PACKETS_REQ_CALC_RATE and ONLY if those 
			 * packets were transmitted faster than the receiver rate, use it for
			 * calculating reciver rate.
			 */
			enter_BM_mode = 1;
		} else {
			LOG_IT(REVSW_RRE_LOG_INFO, "Slow Sender\n");
			rre->rev_rre_ts_r2 		= tp->rx_opt.rcv_tsecr;
			rre->rev_rre_ts_r1 		= tp->rx_opt.rcv_tsval;
			rre->rev_rre_ack_r1 	= ack;
			rre->rev_rre_RDmin 		= (int) (tp->rx_opt.rcv_tsval - tp->rx_opt.rcv_tsecr);
			rre->rev_rre_ack_r2 	= ack;
			rre->rev_sending_rate 	= rre->rev_init_cwnd * tp->mss_cache;
			enter_BM_mode = 0;
		}
		if(enter_BM_mode) {
			LOG_IT(REVSW_RRE_LOG_INFO, "Switching to BM mode after %u packets are acked.\n",
					(ack - rre->rev_rre_ack_r2)/tp->mss_cache);

			rre->rev_rre_ts_r2 = tp->rx_opt.rcv_tsval;
			rre->rev_rre_ack_r2 = ack;

			rev_rre_receive_rate(tp, rre, ack);

			rre->rev_rre_t = (((u32) ewma_read(&tp->rev_rre_receiving_rate)) * rre->rev_rtt_min) / 1000;
			rre->rev_rre_Bmax = rre->rev_rre_t + (rre->rev_rre_t >> 1); // t + t/2
			rre->rev_rre_Bmin = rre->rev_rre_t - (rre->rev_rre_t >> 1); // t - t/2
			
			LOG_IT(REVSW_RRE_LOG_INFO, "T %u, Bmax %u, Bmin %u, RDmin %d\n",
					rre->rev_rre_t, 
					rre->rev_rre_Bmax,
					rre->rev_rre_Bmin,
					rre->rev_rre_RDmin);

			
			rre->rev_sending_rate = (u32) ewma_read(&tp->rev_rre_receiving_rate);
			rre->rev_rre_mode = TCP_REV_RRE_MODE_BM;
		}
	}

	if(rre->rev_rre_mode == TCP_REV_RRE_MODE_INIT) {
		if(rre->rev_rre_state == TCP_REV_RRE_STATE_FORCE_DRAIN) {
			TCP_RRE_SET_STATE(rre, TCP_REV_RRE_STATE_SACK);
		} else {
			rre->rev_sending_rate += (2 * tp->mss_cache); // Exp growth
			LOG_IT(REVSW_RRE_LOG_VERBOSE, "Mode: INIT. Exp Growth. Sending Rate: %u\n",
					rre->rev_sending_rate);
		}
	} else {
		if(rre->rev_rre_state == TCP_REV_RRE_STATE_FORCE_DRAIN)
			rev_rre_drain_buffer(tp, rre);
		else
			rev_rre_fill_buffer(tp, rre);
		LOG_IT(REVSW_RRE_LOG_SACK, "Mode: %u. State %u. Sending Rate: %u\n",
					rre->rev_rre_mode, rre->rev_rre_state, rre->rev_sending_rate);
	}
	return;
}

static __inline__ void revsw_tcp_handle_common_ack(struct tcp_sock *tp, struct revsw_rre *rre)
{
	if(rre->rev_rre_state == TCP_REV_RRE_STATE_SACK && 
				((tcp_time_stamp - rre->rre_sack_time_stamp) > (tp->srtt >> 3))) {
		LOG_IT(REVSW_RRE_LOG_INFO, "\n\t\t RTT\n\n");
		TCP_RRE_SET_STATE(rre, TCP_REV_RRE_STATE_SACK_DONE);
	}

	switch (rre->rev_rre_mode) {
	case TCP_REV_RRE_MODE_INVALID:
		break;

	case TCP_REV_RRE_MODE_INIT:
		rev_rre_process_mode_init(tp, rre, tp->snd_una);
		break;

	case TCP_REV_RRE_MODE_BM:
		rev_rre_process_mode_bm(tp, rre, tp->snd_una);
		break;

	default:
		break;
	}
}

static __inline__ void revsw_tcp_handle_slow_ack(struct tcp_sock *tp, struct revsw_rre *rre)
{
	if(tp->sacked_out != rre->rev_last_sacked_out) {
		if(tp->sacked_out && ((tcp_time_stamp - rre->rre_sack_time_stamp) > (tp->srtt >> 3))) {
			/* Fresh SACK */
			TCP_RRE_SET_STATE(rre, TCP_REV_RRE_STATE_FORCE_DRAIN);
			rre->rre_sack_time_stamp = tcp_time_stamp;
			LOG_IT(REVSW_RRE_LOG_INFO, "\t\tSACK\n\n");
		}
		rre->rev_last_sacked_out = tp->sacked_out;
		
		LOG_IT(REVSW_RRE_LOG_SACK, "sacked_out %u. ack %u .. Blocks: %u %u, %u %u, %u %u, %u %u \n",
				tp->sacked_out,
				tp->snd_una,
				tp->recv_sack_cache[0].start_seq, tp->recv_sack_cache[0].end_seq,
				tp->recv_sack_cache[1].start_seq, tp->recv_sack_cache[1].end_seq,
				tp->recv_sack_cache[2].start_seq, tp->recv_sack_cache[2].end_seq,
				tp->recv_sack_cache[3].start_seq, tp->recv_sack_cache[3].end_seq);
	}
	revsw_tcp_handle_common_ack(tp, rre);
}

static __inline__ void revsw_tcp_handle_fast_ack(struct tcp_sock *tp, struct revsw_rre *rre)
{
	if(tp->sacked_out && (tp->sacked_out != rre->rev_last_sacked_out))
		LOG_IT(REVSW_RRE_LOG_ERR, "sacked_out in fast ack? %u %u\n", tp->sacked_out, rre->rev_last_sacked_out);

	if(tp->sacked_out != rre->rev_last_sacked_out) {
		LOG_IT(REVSW_RRE_LOG_INFO, "last sacked out updated! %u %u", tp->sacked_out, rre->rev_last_sacked_out);
		rre->rev_last_sacked_out = tp->sacked_out;
	}

	revsw_tcp_handle_common_ack(tp, rre);
}

// TODO:
/*
1. handle tcp_time_stamp reset
*/
static int revsw_tcp_leak_quota(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct revsw_rre *rre = inet_csk_ca(sk);
	u32 	bytes_sent; /* Bytes Sent out after the last call to this fucntion. */
	u32 	quota;		/* Quota: Bytes that can be sent out on wire. */
	u32 	leak_time;	/* Time since this leak started (Used to maintain the leak rate per second). */

	if (rre->rev_last_snd_nxt == 0) {
		/* First Drop. This is the first time this function is getting called for this socket. */

		rre->rev_bytes_sent_this_leak 	= 0;
		rre->rev_leak_start_ts 			= tcp_time_stamp;
		rre->rev_init_cwnd 				= rre_revsw_cong_wnd;
		rre->rev_rre_mode 				= TCP_REV_RRE_MODE_INIT;
		rre->rev_rre_ack_r2 				= tp->snd_una;
		rre->rev_sending_rate 		 	= quota = rre->rev_init_cwnd * 1448;
		ewma_init(&tp->rev_rre_receiving_rate, 1024, 2);

		LOG_IT(REVSW_RRE_LOG_INFO, "Very first packet (snd_una: %u)\n", tp->snd_una);
	} else {
		leak_time = jiffies_to_msecs(tcp_time_stamp - rre->rev_leak_start_ts);
		if(leak_time <= 1000) { /* Still in same leak/drop. */
			bytes_sent = tp->snd_nxt - rre->rev_last_snd_nxt;
			rre->rev_bytes_sent_this_leak += bytes_sent;
			if (rre->rev_bytes_sent_this_leak < rre->rev_sending_rate) {
				/* We can send more data out on wire in this leak */
				quota = rre->rev_sending_rate - rre->rev_bytes_sent_this_leak;
			} else {
				quota = 0;
			}			
		} else {
			/* Next leak */
			rre->rev_leak_start_ts = tcp_time_stamp - msecs_to_jiffies((leak_time - 1000) % 1000);
			rre->rev_bytes_sent_this_leak = 0;
			quota = rre->rev_sending_rate;
		}
	}

	LOG_IT(REVSW_RRE_LOG_VERBOSE, "Quota: %u, snd_rate %u, BY_sent %u, last_sndnxt %u, sndnxt = %u, flight %u and tcp_TS %u\n", 
		quota, rre->rev_sending_rate, rre->rev_bytes_sent_this_leak, rre->rev_last_snd_nxt, tp->snd_nxt,
		tcp_packets_in_flight(tp), tcp_time_stamp);

	rre->rev_last_snd_nxt 	= tp->snd_nxt;
	/*
	 * The TCP stack checks tp->snd_cwnd value at several places. Anyway this variable has
	 * no significance when TCP-RRE is used as CCA. The 2 conditions which we have
	 * to meet pacify the stack are (1) it shouldn't be zero (2) It > packets_in_flight.
	 */
	tp->snd_cwnd 			= max(tp->snd_cwnd, tcp_packets_in_flight(tp)+1);
		
	return (int) (quota/tp->mss_cache);
}

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
			      msecs_to_jiffies(rre_revsw_tcp_session_ttl * 1000));
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
 * @tcp_revsw_init
 */
static void tcp_revsw_init(struct sock *sk)
{
	//tcp_session_start(sk);
}

/*
 * @tcp_revsw_release
 *
 * This function setups up the deletion of the session database entry used by
 * this connection.
 */
static void tcp_revsw_release(struct sock *sk)
{
	//tcp_session_delete(sk);
}

static u32 tcp_revsw_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	return (tp->snd_cwnd);
}

static void tcp_revsw_cong_avoid(struct sock *sk, u32 ack, u32 in_flight)
{
	tcp_sk(sk)->snd_cwnd + 2;
}

static u32 tcp_revsw_min_cwnd(const struct sock *sk)
{
	return tcp_sk(sk)->snd_cwnd/2;
}

/*
 * @revsw_pkts_acked
 * Called after processing group of packets.
 * but all revsw needs is the last sample of srtt.
 */
static void tcp_revsw_pkts_acked(struct sock *sk, u32 cnt, s32 rtt)
{
	struct revsw_rre *rre = inet_csk_ca(sk);

	if (rtt > 0) {
		if (rre->rev_rtt_min == 0) {
			rre->rev_rtt_min = (((u32)rtt) / USEC_PER_MSEC);
			LOG_IT(REVSW_RRE_LOG_INFO, "Setting rtt-min: %u\n", rre->rev_rtt_min);
		}
		else {
			rre->rev_rtt_min = min_t(u32, (((u32)rtt) / USEC_PER_MSEC), rre->rev_rtt_min);
		}
	}

}

static void tcp_revsw_state(struct sock *sk, u8 new_state)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct revsw_rre *rre = inet_csk_ca(sk);

	if (new_state == TCP_CA_Loss) {
		LOG_IT(REVSW_RRE_LOG_INFO, "TCP_CA_Loss State\n");
		TCP_RRE_SET_STATE(rre, TCP_REV_RRE_STATE_FORCE_DRAIN);
		rre->rre_sack_time_stamp = tcp_time_stamp;
		rev_rre_drain_buffer(tp, rre);
		
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

static void tcp_revsw_event(struct sock *sk, enum tcp_ca_event event)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct revsw_rre *rre = inet_csk_ca(sk);

	switch (event) {
	case CA_EVENT_FAST_ACK:
		revsw_tcp_handle_fast_ack(tp, rre);
		break;

	case CA_EVENT_SLOW_ACK:
		revsw_tcp_handle_slow_ack(tp, rre);
		break;

	case CA_EVENT_COMPLETE_CWR:
		break;

	case CA_EVENT_LOSS:
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
	if (ext & (1 << (INET_DIAG_VEGASINFO - 1))) {
		struct tcpvegas_info info = {
			.tcpv_enabled = 1,
			.tcpv_rtt = 0,
			.tcpv_minrtt = 0,
		};

		nla_put(skb, INET_DIAG_VEGASINFO, sizeof(info), &info);
	}
}

static void tcp_revsw_syn_post_config(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct revsw_rre *rre = inet_csk_ca(sk);

	LOG_IT(REVSW_RRE_LOG_INFO, "I am in tcp_revsw_syn_post_config\n");

	tp->rev_rre_hs_tsval = tp->rev_rre_hs_tsval - tp->rx_opt.rcv_tsval;
	rre->rev_rre_first_rtt = tcp_time_stamp - tp->rx_opt.rcv_tsecr;

	/*
	 * Modify the congestion and send windows.  Also fix the
	 * sndbuf size.  Will be changed to use sysctls when they
	 * are available.
	 */
	tp->snd_wnd = rre_revsw_rcv_wnd;
	tp->snd_cwnd = rre_revsw_cong_wnd;
	sk->sk_sndbuf = 3 * tp->snd_wnd;
}

static void tcp_revsw_set_nwin_size(struct sock *sk, u32 nwin)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if ((nwin > rre_revsw_cong_wnd) || (nwin == 0))
		tp->snd_wnd = nwin;
}

static bool
tcp_revsw_handle_nagle_test(struct sock *sk, struct sk_buff *skb,
			    unsigned int mss_now, int nonagle)
{
	return true;
}

static struct tcp_congestion_ops tcp_rre_cca __read_mostly = {
	.flags		= TCP_CONG_RTT_STAMP,
	.init		= tcp_revsw_init,
	.release	= tcp_revsw_release,
	.ssthresh	= tcp_revsw_ssthresh,
	.cong_avoid	= tcp_revsw_cong_avoid,
	.min_cwnd	= tcp_revsw_min_cwnd,
	.set_state	= tcp_revsw_state,
	.cwnd_event	= tcp_revsw_event,
	.get_info	= NULL, //tcp_revsw_info,
	.pkts_acked	= tcp_revsw_pkts_acked,
	.syn_post_config = 		tcp_revsw_syn_post_config,
	.set_nwin_size = 		tcp_revsw_set_nwin_size,
	.handle_nagle_test = 	tcp_revsw_handle_nagle_test,
	.get_session_info = 	tcp_get_session_info,
	.revsw_get_leak_quota = revsw_tcp_leak_quota,

	.owner		= THIS_MODULE,
	.name		= "rre"
};

static int __init tcp_revsw_register(void)
{
	BUILD_BUG_ON(sizeof(struct revsw_rre) > ICSK_CA_PRIV_SIZE);

	revsw_ctl_table_hdr = register_sysctl("rre", revsw_ctl_table);
	if (!revsw_ctl_table_hdr)
		return -EFAULT;
	return tcp_register_congestion_control(&tcp_rre_cca);
}

static void __exit tcp_revsw_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_rre_cca);
	unregister_sysctl_table(revsw_ctl_table_hdr);
	//tcp_session_hash_cleanup();
}

module_init(tcp_revsw_register);
module_exit(tcp_revsw_unregister);

MODULE_AUTHOR("Akhil Shashidhar");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP RevSw RRE");

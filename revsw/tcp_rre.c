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
	if(rre_revsw_tcp_rre_loglevel && rre_revsw_tcp_rre_loglevel >= loglevel) \
		printk(format, ## __VA_ARGS__);

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
	ewma_add(&tp->rev_tp_receiving_rate, r_rate);

	LOG_IT(REVSW_RRE_LOG_VERBOSE, "ackd_bytes %u in %u msecs. ack %u. r_rate %lu, r_ewma %lu. snd_r = %u\n",
				acked_data, time_in_milisecs, ack, r_rate,
				ewma_read(&tp->rev_tp_receiving_rate), rre->rev_sending_rate);

	LOG_IT(REVSW_RRE_LOG_INFO, "ack %u ; r_rate %lu, avg %lu. snd_r = %u\n",
				ack, r_rate,
				ewma_read(&tp->rev_tp_receiving_rate), rre->rev_sending_rate);

	return (u32) r_rate;

}

static __inline__ void rev_rre_fill_buffer(struct tcp_sock *tp, struct revsw_rre *rre)
{
	u32 srtt_msecs;
	// temp variable
	u32 delta_sending_rate = 0;

	srtt_msecs = jiffies_to_msecs(tp->srtt >> 3);
	delta_sending_rate = ((1000 *(rre->rev_rre_Bmax - rre->rev_rre_t)) / srtt_msecs);
	rre->rev_sending_rate = (u32) ewma_read(&tp->rev_tp_receiving_rate) + delta_sending_rate;
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
	rre->rev_sending_rate = (u32) ewma_read(&tp->rev_tp_receiving_rate) - delta_sending_rate;
	if(rre->rev_rre_state == TCP_REV_RRE_STATE_FORCE_DRAIN)
		rre->rev_rre_state = TCP_REV_RRE_STATE_SACK;
	else
		rre->rev_rre_state = TCP_REV_RRE_STATE_DRAIN;

	LOG_IT(REVSW_RRE_LOG_VERBOSE, "delta_sending_rate %u and sending_rate = %u\n",
						delta_sending_rate, rre->rev_sending_rate);
	return;
}

static void rev_rre_process_mode_bm(struct tcp_sock *tp, struct revsw_rre *rre, u32 ack, u32 ack_seq)
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

	ASSERTMSG(tbuff >=0, "tbuff can not be < 0");
	ASSERTMSG(ewma_read(&tp->rev_tp_receiving_rate) > 0,"Divide by zero check");
	
	network_buffer_capacity = ((rre->rev_rre_t * 1000 )/ (u32) ewma_read(&tp->rev_tp_receiving_rate));

	if(rre->rev_rre_state == TCP_REV_RRE_STATE_FORCE_DRAIN) {
		if(jiffies_to_msecs(tbuff) >= network_buffer_capacity)
			rev_rre_drain_buffer(tp, rre);
	} else if(jiffies_to_msecs(tbuff) < network_buffer_capacity)
		rev_rre_fill_buffer(tp, rre);
	else
		rev_rre_drain_buffer(tp, rre);

	// TODO:  for "pass-time", note we are using ticks from client.  make sure we know the tick granularity accurately.
	// TODO: If possible use local timestamp for this.

	acks_since_last_copy = (rre->rev_rre_ack_r2 + tp->mss_cache * 30);
	if ((ack > acks_since_last_copy)) {
		//	jiffies_to_msecs(tp->rx_opt.rcv_tsval - rre->rev_rre_ts_r2) > 200) {

		rre->rev_rre_ts_r1 = rre->rev_rre_ts_r2;
		rre->rev_rre_ack_r1 = rre->rev_rre_ack_r2;		

		rre->rev_rre_ts_r2 = tp->rx_opt.rcv_tsval;
		rre->rev_rre_ack_r2 = ack;
		LOG_IT(REVSW_RRE_LOG_INFO, "\nr1 r2, sr %u and %u / %u\n", 
							rre->rev_sending_rate, ack, acks_since_last_copy);
	}
	
	LOG_IT(REVSW_RRE_LOG_VERBOSE, "(BM) tbuff = %d, network_buffer_capacity = %d, rtt-min %u.\n",
			jiffies_to_msecs(tbuff), network_buffer_capacity, rre->rev_rtt_min);

}

static void rev_rre_process_mode_init (struct tcp_sock *tp, struct revsw_rre *rre, u32 ack, u32 ack_seq)
{
	if (rre->rev_rre_ack_r1 == 0) {
		LOG_IT(REVSW_RRE_LOG_INFO, "\nFirst valid ACK %u\n", ack);
		rre->rev_rre_ts_tsecr = tp->rx_opt.rcv_tsecr;
		rre->rev_rre_ts_r1 = tp->rx_opt.rcv_tsval;
		rre->rev_rre_ack_r1 = ack;
		rre->rev_rre_RDmin = (int) (tp->rx_opt.rcv_tsval - tp->rx_opt.rcv_tsecr);

		LOG_IT(REVSW_RRE_LOG_ERR, "rtt: %u, first: %u and second: %u ... %u.\n", 
			tp->rev_rtt, tp->rev_first_tsval, tp->rev_second_tsval, tp->rev_first_tsval - tp->rev_second_tsval);
	} else if (ack >= rre->rev_store_seq + (tp->mss_cache * 30 /*rre->rev_init_cwnd * 0.8*/)) { // after we get ack for > 80% CWND packets
		int enter_BM_mode = 0;

		if(rre->rev_rre_ts_r2 == 0) {
			if(((tp->rx_opt.rcv_tsecr - rre->rev_rre_ts_tsecr) /* + ((tp->srtt >> 3)/2)*/) < (tp->rx_opt.rcv_tsval - rre->rev_rre_ts_r1)) {
				enter_BM_mode = 1;
			} else {
				LOG_IT(REVSW_RRE_LOG_INFO, "Slow Sender\n");
				rre->rev_rre_ts_tsecr = tp->rx_opt.rcv_tsecr;
				rre->rev_rre_ts_r1 = tp->rx_opt.rcv_tsval;
				rre->rev_rre_ack_r1 = ack;
				rre->rev_rre_RDmin = (int) (tp->rx_opt.rcv_tsval - tp->rx_opt.rcv_tsecr);
				rre->rev_store_seq = ack;
				rre->rev_sending_rate = rre->rev_init_cwnd * tp->mss_cache;
			}
		}
		if(enter_BM_mode) {
			rre->rev_rre_ts_r2 = tp->rx_opt.rcv_tsval;
			rre->rev_rre_ack_r2 = ack;

			rev_rre_receive_rate(tp, rre, ack);

			rre->rev_rre_t = (((u32) ewma_read(&tp->rev_tp_receiving_rate)) * rre->rev_rtt_min) / 1000;
			rre->rev_rre_Bmax = rre->rev_rre_t + (rre->rev_rre_t >> 1); // t + t/2
			rre->rev_rre_Bmin = rre->rev_rre_t - (rre->rev_rre_t >> 1); // t - t/2
			
			LOG_IT(REVSW_RRE_LOG_INFO, "T %u, Bmax %u, Bmin %u, RDmin %d\n",
						rre->rev_rre_t, 
						rre->rev_rre_Bmax,
						rre->rev_rre_Bmin,
						rre->rev_rre_RDmin);
			LOG_IT(REVSW_RRE_LOG_INFO, "Switching to BM mode after %u packets are acked.\n", (ack - rre->rev_store_seq)/tp->mss_cache);
			
			rre->rev_sending_rate = (u32) ewma_read(&tp->rev_tp_receiving_rate);
			rre->rev_rre_mode = TCP_REV_RRE_MODE_BM;
		}
	}

	if (rre->rev_rre_mode == TCP_REV_RRE_MODE_INIT) {
		if(rre->rev_rre_state == TCP_REV_RRE_STATE_FORCE_DRAIN) {
			rre->rev_rre_state = TCP_REV_RRE_STATE_SACK;
		} else {
			rre->rev_sending_rate += (2 * tp->mss_cache); // Exp growth
			LOG_IT(REVSW_RRE_LOG_VERBOSE, "Mode: INIT. Exp Growth. Sending Rate: %u\n", rre->rev_sending_rate);
		}
	} else {
		rev_rre_drain_buffer(tp, rre);
		LOG_IT(REVSW_RRE_LOG_SACK, "Mode: %u. State %u. Sending Rate: %u\n", rre->rev_rre_mode, rre->rev_rre_state, rre->rev_sending_rate);
	}
	return;
}

static void revsw_syn_ts_cb(struct sock *sk, u32 rcv_tsval, u32 rcv_tsecr)
{
	struct tcp_sock *tp = tcp_sk(sk);

	LOG_IT(REVSW_RRE_LOG_VERBOSE, "NOT HERE !!\n");
	
	tp->rev_first_tsval = rcv_tsval;
	tp->rev_second_tsval = rcv_tsecr;

	return;
}

static void revsw_tcp_calc_sending_rate(struct sock *sk, 
												int context, 
												u32 ack, 
												u32 ack_seq, 
												u8 sacked)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct revsw_rre *rre = inet_csk_ca(sk);

	switch (context) {
	case 100:
	case 101:

		if (sacked) {
			if((tcp_time_stamp - tp->rev_temp1) > (tp->srtt >> 3)) {
				tp->rev_temp1 = tcp_time_stamp;
				LOG_IT(REVSW_RRE_LOG_INFO, "\n\t\tSACK\n\n");
			}
		}

		if(tp->sacked_out) //  && tp->sacked_out != rre->rev_last_sacked_out)
			LOG_IT(REVSW_RRE_LOG_SACK, "sacked_out %u. sacked %u, ack %u .. Blocks: %u %u, %u %u, %u %u, %u %u \n",
					tp->sacked_out,
					sacked,
					ack,
					tp->recv_sack_cache[0].start_seq, tp->recv_sack_cache[0].end_seq,
					tp->recv_sack_cache[1].start_seq, tp->recv_sack_cache[1].end_seq,
					tp->recv_sack_cache[2].start_seq, tp->recv_sack_cache[2].end_seq,
					tp->recv_sack_cache[3].start_seq, tp->recv_sack_cache[3].end_seq);

		if((tcp_time_stamp - tp->rev_temp1) < (tp->srtt >> 3))
			rre->rev_rre_state = TCP_REV_RRE_STATE_FORCE_DRAIN;
		else if (rre->rev_rre_state == TCP_REV_RRE_STATE_SACK) {
			LOG_IT(REVSW_RRE_LOG_INFO, "\n\t\t RTT\n\n");
			rre->rev_rre_state = TCP_REV_RRE_STATE_SACK_DONE;
		}

		switch (rre->rev_rre_mode) {
		case TCP_REV_RRE_MODE_INVALID:
			break;

		case TCP_REV_RRE_MODE_INIT:
			/* Data packet have been sent out but check if this is first ACK (for data) */
			rev_rre_process_mode_init(tp, rre, ack, ack_seq);
			break;

		case TCP_REV_RRE_MODE_BM:
			rev_rre_process_mode_bm(tp, rre, ack, ack_seq);
			break;

		default:
			break;
		}
		break;

	case ICSK_TIME_EARLY_RETRANS:
		/* we would have reduced rate when we got SACK. Ignore this */
		LOG_IT(REVSW_RRE_LOG_INFO, "Context %u, ICSK_TIME_EARLY_RETRANS\n", context);
		break;
		
	case ICSK_TIME_LOSS_PROBE:
		LOG_IT(REVSW_RRE_LOG_INFO, "Context %u, ICSK_TIME_LOSS_PROBE\n", context);
		rev_rre_drain_buffer(tp, rre);
		tp->rev_temp1 = tcp_time_stamp;
		break;
		
	case ICSK_TIME_RETRANS:
		LOG_IT(REVSW_RRE_LOG_INFO, "Context %u, ICSK_TIME_RETRANS\n", context);
		rev_rre_drain_buffer(tp, rre);
		tp->rev_temp1 = tcp_time_stamp;
		break;
		
	case ICSK_TIME_PROBE0:
		// Ignore
		LOG_IT(REVSW_RRE_LOG_INFO, "Context %u, ICSK_TIME_PROBE0\n", context);
		break;
		
	default:
		LOG_IT(REVSW_RRE_LOG_ERR, "Error Context %u\n", context);
		break;
	}

	return;
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
		rre->rev_store_seq 				= tp->snd_una;
		rre->rev_sending_rate 		 	= quota = rre->rev_init_cwnd * 1448;
		ewma_init(&tp->rev_tp_receiving_rate, 1024, 2);

		LOG_IT(REVSW_RRE_LOG_INFO, "Very first packet (%u)\n", rre->rev_init_cwnd);
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

#if 0
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
#endif

static void tcp_revsw_cong_avoid(struct sock *sk, u32 ack, u32 in_flight)
{
	tcp_sk(sk)->snd_cwnd + 2;
}

static u32 tcp_revsw_min_cwnd(const struct sock *sk)
{
	return tcp_sk(sk)->snd_cwnd/2;
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

#if 0
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
	/* If the filter is empty fill it with the first sample of bandwidth  */
	if (w->bw_ns_est == 0 && w->bw_est == 0) {
		w->bw_ns_est = w->bk / delta;
		w->bw_est = w->bw_ns_est;
	} else {
		w->bw_ns_est = tcp_revsw_do_filter(w->bw_ns_est, w->bk / delta);
		w->bw_est = tcp_revsw_do_filter(w->bw_est, w->bw_ns_est);
	}
}
#endif
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

static void tcp_revsw_event(struct sock *sk, enum tcp_ca_event event)
{
	return;
}

#if 0
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
#endif

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
	//.get_info	= tcp_revsw_info,
	.pkts_acked	= tcp_revsw_pkts_acked,
	.syn_post_config = tcp_revsw_syn_post_config,
	.set_nwin_size = tcp_revsw_set_nwin_size,
	.handle_nagle_test = tcp_revsw_handle_nagle_test,
	.get_session_info = tcp_get_session_info,
	.revsw_get_leak_quota = revsw_tcp_leak_quota,
	.revsw_calc_sending_rate = revsw_tcp_calc_sending_rate,
	.revsw_syn_ts = NULL, //revsw_syn_ts_cb,

	.owner		= THIS_MODULE,
	.name		= "rre"
};

#ifdef REV_GENERIC_NETLINK
//Commands: mapping between the command enumeration and the actual function
struct genl_ops doc_exmpl_gnl_ops_echo = {
 .cmd = DOC_EXMPL_C_ECHO,
 .flags = 0,
 .policy = doc_exmpl_genl_policy,
 .doit = doc_exmpl_echo,
 .dumpit = NULL,
};

static int __init gnKernel_init(void) {
 int rc;
 printk("Generic Netlink Example Module inserted.\n");
        
    //Register the new family
 rc = genl_register_family(&doc_exmpl_gnl_family);
 if (rc != 0) {
  goto failure;
 }
 //Register functions (commands) of the new family
 rc = genl_register_ops(&doc_exmpl_gnl_family, &doc_exmpl_gnl_ops_echo);
 if (rc != 0) {
  printk("Register ops: %i\n",rc);
  genl_unregister_family(&doc_exmpl_gnl_family);
  goto failure;
 }
 return 0; 
failure:
 printk("An error occured while inserting the generic netlink example module\n");
 return -1;
}

static void __exit gnKernel_exit(void) {
 int ret;
 printk("Generic Netlink Example Module unloaded.\n");
 
 //Unregister the functions
 ret = genl_unregister_ops(&doc_exmpl_gnl_family, &doc_exmpl_gnl_ops_echo);
 if(ret != 0) {
  printk("Unregister ops: %i\n",ret);
  return;
 }

    //Unregister the family
 ret = genl_unregister_family(&doc_exmpl_gnl_family);
 if(ret !=0) {
  printk("Unregister family %i\n",ret);
 }
}
#endif // REV_GENERIC_NETLINK

static int __init tcp_revsw_register(void)
{
	// TODO: Delete this if
	if(sizeof(struct revsw_rre) > ICSK_CA_PRIV_SIZE) {
		printk("Size !!!!!!!!!!!!!!!!!\n");
	}
	BUILD_BUG_ON(sizeof(struct revsw_rre) > ICSK_CA_PRIV_SIZE);

#if 0
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
#endif
	revsw_ctl_table_hdr = register_sysctl("rre", revsw_ctl_table);
	if (!revsw_ctl_table_hdr)
		return -EFAULT;
	#ifdef REV_GENERIC_NETLINK
	gnKernel_init();
	#endif
	return tcp_register_congestion_control(&tcp_rre_cca);
}

static void __exit tcp_revsw_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_rre_cca);
	unregister_sysctl_table(revsw_ctl_table_hdr);
	#ifdef REV_GENERIC_NETLINK
	gnKernel_exit();
	#endif
	//tcp_session_hash_cleanup();
}

module_init(tcp_revsw_register);
module_exit(tcp_revsw_unregister);

MODULE_AUTHOR("Akhil Shashidhar");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP RevSw RRE");

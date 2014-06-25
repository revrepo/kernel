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
#include "tcp_revsw_sysctl.h"
#include "tcp_rre.h"
#include "tcp_revsw_session_db.h"


#include <linux/kernel.h>

/********************************************************************
 *
 * RevSw TCP RRE
 *
 ********************************************************************/

#define ASSERTMSG(expr,string)  if (!(expr)) {\
							           printk ("Assertion failed: \n" string );\
				                 while (1);}
typedef enum revsw_rre_loglevel_ {
	REVSW_RRE_LOG_NOLOG = REVSW_RRE_LOG_DEFAULT,
	REVSW_RRE_LOG_ERR,
	REVSW_RRE_LOG_INFO,
	REVSW_RRE_LOG_SACK,
	REVSW_RRE_LOG_VERBOSE,
} revsw_rre_loglevel;

#define LOG_IT(loglevel, format, ...) \
	if(revsw_tcp_rre_loglevel && revsw_tcp_rre_loglevel >= loglevel)  { \
		if(loglevel == REVSW_RRE_LOG_ERR)	\
			printk("****** ERR ->");	\
		else if(loglevel == REVSW_RRE_LOG_INFO)	\
			printk("INFO ->");	\
		printk(format, ## __VA_ARGS__);	\
	}

#define TCP_RRE_SET_STATE(rre, state)  { \
	LOG_IT(REVSW_RRE_LOG_INFO, "Setting State from %u to %u\n", rre->rev_rre_state, state);	\
	rre->rev_rre_state = state;	\
}

// TODO: Temp Assumptuion: receiver tick is same as sender tick
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
	} else if (ack >= 
		rre->rev_rre_ack_r2 + (tp->mss_cache * TCP_RRE_PACKETS_REQ_CALC_RATE)) {

		// TODO: Do we ewant to check if sending_rate <<< receiving_rate ?  
		// TODO: Ex: Sending_rate + ((tp->srtt >> 3)/2) < receiving_rate

		/* if (sending_rate < receiving rate) */
		if((tp->rx_opt.rcv_tsecr - rre->rev_rre_ts_r2) < 
								(tp->rx_opt.rcv_tsval - rre->rev_rre_ts_r1)) {
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
			// TODO: Decrease sending_rate ? 
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
static int tcp_rre_get_leak_quota(struct sock *sk)
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
		rre->rev_init_cwnd 				= revsw_cong_wnd;
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
 * RevSw Congestion Control Algorithm
 *
 ********************************************************************/
/*
 * @tcp_rre_init
 */
static void tcp_rre_init(struct sock *sk)
{
	tcp_session_start(sk);
}

/*
 * @tcp_rre_release
 *
 * This function setups up the deletion of the session database entry used by
 * this connection.
 */
static void tcp_rre_release(struct sock *sk)
{
	tcp_session_delete(sk);
}

// TODO: Check where this called from and if we can use this.

static u32 tcp_rre_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	return (tp->snd_cwnd);
}

// TODO: Check where this called from and if we can use this.
static void tcp_rre_cong_avoid(struct sock *sk, u32 ack, u32 in_flight)
{
	tcp_sk(sk)->snd_cwnd + 2;
}

/*
 * @revsw_pkts_acked
 * Called after processing group of packets.
 * but all revsw needs is the last sample of srtt.
 */
static void tcp_rre_pkts_acked(struct sock *sk, u32 cnt, s32 rtt)
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

static void tcp_rre_state(struct sock *sk, u8 new_state)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct revsw_rre *rre = inet_csk_ca(sk);

	if (new_state == TCP_CA_Loss) {
		LOG_IT(REVSW_RRE_LOG_INFO, "TCP_CA_Loss State\n");
		TCP_RRE_SET_STATE(rre, TCP_REV_RRE_STATE_FORCE_DRAIN);
		rre->rre_sack_time_stamp = tcp_time_stamp;
		rev_rre_drain_buffer(tp, rre);
	}
}

static void tcp_rre_event(struct sock *sk, enum tcp_ca_event event)
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

static void tcp_rre_syn_post_config(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct revsw_rre *rre = inet_csk_ca(sk);

	LOG_IT(REVSW_RRE_LOG_INFO, "I am in tcp_rre_syn_post_config\n");

	tp->rev_rre_hs_tsval = tp->rev_rre_hs_tsval - tp->rx_opt.rcv_tsval;
	rre->rev_rre_first_rtt = tcp_time_stamp - tp->rx_opt.rcv_tsecr;

	// TODO: Use same function from both revsw and rre modules.
	/*
	 * Modify the congestion and send windows.  Also fix the
	 * sndbuf size.  Will be changed to use sysctls when they
	 * are available.
	 */
	sk->sk_sndbuf = 3 * tp->snd_wnd;
}

static bool
tcp_revsw_handle_nagle_test(struct sock *sk, struct sk_buff *skb,
			    unsigned int mss_now, int nonagle)
{
	return true;
}

static struct tcp_congestion_ops tcp_rre_cca __read_mostly = {
	.flags		= TCP_CONG_RTT_STAMP,
	.init		= tcp_rre_init,
	.release	= tcp_rre_release,
	.ssthresh	= tcp_rre_ssthresh,
	.cong_avoid	= tcp_rre_cong_avoid,
	.min_cwnd	= NULL,
	.set_state	= tcp_rre_state,
	.cwnd_event	= tcp_rre_event,
	.get_info	= NULL,
	.pkts_acked	= tcp_rre_pkts_acked,
	.syn_post_config = 		tcp_rre_syn_post_config,
	.set_nwin_size = 		NULL,
	.handle_nagle_test = 	tcp_revsw_handle_nagle_test,
	.get_session_info = 	tcp_get_session_info,
	.revsw_get_leak_quota = tcp_rre_get_leak_quota,

	.owner		= THIS_MODULE,
	.name		= "rre"
};

static int __init tcp_revsw_register(void)
{
	BUILD_BUG_ON(sizeof(struct revsw_rre) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&tcp_rre_cca);
}

static void __exit tcp_revsw_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_rre_cca);
}

module_init(tcp_revsw_register);
module_exit(tcp_revsw_unregister);

MODULE_AUTHOR("Akhil Shashidhar");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP RevSw RRE");

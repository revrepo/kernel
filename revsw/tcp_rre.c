/*
 *
 *   RevSw RRE TCP Congestion Control Algorithm
 *
 * This is TCP RRE (Receiver Rate Estimation) Implementation.
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
#include "tcp_revsw_session_db.h"

#include <linux/average.h>

/********************************************************************
 *
 * RevSw RRE Congestion Control Algorithm
 *
 ********************************************************************/

/*
 * Number of packets we require in INIT mode or
 * MONITOR mode to calculate receiver rate
 */
#define TCP_RRE_PACKETS_REQ_CALC_RATE	30

/* Number of packets we use to calculate tbuff */
#define TCP_RRE_TBUFF_PACKETS	30

#define TCP_RRE_LOG_NOLOG  TCP_RRE_LOG_DEFAULT
#define TCP_RRE_LOG_ERR  (TCP_RRE_LOG_DEFAULT + 1)
#define TCP_RRE_LOG_INFO  (TCP_RRE_LOG_DEFAULT + 2)
#define TCP_RRE_LOG_SACK  (TCP_RRE_LOG_DEFAULT + 3)
#define TCP_RRE_LOG_VERBOSE  (TCP_RRE_LOG_DEFAULT + 4)

#define TCP_RRE_MODE_INVALID  0
#define TCP_RRE_MODE_INIT  (TCP_RRE_MODE_INVALID + 1)
#define TCP_RRE_MODE_BM  (TCP_RRE_MODE_INVALID + 2)
#define TCP_RRE_MODE_PRE_MONITOR  (TCP_RRE_MODE_INVALID + 3)
#define TCP_RRE_MODE_MONITOR  (TCP_RRE_MODE_INVALID + 4)

#define TCP_RRE_STATE_INVALID  0
#define TCP_RRE_STATE_FILL  (TCP_RRE_STATE_INVALID + 1)
#define TCP_RRE_STATE_DRAIN  (TCP_RRE_STATE_INVALID + 2)
#define TCP_RRE_STATE_FORCE_DRAIN  (TCP_RRE_STATE_INVALID + 3)
#define TCP_RRE_STATE_SACK  (TCP_RRE_STATE_INVALID + 4)
#define TCP_RRE_STATE_SACK_DONE  (TCP_RRE_STATE_INVALID + 5)

struct revsw_rre {
	u32 rre_ack_r1;
	u32 rre_ts_r1;
	/*
	 * The following 2 variables are overloaded.
	 * They are used differnetly in INIT/BM modes
	 */
	u32 rre_ack_r2;
	u32 rre_ts_r2;

	u32 rre_last_snd_nxt;
	u32 rre_leak_start_ts;
	u32 rre_bytes_sent_this_leak;
	u32 rre_sending_rate;	/*  sending_rate is in bytes/sec */

	u32 rre_T;		/* number of bytes. */
	u32 rre_Bmax;		/* number of bytes. */
	u32 rre_Bmin;		/* number of bytes. */
	int rre_RDmin;		/* in ticks */
	u32 rre_rtt_min;	/* in miliseconds */

	u32 rre_init_cwnd;
	u32 rre_last_sacked_out;
	u32 rre_sack_time_stamp;
	struct ewma rre_receiving_rate;
	u32 rre_first_rtt;

	u32 rre_drain_start_ts;

	u8 rre_mode;
	u8 rre_state;
};

#define LOG_IT(loglevel, format, ...)  { \
	if (revsw_tcp_rre_loglevel && revsw_tcp_rre_loglevel >= loglevel)  { \
		if (loglevel == TCP_RRE_LOG_ERR)		\
			pr_err(format, ## __VA_ARGS__);		\
		else if (loglevel == TCP_RRE_LOG_INFO)		\
			pr_info(format, ## __VA_ARGS__);	\
		else						\
			pr_debug(format, ## __VA_ARGS__);	\
	}							\
}

#define TCP_RRE_SET_STATE(rre, state)  { \
	LOG_IT(TCP_RRE_LOG_VERBOSE, "Setting State from %u to %u\n", \
			rre->rre_state, state);	\
	rre->rre_state = state;	\
}

/*
 * @tcp_rre_receive_rate
 *
 * Calculate the rate at which reciver is receving data. Our sending rate
 * is calculated based on this value.
 *
 * TODO: Use client TCP timestamp's estimated value.
 * (Current Assumptuion: receiver tick is same as sender tick.)
 */
static u32 tcp_rre_receive_rate(struct tcp_sock *tp,
					struct revsw_rre *rre,
					u32 ack)
{
	unsigned long r_rate;
	u32 acked_data, ticks_delta, time_in_milisecs, sacked_bytes = 0;
	u32 acks_since_last_copy;

	if (tp->sacked_out > rre->rre_last_sacked_out) {
		sacked_bytes = (tp->sacked_out - rre->rre_last_sacked_out)
						* tp->mss_cache;
		rre->rre_last_sacked_out = tp->sacked_out;
	}

	acked_data = (ack - rre->rre_ack_r1) + sacked_bytes;
	ticks_delta = tp->rx_opt.rcv_tsval - rre->rre_ts_r1;
	time_in_milisecs = jiffies_to_msecs(ticks_delta);
	if (time_in_milisecs == 0) {
		LOG_IT(TCP_RRE_LOG_ERR, "%s: ZERO miliseconds past?????\n\n",
								__func__);
		return 0;
	}
	/* r_rate is in bytes/sec */
	r_rate = (unsigned long) ((1000*acked_data)/time_in_milisecs);
	ewma_add(&rre->rre_receiving_rate, r_rate);

	/*
	 * TODO: for "pass-time", note we are using ticks from client.
	 * Make sure we know the tick granularity accurately.
	 * TODO: If possible use local timestamp for this.
	 */

	acks_since_last_copy =
		(rre->rre_ack_r2 + tp->mss_cache * TCP_RRE_TBUFF_PACKETS);
	if ((ack + sacked_bytes > acks_since_last_copy)) {
		rre->rre_ts_r1	= rre->rre_ts_r2;
		rre->rre_ack_r1	= rre->rre_ack_r2;
		rre->rre_ts_r2	= tp->rx_opt.rcv_tsval;
		rre->rre_ack_r2	= ack;
		LOG_IT(TCP_RRE_LOG_INFO, "r1 r2, sr %u and %u / %u\n",
			rre->rre_sending_rate, ack,
			acks_since_last_copy);
	}

	LOG_IT(TCP_RRE_LOG_VERBOSE,
	"ackd_bytes %u in %u ms. ack %u. r_rate %lu, r_ewma %lu.snd_r = %u\n",
			acked_data, time_in_milisecs, ack, r_rate,
			ewma_read(&rre->rre_receiving_rate),
			rre->rre_sending_rate);

	LOG_IT(TCP_RRE_LOG_VERBOSE,
	"ack %u ; r_rate %lu, avg %lu. snd_r = %u\n",
			ack, r_rate,
			ewma_read(&rre->rre_receiving_rate),
			rre->rre_sending_rate);

	return (u32) r_rate;

}

/*
 * @tcp_rre_fill_buffer
 *
 * Set Sending rate to > buffer drain rate which will fill network buffer.
 */
static inline void tcp_rre_fill_buffer(struct tcp_sock *tp,
					 struct revsw_rre *rre)
{
	u32 srtt_msecs, delta_sending_rate;

	srtt_msecs = jiffies_to_msecs(tp->srtt >> 3);
	delta_sending_rate =
		((1000 * (rre->rre_Bmax - rre->rre_T)) / srtt_msecs);
	rre->rre_sending_rate = (u32) ewma_read(&rre->rre_receiving_rate);
	rre->rre_sending_rate += delta_sending_rate;
	rre->rre_state = TCP_RRE_STATE_FILL;
	rre->rre_drain_start_ts = 0;

	LOG_IT(TCP_RRE_LOG_VERBOSE,
				"delta_sending_rate %u and sending_rate = %u\n",
				delta_sending_rate, rre->rre_sending_rate);
	return;
}

/*
 * @tcp_rre_drain_buffer
 *
 * Set Sending rate < buffer drain rate which will drain network buffer.
 */
static inline void tcp_rre_drain_buffer(struct tcp_sock *tp,
						struct revsw_rre *rre)
{
	u32 srtt_msecs, delta_sending_rate;

	srtt_msecs = jiffies_to_msecs(tp->srtt >> 3);
	delta_sending_rate =
		(1000 * (rre->rre_T - rre->rre_Bmin) / srtt_msecs);
	rre->rre_sending_rate =	(u32) ewma_read(&rre->rre_receiving_rate);
	rre->rre_sending_rate -= delta_sending_rate;
	if (rre->rre_state == TCP_RRE_STATE_FORCE_DRAIN) {
		TCP_RRE_SET_STATE(rre, TCP_RRE_STATE_SACK);
	} else {
		/* Set state to TCP_RRE_STATE_DRAIN */
		TCP_RRE_SET_STATE(rre, TCP_RRE_STATE_DRAIN);
	}

	if (rre->rre_drain_start_ts == 0)
		rre->rre_drain_start_ts = tcp_time_stamp;

	LOG_IT(TCP_RRE_LOG_VERBOSE,
			"delta_sending_rate %u and sending_rate = %u\n",
			delta_sending_rate, rre->rre_sending_rate);
	return;
}

/*
 * @tcp_rre_process_mode_bm
 *
 * This function is called whne TCP-RRE is in BM (Buffer Management) MODE and
 * when we recive an ack/sack.
 */
static void tcp_rre_process_mode_bm(struct tcp_sock *tp,
			struct revsw_rre *rre,
			u32 ack)
{
	int tbuff, RD, network_buffer_capacity;

	tcp_rre_receive_rate(tp, rre, ack);

	RD = tp->rx_opt.rcv_tsval - tp->rx_opt.rcv_tsecr;
	if (RD < rre->rre_RDmin)
		rre->rre_RDmin = RD;
	tbuff = RD - rre->rre_RDmin;

	/* TODO: We may not need BUG_ON after RRE implementation is complete */
	BUG_ON(tbuff < 0);

	if (rre->rre_state == TCP_RRE_STATE_FORCE_DRAIN) {
		tcp_rre_drain_buffer(tp, rre);
	} else if (rre->rre_state != TCP_RRE_STATE_SACK) {
		network_buffer_capacity = ((rre->rre_T * 1000) /
				(u32) ewma_read(&rre->rre_receiving_rate));

		if (jiffies_to_msecs(tbuff) < network_buffer_capacity)
			tcp_rre_fill_buffer(tp, rre);
		else
			tcp_rre_drain_buffer(tp, rre);

		LOG_IT(TCP_RRE_LOG_VERBOSE,
		"(BM) tbuff = %d, network_buffer_capacity = %d, rtt-min %u.\n",
			jiffies_to_msecs(tbuff),
			network_buffer_capacity,
			rre->rre_rtt_min);
	}

}

/*
 * @tcp_rre_enter_monitor_mode
 *
 * Enter Monitor Mode
 * TODO: handle tcp_time_stamp reset
 */
static inline void tcp_rre_enter_monitor_mode(struct tcp_sock *tp,
							struct revsw_rre *rre)
{
	if (tp->sacked_out || tp->lost_out) {
		if (rre->rre_mode != TCP_RRE_MODE_PRE_MONITOR) {
			rre->rre_mode = TCP_RRE_MODE_PRE_MONITOR;
			rre->rre_sending_rate =
					max_t(u32, rre->rre_sending_rate/2, 10);
		}
		/* Wait until we get ack for all SACKED and LOST packets */
		return;
	}

	if (rre->rre_mode == TCP_RRE_MODE_PRE_MONITOR) {
		/*
		 * The sending rate is already reduced in PRE_MONITOR mode.
		 * Now that we do not have any oustanding RTO/SACK
		 * packets, reset sending_rate.
		 */
		rre->rre_sending_rate =
			max_t(u32, rre->rre_sending_rate, revsw_cong_wnd);
	} else {
		/*
		 * Recuce sending rate so that we drain network buffers.
		 */
		rre->rre_sending_rate =
			max_t(u32, rre->rre_sending_rate/2, revsw_cong_wnd);
	}

	/*
	 * TODO: Do we want to wait for (say) 1 RTT before we
	 * record these values. The reason is that if we send at
	 * a lower rate for one RTT, the buffer will drain and we
	 * get a more accurate RDmin.
	 */
	/* Reset some variables */
	rre->rre_ack_r1 = rre->rre_ts_r1 = 0;
	rre->rre_ack_r2 = rre->rre_ts_r2 = 0;
	rre->rre_T = rre->rre_Bmax = rre->rre_Bmin = 0;
	rre->rre_RDmin = rre->rre_rtt_min = 0;

	rre->rre_ack_r2	= tp->snd_una;
	rre->rre_mode	= TCP_RRE_MODE_MONITOR;
	rre->rre_state	= TCP_RRE_STATE_INVALID;
	ewma_init(&rre->rre_receiving_rate, 1024, 2);

	LOG_IT(TCP_RRE_LOG_INFO, "Entering Monitor Mode (snd_una: %u)\n",
		tp->snd_una);

	return;
}

static inline void tcp_rre_process_pre_monitor(struct tcp_sock *tp,
						struct revsw_rre *rre,
						u32 ack)
{
	if (tp->sacked_out > rre->rre_last_sacked_out) {
		/* Got another SACK, reduce sending_rate again */
		rre->rre_sending_rate = max_t(u32, rre->rre_sending_rate/2, 10);
	}
	tcp_rre_receive_rate(tp, rre, ack);
	tcp_rre_enter_monitor_mode(tp, rre);

	return;
}

/*
 * @tcp_rre_enter_bm_mode
 *
 * Set RRE CCA variables after we get first valid ack.
 */
static inline void tcp_rre_post_first_valid_ack(struct tcp_sock *tp,
						struct revsw_rre *rre,
						u32 ack)
{
	LOG_IT(TCP_RRE_LOG_INFO, "\nFirst valid ACK %u\n", ack);
	rre->rre_ts_r1	= tp->rx_opt.rcv_tsval;
	rre->rre_ack_r1	= ack;
	rre->rre_RDmin	=
	(int) (tp->rx_opt.rcv_tsval - tp->rx_opt.rcv_tsecr);
	rre->rre_ts_r2	= tp->rx_opt.rcv_tsecr;
	return;
}

/*
 * @tcp_rre_enter_bm_mode
 *
 * Enter BM mode.
 */
static inline void tcp_rre_enter_bm_mode(struct tcp_sock *tp,
						struct revsw_rre *rre,
						u32 ack)
{
	u32 avg_r_rate;

	LOG_IT(TCP_RRE_LOG_INFO,
		"Switching to BM mode after %u packets are acked.\n",
		(ack - rre->rre_ack_r2)/tp->mss_cache);

	rre->rre_ts_r2 = tp->rx_opt.rcv_tsval;
	rre->rre_ack_r2 = ack;

	tcp_rre_receive_rate(tp, rre, ack);

	avg_r_rate = (u32) ewma_read(&rre->rre_receiving_rate);
	rre->rre_T = ((avg_r_rate) * rre->rre_rtt_min) / 1000;
	rre->rre_Bmax = rre->rre_T + (rre->rre_T >> 1); /* t + t/2 */
	rre->rre_Bmin = rre->rre_T - (rre->rre_T >> 1); /* t - t/2 */

	LOG_IT(TCP_RRE_LOG_INFO, "T %u, Bmax %u, Bmin %u, RDmin %d\n",
			rre->rre_T,
			rre->rre_Bmax,
			rre->rre_Bmin,
			rre->rre_RDmin);

	rre->rre_sending_rate = avg_r_rate;
	rre->rre_mode = TCP_RRE_MODE_BM;

	return;
}

/*
 * @tcp_rre_init_monitor_common
 *
 * Common processing for init and monitor mode
 */
static inline void tcp_rre_init_monitor_common(struct tcp_sock *tp,
						struct revsw_rre *rre,
						u32 ack)
{
	int enter_BM_mode;

	if (ack >= (rre->rre_ack_r2 +
		(tp->mss_cache * TCP_RRE_PACKETS_REQ_CALC_RATE))) {

		/*
		* TODO: Do we want to check if sending_rate MUCH LESSER than
		* receiving_rate ?
		* TODO: Ex: Sending_rate + ((tp->srtt >> 3)/2) < receiving_rate
		*/

		/* if (sending_rate < receiving rate) */
		if ((tp->rx_opt.rcv_tsecr - rre->rre_ts_r2) <
			(tp->rx_opt.rcv_tsval - rre->rre_ts_r1)) {
			/*
			 * If we receive TCP_RRE_PACKETS_REQ_CALC_RATE and
			 * ONLY if those packets were transmitted faster than
			 * the receiver rate, use it for
			 * calculating reciver rate.
			 */
			enter_BM_mode = 1;
		} else {
			LOG_IT(TCP_RRE_LOG_INFO, "Slow Sender\n");
			rre->rre_ts_r2  = tp->rx_opt.rcv_tsecr;
			rre->rre_ts_r1  = tp->rx_opt.rcv_tsval;
			rre->rre_ack_r1 = ack;
			rre->rre_RDmin  =
			(int) (tp->rx_opt.rcv_tsval - tp->rx_opt.rcv_tsecr);
			rre->rre_ack_r2 = ack;
			rre->rre_sending_rate = rre->rre_init_cwnd *
					       tp->mss_cache;
			enter_BM_mode = 0;
		}
		if (enter_BM_mode)
			tcp_rre_enter_bm_mode(tp, rre, ack);
	}

	return;
}

/*
 * @tcp_rre_init_monitor_common
 *
 * Set sending rate when you are in init mode. Unless we
 * have recived a SACK, it will be exponential growth
 */
static inline void tcp_rre_set_init_monitor_sending_rate(
					struct tcp_sock *tp,
					struct revsw_rre *rre)
{
	if (rre->rre_mode == TCP_RRE_MODE_INIT ||
		rre->rre_mode == TCP_RRE_MODE_MONITOR) {
		if (rre->rre_state == TCP_RRE_STATE_FORCE_DRAIN) {
			/* TODO: Decrease sending_rate ? */
			TCP_RRE_SET_STATE(rre, TCP_RRE_STATE_SACK);
		} else {
			 /* Exponential growth */
			rre->rre_sending_rate += (2 * tp->mss_cache);
			LOG_IT(TCP_RRE_LOG_VERBOSE,
				"INIT. Exp Growth. Sending Rate: %u\n",
					rre->rre_sending_rate);
		}
	} else {
		if (rre->rre_state == TCP_RRE_STATE_FORCE_DRAIN)
			tcp_rre_drain_buffer(tp, rre);
		else
			tcp_rre_fill_buffer(tp, rre);

		LOG_IT(TCP_RRE_LOG_SACK,
			"Mode: %u. State %u. Sending Rate: %u\n",
			rre->rre_mode, rre->rre_state, rre->rre_sending_rate);
	}

	return;
}

/*
 * @tcp_rre_process_mode_monitor
 *
 * This function is called when TCP-RRE is
 * in MONITOR MODE and when we recive an ack/sack.
 */
static void tcp_rre_process_mode_monitor(struct tcp_sock *tp,
						struct revsw_rre *rre,
						u32 ack)
{
	if (rre->rre_ack_r1 == 0 && ack > rre->rre_ack_r2) {
		/*
		 * We have received all data sent before
		 * entering monitor mode. Start receive
		 * rate calculation now. rre->rre_ack_r1
		 */
		tcp_rre_post_first_valid_ack(tp, rre, ack);
	} else {
		tcp_rre_init_monitor_common(tp, rre, ack);
	}

	tcp_rre_set_init_monitor_sending_rate(tp, rre);

	return;
}

/*
 * @tcp_rre_process_mode_init
 *
 * This function is called whne TCP-RRE is in INIT MODE
 * and when we recive an ack/sack.
 */
static void tcp_rre_process_mode_init(struct tcp_sock *tp,
						struct revsw_rre *rre,
						u32 ack)
{
	if (rre->rre_ack_r1 == 0)
		tcp_rre_post_first_valid_ack(tp, rre, ack);
	else
		tcp_rre_init_monitor_common(tp, rre, ack);

	tcp_rre_set_init_monitor_sending_rate(tp, rre);

	return;
}

/*
 * @tcp_rre_common_ack
 *
 * This function is common for both fast and slow ack
 */
static inline void tcp_rre_common_ack(struct tcp_sock *tp,
						 struct revsw_rre *rre)
{
	if (rre->rre_state == TCP_RRE_STATE_SACK &&
			((tcp_time_stamp - rre->rre_sack_time_stamp) >
			(tp->srtt >> 3))) {
		/*
		 * Throttle sending_rate only for one RTT after
		 * SACK
		 */
		LOG_IT(TCP_RRE_LOG_INFO, "\n\t\t RTT\n\n");
		TCP_RRE_SET_STATE(rre, TCP_RRE_STATE_SACK_DONE);
	}

	switch (rre->rre_mode) {
	case TCP_RRE_MODE_INVALID:
		BUG_ON(rre->rre_mode == TCP_RRE_MODE_INVALID);
		break;

	case TCP_RRE_MODE_INIT:
		tcp_rre_process_mode_init(tp, rre, tp->snd_una);
		break;

	case TCP_RRE_MODE_BM:
		tcp_rre_process_mode_bm(tp, rre, tp->snd_una);
		break;

	case TCP_RRE_MODE_PRE_MONITOR:
		tcp_rre_process_pre_monitor(tp, rre, tp->snd_una);
		break;

	case TCP_RRE_MODE_MONITOR:
		tcp_rre_process_mode_monitor(tp, rre, tp->snd_una);
		break;

	default:
		BUG_ON(1);
		break;
	}
}

/*
 * @tcp_rre_handle_slow_ack
 *
 * Handle slow ack.
 */
static inline void tcp_rre_handle_slow_ack(struct tcp_sock *tp,
							 struct revsw_rre *rre)
{
	if (tp->sacked_out != rre->rre_last_sacked_out) {
		if (tp->sacked_out &&
			((tcp_time_stamp - rre->rre_sack_time_stamp) >
				(tp->srtt >> 3))) {
			/* Fresh SACK */
			TCP_RRE_SET_STATE(rre, TCP_RRE_STATE_FORCE_DRAIN);
			rre->rre_sack_time_stamp = tcp_time_stamp;
			LOG_IT(TCP_RRE_LOG_INFO, "\t\tSACK\n\n");
		}
		/*rre->rre_last_sacked_out = tp->sacked_out;*/

		LOG_IT(TCP_RRE_LOG_SACK, "sacked_out %u. ack %u ..",
				tp->sacked_out,
				tp->snd_una);

		LOG_IT(TCP_RRE_LOG_SACK,
			"Blocks: %u %u, %u %u, %u %u, %u %u\n",
			tp->recv_sack_cache[0].start_seq,
			tp->recv_sack_cache[0].end_seq,
			tp->recv_sack_cache[1].start_seq,
			tp->recv_sack_cache[1].end_seq,
			tp->recv_sack_cache[2].start_seq,
			tp->recv_sack_cache[2].end_seq,
			tp->recv_sack_cache[3].start_seq,
			tp->recv_sack_cache[3].end_seq);
	}

	tcp_rre_common_ack(tp, rre);
}

/*
 * @tcp_rre_handle_fast_ack
 *
 * Handle fast ack.
 */
static inline void tcp_rre_handle_fast_ack(struct tcp_sock *tp,
							struct revsw_rre *rre)
{
	if (tp->sacked_out && (tp->sacked_out != rre->rre_last_sacked_out))
		LOG_IT(TCP_RRE_LOG_ERR, "sacked_out in fast ack? %u %u\n",
				tp->sacked_out, rre->rre_last_sacked_out);

	if (tp->sacked_out != rre->rre_last_sacked_out) {
		LOG_IT(TCP_RRE_LOG_INFO, "last sacked out updated! %u %u",
				tp->sacked_out, rre->rre_last_sacked_out);
		rre->rre_last_sacked_out = tp->sacked_out;
	}

	tcp_rre_common_ack(tp, rre);
}

/*
 * @tcp_rre_remaining_leak_quota
 *
 * Return number of packets that can be sent as part
 * of this leak
 *
 * TODO: handle tcp_time_stamp reset
 */
static inline int tcp_rre_remaining_leak_quota(struct tcp_sock *tp,
							struct revsw_rre *rre)
{
	/* Bytes Sent out after the last call to this function. */
	u32 bytes_sent;
	/* Quota: Bytes that can be sent out on wire. */
	u32 quota;
	/* Time since this leak started (Used to maintain leakrate/sec) */
	u32 leak_time;

	leak_time = jiffies_to_msecs(tcp_time_stamp - rre->rre_leak_start_ts);
	if (leak_time <= 1000) { /* Still in same leak/drop. */
		bytes_sent = tp->snd_nxt - rre->rre_last_snd_nxt;
		rre->rre_bytes_sent_this_leak += bytes_sent;
		if (rre->rre_bytes_sent_this_leak < rre->rre_sending_rate) {
			/* We can send more data out on wire in this leak */
			quota = rre->rre_sending_rate -
						rre->rre_bytes_sent_this_leak;
		} else {
			quota = 0;
		}
	} else {
		/* Next leak */
		rre->rre_leak_start_ts = tcp_time_stamp -
				msecs_to_jiffies((leak_time - 1000) % 1000);
		rre->rre_bytes_sent_this_leak = 0;
		quota = rre->rre_sending_rate;
	}

	return quota;
}

/*
 * @tcp_rre_get_cwnd_quota
 *
 * This function is called before sending any packet out on wire.
 * Here we determine the number of packets that can be sent
 * out in this leak. A leak is number of packets per second
 * which is = sending_rate.
 *
 * TODO: handle tcp_time_stamp reset
 */
static int tcp_rre_get_cwnd_quota(struct sock *sk, const struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct revsw_rre *rre = inet_csk_ca(sk);
	/* Quota: Bytes that can be sent out on wire. */
	u32 quota;

	if (rre->rre_last_snd_nxt == 0) {

		/*
		 * First Drop.
		 * First time this function is getting called for this socket.
		 */

		rre->rre_bytes_sent_this_leak	= 0;
		rre->rre_leak_start_ts	= tcp_time_stamp;
		rre->rre_init_cwnd	= revsw_cong_wnd;
		rre->rre_mode		= TCP_RRE_MODE_INIT;
		rre->rre_ack_r2		= tp->snd_una;
		rre->rre_sending_rate	= quota = rre->rre_init_cwnd * 1448;
		ewma_init(&rre->rre_receiving_rate, 1024, 2);

		LOG_IT(TCP_RRE_LOG_INFO, "Very first packet (snd_una: %u)\n",
								tp->snd_una);
	} else {
		if (rre->rre_mode != TCP_RRE_MODE_MONITOR &&
			rre->rre_mode != TCP_RRE_MODE_PRE_MONITOR &&
			rre->rre_drain_start_ts > (4 * (tp->srtt >> 3))) {
			/*
			 * Enter Monitor Mode. We are in
			 * BUFFER_DRAIN state for more than 4 RTT
			 */
			tcp_rre_enter_monitor_mode(tp, rre);
		}
		quota = tcp_rre_remaining_leak_quota(tp, rre);
	}

	LOG_IT(TCP_RRE_LOG_VERBOSE, "Quota: %u, snd_rate %u, BY_sent %u,",
		quota, rre->rre_sending_rate, rre->rre_bytes_sent_this_leak);

	LOG_IT(TCP_RRE_LOG_VERBOSE,
		" last_sndnxt %u, sndnxt = %u, flight %u and tcp_TS %u\n",
		rre->rre_last_snd_nxt, tp->snd_nxt, tcp_packets_in_flight(tp),
		tcp_time_stamp);

	rre->rre_last_snd_nxt = tp->snd_nxt;
	/*
	 * The TCP stack checks tp->snd_cwnd value at several
	 * places. Anyway this variable has no significance when
	 * TCP-RRE is used as CCA. The 2 conditions which we
	 * have to meet pacify the stack are
	 * (1) it shouldn't be zero (2) It > packets_in_flight.
	 */
	tp->snd_cwnd = max(tp->snd_cwnd, tcp_packets_in_flight(tp)+1);

	return (int) (quota/tp->mss_cache);
}

/*
 * @tcp_rre_init
 *
 * Starts session DB for this connection.
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

/*
 * @tcp_rre_ssthresh
 *
 * This is a mandatory callback function. Currently not used by RRE.
 * TODO: Check where this function si called from and if we can use
 * this for RRE.
 * TODO: Also check if returning a different value makes
 * any difference to RRE
 */
static u32 tcp_rre_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	return tp->snd_cwnd;
}

/*
 * @tcp_rre_cong_avoid
 *
 * This is a mandatory callback function. Currently not used by RRE.
 * TODO: Check where this function si called from and if we can use
 * this for RRE.
 * TODO: Also check if returning a different value makes
 * any difference to RRE
 */
static void tcp_rre_cong_avoid(struct sock *sk, u32 ack, u32 in_flight)
{
	tcp_sk(sk)->snd_cwnd + 2;
}

/*
 * @tcp_rre_pkts_acked
 *
 * Called after processing group of packets.
 * but all RRE needs is the minimum RTT.
 */
static void tcp_rre_pkts_acked(struct sock *sk, u32 cnt, s32 rtt)
{
	struct revsw_rre *rre = inet_csk_ca(sk);

	if (rtt > 0) {
		if (rre->rre_rtt_min == 0) {
			rre->rre_rtt_min = (((u32)rtt) / USEC_PER_MSEC);
			LOG_IT(TCP_RRE_LOG_INFO,
				"Setting rtt-min: %u\n", rre->rre_rtt_min);
		} else {
			rre->rre_rtt_min = min_t(u32,
				(((u32)rtt) / USEC_PER_MSEC),
				rre->rre_rtt_min);
		}
	}

}

/*
 * @tcp_rre_state
 *
 * Handling RTO in this function.
 */
static void tcp_rre_state(struct sock *sk, u8 new_state)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct revsw_rre *rre = inet_csk_ca(sk);

	if (new_state == TCP_CA_Loss) {
		LOG_IT(TCP_RRE_LOG_INFO, "TCP_CA_Loss State\n");
		TCP_RRE_SET_STATE(rre, TCP_RRE_STATE_FORCE_DRAIN);
		rre->rre_sack_time_stamp = tcp_time_stamp;
		tcp_rre_drain_buffer(tp, rre);
	}
}

/*
 * @tcp_rre_event
 *
 * Fast acks and Slow acks used to calculate receiving rate and adjust
 *  sending rate. SACK is also handled (with respect to RRE) in this function.
 */
static void tcp_rre_event(struct sock *sk, enum tcp_ca_event event)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct revsw_rre *rre = inet_csk_ca(sk);

	switch (event) {
	case CA_EVENT_FAST_ACK:
		tcp_rre_handle_fast_ack(tp, rre);
		break;

	case CA_EVENT_SLOW_ACK:
		tcp_rre_handle_slow_ack(tp, rre);
		break;

	default:
		/* don't care */
		break;
	}
}

/*
 * @tcp_rre_syn_post_config
 *
 * Use this function to calculate first RTT which inturn is used to
 * estimate client's TCP timestamp. (To be implemented)
 */
static void tcp_rre_syn_post_config(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	/*struct revsw_rre *rre = inet_csk_ca(sk);*/

	LOG_IT(TCP_RRE_LOG_INFO, "I am in tcp_rre_syn_post_config\n");

	/*tp->rre_first_hs_tsval =
			tp->rre_first_hs_tsval-tp->rx_opt.rcv_tsval;*/
	/*rre->rre_first_rtt = tcp_time_stamp - tp->rx_opt.rcv_tsecr;*/

	/* TODO: Use same function from both revsw and rre modules. */
	/*
	 * Modify the congestion and send windows.  Also fix the
	 * sndbuf size.  Will be changed to use sysctls when they
	 * are available.
	 */
	sk->sk_sndbuf = 3 * tp->snd_wnd;
}

static bool
tcp_rre_handle_nagle_test(struct sock *sk, struct sk_buff *skb,
			    unsigned int mss_now, int nonagle)
{
	return true;
}

static bool
tcp_rre_snd_wnd_test(const struct tcp_sock *tp,const struct sk_buff *skb,
		     unsigned int cur_mss)
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
	.syn_post_config = tcp_rre_syn_post_config,
	.set_nwin_size = NULL,
	.handle_nagle_test = tcp_rre_handle_nagle_test,
	.get_session_info = tcp_session_get_info,
	.get_cwnd_quota = tcp_rre_get_cwnd_quota,
	.snd_wnd_test = tcp_rre_snd_wnd_test,

	.owner		= THIS_MODULE,
	.name		= "rre"
};

static int __init tcp_rre_register(void)
{
	BUILD_BUG_ON(sizeof(struct revsw_rre) > ICSK_CA_PRIV_SIZE);
	return tcp_register_congestion_control(&tcp_rre_cca);
}

static void __exit tcp_rre_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_rre_cca);
}

module_init(tcp_rre_register);
module_exit(tcp_rre_unregister);

MODULE_AUTHOR("Akhil Shashidhar");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP RevSw RRE");

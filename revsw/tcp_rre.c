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
#include "tcp_revsw.h"
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
#define TCP_RRE_TBUFF_PACKETS		30
#define TCP_RRE_MSECS_PER_LEAK		1000
#define TCP_RRE_LEAK_QUOTA_TIMER	990

#define TCP_RRE_LOG_NOLOG  REVSW_RRE_LOG_DEFAULT
#define TCP_RRE_LOG_ERR  (REVSW_RRE_LOG_DEFAULT + 1)
#define TCP_RRE_LOG_INFO  (REVSW_RRE_LOG_DEFAULT + 2)
#define TCP_RRE_LOG_SACK  (REVSW_RRE_LOG_DEFAULT + 3)
#define TCP_RRE_LOG_VERBOSE  (REVSW_RRE_LOG_DEFAULT + 4)

#define TCP_RRE_MODE_INVALID  0
#define TCP_RRE_MODE_INIT  (TCP_RRE_MODE_INVALID + 1)
#define TCP_RRE_MODE_BM  (TCP_RRE_MODE_INVALID + 2)
#define TCP_RRE_MODE_PRE_MONITOR  (TCP_RRE_MODE_INVALID + 3)
#define TCP_RRE_MODE_MONITOR  (TCP_RRE_MODE_INVALID + 4)
#define TCP_RRE_MODE_UNUSED_MAX	(TCP_RRE_MODE_INVALID + 5)

#define TCP_RRE_STATE_INVALID  0
#define TCP_RRE_STATE_FILL  (TCP_RRE_STATE_INVALID + 1)
#define TCP_RRE_STATE_DRAIN  (TCP_RRE_STATE_INVALID + 2)
#define TCP_RRE_STATE_FORCE_DRAIN  (TCP_RRE_STATE_INVALID + 3)
#define TCP_RRE_STATE_SACK  (TCP_RRE_STATE_INVALID + 4)
#define TCP_RRE_STATE_SACK_DONE  (TCP_RRE_STATE_INVALID + 5)
#define TCP_RRE_STATE_UNUSED_MAX  (TCP_RRE_STATE_INVALID + 6)

#define TCP_RRE_HONOR_RCV_WND 0
#define TCP_RRE_IGNORE_INIT_BURST (TCP_RRE_HONOR_RCV_WND + 1)
#define TCP_RRE_HONOR_NO_REXMIT (TCP_RRE_HONOR_RCV_WND + 2)
#define TCP_RRE_IGNORE_RCV_WND (TCP_RRE_HONOR_RCV_WND + 3)

const char *tcp_rre_mode_string[TCP_RRE_MODE_UNUSED_MAX] = {
	"TCP_RRE_MODE_INVALID", "TCP_RRE_MODE_INIT", "TCP_RRE_MODE_BM",
	"TCP_RRE_MODE_PRE_MONITOR", "TCP_RRE_MODE_MONITOR"
	};

const char *tcp_rre_state_string[TCP_RRE_STATE_UNUSED_MAX] = {
	"TCP_RRE_STATE_INVALID", "TCP_RRE_STATE_FILL", "TCP_RRE_STATE_DRAIN",
	"TCP_RRE_STATE_FORCE_DRAIN", "TCP_RRE_STATE_SACK",
	"TCP_RRE_STATE_SACK_DONE"
	};

struct icsk_priv {
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

	u32 rre_rtt_min;	/* in miliseconds */

	u32 rre_init_cwnd;
	u32 rre_last_sacked_out;
	u32 rre_sack_time_stamp;

	u32 rre_drain_start_ts;
	u32 rre_syn_ack_tsecr;
	u32 rre_una;
	u16 rre_estimated_tick_gra;
	u8 rre_mode;
	u8 rre_state;
};

struct sess_priv {
	/* rre_timer has to be first item */
	/*
	 * TODO: Check if we can use any existing timer in scoket
	 * which will some memory
	 */
	struct timer_list rre_timer;

	u32 rre_T;		/* number of bytes. */
	u32 rre_Bmax;		/* number of bytes. */
	u32 rre_Bmin;		/* number of bytes. */
	int rre_RDmin;		/* in ticks */

	struct ewma rre_receiving_rate;
	struct sock *tsk;
};

struct revsw_rre {
	struct icsk_priv *i;
	struct sess_priv *s;
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
	if (rre->i->rre_state != state)	\
		LOG_IT(TCP_RRE_LOG_INFO, "	%s to %s\n", \
			tcp_rre_state_string[rre->i->rre_state],	\
			tcp_rre_state_string[state]);	\
	rre->i->rre_state = state;	\
}

#define TCP_RRE_SET_MODE(rre, mode)  { \
	LOG_IT(TCP_RRE_LOG_INFO, "	%s to %s\n", \
			tcp_rre_mode_string[rre->i->rre_mode],	\
			tcp_rre_mode_string[mode]);	\
	rre->i->rre_mode = mode;	\
}

#define TCP_RRE_PRIVATE_DATE(__rre)	\
{	\
	struct tcp_session_entry *__session = tcp_sk(sk)->session_info;	\
	__rre.i = (struct icsk_priv *) inet_csk_ca(sk);	\
	if (__session)	\
		__rre.s = (struct sess_priv *) (&(__session->cca_priv)); \
	else	\
		__rre.s = NULL;	\
}

#define TCP_RRE_CALC_TBUFF(tp, rre)	do { \
	rre->s->rre_T = tcp_revsw_division(	\
			(((u32) ewma_read(&rre->s->rre_receiving_rate)) \
				* rre->i->rre_rtt_min),	\
				1000);	\
	rre->s->rre_Bmax = rre->s->rre_T + (rre->s->rre_T >> 1); /* t + t/2 */\
	rre->s->rre_Bmin = rre->s->rre_T - (rre->s->rre_T >> 1); /* t - t/2 */\
} while (0)

/* TODO: What do we do when rre->i->rre_estimated_tick_gra  is 0 ? */
#define TCP_RRE_CLINET_JIFFIES_TO_MSECS(rre, ticks, in_msecs)	do { \
	if (rre->i->rre_estimated_tick_gra > 0)	\
		in_msecs = (ticks * rre->i->rre_estimated_tick_gra);	\
	else	\
		in_msecs = jiffies_to_msecs(ticks);	\
} while (0)

/*
 * @tcp_rre_estimate_granularity
 *
 * Estimate client's TCP timestamp granulairty as
 * it is required to calculate the receiving rate.
 */
static inline int tcp_rre_estimate_granularity(struct tcp_sock *tp,
						struct revsw_rre *rre)
{
	int granularity, changed = 0;

	/* granularity = msecs past / num of ticks */
	granularity =
		jiffies_to_msecs(tcp_time_stamp - rre->i->rre_syn_ack_tsecr) /
		(tp->rx_opt.rcv_tsval - tp->rre_syn_tsval);

	if (granularity >= 0 && granularity <= 2) {
		granularity = 1;
	} else if (granularity > 2 && granularity <= 6) {
		granularity = 4;
	} else if (granularity > 6 && granularity <= 14) {
		granularity = 10;
	} else {
		LOG_IT(TCP_RRE_LOG_ERR,
			"Wrong previous Estimation of Client TCP Granularity."
			" Current Estimation: %u. Previous Estimation: %u\n",
				granularity, rre->i->rre_estimated_tick_gra);
		granularity = 0;
	}

	if (granularity != rre->i->rre_estimated_tick_gra) {
		int loglevel;

		if (rre->i->rre_estimated_tick_gra)
			loglevel = TCP_RRE_LOG_ERR;
		else
			loglevel = TCP_RRE_LOG_INFO;

		LOG_IT(loglevel,
			"--------------> Changing granularity from %u to %u\n",
			rre->i->rre_estimated_tick_gra, granularity);

		LOG_IT(TCP_RRE_LOG_INFO,
			"%u %u %u %u\n",
			tcp_time_stamp, rre->i->rre_syn_ack_tsecr,
			tp->rx_opt.rcv_tsval, tp->rre_syn_tsval);

		rre->i->rre_estimated_tick_gra = granularity;
		changed = 1;
	}

	return changed;
}

static void tcp_rre_timer_handler(unsigned long data)
{
	struct sock *sk;
	struct tcp_sock *tp;
	struct revsw_rre *rre, __rre;

	__rre.s = (struct sess_priv *) data;
	if (__rre.s == NULL) {
		LOG_IT(TCP_RRE_LOG_ERR, "%s: ERRORR, data is NULL\n", __func__);
		return;
	}

	sk = __rre.s->tsk;
	if (sk == NULL) {
		LOG_IT(TCP_RRE_LOG_INFO, "%s: tsk is NULL\n", __func__);
		return;
	}

	if (sk->sk_state != TCP_ESTABLISHED) {
		LOG_IT(TCP_RRE_LOG_INFO, "%s: sk_state != TCP_ESTABLISHED\n",
			__func__);
		return;
	}

	tp = tcp_sk(sk);
	__rre.i = (struct icsk_priv *) inet_csk_ca(sk);
	rre = &__rre;

	if (rre->i->rre_bytes_sent_this_leak < rre->i->rre_sending_rate) {
		LOG_IT(TCP_RRE_LOG_INFO,
			"** %s: Quota is not fully utilized\n",
			__func__);

		if (tcp_send_head(sk)) {
			bh_lock_sock(sk);
			/* TODO: Should I hold? */
			sock_hold(sk);
			if (!sock_owned_by_user(sk)) {
				tcp_data_snd_check(sk);
				sk_mem_reclaim(sk);
			} else {
				/*
				 * TODO: delegate our work to tcp_release_cb() ?
				 * or as socket is being used, is it safe to
				 * assume xmit will be called and our
				 * sending_rate is maintained?
				 */
			}

			bh_unlock_sock(sk);
			sock_put(sk);
		}
	} else {
		LOG_IT(TCP_RRE_LOG_INFO,
			"** %s: In Timer Callback\n",
			__func__);

	}

	if (tcp_send_head(sk)) {
		if (mod_timer(&rre->s->rre_timer, jiffies +
			msecs_to_jiffies(TCP_RRE_MSECS_PER_LEAK))) {
			/* TODO: Handle error */
			LOG_IT(TCP_RRE_LOG_ERR,
				"%s: Error modifying timer\n", __func__);
		}
	}

	return;
}

/*
 * @tcp_rre_init_timer
 *
 */
static inline int tcp_rre_init_timer(struct revsw_rre *rre, struct sock *sk)
{
	if (!rre->s)
		return -1;

	if (rre->s->tsk == sk)
		return 0;

	/* TODO: Instead of memset, just set required variables. */
	memset(&rre->s->rre_timer, 0, sizeof(struct sess_priv));
	ewma_init(&rre->s->rre_receiving_rate, 1024, 2);

	/*
	 * Set timer and callback function for maintaining
	 * sending_rate
	 */
	rre->s->tsk = sk;
	setup_timer(&rre->s->rre_timer, tcp_rre_timer_handler,
		(unsigned long) &rre->s->rre_timer);
	if (mod_timer(&rre->s->rre_timer, jiffies +
		msecs_to_jiffies(TCP_RRE_LEAK_QUOTA_TIMER))) {
		LOG_IT(TCP_RRE_LOG_ERR,
			"%s: Error modifying timer\n", __func__);
	}

	return 0;
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
	u32 next_checkpoint;

	if (tp->sacked_out > rre->i->rre_last_sacked_out) {
		sacked_bytes = (tp->sacked_out - rre->i->rre_last_sacked_out)
						* tp->mss_cache;
		rre->i->rre_last_sacked_out = tp->sacked_out;
	}

	acked_data = (ack - rre->i->rre_ack_r1) + sacked_bytes;
	ticks_delta = tp->rx_opt.rcv_tsval - rre->i->rre_ts_r1;
	TCP_RRE_CLINET_JIFFIES_TO_MSECS(rre, ticks_delta, time_in_milisecs);
	if (time_in_milisecs == 0) {
		/* TODO */
		LOG_IT(TCP_RRE_LOG_ERR, "%s: ZERO miliseconds past?????\n\n",
								__func__);
		return 0;
	}
	/* r_rate is in bytes/sec */
	r_rate = (unsigned long) tcp_revsw_division((1000*acked_data),
							time_in_milisecs);
	ewma_add(&rre->s->rre_receiving_rate, r_rate);

	/*
	 * TODO: Should we NOT take sample when we are
	 * in TCP_RRE_STATE_SACK ? As you can see below,
	 * we are taking samples now.
	 */

	next_checkpoint =
		(rre->i->rre_ack_r2 + tp->mss_cache * TCP_RRE_TBUFF_PACKETS);
	if ((ack + sacked_bytes > next_checkpoint)) {
		rre->i->rre_ts_r1	= rre->i->rre_ts_r2;
		rre->i->rre_ack_r1	= rre->i->rre_ack_r2;
		rre->i->rre_ts_r2	= tp->rx_opt.rcv_tsval;
		rre->i->rre_ack_r2	= ack + sacked_bytes;
		if (tcp_rre_estimate_granularity(tp, rre))
			TCP_RRE_CALC_TBUFF(tp, rre);

		LOG_IT(TCP_RRE_LOG_VERBOSE, "r1 r2, sr %u and %u / %u\n",
			rre->i->rre_sending_rate, ack,
			next_checkpoint);
	}

	LOG_IT(TCP_RRE_LOG_VERBOSE,
	"ackd_bytes %u in %u ms. ack %u. r_rate %lu, r_ewma %lu.snd_r = %u\n",
			acked_data, time_in_milisecs, ack, r_rate,
			ewma_read(&rre->s->rre_receiving_rate),
			rre->i->rre_sending_rate);

	LOG_IT(TCP_RRE_LOG_VERBOSE,
	"ack %u ; r_rate %lu, avg %lu. snd_r = %u\n",
			ack, r_rate,
			ewma_read(&rre->s->rre_receiving_rate),
			rre->i->rre_sending_rate);

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
	u32 srtt_msecs;
	u32 delta_sending_rate; /* per second */

	srtt_msecs = jiffies_to_msecs(tp->srtt >> 3);
	delta_sending_rate = tcp_revsw_division(
				(1000 * (rre->s->rre_Bmax - rre->s->rre_T)),
				srtt_msecs);
	rre->i->rre_sending_rate = (u32) ewma_read(&rre->s->rre_receiving_rate);
	rre->i->rre_sending_rate += delta_sending_rate;
	TCP_RRE_SET_STATE(rre, TCP_RRE_STATE_FILL);
	rre->i->rre_drain_start_ts = 0;

	LOG_IT(TCP_RRE_LOG_VERBOSE,
				"delta_sending_rate %u and sending_rate = %u\n",
				delta_sending_rate, rre->i->rre_sending_rate);
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
	u32 srtt_msecs;
	u32 delta_sending_rate; /* per second */

	srtt_msecs = jiffies_to_msecs(tp->srtt >> 3);
	delta_sending_rate = tcp_revsw_division(
				(1000 * (rre->s->rre_T - rre->s->rre_Bmin)),
				srtt_msecs);
	rre->i->rre_sending_rate = (u32) ewma_read(&rre->s->rre_receiving_rate);
	rre->i->rre_sending_rate -= delta_sending_rate;
	if (rre->i->rre_state == TCP_RRE_STATE_FORCE_DRAIN) {
		TCP_RRE_SET_STATE(rre, TCP_RRE_STATE_SACK);
	} else {
		/* Set state to TCP_RRE_STATE_DRAIN */
		TCP_RRE_SET_STATE(rre, TCP_RRE_STATE_DRAIN);
	}

	if (rre->i->rre_drain_start_ts == 0)
		rre->i->rre_drain_start_ts = tcp_time_stamp;

	LOG_IT(TCP_RRE_LOG_VERBOSE,
			"delta_sending_rate %u and sending_rate = %u\n",
			delta_sending_rate, rre->i->rre_sending_rate);
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
	if (RD < rre->s->rre_RDmin)
		rre->s->rre_RDmin = RD;
	tbuff = RD - rre->s->rre_RDmin;

	/* TODO: We may not need BUG_ON after RRE implementation is complete */
	BUG_ON(tbuff < 0);

	if (rre->i->rre_state == TCP_RRE_STATE_FORCE_DRAIN) {
		tcp_rre_drain_buffer(tp, rre);
	} else if (rre->i->rre_state != TCP_RRE_STATE_SACK) {
		network_buffer_capacity = tcp_revsw_division(
				(rre->s->rre_T * 1000),
				(u32) ewma_read(&rre->s->rre_receiving_rate));

		if (jiffies_to_msecs(tbuff) < network_buffer_capacity)
			tcp_rre_fill_buffer(tp, rre);
		else
			tcp_rre_drain_buffer(tp, rre);

		LOG_IT(TCP_RRE_LOG_VERBOSE,
		"(BM) tbuff = %d, network_buffer_capacity = %d, rtt-min %u.\n",
			jiffies_to_msecs(tbuff),
			network_buffer_capacity,
			rre->i->rre_rtt_min);
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
		if (rre->i->rre_mode != TCP_RRE_MODE_PRE_MONITOR) {
			TCP_RRE_SET_MODE(rre, TCP_RRE_MODE_PRE_MONITOR);
			rre->i->rre_sending_rate =
				max_t(u32, rre->i->rre_sending_rate >> 1, 10);
		}
		/* Wait until we get ack for all SACKED and LOST packets */
		return;
	}

	if (rre->i->rre_mode == TCP_RRE_MODE_PRE_MONITOR) {
		/*
		 * The sending rate is already reduced in PRE_MONITOR mode.
		 * Now that we do not have any oustanding RTO/SACK
		 * packets, reset sending_rate.
		 */
		rre->i->rre_sending_rate =
			max_t(u32, rre->i->rre_sending_rate, revsw_cong_wnd);
	} else {
		/*
		 * Recuce sending rate so that we drain network buffers.
		 */
		rre->i->rre_sending_rate =
			max_t(u32, rre->i->rre_sending_rate >> 1,
					revsw_cong_wnd);
	}

	/*
	 * TODO: Do we want to wait for (say) 1 RTT before we
	 * record these values. The reason is that if we send at
	 * a lower rate for one RTT, the buffer will drain and we
	 * get a more accurate RDmin.
	 */
	/* Reset some variables */
	rre->i->rre_ack_r1 = rre->i->rre_ts_r1 = 0;
	rre->i->rre_ack_r2 = rre->i->rre_ts_r2 = 0;
	rre->s->rre_T = rre->s->rre_Bmax = rre->s->rre_Bmin = 0;
	rre->s->rre_RDmin = rre->i->rre_rtt_min = 0;

	if (tcp_rre_init_timer(rre, (struct sock *) tp) == -1) {
		LOG_IT(TCP_RRE_LOG_ERR,
			"%s: Session DB not yet allocated\n", __func__);
		return;
	}


	rre->i->rre_ack_r2	= tp->snd_una;
	rre->i->rre_state	= TCP_RRE_STATE_INVALID;
	TCP_RRE_SET_MODE(rre, TCP_RRE_MODE_MONITOR);
	ewma_init(&rre->s->rre_receiving_rate, 1024, 2);

	LOG_IT(TCP_RRE_LOG_INFO, "Entering Monitor Mode (snd_una: %u)\n",
		tp->snd_una);

	return;
}

static inline void tcp_rre_process_pre_monitor(struct tcp_sock *tp,
						struct revsw_rre *rre,
						u32 ack)
{
	if (tp->sacked_out > rre->i->rre_last_sacked_out) {
		/* Got another SACK, reduce sending_rate again */
		rre->i->rre_sending_rate = max_t(u32,
					rre->i->rre_sending_rate >> 1, 10);
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
	LOG_IT(TCP_RRE_LOG_INFO, "\nFirst valid ACK %u. %u / %u\n",
							ack,
							tp->snd_cwnd,
							tp->snd_wnd);
	rre->i->rre_ts_r1	= tp->rx_opt.rcv_tsval;
	rre->i->rre_ack_r1	= ack;
	rre->s->rre_RDmin	=
	(int) (tp->rx_opt.rcv_tsval - tp->rx_opt.rcv_tsecr);
	rre->i->rre_ts_r2	= tp->rx_opt.rcv_tsecr;
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
	LOG_IT(TCP_RRE_LOG_INFO,
		"Switching to BM mode after %u packets are acked.\n",
		tcp_revsw_division((ack - rre->i->rre_ack_r2), tp->mss_cache));

	rre->i->rre_ts_r2 = tp->rx_opt.rcv_tsval;
	rre->i->rre_ack_r2 = ack;

	tcp_rre_receive_rate(tp, rre, ack);
	TCP_RRE_CALC_TBUFF(tp, rre);

	LOG_IT(TCP_RRE_LOG_INFO,
			"T %u, Bmax %u, Bmin %u, RDmin %d. r_rate = %u\n",
			rre->s->rre_T,
			rre->s->rre_Bmax,
			rre->s->rre_Bmin,
			rre->s->rre_RDmin,
			(u32) ewma_read(&rre->s->rre_receiving_rate));

	rre->i->rre_sending_rate = (u32) ewma_read(&rre->s->rre_receiving_rate);
	TCP_RRE_SET_MODE(rre, TCP_RRE_MODE_BM);

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
	u32 received_in_msecs;

	if (ack >= (rre->i->rre_ack_r2 +
		(tp->mss_cache * TCP_RRE_PACKETS_REQ_CALC_RATE))) {

		tcp_rre_estimate_granularity(tp, rre);
		/*
		* TODO: Do we want to check if sending_rate MUCH LESSER than
		* received_in_msecs ?
		* TODO: Ex: Sending_rate + ((tp->srtt >> 3)/2) < receiving_rate
		*/

		TCP_RRE_CLINET_JIFFIES_TO_MSECS(rre,
				(tp->rx_opt.rcv_tsval - rre->i->rre_ts_r1),
				received_in_msecs);
		/* if (sending_rate < receiving rate) */
		if (jiffies_to_msecs(tp->rx_opt.rcv_tsecr - rre->i->rre_ts_r2) <
			received_in_msecs) {
			/*
			 * If we receive TCP_RRE_PACKETS_REQ_CALC_RATE and
			 * ONLY if those packets were transmitted faster than
			 * the receiver rate, use it for
			 * calculating reciver rate.
			 */
			enter_BM_mode = 1;
		} else {
			LOG_IT(TCP_RRE_LOG_INFO, "Slow Sender\n");
			rre->i->rre_ts_r2  = tp->rx_opt.rcv_tsecr;
			rre->i->rre_ts_r1  = tp->rx_opt.rcv_tsval;
			rre->i->rre_ack_r1 = ack;
			rre->s->rre_RDmin  =
			(int) (tp->rx_opt.rcv_tsval - tp->rx_opt.rcv_tsecr);
			rre->i->rre_ack_r2 = ack;
			rre->i->rre_sending_rate = rre->i->rre_init_cwnd *
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
	if (rre->i->rre_mode == TCP_RRE_MODE_INIT ||
		rre->i->rre_mode == TCP_RRE_MODE_MONITOR) {
		if (rre->i->rre_state == TCP_RRE_STATE_FORCE_DRAIN) {
			/* TODO: Decrease sending_rate ? */
			TCP_RRE_SET_STATE(rre, TCP_RRE_STATE_SACK);
		} else {
			rre->i->rre_sending_rate += (3 *
					(tp->snd_una - rre->i->rre_una));
			LOG_IT(TCP_RRE_LOG_VERBOSE,
				"INIT. Exp Growth. Sending Rate: %u\n",
					rre->i->rre_sending_rate);
		}
	} else {
		if (rre->i->rre_state == TCP_RRE_STATE_FORCE_DRAIN)
			tcp_rre_drain_buffer(tp, rre);
		else
			tcp_rre_fill_buffer(tp, rre);

		LOG_IT(TCP_RRE_LOG_SACK,
		"Mode: %u. State %u. Sending Rate: %u\n",
		rre->i->rre_mode, rre->i->rre_state, rre->i->rre_sending_rate);

		LOG_IT(TCP_RRE_LOG_INFO,
			"Sending rate: %u, una: %u\n",
			rre->i->rre_sending_rate,
			tp->snd_una);
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
	if (rre->i->rre_ack_r1 == 0 && ack > rre->i->rre_ack_r2) {
		/*
		 * We have received all data sent before
		 * entering monitor mode. Start receive
		 * rate calculation now. rre->i->rre_ack_r1
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
	/*
	 * At least by this time the session DB should
	 * be allocated.
	 */
	if (tcp_rre_init_timer(rre, (struct sock *) tp) == -1) {
		LOG_IT(TCP_RRE_LOG_ERR,
			"%s: Session DB not yet allocated\n", __func__);
		return;
	}

	if (rre->i->rre_ack_r1 == 0)
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
	if (rre->i->rre_state == TCP_RRE_STATE_SACK &&
			((tcp_time_stamp - rre->i->rre_sack_time_stamp) >
			(tp->srtt >> 3))) {
		/*
		 * Throttle sending_rate only for one RTT after
		 * SACK
		 */
		LOG_IT(TCP_RRE_LOG_INFO, "\n\t\t RTT\n\n");
		TCP_RRE_SET_STATE(rre, TCP_RRE_STATE_SACK_DONE);
	}

	switch (rre->i->rre_mode) {
	case TCP_RRE_MODE_INVALID:
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

	rre->i->rre_una = tp->snd_una;
	return;
}

/*
 * @tcp_rre_handle_slow_ack
 *
 * Handle slow ack.
 */
static inline void tcp_rre_handle_slow_ack(struct tcp_sock *tp,
							 struct revsw_rre *rre)
{
	if (tp->sacked_out != rre->i->rre_last_sacked_out) {
		if (tp->sacked_out &&
			((tcp_time_stamp - rre->i->rre_sack_time_stamp) >
				(tp->srtt >> 3))) {
			/* Fresh SACK */
			TCP_RRE_SET_STATE(rre, TCP_RRE_STATE_FORCE_DRAIN);
			rre->i->rre_sack_time_stamp = tcp_time_stamp;
			LOG_IT(TCP_RRE_LOG_INFO, "\t\tSACK\n\n");
		}

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
	if (tp->sacked_out != rre->i->rre_last_sacked_out) {
		if (tp->sacked_out)
			LOG_IT(TCP_RRE_LOG_ERR, "sacked_out: fast ack? %u %u\n",
				tp->sacked_out, rre->i->rre_last_sacked_out);

		LOG_IT(TCP_RRE_LOG_INFO, "last sacked out updated! %u %u",
				tp->sacked_out, rre->i->rre_last_sacked_out);
		rre->i->rre_last_sacked_out = tp->sacked_out;
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
	u32 unutilized_time; /* In that leak */

	leak_time = jiffies_to_msecs(tcp_time_stamp -
						rre->i->rre_leak_start_ts);
	if (leak_time <= TCP_RRE_MSECS_PER_LEAK) {
		/* Still in same leak/drop. */
		bytes_sent = tp->snd_nxt - rre->i->rre_last_snd_nxt;
		rre->i->rre_bytes_sent_this_leak += bytes_sent;
		if (rre->i->rre_bytes_sent_this_leak <
						rre->i->rre_sending_rate) {
			/* We can send more data out on wire in this leak */
			quota = rre->i->rre_sending_rate -
					rre->i->rre_bytes_sent_this_leak;
		} else {
			quota = 0;
		}
	} else {
		if (tcp_rre_init_timer(rre, (struct sock *) tp) == -1) {
			LOG_IT(TCP_RRE_LOG_ERR,
			"%s: Session DB not yet allocated\n", __func__);
			return;
		}
		/* Next leak */
		unutilized_time = msecs_to_jiffies((leak_time - 1000) % 1000);
		rre->i->rre_leak_start_ts = tcp_time_stamp - unutilized_time;

		if (timer_pending(&rre->s->rre_timer) == 0) {
			/* If timer is not pending, start it. */
			if (mod_timer(&rre->s->rre_timer, jiffies +
				msecs_to_jiffies(TCP_RRE_LEAK_QUOTA_TIMER) -
				unutilized_time)) {
				/* TODO: Handle error? */
				LOG_IT(TCP_RRE_LOG_ERR,
					"%s: Error modifying timer", __func__);
			}
		}
		rre->i->rre_bytes_sent_this_leak = 0;
		quota = rre->i->rre_sending_rate;
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
	/* Quota: Bytes that can be sent out on wire. */
	u32 quota, in_flight;
	int cwnd_quota;
	struct revsw_rre *rre, __rre;

	TCP_RRE_PRIVATE_DATE(__rre);
	rre = &__rre;

	if (rre->i->rre_last_snd_nxt == 0) {

		/*
		 * First Drop.
		 * First time this function is getting called for this socket.
		 */

		rre->i->rre_bytes_sent_this_leak	= 0;
		rre->i->rre_leak_start_ts		= tcp_time_stamp;
		rre->i->rre_init_cwnd			= tp->snd_cwnd;
		rre->i->rre_una				= tp->snd_una;
		rre->i->rre_ack_r2			= tp->snd_una;
		rre->i->rre_sending_rate = quota = rre->i->rre_init_cwnd * 1448;
		TCP_RRE_SET_MODE(rre, TCP_RRE_MODE_INIT);

		/*
		 * If session DB is not yet allocated, timer_init wont happen.
		 * We will try again later
		 */
		tcp_rre_init_timer(rre, sk);

		LOG_IT(TCP_RRE_LOG_INFO,
			"Sending Very first packet (%u / %u) and una : %u\n",
					rre->i->rre_init_cwnd, tp->snd_cwnd,
					tp->snd_una);
	} else {
		if (rre->i->rre_mode != TCP_RRE_MODE_MONITOR &&
			rre->i->rre_mode != TCP_RRE_MODE_PRE_MONITOR &&
			rre->i->rre_drain_start_ts >
				(tcp_time_stamp + (4 * (tp->srtt >> 3)))) {
			/*
			 * Enter Monitor Mode. We are in
			 * BUFFER_DRAIN state for more than 4 RTT
			 */
			LOG_IT(TCP_RRE_LOG_INFO, "Enter Monitor Mode");
			tcp_rre_enter_monitor_mode(tp, rre);
		}
		quota = tcp_rre_remaining_leak_quota(tp, rre);
	}

	LOG_IT(TCP_RRE_LOG_VERBOSE,
		"Quota: %u, snd_rate %u, BY_sent %u last_SN %u, SN = %u\n",
				quota, rre->i->rre_sending_rate,
				rre->i->rre_bytes_sent_this_leak,
				rre->i->rre_last_snd_nxt, tp->snd_nxt);

	rre->i->rre_last_snd_nxt = tp->snd_nxt;
	/*
	 * The TCP stack checks tp->snd_cwnd value at several
	 * places. Anyway this variable has no significance when
	 * TCP-RRE is used as CCA. The 2 conditions which we
	 * have to meet pacify the stack are
	 * (1) it shouldn't be zero (2) It > packets_in_flight.
	 */
	cwnd_quota = (int) tcp_revsw_division(quota,
						max_t(u32, 1, tp->mss_cache));
	in_flight = tcp_packets_in_flight(tp);
	tp->snd_cwnd = in_flight + cwnd_quota + 2;


	LOG_IT(TCP_RRE_LOG_VERBOSE,
		"cwnd_quota %d, flight %u, cwnd %u ; snd_cwnd %u\n\n",
		cwnd_quota, in_flight,
		tcp_revsw_division(rre->i->rre_sending_rate,
					max_t(u32, 1, tp->mss_cache)),
					tp->snd_cwnd);

	return cwnd_quota;
}

/*
 * @tcp_rre_init
 *
 * Starts session DB for this connection.
 */
static void tcp_rre_init(struct sock *sk)
{
	tcp_session_start(sk);
	LOG_IT(TCP_RRE_LOG_INFO, "%s\n", __func__);
}

/*
 * @tcp_rre_release
 *
 * This function setups up the deletion of the session database entry used by
 * this connection.
 */
static void tcp_rre_release(struct sock *sk)
{
	struct revsw_rre *rre, __rre;

	TCP_RRE_PRIVATE_DATE(__rre);
	rre = &__rre;

	if (rre->s)
		rre->s->tsk = NULL;
	tcp_session_delete(sk);

	LOG_IT(TCP_RRE_LOG_INFO, "%s Exiting\n", __func__);
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
	struct revsw_rre *rre, __rre;

	TCP_RRE_PRIVATE_DATE(__rre);
	rre = &__rre;

	if (rtt > 0) {
		if (rre->i->rre_rtt_min == 0) {
			rre->i->rre_rtt_min = tcp_revsw_division(((u32)rtt),
							(u32) USEC_PER_MSEC);
			LOG_IT(TCP_RRE_LOG_INFO,
				"Setting rtt-min: %u\n", rre->i->rre_rtt_min);
		} else {
			rre->i->rre_rtt_min = min_t(u32,
			tcp_revsw_division(((u32)rtt),	(u32) USEC_PER_MSEC),
			rre->i->rre_rtt_min);
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
	struct revsw_rre *rre, __rre;

	TCP_RRE_PRIVATE_DATE(__rre);
	rre = &__rre;

	if (new_state == TCP_CA_Loss) {
		LOG_IT(TCP_RRE_LOG_INFO, "TCP_CA_Loss State\n");
		TCP_RRE_SET_STATE(rre, TCP_RRE_STATE_FORCE_DRAIN);
		rre->i->rre_sack_time_stamp = tcp_time_stamp;
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
	struct revsw_rre *rre, __rre;
	TCP_RRE_PRIVATE_DATE(__rre);
	rre = &__rre;

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
	struct revsw_rre *rre, __rre;

	TCP_RRE_PRIVATE_DATE(__rre);
	rre = &__rre;

	LOG_IT(TCP_RRE_LOG_VERBOSE, "%s: Entering\n", __func__);

	if (!tp->rx_opt.tstamp_ok) {
		LOG_IT(TCP_RRE_LOG_ERR,
		"%s: Timestamp not enabled on client . RBE can not be CCA for this connection\n",
		__func__);
		rre->i->rre_syn_ack_tsecr = 0;
	} else {
		/* TODO: SYN ACK must not be re-tx */
		rre->i->rre_syn_ack_tsecr = tp->rx_opt.rcv_tsecr;
	}

	tcp_revsw_syn_post_config(sk);
}

static bool
tcp_rre_handle_nagle_test(struct sock *sk, struct sk_buff *skb,
			    unsigned int mss_now, int nonagle)
{
	return tcp_revsw_handle_nagle_test(sk, skb, mss_now, nonagle);
}

/*
 * @tcp_rre_snd_wnd_test
 *
 * This function determines if we should
 * ignore or honor receive window?
 */
static bool
tcp_rre_snd_wnd_test(const struct tcp_sock *tp, const struct sk_buff *skb,
		     unsigned int cur_mss)
{
	int test_snd_wnd;
	u32 delta_win;
	struct sock *sk = (struct sock *) tp;
	struct revsw_rre *rre, __rre;

	TCP_RRE_PRIVATE_DATE(__rre);
	rre = &__rre;

	switch (revsw_tcp_test_snd_wnd) {

	case TCP_RRE_IGNORE_INIT_BURST:
		if (revsw_cong_wnd && rre->i->rre_mode == TCP_RRE_MODE_INIT)
			test_snd_wnd = TCP_RRE_IGNORE_RCV_WND;
		else
			test_snd_wnd = TCP_RRE_HONOR_RCV_WND;
		break;

	case TCP_RRE_HONOR_NO_REXMIT:
		if (rre->i->rre_state == TCP_RRE_STATE_FORCE_DRAIN ||
				rre->i->rre_state == TCP_RRE_STATE_SACK)
			test_snd_wnd = TCP_RRE_HONOR_RCV_WND;

		/* No break, continue */

	case TCP_RRE_IGNORE_RCV_WND:
		if (revsw_rwin_scale > 0) {
			delta_win = tp->snd_wnd * tcp_revsw_division(
					revsw_rwin_scale, 100);
			if (TCP_SKB_CB(tcp_send_head(sk))->seq >
				(tp->snd_una +
				(tp->snd_wnd + delta_win)))
				test_snd_wnd = TCP_RRE_HONOR_RCV_WND;
			}

		test_snd_wnd = TCP_RRE_IGNORE_RCV_WND;
		break;

	case TCP_RRE_HONOR_RCV_WND:
		test_snd_wnd = TCP_RRE_HONOR_RCV_WND;
		break;
	}

	if (test_snd_wnd == TCP_RRE_HONOR_RCV_WND) {
		u32 end_seq = TCP_SKB_CB(skb)->end_seq;

		if (skb->len > cur_mss)
			end_seq = TCP_SKB_CB(skb)->seq + cur_mss;

		return !after(end_seq, tcp_wnd_end(tp));
	} else {
		return TCP_RRE_IGNORE_RCV_WND;
	}
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
	BUILD_BUG_ON(sizeof(struct icsk_priv) > ICSK_CA_PRIV_SIZE);
	BUILD_BUG_ON(sizeof(struct sess_priv) > TCP_CCA_PRIV_SIZE);
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

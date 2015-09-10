/*
 *
 *   RevSw RBE TCP Congestion Control Algorithm
 *
 * This is TCP RBE (Receiver Rate Estimation) Implementation.
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

#include <linux/average.h>

/********************************************************************
 *
 * RevSw RBE Congestion Control Algorithm
 *
 ********************************************************************/

/*
 * Number of packets we require in INIT mode or
 * MONITOR mode to calculate receiver rate
 */
#define TCP_REVSW_RBE_PACKETS_REQ_CALC_RATE	20

/* Number of packets we use to calculate tbuff */
#define TCP_REVSW_RBE_TBUFF_PACKETS		30
#define TCP_REVSW_RBE_MSECS_PER_LEAK		1000
#define TCP_REVSW_RBE_LEAK_QUOTA_TIMER		250

#define TCP_REVSW_RBE_LOG_NOLOG  TCP_REVSW_RBE_LOG_DEFAULT
#define TCP_REVSW_RBE_LOG_ERR  (TCP_REVSW_RBE_LOG_DEFAULT + 1)
#define TCP_REVSW_RBE_LOG_INFO  (TCP_REVSW_RBE_LOG_DEFAULT + 2)
#define TCP_REVSW_RBE_LOG_SACK  (TCP_REVSW_RBE_LOG_DEFAULT + 3)
#define TCP_REVSW_RBE_LOG_VERBOSE  (TCP_REVSW_RBE_LOG_DEFAULT + 4)

#define TCP_REVSW_RBE_MODE_INVALID  0
#define TCP_REVSW_RBE_MODE_INIT  (TCP_REVSW_RBE_MODE_INVALID + 1)
#define TCP_REVSW_RBE_MODE_BM  (TCP_REVSW_RBE_MODE_INVALID + 2)
#define TCP_REVSW_RBE_MODE_PRE_MONITOR  (TCP_REVSW_RBE_MODE_INVALID + 3)
#define TCP_REVSW_RBE_MODE_MONITOR  (TCP_REVSW_RBE_MODE_INVALID + 4)
#define TCP_REVSW_RBE_MODE_UNUSED_MAX	(TCP_REVSW_RBE_MODE_INVALID + 5)

#define TCP_REVSW_RBE_STATE_INVALID  0
#define TCP_REVSW_RBE_STATE_FILL  (TCP_REVSW_RBE_STATE_INVALID + 1)
#define TCP_REVSW_RBE_STATE_DRAIN  (TCP_REVSW_RBE_STATE_INVALID + 2)
#define TCP_REVSW_RBE_STATE_FORCE_DRAIN  (TCP_REVSW_RBE_STATE_INVALID + 3)
#define TCP_REVSW_RBE_STATE_SACK  (TCP_REVSW_RBE_STATE_INVALID + 4)
#define TCP_REVSW_RBE_STATE_SACK_DONE  (TCP_REVSW_RBE_STATE_INVALID + 5)
#define TCP_REVSW_RBE_STATE_UNUSED_MAX  (TCP_REVSW_RBE_STATE_INVALID + 6)

#define TCP_REVSW_RBE_HONOR_RCV_WND 0
#define TCP_REVSW_RBE_IGNORE_INIT_BURST (TCP_REVSW_RBE_HONOR_RCV_WND + 1)
#define TCP_REVSW_RBE_HONOR_NO_REXMIT (TCP_REVSW_RBE_HONOR_RCV_WND + 2)
#define TCP_REVSW_RBE_IGNORE_RCV_WND (TCP_REVSW_RBE_HONOR_RCV_WND + 3)

#define TCP_REVSW_RBE_SS_DEFAULT	3
#define TCP_REVSW_RBE_SS_LVL1		TCP_REVSW_RBE_SS_DEFAULT + 1
#define TCP_REVSW_RBE_SS_LVL2		TCP_REVSW_RBE_SS_DEFAULT + 2
#define TCP_REVSW_RBE_SS_LVL3		TCP_REVSW_RBE_SS_DEFAULT + 3
#define TCP_REVSW_RBE_SS_LVL4		TCP_REVSW_RBE_SS_DEFAULT + 4

/*
 * RBE Validation Conditions
 */
#define TCP_REVSW_RBE_CLIENT_INITIATED	(1 << 3)
#define TCP_REVSW_RBE_NON_LOCAL_HOST	(1 << 2)
#define TCP_REVSW_RBE_TIMESTAMP		(1 << 1)
#define TCP_REVSW_RBE_SACK		(1 << 0)
#define TCP_REVSW_RBE_VALID		(TCP_REVSW_RBE_CLIENT_INITIATED | \
					 TCP_REVSW_RBE_NON_LOCAL_HOST | \
					 TCP_REVSW_RBE_TIMESTAMP | \
					 TCP_REVSW_RBE_SACK)
#define TCP_REVSW_RBE_VALID_LOG		(TCP_REVSW_RBE_CLIENT_INITIATED | \
					 TCP_REVSW_RBE_NON_LOCAL_HOST)

const char *tcp_revsw_rbe_mode_string[TCP_REVSW_RBE_MODE_UNUSED_MAX] = {
	"TCP_REVSW_RBE_MODE_INVALID", "TCP_REVSW_RBE_MODE_INIT", "TCP_RBE_MODE_BM",
	"TCP_REVSW_RBE_MODE_PRE_MONITOR", "TCP_REVSW_RBE_MODE_MONITOR"
	};

const char *tcp_revsw_rbe_state_string[TCP_REVSW_RBE_STATE_UNUSED_MAX] = {
	"TCP_REVSW_RBE_STATE_INVALID", "TCP_REVSW_RBE_STATE_FILL", "TCP_RBE_STATE_DRAIN",
	"TCP_REVSW_RBE_STATE_FORCE_DRAIN", "TCP_REVSW_RBE_STATE_SACK",
	"TCP_REVSW_RBE_STATE_SACK_DONE"
	};

struct icsk_priv {
	u32 rbe_ack_r1;
	u32 rbe_ts_r1;
	/*
	 * The following 2 variables are overloaded.
	 * They are used differnetly in INIT/BM modes
	 */
	u32 rbe_ack_r2;
	u32 rbe_ts_r2;

	u32 rbe_last_snd_nxt;
	u32 rbe_leak_start_ts;
	u32 rbe_bytes_sent_this_leak;
	u32 rbe_sending_rate;	/*  sending_rate is in bytes/sec */

	u32 rbe_rtt_min;	/* in miliseconds */

	u32 rbe_init_cwnd;
	u32 rbe_last_sacked_out;
	u32 rbe_sack_time_stamp;

	u32 rbe_drain_start_ts;
	u32 rbe_syn_ack_tsecr;
	u32 rbe_una;
	u16 rbe_estimated_tick_gra;
	u8 rbe_mode;
	u8 rbe_state;
	u8 ss_growth_factor;
};

struct sess_priv {
	/* rbe_timer has to be first item */
	/*
	 * TODO: Check if we can use any existing timer in scoket
	 * which will some memory
	 */
	struct timer_list rbe_timer;

	u32 rbe_T;		/* number of bytes. */
	u32 tbuff_acked_data;
	u32 tbuff_ticks;
	u32 rbe_rdmin_tsval;
	u32 rbe_rdmin_tsecr;

	struct ewma rbe_receiving_rate;
	struct sock *tsk;
};

struct revsw_rbe {
	struct icsk_priv *i;
	struct sess_priv *s;

#define ack_r1			i->rbe_ack_r1
#define ts_r1			i->rbe_ts_r1
#define ack_r2			i->rbe_ack_r2
#define ts_r2			i->rbe_ts_r2
#define last_snd_nxt		i->rbe_last_snd_nxt
#define leak_start_ts		i->rbe_leak_start_ts
#define bytes_sent_this_leak	i->rbe_bytes_sent_this_leak
#define sending_rate		i->rbe_sending_rate
#define rtt_min			i->rbe_rtt_min
#define init_cwnd		i->rbe_init_cwnd
#define last_sacked_out		i->rbe_last_sacked_out
#define sack_time_stamp		i->rbe_sack_time_stamp
#define drain_start_ts		i->rbe_drain_start_ts
#define syn_ack_tsecr		i->rbe_syn_ack_tsecr
#define una			i->rbe_una
#define estimated_tick_gra	i->rbe_estimated_tick_gra
#define rbe_mode		i->rbe_mode
#define rbe_state		i->rbe_state
#define ss_growth_factor	i->ss_growth_factor

#define timer			s->rbe_timer
#define Tbuff			s->rbe_T
#define tbuff_acked_data	s->tbuff_acked_data
#define tbuff_ticks		s->tbuff_ticks
#define rdmin_tsval		s->rbe_rdmin_tsval
#define rdmin_tsecr		s->rbe_rdmin_tsecr
#define receiving_rate		s->rbe_receiving_rate
#define tsk			s->tsk

};

#define TCP_REVSW_RBE_BMAX(rbe)      (rbe->Tbuff + (rbe->Tbuff >> 1))
#define TCP_REVSW_RBE_BMIN(rbe)      (rbe->Tbuff - (rbe->Tbuff >> 1))

#define TCP_REVSW_RBE_RETX_IN_LAST_RTT(tp)	\
	((tcp_time_stamp - tp->retrans_stamp) < (tp->srtt >> 3))

#define TCP_REVSW_RBE_TIME_SINCE_LAST_SACK(tp)	\
				((tp->srtt >> 3) + ((tp->srtt >> 3) >> 2))

#define TCP_REVSW_RBE_SET_STATE(rbe, state)  { 						\
	if (rbe->rbe_state != state)							\
		LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_INFO, "        %s to %s. Sending-rate = %u\n",	\
		       tcp_revsw_rbe_state_string[rbe->rbe_state],			\
		       tcp_revsw_rbe_state_string[state],				\
		       rbe->sending_rate);						\
	rbe->rbe_state = state;								\
}

#define TCP_REVSW_RBE_SET_MODE(rbe, mode)  { 			\
	LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_INFO, "        %s to %s\n",	\
	       tcp_revsw_rbe_mode_string[rbe->rbe_mode],	\
	       tcp_revsw_rbe_mode_string[mode]);		\
	rbe->rbe_mode = mode;					\
}

#define TCP_REVSW_RBE_PRIVATE_DATE(__rbe)				\
{									\
	struct tcp_revsw_cca_data *ca = inet_csk_ca(sk);		\
	__rbe.i = (struct icsk_priv *)ca->padding;			\
	__rbe.s = (struct sess_priv *)tcp_session_get_cca_priv(sk);	\
}

/* TODO: What do we do when rbe->estimated_tick_gra  is 0 ? */
#define TCP_REVSW_RBE_CLINET_JIFFIES_TO_MSECS(rbe, ticks, in_msecs)	\
do {									\
	if (rbe->estimated_tick_gra > 0)				\
		in_msecs = (ticks * rbe->estimated_tick_gra);		\
	else								\
		in_msecs = jiffies_to_msecs(ticks);			\
} while (0)

/*
 * @tcp_rbe_estimate_tbuff
 *
 * Estimate Network Buffer
 */
static inline void tcp_rbe_estimate_tbuff(struct revsw_rbe *rbe)
{
	u32 time_in_milisecs;

	TCP_REVSW_RBE_CLINET_JIFFIES_TO_MSECS(rbe, rbe->tbuff_ticks, 
							time_in_milisecs);
	if (time_in_milisecs == 0) {
	       /* TODO: Handle this in some other way? */
	       LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_ERR, "%s: NOT GOOD\n", __func__);
	       return;
	}

	/* 
	 * RRATE is in bytes/sec 	
	 * RRATE 	= ((1000*rbe->tbuff_acked_data) / time_in_milisecs);
	 * rbe->Tbuff 	= ((RRATE * rbe->rtt_min) / 1000);
	 * Simplified formula below
	 */

	rbe->Tbuff = (rbe->tbuff_acked_data * rbe->rtt_min) / time_in_milisecs;

	LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_INFO,
		       "T %u, Bmax %u, Bmin %u, r_rate = %u\n",
		       rbe->Tbuff,
		       TCP_REVSW_RBE_BMAX(rbe),
		       TCP_REVSW_RBE_BMIN(rbe),
		       (u32) ewma_read(&rbe->receiving_rate));
	return;
}

/*
 * @tcp_revsw_rbe_estimate_granularity
 *
 * Estimate client's TCP timestamp granulairty as
 * it is required to calculate the receiving rate.
 */
static inline int tcp_revsw_rbe_estimate_granularity(struct tcp_sock *tp,
						struct revsw_rbe *rbe)
{
	int granularity;
	int changed = 0;
	u32 tsdiff = 0;

	tsdiff = tp->rx_opt.rcv_tsval - tp->rbe_syn_tsval;
	if (tsdiff == 0) {
		LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_ERR,
			"%s: TS diff is ZERO rx_opt.rcv_tsval %u rbe_syn_tsval %u\n",
		       __func__, tp->rx_opt.rcv_tsval, tp->rbe_syn_tsval);
		return 0;
	}

	/* granularity = msecs past / num of ticks */
	granularity =
		jiffies_to_msecs(tcp_time_stamp - rbe->syn_ack_tsecr) /
		 tsdiff;

	if (granularity >= 0 && granularity < 2) {
		granularity = 1;
	} else if (granularity >= 2 && granularity < 7) {
		granularity = 4;
	} else if (granularity >= 7 && granularity < 14) {
		granularity = 10;
	} else {
		LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_ERR,
			"Wrong previous Estimation of Client TCP Granularity."
			" Curbent Estimation: %u. Previous Estimation: %u\n",
				granularity, rbe->estimated_tick_gra);
		granularity = 0;
	}

	if (granularity != rbe->estimated_tick_gra) {
		LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_INFO,
		  "--------------> (%u/%u) Changing granularity from %u to %u\n",
		  jiffies_to_msecs(tcp_time_stamp - rbe->syn_ack_tsecr),
		  (tp->rx_opt.rcv_tsval - tp->rbe_syn_tsval),
		  rbe->estimated_tick_gra, granularity);

		LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_VERBOSE,
			"%u %u %u %u\n",
			tcp_time_stamp, rbe->syn_ack_tsecr,
			tp->rx_opt.rcv_tsval, tp->rbe_syn_tsval);

		rbe->estimated_tick_gra = granularity;
		changed = 1;
	}

	return changed;
}

static void tcp_revsw_rbe_timer_handler(unsigned long data)
{
	struct sock *sk;
	struct tcp_sock *tp;
	struct revsw_rbe *rbe, __rbe;
	struct tcp_revsw_cca_data *ca;

	__rbe.s = (struct sess_priv *) data;
	if (__rbe.s == NULL) {
		LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_ERR, "%s: ERRORR, data is NULL\n", __func__);
		return;
	}

	sk = __rbe.tsk;
	if (sk == NULL) {
		LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_INFO, "%s: tsk is NULL\n", __func__);
		return;
	}

	if (sk->sk_state != TCP_ESTABLISHED) {
		LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_INFO, "%s: sk_state != TCP_ESTABLISHED\n",
			__func__);
		return;
	}

	tp = tcp_sk(sk);
	ca = inet_csk_ca(sk);
	__rbe.i = (struct icsk_priv *)ca->padding;
	rbe = &__rbe;

	if (rbe->bytes_sent_this_leak < rbe->sending_rate) {
		if (tcp_send_head(sk)) {

			LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_INFO,
				"** %s: Quota is not fully utilized\n",
				__func__);

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
		LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_VERBOSE,
			"** %s: In Timer Callback\n",
			__func__);

	}

	if (tcp_send_head(sk)) {
		if (mod_timer(&rbe->timer, jiffies +
			msecs_to_jiffies(TCP_REVSW_RBE_LEAK_QUOTA_TIMER))) {
			/* TODO: Handle error */
			LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_ERR,
				"%s: Error modifying timer\n", __func__);
		}
	}
}

/*
 * @tcp_revsw_rbe_init_timer
 *
 */
static inline int tcp_revsw_rbe_init_timer(struct revsw_rbe *rbe, struct sock *sk)
{
	if (!rbe->s)
		return -1;

	if (rbe->tsk == sk)
		return 0;

	/* TODO: Check if we need to initialize all these variables */
	rbe->Tbuff = 0;
	rbe->tbuff_acked_data = 0;
	rbe->tbuff_ticks = 0;
	rbe->rdmin_tsval = 0;
	rbe->rdmin_tsecr = 0;

	/* TODO: 1024 and 2, right values? */
	ewma_init(&rbe->receiving_rate, 1024, 2);

	/*
	 * Set timer and callback function for maintaining
	 * sending_rate
	 */
	rbe->tsk = sk;
	setup_timer(&rbe->timer, tcp_revsw_rbe_timer_handler,
		(unsigned long) &rbe->timer);
	if (mod_timer(&rbe->timer, jiffies +
		msecs_to_jiffies(TCP_REVSW_RBE_LEAK_QUOTA_TIMER))) {
		/* TODO: Handle error */
		LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_ERR,
			"%s: Error modifying timer\n", __func__);
	}

	return 0;
}

/*
 * @tcp_revsw_rbe_receive_rate
 *
 * Calculate the rate at which reciver is receving data. Our sending rate
 * is calculated based on this value.
 *
 * TODO: Use client TCP timestamp's estimated value.
 * (Curbent Assumptuion: receiver tick is same as sender tick.)
 */
static u32 tcp_revsw_rbe_receive_rate(struct tcp_sock *tp,
					struct revsw_rbe *rbe,
					u32 ack)
{
	unsigned long r_rate;
	u32 acked_data, ticks_delta, time_in_milisecs, sacked_bytes = 0;
	u32 next_checkpoint;

	if (tp->sacked_out > rbe->last_sacked_out) {
		sacked_bytes = (tp->sacked_out - rbe->last_sacked_out)
						* tp->mss_cache;
		rbe->last_sacked_out = tp->sacked_out;
	}

	acked_data = (ack - rbe->ack_r1) + sacked_bytes;
	ticks_delta = tp->rx_opt.rcv_tsval - rbe->ts_r1;
	TCP_REVSW_RBE_CLINET_JIFFIES_TO_MSECS(rbe, ticks_delta, time_in_milisecs);
	if (time_in_milisecs == 0) {
		/* TODO: Handle this in some other way? */
		LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_INFO, "%s: Network is fast!\n",
							__func__);
		return 0;
	}
	/* r_rate is in bytes/sec */
	r_rate = (unsigned long) (1000 * acked_data / time_in_milisecs);
	ewma_add(&rbe->receiving_rate, r_rate);

	/*
	 * TODO: Should we NOT take sample when we are
	 * in TCP_REVSW_RBE_STATE_SACK ? As you can see below,
	 * we are taking samples now.
	 */

	next_checkpoint =
		(rbe->ack_r2 + tp->mss_cache * TCP_REVSW_RBE_TBUFF_PACKETS);
	if ((ack + sacked_bytes > next_checkpoint)) {
		rbe->ts_r1	= rbe->ts_r2;
		rbe->ack_r1	= rbe->ack_r2;
		rbe->ts_r2	= tp->rx_opt.rcv_tsval;
		rbe->ack_r2	= ack + sacked_bytes;
		if (tcp_revsw_rbe_estimate_granularity(tp, rbe))
			tcp_rbe_estimate_tbuff(rbe);

		LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_VERBOSE, "r1 r2, sr %u and %u / %u\n",
			rbe->sending_rate, ack,
			next_checkpoint);
	}

	LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_VERBOSE,
	"ackd_bytes %u in %u ms. ack %u. r_rate %lu, r_ewma %lu.snd_r = %u\n",
			acked_data, time_in_milisecs, ack, r_rate,
			ewma_read(&rbe->receiving_rate),
			rbe->sending_rate);

	LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_VERBOSE,
	"ack %u ; r_rate %lu, avg %lu. snd_r = %u\n",
			ack, r_rate,
			ewma_read(&rbe->receiving_rate),
			rbe->sending_rate);

	return acked_data;
}

/*
 * @tcp_revsw_rbe_fill_buffer
 *
 * Set Sending rate to > buffer drain rate which will fill network buffer.
 */
static inline void tcp_revsw_rbe_fill_buffer(struct tcp_sock *tp,
					 struct revsw_rbe *rbe)
{
	u32 delta_sending_rate; /* per second */
	u32 Bmax;

	/*
	 * Fill the buffer faster if there are no re-tranmissions in
	 * last RTT.
	 */
	Bmax = TCP_REVSW_RBE_BMAX(rbe) +
		TCP_REVSW_RBE_RETX_IN_LAST_RTT(tp) ? 0: (rbe->Tbuff >> 2);
	/*
	 * TODO (minor): Bmax adds rbe->Tbuff and we subtract it again.
	 * Optimize this addition, subtraction calculation.
	 */
	delta_sending_rate = (1000 * (Bmax - rbe->Tbuff)) /
			     jiffies_to_msecs(tp->srtt >> 3);


	rbe->sending_rate = (u32) ewma_read(&rbe->receiving_rate);
	rbe->sending_rate += delta_sending_rate;
	TCP_REVSW_RBE_SET_STATE(rbe, TCP_REVSW_RBE_STATE_FILL);
	rbe->drain_start_ts = 0;

	LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_VERBOSE,
			"%s: delta_sending_rate %u and sending_rate = %u\n",
			__func__,
			delta_sending_rate, rbe->sending_rate);
}

/*
 * @tcp_revsw_rbe_drain_buffer
 *
 * Set Sending rate < buffer drain rate which will drain network buffer.
 */
static inline void tcp_revsw_rbe_drain_buffer(struct tcp_sock *tp,
						struct revsw_rbe *rbe)
{
	u32 srtt_msecs;
	u32 delta_sending_rate; /* per second */

	if (rbe->rbe_state == TCP_REVSW_RBE_STATE_DRAIN)
		return;

	srtt_msecs = jiffies_to_msecs(tp->srtt >> 3);
	if (srtt_msecs == 0) {
		pr_err("%s: ERROR - srtt_msecs is ZERO (%u)\n", __func__, tp->srtt);
		return;
	}

	delta_sending_rate = 1000 * (rbe->Tbuff - TCP_REVSW_RBE_BMIN(rbe)) /
			     srtt_msecs;

	rbe->sending_rate = (u32) ewma_read(&rbe->receiving_rate);
	if (delta_sending_rate > rbe->sending_rate)
		rbe->sending_rate = 2 * tp->mss_cache;
	else
		rbe->sending_rate -= delta_sending_rate;

	/* Min drain rate = 10 packets. TODO: Review this */
	if (rbe->sending_rate < (10 * tp->mss_cache))
		rbe->sending_rate = 10 * tp->mss_cache;

	if (rbe->rbe_state == TCP_REVSW_RBE_STATE_FORCE_DRAIN) {
		LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_INFO,
			"%s: Reduced sending_rate to %u. delta = %u\n",
			__func__,
			rbe->sending_rate, delta_sending_rate);
		TCP_REVSW_RBE_SET_STATE(rbe, TCP_REVSW_RBE_STATE_SACK);
	} else {
		/* Set state to TCP_REVSW_RBE_STATE_DRAIN */
		TCP_REVSW_RBE_SET_STATE(rbe, TCP_REVSW_RBE_STATE_DRAIN);
	}

	if (rbe->drain_start_ts == 0)
		rbe->drain_start_ts = tcp_time_stamp;

	LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_VERBOSE,
			"%s: delta_sending_rate %u and sending_rate = %u\n",
			__func__,
			delta_sending_rate, rbe->sending_rate);
}

/*
 * @tcp_revsw_rbe_process_mode_bm
 *
 * This function is called whne TCP-RBE is in BM (Buffer Management) MODE and
 * when we recive an ack/sack.
 */
static void tcp_revsw_rbe_process_mode_bm(struct tcp_sock *tp,
			struct revsw_rbe *rbe,
			u32 ack)
{
	int tbuff, RD, network_buffer_capacity, RDmin;
	u32 tsval_adjusted, in_msecs;

	tcp_revsw_rbe_receive_rate(tp, rbe, ack);

	/*
	 * If the TCP TS granularity of client and server are same,
	 * RD = tp->rx_opt.rcv_tsval - tp->rx_opt.rcv_tsecr;
	 * AS the granularity may be different we have to
	 * calculate RD.
	 */

	RDmin = rbe->rdmin_tsval - rbe->rdmin_tsecr;

	TCP_REVSW_RBE_CLINET_JIFFIES_TO_MSECS(rbe,
			(tp->rx_opt.rcv_tsval - rbe->rdmin_tsval),
			in_msecs);
	tsval_adjusted = rbe->rdmin_tsval + msecs_to_jiffies(in_msecs);

	RD = tsval_adjusted - tp->rx_opt.rcv_tsecr;
	if (RD < RDmin) {
		rbe->rdmin_tsval = tp->rx_opt.rcv_tsval;
		rbe->rdmin_tsecr = tp->rx_opt.rcv_tsecr;
		RD = RDmin;
	}

	tbuff = RD - RDmin;
	if (tbuff < 0) {
		LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_ERR,
			"(BM) tbuff < ZERO\n");
		return;
	}

	if (rbe->rbe_state == TCP_REVSW_RBE_STATE_FORCE_DRAIN) {
		tcp_revsw_rbe_drain_buffer(tp, rbe);
	} else if (rbe->rbe_state != TCP_REVSW_RBE_STATE_SACK) {
		u32 rr_ewma = (u32) ewma_read(&rbe->receiving_rate);

		if (rr_ewma) {
			network_buffer_capacity = rbe->Tbuff * 1000 / rr_ewma;

			if (jiffies_to_msecs(tbuff) < network_buffer_capacity)
				tcp_revsw_rbe_fill_buffer(tp, rbe);
			else
				tcp_revsw_rbe_drain_buffer(tp, rbe);

			LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_VERBOSE,
			       "(BM) tbuff = %d, network_buffer_capacity = %d, rtt-min %u.\n",
			       jiffies_to_msecs(tbuff),
			       network_buffer_capacity,
			       rbe->rtt_min);
		} else {
			pr_err("%s: Receive Rate EWMA is ZERO: internal %lu factor %lu weight %lu\n",
			       __func__, rbe->receiving_rate.internal, rbe->receiving_rate.factor,
			       rbe->receiving_rate.weight);
		}
	}

}

/*
 * @tcp_revsw_rbe_enter_monitor_mode
 *
 * Enter Monitor Mode
 * TODO: handle tcp_time_stamp reset
 */
static inline void tcp_revsw_rbe_enter_monitor_mode(struct tcp_sock *tp,
							struct revsw_rbe *rbe)
{
	if (tp->sacked_out || tp->lost_out) {
		if (rbe->rbe_mode != TCP_REVSW_RBE_MODE_PRE_MONITOR) {
			TCP_REVSW_RBE_SET_MODE(rbe, TCP_REVSW_RBE_MODE_PRE_MONITOR);
			rbe->sending_rate =
				max_t(u32, rbe->sending_rate >> 1,
				(TCP_REVSW_RBE_PACKETS_REQ_CALC_RATE + 10) *
				tp->mss_cache);
			/* TODO: Reset rbe_drain_start_ts ? */
		}
		/* Wait until we get ack for all SACKED and LOST packets */
		return;
	}

	if (rbe->rbe_mode == TCP_REVSW_RBE_MODE_PRE_MONITOR) {
		/*
		 * The sending rate is already reduced in PRE_MONITOR mode.
		 * Now that we do not have any oustanding RTO/SACK
		 * packets, reset sending_rate.
		 */
		rbe->sending_rate =
			max_t(u32, rbe->sending_rate,
				(TCP_REVSW_RBE_PACKETS_REQ_CALC_RATE + 10) *
				tp->mss_cache);
	} else {
		/*
		 * Reduce sending rate so that we drain network buffers.
		 */
		rbe->sending_rate =
			max_t(u32, rbe->sending_rate >> 1,
				(TCP_REVSW_RBE_PACKETS_REQ_CALC_RATE + 10) *
				tp->mss_cache);
	}

	/*
	 * TODO: Do we want to wait for (say) 1 RTT before we
	 * record these values. The reason is that if we send at
	 * a lower rate for one RTT, the buffer will drain and we
	 * get a more accurate RDmin.
	 */
	/* Reset some variables */
	rbe->ack_r1 = rbe->ts_r1 = 0;
	rbe->ack_r2 = rbe->ts_r2 = 0;
	rbe->Tbuff = 0;

	rbe->rtt_min = 0;
	rbe->rdmin_tsval = rbe->rdmin_tsecr = 0;

	if (tcp_revsw_rbe_init_timer(rbe, (struct sock *) tp) == -1) {
		LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_ERR,
			"%s: Session DB not yet allocated\n", __func__);
		return;
	}


	rbe->ack_r2	= tp->snd_una;
	rbe->rbe_state	= TCP_REVSW_RBE_STATE_INVALID;
	TCP_REVSW_RBE_SET_MODE(rbe, TCP_REVSW_RBE_MODE_MONITOR);
	ewma_init(&rbe->receiving_rate, 1024, 2);

	LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_INFO, "Entering Monitor Mode (snd_una: %u)\n",
		tp->snd_una);
}

static inline void tcp_revsw_rbe_process_pre_monitor(struct tcp_sock *tp,
						struct revsw_rbe *rbe,
						u32 ack)
{
	if (tp->sacked_out > rbe->last_sacked_out) {
		/* Got another SACK, reduce sending_rate again */
		rbe->sending_rate = max_t(u32,
				rbe->sending_rate >> 1,
				(TCP_REVSW_RBE_PACKETS_REQ_CALC_RATE + 10) *
				tp->mss_cache);
	}
	tcp_revsw_rbe_receive_rate(tp, rbe, ack);
	tcp_revsw_rbe_enter_monitor_mode(tp, rbe);
}

/*
 * @tcp_revsw_rbe_enter_bm_mode
 *
 * Set RBE CCA variables after we get first valid ack.
 */
static inline void tcp_revsw_rbe_post_first_valid_ack(struct tcp_sock *tp,
						struct revsw_rbe *rbe,
						u32 ack)
{
	LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_INFO, "\nFirst valid ACK %u. %u / %u\n",
							ack,
							tp->snd_cwnd,
							tp->snd_wnd);
	rbe->ts_r1	= tp->rx_opt.rcv_tsval;
	rbe->ack_r1	= ack;
	rbe->rdmin_tsval = tp->rx_opt.rcv_tsval;
	rbe->rdmin_tsecr = tp->rx_opt.rcv_tsecr;
	rbe->ts_r2	= tp->rx_opt.rcv_tsecr;
}

/*
 * @tcp_revsw_rbe_enter_bm_mode
 *
 * Enter BM mode.
 */
static inline void tcp_revsw_rbe_enter_bm_mode(struct tcp_sock *tp,
						struct revsw_rbe *rbe,
						u32 ack)
{
	LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_INFO,
		"Switching to BM mode after %u packets are acked.\n",
		(ack - rbe->ack_r2) / tp->mss_cache);

	rbe->ts_r2 = tp->rx_opt.rcv_tsval;
	rbe->ack_r2 = ack;

	/* First time we are estimating receive rate */

	rbe->tbuff_ticks = tp->rx_opt.rcv_tsval - rbe->ts_r1;
	rbe->tbuff_acked_data = tcp_revsw_rbe_receive_rate(tp, rbe, ack);

	tcp_rbe_estimate_tbuff(rbe);

	rbe->sending_rate = (u32) ewma_read(&rbe->receiving_rate);
	TCP_REVSW_RBE_SET_MODE(rbe, TCP_REVSW_RBE_MODE_BM);
}

/*
 * @tcp_revsw_rbe_init_monitor_common
 *
 * Common processing for init and monitor mode
 */
static inline void tcp_revsw_rbe_init_monitor_common(struct tcp_sock *tp,
						struct revsw_rbe *rbe,
						u32 ack)
{
	int enter_BM_mode;
	u32 received_in_msecs;

	if (ack >= (rbe->ack_r2 +
		(tp->mss_cache * TCP_REVSW_RBE_PACKETS_REQ_CALC_RATE))) {

		tcp_revsw_rbe_estimate_granularity(tp, rbe);
		/*
		* TODO: Do we want to check if sending_rate MUCH LESSER than
		* received_in_msecs ?
		* TODO: Ex: Sending_rate + ((tp->srtt >> 3)/2) < receiving_rate
		*/

		TCP_REVSW_RBE_CLINET_JIFFIES_TO_MSECS(rbe,
				(tp->rx_opt.rcv_tsval - rbe->ts_r1),
				received_in_msecs);
		/* if (sending_rate < receiving rate) */
		if (jiffies_to_msecs(tp->rx_opt.rcv_tsecr - rbe->ts_r2) <
			received_in_msecs) {
			/*
			 * If we receive TCP_REVSW_RBE_PACKETS_REQ_CALC_RATE and
			 * ONLY if those packets were transmitted faster than
			 * the receiver rate, use it for
			 * calculating reciver rate.
			 */
			enter_BM_mode = 1;
		} else {
			LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_INFO, "Slow Sender\n");
			rbe->ts_r2  = tp->rx_opt.rcv_tsecr;
			rbe->ts_r1  = tp->rx_opt.rcv_tsval;
			rbe->ack_r1 = ack;
			rbe->rdmin_tsval = tp->rx_opt.rcv_tsval;
			rbe->rdmin_tsecr = tp->rx_opt.rcv_tsecr;
			rbe->ack_r2 = ack;
			rbe->sending_rate = rbe->init_cwnd *
					       tp->mss_cache;
			enter_BM_mode = 0;
		}
		if (enter_BM_mode)
			tcp_revsw_rbe_enter_bm_mode(tp, rbe, ack);
	}
}

/*
 * @tcp_revsw_rbe_init_monitor_common
 *
 * Set sending rate when you are in init mode. Unless we
 * have recived a SACK, it will be exponential growth
 */
static inline void tcp_revsw_rbe_set_init_monitor_sending_rate(
					struct tcp_sock *tp,
					struct revsw_rbe *rbe)
{
	if (rbe->rbe_mode == TCP_REVSW_RBE_MODE_INIT ||
		rbe->rbe_mode == TCP_REVSW_RBE_MODE_MONITOR) {
		if (rbe->rbe_state == TCP_REVSW_RBE_STATE_FORCE_DRAIN) {
			/* TODO: Decrease sending_rate ? */
			TCP_REVSW_RBE_SET_STATE(rbe, TCP_REVSW_RBE_STATE_SACK);
		} else {
			rbe->sending_rate += (rbe->ss_growth_factor *
					(tp->snd_una - rbe->una));
			LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_VERBOSE,
				"INIT. Exp Growth. Sending Rate: %u\n",
					rbe->sending_rate);
		}
	} else {
		if (rbe->rbe_state == TCP_REVSW_RBE_STATE_FORCE_DRAIN)
			tcp_revsw_rbe_drain_buffer(tp, rbe);
		else
			tcp_revsw_rbe_fill_buffer(tp, rbe);

		LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_SACK,
			"Mode: %s. State %s. Sending Rate: %u\n",
			tcp_revsw_rbe_mode_string[rbe->rbe_mode],
			tcp_revsw_rbe_state_string[rbe->rbe_state],
			rbe->sending_rate);

		LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_INFO,
			"Sending rate: %u, una: %u\n",
			rbe->sending_rate,
			tp->snd_una);
	}
}

/*
 * @tcp_revsw_rbe_process_mode_monitor
 *
 * This function is called when TCP-RBE is
 * in MONITOR MODE and when we recive an ack/sack.
 */
static void tcp_revsw_rbe_process_mode_monitor(struct tcp_sock *tp,
						struct revsw_rbe *rbe,
						u32 ack)
{
	if (rbe->ack_r1 == 0 && ack > rbe->ack_r2) {
		/*
		 * We have received all data sent before
		 * entering monitor mode. Start receive
		 * rate calculation now. rbe->ack_r1
		 */
		tcp_revsw_rbe_post_first_valid_ack(tp, rbe, ack);
	} else {
		tcp_revsw_rbe_init_monitor_common(tp, rbe, ack);
	}

	tcp_revsw_rbe_set_init_monitor_sending_rate(tp, rbe);
}

/*
 * @tcp_revsw_rbe_process_mode_init
 *
 * This function is called whne TCP-RBE is in INIT MODE
 * and when we recive an ack/sack.
 */
static void tcp_revsw_rbe_process_mode_init(struct tcp_sock *tp,
						struct revsw_rbe *rbe,
						u32 ack)
{
	/*
	 * At least by this time the session DB should
	 * be allocated.
	 */
	if (tcp_revsw_rbe_init_timer(rbe, (struct sock *) tp) == -1) {
		LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_ERR,
			"%s: Session DB not yet allocated\n", __func__);
		return;
	}

	if (rbe->ack_r1 == 0)
		tcp_revsw_rbe_post_first_valid_ack(tp, rbe, ack);
	else
		tcp_revsw_rbe_init_monitor_common(tp, rbe, ack);

	tcp_revsw_rbe_set_init_monitor_sending_rate(tp, rbe);
}

/*
 * @tcp_revsw_rbe_common_ack
 *
 * This function is common for both fast and slow ack
 */
static inline void tcp_revsw_rbe_common_ack(struct tcp_sock *tp,
						 struct revsw_rbe *rbe)
{
	if (rbe->rbe_state == TCP_REVSW_RBE_STATE_SACK &&
			((tcp_time_stamp - rbe->sack_time_stamp) >
			((tp->srtt >> 3) - ((tp->srtt >> 3) >> 2)))) {
			

		/* 
		 * TODO: Throttling sending_rate for < 1 RTT (75% of RTT)
		 * after SACK. It was 1 RTT before. This is 
		 * being too aggresive. Review this.
		 */
		TCP_REVSW_RBE_SET_STATE(rbe, TCP_REVSW_RBE_STATE_SACK_DONE);
	}

	switch (rbe->rbe_mode) {
	case TCP_REVSW_RBE_MODE_INVALID:
		break;

	case TCP_REVSW_RBE_MODE_INIT:
		tcp_revsw_rbe_process_mode_init(tp, rbe, tp->snd_una);
		break;

	case TCP_REVSW_RBE_MODE_BM:
		tcp_revsw_rbe_process_mode_bm(tp, rbe, tp->snd_una);
		break;

	case TCP_REVSW_RBE_MODE_PRE_MONITOR:
		tcp_revsw_rbe_process_pre_monitor(tp, rbe, tp->snd_una);
		break;

	case TCP_REVSW_RBE_MODE_MONITOR:
		tcp_revsw_rbe_process_mode_monitor(tp, rbe, tp->snd_una);
		break;

	default:
		LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_ERR, "%s: ERROR!\n", __func__);
		break;
	}

	rbe->una = tp->snd_una;
}

/*
 * @tcp_revsw_rbe_handle_slow_ack
 *
 * Handle slow ack.
 */
static inline void tcp_revsw_rbe_handle_slow_ack(struct tcp_sock *tp,
							 struct revsw_rbe *rbe)
{
	if (tp->sacked_out != rbe->last_sacked_out) {
		if (tp->sacked_out &&
			((tcp_time_stamp - rbe->sack_time_stamp) >
			TCP_REVSW_RBE_TIME_SINCE_LAST_SACK(tp))) {
			/*
			 * Fresh SACK
			 * TODO: After 1 SACK, we are not throttling
			 * sending_rate for subsequent SACKs for
			 * TCP_REVSW_RBE_TIME_SINCE_LAST_SACK() RTT
			 */
			LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_INFO, 
				"\t\tFresh SACK. Current-State before changing = %u\n\n",
				rbe->rbe_state);
			
			TCP_REVSW_RBE_SET_STATE(rbe, TCP_REVSW_RBE_STATE_FORCE_DRAIN);
			rbe->sack_time_stamp = tcp_time_stamp;
		}

		LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_SACK, "sacked_out %u. ack %u ..",
				tp->sacked_out,
				tp->snd_una);

		LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_SACK,
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

	tcp_revsw_rbe_common_ack(tp, rbe);
}

/*
 * @tcp_revsw_rbe_handle_fast_ack
 *
 * Handle fast ack.
 */
static inline void tcp_revsw_rbe_handle_fast_ack(struct tcp_sock *tp,
					   struct revsw_rbe *rbe)
{
	if (tp->sacked_out != rbe->last_sacked_out) {
		if (tp->sacked_out)
			LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_INFO,
			       "sacked_out: fast ack? %u %u\n",
			       tp->sacked_out, rbe->last_sacked_out);

		LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_INFO, "last sacked out updated! %u %u",
		       tp->sacked_out, rbe->last_sacked_out);
		rbe->last_sacked_out = tp->sacked_out;
	}

	tcp_revsw_rbe_common_ack(tp, rbe);
}

/*
 * @tcp_revsw_rbe_remaining_leak_quota
 *
 * Return number of packets that can be sent as part
 * of this leak
 *
 * TODO: handle tcp_time_stamp reset
 */
static inline int tcp_revsw_rbe_remaining_leak_quota(struct tcp_sock *tp,
							struct revsw_rbe *rbe)
{
	/* Bytes Sent out after the last call to this function. */
	u32 bytes_sent;
	/* Quota: Bytes that can be sent out on wire. */
	u32 quota;
	/* Time since this leak started (Used to maintain leakrate/sec) */
	u32 leak_time;
	u32 unutilized_time; /* In that leak */

	leak_time = jiffies_to_msecs(tcp_time_stamp -
				     rbe->leak_start_ts);

	quota = 0;

	if (leak_time <= TCP_REVSW_RBE_MSECS_PER_LEAK) {
		/* Still in same leak/drop. */
		bytes_sent = tp->snd_nxt - rbe->last_snd_nxt;
		rbe->bytes_sent_this_leak += bytes_sent;
		if (rbe->bytes_sent_this_leak < rbe->sending_rate)
			quota = rbe->sending_rate -
					rbe->bytes_sent_this_leak;
	} else {
		/* 
		 * TODO: Session DB is now always allocated.
		 * Do we need to defer init_timer () ? 
		 * Btw, Does no harm.
		 */
		if (tcp_revsw_rbe_init_timer(rbe, (struct sock *) tp) == -1) {
			LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_ERR,
			       "%s: Session DB not yet allocated\n", __func__);
			goto exit;
		}
		/* Next leak */
		unutilized_time = msecs_to_jiffies((leak_time - 1000) % 1000);
		rbe->leak_start_ts = tcp_time_stamp - unutilized_time;

		if (timer_pending(&rbe->timer) == 0) {
			/* If timer is not pending, start it. */
			if (mod_timer(&rbe->timer, jiffies +
				msecs_to_jiffies(TCP_REVSW_RBE_LEAK_QUOTA_TIMER) -
				unutilized_time)) {
				/* TODO: Handle error? */
				LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_ERR,
					"%s: Error modifying timer", __func__);
			}
		}
		rbe->bytes_sent_this_leak = 0;
		quota = rbe->sending_rate;
	}

exit:
	return quota;
}

/*
 * @tcp_revsw_rbe_get_cwnd_quota
 *
 * This function is called before sending any packet out on wire.
 * Here we determine the number of packets that can be sent
 * out in this leak. A leak is number of packets per second
 * which is = sending_rate.
 *
 * TODO: handle tcp_time_stamp reset
 */
static int tcp_revsw_rbe_get_cwnd_quota(struct sock *sk, const struct sk_buff *skb)
{
	struct tcp_sock *tp = tcp_sk(sk);
	/* Quota: Bytes that can be sent out on wire. */
	u32 quota, in_flight;
	int cwnd_quota;
	//int cwnd;
	struct revsw_rbe *rbe, __rbe;

	TCP_REVSW_RBE_PRIVATE_DATE(__rbe);
	rbe = &__rbe;

	if (rbe->last_snd_nxt == 0) {

		/*
		 * First Drop.
		 * First time this function is getting called for this socket.
		 */

		rbe->bytes_sent_this_leak	= 0;
		rbe->leak_start_ts		= tcp_time_stamp;
		rbe->init_cwnd			= tp->snd_cwnd;
		rbe->una				= tp->snd_una;
		rbe->ack_r2			= tp->snd_una;
		rbe->sending_rate = quota = rbe->init_cwnd * 1448;
		TCP_REVSW_RBE_SET_MODE(rbe, TCP_REVSW_RBE_MODE_INIT);

		/*
		 * If session DB is not yet allocated, timer_init wont happen.
		 * We will try again later
		 */
		tcp_revsw_rbe_init_timer(rbe, sk);

		LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_INFO,
			"Sending Very first packet (%u / %u) and una : %u\n",
					rbe->init_cwnd, tp->snd_cwnd,
					tp->snd_una);
	} else {
		if (rbe->rbe_mode != TCP_REVSW_RBE_MODE_MONITOR &&
			rbe->rbe_mode != TCP_REVSW_RBE_MODE_PRE_MONITOR &&
			rbe->drain_start_ts >
				(tcp_time_stamp + (4 * (tp->srtt >> 3)))) {
			/*
			 * Enter Monitor Mode. We are in
			 * BUFFER_DRAIN state for more than 4 RTT
			 */
			LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_INFO, "!!Enter Monitor Mode\n");
			tcp_revsw_rbe_enter_monitor_mode(tp, rbe);
		}
		quota = tcp_revsw_rbe_remaining_leak_quota(tp, rbe);
	}

	LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_VERBOSE,
		"Quota: %u, snd_rate %u, BY_sent %u last_SN %u, SN = %u\n",
				quota, rbe->sending_rate,
				rbe->bytes_sent_this_leak,
				rbe->last_snd_nxt, tp->snd_nxt);

	rbe->last_snd_nxt = tp->snd_nxt;
	/*
	 * The TCP stack checks tp->snd_cwnd value at several
	 * places. Anyway this variable has no significance when
	 * TCP-RBE is used as CCA. The 2 conditions which we
	 * have to meet pacify the stack are
	 * (1) it shouldn't be zero (2) It > packets_in_flight.
	 */
	cwnd_quota = (int)quota / max_t(u32, 1, tp->mss_cache);
	in_flight = tcp_packets_in_flight(tp);
	tp->snd_cwnd = in_flight + cwnd_quota + 2;

	LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_VERBOSE,
	       "cwnd_quota %d, flight %u ; snd_wnd  %u ; snd_cwnd %u\n",
	       cwnd_quota, in_flight, tp->snd_wnd, tp->snd_cwnd);

	return cwnd_quota;
}

/*
 * @tcp_revsw_rbe_init
 *
 * Starts session DB for this connection.
 */
static void tcp_revsw_rbe_init(struct sock *sk)
{
	struct revsw_rbe *rbe, __rbe;
	u32 bko_level;

	const struct inet_sock *isk = inet_sk(sk);

	tcp_session_add(sk, TCP_REVSW_CCA_RBE);
	if (isk != NULL) {
	  LOG_IT(tcp_revsw_sysctls.sess_loglevel, TCP_REVSW_UTL_LOG_VERBOSE,
		 "Starting session for rbe socket: %pI4:%d -> %pI4:%d\n",  &isk->inet_saddr, ntohs(isk->inet_sport), &isk->inet_daddr, ntohs(isk->inet_dport));
	}

	TCP_REVSW_RBE_PRIVATE_DATE(__rbe);
	rbe = &__rbe;

	bko_level = tcp_session_get_backoff_level(sk);
	
	rbe->syn_ack_tsecr = tcp_time_stamp;

	switch (bko_level) {
	case TCP_REVSW_BKO_OK:
		rbe->ss_growth_factor = TCP_REVSW_RBE_SS_LVL4;
		break;

	case TCP_REVSW_BKO_LVL1:
		rbe->ss_growth_factor = TCP_REVSW_RBE_SS_LVL3;
		break;

	case TCP_REVSW_BKO_LVL2:
		rbe->ss_growth_factor = TCP_REVSW_RBE_SS_LVL2;
		break;

	case TCP_REVSW_BKO_LVL3:
		rbe->ss_growth_factor = TCP_REVSW_RBE_SS_LVL1;
		break;

	case TCP_REVSW_BKO_LVL4:
		rbe->ss_growth_factor = TCP_REVSW_RBE_SS_DEFAULT;
		break;
	default:
		rbe->ss_growth_factor = TCP_REVSW_RBE_SS_DEFAULT;
		break;
	}

	if (isk != NULL) {
	  LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_INFO, "%s: rbe socket %pI4:%d -> %pI4:%d - Growth Factor: %u\n", 
		 __func__,&isk->inet_saddr, ntohs(isk->inet_sport), &isk->inet_daddr, ntohs(isk->inet_dport), rbe->ss_growth_factor);
	}
}

/*
 * @tcp_revsw_rbe_release
 *
 * This function setups up the deletion of the session database entry used by
 * this connection.
 */
static void tcp_revsw_rbe_release(struct sock *sk)
{
	struct revsw_rbe *rbe, __rbe;
	const struct inet_sock *isk = inet_sk(sk);

	TCP_REVSW_RBE_PRIVATE_DATE(__rbe);
	rbe = &__rbe;

	if (rbe->s)
		rbe->tsk = NULL;
	if (isk != NULL) {
	  LOG_IT(tcp_revsw_sysctls.sess_loglevel, TCP_REVSW_UTL_LOG_VERBOSE,
	       "Freeing session for rbe socket: %pI4:%d -> %pI4:%d\n", &isk->inet_saddr, ntohs(isk->inet_sport), &isk->inet_daddr, ntohs(isk->inet_dport))
	}
	tcp_session_delete(sk);

	LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_INFO, "%s Exiting\n", __func__);
}

/*
 * @tcp_revsw_rbe_ssthresh
 *
 * This is a mandatory callback function. Curbently not used by RBE.
 * TODO: Check where this function si called from and if we can use
 * this for RBE.
 * TODO: Also check if returning a different value makes
 * any difference to RBE
 */
static u32 tcp_revsw_rbe_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);

	return tp->snd_cwnd;
}

/*
 * @tcp_revsw_rbe_cong_avoid
 *
 * This is a mandatory callback function. Currently not used by RBE.
 * TODO: Check where this function is called from and if we can use
 * this for RBE.
 * TODO: Also check if returning a different value makes
 * any difference to RBE
 */
static void tcp_revsw_rbe_cong_avoid(struct sock *sk, u32 ack, u32 in_flight)
{
}

/*
 * @tcp_revsw_rbe_pkts_acked
 *
 * Called after processing group of packets.
 * but all RBE needs is the minimum RTT.
 */
static void tcp_revsw_rbe_pkts_acked(struct sock *sk, u32 cnt, s32 rtt)
{
	struct revsw_rbe *rbe, __rbe;
	u32 mrtt = (u32)rtt / (u32)USEC_PER_MSEC;

	TCP_REVSW_RBE_PRIVATE_DATE(__rbe);
	rbe = &__rbe;

	if (mrtt > 0) {
		if (rbe->rtt_min != 0)
			rbe->rtt_min = min(mrtt, rbe->rtt_min);
		else
			rbe->rtt_min = mrtt;


		LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_INFO,
			   "Setting rtt-min: %u\n", rbe->rtt_min);
	}
}

/*
 * @tcp_revsw_rbe_state
 *
 * Handling RTO in this function.
 */
static void tcp_revsw_rbe_state(struct sock *sk, u8 new_state)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct revsw_rbe *rbe, __rbe;

	TCP_REVSW_RBE_PRIVATE_DATE(__rbe);
	rbe = &__rbe;

	if (new_state == TCP_CA_Loss) {
		if (rbe->rbe_state == TCP_REVSW_RBE_STATE_SACK) {
			/*
			 * We are in SACK processing state which means
			 * we are already draining buffer.
			 * (1) Ignore this event, if We entered SACK state
			 * in last TCP_REVSW_RBE_TIME_SINCE_LAST_SACK/2 ticks.
			 * (2) If not 1, we are in SACK processing state but
			 * it may not be enough. So, drain more.
			 */
			if ((tcp_time_stamp - rbe->sack_time_stamp) <
			    (TCP_REVSW_RBE_TIME_SINCE_LAST_SACK(tp) >> 1))
				return;
		} else if (!TCP_REVSW_RBE_RETX_IN_LAST_RTT(tp)) {
			/*
			 * There has not been any retransmits in last RTT,
			 * no SACK but RTO. This is unlikely.
			 * TODO: Review this.
			 */
			LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_ERR,
			       "\n RTO without SACK (unlikely event)");
			return;
		}

		LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_INFO, "!!!! TCP_CA_Loss State\n");
		TCP_REVSW_RBE_SET_STATE(rbe, TCP_REVSW_RBE_STATE_FORCE_DRAIN);
		rbe->sack_time_stamp = tcp_time_stamp;
		tcp_revsw_rbe_drain_buffer(tp, rbe);
	}
}

/*
 * @tcp_revsw_rbe_event
 *
 * Fast acks and Slow acks used to calculate receiving rate and adjust
 *  sending rate. SACK is also handled (with respect to RBE) in this function.
 */
static void tcp_revsw_rbe_event(struct sock *sk, enum tcp_ca_event event)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct revsw_rbe *rbe, __rbe;
	TCP_REVSW_RBE_PRIVATE_DATE(__rbe);
	rbe = &__rbe;

	switch (event) {
	case CA_EVENT_FAST_ACK:
		tcp_revsw_rbe_handle_fast_ack(tp, rbe);
		break;

	case CA_EVENT_SLOW_ACK:
		tcp_revsw_rbe_handle_slow_ack(tp, rbe);
		break;

	default:
		/* don't care */
		break;
	}
}

/*
 * @tcp_revsw_rbe_snd_wnd_test
 *
 * This function determines if we should
 * ignore or honor receive window?
 */
static bool
tcp_revsw_rbe_snd_wnd_test(const struct tcp_sock *tp, const struct sk_buff *skb,
		     unsigned int cur_mss)
{
	int test_snd_wnd;
	u32 delta_win;
	struct sock *sk = (struct sock *) tp;
	struct revsw_rbe *rbe, __rbe;

	TCP_REVSW_RBE_PRIVATE_DATE(__rbe);
	rbe = &__rbe;

	switch (tcp_revsw_sysctls.test_tcp_snd_wnd) {

	case TCP_REVSW_RBE_IGNORE_INIT_BURST:
		if (tcp_revsw_sysctls.cong_wnd && rbe->rbe_mode == TCP_REVSW_RBE_MODE_INIT)
			test_snd_wnd = TCP_REVSW_RBE_IGNORE_RCV_WND;
		else
			test_snd_wnd = TCP_REVSW_RBE_HONOR_RCV_WND;
		break;

	case TCP_REVSW_RBE_HONOR_NO_REXMIT:
		if (rbe->rbe_state == TCP_REVSW_RBE_STATE_FORCE_DRAIN ||
				rbe->rbe_state == TCP_REVSW_RBE_STATE_SACK)
			test_snd_wnd = TCP_REVSW_RBE_HONOR_RCV_WND;

		/* No break, continue */

	case TCP_REVSW_RBE_IGNORE_RCV_WND:
		if (tcp_revsw_sysctls.rwin_scale > 0) {
			delta_win = tp->snd_wnd * tcp_revsw_sysctls.rwin_scale / 100;
			if (TCP_SKB_CB(tcp_send_head(sk))->seq >
				(tp->snd_una +
				(tp->snd_wnd + delta_win)))
				test_snd_wnd = TCP_REVSW_RBE_HONOR_RCV_WND;
			}

		test_snd_wnd = TCP_REVSW_RBE_IGNORE_RCV_WND;
		break;

	default:
		test_snd_wnd = TCP_REVSW_RBE_HONOR_RCV_WND;
		break;
	}

	if (test_snd_wnd == TCP_REVSW_RBE_HONOR_RCV_WND) {
		u32 end_seq = TCP_SKB_CB(skb)->end_seq;

		if (skb->len > cur_mss)
			end_seq = TCP_SKB_CB(skb)->seq + cur_mss;

		return !after(end_seq, tcp_wnd_end(tp));
	} else {
		return TCP_REVSW_RBE_IGNORE_RCV_WND;
	}
}

static void tcp_rbe_session_delete_cb(struct tcp_session_info *info,
				      void *cca_priv)
{
	struct sess_priv *s = (struct sess_priv *) cca_priv;

	LOG_IT(tcp_revsw_sysctls.rbe_loglevel, TCP_REVSW_UTL_LOG_VERBOSE, "%s: Cleaning up\n", __func__);

	del_timer(&s->rbe_timer);
}

static bool tcp_revsw_rbe_validate_use(struct sock *sk, u8 initiated)
{
	const struct inet_sock *inet = inet_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	bool use_valid = false;
	u8 results = 0;

/*
 * RBE will be selected as long as the following conditions
 * are met:
 * - RBE is listed in the supported_cca sysctl
 * - the connection is client initiated
 * - client is not the LOCAL HOST
 * - client has enabled TCP timestamps
 * - client has enabled SACKs
 */
	if (initiated == TCP_SESSION_CLIENT_INITIATED)
		results |= TCP_REVSW_RBE_CLIENT_INITIATED;

	if (inet->inet_daddr != TCP_REVSW_LOCALHOST)
		results |= TCP_REVSW_RBE_NON_LOCAL_HOST;

	if (tp->rx_opt.tstamp_ok == 1)
		results |= TCP_REVSW_RBE_TIMESTAMP;

	if (tp->rx_opt.sack_ok & TCP_SACK_SEEN)
		results |= TCP_REVSW_RBE_SACK;

	if (tcp_revsw_sysctls.supported_cca & (1 << TCP_REVSW_CCA_RBE) &&
	    (results == TCP_REVSW_RBE_VALID))
		use_valid = true;

	/*
	* RBE is supported but it was not selected as the CCA for this 
	* connection.  Log this fact.  This is a temporary log for initial
	* testing of the new RBE code. Only create a log for client initiated
	* connections that are not from the local host.
	*/
	if ((results & TCP_REVSW_RBE_VALID_LOG) == TCP_REVSW_RBE_VALID_LOG) {
		if (use_valid && tcp_revsw_sysctls.rbe_loglevel > 1)
			pr_err("%s: %p IP %pI4:%u using RBE (%d)\n", __func__, sk,
				&inet->inet_daddr, ntohs(inet->inet_dport), results);
		else if (!use_valid && tcp_revsw_sysctls.rbe_loglevel)
			pr_err("%s: %p IP %pI4:%u did not use RBE (%d)\n", __func__, sk,
				&inet->inet_daddr, ntohs(inet->inet_dport), results);
	}

	return use_valid;
}

static struct tcp_congestion_ops tcp_revsw_rbe __read_mostly = {
	.flags		= TCP_CONG_RTT_STAMP,
	.init		= tcp_revsw_rbe_init,
	.release	= tcp_revsw_rbe_release,
	.ssthresh	= tcp_revsw_rbe_ssthresh,
	.cong_avoid	= tcp_revsw_rbe_cong_avoid,
	.min_cwnd	= NULL,
	.set_state	= tcp_revsw_rbe_state,
	.cwnd_event	= tcp_revsw_rbe_event,
	.get_info	= NULL,
	.pkts_acked	= tcp_revsw_rbe_pkts_acked,
	.syn_post_config = tcp_revsw_generic_syn_post_config,
	.set_nwin_size = NULL,
	.handle_nagle_test = tcp_revsw_generic_handle_nagle_test,
	.get_session_info = tcp_session_get_info,
	.get_cwnd_quota = tcp_revsw_rbe_get_cwnd_quota,
	.snd_wnd_test = tcp_revsw_rbe_snd_wnd_test,

	.owner		= THIS_MODULE,
	.name		= "rbe"
};

static struct tcp_session_info_ops tcp_rbe_session_ops __read_mostly = {
	.session_add	= NULL,
	.session_delete = tcp_rbe_session_delete_cb
};

struct tcp_revsw_cca_entry tcp_revsw_rbe_cca __read_mostly = {
	.revsw_cca = TCP_REVSW_CCA_RBE,
	.cca_validate_use = tcp_revsw_rbe_validate_use,
	.cca_ops = &tcp_revsw_rbe,
	.session_ops = &tcp_rbe_session_ops,
};

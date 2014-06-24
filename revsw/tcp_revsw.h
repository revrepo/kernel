/*
 *
 *   RevSw TCP Congestion Control Algorithm
 *
 * Starting off RevSw will be utilizing the Westwood CCA with
 * some minor tweaks to get better throughput and congestion
 * control.
 *
 */
#ifndef __TCP_REVSW_H__
#define __TCP_REVSW_H__


/* TCP RevSw structure */
struct revsw {
	struct tcp_session_entry *session;
	u32 bw_ns_est;  /* first bandwidth estimation..not smoothed 8) */
	u32 bw_est;     /* bandwidth estimate */
	u32 rtt_win_sx; /* here starts a new evaluation... */
	u32 bk;
	u32 snd_una;    /* used for evaluating the number of acked bytes */
	u32 cumul_ack;
	u32 accounted;
	u32 rtt;
	u32 rtt_min;    /* minimum observed RTT */
	u8 first_ack;   /* flag which infers that this is the first ack */
	u8 reset_rtt_min; /* Reset RTT min to next RTT sample*/
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
};

#define TCP_REVSW_RTT_MIN   (HZ/20)     /* 50ms */
#define TCP_REVSW_INIT_RTT  (20*HZ)     /* maybe too conservative?! */
#define BICTCP_BETA_SCALE    1024	/* Scale factor beta calculation
					 * max_cwnd = snd_cwnd * beta
					 */

#define BICTCP_HZ     10  /* BIC HZ 2^10 = 1024 */

/* Two methods of hybrid slow start */
#define HYSTART_ACK_TRAIN		0x1
#define HYSTART_DELAY			0x2

#endif /* __TCP_REVSW_H__ */

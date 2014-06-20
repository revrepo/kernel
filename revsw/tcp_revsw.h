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

/********************************************************************
 *
 * RevSw sysctl support
 *
 ********************************************************************/

#define REVSW_RWND_MPLR_MIN		1
#define REVSW_RWND_MPLR_MAX		5
#define REVSW_RWND_MPLR_DEFAULT		3
#define REVSW_LARGE_RWND_MPLR		2
#define REVSW_LARGE_RWND_SIZE		65536

/*
 * Initial Congestion Window
 * Default of 0 means that the system will determine the
 * initial cwnd based on the RWND and MTU.  Otherwise is
 * will take what the user has set.
 */
#define REVSW_CONG_WND_MIN      0
#define REVSW_CONG_WND_MAX      200
#define REVSW_CONG_WND_DEFAULT  REVSW_CONG_WND_MIN

#define REVSW_RTO_DEFAULT       63

/********************************************************************
 *
 * RevSw TCP Session Database
 *
 ********************************************************************/
#define TCP_SESSION_HASH_BITS           16
#define TCP_SESSION_KEY_BITMASK         0xFFFF
#define TCP_SESSION_DEFAULT_LATENCY     10000
#define TCP_SESSION_DEFAULT_BW          0
#define TCP_SESSION_TTL_MAX		259200
#define TCP_SESSION_TTL_DEFAULT		10800

#define TCP_SESSION_HASH_SIZE   (1 << TCP_SESSION_HASH_BITS)

#define TCP_SESSION_INFO_VERSION 1

struct tcp_session_info {
	__u32 version;
	__u32 cookie;
	__u32 latency;
	__u32 bandwidth;
};

struct tcp_session_entry {
	struct hlist_node node;
	struct delayed_work work;
	struct tcp_session_info info;
	__u32 addr;
	__u16 port;
};

struct tcp_session_info_hash {
	struct hlist_head hlist;
	spinlock_t lock;
};

/********************************************************************
 *
 * RevSw Congestion Control Algorithm
 *
 ********************************************************************/

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

/* TCP RevSw functions and constants */
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

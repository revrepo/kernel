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
#define REVSW_RCV_WND_MIN       6000
#define REVSW_RCV_WND_MAX       393216
#define REVSW_RCV_WND_DEFAULT   131072
#define REVSW_CONG_WND_MIN      10
#define REVSW_CONG_WND_MAX      200
#define REVSW_CONG_WND_DEFAULT  100
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
 * RevSw TCP RRE Log Level (Keep it until RRE is compleetely ready and we dont need dev-logs)
 *
 ********************************************************************/
typedef enum revsw_rre_loglevel_ {
	REVSW_RRE_LOG_NOLOG = 0,
	REVSW_RRE_LOG_ERR,
	REVSW_RRE_LOG_INFO,
	REVSW_RRE_LOG_SACK,
	REVSW_RRE_LOG_VERBOSE,
} revsw_rre_loglevel;

/********************************************************************
 *
 * RevSw TCP RRE Modes
 *
 ********************************************************************/
typedef enum _rev_rre_mode_ {
	TCP_REV_RRE_MODE_INVALID = 0,
	TCP_REV_RRE_MODE_INIT,
	TCP_REV_RRE_MODE_BM,
	TCP_REV_RRE_MODE_MONITOR,
} rev_rre_mode_e;

typedef enum _rev_rre_state_ {
	TCP_REV_RRE_STATE_INVALID = 0,
	TCP_REV_RRE_STATE_FILL,
	TCP_REV_RRE_STATE_DRAIN,
	TCP_REV_RRE_STATE_FORCE_DRAIN,
	TCP_REV_RRE_STATE_SACK,
	TCP_REV_RRE_STATE_SACK_DONE,
} rev_rre_state_e;

/********************************************************************
 *
 * RevSw RRE Congestion Control Algorithm
 *
 ********************************************************************/

struct revsw_rre {
	/* Revsw variables */
	u32 rev_store_seq; // check if we can use an existing variable
	u32 rev_rre_ts_tsecr;
	u32 rev_rre_ts_r1;
	u32 rev_rre_ts_r2;
	u32 rev_rre_ack_r1;
	u32 rev_rre_ack_r2;

	u32 rev_last_snd_nxt;
	u32 rev_leak_start_ts;
	u32 rev_leak_sent_ts;
	u32 rev_bytes_sent_this_leak;

	u32 rev_sending_rate; 	//  sending_rate is in bytes/sec

	// 10

	//struct ewma rev_receiving_rate;
	u32 rev_rre_t;  		// number of bytes.
	u32 rev_rre_Bmax;       // number of bytes.
	u32 rev_rre_Bmin;       // number of bytes.
	int rev_rre_RDmin;      // in ticks
	u32 rev_rtt_min;        // in miliseconds

	u32 rev_rre_last_ts;
	u32 rev_rre_last_ack;
	u32 rev_rre_calc_ts;
	u32 rev_init_cwnd;
	u8 rev_rre_mode;
	u8 rev_rre_state;
	u32 rev_last_sacked_out;
//	ICSK_CA_PRIV_SIZE 24 u32
};

#endif /* __TCP_REVSW_H__ */

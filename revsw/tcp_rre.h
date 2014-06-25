/*
 *
 *   RevSw TCP Congestion Control Algorithm
 *
 * Starting off RevSw will be utilizing the Westwood CCA with
 * some minor tweaks to get better throughput and congestion
 * control.
 *
 */
#ifndef __TCP_REVSW_RRE_H__
#define __TCP_REVSW_RRE_H__

#include <linux/average.h>

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
	u32 rev_rre_ack_r1;
	u32 rev_rre_ts_r1;
	/* The following 2 variables are overloaded. They are used differnetly in INIT and BM modes. */
	u32 rev_rre_ack_r2;
	u32 rev_rre_ts_r2;

	u32 rev_last_snd_nxt;
	u32 rev_leak_start_ts;
	u32 rev_bytes_sent_this_leak;
	u32 rev_sending_rate; 	//  sending_rate is in bytes/sec

	// 8

	//struct ewma rev_receiving_rate;
	u32 rev_rre_t;  		// number of bytes.
	u32 rev_rre_Bmax;       // number of bytes.
	u32 rev_rre_Bmin;       // number of bytes.
	int rev_rre_RDmin;      // in ticks
	u32 rev_rtt_min;        // in miliseconds

	u32 rev_init_cwnd;
	u32 rev_last_sacked_out;
	u32 rre_sack_time_stamp;
	struct ewma rev_rre_receiving_rate;
	u32 rev_rre_first_rtt;

	// 17
	u8 rev_rre_mode;
	u8 rev_rre_state;
//	ICSK_CA_PRIV_SIZE 24 u32
};

#endif /* __TCP_REVSW_RRE_H__ */

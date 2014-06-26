/*
 *
 *   RevSw RRE TCP Congestion Control Algorithm Header File
 *
 */
#ifndef __TCP_REVSW_RRE_H__
#define __TCP_REVSW_RRE_H__

#include <linux/average.h>

/* Number of packets we require in INIT mode or MONITOR mode to calculate receiver rate */
#define TCP_RRE_PACKETS_REQ_CALC_RATE	30

/* Number of packets we use to calculate tbuff */
#define TCP_RRE_TBUFF_PACKETS	30

typedef enum revsw_rre_loglevel_ {
	REVSW_RRE_LOG_NOLOG = REVSW_RRE_LOG_DEFAULT,
	REVSW_RRE_LOG_ERR,
	REVSW_RRE_LOG_INFO,
	REVSW_RRE_LOG_SACK,
	REVSW_RRE_LOG_VERBOSE,
} revsw_rre_loglevel;

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

	u8 rev_rre_mode;
	u8 rev_rre_state;
};

#endif /* __TCP_REVSW_RRE_H__ */

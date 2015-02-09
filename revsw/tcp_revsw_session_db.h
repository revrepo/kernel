/*
 *
 *   RevSw TCP Sysctl Support
 *
 * This module provides the sysctls that the various RevSw
 * congestion control algortihms and session database require.
 *
 * Copyright (c) 2013-2014, Rev Software, Inc.
 * All Rights Reserved.
 * This code is confidential and proprietary to Rev Software, Inc
 * and may only be used under a license from Rev Software Inc.
 */
#ifndef __TCP_REVSW_SESSION_DB_H__
#define __TCP_REVSW_SESSION_DB_H__

#define TCP_SESSION_DEFAULT_LATENCY     10000
#define TCP_SESSION_DEFAULT_BW          0

#define TCP_SESSION_HASH_SIZE   (1 << TCP_SESSION_HASH_BITS)

#define TCP_SESSION_INFO_VERSION 2
#define TCP_CCA_PRIV_UINTS	40
#define TCP_CCA_PRIV_SIZE	(TCP_CCA_PRIV_UINTS * sizeof(u32))

/*
 * Definitions to indicate who initiated the connection
 */
#define TCP_SESSION_SERVER_INITIATED 0
#define TCP_SESSION_CLIENT_INITIATED 1

/*
 * RevSw Congestion Control Algorithms
 * UNKNOWN must always be 0
 */
#define TCP_REVSW_CCA_UNKNOWN   0
#define TCP_REVSW_CCA_STANDARD  1
#define TCP_REVSW_CCA_RBE       2
#define TCP_REVSW_CCA_MAX       3

/*
 * RevSw Safetynet Backoff levels
 */
#define TCP_REVSW_BKO_OK 0
#define TCP_REVSW_BKO_LVL1 1
#define TCP_REVSW_BKO_LVL2 2
#define TCP_REVSW_BKO_LVL3 3
#define TCP_REVSW_BKO_LVL4 4

/*
 * RevSw Window Size
 */
#define TCP_REVSW_RWIN_SM 0
#define TCP_REVSW_RWIN_MED 1
#define TCP_REVSW_RWIN_LRG 2
#define TCP_REVSW_RWIN_MAX 3

struct tcp_session_info {
	u32 version;
	u32 cookie;
	u32 latency;
	u32 bandwidth;
	u8 quota_reached;
	u8 cca_type;
};

extern void tcp_session_update_initiator(const struct sock *sk, u8 initiated);
extern u16 tcp_session_get_act_cnt(const struct sock *sk);
extern int tcp_session_get_info(struct sock *sk, unsigned char *data, int *len);
extern void tcp_session_add(struct sock *sk, u8 cca_type);
extern void tcp_session_delete(const struct sock *sk);
extern struct tcp_session_info *tcp_session_get_info_ptr(struct sock *sk);
extern u32 *tcp_session_get_cca_priv(const struct sock *sk);
extern u8 tcp_session_get_backoff_level(const struct sock *sk);
extern u8 tcp_session_get_rwin(const struct sock *sk);
extern int tcp_revsw_session_db_init(void);
extern void tcp_revsw_session_db_remove(void);

#endif /* __TCP_REVSW_SESSION_DB_H__ */

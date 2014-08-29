/*
 *
 *   RevSw TCP Sysctl Support
 *
 * This module provides the sysctls that the various RevSw
 * congestion control algortihms and session database require.
 *
 */

#ifndef __TCP_REVSW_SESSION_DB_H__
#define __TCP_REVSW_SESSION_DB_H__

#define TCP_SESSION_HASH_BITS           16
#define TCP_SESSION_KEY_BITMASK         0xFFFF
#define TCP_SESSION_DEFAULT_LATENCY     10000
#define TCP_SESSION_DEFAULT_BW          0

#define TCP_SESSION_HASH_SIZE   (1 << TCP_SESSION_HASH_BITS)

#define TCP_SESSION_INFO_VERSION 1
#define TCP_CCA_PRIV_UINTS	40
#define TCP_CCA_PRIV_SIZE	(TCP_CCA_PRIV_UINTS * sizeof(u32))

/*
 * RevSw Congestion Control Algorithms
 * UNKNOWN must always be 0
 */
#define TCP_REVSW_CCA_UNKNOWN   0
#define TCP_REVSW_CCA_STANDARD  1
#define TCP_REVSW_CCA_RBE       2
#define TCP_REVSW_CCA_MAX       3

struct tcp_session_info {
	__u32 version;
	__u32 cookie;
	__u32 latency;
	__u32 bandwidth;
	__u8 quota_reached;
};

struct tcp_session_info_ops {
	void (*session_add)(struct sock *sk, struct tcp_session_info *info);
	void (*session_delete)(struct sock *sk, struct tcp_session_info *info);
};

extern void tcp_session_add(struct sock *sk);
extern void tcp_session_delete(struct sock *sk);
extern int tcp_session_get_info(struct sock *sk, unsigned char *data, int *len);
extern int tcp_session_get_act_cnt(struct sock *sk);
extern struct tcp_session_info *tcp_session_get_info_ptr(struct sock *sk);
extern u32 *tcp_session_get_cca_priv(struct sock *sk);
extern void tcp_session_register_ops(u32 cca_type, 
				     struct tcp_session_info_ops *ops);
extern void tcp_session_deregister_ops(u32 cca_type);

#endif /* __TCP_REVSW_SESSION_DB_H__ */

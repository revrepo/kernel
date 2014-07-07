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
#define TCP_CCA_PRIV_UINTS	16
#define TCP_CCA_PRIV_SIZE	(TCP_CCA_PRIV_UINTS * sizeof(u32))

struct tcp_session_info {
	__u32 version;
	__u32 cookie;
	__u32 latency;
	__u32 bandwidth;
	__u8 quota_reached;
};

struct tcp_session_entry {
	struct hlist_node node;
	struct delayed_work work;
	struct tcp_session_info info;
	__u32 addr;
	__u16 port;
	u32 cca_priv[TCP_CCA_PRIV_UINTS];
};

struct tcp_session_info_hash {
	struct hlist_head hlist;
	spinlock_t lock;
	__u16 entries;
	__u16 act_entries;
};

extern void tcp_session_start(struct sock *sk);
extern void tcp_session_delete(struct sock *sk);
extern int tcp_session_get_info(struct sock *sk, unsigned char *data, int *len);
extern int tcp_session_get_act_cnt(struct sock *sk);

#endif /* __TCP_REVSW_SESSION_DB_H__ */

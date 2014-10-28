/*
 *   tcp_revsw.h
 *
 *   RevSw TCP Congestion Control Algorithm Wrapper
 *
 * RevSw has two congestion control algorithms that can be used
 * depending on various paramters: who initiated the connection,
 * what TCP parameters are supported on the connection, etc.  This
 * module provides a means to automatically determine which CCA
 * should be used and provides the mechanism to call the appropriate
 * CCA specific APIs when necessary.
 *
 * Copyright 2014 - RevSw
 *
 */
#ifndef __TCP_REVSW_H__
#define __TCP_REVSW_H__

#define TCP_REVSW_LOCALHOST 0x100007f

/*
 * Each of the RevSw TCP CCA algorithms have their own CCA data
 * structures but all of them MUST have the CCA type and TCP
 * session entry data structure as the first and second fields.
 */
#define TCP_REVSW_CCA_PADDING (ICSK_CA_PRIV_SIZE - 9)
struct tcp_revsw_cca_data {
	struct tcp_session_entry *session;
	u8 tcp_revsw_cca;
	u8 padding[TCP_REVSW_CCA_PADDING];
};

/*
 * For each possible RevSw CCA there needs to be a congestion
 * control ops vector.  The following data structure and table
 * will be used to pair them together.
 */
struct tcp_revsw_cca_entry {
	u8 revsw_cca;
	void (*cca_init)(void);
	struct tcp_congestion_ops *cca_ops;
	struct tcp_session_info_ops *session_ops;
};

/*
 * Congestion Control Algorithm Pointers - should be one
 * for every different RevSw algorithm.
 */
extern struct tcp_revsw_cca_entry tcp_revsw_std_cca;
extern struct tcp_revsw_cca_entry tcp_revsw_rbe_cca;

/*
 * RevSw Sysctl defines and data structures
 */
#define REVSW_LARGE_RWND_SIZE		65535
#define TCP_REVSW_RBE_LOG_DEFAULT	0

#define REVSW_PACKET_SIZE_MIN		300
#define REVSW_PACKET_SIZE_MAX		2000
#define REVSW_PACKET_SIZE_DEFAULT	1024

#define REVSW_ACTIVE_SCALE_MIN		0
#define REVSW_ACTIVE_SCALE_MAX		100
#define REVSW_ACTIVE_SCALE_DEFAULT	50

#define REVSW_INIT_CWND_MAX		100

#define REVSW_RWIN_SCALE_MIN		0
#define REVSW_RWIN_SCALE_MAX		sizeof(int)

#define REVSW_CL_ENTRIES_MIN	1
#define REVSW_CL_ENTRIES_MAX	10000
#define REVSW_CL_ENTRIES_DEFAULT 3000

struct tcp_revsw_sysctl_data {
	int sm_rcv_wnd;
	int lrg_rcv_wnd;
	int cong_wnd;
	int packet_size;
	int active_scale;
	int max_init_cwnd;
	int rwin_scale;
	int disable_nagle_mss;
	int rbe_loglevel;
	int test_tcp_snd_wnd;
	int cl_entries;
	int cn_entries;
	int fc_entries;
	int max_cl_entries;
	int supported_cca;
};

extern struct ctl_table revsw_ctl_table[];
extern struct tcp_revsw_sysctl_data tcp_revsw_sysctls;

extern void tcp_revsw_generic_syn_post_config(struct sock *sk);

extern bool tcp_revsw_generic_handle_nagle_test(struct sock *sk,
												struct sk_buff *skb,
												unsigned int mss_now,
												int nonagle);

#endif /* __TCP_REVSW_H__ */

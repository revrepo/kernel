/*
 *
 *   RevSw TCP Sysctl Support
 *
 * This module provides the sysctls that the various RevSw
 * congestion control algortihms and session database require.
 *
 */
#ifndef __TCP_REVSW_SYSCTL_H__
#define __TCP_REVSW_SYSCTL_H__

#define TCP_SESSION_TTL_MAX		259200
#define TCP_SESSION_TTL_DEFAULT		10800

#define REVSW_LARGE_RWND_SIZE		65535
#define REVSW_RRE_LOG_DEFAULT		0

#define REVSW_PACKET_SIZE_MIN          300
#define REVSW_PACKET_SIZE_MAX          2000
#define REVSW_PACKET_SIZE_DEFAULT      1024

#define REVSW_ACTIVE_SCALE_MIN         10
#define REVSW_ACTIVE_SCALE_MAX         100
#define REVSW_ACTIVE_SCALE_DEFAULT     50

extern int revsw_sm_rcv_wnd;
extern int revsw_lrg_rcv_wnd;
extern int revsw_cong_wnd;
extern int revsw_tcp_session_ttl;
extern int revsw_tcp_rre_loglevel;
extern int revsw_packet_size;
extern int revsw_active_scale;

#endif /* __TCP_REVSW_SYSCTL_H__ */


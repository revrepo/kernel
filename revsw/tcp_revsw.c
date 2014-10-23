/*
 *   tcp_revsw.c
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
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/inet_diag.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <net/tcp.h>
#include "tcp_revsw.h"
#include "tcp_revsw_session_db.h"
#include "tcp_revsw_version.h"

#define TCP_REVSW_LOCALHOST 0x100007f

static struct ctl_table_header *revsw_ctl_table_hdr;

/*
 * @tcp_revsw_register
 */
static int __init tcp_revsw_register(void)
{
	revsw_ctl_table_hdr = register_sysctl("revsw", revsw_ctl_table);
	if (!revsw_ctl_table_hdr)
		return -EFAULT;

	tcp_revsw_session_db_init();

	return 0;
}

/*
 * @tcp_revsw_unregister
 */
static void __exit tcp_revsw_unregister(void)
{
	tcp_revsw_session_db_remove();

	unregister_sysctl_table(revsw_ctl_table_hdr);
}

module_init(tcp_revsw_register);
module_exit(tcp_revsw_unregister);

MODULE_AUTHOR("Tom Kavanagh");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP RevSw");
MODULE_VERSION(__stringify(TCP_REVSW_MAJOR) "."
               __stringify(TCP_REVSW_MINOR) "."
               __stringify(TCP_REVSW_SUBLEVEL));
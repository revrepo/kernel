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
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/inet_diag.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <net/tcp.h>
#include "tcp_revsw_session_db.h"
#include "tcp_revsw_sysctl.h"

#define TCP_SESSION_BLOCK_SIZE	300

/*
 * Data structure used to hold individual session
 * information
 */
struct tcp_session_entry {
	struct hlist_node node;
	struct delayed_work work;
	struct tcp_session_info info;
	struct sock *sk;
	u32 addr;
	u16 port;
	u32 cca_priv[TCP_CCA_PRIV_UINTS];
};

/*
 * Data structure to be used for the session
 * info database hash table
 */
struct tcp_session_info_hash {
	struct hlist_head hlist;
	spinlock_t lock;
	u16 entries;
	u16 act_entries;
};

/*
 * Data structure to be used to hold
 * the pre-allocated session info records
 */
struct tcp_session_container {
	struct hlist_head hlist;
	struct delayed_work work;
	bool work_pending;
	spinlock_t lock;
	u16 entries;
};

static struct tcp_session_info_hash *tcpsi_hash;

static struct tcp_session_container *tcpsi_container;

static struct tcp_session_info_ops *tcpsi_ops[TCP_REVSW_CCA_MAX];

static void tcp_revsw_session_cleanup_hlist(struct hlist_head *hlist)
{
	struct tcp_session_entry *session;
	struct hlist_node *tnode;

	if (hlist_empty(hlist))
		return;

	hlist_for_each_entry_safe(session, tnode, hlist, node) {
		hlist_del(&session->node);
		cancel_delayed_work_sync(&session->work);
		kfree(session);
	}
}

static void tcp_revsw_session_move_to_container(struct work_struct *work)
{
	struct tcp_session_info_hash *thash;
	struct tcp_session_entry *session;
	u32 cca_type;
	u32 hash;

	session = container_of(to_delayed_work(work),
			       struct tcp_session_entry, work);

	cca_type = session->info.cca_type;

	hash = hash_32((session->addr & TCP_SESSION_KEY_BITMASK),
		       TCP_SESSION_HASH_BITS);

	thash = &tcpsi_hash[hash];

	spin_lock_bh(&thash->lock);
	hlist_del(&session->node);
	thash->entries--;
	spin_unlock_bh(&thash->lock);

	if (tcpsi_ops[cca_type] && tcpsi_ops[cca_type]->session_delete) {
		tcpsi_ops[cca_type]->session_delete(&session->info,
						(void *) &session->cca_priv[0]);
	}

	session->sk = NULL;
	session->addr = 0;
	session->port = 0;
	memset(&session->info, 0, sizeof(struct tcp_session_info));
	memset(session->cca_priv, 0, sizeof(u32) * TCP_CCA_PRIV_UINTS);

	spin_lock_bh(&tcpsi_container->lock);
	hlist_add_head(&session->node, &tcpsi_container->hlist);
	tcpsi_container->entries++;
	spin_unlock_bh(&tcpsi_container->lock);
}

static void tcp_revsw_session_allocate_block(struct work_struct *work)
{
	struct tcp_session_entry *session;
	int i;

	for (i = 0; i < TCP_SESSION_BLOCK_SIZE; i++) {
		session = kzalloc(sizeof(*session), GFP_KERNEL);
		if (!session) {
			pr_err("%s: Failed to allocate a test entry pointer (%d)\n",
			       __func__, i);
			return;
		}

		INIT_DELAYED_WORK(&session->work,
				  tcp_revsw_session_move_to_container);

		spin_lock_bh(&tcpsi_container->lock);
		hlist_add_head(&session->node, &tcpsi_container->hlist);
		spin_unlock_bh(&tcpsi_container->lock);
	}

	tcpsi_container->entries += TCP_SESSION_BLOCK_SIZE;
}

static struct tcp_session_entry *tcp_revsw_session_get_free_entry(void)
{
	struct tcp_session_entry *session;

	spin_lock_bh(&tcpsi_container->lock);
	session = hlist_entry_safe((tcpsi_container->hlist.first),
				   struct tcp_session_entry,
				   node);

	hlist_del(&session->node);
	tcpsi_container->entries--;
	spin_unlock_bh(&tcpsi_container->lock);

	/*
	 * Need to make sure there is always a sufficient
	 * number of free entries in the container.  Need
	 * to keep at least 1/3 of the original block size.
	 */
	if (tcpsi_container->entries < (TCP_SESSION_BLOCK_SIZE / 3))
		schedule_delayed_work(&tcpsi_container->work, 0);

	return session;
}

void tcp_session_add(struct sock *sk, u8 cca_type)
{
	const struct inet_sock *inet = inet_sk(sk);
	struct tcp_session_info_hash *thash;
	struct tcp_session_entry *session;
	struct tcp_sock *tp = tcp_sk(sk);
	__u32 addr;
	__u16 port;
	u32 hash;

	addr = (__force __u32)inet->inet_daddr;
	port = (__force __u16)inet->inet_dport;
	hash = hash_32((addr & TCP_SESSION_KEY_BITMASK),
				   TCP_SESSION_HASH_BITS);

	session = tcp_revsw_session_get_free_entry();
	if (!session) {
		pr_err("%s: Failed to get a free session record\n", __func__);
		return;
	}

	session->sk = sk;
	session->addr = addr;
	session->port = port;
	session->info.latency = TCP_SESSION_DEFAULT_LATENCY;
	session->info.bandwidth = TCP_SESSION_DEFAULT_BW;
	session->info.cca_type = cca_type;

	thash = &tcpsi_hash[hash];

	spin_lock_bh(&thash->lock);
	hlist_add_head(&session->node, &thash->hlist);
	thash->entries++;
	thash->act_entries++;
	spin_unlock_bh(&thash->lock);

	tp->session_info = (void *)session;

	if (tcpsi_ops[cca_type] && tcpsi_ops[cca_type]->session_add)
		tcpsi_ops[cca_type]->session_add(session->sk, &session->info);
}
EXPORT_SYMBOL_GPL(tcp_session_add);

void tcp_session_delete(struct sock *sk)
{
	const struct inet_sock *inet = inet_sk(sk);
	struct tcp_session_info_hash *thash;
	struct tcp_session_entry *session;
	struct tcp_sock *tp = tcp_sk(sk);
	__u32 addr;
	u32 hash;

	addr = (__force __u32)inet->inet_daddr;

	session = tp->session_info;
	if (!session)
		return;

	hash = hash_32((session->addr & TCP_SESSION_KEY_BITMASK),
		       TCP_SESSION_HASH_BITS);

	thash = &tcpsi_hash[hash];

	spin_lock_bh(&thash->lock);
	thash->act_entries--;
	spin_unlock_bh(&thash->lock);

	schedule_delayed_work(&session->work,
			      msecs_to_jiffies(revsw_tcp_session_ttl * 1000));
}
EXPORT_SYMBOL_GPL(tcp_session_delete);

int tcp_session_get_info(struct sock *sk, unsigned char *data, int *len)
{
	const struct inet_sock *inet = inet_sk(sk);
	__u32 addr = (__force u32)(inet->inet_daddr);
	struct tcp_session_info_hash *thash;
	struct tcp_session_entry *session;
	struct tcp_session_info info;
	struct hlist_node *tmp;
	u32 hash;

	hash = hash_32((addr & TCP_SESSION_KEY_BITMASK), TCP_SESSION_HASH_BITS);
	thash = &tcpsi_hash[hash];

	info.version = TCP_SESSION_INFO_VERSION;
	info.cookie = 0;
	info.latency = TCP_SESSION_DEFAULT_LATENCY;
	info.bandwidth = TCP_SESSION_DEFAULT_BW;

	if (hlist_empty(&thash->hlist))
		return -1;

	spin_lock_bh(&thash->lock);

	hlist_for_each_entry_safe(session, tmp, &thash->hlist, node) {
		if (session->addr == addr) {
			if ((session->info.latency <= info.latency) &&
				(session->info.bandwidth >= info.bandwidth)) {
				info.latency = session->info.latency;
				info.bandwidth = session->info.bandwidth;
			}
		}
	}

	spin_unlock_bh(&thash->lock);

	*len = min(*len, sizeof(info));

	memcpy(data, &info, *len);

	return 0;
}
EXPORT_SYMBOL_GPL(tcp_session_get_info);

int tcp_session_get_act_cnt(struct sock *sk)
{
	const struct inet_sock *inet = inet_sk(sk);
	__u32 addr = (__force u32)(inet->inet_daddr);
	u32 hash = hash_32((addr & TCP_SESSION_KEY_BITMASK),
					   TCP_SESSION_HASH_BITS);
	struct tcp_session_info_hash *thash = &tcpsi_hash[hash];

	return thash->act_entries;
}
EXPORT_SYMBOL_GPL(tcp_session_get_act_cnt);

/*
 * tcp_session_get_info_ptr
 *
 * Returns a pointer to the tcp_session_info data structure inside of the
 * TCP socket session_info.
 */
struct tcp_session_info *tcp_session_get_info_ptr(struct sock *sk)
{
	struct tcp_session_entry *session;
	struct tcp_sock *tp = tcp_sk(sk);

	session = tp->session_info;
	if (session)
		return &(session->info);

	return NULL;
}
EXPORT_SYMBOL_GPL(tcp_session_get_info_ptr);

u32 *tcp_session_get_cca_priv(struct sock *sk)
{
	struct tcp_session_entry *session;
	struct tcp_sock *tp = tcp_sk(sk);

	session = tp->session_info;
	if (session)
		return session->cca_priv;

	return NULL;
}
EXPORT_SYMBOL_GPL(tcp_session_get_cca_priv);

void tcp_session_register_ops(u32 cca_type, struct tcp_session_info_ops *ops)
{
	if (cca_type < TCP_REVSW_CCA_MAX)
		tcpsi_ops[cca_type] = ops;
}
EXPORT_SYMBOL_GPL(tcp_session_register_ops);

void tcp_session_deregister_ops(u32 cca_type)
{
	if (cca_type < TCP_REVSW_CCA_MAX)
		tcpsi_ops[cca_type] = NULL;
}
EXPORT_SYMBOL_GPL(tcp_session_deregister_ops);

static int __init tcp_revsw_session_db_register(void)
{
	struct tcp_session_entry *session;
	int i;

	tcpsi_container = kzalloc(sizeof(*tcpsi_container), GFP_KERNEL);
	if (!tcpsi_container) {
		pr_err("%s: Failed to allocate memory for container\n",
		       __func__);
		return -ENOMEM;
	}

	INIT_HLIST_HEAD(&tcpsi_container->hlist);
	spin_lock_init(&tcpsi_container->lock);
	INIT_DELAYED_WORK(&tcpsi_container->work,
			  tcp_revsw_session_allocate_block);

	for (i = 0; i < TCP_SESSION_BLOCK_SIZE; i++) {
		session = kzalloc(sizeof(*session), GFP_KERNEL);
		if (!session) {
			pr_err("%s: Failed to allocate a session record\n",
			       __func__);
			goto container_fail;
		}

		INIT_DELAYED_WORK(&session->work,
				  tcp_revsw_session_move_to_container);

		hlist_add_head(&session->node, &tcpsi_container->hlist);
		tcpsi_container->entries++;
	}

	tcpsi_hash = kzalloc(TCP_SESSION_HASH_SIZE * sizeof(*tcpsi_hash),
			     GFP_KERNEL);

	if (!tcpsi_hash) {
		pr_err("%s: Failed to allocate memory for hash table\n", __func__);
		goto container_fail;
	}

	for (i = 0; i < TCP_SESSION_HASH_SIZE; i++) {
		spin_lock_init(&tcpsi_hash[i].lock);
		INIT_HLIST_HEAD(&tcpsi_hash[i].hlist);
	}

	return 0;

container_fail:
	tcp_revsw_session_cleanup_hlist(&tcpsi_container->hlist);
	kfree(tcpsi_container);

	return -ENOMEM;
}

static void __exit tcp_revsw_session_db_unregister(void)
{
	int i;

	cancel_delayed_work_sync(&tcpsi_container->work);
	tcp_revsw_session_cleanup_hlist(&tcpsi_container->hlist);
	kfree(tcpsi_container);

	for (i = 0; i < TCP_SESSION_HASH_SIZE; i++) {
		tcp_revsw_session_cleanup_hlist(&tcpsi_hash[i].hlist);
	}

	kfree(tcpsi_hash);
}

module_init(tcp_revsw_session_db_register);
module_exit(tcp_revsw_session_db_unregister);

MODULE_AUTHOR("Tom Kavanagh");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP RevSw Session DB");

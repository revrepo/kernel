/*
 *
 *   RevSw TCP Sysctl Support
 *
 * This module provides the sysctls that the various RevSw
 * congestion control algortihms and session database require.
 *
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

struct tcp_session_entry {
	struct hlist_node node;
	struct delayed_work work;
	struct tcp_session_info info;
	struct sock *sk;
	u32 addr;
	u16 port;
	u32 cca_priv[TCP_CCA_PRIV_UINTS];
};

struct tcp_session_info_hash {
	struct hlist_head hlist;
	spinlock_t lock;
	u16 entries;
	u16 act_entries;
};

static struct tcp_session_info_hash *tcpsi_hash;

static struct tcp_session_info_ops *tcpsi_ops[TCP_REVSW_CCA_MAX];

static int tcp_session_hash_init(void)
{
	__u64 i;

	tcpsi_hash = kzalloc(TCP_SESSION_HASH_SIZE * sizeof(*tcpsi_hash),
			     GFP_KERNEL);
	if (!tcpsi_hash)
		return -ENOMEM;

	for (i = 0; i < TCP_SESSION_HASH_SIZE; i++) {
		spin_lock_init(&tcpsi_hash[i].lock);
		INIT_HLIST_HEAD(&tcpsi_hash[i].hlist);
	}

	return 0;
}

static void tcp_session_hash_cleanup(void)
{
	__u64 i;
	struct tcp_session_info_hash *thash;
	struct tcp_session_entry *session;
	struct hlist_node *tmp;

	for (i = 0; i < TCP_SESSION_HASH_SIZE; i++) {
		thash = &tcpsi_hash[i];
		if (hlist_empty(&thash->hlist))
			continue;

		spin_lock_bh(&thash->lock);

		hlist_for_each_entry_safe(session, tmp, &thash->hlist, node) {
			hlist_del(&session->node);
			cancel_delayed_work_sync(&session->work);
			kfree(session);
		}

		spin_unlock_bh(&thash->lock);
	}

	kfree(tcpsi_hash);
}

static void tcp_session_delete_work_handler(struct work_struct *work)
{
	struct tcp_session_entry *session = container_of(to_delayed_work(work),
						 struct tcp_session_entry,
						 work);
	struct tcp_session_info_hash *thash;
	struct tcp_sock *tp;
	u32 cca_type;
	u32 hash;

	if (hlist_unhashed(&session->node))
		return;

	hash = hash_32((session->addr & TCP_SESSION_KEY_BITMASK),
				   TCP_SESSION_HASH_BITS);

	thash = &tcpsi_hash[hash];

	tp = tcp_sk(session->sk);
	cca_type = *(u32 *)inet_csk_ca(session->sk);

	spin_lock_bh(&thash->lock);
	hlist_del(&session->node);
	thash->entries--;
	spin_unlock_bh(&thash->lock);

	if (tcpsi_ops[cca_type] && tcpsi_ops[cca_type]->session_delete)
		tcpsi_ops[cca_type]->session_delete(&session->info,
						(void *) &session->cca_priv[0]);

	kfree(session);
}

static void tcp_session_add_work_handler(struct work_struct *work)
{
	struct tcp_session_info_hash *thash;
	struct tcp_session_entry *session;
	const struct inet_sock *inet;
	struct tcp_sock *tp;
	struct sock *sk;
	u32 cca_type;
	__u32 addr;
	__u16 port;
	u32 hash;

	tp = container_of(to_delayed_work(work), struct tcp_sock, session_work);
	sk = (struct sock *)tp;
	inet = inet_sk(sk);
	cca_type = *(u32 *)inet_csk_ca(sk);

	addr =  (__force __u32)inet->inet_daddr;
	port = (__force __u16)inet->inet_dport;

	session = kzalloc(sizeof(*session), GFP_KERNEL);
	if (!session)
		return;

	session->sk = sk;
	session->addr = addr;
	session->port = port;
	session->info.latency = TCP_SESSION_DEFAULT_LATENCY;
	session->info.bandwidth = TCP_SESSION_DEFAULT_BW;
	INIT_DELAYED_WORK(&session->work, tcp_session_delete_work_handler);

	hash = hash_32((addr & TCP_SESSION_KEY_BITMASK),
				   TCP_SESSION_HASH_BITS);
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

void tcp_session_add(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	INIT_DELAYED_WORK(&tp->session_work, tcp_session_add_work_handler);

	mod_delayed_work(system_wq, &tp->session_work, 0);
}
EXPORT_SYMBOL_GPL(tcp_session_add);

void tcp_session_delete(struct sock *sk)
{
	struct tcp_session_info_hash *thash;
	struct tcp_session_entry *session;
	const struct inet_sock *inet;
	struct tcp_sock *tp;
	__u32 addr;
	u32 hash;

	tp = tcp_sk(sk);
	inet = inet_sk(sk);
	addr = (__force __u32)inet->inet_daddr;

	session = tp->session_info;

	if (!session)
		return;

	hash = hash_32((addr & TCP_SESSION_KEY_BITMASK),
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
	u32 hash = hash_32((addr & TCP_SESSION_KEY_BITMASK),
			   TCP_SESSION_HASH_BITS);
	struct tcp_session_info_hash *thash = &tcpsi_hash[hash];
	struct tcp_session_entry *session;
	struct tcp_session_info info;
	struct hlist_node *tmp;

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
	return tcp_session_hash_init();
}

static void __exit tcp_revsw_session_db_unregister(void)
{
	tcp_session_hash_cleanup();
}

module_init(tcp_revsw_session_db_register);
module_exit(tcp_revsw_session_db_unregister);

MODULE_AUTHOR("Tom Kavanagh");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TCP RevSw Session DB");

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
#include <linux/list.h>
#include <linux/spinlock.h>
#include <net/tcp.h>
#include "tcp_revsw_wrapper.h"
#include "tcp_revsw_session_db.h"

#define TCP_SESSION_BLOCK_SIZE	300

#define TCP_SESSION_HASH_BITS	16
#define TCP_SESSION_KEY_BITMASK	0xFFFF
#define TCP_SESSION_HASH_SIZE   (1 << TCP_SESSION_HASH_BITS)

/*
 * Data structure used to hold individual session
 * information
 */
struct tcp_session_entry {
	u32 cca_priv[TCP_CCA_PRIV_UINTS];
	struct tcp_session_info info;
	struct sock *sk;
	u32 total_retrans;
	u32 total_pkts;
	u32 rwin;
	u32 iseq;
	u8 initiated;
};

/*
 * Data structure used to hold information regarding
 * a particular window size's performance
 */
struct tcp_session_client_entry {
	u32 total_retrans;
	u32 total_pkts;
	u32 bw_high;
	u32 bw_low;
	u32 bw_last;
	u32 latency_high;
	u32 latency_low;
	u32 latency_last;
	u8 backoff_level;
};

/*
 * Data structure to be used by all hash lists
 */
struct tcp_session_hash_entry {
	struct hlist_node node;
	struct timeval tv;
	u32 addr;
	union {
		struct tcp_session_entry session;
		struct tcp_session_client_entry client[TCP_REVSW_RWIN_MAX];
	} hdata;
};

/*
 * Data structure to hold the pre-allocated
 * session info records
 */
struct tcp_session_container {
	struct hlist_head hlist;
	struct delayed_work work;
	spinlock_t lock;
	u16 entries;
};

/*
 * Data sructure to hold the subpar client list
 * and the required back off level
 */
struct tcp_session_client {
	struct hlist_head hlist;
	spinlock_t lock;
	u16 entries;
};

/*
 * Data structure to be used for the connection list
 */
struct tcp_session_connection {
	struct hlist_head hlist;
	spinlock_t lock;
	u16 entries;
};

/*
 * Data structure to be used for the session
 * info database hash table
 */
struct tcp_session_info_hash {
	spinlock_t lock;
	struct tcp_session_connection conn_list;
	struct tcp_session_client client_list;
};

static struct tcp_session_container tcpsi_container;

static struct tcp_session_info_hash *tcpsi_hash;

static struct tcp_session_info_ops *tcpsi_ops[TCP_REVSW_CCA_MAX];

static struct tcp_session_hash_entry *tcpsi_entry_blocks[1000];
static int tcpsi_entry_block_cnt;

/*
 * tcp_revsw_session_cleanup_hlist
 */
static void tcp_revsw_session_cleanup_hlist(struct hlist_head *hlist)
{
	struct tcp_session_hash_entry *entry;
	struct hlist_node *tnode;

	if (hlist_empty(hlist))
		return;

	hlist_for_each_entry_safe(entry, tnode, hlist, node) {
		hlist_del(&entry->node);
		kfree(entry);
	}
}

/*********************************************************************
 * TCP Session Info Container APIs
 *********************************************************************/

/*
 * tcp_revsw_session_allocate_block
 */
static void tcp_revsw_session_allocate_block(struct work_struct *work)
{
	struct tcp_session_hash_entry *entry;
	int i;

	entry = kzalloc(sizeof(*entry) * TCP_SESSION_BLOCK_SIZE, GFP_KERNEL);
	BUG_ON(!entry);

	spin_lock_bh(&tcpsi_container.lock);

	tcpsi_entry_blocks[tcpsi_entry_block_cnt++] = entry;

	pr_err("Revsw: Allocated new session block (%d)\n",
		   tcpsi_entry_block_cnt);
	
	for (i = 0; i < TCP_SESSION_BLOCK_SIZE; i++)
		hlist_add_head(&entry[i].node, &tcpsi_container.hlist);

	tcpsi_container.entries += TCP_SESSION_BLOCK_SIZE;

	tcp_revsw_sysctls.fc_entries += TCP_SESSION_BLOCK_SIZE;

	spin_unlock_bh(&tcpsi_container.lock);
}

/*
 * tcp_revsw_session_get_free_entry
 */
static struct tcp_session_hash_entry *tcp_revsw_session_get_free_entry(void)
{
	struct tcp_session_hash_entry *entry;

	spin_lock_bh(&tcpsi_container.lock);
	entry = hlist_entry_safe((tcpsi_container.hlist.first),
				 struct tcp_session_hash_entry, node);

	hlist_del(&entry->node);
	tcpsi_container.entries--;
	tcp_revsw_sysctls.fc_entries--;
	spin_unlock_bh(&tcpsi_container.lock);

	/*
	 * Need to make sure there is always a sufficient
	 * number of free entries in the container.  Need
	 * to keep at least 1/3 of the original block size.
	 */
	if (tcpsi_container.entries < (TCP_SESSION_BLOCK_SIZE / 3))
		schedule_delayed_work(&tcpsi_container.work, 0);

	return entry;
}

/**************** END TCP Session Info Container APIs ****************/

/*********************************************************************
 * TCP Session Info Hash APIs
 *********************************************************************/

/*
 * tcp_session_get_hash_from_entry
 */
static u32 tcp_session_get_hash_from_entry(struct tcp_session_hash_entry *entry)
{
	struct tcp_session_entry *session = &entry->hdata.session;
	const struct inet_sock *inet = inet_sk(session->sk);
	__u32 addr = (__force __u32)inet->inet_daddr;

	return hash_32((addr & TCP_SESSION_KEY_BITMASK), TCP_SESSION_HASH_BITS);
}

/*
 * tcp_session_get_hash_from_sk
 */
static u32 tcp_session_get_hash_from_sk(const struct sock *sk)
{
	const struct inet_sock *inet = inet_sk(sk);
	__u32 addr = (__force u32)(inet->inet_daddr);

	return hash_32((addr & TCP_SESSION_KEY_BITMASK), TCP_SESSION_HASH_BITS);
}

/*
 * tcp_session_add_connection_entry
 */
static void
tcp_session_add_connection_entry(struct tcp_session_hash_entry *entry)
{
	struct tcp_session_info_hash *thash;

	thash = &tcpsi_hash[tcp_session_get_hash_from_entry(entry)];

	spin_lock_bh(&thash->conn_list.lock);
	hlist_add_head(&entry->node, &thash->conn_list.hlist);
	thash->conn_list.entries++;
	tcp_revsw_sysctls.cn_entries++;
	spin_unlock_bh(&thash->conn_list.lock);
}

/*
 * tcp_session_delete_connection_entry
 */
static void
tcp_session_delete_connection_entry(struct tcp_session_hash_entry *entry)
{
	struct tcp_session_info_hash *thash;

	thash = &tcpsi_hash[tcp_session_get_hash_from_entry(entry)];

	spin_lock_bh(&thash->conn_list.lock);
	hlist_del(&entry->node);
	thash->conn_list.entries--;
	tcp_revsw_sysctls.cn_entries--;
	spin_unlock_bh(&thash->conn_list.lock);
}

/*
 * tcp_session_update_info
 */
static void tcp_session_update_info(u32 addr, struct tcp_session_entry *session,
				    struct tcp_session_client_entry *client)
{
	if (session->info.bandwidth > client->bw_high)
		client->bw_high = session->info.bandwidth;
	else if (session->info.bandwidth < client->bw_low)
		client->bw_low = session->info.bandwidth;

	client->bw_last = session->info.bandwidth;

	if (session->info.latency > client->latency_high)
		client->latency_high = session->info.latency;
	else if (session->info.latency < client->latency_low)
		client->latency_low = session->info.latency;

	client->latency_last = session->info.latency;

//	if (session->total_retrans == 0)
//		return;

	client->total_retrans += session->total_retrans;
	client->total_pkts += session->total_pkts;
	client->backoff_level = (client->total_retrans * 10) /
				 client->total_pkts;

	if (client->backoff_level)
		pr_err("%s: IP %pI4 backoff %d (%u %u - %u %u)\n", __func__, &addr,
			   client->backoff_level, session->total_retrans, session->total_pkts,
			   client->total_retrans, client->total_pkts);
}

/*
 * tcp_session_update_client
 */
static void tcp_session_update_client(struct tcp_session_hash_entry *entry)
{
	struct tcp_session_client_entry *client = NULL;
	struct tcp_session_hash_entry *temp;
	struct tcp_session_info_hash *thash;
	struct tcp_session_entry session;
	struct hlist_node *tnode;
	u32 backoff_level;
	u32 rwin;
	u32 addr;

	thash = &tcpsi_hash[tcp_session_get_hash_from_entry(entry)];

	spin_lock_bh(&thash->client_list.lock);

	backoff_level = TCP_REVSW_BKO_OK;

	rwin = entry->hdata.session.rwin;

	addr = entry->addr;

	hlist_for_each_entry_safe(temp, tnode, &thash->client_list.hlist,
				  node) {
		if (temp->addr == entry->addr) {
			client = &temp->hdata.client[entry->hdata.session.rwin];
			break;
		}
	}

	if (!client) {
		/*
		 * TEMPORARY Change
		 * If we have reached the maximum number of client records
		 * allowed on the system or the backoff level for this record
		 * is level than 2, do not create a new client record.
		 */
		backoff_level = (entry->hdata.session.total_retrans * 10) /
		entry->hdata.session.total_pkts;

		if ((tcp_revsw_sysctls.cl_entries >= tcp_revsw_sysctls.max_cl_entries) ||
		    (backoff_level < TCP_REVSW_BKO_LVL2)) {

			spin_unlock_bh(&thash->client_list.lock);

			memset(&(entry->hdata), 0, sizeof(entry->hdata));

			spin_lock_bh(&tcpsi_container.lock);
			hlist_add_head(&entry->node, &tcpsi_container.hlist);
			tcpsi_container.entries++;
			tcp_revsw_sysctls.fc_entries++;
			spin_unlock_bh(&tcpsi_container.lock);
		} else {
			memcpy(&session, &entry->hdata.session, sizeof(session));
			memset(&entry->hdata.session, 0, sizeof(session));

			client = &entry->hdata.client[entry->hdata.session.rwin];

			tcp_session_update_info(addr, &session, client);

			hlist_add_head(&entry->node, &thash->client_list.hlist);
			thash->client_list.entries++;
			tcp_revsw_sysctls.cl_entries++;
			spin_unlock_bh(&thash->client_list.lock);
		}
	} else {
		tcp_session_update_info(addr, &entry->hdata.session, client);

		spin_unlock_bh(&thash->client_list.lock);

		spin_lock_bh(&tcpsi_container.lock);
		hlist_add_head(&entry->node, &tcpsi_container.hlist);
		tcpsi_container.entries++;
		tcp_revsw_sysctls.fc_entries++;
		spin_unlock_bh(&tcpsi_container.lock);
	}
}

void tcp_session_update_initiator(const struct sock *sk, u8 initiated)
{
	struct tcp_revsw_cca_data *ca = inet_csk_ca(sk);

	if (ca->session)
		ca->session->initiated = initiated;
}

/*
 * tcp_session_get_act_cnt
 */
u16 tcp_session_get_act_cnt(const struct sock *sk)
{
	const struct inet_sock *inet = inet_sk(sk);
	__u32 addr = (__force u32)(inet->inet_daddr);
	struct tcp_session_hash_entry *entry;
	struct tcp_session_info_hash *thash;
	struct hlist_node *tnode;
	u16 cnt = 0;

	thash = &tcpsi_hash[tcp_session_get_hash_from_sk(sk)];

	spin_lock_bh(&thash->conn_list.lock);

	if (hlist_empty(&thash->conn_list.hlist))
		goto exit;

	hlist_for_each_entry_safe(entry, tnode, &thash->conn_list.hlist, node) {
		if (entry->addr == addr)
			cnt++;
	}

exit:
	spin_unlock_bh(&thash->conn_list.lock);

	return cnt;

}

/*
 * tcp_session_get_backoff_level
 */
u8 tcp_session_get_backoff_level(const struct sock *sk)
{
	struct tcp_revsw_cca_data *ca = inet_csk_ca(sk);
	const struct inet_sock *inet = inet_sk(sk);
	__u32 addr = (__force u32)(inet->inet_daddr);
	struct tcp_session_hash_entry *entry;
	struct tcp_session_info_hash *thash;
	u8 bko_level = TCP_REVSW_BKO_OK;
	struct hlist_node *tnode;

	thash = &tcpsi_hash[tcp_session_get_hash_from_sk(sk)];


	spin_lock_bh(&thash->client_list.lock);

	if (hlist_empty(&thash->client_list.hlist))
		goto exit;

	hlist_for_each_entry_safe(entry, tnode, &thash->client_list.hlist,
				  node) {
		if (entry->addr == addr) {
			bko_level =
			    entry->hdata.client[ca->session->rwin].backoff_level;
			break;
		}
	}

exit:
	spin_unlock_bh(&thash->client_list.lock);

	return bko_level;
}

/*
 * tcp_session_get_rwin
 */
u8 tcp_session_get_rwin(const struct sock *sk)
{
	struct tcp_revsw_cca_data *ca = inet_csk_ca(sk);

	if (!ca->session)
		return TCP_REVSW_RWIN_SM;

	if (ca->session->rwin == TCP_REVSW_RWIN_MAX)
		return TCP_REVSW_RWIN_SM;

	return ca->session->rwin;
}

/********************* TCP Session Info Hash APIs ********************/

/*********************************************************************
 * Userspace TCP Session Info APIs
 *********************************************************************/

/*
 * tcp_session_get_info
 */
int tcp_session_get_info(struct sock *sk, unsigned char *data, int *len)
{
	struct tcp_revsw_cca_data *ca = inet_csk_ca(sk);
	const struct inet_sock *inet = inet_sk(sk);
	__u32 addr = (__force u32)(inet->inet_daddr);
	struct tcp_session_client_entry *client;
	struct tcp_session_hash_entry *entry;
	struct tcp_session_info_hash *thash;
	struct tcp_session_info info;
	struct hlist_node *tnode;

	info.version = TCP_SESSION_INFO_VERSION;
	info.cookie = 0;
	info.latency = TCP_SESSION_DEFAULT_LATENCY;
	info.bandwidth = TCP_SESSION_DEFAULT_BW;

	thash = &tcpsi_hash[tcp_session_get_hash_from_sk(sk)];


	spin_lock_bh(&thash->client_list.lock);

	if (hlist_empty(&thash->client_list.hlist))
		goto exit;

	hlist_for_each_entry_safe(entry, tnode, &thash->client_list.hlist,
				  node) {
		if (entry->addr == addr) {
			client = &entry->hdata.client[ca->session->rwin];

			if (client->backoff_level == TCP_REVSW_BKO_OK) {
				info.latency = client->latency_high;
				info.bandwidth = client->bw_high;
			} else {
				info.latency = client->latency_low;
				info.bandwidth = client->bw_low;
			}

			break;
		}
	}

exit:
	spin_unlock_bh(&thash->client_list.lock);

	*len = min(*len, sizeof(info));
	memcpy(data, &info, *len);

	return 0;
}

/**************** END Userspace TCP Session Info APIs ****************/

/*********************************************************************
 * TCP Session Info OPs APIs
 *********************************************************************/

/*
 * tcp_session_register_ops
 */
void tcp_session_register_ops(u32 cca_type, struct tcp_session_info_ops *ops)
{
	if (cca_type < TCP_REVSW_CCA_MAX)
		tcpsi_ops[cca_type] = ops;
}

/*
 * tcp_session_deregister_ops
 */
void tcp_session_deregister_ops(u32 cca_type)
{
	if (cca_type < TCP_REVSW_CCA_MAX)
		tcpsi_ops[cca_type] = NULL;
}

/********************* TCP Session Info OPs APIs *********************/

/*********************************************************************
 * TCP Session APIs
 *********************************************************************/

/*
 * tcp_session_add
 */
void tcp_session_add(struct sock *sk, u8 cca_type)
{
	struct tcp_revsw_cca_data *ca = inet_csk_ca(sk);
	const struct inet_sock *inet = inet_sk(sk);
	struct tcp_session_hash_entry *entry;
	struct tcp_session_entry *session;
	struct tcp_sock *tp = tcp_sk(sk);
	__u32 addr = (__force __u32)inet->inet_daddr;

	entry = tcp_revsw_session_get_free_entry();
	BUG_ON(!entry);

	entry->addr = addr;
	session = &entry->hdata.session;
	session->sk = sk;
	session->info.latency = TCP_SESSION_DEFAULT_LATENCY;
	session->info.bandwidth = TCP_SESSION_DEFAULT_BW;
	session->info.cca_type = cca_type;

	tcp_session_add_connection_entry(entry);

	ca->session = session;

	if (tp->snd_wnd < REVSW_LARGE_RWND_SIZE)
		session->rwin = TCP_REVSW_RWIN_SM;
	else if (tp->snd_wnd < (REVSW_LARGE_RWND_SIZE * 2))
		session->rwin = TCP_REVSW_RWIN_MED;
	else
		session->rwin = TCP_REVSW_RWIN_LRG;

	session->iseq = tp->snd_nxt;

	if (tcpsi_ops[cca_type] && tcpsi_ops[cca_type]->session_add)
		tcpsi_ops[cca_type]->session_add(sk, &session->info);
}

/*
 * tcp_session_delete
 */
void tcp_session_delete(const struct sock *sk)
{
	struct tcp_revsw_cca_data *ca = inet_csk_ca(sk);
	struct tcp_session_hash_entry *entry;
	struct tcp_session_entry *session;
	struct tcp_sock *tp = tcp_sk(sk);
	u32 cca_type;
	u32 nbytes;

	/*
	 * It is possible that a socket was opened but never went through a 
	 * complete connection setup., the TCP socket session_info
	 * pointer will be NULL.  If this is the case simply return as 
	 * there is no information to update.
	 */
	if (!ca->session)
		return;

	session = ca->session;
	cca_type = session->info.cca_type;

	entry = container_of(session, struct tcp_session_hash_entry,
			     hdata.session);

	tcp_session_delete_connection_entry(entry);

	if (tcpsi_ops[cca_type] && tcpsi_ops[cca_type]->session_delete) {
		tcpsi_ops[cca_type]->session_delete(&session->info,
						(void *) &session->cca_priv[0]);
	}

	/*
	 * Update final stats
	 */
	session->total_retrans = tp->total_retrans;

	nbytes = tp->snd_nxt - session->iseq;

	if (nbytes > 1448)
		session->total_pkts = nbytes / 1448;
	else
		session->total_pkts = 1;

	if (session->initiated == TCP_SESSION_CLIENT_INITIATED)
		tcp_session_update_client(entry);
	else {
		memset(&(entry->hdata), 0, sizeof(entry->hdata));
		spin_lock_bh(&tcpsi_container.lock);
		hlist_add_head(&entry->node, &tcpsi_container.hlist);
		tcpsi_container.entries++;
		tcp_revsw_sysctls.fc_entries++;
		spin_unlock_bh(&tcpsi_container.lock);
	}
}

/*
 * tcp_session_get_info_ptr
 *
 * Returns a pointer to the tcp_session_info data structure inside of the
 * TCP socket session_info.
 */
struct tcp_session_info *tcp_session_get_info_ptr(struct sock *sk)
{
	struct tcp_revsw_cca_data *ca = inet_csk_ca(sk);

	BUG_ON(!ca->session);

	return &ca->session->info;
}

/*
 * tcp_session_get_cca_priv
 */
u32 *tcp_session_get_cca_priv(const struct sock *sk)
{
	struct tcp_revsw_cca_data *ca = inet_csk_ca(sk);

	BUG_ON(!ca->session);

	return ca->session->cca_priv;
}

/************************ END TCP Session APIs ***********************/

/*
 * tcp_revsw_session_db_register
 */
int __init tcp_revsw_session_db_init(void)
{
	struct tcp_session_hash_entry *entry;
	int i;

	tcpsi_entry_block_cnt = 0;

	tcp_revsw_sysctls.cl_entries = 0;
	tcp_revsw_sysctls.cn_entries = 0;
	tcp_revsw_sysctls.fc_entries = 0;

	/*
	 * Initial all lists, locks, etc for the tcpsi container hash
	 */
	INIT_HLIST_HEAD(&tcpsi_container.hlist);
	spin_lock_init(&tcpsi_container.lock);
	INIT_DELAYED_WORK(&tcpsi_container.work,
			  tcp_revsw_session_allocate_block);

	entry = kzalloc(sizeof(*entry) * TCP_SESSION_BLOCK_SIZE, GFP_KERNEL);
	BUG_ON(!entry);

	tcpsi_entry_blocks[tcpsi_entry_block_cnt++] = entry;

	for (i = 0; i < TCP_SESSION_BLOCK_SIZE; i++)
		hlist_add_head(&entry[i].node, &tcpsi_container.hlist);

	tcpsi_container.entries = TCP_SESSION_BLOCK_SIZE;
	tcp_revsw_sysctls.fc_entries = TCP_SESSION_BLOCK_SIZE;

	/*
	 * Initial all lists, locks, etc for the tcpsi hash
	 */
	tcpsi_hash = kzalloc(TCP_SESSION_HASH_SIZE * sizeof(*tcpsi_hash),
			     GFP_KERNEL);

	if (!tcpsi_hash)
		goto container_fail;

	spin_lock_init(&tcpsi_hash->lock);

	for (i = 0; i < TCP_SESSION_HASH_SIZE; i++) {
		spin_lock_init(&tcpsi_hash[i].conn_list.lock);
		INIT_HLIST_HEAD(&tcpsi_hash[i].conn_list.hlist);

		spin_lock_init(&tcpsi_hash[i].client_list.lock);
		INIT_HLIST_HEAD(&tcpsi_hash[i].client_list.hlist);
	}

	return 0;

container_fail:
	tcp_revsw_session_cleanup_hlist(&tcpsi_container.hlist);

	return -ENOMEM;
}

/*
 * tcp_revsw_session_db_unregister
 */
void __exit tcp_revsw_session_db_remove(void)
{
	int i;

	for (i = 0; i < tcpsi_entry_block_cnt; i++)
		kfree(tcpsi_entry_blocks[i]);

	kfree(tcpsi_hash);
}

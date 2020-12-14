/* SPDX-License-Identifier: LGPL-2.1-only */
/*
 * Copyright (c) 2007, 2008 Patrick McHardy <kaber@trash.net>
 */

#ifndef NETLINK_CHAIN_H_
#define NETLINK_CHAIN_H_

#include <netlink/netlink.h>
#include <netlink/netfilter/nft_table.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nl_sock;
struct nlmsghdr;

enum nftnl_chain_type {
  UNSPECIFIED,
  FILTER,
  NAT,
  ROUTE
};

struct nftnl_chain* nftnl_chain_alloc(void);
void nftnl_chain_put(struct nftnl_chain* chain);
int nftnl_chain_alloc_cache(struct nl_sock* sk, struct nl_cache** result);
struct nftnl_chain* nftnl_chain_get(struct nl_cache* cache, char* tableName, char* chainName);
char* nftnl_chain_flags2str(int flags, char* buf, size_t size);
//ATTRS
void nftnl_chain_set_table(struct nftnl_chain *chain, struct nftnl_table* table);
struct nftnl_table *nftnl_chain_get_table(struct nftnl_chain *chain);
int nftnl_chain_set_handle(struct nftnl_chain* chain, uint64_t handle);
uint64_t nftnl_chain_get_handle(struct nftnl_chain* chain);
int nftnl_chain_set_name(struct nftnl_chain* chain, const char* name);
char* nftnl_chain_get_name(struct nftnl_chain* chain);
int nftnl_chain_set_policy(struct nftnl_chain* chain, uint32_t policy);
uint32_t nftnl_chain_get_policy(struct nftnl_chain* chain);
int nftnl_chain_set_use(struct nftnl_chain* chain, uint32_t use);
uint32_t nftnl_chain_get_use(struct nftnl_chain* chain);
void nftnl_chain_set_type(struct nftnl_chain* chain, enum nftnl_chain_type type);
enum nftnl_chain_type nftnl_chain_get_type(struct nftnl_chain* chain);
//HOOK ATTRS
int nftnl_chain_hook_set_hooknum(struct nftnl_chain* chain, uint32_t hooknum);
uint32_t nftnl_chain_hook_get_hooknum(struct nftnl_chain* chain);
int nftnl_chain_hook_set_priority(struct nftnl_chain* chain, uint32_t priority);
uint32_t nftnl_chain_hook_get_priority(struct nftnl_chain* chain);
int nftnl_chain_hook_set_dev(struct nftnl_chain* chain, const char* dev);
char* nftnl_chain_hook_get_dev(struct nftnl_chain* chain);
//ADD REMOVE
int nftnl_chain_add(struct nl_sock* sk, struct nftnl_chain* chain, int flags);
int nftnl_chain_delete(struct nl_sock* sk, struct nftnl_chain* chain, int flags);



#ifdef __cplusplus
}
#endif

#endif


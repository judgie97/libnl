/* SPDX-License-Identifier: LGPL-2.1-only */
/*
 * Copyright (c) 2007, 2008 Patrick McHardy <kaber@trash.net>
 */

#ifndef NETLINK_TABLE_H_
#define NETLINK_TABLE_H_

#include <netlink/netlink.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nl_sock;
struct nlmsghdr;

struct nftnl_table *nftnl_table_alloc(void);
void nftnl_table_put(struct nftnl_table *table);
int nftnl_table_alloc_cache(struct nl_sock *sk, struct nl_cache **result);
struct nftnl_table *nftnl_table_get(struct nl_cache *cache, char *name);
int nftnl_table_build_add_request(struct nftnl_table *table, int flags, struct nl_msg **result);
int nftnl_table_add(struct nl_sock *sk, struct nftnl_table *table, int flags);
int nftnl_table_build_delete_request(struct nftnl_table *table, int flags, struct nl_msg **result);
int nftnl_table_delete(struct nl_sock *sk, struct nftnl_table *table, int flags);
char *nftnl_table_flags2str(int flags, char *buf, size_t size);
int nftnl_table_str2flags(const char *name);
//GETTERS / SETTERS
int nftnl_table_set_name(struct nftnl_table *table, const char *name);
char *nftnl_table_get_name(struct nftnl_table *table);
int nftnl_table_set_handle(struct nftnl_table *table, uint64_t handle);
uint64_t nftnl_table_get_handle(struct nftnl_table *table);
int nftnl_table_set_family(struct nftnl_table *table, uint32_t family);
uint32_t nftnl_table_get_family(struct nftnl_table *table);

#ifdef __cplusplus
}
#endif

#endif


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

struct nftnl_chain* nftnl_chain_alloc(void);
void nftnl_chain_put(struct nftnl_chain* chain);
int nftnl_chain_alloc_cache(struct nl_sock* sk, struct nl_cache** result);
struct nftnl_chain* nftnl_chain_get(struct nl_cache* cache, char* name);
char* nftnl_chain_flags2str(int flags, char* buf, size_t size);

#ifdef __cplusplus
}
#endif

#endif


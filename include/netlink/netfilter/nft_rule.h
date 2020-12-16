/* SPDX-License-Identifier: LGPL-2.1-only */
/*
 * Copyright (c) 2007, 2008 Patrick McHardy <kaber@trash.net>
 */

#ifndef NETLINK_RULE_H_
#define NETLINK_RULE_H_

#include <netlink/netlink.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nl_sock;
struct nlmsghdr;

struct nftnl_rule* nftnl_rule_alloc(void);
void nftnl_rule_put(struct nftnl_rule* rule);
int nftnl_rule_alloc_cache(struct nl_sock* sk, struct nl_cache** result);


#ifdef __cplusplus
}
#endif

#endif


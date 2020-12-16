/* SPDX-License-Identifier: LGPL-2.1-only */
/*
 * Copyright (c) 2007, 2008 Patrick McHardy <kaber@trash.net>
 */

#ifndef NETLINK_RULE_EXPRESSION_H_
#define NETLINK_RULE_EXPRESSION_H_

#include <netlink/netlink.h>

#ifdef __cplusplus
extern "C" {
#endif

struct nl_sock;
struct nlmsghdr;
struct nftnl_rule;
struct nftnl_expression_list;

void rule_delete_expression_list(struct nftnl_rule* rule);
void rule_expression_list_clone(struct nftnl_expression_list* dst, struct nftnl_expression_list* src);
void rule_expression_parse(struct nlattr* attrs, struct nftnl_expression_list* expressionList);

#ifdef __cplusplus
}
#endif

#endif


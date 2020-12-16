/* SPDX-License-Identifier: LGPL-2.1-only */
/*
 * Copyright (c) 2003-2012 Thomas Graf <tgraf@suug.ch>
 * Copyright (c) 2003-2006 Baruch Even <baruch@ev-en.org>
 * Copyright (c) 2003-2006 Mediatrix Telecom, inc. <ericb@mediatrix.com>
 */
#include <netlink-private/netlink.h>
#include <netlink/netlink.h>
#include <netlink/netfilter/nft_rule.h>
#include <netlink/netfilter/nft_chain.h>
#include <netlink/netfilter/nft_table.h>
#include <netlink-private/nft_util.h>
#include <netlink/netfilter/nft_rule_expression.h>
#include <netlink/utils.h>
#include <linux/netfilter/nf_tables.h>

//RULE DIRECT ATTRIBUTES
#define NFTRUL_ATTR_CHAIN  0x0001
#define NFTRUL_ATTR_HANDLE  0x0002
#define NFTRUL_ATTR_EXPRESSION   0x0004
#define NFTRUL_ATTR_COMPAT  0x0010
#define NFTRUL_ATTR_POSITION  0x0020
#define NFTRUL_ATTR_USERDATA  0x0040
#define NFTRUL_ATTR_ID  0x0080
#define NFTRUL_ATTR_POSITION_ID  0x0100

static struct nl_cache_ops nftnl_rule_ops;
static struct nl_object_ops rule_obj_ops;

static void rule_constructor(struct nl_object* obj)
{
  struct nftnl_rule* rule = nl_object_priv(obj);

  rule->a_chain = 0;
  rule->a_userdata[0] = 0;
  rule->a_expressions.a_count = 0;
  rule->a_expressions.a_list = 0;
}

static void rule_free_data(struct nl_object* obj)
{
  struct nftnl_rule* rule = nl_object_priv(obj);

  if(!rule)
    return;

  if((rule->ce_mask & NFTRUL_ATTR_CHAIN) && rule->a_chain)
    nftnl_chain_put(rule->a_chain);

  rule_delete_expression_list(rule);
  //if other objects get stored in rules they need to be put back into their caches so they can be deleted later
}

static int rule_clone(struct nl_object* _dst, struct nl_object* _src)
{
  struct nftnl_rule* dst = nl_object_priv(_dst);
  struct nftnl_rule* src = nl_object_priv(_src);

  dst->a_chain = 0;
  if(src->a_chain)
  {
    nl_object_get((struct nl_object*) src->a_chain);
    dst->a_chain = src->a_chain;
  }
  dst->a_handle = src->a_handle;
  rule_expression_list_clone(&(dst->a_expressions), &(src->a_expressions));
  dst->a_position = src->a_position;
  memcpy(dst->a_userdata, src->a_userdata, NFT_USERDATA_MAXLEN);
  dst->a_id = src->a_id;
  dst->a_posId = src->a_posId;
  dst->a_handleId = src->a_handleId;

  return 0;
}

static struct nla_policy rule_policy[NFTA_RULE_MAX + 1] = {
  [NFTA_RULE_TABLE]  = {.type = NLA_STRING, .maxlen = NFT_TABLE_MAXNAMELEN},
  [NFTA_RULE_CHAIN]  = {.type = NLA_STRING, .maxlen = NFT_CHAIN_MAXNAMELEN},
  [NFTA_RULE_HANDLE]  = {.type = NLA_U64},
  [NFTA_RULE_EXPRESSIONS]  = {.type = NLA_NESTED},
  [NFTA_RULE_COMPAT]  = {.type = NLA_NESTED},
  [NFTA_RULE_POSITION]  = {.type = NLA_U64},
  [NFTA_RULE_USERDATA]  = {.type = NLA_BINARY, .maxlen = NFT_USERDATA_MAXLEN},
  [NFTA_RULE_ID]  = {.type = NLA_U32},
  [NFTA_RULE_POSITION_ID]  = {.type = NLA_U32},
};
/*
static int build_chain_msg(struct nftnl_chain* tmpl, int cmd, int flags, struct nl_msg** result) //TODO
{
  struct nl_msg* msg;
  struct nfgenmsg cm = {
    .nfgen_family = nftnl_table_get_family(tmpl->a_table),
    .version = 0,
    .res_id = 0
  };

  msg = nlmsg_alloc_simple(cmd, flags);
  if(!msg)
    return -NLE_NOMEM;

  if(nlmsg_append(msg, &cm, sizeof(cm), NLMSG_ALIGNTO) < 0)
    goto nla_put_failure;

  if(tmpl->ce_mask & NFTCHA_ATTR_NAME)
    NLA_PUT_STRING(msg, NFTA_CHAIN_NAME, tmpl->a_name);

  if(tmpl->ce_mask & NFTCHA_ATTR_FLAGS)
    NLA_PUT_U32(msg, NFTA_CHAIN_FLAGS, tmpl->a_flags);
  else
    NLA_PUT_U32(msg, NFTA_CHAIN_FLAGS, 0);

  if(tmpl->ce_mask & NFTCHA_ATTR_USE)
    NLA_PUT_U32(msg, NFTA_CHAIN_USE, tmpl->a_use);

  if(tmpl->ce_mask & NFTCHA_ATTR_TYPE)
    NLA_PUT_STRING(msg, NFTA_CHAIN_TYPE, chain_types[tmpl->a_type]);

  if(tmpl->ce_mask & NFTCHA_ATTR_HANDLE)
    NLA_PUT_U64(msg, NFTA_CHAIN_HANDLE, tmpl->a_handle);

  if(tmpl->ce_mask & NFTCHA_ATTR_TABLE)
    NLA_PUT_STRING(msg, NFTA_CHAIN_TABLE, nftnl_table_get_name(tmpl->a_table));

  if(tmpl->ce_mask & NFTCHA_HOOK_ATTR_ANY)
  {
    struct nlattr* start = nla_nest_start(msg, NFTA_CHAIN_HOOK);

    if(tmpl->ce_mask & NFTCHA_HOOK_ATTR_HOOKNUM)
      NLA_PUT_U32(msg, NFTA_HOOK_HOOKNUM, tmpl->a_hook.a_hooknum);

    if(tmpl->ce_mask & NFTCHA_HOOK_ATTR_PRIORITY)
      NLA_PUT_U32(msg, NFTA_HOOK_PRIORITY, tmpl->a_hook.a_priority);

    if(tmpl->ce_mask & NFTCHA_HOOK_ATTR_DEV)
      NLA_PUT_STRING(msg, NFTA_HOOK_DEV, tmpl->a_hook.a_device);

    nla_nest_end(msg, start);
  }

  *result = msg;
  return 0;

nla_put_failure:
  nlmsg_free(msg);
  return -NLE_MSGSIZE;
}

int nftnl_chain_build_add_request(struct nftnl_chain* chain, int flags, struct nl_msg** result) //TODO
{
  uint32_t required = NFTCHA_ATTR_NAME | NFTCHA_ATTR_TABLE | NFTCHA_ATTR_TYPE | NFTCHA_HOOK_ATTR_HOOKNUM | NFTCHA_HOOK_ATTR_PRIORITY;

  if((chain->ce_mask & required) != required)
    return -NLE_MISSING_ATTR;

  return build_chain_msg(chain, NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_NEWCHAIN, NLM_F_CREATE | flags, result);
}

int nftnl_chain_build_del_request(struct nftnl_chain* chain, int flags, struct nl_msg** result) //TODO
{
  uint32_t required = NFTCHA_ATTR_NAME | NFTCHA_ATTR_TABLE;

  if((chain->ce_mask & required) != required)
    return -NLE_MISSING_ATTR;

  return build_chain_msg(chain, NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_DELCHAIN, NLM_F_CREATE | flags, result);
}

int nftnl_chain_add(struct nl_sock* sk, struct nftnl_chain* chain, int flags) //TODO
{
  struct nl_msg* msg;
  int err;

  if((err = nftnl_chain_build_add_request(chain, flags, &msg)) < 0)
    return err;

  err = nf_batch_send(sk, msg);
  nlmsg_free(msg);
  if(err < 0)
    return err;

  err = wait_for_ack(sk);
  sk->s_seq_expect++;
  return err;
}

int nftnl_chain_delete(struct nl_sock* sk, struct nftnl_chain* chain, int flags) //TODO
{
  struct nl_msg* msg;
  int err;

  if((err = nftnl_chain_build_del_request(chain, flags, &msg)) < 0)
    return err;

  err = nf_batch_send(sk, msg);
  nlmsg_free(msg);
  if(err < 0)
    return err;

  err = wait_for_ack(sk);
  sk->s_seq_expect++;
  return err;
}
*/
static int rule_msg_parser(struct nl_cache_ops* ops, struct sockaddr_nl* who,
                            struct nlmsghdr* nlh, struct nl_parser_param* pp)
{
  struct nftnl_rule* rule;
  struct nfgenmsg* hdr;
  struct nlattr* tb[__NFTA_RULE_MAX + 1];
  int err;
  struct nl_cache* chain_cache;

  rule = nftnl_rule_alloc();
  if(!rule)
    return -NLE_NOMEM;

  rule->ce_msgtype = nlh->nlmsg_type;

  err = nlmsg_parse(nlh, sizeof(*hdr), tb, __NFTA_RULE_MAX, rule_policy);
  if(err < 0)
    goto errout;

  if(tb[NFTA_RULE_TABLE] && tb[NFTA_RULE_CHAIN])
  {
    char table_buffer[NFT_TABLE_MAXNAMELEN];
    char chain_buffer[NFT_CHAIN_MAXNAMELEN];
    nla_strlcpy(table_buffer, tb[NFTA_RULE_TABLE], NFT_TABLE_MAXNAMELEN);
    nla_strlcpy(chain_buffer, tb[NFTA_RULE_CHAIN], NFT_CHAIN_MAXNAMELEN);

    if((chain_cache = __nl_cache_mngt_require("netfilter/chain")))
    {
      struct nftnl_chain* chain;

      if((chain = nftnl_chain_get(chain_cache, table_buffer, chain_buffer)))
      {
        rule->a_chain = chain;
        rule->ce_mask |= NFTRUL_ATTR_CHAIN;

        nftnl_chain_put(chain);
      }
    }
  }

  if(tb[NFTA_RULE_HANDLE])
  {
    rule->a_handle = swap_order(*(uint64_t*) nla_data(tb[NFTA_RULE_HANDLE]));
    rule->ce_mask |= NFTRUL_ATTR_HANDLE;
  }

  if(tb[NFTA_RULE_EXPRESSIONS])
  {
    rule_expression_parse(tb[NFTA_RULE_EXPRESSIONS], &(rule->a_expressions));
    rule->ce_mask |= NFTRUL_ATTR_EXPRESSION;
  }

  //TODO Compat processing

  if(tb[NFTA_RULE_USERDATA])
  {
    memcpy(rule->a_userdata, nla_data(tb[NFTA_RULE_USERDATA]), nla_len(tb[NFTA_RULE_USERDATA]));
    rule->ce_mask |= NFTRUL_ATTR_USERDATA;
  }

  if(tb[NFTA_RULE_ID])
  {
    rule->a_id = *(uint32_t*) nla_data(tb[NFTA_RULE_ID]);
    rule->ce_mask |= NFTRUL_ATTR_ID;
  }

  if(tb[NFTA_RULE_POSITION_ID])
  {
    rule->a_posId = *(uint32_t*) nla_data(tb[NFTA_RULE_POSITION]);
    rule->ce_mask |= NFTRUL_ATTR_POSITION_ID;
  }

  err = pp->pp_cb((struct nl_object*) rule, pp);
errout:
  nftnl_rule_put(rule);

  return err;
}

static int rule_request_update(struct nl_cache* cache, struct nl_sock* sk)
{
  return nl_rtgen_request(sk, NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_GETRULE, AF_UNSPEC, NLM_F_DUMP);
}

static void rule_dump_line(struct nl_object* obj, struct nl_dump_params* p) //TODO
{
  /*struct nftnl_table* table = (struct nftnl_table*) obj;
  char buf[128];

  if(table->ce_mask & NFTTAB_ATTR_NAME)
    nl_dump_line(p, "%s", table->a_label);
  else
    nl_dump_line(p, "none");

  if(table->ce_mask & NFTTAB_ATTR_FAMILY)
    nl_dump(p, " family %s", nl_af2str(table->a_family, buf, sizeof(buf)));

  nl_dump(p, "handle %d", table->a_handle);

  nftnl_table_flags2str(table->a_flags, buf, sizeof(buf));
  if(buf[0])
    nl_dump(p, " <%s>", buf);

  nl_dump(p, "\n");*/
}

static void rule_dump_details(struct nl_object* obj, struct nl_dump_params* p)
{
  rule_dump_line(obj, p);
}

static void rule_dump_stats(struct nl_object* obj, struct nl_dump_params* p)
{
  rule_dump_details(obj, p);
}

static uint32_t rule_id_attrs_get(struct nl_object* obj)
{
  return NFTRUL_ATTR_HANDLE | NFTRUL_ATTR_CHAIN;
}


static uint64_t rule_compare(struct nl_object* _a, struct nl_object* _b, uint64_t attrs, int flags)
{
  struct nftnl_rule* a = (struct nftnl_chain*) _a;
  struct nftnl_rule* b = (struct nftnl_chain*) _b;
  uint64_t diff = 0;

#define NFTRUL_DIFF(ATTR, EXPR) ATTR_DIFF(attrs, NFTRUL_ATTR_##ATTR, a, b, EXPR)

  //TODO ADD THE MISSING ATTRS
  /*
  diff |= NFTCHA_DIFF(HANDLE, a->a_handle != b->a_handle);
  diff |= NFTCHA_DIFF(NAME, strncmp(a->a_name, b->a_name, NFTCHANAMSIZ) != 0);
  diff |= NFTCHA_DIFF(POLICY, a->a_policy != b->a_policy);
  diff |= NFTCHA_DIFF(USE, a->a_use != b->a_use);
  diff |= NFTCHA_DIFF(TYPE, a->a_type == b->a_type);
  diff |= NFTCHA_DIFF(FLAGS, a->a_flags != b->a_flags);
  */

#undef NFTCHA_DIFF

  return diff;
}

static const struct trans_tbl rule_attrs[] = {
  __ADD(NFTRUL_ATTR_CHAIN, chain),
  __ADD(NFTRUL_ATTR_HANDLE, handle),
  __ADD(NFTRUL_ATTR_EXPRESSION, expression),
  __ADD(NFTRUL_ATTR_COMPAT, compat),
  __ADD(NFTRUL_ATTR_POSITION, position),
  __ADD(NFTRUL_ATTR_USERDATA, userdata),
  __ADD(NFTRUL_ATTR_ID, id),
  __ADD(NFTRUL_ATTR_POSITION_ID, position_id)
};

static char* rule_attrs2str(int attrs, char* buf, size_t len)
{
  return __flags2str(attrs, buf, len, rule_attrs,
                     ARRAY_SIZE(rule_attrs));
}

struct nftnl_rule* nftnl_rule_alloc(void)
{
  return (struct nftnl_rule*) nl_object_alloc(&rule_obj_ops);
}

void nftnl_rule_put(struct nftnl_rule* rule)
{
  nl_object_put((struct nl_object*) rule);
}

int nftnl_rule_alloc_cache(struct nl_sock* sk, struct nl_cache** result)
{
  return nl_cache_alloc_and_fill(&nftnl_rule_ops, sk, result);
}

/*
struct nftnl_rule* nftnl_rule_get(struct nl_cache* cache, char* name) //TODO Unclear what to do with this
{
  struct nftnl_chain* a;

  if(cache->c_ops != &nftnl_chain_ops)
    return NULL;

  nl_list_for_each_entry(a, &cache->c_items, ce_list)
  {
    if(strncmp(a->a_name, name, NFTCHANAMSIZ) == 0)
      return a;
  }

  return NULL;
}
*/
static struct nl_object_ops rule_obj_ops = {
  .oo_name    = "netfilter/rule",
  .oo_size    = sizeof(struct nftnl_rule),
  .oo_constructor    = rule_constructor,
  .oo_free_data    = rule_free_data,
  .oo_clone    = rule_clone,
  .oo_dump = {
    [NL_DUMP_LINE]  = rule_dump_line,
    [NL_DUMP_DETAILS]  = rule_dump_details,
    [NL_DUMP_STATS]  = rule_dump_stats,
  },
  .oo_compare    = rule_compare,
  .oo_attrs2str    = rule_attrs2str,
  .oo_id_attrs_get  = rule_id_attrs_get,
  .oo_id_attrs    = (NFTRUL_ATTR_HANDLE | NFTRUL_ATTR_CHAIN),
};

static struct nl_cache_ops nftnl_rule_ops = {
  .co_name    = "netfilter/rule",
  .co_hdrsize    = sizeof(struct nfgenmsg),
  .co_msgtypes    = {
    {NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_NEWRULE, NL_ACT_NEW, "new"},
    {NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_DELRULE, NL_ACT_DEL, "del"},
    {NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_GETRULE, NL_ACT_GET, "get"},
    END_OF_MSGTYPES_LIST,
  },
  .co_protocol    = NETLINK_NETFILTER,
  .co_request_update      = rule_request_update,
  .co_msg_parser          = rule_msg_parser,
  .co_obj_ops    = &rule_obj_ops,
};

static void __init

rule_init(void)
{
  nl_cache_mngt_register(&nftnl_rule_ops);
}

static void __exit

rule_exit(void)
{
  nl_cache_mngt_unregister(&nftnl_rule_ops);
}

/* SPDX-License-Identifier: LGPL-2.1-only */
/*
 * Copyright (c) 2003-2012 Thomas Graf <tgraf@suug.ch>
 * Copyright (c) 2003-2006 Baruch Even <baruch@ev-en.org>
 * Copyright (c) 2003-2006 Mediatrix Telecom, inc. <ericb@mediatrix.com>
 */

#include <netlink-private/netlink.h>
#include <netlink/netlink.h>
#include <netlink/netfilter/nft_table.h>
#include <netlink/utils.h>
#include <linux/netfilter/nf_tables.h>

#define NFTTAB_ATTR_NAME  0x0001
#define NFTTAB_ATTR_HANDLE  0x0002
#define NFTTAB_ATTR_FLAGS   0x0004
#define NFTTAB_ATTR_USE    0x0008
#define NFTTAB_ATTR_FAMILY  0x0010

static struct nl_cache_ops nftnl_table_ops;
static struct nl_object_ops table_obj_ops;

static void table_constructor(struct nl_object* obj)
{
  struct nftnl_table* table = nl_object_priv(obj);

  table->a_label[0] = 0;
  table->a_flags = 0;
  table->a_family = AF_UNSPEC;
}

static void table_free_data(struct nl_object* obj)
{
  struct nftnl_table* table = nl_object_priv(obj);

  if(!table)
    return;

  //if other objects get stored in tables they need to be put back into their caches so they can be deleted later
}

static int table_clone(struct nl_object* _dst, struct nl_object* _src)
{
  struct nftnl_table* dst = nl_object_priv(_dst);
  struct nftnl_table* src = nl_object_priv(_src);

  dst->a_family = src->a_family;
  dst->a_flags = src->a_flags;
  dst->a_use = src->a_use;
  dst->a_handle = src->a_handle;
  strncpy(dst->a_label, src->a_label, NFTTABNAMSIZ);

  return 0;
}

static struct nla_policy table_policy[IFA_MAX + 1] = {
  [NFTA_TABLE_NAME]  = {.type = NLA_STRING, .maxlen = NFTTABNAMSIZ},
  [NFTA_TABLE_FLAGS]  = {.type = NLA_U32},
  [NFTA_TABLE_USE]  = {.type = NLA_U32},
  [NFTA_TABLE_HANDLE]  = {.type = NLA_S64},
  [NFTA_TABLE_PAD]  = {.type = NLA_U32},
};

static int table_msg_parser(struct nl_cache_ops* ops, struct sockaddr_nl* who,
                            struct nlmsghdr* nlh, struct nl_parser_param* pp)
{
  struct nftnl_table* table;
  struct nfgenmsg* hdr;
  struct nlattr* tb[__NFTA_TABLE_MAX + 1];
  int err;

  table = nftnl_table_alloc();
  if(!table)
    return -NLE_NOMEM;

  table->ce_msgtype = nlh->nlmsg_type;

  err = nlmsg_parse(nlh, sizeof(*hdr), tb, __NFTA_TABLE_MAX, table_policy);
  if(err < 0)
    goto errout;

  hdr = nlmsg_data(nlh);
  table->a_family = hdr->nfgen_family;
  table->ce_mask = NFTTAB_ATTR_FAMILY;

  if(tb[NFTA_TABLE_NAME])
  {
    nla_strlcpy(table->a_label, tb[NFTA_TABLE_NAME], NFTTABNAMSIZ);
    table->ce_mask |= NFTTAB_ATTR_NAME;
  }

  if(tb[NFTA_TABLE_FLAGS])
  {
    table->a_flags = *(uint32_t*) nla_data(tb[NFTA_TABLE_FLAGS]);
    table->ce_mask |= NFTTAB_ATTR_FLAGS;
  }

  if(tb[NFTA_TABLE_USE])
  {
    table->a_use = *(uint32_t*) nla_data(tb[NFTA_TABLE_USE]);
    table->ce_mask |= NFTTAB_ATTR_USE;
  }

  if(tb[NFTA_TABLE_HANDLE])
  {
    table->a_handle = swap_order(*(uint64_t*) nla_data(tb[NFTA_TABLE_HANDLE]));
    table->ce_mask |= NFTTAB_ATTR_HANDLE;
  }

  err = pp->pp_cb((struct nl_object*) table, pp);
errout:
  nftnl_table_put(table);

  return err;

errout_nomem:
  err = -NLE_NOMEM;
  goto errout;
}

static int table_request_update(struct nl_cache* cache, struct nl_sock* sk)
{
  return nl_rtgen_request(sk, NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_GETTABLE, AF_UNSPEC, NLM_F_DUMP);
}

static void table_dump_line(struct nl_object* obj, struct nl_dump_params* p)
{
  struct nftnl_table* table = (struct nftnl_table*) obj;
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

  nl_dump(p, "\n");
}

static void table_dump_details(struct nl_object* obj, struct nl_dump_params* p)
{
  table_dump_line(obj, p);
}

static void table_dump_stats(struct nl_object* obj, struct nl_dump_params* p)
{
  table_dump_details(obj, p);
}

static uint32_t table_id_attrs_get(struct nl_object* obj)
{
  return NFTTAB_ATTR_HANDLE | NFTTAB_ATTR_FAMILY | NFTTAB_ATTR_NAME;

}

static uint64_t table_compare(struct nl_object* _a, struct nl_object* _b,
                              uint64_t attrs, int flags)
{
  struct nftnl_table* a = (struct nftnl_table*) _a;
  struct nftnl_table* b = (struct nftnl_table*) _b;
  uint64_t diff = 0;

#define NFTTAB_DIFF(ATTR, EXPR) ATTR_DIFF(attrs, NFTTAB_ATTR_##ATTR, a, b, EXPR)

  diff |= NFTTAB_DIFF(NAME, strncmp(a->a_label, b->a_label, NFTTABNAMSIZ) != 0);
  diff |= NFTTAB_DIFF(FAMILY, a->a_family != b->a_family);
  diff |= NFTTAB_DIFF(USE, a->a_use != b->a_use);
  diff |= NFTTAB_DIFF(HANDLE, a->a_handle != b->a_handle);
  diff |= NFTTAB_DIFF(FLAGS, a->a_flags != b->a_flags);

#undef NFTTAB_DIFF

  return diff;
}

static const struct trans_tbl table_attrs[] = {
  __ADD(NFTTAB_ATTR_FAMILY, family),
  __ADD(NFTTAB_ATTR_FLAGS, flags),
  __ADD(NFTTAB_ATTR_NAME, name),
  __ADD(NFTTAB_ATTR_USE, use),
  __ADD(NFTTAB_ATTR_HANDLE, handle)
};

static char* table_attrs2str(int attrs, char* buf, size_t len)
{
  return __flags2str(attrs, buf, len, table_attrs,
                     ARRAY_SIZE(table_attrs));
}

struct nftnl_table* nftnl_table_alloc(void)
{
  return (struct nftnl_table*) nl_object_alloc(&table_obj_ops);
}

void nftnl_table_put(struct nftnl_table* table)
{
  nl_object_put((struct nl_object*) table);
}

int nftnl_table_alloc_cache(struct nl_sock* sk, struct nl_cache** result)
{
  return nl_cache_alloc_and_fill(&nftnl_table_ops, sk, result);
}

struct nftnl_table* nftnl_table_get(struct nl_cache* cache, char* name)
{
  struct nftnl_table* a;

  if(cache->c_ops != &nftnl_table_ops)
    return NULL;

  nl_list_for_each_entry(a, &cache->c_items, ce_list)
  {
    if(strncmp(a->a_label, name, NFTTABNAMSIZ) == 0)
      nl_object_get((struct nl_object*) a);
      return a;
  }

  return NULL;
}

static int build_table_msg(struct nftnl_table* tmpl, int cmd, int flags, struct nl_msg** result)
{
  struct nl_msg* msg;
  struct nfgenmsg tm = {
    .nfgen_family = tmpl->a_family,
    .version = 0,
    .res_id = 0
  };

  msg = nlmsg_alloc_simple(cmd, flags);
  if(!msg)
    return -NLE_NOMEM;

  if(nlmsg_append(msg, &tm, sizeof(tm), NLMSG_ALIGNTO) < 0)
    goto nla_put_failure;

  if(tmpl->ce_mask & NFTTAB_ATTR_NAME)
    NLA_PUT_STRING(msg, NFTA_TABLE_NAME, tmpl->a_label);

  if(tmpl->ce_mask & NFTTAB_ATTR_FLAGS)
    NLA_PUT_U32(msg, NFTA_TABLE_FLAGS, tmpl->a_flags);
  else
    NLA_PUT_U32(msg, NFTA_TABLE_FLAGS, 0);

  if(tmpl->ce_mask & NFTTAB_ATTR_USE)
    NLA_PUT_U32(msg, NFTA_TABLE_USE, tmpl->a_use);

  if(tmpl->ce_mask & NFTTAB_ATTR_HANDLE)
    NLA_PUT_U64(msg, NFTA_TABLE_HANDLE, tmpl->a_handle);

  *result = msg;
  return 0;

nla_put_failure:
  nlmsg_free(msg);
  return -NLE_MSGSIZE;
}

int nftnl_table_build_add_request(struct nftnl_table* table, int flags, struct nl_msg** result)
{
  uint32_t required = NFTTAB_ATTR_NAME | NFTTAB_ATTR_FAMILY;

  if((table->ce_mask & required) != required || table->a_family == AF_UNSPEC)
    return -NLE_MISSING_ATTR;

  return build_table_msg(table, NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_NEWTABLE, NLM_F_CREATE | flags, result);
}

int nftnl_table_add(struct nl_sock* sk, struct nftnl_table* table, int flags)
{
  struct nl_msg* msg;
  int err;

  if((err = nftnl_table_build_add_request(table, flags, &msg)) < 0)
    return err;

  err = nf_batch_send(sk, msg);
  nlmsg_free(msg);
  if(err < 0)
    return err;

  err = wait_for_ack(sk);
  sk->s_seq_expect++;
  return err;
}

int nftnl_table_build_delete_request(struct nftnl_table* table, int flags, struct nl_msg** result)
{
  uint32_t required = NFTTAB_ATTR_FAMILY | NFTTAB_ATTR_NAME;

  if((table->ce_mask & required) != required)
    return -NLE_MISSING_ATTR;

  return build_table_msg(table, NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_DELTABLE, flags, result);
}

int nftnl_table_delete(struct nl_sock* sk, struct nftnl_table* table, int flags)
{
  struct nl_msg* msg;
  int err;

  if((err = nftnl_table_build_delete_request(table, flags, &msg)) < 0)
    return err;

  err = nf_batch_send(sk, msg);
  nlmsg_free(msg);
  if(err < 0)
    return err;

  err = wait_for_ack(sk);
  sk->s_seq_expect++;
  return err;
}

int nftnl_table_set_name(struct nftnl_table* table, const char* name)
{
  if(strlen(name) > sizeof(table->a_label) - 1)
    return -NLE_RANGE;

  strcpy(table->a_label, name);
  table->ce_mask |= NFTTAB_ATTR_NAME;

  return 0;
}

char* nftnl_table_get_name(struct nftnl_table* table)
{
  if(table->ce_mask & NFTTAB_ATTR_NAME)
    return table->a_label;
  else
    return NULL;
}

int nftnl_table_set_handle(struct nftnl_table* table, uint64_t handle)
{
  table->a_handle = handle;
  table->ce_mask |= NFTTAB_ATTR_HANDLE;

  return 0;
}

uint64_t nftnl_table_get_handle(struct nftnl_table* table)
{
  if(table->ce_mask & NFTTAB_ATTR_HANDLE)
    return table->a_handle;
  else
    return NULL;
}

int nftnl_table_set_family(struct nftnl_table* table, uint32_t family)
{
  table->a_family = family;
  table->ce_mask |= NFTTAB_ATTR_FAMILY;

  return 0;
}

uint32_t nftnl_table_get_family(struct nftnl_table* table)
{
  if(table->ce_mask & NFTTAB_ATTR_FAMILY)
    return table->a_family;
  else
    return NULL;
}

static const struct trans_tbl table_flags[] = {
};

char* nftnl_table_flags2str(int flags, char* buf, size_t size)
{
  return __flags2str(flags, buf, size, table_flags, ARRAY_SIZE(table_flags));
}

int rtnl_addr_str2flags(const char* name)
{
  return __str2flags(name, table_flags, ARRAY_SIZE(table_flags));
}


static struct nl_object_ops table_obj_ops = {
  .oo_name    = "netfilter/table",
  .oo_size    = sizeof(struct nftnl_table),
  .oo_constructor    = table_constructor,
  .oo_free_data    = table_free_data,
  .oo_clone    = table_clone,
  .oo_dump = {
    [NL_DUMP_LINE]  = table_dump_line,
    [NL_DUMP_DETAILS]  = table_dump_details,
    [NL_DUMP_STATS]  = table_dump_stats,
  },
  .oo_compare    = table_compare,
  .oo_attrs2str    = table_attrs2str,
  .oo_id_attrs_get  = table_id_attrs_get,
  .oo_id_attrs    = (NFTTAB_ATTR_HANDLE | NFTTAB_ATTR_FAMILY | NFTTAB_ATTR_NAME),
};

static struct nl_cache_ops nftnl_table_ops = {
  .co_name    = "netfilter/table",
  .co_hdrsize    = sizeof(struct nfgenmsg),
  .co_msgtypes    = {
    {NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_NEWTABLE, NL_ACT_NEW, "new"},
    {NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_DELTABLE, NL_ACT_DEL, "del"},
    {NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_GETTABLE, NL_ACT_GET, "get"},
    END_OF_MSGTYPES_LIST,
  },
  .co_protocol    = NETLINK_NETFILTER,
  .co_request_update      = table_request_update,
  .co_msg_parser          = table_msg_parser,
  .co_obj_ops    = &table_obj_ops,
};

static void __init

table_init(void)
{
  nl_cache_mngt_register(&nftnl_table_ops);
}

static void __exit

table_exit(void)
{
  nl_cache_mngt_unregister(&nftnl_table_ops);
}
/* SPDX-License-Identifier: LGPL-2.1-only */
/*
 * Copyright (c) 2003-2012 Thomas Graf <tgraf@suug.ch>
 * Copyright (c) 2003-2006 Baruch Even <baruch@ev-en.org>
 * Copyright (c) 2003-2006 Mediatrix Telecom, inc. <ericb@mediatrix.com>
 */


//TODO This should be a code example of adding a new chain using this shit
/**
 * @ingroup rtnl
 * @defgroup rtaddr Addresses
 * @brief
 *
 * @note The maximum size of an address label is IFNAMSIZ.
 *
 * @note The address may not contain a prefix length if the peer address
 *       has been specified already.
 *
 * @par 1) Address Addition
 * @code
 * // Allocate an empty address object to be filled out with the attributes
 * // of the new address.
 * struct rtnl_addr *addr = rtnl_addr_alloc();
 *
 * // Fill out the mandatory attributes of the new address. Setting the
 * // local address will automatically set the address family and the
 * // prefix length to the correct values.
 * rtnl_addr_set_ifindex(addr, ifindex);
 * rtnl_addr_set_local(addr, local_addr);
 *
 * // The label of the address can be specified, currently only supported
 * // by IPv4 and DECnet.
 * rtnl_addr_set_label(addr, "mylabel");
 *
 * // The peer address can be specified if necessary, in either case a peer
 * // address will be sent to the kernel in order to fullfil the interface
 * // requirements. If none is set, it will equal the local address.
 * // Note: Real peer addresses are only supported by IPv4 for now.
 * rtnl_addr_set_peer(addr, peer_addr);
 *
 * // In case you want to have the address have a scope other than global
 * // it may be overwritten using rtnl_addr_set_scope(). The scope currently
 * // cannot be set for IPv6 addresses.
 * rtnl_addr_set_scope(addr, rtnl_str2scope("site"));
 *
 * // Broadcast address may be specified using the relevant
 * // functions, the address family will be verified if one of the other
 * // addresses has been set already. Currently only works for IPv4.
 * rtnl_addr_set_broadcast(addr, broadcast_addr);
 *
 * // Build the netlink message and send it to the kernel, the operation will
 * // block until the operation has been completed. Alternatively the required
 * // netlink message can be built using rtnl_addr_build_add_request() to be
 * // sent out using nl_send_auto_complete().
 * rtnl_addr_add(sk, addr, 0);
 *
 * // Free the memory
 * rtnl_addr_put(addr);
 * @endcode
 *
 * @par 2) Address Deletion
 * @code
 * // Allocate an empty address object to be filled out with the attributes
 * // matching the address to be deleted. Alternatively a fully equipped
 * // address object out of a cache can be used instead.
 * struct rtnl_addr *addr = rtnl_addr_alloc();
 *
 * // The only mandatory parameter besides the address family is the interface
 * // index the address is on, i.e. leaving out all other parameters will
 * // result in all addresses of the specified address family interface tuple
 * // to be deleted.
 * rtnl_addr_set_ifindex(addr, ifindex);
 *
 * // Specyfing the address family manually is only required if neither the
 * // local nor peer address have been specified.
 * rtnl_addr_set_family(addr, AF_INET);
 *
 * // Specyfing the local address is optional but the best choice to delete
 * // specific addresses.
 * rtnl_addr_set_local(addr, local_addr);
 *
 * // The label of the address can be specified, currently only supported
 * // by IPv4 and DECnet.
 * rtnl_addr_set_label(addr, "mylabel");
 *
 * // The peer address can be specified if necessary, in either case a peer
 * // address will be sent to the kernel in order to fullfil the interface
 * // requirements. If none is set, it will equal the local address.
 * // Note: Real peer addresses are only supported by IPv4 for now.
 * rtnl_addr_set_peer(addr, peer_addr);
 *
 * // Build the netlink message and send it to the kernel, the operation will
 * // block until the operation has been completed. Alternatively the required
 * // netlink message can be built using rtnl_addr_build_delete_request()
 * // to be sent out using nl_send_auto_complete().
 * rtnl_addr_delete(sk, addr, 0);
 *
 * // Free the memory
 * rtnl_addr_put(addr);
 * @endcode
 * @{
 */

#include <netlink-private/netlink.h>
#include <netlink/netlink.h>
#include <netlink/netfilter/nft_chain.h>
#include <netlink/netfilter/nft_table.h>
#include <netlink/utils.h>
#include <linux/netfilter/nf_tables.h>

/** @cond SKIP */
//CHAIN DIRECT ATTRIBUTES
#define NFTCHA_ATTR_TABLE  0x0001
#define NFTCHA_ATTR_HANDLE  0x0002
#define NFTCHA_ATTR_NAME   0x0004
#define NFTCHA_ATTR_POLICY  0x0010
#define NFTCHA_ATTR_USE  0x0020
#define NFTCHA_ATTR_TYPE  0x0040
#define NFTCHA_ATTR_COUNTERS  0x0080
#define NFTCHA_ATTR_FLAGS  0x0100
//CHAIN HOOK ATTRIBUTES
#define NFTCHA_HOOK_ATTR_HOOKNUM 0x0200
#define NFTCHA_HOOK_ATTR_PRIORITY 0x0400
#define NFTCHA_HOOK_ATTR_DEV 0x0800
#define NFTCHA_HOOK_ATTR_ANY NFTCHA_HOOK_ATTR_HOOKNUM | NFTCHA_HOOK_ATTR_PRIORITY | NFTCHA_HOOK_ATTR_DEV

static struct nl_cache_ops nftnl_chain_ops;
static struct nl_object_ops chain_obj_ops;

/** @endcond */

char chain_types[][8] = {"", "filter", "route", "nat"};

static void chain_constructor(struct nl_object* obj)
{
  struct nftnl_chain* chain = nl_object_priv(obj);

  chain->a_name[0] = 0;
  chain->a_type = UNSPECIFIED;
  chain->a_flags = 0;
}

static void chain_free_data(struct nl_object* obj)
{
  struct nftnl_chain* chain = nl_object_priv(obj);

  if(!chain)
    return;

  //if other objects get stored in chains they need to be put back into their caches so they can be deleted later
}

static int chain_clone(struct nl_object* _dst, struct nl_object* _src)
{
  struct nftnl_chain* dst = nl_object_priv(_dst);
  struct nftnl_chain* src = nl_object_priv(_src);

  //TODO ADD MISSNG ATTRS HERE
  dst->a_table = 0;
  if(src->a_table)
  {
    nl_object_get((struct nl_object*) src->a_table);
    dst->a_table = src->a_table;
  }
  dst->a_handle = src->a_handle;
  dst->a_policy = src->a_policy;
  dst->a_use = src->a_use;
  dst->a_flags = src->a_flags;
  strncpy(dst->a_name, src->a_name, NFTCHANAMSIZ);
  dst->a_type = src->a_type;

  return 0;
}

static struct nla_policy chain_policy[NFTA_CHAIN_MAX + 1] = {
  [NFTA_CHAIN_TABLE]  = {.type = NLA_STRING, .maxlen = NFTTABNAMSIZ},
  [NFTA_CHAIN_HANDLE]  = {.type = NLA_U64},
  [NFTA_CHAIN_NAME]  = {.type = NLA_STRING, .maxlen = NFTCHANAMSIZ},
  [NFTA_CHAIN_HOOK]  = {.type = NLA_NESTED},
  [NFTA_CHAIN_POLICY]  = {.type = NLA_U32},
  [NFTA_CHAIN_USE]  = {.type = NLA_U32},
  [NFTA_CHAIN_TYPE]  = {.type = NLA_NUL_STRING},
  [NFTA_CHAIN_COUNTERS]  = {.type = NLA_NESTED},
  [NFTA_CHAIN_FLAGS]  = {.type = NLA_U32},
};

static struct nla_policy hook_info_policy[NFTA_HOOK_MAX + 1] = {
  [NFTA_HOOK_HOOKNUM] = {.type = NLA_U32},
  [NFTA_HOOK_PRIORITY] = {.type = NLA_U32},
  [NFTA_HOOK_DEV] = {.type = NLA_STRING},
  [NFTA_HOOK_DEVS] = {.type = NLA_NESTED},
};

static int build_chain_msg(struct nftnl_chain* tmpl, int cmd, int flags, struct nl_msg** result)
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

int nftnl_chain_build_add_request(struct nftnl_chain* chain, int flags, struct nl_msg** result)
{
  uint32_t required = NFTCHA_ATTR_NAME | NFTCHA_ATTR_TABLE | NFTCHA_ATTR_TYPE | NFTCHA_HOOK_ATTR_HOOKNUM | NFTCHA_HOOK_ATTR_PRIORITY;

  if((chain->ce_mask & required) != required)
    return -NLE_MISSING_ATTR;

  return build_chain_msg(chain, NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_NEWCHAIN, NLM_F_CREATE | flags, result);
}

int nftnl_chain_add(struct nl_sock* sk, struct nftnl_chain* chain, int flags)
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

static int chain_msg_parser(struct nl_cache_ops* ops, struct sockaddr_nl* who,
                            struct nlmsghdr* nlh, struct nl_parser_param* pp)
{
  struct nftnl_chain* chain;
  struct nfgenmsg* hdr;
  struct nlattr* tb[__NFTA_CHAIN_MAX + 1];
  int err;
  struct nl_cache* table_cache;

  chain = nftnl_chain_alloc();
  if(!chain)
    return -NLE_NOMEM;

  chain->ce_msgtype = nlh->nlmsg_type;

  err = nlmsg_parse(nlh, sizeof(*hdr), tb, __NFTA_CHAIN_MAX, chain_policy);
  if(err < 0)
    goto errout;

  if(tb[NFTA_CHAIN_TABLE])
  {
    char buffer[NFTTABNAMSIZ];
    nla_strlcpy(buffer, tb[NFTA_CHAIN_TABLE], NFTTABNAMSIZ);

    if((table_cache = __nl_cache_mngt_require("netfilter/table")))
    {
      struct nftnl_table* table;

      if((table = nftnl_table_get(table_cache, buffer)))
      {
        chain->a_table = table;
        chain->ce_mask |= NFTCHA_ATTR_TABLE;

        nftnl_table_put(table);
      }
    }
  }

  if(tb[NFTA_CHAIN_HANDLE])
  {
    chain->a_handle = swap_order(*(uint64_t*) nla_data(tb[NFTA_CHAIN_HANDLE]));
    chain->ce_mask |= NFTCHA_ATTR_HANDLE;
  }

  if(tb[NFTA_CHAIN_NAME])
  {
    nla_strlcpy(chain->a_name, tb[NFTA_CHAIN_NAME], NFTCHANAMSIZ);
    chain->ce_mask |= NFTCHA_ATTR_NAME;
  }

  if(tb[NFTA_CHAIN_HOOK])
  {
    struct nlattr* hi[NFTA_HOOK_MAX + 1];
    err = nla_parse_nested(hi, NFTA_HOOK_MAX, tb[NFTA_CHAIN_HOOK], hook_info_policy);

    if(err < 0)
      return err;

    if(hi[NFTA_HOOK_HOOKNUM])
    {
      chain->a_hook.a_hooknum = *(uint32_t*) nla_data(hi[NFTA_HOOK_HOOKNUM]);
      chain->ce_mask |= NFTCHA_HOOK_ATTR_HOOKNUM;
    }

    if(hi[NFTA_HOOK_PRIORITY])
    {
      chain->a_hook.a_priority = *(uint32_t*) nla_data(hi[NFTA_HOOK_PRIORITY]);
      chain->ce_mask |= NFTCHA_HOOK_ATTR_PRIORITY;
    }

    if(hi[NFTA_HOOK_DEV])
    {
      nla_strlcpy(chain->a_hook.a_device, hi[NFTA_HOOK_DEV], IFNAMSIZ);
      chain->ce_mask |= NFTCHA_HOOK_ATTR_DEV;
    }
  }

  if(tb[NFTA_CHAIN_POLICY])
  {
    chain->a_policy = *(uint32_t*) nla_data(tb[NFTA_CHAIN_POLICY]);
    chain->ce_mask |= NFTCHA_ATTR_POLICY;
  }

  if(tb[NFTA_CHAIN_USE])
  {
    chain->a_use = *(uint32_t*) nla_data(tb[NFTA_CHAIN_USE]);
    chain->ce_mask |= NFTCHA_ATTR_USE;
  }

  chain->a_type = UNSPECIFIED;
  if(tb[NFTA_CHAIN_TYPE])
  {
    char buffer[NFTCHATYPSIZ];
    nla_strlcpy(buffer, tb[NFTA_CHAIN_TYPE], NFTCHATYPSIZ);

#define COMPARE(X, Y) if(!strncmp(buffer, #X, NFTCHATYPSIZ)){chain->a_type = Y;}
    COMPARE(filter, FILTER)
    COMPARE(nat, NAT)
    COMPARE(route, ROUTE)
#undef COMPARE

    if(chain->a_type == UNSPECIFIED)
      goto errout;
    chain->ce_mask |= NFTCHA_ATTR_TYPE;
  }

  if(tb[NFTA_CHAIN_COUNTERS])
  {
    //TODO STORE THESE SOMEWHERE
  }

  if(tb[NFTA_CHAIN_FLAGS])
  {
    chain->a_flags = *(uint32_t*) nla_data(tb[NFTA_CHAIN_FLAGS]);
    chain->ce_mask |= NFTCHA_ATTR_FLAGS;
  }

  err = pp->pp_cb((struct nl_object*) chain, pp);
errout:
  nftnl_chain_put(chain);

  return err;
}

static int chain_request_update(struct nl_cache* cache, struct nl_sock* sk)
{
  return nl_rtgen_request(sk, NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_GETCHAIN, AF_UNSPEC, NLM_F_DUMP);
}

static void chain_dump_line(struct nl_object* obj, struct nl_dump_params* p) //TODO
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

static void chain_dump_details(struct nl_object* obj, struct nl_dump_params* p)
{
  chain_dump_line(obj, p);
}

static void chain_dump_stats(struct nl_object* obj, struct nl_dump_params* p)
{
  chain_dump_details(obj, p);
}

static uint32_t chain_id_attrs_get(struct nl_object* obj)
{
  return NFTCHA_ATTR_HANDLE | NFTCHA_ATTR_TABLE | NFTCHA_ATTR_NAME;
}

static uint64_t chain_compare(struct nl_object* _a, struct nl_object* _b,
                              uint64_t attrs, int flags)
{
  struct nftnl_chain* a = (struct nftnl_chain*) _a;
  struct nftnl_chain* b = (struct nftnl_chain*) _b;
  uint64_t diff = 0;

#define NFTCHA_DIFF(ATTR, EXPR) ATTR_DIFF(attrs, NFTCHA_ATTR_##ATTR, a, b, EXPR)

  //TODO ADD THE MISSING ATTRS
  diff |= NFTCHA_DIFF(HANDLE, a->a_handle != b->a_handle);
  diff |= NFTCHA_DIFF(NAME, strncmp(a->a_name, b->a_name, NFTCHANAMSIZ) != 0);
  diff |= NFTCHA_DIFF(POLICY, a->a_policy != b->a_policy);
  diff |= NFTCHA_DIFF(USE, a->a_use != b->a_use);
  diff |= NFTCHA_DIFF(TYPE, a->a_type == b->a_type);
  diff |= NFTCHA_DIFF(FLAGS, a->a_flags != b->a_flags);

#undef NFTCHA_DIFF

  return diff;
}

static const struct trans_tbl chain_attrs[] = {
  __ADD(NFTCHA_ATTR_TABLE, table),
  __ADD(NFTCHA_ATTR_HANDLE, handle),
  __ADD(NFTCHA_ATTR_NAME, name),
  __ADD(NFTCHA_ATTR_POLICY, policy),
  __ADD(NFTCHA_ATTR_USE, use),
  __ADD(NFTCHA_ATTR_TYPE, type),
  __ADD(NFTCHA_ATTR_COUNTERS, counters),
  __ADD(NFTCHA_ATTR_FLAGS, flags)
  //TODO Add hooks here
};

static char* chain_attrs2str(int attrs, char* buf, size_t len)
{
  return __flags2str(attrs, buf, len, chain_attrs,
                     ARRAY_SIZE(chain_attrs));
}

/**
 * @name Allocation/Freeing
 * @{
 */

struct nftnl_chain* nftnl_chain_alloc(void)
{
  return (struct nftnl_chain*) nl_object_alloc(&chain_obj_ops);
}

void nftnl_chain_put(struct nftnl_chain* chain)
{
  nl_object_put((struct nl_object*) chain);
}

/** @} */

/**
 * @name Cache Management
 * @{
 */

int nftnl_chain_alloc_cache(struct nl_sock* sk, struct nl_cache** result)
{
  return nl_cache_alloc_and_fill(&nftnl_chain_ops, sk, result);
}

/**
 * Search address in cache
 * @arg cache		Address cache
 * @arg ifindex		Interface index of address
 * @arg addr		Local address part
 *
 * Searches address cache previously allocated with rtnl_addr_alloc_cache()
 * for an address with a matching local address.
 *
 * The reference counter is incremented before returning the address, therefore
 * the reference must be given back with rtnl_addr_put() after usage.
 *
 * @return Address object or NULL if no match was found.
 */
struct nftnl_chain* nftnl_chain_get(struct nl_cache* cache, char* name)
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

/** @} */

/*static int build_table_msg(struct nftnl_table* tmpl, int cmd, int flags, struct nl_msg** result) //TODO
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

/**
 * @name Addition
 * @{
 */

/**
 * Build netlink request message to request addition of new address
 * @arg addr		Address object representing the new address.
 * @arg flags		Additional netlink message flags.
 * @arg result		Pointer to store resulting message.
 *
 * Builds a new netlink message requesting the addition of a new
 * address. The netlink message header isn't fully equipped with
 * all relevant fields and must thus be sent out via nl_send_auto_complete()
 * or supplemented as needed.
 *
 * Minimal required attributes:
 *   - interface index (rtnl_addr_set_ifindex())
 *   - local address (rtnl_addr_set_local())
 *
 * The scope will default to universe except for loopback addresses in
 * which case a host scope is used if not specified otherwise.
 *
 * @note Free the memory after usage using nlmsg_free().
 *
 * @return 0 on success or a negative error code.
 */
/*int nftnl_table_build_add_request(struct nftnl_table* table, int flags, struct nl_msg** result) //TODO
{
  uint32_t required = NFTTAB_ATTR_NAME | NFTTAB_ATTR_FAMILY;

  if((table->ce_mask & required) != required || table->a_family == AF_UNSPEC)
    return -NLE_MISSING_ATTR;

  return build_table_msg(table, NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_NEWTABLE, NLM_F_CREATE | flags, result);
}


static int nf_batch_send(struct nl_sock* sk, struct nl_msg* msg) //TODO
{
  //HEADER FOR BOTH
  struct nfgenmsg hdr = {
    .nfgen_family = AF_UNSPEC,
    .version = 0,
    .res_id = 10
  };
  int err;

  //MAKE THE START MESSAGE
  struct nl_msg* start;
  start = nlmsg_alloc_simple(NFNL_MSG_BATCH_BEGIN, 0);
  if(!start)
    return -NLE_NOMEM;

  if(nlmsg_append(start, &hdr, sizeof(hdr), NLMSG_ALIGNTO) < 0)
  {
    err = -NLE_NOMEM;
    goto err_freestart;
  }
  //MAKE THE END MESSAGE
  struct nl_msg* end;
  end = nlmsg_alloc_simple(NFNL_MSG_BATCH_END, 0);
  if(!end)
  {
    err = -NLE_NOMEM;
    goto err_freestart;
  }

  if(nlmsg_append(end, &hdr, sizeof(hdr), NLMSG_ALIGNTO) < 0)
  {
    err = -NLE_NOMEM;
    goto err_freeend;
  }

  //PUT THE SEQUENCE IDS IN THE MESSAGES
  nl_complete_msg(sk, start);
  nl_complete_msg(sk, msg);
  nl_complete_msg(sk, end);

  //STORE THE LENGTH OF THE FIRST MESSAGE BECAUSE APPEND WILL CHANGE IT
  int startLength = nlmsg_hdr(start)->nlmsg_len;

  //APPEND THE MESSAGE TO THE START
  if(nlmsg_append(start, nlmsg_hdr(msg), nlmsg_hdr(msg)->nlmsg_len, NLMSG_ALIGNTO) < 0)
  {
    err = -NLE_NOMEM;
    goto err_freeend;
  }
  //APPEND THE MESSAGE TO THE END
  if(nlmsg_append(start, nlmsg_hdr(end), nlmsg_hdr(end)->nlmsg_len, NLMSG_ALIGNTO) < 0)
  {
    err = -NLE_NOMEM;
    goto err_freeend;
  }

  //THIS LENGTH IS THE ACTUAL SIZE TO SEND (ALL MESSAGES)
  int finalLength = nlmsg_hdr(start)->nlmsg_len;
  //PUT THE LENGTH OF THE FIRST MESSAGE BACK INTO THE FIRST MESSAGE
  nlmsg_hdr(start)->nlmsg_len = startLength;
  sk->s_seq_expect++;
  err = nl_send_arb(sk, start, finalLength);

err_freeend:
  nlmsg_free(end);
err_freestart:
  nlmsg_free(start);
  if(err < 0)
    return err;

  return 0;
}


/**
 * Request addition of new address
 * @arg sk		Netlink socket.
 * @arg addr		Address object representing the new address.
 * @arg flags		Additional netlink message flags.
 *
 * Builds a netlink message by calling rtnl_addr_build_add_request(),
 * sends the request to the kernel and waits for the next ACK to be
 * received and thus blocks until the request has been fullfilled.
 *
 * @see rtnl_addr_build_add_request()
 *
 * @return 0 on sucess or a negative error if an error occured.
 */
/*int nftnl_table_add(struct nl_sock* sk, struct nftnl_table* table, int flags) //TODO
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

/** @} */

/**
 * @name Deletion
 * @{
 */

/**
 * Build a netlink request message to request deletion of an address
 * @arg addr		Address object to be deleteted.
 * @arg flags		Additional netlink message flags.
 * @arg result		Pointer to store resulting message.
 *
 * Builds a new netlink message requesting a deletion of an address.
 * The netlink message header isn't fully equipped with all relevant
 * fields and must thus be sent out via nl_send_auto_complete()
 * or supplemented as needed.
 *
 * Minimal required attributes:
 *   - interface index (rtnl_addr_set_ifindex())
 *   - address family (rtnl_addr_set_family())
 *
 * Optional attributes:
 *   - local address (rtnl_addr_set_local())
 *   - label (rtnl_addr_set_label(), IPv4/DECnet only)
 *   - peer address (rtnl_addr_set_peer(), IPv4 only)
 *
 * @note Free the memory after usage using nlmsg_free().
 *
 * @return 0 on success or a negative error code.
 */
/*int nftnl_table_build_delete_request(struct nftnl_table* table, int flags, struct nl_msg** result) //TODO
{
  uint32_t required = NFTTAB_ATTR_FAMILY | NFTTAB_ATTR_NAME;

  if((table->ce_mask & required) != required)
    return -NLE_MISSING_ATTR;

  return build_table_msg(table, NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_DELTABLE, flags, result);
}

/**
 * Request deletion of an address
 * @arg sk		Netlink socket.
 * @arg addr		Address object to be deleted.
 * @arg flags		Additional netlink message flags.
 *
 * Builds a netlink message by calling rtnl_addr_build_delete_request(),
 * sends the request to the kernel and waits for the next ACK to be
 * received and thus blocks until the request has been fullfilled.
 *
 * @see rtnl_addr_build_delete_request();
 *
 * @return 0 on sucess or a negative error if an error occured.
 */
/*int nftnl_table_delete(struct nl_sock* sk, struct nftnl_table* table, int flags)//TODO
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

/** @} */

/**
 * @name Attributes
 * @{
 */

void nftnl_chain_set_table(struct nftnl_chain* chain, struct nftnl_table* table)
{
  nftnl_chain_put(chain->a_table);

  if(!table)
    return;

  nl_object_get(OBJ_CAST(table));
  chain->a_table = table;
  chain->ce_mask |= NFTCHA_ATTR_TABLE;
}

struct nftnl_table* nftnl_chain_get_table(struct nftnl_chain* chain)
{
  if(chain->a_table)
  {
    nl_object_get(OBJ_CAST(chain->a_table));
    return chain->a_table;
  }
  return NULL;
}

int nftnl_chain_set_handle(struct nftnl_chain* chain, uint64_t handle)
{
  chain->a_handle = handle;
  chain->ce_mask |= NFTCHA_ATTR_HANDLE;

  return 0;
}

uint64_t nftnl_chain_get_handle(struct nftnl_chain* chain)
{
  if(chain->ce_mask & NFTCHA_ATTR_HANDLE)
    return chain->a_handle;
  else
    return NULL;
}

int nftnl_chain_set_name(struct nftnl_chain* chain, const char* name)
{
  if(strlen(name) > sizeof(chain->a_name) - 1)
    return -NLE_RANGE;

  strcpy(chain->a_name, name);
  chain->ce_mask |= NFTCHA_ATTR_NAME;

  return 0;
}

char* nftnl_chain_get_name(struct nftnl_chain* chain)
{
  if(chain->ce_mask & NFTCHA_ATTR_NAME)
    return chain->a_name;
  else
    return NULL;
}

int nftnl_chain_set_policy(struct nftnl_chain* chain, uint32_t policy)
{
  chain->a_policy = policy;
  chain->ce_mask |= NFTCHA_ATTR_POLICY;

  return 0;
}

uint32_t nftnl_chain_get_policy(struct nftnl_chain* chain)
{
  if(chain->ce_mask & NFTCHA_ATTR_POLICY)
    return chain->a_policy;
  else
    return NULL;
}

int nftnl_chain_set_use(struct nftnl_chain* chain, uint32_t use)
{
  chain->a_use = use;
  chain->ce_mask |= NFTCHA_ATTR_USE;

  return 0;
}

uint32_t nftnl_chain_get_use(struct nftnl_chain* chain)
{
  if(chain->ce_mask & NFTCHA_ATTR_USE)
    return chain->a_use;
  else
    return NULL;
}

void nftnl_chain_set_type(struct nftnl_chain* chain, enum nftnl_chain_type type)
{
  chain->a_type = type;
  chain->ce_mask |= NFTCHA_ATTR_TYPE;
}

enum nftnl_chain_type nftnl_chain_get_type(struct nftnl_chain* chain)
{
  if(chain->ce_mask & NFTCHA_ATTR_TYPE)
    return chain->a_type;
  return UNSPECIFIED;
}


int nftnl_chain_hook_set_hooknum(struct nftnl_chain* chain, uint32_t hooknum)
{
  chain->a_hook.a_hooknum = hooknum;
  chain->ce_mask |= NFTCHA_HOOK_ATTR_HOOKNUM;

  return 0;
}

uint32_t nftnl_chain_hook_get_hooknum(struct nftnl_chain* chain)
{
  if(chain->ce_mask & NFTCHA_HOOK_ATTR_HOOKNUM)
    return chain->a_hook.a_hooknum;
  else
    return NULL;
}

int nftnl_chain_hook_set_priority(struct nftnl_chain* chain, uint32_t priority)
{
  chain->a_hook.a_priority = priority;
  chain->ce_mask |= NFTCHA_HOOK_ATTR_PRIORITY;

  return 0;
}

uint32_t nftnl_chain_hook_get_priority(struct nftnl_chain* chain)
{
  if(chain->ce_mask & NFTCHA_HOOK_ATTR_PRIORITY)
    return chain->a_hook.a_priority;
  else
    return NULL;
}

int nftnl_chain_hook_set_dev(struct nftnl_chain* chain, const char* dev)
{
  if(strlen(dev) > sizeof(chain->a_hook.a_device) - 1)
    return -NLE_RANGE;

  strcpy(chain->a_hook.a_device, dev);
  chain->ce_mask |= NFTCHA_HOOK_ATTR_DEV;

  return 0;
}

char* nftnl_chain_hook_get_dev(struct nftnl_chain* chain)
{
  if(chain->ce_mask & NFTCHA_HOOK_ATTR_DEV)
    return chain->a_hook.a_device;
  else
    return NULL;
}

#define NFTCHA_HOOK_ATTR_DEV 0x0800

/** @} */

/**
 * @name Flags Translations
 * @{
 */

static const struct trans_tbl chain_flags[] = {
};

char* nftnl_chain_flags2str(int flags, char* buf, size_t size)
{
  return __flags2str(flags, buf, size, chain_flags, ARRAY_SIZE(chain_flags));
}

/** @} */

static struct nl_object_ops chain_obj_ops = {
  .oo_name    = "netfilter/chain",
  .oo_size    = sizeof(struct nftnl_chain),
  .oo_constructor    = chain_constructor,
  .oo_free_data    = chain_free_data,
  .oo_clone    = chain_clone,
  .oo_dump = {
    [NL_DUMP_LINE]  = chain_dump_line,
    [NL_DUMP_DETAILS]  = chain_dump_details,
    [NL_DUMP_STATS]  = chain_dump_stats,
  },
  .oo_compare    = chain_compare,
  .oo_attrs2str    = chain_attrs2str,
  .oo_id_attrs_get  = chain_id_attrs_get,
  .oo_id_attrs    = (NFTCHA_ATTR_HANDLE | NFTCHA_ATTR_TABLE | NFTCHA_ATTR_NAME),
};

static struct nl_cache_ops nftnl_chain_ops = {
  .co_name    = "netfilter/chain",
  .co_hdrsize    = sizeof(struct nfgenmsg),
  .co_msgtypes    = {
    {NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_NEWCHAIN, NL_ACT_NEW, "new"},
    {NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_DELCHAIN, NL_ACT_DEL, "del"},
    {NFNL_SUBSYS_NFTABLES << 8 | NFT_MSG_GETCHAIN, NL_ACT_GET, "get"},
    END_OF_MSGTYPES_LIST,
  },
  .co_protocol    = NETLINK_NETFILTER,
  .co_request_update      = chain_request_update,
  .co_msg_parser          = chain_msg_parser,
  .co_obj_ops    = &chain_obj_ops,
};

static void __init

chain_init(void)
{
  nl_cache_mngt_register(&nftnl_chain_ops);
}

static void __exit

chain_exit(void)
{
  nl_cache_mngt_unregister(&nftnl_chain_ops);
}

/** @} */

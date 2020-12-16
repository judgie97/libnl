/* SPDX-License-Identifier: LGPL-2.1-only */
/*
 * Copyright (c) 2003-2012 Thomas Graf <tgraf@suug.ch>
 * Copyright (c) 2003-2006 Baruch Even <baruch@ev-en.org>
 * Copyright (c) 2003-2006 Mediatrix Telecom, inc. <ericb@mediatrix.com>
 */
#include <netlink-private/netlink.h>
#include <netlink/netlink.h>
#include <netlink/netfilter/nft_chain.h>
#include <netlink/netfilter/nft_table.h>
#include <netlink/netfilter/nft_rule.h>
#include <netlink/utils.h>
#include <linux/netfilter/nf_tables.h>
#include <stdlib.h>

void rule_delete_expression_list(struct nftnl_rule* rule)
{
  rule->a_expressions.a_count = 0;
  if(rule->a_expressions.a_list)
  {
    free(rule->a_expressions.a_list);
    rule->a_expressions.a_list = 0;
  }
}

void rule_expression_list_clone(struct nftnl_expression_list* dst, struct nftnl_expression_list* src)
{
  dst->a_count = src->a_count;
  dst->a_list = malloc(dst->a_count * sizeof(struct nftnl_expression));
  memcpy(dst->a_list, dst->a_list, dst->a_count * sizeof(struct nftnl_expression));
}

static struct nla_policy expression_policy[NFTA_EXPR_MAX + 1] = {
  [NFTA_EXPR_NAME]  = {.type = NLA_STRING, .maxlen = NFT_NAME_MAXNAMELEN},
  [NFTA_EXPR_DATA]  = {.type = NLA_NESTED},
};

static struct nla_policy payload_policy[NFTA_PAYLOAD_MAX + 1] = {
  [NFTA_PAYLOAD_DREG]  = {.type = NLA_U32},
  [NFTA_PAYLOAD_BASE]  = {.type = NLA_U32},
  [NFTA_PAYLOAD_OFFSET]  = {.type = NLA_U32},
  [NFTA_PAYLOAD_LEN]  = {.type = NLA_U32},
  [NFTA_PAYLOAD_SREG]  = {.type = NLA_U32},
  [NFTA_PAYLOAD_CSUM_TYPE]  = {.type = NLA_U32},
  [NFTA_PAYLOAD_CSUM_OFFSET]  = {.type = NLA_U32},
  [NFTA_PAYLOAD_CSUM_FLAGS]  = {.type = NLA_U32}
};

int rule_expression_parse(struct nlattr* attrs, struct nftnl_expression_list* expressionList)
{
  expressionList->a_count = 0;
  uint16_t attrLen = attrs->nla_len;
  int err;

  unsigned int curr = 4;
  while(curr < attrLen)
  {
    struct nlattr* currentAttr = (struct nlattr*)(((uint8_t*)attrs) + curr);
    curr += currentAttr->nla_len;
    expressionList->a_count++;
  }

  expressionList->a_list = calloc(expressionList->a_count * sizeof(struct nftnl_expression));
  curr = 4;
  for(uint32_t i = 0; i < expressionList; i++)
  {
    struct nlattr* currentAttr = (struct nlattr*)(((uint8_t*)attrs) + curr);
    struct nlattr* exprAttr[NFTA_EXPR_MAX + 1];
    err = nla_parse_nested(exprAttr, NFTA_EXPR_MAX, currentAttr, expression_policy);
    if(err < 0)
      goto errout;

    char buffer[NFT_NAME_MAXNAMELEN];
    if(!exprAttr[NFTA_EXPR_NAME])
    {
      err = -1;
      goto errout;
    }
    nla_strlcpy(buffer, exprAttr[NFTA_EXPR_NAME], NFT_NAME_MAXLEN);
    if(strncmp(buffer, "payload", NFT_MAX_NAMELEN))
    {
      struct nlattr* payloadAttr[NFTA_PAYLOAD_MAX + 1];
      err = nla_parse_nested(payloadAttr, NFTA_PAYLOAD_MAX, exprAttr[NFTA_EXPR_DATA], payload_policy);
      if(err < 0)
        goto errout;

      enum nftnl_match_property property = NFNTL_MATCH_PROP_UNSPEC;

      unsigned int base = -1;
      unsigned int offset = -1;
      unsigned int length = -1;

      if(payloadAttr[NFTA_PAYLOAD_BASE])
        base = *(uint32_t*)nla_data(payloadAttr[NFTA_PAYLOAD_BASE]);

      if(payloadAttr[NFTA_PAYLOAD_OFFSET])
        offset = *(uint32_t*)nla_data(payloadAttr[NFTA_PAYLOAD_OFFSET]);

      if(payloadAttr[NFTA_PAYLOAD_LEN])
        length = *(uint32_t*)nla_data(payloadAttr[NFTA_PAYLOAD_LEN]);

      //12 is the offset of the source ip in the ipv4 header
      //4 is the length of the source address in the ipv4 header
      if(length == 4 && base == NFT_PAYLOAD_NETWORK_HEADER && offset == 12)
        property = NFTNL_MATCH_PROP_IP_SADDR;
      //16 is the offset of the destination address in the ipv4 header
      if(length == 4 && base == NFT_PAYLOAD_NETWORK_HEADER && offset == 16)
        property = NFTNL_MATCH_PROP_IP_DADDR;

      if(property == NFTNL_MATCH_PROP_UNSPEC)
      {
        printf("Unknown property combination base: %d  offset: %d length: %d\n", base, offset, length);
        err = -1;
        goto errout;
      }

      expressionList->a_list[i].a_type = NFTNL_EXPR_MATCH;
      expressionList->a_list[i].a_statement.a_match.a_property = property;

      //TODO WORK OUT HOW TO SHRINK THE EXPRESSION LIST TO NOT INCLUDE COMPARES BECAUSE THEY GO IN THE ACTUAL EXPRESSION
    }

  }


errout:
  free(a_expressions.a_list);
  a_expressions.a_list = 0;
  return err;
}
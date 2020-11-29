#ifndef LIBNL_NFT_UTIL_H
#define LIBNL_NFT_UTIL_H

#include <netlink/utils.h>

struct nl_sock;
struct nl_msg;

int nf_batch_send(struct nl_sock* sk, struct nl_msg* msg);
uint64_t swap_order(uint64_t original);

#endif
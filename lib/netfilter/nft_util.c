#include <netlink-private/nft_util.h>
#include <linux/socket.h>
#include <linux/netfilter/nfnetlink.h>
#include <netlink-private/netlink.h>


int nf_batch_send(struct nl_sock* sk, struct nl_msg* msg)
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

uint64_t swap_order(uint64_t original)
{
  uint8_t* bytes = (uint8_t * ) & original;
  uint64_t output = 0;

  uint8_t* newBytes = (uint8_t * ) & output;
  for(int i = 0; i < 8; i++)
    newBytes[i] = bytes[7 - i];
  return output;
}
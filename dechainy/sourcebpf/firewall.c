// Copyright 2020 DeChainy
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Value of eBPF maps, representing an array of rules (each bit is a rule)
struct rules {
  u64 rule_words[RULE_IDS_WORDS_PER_ENTRY];
} __attribute__((packed));

// Maps matching a specific value (lpm_key specified in helpers.h)
BPF_F_TABLE("lpm_trie", struct lpm_key, struct rules, IPV4_SRC, RULE_IDS_MAX_ENTRY, BPF_F_NO_PREALLOC);
BPF_F_TABLE("lpm_trie", struct lpm_key, struct rules, IPV4_DST, RULE_IDS_MAX_ENTRY, BPF_F_NO_PREALLOC);
BPF_TABLE("hash", __be16, struct rules, PORT_SRC, RULE_IDS_MAX_ENTRY);
BPF_TABLE("hash", __be16, struct rules, PORT_DST, RULE_IDS_MAX_ENTRY);
BPF_TABLE("hash", __u8,  struct rules, IP_PROTO, RULE_IDS_MAX_ENTRY);
BPF_TABLE("hash", __u8, struct rules, TCP_FLAGS, RULE_IDS_MAX_ENTRY);

// Maps containing wildcards, when no value is matched
BPF_TABLE("array", int, struct rules, IPV4_SRC_WILDCARDS, 1);
BPF_TABLE("array", int, struct rules, IPV4_DST_WILDCARDS, 1);
BPF_TABLE("array", int, struct rules, PORT_SRC_WILDCARDS, 1);
BPF_TABLE("array", int, struct rules, PORT_DST_WILDCARDS, 1);
BPF_TABLE("array", int, struct rules, IP_PROTO_WILDCARDS, 1);
BPF_TABLE("array", int, struct rules, TCP_FLAGS_WILDCARDS, 1);

// Map of actions for each rule, need an array since there
// could be more than 2 action for each rule (otherwise could
// have implemented one like wildcards)
BPF_TABLE("array", int, __u8, ACTIONS, MAX_RULES);

static __always_inline
int handler(struct CTXTYPE *ctx, struct pkt_metadata *md) {
  void *data = (void *) (long) ctx->data;
  void *data_end = (void *) (long) ctx->data_end;

  /*Parsing L2*/
  struct eth_hdr *ethernet = data;
  if (data + sizeof(*ethernet) > data_end)
    return PASS;

  if (ethernet->proto != bpf_htons(ETH_P_IP))
    return PASS;

  /*Parsing L3*/
  struct iphdr *ip = data + sizeof(struct eth_hdr);
  if (data + sizeof(struct eth_hdr) + sizeof(*ip) > data_end)
    return PASS;

  if ((int) ip->version != 4)
    return PASS;

  uint8_t ip_header_len = ip->ihl << 2, flags = 0;
  __be16 sport = 0, dport = 0;

  /*Parsing L4*/
  switch (ip->protocol) {
  case IPPROTO_TCP: {
    /*Parsing L4 TCP*/
    struct tcphdr *tcp = data + sizeof(struct eth_hdr) + ip_header_len;
    if ((void *) tcp + sizeof(*tcp) > data_end) {
      return PASS;
    }
    sport = tcp->source;
    dport = tcp->dest;
    flags = (tcp->cwr << 7) | (tcp->ece << 6) | (tcp->urg << 5) | (tcp->ack << 4) | (tcp->psh << 3)| (tcp->rst << 2) | (tcp->syn << 1) | tcp->fin;
    break;
  }
  case IPPROTO_UDP: {
    /*Parsing L4 UDP*/
    struct udphdr *udp = data + sizeof(struct eth_hdr) + ip_header_len;
    if ((void *) udp + sizeof(*udp) > data_end) {
      return PASS;
    }
    sport = udp->source;
    dport = udp->dest;
    break;
  }
  /*Ignored protocol*/
  default : {
    break;
  }
  }

  struct lpm_key src_key = {.netmask_len=32, .ip=ip->saddr};
  struct lpm_key dst_key = {.netmask_len=32, .ip=ip->daddr};

  // Try to lookup with retrieved values
  struct rules *ipv4_src_res = IPV4_SRC.lookup(&src_key);
  struct rules *ipv4_dst_res = IPV4_DST.lookup(&dst_key);
  struct rules *ip_proto_res = IP_PROTO.lookup(&(ip->protocol));
  struct rules *port_src_res = PORT_SRC.lookup(&sport);
  struct rules *port_dst_res = PORT_DST.lookup(&dport);
  struct rules *tcp_flags_res = TCP_FLAGS.lookup(&flags);

  // If no matches then end
  if(!ipv4_src_res && !ipv4_dst_res && !port_src_res && !port_dst_res && !ip_proto_res && !tcp_flags_res) {
    return PASS;
  }

  // Lookup wildcards, because at least 1 value matched
  int zero = 0;
  if(!ipv4_src_res)  ipv4_src_res = IPV4_SRC_WILDCARDS.lookup(&zero);
  if(!ipv4_dst_res)  ipv4_dst_res = IPV4_DST_WILDCARDS.lookup(&zero);
  if(!port_src_res)  port_src_res = PORT_SRC_WILDCARDS.lookup(&zero);
  if(!port_dst_res)  port_dst_res = PORT_DST_WILDCARDS.lookup(&zero);
  if(!ip_proto_res)  ip_proto_res = IP_PROTO_WILDCARDS.lookup(&zero);
  if(!tcp_flags_res) tcp_flags_res = TCP_FLAGS_WILDCARDS.lookup(&zero);

  // If also some wildcard has failed, end
  if(!ipv4_src_res || !ipv4_dst_res || !port_src_res || !port_dst_res || !ip_proto_res || !tcp_flags_res) {
    return PASS;
  }

  // Iterate through all words, finding the 1st one with "1" set
  for (u64 word = 0; word < RULE_IDS_WORDS_PER_ENTRY; word++) {
    u64 word_match = ipv4_src_res->rule_words[word] & ipv4_dst_res->rule_words[word] & port_src_res->rule_words[word]
      & port_dst_res->rule_words[word] & ip_proto_res->rule_words[word] & tcp_flags_res->rule_words[word];
    if (word_match) {
      // Computing the ID
      int rule_id = (word * 64) + first_bit_set_pos(word_match);
      dp_log(DEBUG, "Matched RuleId: %d", rule_id);
      uint8_t *action = ACTIONS.lookup(&rule_id);
      if (!action) {
        return FW_ACTION_DEFAULT;
      }
      return *action;
    }
  }

  return PASS;
}
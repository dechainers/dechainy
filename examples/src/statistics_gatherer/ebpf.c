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

/*Protocol types according to the standard*/
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

/* Number of max TCP session tracked */
#define N_SESSION 10000

/*Features to be exported*/
struct features {
    //Real features
    uint64_t n_packets;                             // Number of packets on one direction
    uint64_t n_packets_reverse;                     // Number of packets on opposite direction
    uint64_t n_bytes;                               // Total bytes on one direction
    uint64_t n_bytes_reverse;                       // Total bytes on opposite direction
    uint64_t start_timestamp;                       // Connection begin timestamp
    uint64_t alive_timestamp;                       // Last message received timestamp
    uint32_t server_ip;                             // The IP of the server
    uint32_t method;                                // The method used to determine the server
} __attribute__((packed));

/*Session identifier*/
struct session_key {
    __be32 saddr;                                   //IP source address
    __be32 daddr;                                   //IP dest address
    __be16 sport;                                   //Source port
    __be16 dport;                                   //Dest port
    __u8   proto;                                   //Protocol ID
} __attribute__((packed));

/*Tracked session map*/
#if PTYPE == 0
BPF_TABLE_SHARED("percpu_hash", struct session_key, struct features, SESSIONS_TRACKED_CRYPTO, N_SESSION)__attribute((SWAP));
#else
BPF_TABLE("extern", struct session_key, struct features, SESSIONS_TRACKED_CRYPTO, N_SESSION)__attribute((SWAP));
#endif

/*Method to return the session identifier, with the lower IP as first member*/
static __always_inline struct session_key get_key(uint32_t ip_a, uint32_t ip_b, uint16_t port_a, uint16_t port_b, uint8_t proto) {
  if(ip_a < ip_b) {
    struct session_key ret = {.saddr=ip_a, .daddr=ip_b, .sport=port_a, .dport=port_b, .proto=proto};
    return ret;
  } else {
    struct session_key ret = {.saddr=ip_b, .daddr=ip_a, .sport=port_b, .dport=port_a, .proto=proto};
    return ret;
  }
}

/*Method to determine which member of the communication is the server*/
static __always_inline __be32 heuristic_server(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint32_t *method, struct tcphdr *tcp) {
  /*If Syn, then srcIp is the server*/
  if(tcp && tcp->syn) {/*If source port < 1024, then srcIp is the server*/
    *method = 1;
    return tcp->ack? src_ip : dst_ip;
  }
  dst_port = bpf_htons(dst_port);
  /*If destination port < 1024, then dstIp is the server*/
  if(dst_port < 1024) {
    *method = 2;
    return dst_ip;
  }
  src_port = bpf_htons(src_port);
  /*If source port < 1024, then srcIp is the server*/
  if(src_port < 1024) {
    *method = 2;
    return src_ip;
  }
  *method = 3;
  /*Otherwise, the lowest port is the server*/
  return dst_port <= src_port ? dst_ip : src_ip;
}

static __always_inline void do_update(struct features *value, uint64_t len, uint64_t curr_time, bool cond) {
  if (cond) {
    value->n_packets += 1;
    value->n_bytes += len;
  } else {
    value->n_packets_reverse += 1;
    value->n_bytes_reverse += len;
  }
  value->alive_timestamp = curr_time;
}


static __always_inline int handler(struct CTXTYPE *ctx, struct pkt_metadata *md) {
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

  /*Calculating ip header length
   * value to multiply by 4 (SHL 2)
   *e.g. ip->ihl = 5 ; TCP Header starts at = 5 x 4 byte = 20 byte */
  uint8_t ip_header_len = ip->ihl << 2;

  switch (ip->protocol) {
    case IPPROTO_TCP: {
      /*Parsing L4 TCP*/
      struct tcphdr *tcp = data + sizeof(struct eth_hdr) + ip_header_len;
      if ((void *) tcp + sizeof(*tcp) > data_end) {
        return PASS;
      }

      uint64_t curr_time = get_time_epoch();
      struct session_key key = get_key(ip->saddr, ip->daddr, tcp->source, tcp->dest, ip->protocol);

      /*Check if match*/
      struct features *value = SESSIONS_TRACKED_CRYPTO.lookup(&key);
      if (!value) {
        uint32_t method;
        uint32_t server_ip = heuristic_server(ip->saddr, ip->daddr, tcp->source, tcp->dest, &method, tcp);
        struct features zero = {.start_timestamp=curr_time, .method=method, .server_ip=server_ip};
        SESSIONS_TRACKED_CRYPTO.insert(&key, &zero);
        value = SESSIONS_TRACKED_CRYPTO.lookup(&key);
        if (!value) {
          return PASS;
        }
      }

      /*Update current session*/
      do_update(value, bpf_ntohs(ip->tot_len), curr_time, ip->saddr == key.saddr);
      break;
    }
    case IPPROTO_UDP: {
      /*Parsing L4 UDP*/
      struct udphdr *udp = data + sizeof(struct eth_hdr) + ip_header_len;
      if ((void *) udp + sizeof(*udp) > data_end) {
        return PASS;
      }

      uint64_t curr_time = get_time_epoch();
      struct session_key key = get_key(ip->saddr, ip->daddr, udp->source, udp->dest, ip->protocol);

      /*Check if match*/
      struct features *value = SESSIONS_TRACKED_CRYPTO.lookup(&key);
      if (!value) {
        uint32_t method;
        uint32_t server_ip = heuristic_server(ip->saddr, ip->daddr, udp->source, udp->dest, &method, NULL);
        struct features zero = {.start_timestamp=curr_time, .method=method, .server_ip=server_ip};
        SESSIONS_TRACKED_CRYPTO.insert(&key, &zero);
        value = SESSIONS_TRACKED_CRYPTO.lookup(&key);
        if (!value) {
          return PASS;
        }
      }

      /*Update current session*/
      do_update(value, bpf_ntohs(ip->tot_len), curr_time, ip->saddr == key.saddr);
      break;
    }
    /*Ignored protocols*/
    default: {
      return PASS;
    }
  }

  /* Here operations after the capture */
  return PASS;
}

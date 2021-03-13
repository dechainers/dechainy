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

// Number of max TCP session tracked
#ifndef N_SESSION
#define N_SESSION                   1024
#endif
// Number of packet from the same TCP session
#ifndef N_PACKET_PER_SESSION
#define N_PACKET_PER_SESSION        10
#endif

/*Session identifier*/
struct session_key {
    __be32 saddr;                                   //IP source address
    __be32 daddr;                                   //IP dest address
    __be16 sport;                                   //Source port (if ICMP = 0)
    __be16 dport;                                   //Dest port (if ICMP = 0)
    __u8   proto;                                   //Protocol ID
} __attribute__((packed));

/*Features to be exported*/
struct features {
    struct session_key id;                          //Session identifier
    #ifdef TIMESTAMP
    uint64_t timestamp;                             //Packet timestamp
#endif
#ifdef IP_LENGTH
    uint16_t length;                                //IP length value
#endif
#ifdef IP_FLAGS
    uint16_t ip_flags;                           //IP flags
#endif
#ifdef TCP_LEN
    uint16_t tcp_len;                                //TCP payload length
#endif
#ifdef TCP_ACK
    uint32_t tcp_ack;                                //TCP ack n°
#endif
#ifdef TCP_FLAGS
    uint8_t tcp_flags;                               //TCP flags
#endif
#ifdef TCP_WIN
    uint16_t tcp_win;                                //TCP window value
#endif
#ifdef UDP_LEN
    uint8_t udp_len;                                //UDP payload length
#endif
#ifdef ICMP_TYPE
    uint8_t icmp_type;                               //ICMP operation type
#endif
} __attribute__((packed));

/*Queue containing only packets to userspace, hash to store total number of packets for each session*/
#if PTYPE == 0
BPF_QUEUESTACK_SHARED("queue", PACKET_BUFFER_DDOS, struct features, N_SESSION * N_PACKET_PER_SESSION, 0)__attribute((SWAP));
BPF_TABLE_SHARED("hash", struct session_key, uint64_t, SESSIONS_TRACKED_DDOS, N_SESSION)__attribute((SWAP));
#else
BPF_QUEUESTACK("extern", PACKET_BUFFER_DDOS, struct features, N_SESSION * N_PACKET_PER_SESSION, 0)__attribute((SWAP));
BPF_TABLE("extern", struct session_key, uint64_t, SESSIONS_TRACKED_DDOS, N_SESSION)__attribute((SWAP));
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

/*Default function called at each packet on interface*/
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
  uint64_t zero = 0;

  switch (ip->protocol) {
    case IPPROTO_TCP: {
      /*Parsing L4 TCP*/
      struct tcphdr *tcp = data + sizeof(struct eth_hdr) + ip_header_len;
      if ((void *) tcp + sizeof(*tcp) > data_end) {
        return PASS;
      }
      /*Check if it is already tracked or try to track it*/
      struct session_key key = get_key(ip->saddr, ip->daddr, tcp->source, tcp->dest, ip->protocol);
      uint64_t *value = SESSIONS_TRACKED_DDOS.lookup_or_try_init(&key, &zero);
      if(!value) {
        return PASS;
      }
      *value += 1;

      /*Check if max packets per session*/
      if (*value > N_PACKET_PER_SESSION) {
        return PASS;
      }

      /*Now I'm sure to take the packet*/
      struct features new_features = {
#ifdef IP_LENGTH
        .length=bpf_ntohs(ip->tot_len), 
#endif
#ifdef TIMESTAMP
       .timestamp=get_time_epoch(), 
#endif
#ifdef IP_FLAGS
        .ip_flags=ip->frag_off,
#endif
#ifdef TCP_ACK
        .tcp_ack=tcp->ack_seq,
#endif
#ifdef TCP_WIN
        .tcp_win=tcp->window, 
#endif
#ifdef TCP_LEN
        .tcp_len=(uint16_t)(bpf_ntohs(ip->tot_len) - ip_header_len - sizeof(*tcp)),
#endif
#ifdef TCP_FLAGS
        .tcp_flags=(tcp->cwr << 7) | (tcp->ece << 6) | (tcp->urg << 5) | (tcp->ack << 4)
                | (tcp->psh << 3)| (tcp->rst << 2) | (tcp->syn << 1) | tcp->fin,
#endif
        .id=key
      };

      /*Push those features into PACKET_BUFFER*/
      PACKET_BUFFER_DDOS.push(&new_features, 0);
      break;
    }
    case IPPROTO_ICMP: {
      /*Parsing L4 ICMP*/
      struct icmphdr *icmp = data + sizeof(struct eth_hdr) + ip_header_len;
      if ((void *) icmp + sizeof(*icmp) > data_end) {
        return PASS;
      }

      /*Check if it is already tracked or try to track it*/
      struct session_key key = get_key(ip->saddr, ip->daddr, 0, 0, ip->protocol);
      uint64_t *value = SESSIONS_TRACKED_DDOS.lookup_or_try_init(&key, &zero);
      if(!value) {
        return PASS;
      }
      *value += 1;

      /*Check if max packets per session*/
      if (*value > N_PACKET_PER_SESSION) {
        return PASS;
      }
      
      /*Now I'm sure to take the packet*/
      struct features new_features = {
#ifdef IP_LENGTH
        .length=bpf_ntohs(ip->tot_len), 
#endif
#ifdef TIMESTAMP
        .timestamp=get_time_epoch(), 
#endif
#ifdef IP_FLAGS
        .ip_flags=ip->frag_off,
#endif
#ifdef ICMP_TYPE
        .icmp_type=icmp->type,
#endif
        .id=key
      };

      /*Push those features into PACKET_BUFFER*/
      PACKET_BUFFER_DDOS.push(&new_features, 0);
      break;
    }
    case IPPROTO_UDP: {
      /*Parsing L4 UDP*/
      struct udphdr *udp = data + sizeof(struct eth_hdr) + ip_header_len;
      if ((void *) udp + sizeof(*udp) > data_end) {
        return PASS;
      }

      /*Check if it is already tracked or try to track it*/
      struct session_key key = get_key(ip->saddr, ip->daddr, udp->source, udp->dest, ip->protocol);
      uint64_t *value = SESSIONS_TRACKED_DDOS.lookup_or_try_init(&key, &zero);
      if(!value) {
        return PASS;
      }
      *value += 1;

      /*Check if max packets per session*/
      if (*value > N_PACKET_PER_SESSION) {
        return PASS;
      }

      /*Now I'm sure to take the packet*/
      struct features new_features = {
#ifdef IP_LENGTH
        .length=bpf_ntohs(ip->tot_len), 
#endif
#ifdef TIMESTAMP
        .timestamp=get_time_epoch(), 
#endif
#ifdef IP_FLAGS
        .ip_flags=ip->frag_off,
#endif
#ifdef UDP_LEN
        .udp_len=bpf_ntohs(udp->len) - sizeof(*udp),
#endif
        .id=key
      };

      /*Push those features into PACKET_BUFFER*/
      PACKET_BUFFER_DDOS.push(&new_features, 0);
      break;
    }
    /*Unchecked protocols*/
    default : {
      return PASS;
    }
  }

  /*Here the packet has been successfully taken*/
  return PASS;
}
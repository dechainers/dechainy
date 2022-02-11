// Copyright 2022 DeChainers
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
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1
#define ETH_P_IP 0x0800

#define ECHO_REQUEST 8
#define ECHO_REPLY  0

/*Own control variables*/
#define N_SESSION                   1024            // Number of max TCP session tracked
#define N_PACKET_PER_SESSION        100             // Number of packet from the same TCP session
#define N_PACKET_TOTAL \
    N_SESSION * N_PACKET_PER_SESSION                // Number of max packet captured (Size of PACKET_BUFFER)

/*Session identifier*/
struct session_key {
    __be32 saddr;                                   //IP source address
    __be32 daddr;                                   //IP dest address
    __be16 sport;                                   //Source port (if ICMP = 0)
    __be16 dport;                                   //Dest port (if ICMP = 0)
    __u8   proto;                                   //Protocol ID
} __attribute__((packed));

/*Session value*/
struct session_value {
  __be32 server_ip;                                 //The server IP
  uint64_t n_packets;                               //The number of packet captured so far
} __attribute__((packed));

/*Features to be exported*/
struct features {
    struct session_key id;                          //Session identifier
    uint64_t timestamp;                             //Packet timestamp
    uint16_t ipFlagsFrag;                           //IP flags
    uint8_t tcpFlags;                               //TCP flags
    uint16_t tcpWin;                                //TCP window value
    uint8_t udpSize;                                //UDP payload length
    uint8_t icmpType;                               //ICMP operation type
} __attribute__((packed));

/*Ethernet Header => https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_ether.h (slightly different)*/
struct eth_hdr {
    __be64 dst: 48;
    __be64 src: 48;
    __be16 proto;
} __attribute__((packed));

/*Ip Header => https://github.com/torvalds/linux/blob/master/include/uapi/linux/ip.h */
/*The "_" is useful if mode=BPF.XDP and XDPFlags.SKB_MODE, since already named iphdr*/
struct iphdr_ {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8    ihl:4,
        version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
    __u8    version:4,
        ihl:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __sum16 check;
    __be32 saddr;
    __be32 daddr;
    /*The options start here. */
} __attribute__((packed));

/*TCP Header => https://github.com/torvalds/linux/blob/master/include/uapi/linux/tcp.h */
struct tcphdr {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u16   res1:4,
        doff:4,
        fin:1,
        syn:1,
        rst:1,
        psh:1,
        ack:1,
        urg:1,
        ece:1,
        cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u16   doff:4,
        res1:4,
        cwr:1,
        ece:1,
        urg:1,
        ack:1,
        psh:1,
        rst:1,
        syn:1,
        fin:1;
#else
#error  "Adjust your <asm/byteorder.h> defines"
#endif
    __be16 window;
    __sum16 check;
    __be16 urg_ptr;
} __attribute__((packed));

/*UDP Header https://github.com/torvalds/linux/blob/master/include/uapi/linux/udp.h */
struct udphdr {
    __be16 source;
    __be16 dest;
    __be16 len;
    __sum16 check;
} __attribute__((packed));

/*ICMP Header https://github.com/torvalds/linux/blob/master/include/uapi/linux/icmp.h*/
struct icmphdr {
    __u8 type;
    __u8 code;
    __sum16 checksum;
    union {
        struct {
            __be16 id;
            __be16 sequence;
        } echo;
        __be32 gateway;
        struct {
            __be16 __unused;
            __be16 mtu;
        } frag;
        __u8 reserved[4];
    } un;
} __attribute__((packed));

#if POLYCUBE_PROGRAM_TYPE == 0 
BPF_QUEUESTACK_SHARED("queue",PACKET_BUFFER_DDOS, struct features, N_PACKET_TOTAL, 0);
BPF_TABLE_SHARED("hash", struct session_key, struct session_value, SESSIONS_TRACKED_DDOS, N_SESSION);
#else
BPF_QUEUESTACK("extern", PACKET_BUFFER_DDOS, struct features, N_PACKET_TOTAL, 0);
BPF_TABLE("extern", struct session_key, struct session_value, SESSIONS_TRACKED_DDOS, N_SESSION);
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
static __always_inline __be32 heuristic_server(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, struct tcphdr *tcp, struct icmphdr *icmp) {
  /*If Syn, then srcIp is the server*/
  if(tcp && tcp->syn) {/*If source port < 1024, then srcIp is the server*/
    return tcp->ack? src_ip : dst_ip;
  }
  /*Check if Echo Request/Reply*/
  if(icmp) {
    if(icmp->type == ECHO_REQUEST)
      return dst_ip;
    if(icmp->type == ECHO_REPLY)
      return src_ip;
  }
  dst_port = bpf_htons(dst_port);
  /*If destination port < 1024, then dstIp is the server*/
  if(dst_port < 1024) {
    return dst_ip;
  }
  src_port = bpf_htons(src_port);
  /*If source port < 1024, then srcIp is the server*/
  if(src_port < 1024) {
    return src_ip;
  }
  /*Otherwise, the lowest port is the server*/
  return dst_port <= src_port ? dst_ip : src_ip;
}

/*Default function called at each packet on interface*/
int handle_rx(struct CTXTYPE *ctx) {
  void *data = (void *) (long) ctx->data;
  void *data_end = (void *) (long) ctx->data_end;

  /*Parsing L2*/
  struct eth_hdr *ethernet = data;
  if (data + sizeof(*ethernet) > data_end)
    return RX_OK;

  if (ethernet->proto != bpf_htons(ETH_P_IP))
    return RX_OK;

  /*Parsing L3*/
  struct iphdr_ *ip = data + sizeof(struct eth_hdr);
  if (data + sizeof(struct eth_hdr) + sizeof(*ip) > data_end)
    return RX_OK;
  if ((int) ip->version != 4)
    return RX_OK;

  /*Checking for considered protocols*/
  if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP && ip->protocol != IPPROTO_ICMP) {
    return RX_OK;
  }

  /*Calculating ip header length
   * value to multiply by 4 (SHL 2)
   *e.g. ip->ihl = 5 ; TCP Header starts at = 5 x 4 byte = 20 byte */
  uint8_t ip_header_len = ip->ihl << 2;
  
  /*Checking if packed is already timestamped, otherwise get it from kernel bpf function*/
  uint64_t curr_time = EPOCH_BASE + bpf_ktime_get_ns();
  struct session_value zero = {.n_packets=0, .server_ip=0};

  switch (ip->protocol) {
    case IPPROTO_TCP: {
      /*Parsing L4 TCP*/
      struct tcphdr *tcp = data + sizeof(struct eth_hdr) + ip_header_len;
      if ((void *) tcp + sizeof(*tcp) > data_end) {
        return RX_OK;
      }
      /*Check if it is already tracked or try to track it*/
      struct session_key key = get_key(ip->saddr, ip->daddr, tcp->source, tcp->dest, ip->protocol);
      struct session_value *value = SESSIONS_TRACKED_DDOS.lookup_or_try_init(&key, &zero);
      if(!value) {
        break;
      }

      /*Check if max packet reached*/
      if(value->n_packets == N_PACKET_PER_SESSION){
        break;
      } else if(value->n_packets == 0){
        value->server_ip = heuristic_server(ip->saddr, ip->daddr, tcp->source, tcp->dest, tcp, NULL);
      }
      value->n_packets +=1;

      /*Now I'm sure to take the packet*/
      struct features new_features = {.id=key, .timestamp=curr_time, .ipFlagsFrag=bpf_ntohs(ip->frag_off),
        .tcpWin=bpf_ntohs(tcp->window),
        .tcpFlags=(tcp->cwr << 7) | (tcp->ece << 6) | (tcp->urg << 5) | (tcp->ack << 4)
                | (tcp->psh << 3)| (tcp->rst << 2) | (tcp->syn << 1) | tcp->fin};
      
      /*Push those features into PACKET_BUFFER*/
      PACKET_BUFFER_DDOS.push(&new_features, 0);
      break;
    }
    case IPPROTO_ICMP: {
      /*Parsing L4 ICMP*/
      struct icmphdr *icmp = data + sizeof(struct eth_hdr) + ip_header_len;
      if ((void *) icmp + sizeof(*icmp) > data_end) {
        return RX_OK;
      }

      /*Check if it is already tracked or try to track it*/
      struct session_key key = get_key(ip->saddr, ip->daddr, 0, 0, ip->protocol);
      struct session_value *value = SESSIONS_TRACKED_DDOS.lookup_or_try_init(&key, &zero);
      if(!value) {
        break;
      }

      /*Check if max packet reached*/
      if(value->n_packets == N_PACKET_PER_SESSION){
        break;
      } else if(value->n_packets == 0){
        value->server_ip = heuristic_server(ip->saddr, ip->daddr, 0, 0, NULL, icmp);
      }
      value->n_packets +=1;

      /*Now I'm sure to take the packet*/
      struct features new_features = {.id=key, .icmpType=icmp->type, .timestamp=curr_time, .ipFlagsFrag=bpf_ntohs(ip->frag_off)};
      
      /*Push those features into PACKET_BUFFER*/
      PACKET_BUFFER_DDOS.push(&new_features, 0);
      break;
    }
    case IPPROTO_UDP: {
      /*Parsing L4 UDP*/
      struct udphdr *udp = data + sizeof(struct eth_hdr) + ip_header_len;
      if ((void *) udp + sizeof(*udp) > data_end) {
        return RX_OK;
      }

      /*Check if it is already tracked or try to track it*/
      struct session_key key = get_key(ip->saddr, ip->daddr, udp->source, udp->dest, ip->protocol);
      struct session_value *value = SESSIONS_TRACKED_DDOS.lookup_or_try_init(&key, &zero);
      if(!value) {
        break;
      }

      /*Check if max packet reached*/
      if(value->n_packets == N_PACKET_PER_SESSION){
        break;
      } else if(value->n_packets == 0){
        value->server_ip = heuristic_server(ip->saddr, ip->daddr, udp->source, udp->dest, NULL, NULL);
      }
      value->n_packets +=1;

      /*Now I'm sure to take the packet*/
      struct features new_features = {.id=key, .udpSize=bpf_ntohs(udp->len) - sizeof(*udp), .timestamp=curr_time, .ipFlagsFrag=bpf_ntohs(ip->frag_off)};
      
      /*Push those features into PACKET_BUFFER*/
      PACKET_BUFFER_DDOS.push(&new_features, 0);
      break;
    }
    /*Should never reach this code since already checked*/
    default : {
      return RX_OK;
    }
  }

  return RX_OK;
}
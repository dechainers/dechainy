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

// Map containing the blacklisted IPS
BPF_TABLE("hash", struct lpm_key, uint64_t, BLACKLISTED_IPS, MAX_IPS);

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

    struct lpm_key key = {.netmask_len=32, .ip=ip->saddr};
    uint64_t *val = BLACKLISTED_IPS.lookup(&key);
    // If the IP has matched, increment the counter and drop the packet
    if(val) {
      dp_log(LOG_INFO, "Mitigated IP: %d", ip->saddr);
      *val += 1;
      return DROP;
    }
    return PASS;
}
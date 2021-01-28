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
BPF_TABLE("array", int, uint64_t, TOTAL_PACKETS, 1);

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

    TOTAL_PACKETS.increment(0);

    return PASS;
}
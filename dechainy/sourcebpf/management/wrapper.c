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

// extern programs map
BPF_TABLE("extern", int, int, PROGRAM_TYPE_next_MODE, MAX_PROGRAMS_PER_HOOK);

// redirect table, containing the index of the next interface
#ifdef PTYPE == 0
#ifdef XDP
BPF_DEVMAP(DEVMAP, 1);
#else
BPF_TABLE("array", int, int, DEVMAP, 1);
#endif
#endif

// Function called, defined by user
static __always_inline
int handler(struct CTXTYPE *ctx, struct pkt_metadata *md);

// Hook handler wrapper, to call the apposite function
int internal_handler(struct CTXTYPE *ctx) {
  struct pkt_metadata md = {ctx->ingress_ifindex, PTYPE, PROBE_ID};
  
  int rc = handler(ctx, &md);
  
  switch (rc) {
    case DROP:
      return DROP;
    case PASS: {
      PROGRAM_TYPE_next_MODE.call(ctx, md.probe_id);
      break;
    }
    case REDIRECT: {
// Return explicitly redirect, then if ingress ok
#if PTYPE == 0
#ifdef XDP
      return DEVMAP.redirect_map(0, 0);
#else
      int zero = 0;
      u32 *ifindex = DEVMAP.lookup(&zero);
      if (ifindex) {
        return bpf_redirect(*ifindex, 0);  
      }
      PROGRAM_TYPE_next_MODE.call(ctx, md.probe_id);
#endif
#endif
      break;
    }
#if PTYPE == 0  && XDP
    // The packet can be redirect in TX only in XDP
    case BACK_TX: {
      return BACK_TX;
    }
#endif
    default: break;
  }
  return PASS;
}

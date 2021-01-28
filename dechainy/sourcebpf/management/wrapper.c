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
      // TODO: implement redirect
      break;
    }
    default: break;
  }
  return PASS;
}

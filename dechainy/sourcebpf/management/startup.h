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

// Table for pushing custom events to userspace via ring buffer
struct log_table_t {
  int key;
  u32 leaf;
  int (*perf_submit) (void *, void *, u32);
  int (*perf_submit_skb) (void *, u32, void *, u32);
  u32 data[0];
};
__attribute__((section("maps/perf_output")))
struct log_table_t log_buffer;
__attribute__((section("maps/export")))
struct log_table_t __log_buffer;
__attribute__((section("maps/perf_output")))
struct log_table_t control_plane;
__attribute__((section("maps/export")))
struct log_table_t __control_plane;

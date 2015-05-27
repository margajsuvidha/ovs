/*
 * Copyright (c) 2014 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CONNTRACK_H
#define CONNTRACK_H 1

#include <stdbool.h>

#include "hmap.h"
#include "openvswitch/thread.h"
#include "openvswitch/types.h"

struct dp_packet;

struct conntrack {
    struct ovs_mutex mutex;
    struct hmap connections OVS_GUARDED;
};

void conntrack_init(struct conntrack *);
void conntrack_run(struct conntrack *);
void conntrack_destroy(struct conntrack *);

int conntrack(struct conntrack *, struct dp_packet **, size_t, bool commit,
              uint16_t zone, const char *helper);

#endif /* conntrack.h */

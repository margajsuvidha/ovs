/*
 * Copyright (c) 2015 Nicira, Inc.
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

#ifndef CONNTRACK_PRIVATE_H
#define CONNTRACK_PRIVATE_H 1

#include <netinet/in.h>
#include <netinet/ip6.h>

#include "hmap.h"
#include "packets.h"
#include "unaligned.h"

#define IN6_U32 (sizeof(union ovs_16aligned_in6_addr) / sizeof(uint32_t))

struct ct_addr {
    union {
            ovs_16aligned_be32 ipv4;
            union ovs_16aligned_in6_addr ipv6;
            uint32_t ipv4_aligned;
            uint32_t ipv6_aligned[IN6_U32];
    };
};

struct ct_endpoint {
    struct ct_addr addr;
    ovs_be16 port;
};

struct conn_key {
    struct ct_endpoint src;
    struct ct_endpoint dst;

    ovs_be16 dl_type;
    uint8_t nw_proto;
    uint16_t zone;
};

struct conn {
    struct conn_key key;
    struct conn_key rev_key;
    long long expiration;
    struct hmap_node node;
};

struct ct_l4_proto {
    struct conn *(*new_conn)(struct dp_packet *pkt, long long now);
    bool (*valid_new)(struct dp_packet *pkt);
    bool (*conn_update)(struct conn *conn, struct dp_packet *pkt, bool reply,
                        long long now);
};

extern struct ct_l4_proto ct_proto_tcp;
extern struct ct_l4_proto ct_proto_other;

#endif /* conntrack-private.h */

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

#include <config.h>
#include "conntrack.h"

#include <errno.h>

#include "conntrack-private.h"
#include "dp-packet.h"
#include "flow.h"
#include "hmap.h"
#include "netdev.h"
#include "odp-netlink.h"
#include "openvswitch/vlog.h"
#include "timeval.h"

/*
VLOG_DEFINE_THIS_MODULE(conntrack);
*/

struct conn_key_lookup {
    struct conn_key key;
    struct conn *conn;
    uint32_t hash;
    bool reply;
    bool key_ok;
};

static int conn_key_extract(struct dp_packet *pkt, struct conn_key *key,
                            uint16_t zone);
static uint32_t conn_key_hash(const struct conn_key *key);
static void conn_key_reverse(struct conn_key *key);
static void conn_keys_lookup(struct hmap *connections,
                             struct conn_key_lookup *keys, size_t cnt,
                             long long now);
static bool valid_new(struct dp_packet *pkt, struct conn_key *);
static struct conn *new_conn(struct dp_packet *pkt, struct conn_key *,
                             long long now);
static void delete_conn(struct conn *);
static bool conn_update(struct conn *, struct dp_packet*, bool reply,
                        long long now);
static bool conn_expired(struct conn *, long long now);

static struct ct_l4_proto *l4_protos[] = {
    [IPPROTO_TCP] = &ct_proto_tcp,
    [IPPROTO_UDP] = &ct_proto_other,
};

void
conntrack_init(struct conntrack *ct)
{
    ovs_mutex_init(&ct->mutex);
    ovs_mutex_lock(&ct->mutex);
    hmap_init(&ct->connections);
    ovs_mutex_unlock(&ct->mutex);
}

void
conntrack_destroy(struct conntrack *ct)
{
    struct conn *conn, *next;
    ovs_mutex_lock(&ct->mutex);
    HMAP_FOR_EACH_SAFE(conn, next, node, &ct->connections) {
        hmap_remove(&ct->connections, &conn->node);
        delete_conn(conn);
    }
    hmap_destroy(&ct->connections);
    ovs_mutex_unlock(&ct->mutex);
}

int
conntrack(struct conntrack *ct, struct dp_packet **pkts, size_t cnt,
          bool commit, uint16_t zone, const char *helper OVS_UNUSED)
{
#if !defined(__CHECKER__) && !defined(_WIN32)
    const size_t KEY_ARRAY_SIZE = cnt;
#else
    enum { KEY_ARRAY_SIZE = NETDEV_MAX_BURST };
#endif
    struct conn_key_lookup keys[KEY_ARRAY_SIZE];
    long long now = time_msec();
    size_t i = 0;

    /*
    VLOG_INFO("Executing CT(commit=%d,zone=%"PRIu16",helper=%s)",
              commit, zone, helper ? helper : "<none>");
    */

    for (i = 0; i < cnt; i++) {
        pkts[i]->md.conn_state = OVS_CS_F_TRACKED;
        keys[i].conn = NULL;
        if (!conn_key_extract(pkts[i], &keys[i].key, zone)) {
            keys[i].key_ok = true;
        } else {
            keys[i].key_ok = false;
        }
    }

    ovs_mutex_lock(&ct->mutex);
    conn_keys_lookup(&ct->connections, keys, cnt, now);

    for (i = 0; i < cnt; i++) {
        if (keys[i].conn) {
            /* XXX if this has already been tracked on the same zone
             * (and with the same helper?) do not update.  It was also
             * a waste to extract the key. */
            if (conn_update(keys[i].conn, pkts[i], keys[i].reply, now)) {
                pkts[i]->md.conn_state |= OVS_CS_F_ESTABLISHED;
                if (keys[i].reply) {
                    pkts[i]->md.conn_state |= OVS_CS_F_REPLY_DIR;
                }
            } else {
                pkts[i]->md.conn_state |= OVS_CS_F_INVALID;
            }

            pkts[i]->md.conn_zone = zone;
        } else if (keys[i].key_ok) {

            if (!valid_new(pkts[i], &keys[i].key)) {
                pkts[i]->md.conn_state |= OVS_CS_F_INVALID;
                continue;
            }

            pkts[i]->md.conn_state |= OVS_CS_F_NEW;

            if (commit) {
                struct conn *nc = new_conn(pkts[i], &keys[i].key, now);

                memcpy(&nc->rev_key, &keys[i].key, sizeof nc->rev_key);

                conn_key_reverse(&nc->rev_key);
                hmap_insert(&ct->connections, &nc->node, keys[i].hash);
            }
            pkts[i]->md.conn_zone = zone;
        } else {
            pkts[i]->md.conn_state |= OVS_CS_F_INVALID;
        }
    }
    ovs_mutex_unlock(&ct->mutex);

    return 0;
}

void conntrack_run(struct conntrack *ct)
{
    struct conn *conn, *next;
    long long now = time_msec();

    ovs_mutex_lock(&ct->mutex);
    /* XXX do not check every connection each time */
    HMAP_FOR_EACH_SAFE(conn, next, node, &ct->connections) {
        if (conn_expired(conn, now)) {
            hmap_remove(&ct->connections, &conn->node);
            delete_conn(conn);
        }
    }
    ovs_mutex_unlock(&ct->mutex);
}

static int
conn_key_extract(struct dp_packet *pkt, struct conn_key *key, uint16_t zone)
{
    const struct ip_header *l3 = dp_packet_l3(pkt);
    const void *l4 = dp_packet_l4(pkt);

    if (!l3 || !l4) {
        return EINVAL;
    }
    memset(key, 0, sizeof *key);
    key->zone = zone;

    /* IPv4 or IPv6 */
    if (IP_VER(l3->ip_ihl_ver) == IP_VERSION) {
        const struct ip_header *ip = dp_packet_l3(pkt);

        key->src.addr.ipv4 = ip->ip_src;
        key->dst.addr.ipv4 = ip->ip_dst;
        key->dl_type = htons(ETH_TYPE_IP);
        key->nw_proto = ip->ip_proto;
    } else if (IP_VER(l3->ip_ihl_ver) == 6) {
        const struct ovs_16aligned_ip6_hdr *ip6 = dp_packet_l3(pkt);
        uint8_t nw_proto = ip6->ip6_nxt;
        uint8_t nw_frag;
        const void *data = ip6 + 1;
        size_t size = (char *) dp_packet_tail(pkt) - (char *) data;

        if (!parse_ipv6_ext_hdrs(&data, &size, &nw_proto, &nw_frag)) {
            return EINVAL;
        }

        key->src.addr.ipv6 = ip6->ip6_src;
        key->dst.addr.ipv6 = ip6->ip6_dst;
        key->dl_type = htons(ETH_TYPE_IPV6);
        key->nw_proto = nw_proto;
    } else {
        return EINVAL;
    }

    if (key->nw_proto == IPPROTO_TCP) {
        const struct tcp_header *tcp = l4;

        if (!dp_packet_get_tcp_payload(pkt)) {
            return EINVAL;
        }
        key->src.port = tcp->tcp_src;
        key->dst.port = tcp->tcp_dst;
    } else if (key->nw_proto == IPPROTO_UDP) {
        const struct udp_header *udp = l4;

        if (!dp_packet_get_udp_payload(pkt)) {
            return EINVAL;
        }
        key->src.port = udp->udp_src;
        key->dst.port = udp->udp_dst;
    } else {
        /* XXX support sctp and icmp ? */
        return EINVAL;
    }
    return 0;
}

/* Symmetric */
static uint32_t
conn_key_hash(const struct conn_key *key)
{
    uint32_t hsrc, hdst, hash;
    int i;

    hsrc = hdst = 0;

    for (i = 0; i < sizeof(key->src) / sizeof(uint32_t); i++) {
        hsrc = hash_add(hsrc, ((uint32_t *) &key->src)[i]);
        hdst = hash_add(hdst, ((uint32_t *) &key->dst)[i]);
    }

    hash = hsrc ^ hdst;

    hash = hash_words((uint32_t *) &key->dst + 1,
                      (uint32_t *) (key + 1) - (uint32_t *) (&key->dst + 1),
                      hash);

    return hash;
}

static void
conn_key_reverse(struct conn_key *key)
{
    struct ct_endpoint tmp;
    tmp = key->src;
    key->src = key->dst;
    key->dst = tmp;
}

static void
conn_keys_lookup(struct hmap *connections,
                 struct conn_key_lookup *keys,
                 size_t cnt, long long now)
{
    size_t i;

    for (i = 0; i < cnt; i++) {
        struct conn *conn, *found = NULL;
        uint32_t hash = conn_key_hash(&keys[i].key);
        bool reply;

        HMAP_FOR_EACH_WITH_HASH(conn, node, hash, connections) {
            if (!memcmp(&conn->key, &keys[i].key, sizeof(conn->key))) {
                found = conn;
                reply = false;
                break;
            }
            if (!memcmp(&conn->rev_key, &keys[i].key, sizeof(conn->rev_key))) {
                found = conn;
                reply = true;
                break;
            }
        }

        if (found) {
            if (conn_expired(found, now)) {
                found = NULL;
            } else {
                keys[i].reply = reply;
            }
        }

        keys[i].conn = found;
        keys[i].hash = hash;
    }
}

static bool
conn_update(struct conn *conn, struct dp_packet *pkt, bool reply,
            long long now)
{
    return l4_protos[conn->key.nw_proto]->conn_update(conn, pkt, reply, now);
}

static bool
conn_expired(struct conn *conn, long long now)
{
    return now > conn->expiration;
}

static bool
valid_new(struct dp_packet *pkt, struct conn_key *key)
{
    return l4_protos[key->nw_proto]->valid_new(pkt);
}

static struct conn *
new_conn(struct dp_packet *pkt, struct conn_key *key, long long now)
{
    struct conn *newconn;

    newconn = l4_protos[key->nw_proto]->new_conn(pkt, now);

    if (newconn) {
        newconn->key = *key;
    }

    return newconn;
}

static void
delete_conn(struct conn *conn)
{
    free(conn);
}

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
#include <netinet/icmp6.h>

#include "conntrack-private.h"
#include "dp-packet.h"
#include "flow.h"
#include "hmap.h"
#include "netdev.h"
#include "odp-netlink.h"
#include "openvswitch/vlog.h"
#include "ovs-rcu.h"
#include "timeval.h"

/*
VLOG_DEFINE_THIS_MODULE(conntrack);
*/

struct conn_key_lookup {
    struct conn_key key;
    struct conn *conn;
    uint32_t hash;
    bool reply;
    bool related;
    bool key_ok;
};

static void conn_key_extract(struct dp_packet *pkt,
                             struct conn_key_lookup *key,
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
    [IPPROTO_ICMP] = &ct_proto_other,
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
        pkts[i]->md.ct_state = OVS_CS_F_TRACKED;
        conn_key_extract(pkts[i], &keys[i], zone);
    }

    ovs_mutex_lock(&ct->mutex);
    conn_keys_lookup(&ct->connections, keys, cnt, now);

    for (i = 0; i < cnt; i++) {
        pkts[i]->ct_conn = NULL;

        if (keys[i].conn) {
            /* XXX if this has already been tracked on the same zone
             * (and with the same helper?) do not update.  It was also
             * a waste to extract the key. */

            if (keys[i].related) {
                pkts[i]->md.ct_state |= OVS_CS_F_RELATED;
                if (keys[i].reply) {
                    pkts[i]->md.ct_state |= OVS_CS_F_REPLY_DIR;
                }
            } else if (conn_update(keys[i].conn, pkts[i], keys[i].reply,
                                   now)) {
                pkts[i]->md.ct_state |= OVS_CS_F_ESTABLISHED;
                if (keys[i].reply) {
                    pkts[i]->md.ct_state |= OVS_CS_F_REPLY_DIR;
                }
            } else {
                pkts[i]->md.ct_state |= OVS_CS_F_INVALID;
            }

            pkts[i]->md.ct_zone = zone;
            pkts[i]->md.ct_label = keys[i].conn->label;
            pkts[i]->md.ct_mark = keys[i].conn->mark;
            pkts[i]->ct_conn = keys[i].conn;

        } else if (keys[i].key_ok) {

            if (!valid_new(pkts[i], &keys[i].key)) {
                pkts[i]->md.ct_state |= OVS_CS_F_INVALID;
                continue;
            }

            pkts[i]->md.ct_state |= OVS_CS_F_NEW;

            if (commit) {
                struct conn *nc = new_conn(pkts[i], &keys[i].key, now);

                memcpy(&nc->rev_key, &keys[i].key, sizeof nc->rev_key);

                conn_key_reverse(&nc->rev_key);
                hmap_insert(&ct->connections, &nc->node, keys[i].hash);
                pkts[i]->ct_conn = nc;
            }
            pkts[i]->md.ct_zone = zone;
        } else {
            pkts[i]->md.ct_state |= OVS_CS_F_INVALID;
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

void
conntrack_set_mark(struct conntrack *ct, struct dp_packet **pkts, size_t cnt,
                   uint32_t val, uint32_t mask)
{
    size_t i = 0;

    ovs_mutex_lock(&ct->mutex);
    for (i = 0; i < cnt; i++) {
        struct conn *conn;

        /* XXX Here I assume that pkts[i]->ct_conn is a valid pointer
         * if ct_state is tracked.  Is it safe to assume that? Can a user
         * set the connection state?  Should I always initialize the ct_conn
         * to NULL? (in dp_netdev_process_rxq_port and from kernel upcalls)
         * DOUBLE CHECK */
        if (!(pkts[i]->md.ct_state & OVS_CS_F_TRACKED)
            || !pkts[i]->ct_conn) {
            continue;
        }

        pkts[i]->md.ct_mark = val | (pkts[i]->md.ct_mark & ~(mask));
        conn = pkts[i]->ct_conn;
        conn->mark = pkts[i]->md.ct_mark;
    }
    ovs_mutex_unlock(&ct->mutex);
}

void
conntrack_set_label(struct conntrack *ct, struct dp_packet **pkts, size_t cnt,
                    const struct ovs_key_ct_label *val,
                    const struct ovs_key_ct_label *mask)
{
    size_t i = 0;

    ovs_mutex_lock(&ct->mutex);
    for (i = 0; i < cnt; i++) {
        struct conn *conn;

        /* XXX Here I assume that pkts[i]->ct_conn is a valid pointer
         * if ct_state is tracked.  Is it safe to assume that? Can a user
         * set the connection state?  Should I always initialize the ct_conn
         * to NULL? (in dp_netdev_process_rxq_port and from kernel upcalls)
         * DOUBLE CHECK */
        if (!(pkts[i]->md.ct_state & OVS_CS_F_TRACKED)
            || !pkts[i]->ct_conn) {
            continue;
        }

        if (mask) {
            ovs_u128 v, m;

            /* XXX odp-util does like this. What about endianness? */
            memcpy(&v, val, sizeof(v));
            memcpy(&m, mask, sizeof(m));

            pkts[i]->md.ct_label.u64.lo = v.u64.lo
                                            | (pkts[i]->md.ct_label.u64.lo &
                                               ~(m.u64.lo));
            pkts[i]->md.ct_label.u64.hi = v.u64.hi
                                            | (pkts[i]->md.ct_label.u64.hi &
                                               ~(m.u64.hi));
        } else {
            /* XXX odp-util does this. What about endianness? */
            memcpy(&pkts[i]->md.ct_label, val, sizeof(pkts[i]->md.ct_label));
        }

        conn = pkts[i]->ct_conn;
        conn->label = pkts[i]->md.ct_label;
    }
    ovs_mutex_unlock(&ct->mutex);
}

/* Key extraction */

static inline bool
extract_l3_ipv4(struct conn_key *key, const void *data, size_t size,
                const char **new_data)
{
    const struct ip_header *ip = data;

    if (new_data) {
        size_t ip_len;

        if (OVS_UNLIKELY(size < IP_HEADER_LEN)) {
            return false;
        }
        ip_len = IP_IHL(ip->ip_ihl_ver) * 4;

        if (OVS_UNLIKELY(ip_len < IP_HEADER_LEN)) {
            return false;
        }
        if (OVS_UNLIKELY(size < ip_len)) {
            return false;
        }

        *new_data = (char *) data + ip_len;
    }

    key->src.addr.ipv4 = ip->ip_src;
    key->dst.addr.ipv4 = ip->ip_dst;
    key->nw_proto = ip->ip_proto;

    return true;
}

static inline int
extract_l3_ipv6(struct conn_key *key, const void *data, size_t size,
                const char **new_data)
{
    const struct ovs_16aligned_ip6_hdr *ip6 = data;
    uint8_t nw_proto = ip6->ip6_nxt;
    uint8_t nw_frag;
    
    if (new_data) {
        if (OVS_UNLIKELY(size < sizeof *ip6)) {
            return false;
        }
    }

    data = ip6 + 1;
    size -=  sizeof *ip6;

    if (!parse_ipv6_ext_hdrs(&data, &size, &nw_proto, &nw_frag)) {
        return false;
    }

    if (new_data) {
        *new_data = data;
    }

    key->src.addr.ipv6 = ip6->ip6_src;
    key->dst.addr.ipv6 = ip6->ip6_dst;
    key->nw_proto = nw_proto;

    return true;
}

static inline bool
check_l4_tcp(const void *data, size_t size)
{
    const struct tcp_header *tcp = data;
    size_t tcp_len = TCP_OFFSET(tcp->tcp_ctl) * 4;

    if (OVS_LIKELY(tcp_len >= TCP_HEADER_LEN && tcp_len <= size)) {
        return true;
    }

    return false;
}

static inline bool
extract_l4_tcp(struct conn_key *key, const void *data, size_t size)
{
    const struct tcp_header *tcp = data;

    if (OVS_UNLIKELY(size < TCP_HEADER_LEN)) {
        return false;
    }

    key->src.port = tcp->tcp_src;
    key->dst.port = tcp->tcp_dst;

    return true;
}

static inline bool
extract_l4_udp(struct conn_key *key, const void *data, size_t size)
{
    const struct udp_header *udp = data;

    if (OVS_UNLIKELY(size < UDP_HEADER_LEN)) {
        return false;
    }

    key->src.port = udp->udp_src;
    key->dst.port = udp->udp_dst;

    return true;
}

static inline bool extract_l4(struct conn_key *key, const void *data,
                              size_t size, bool *related);

static inline int
extract_l4_icmp(struct conn_key *key, const void *data, size_t size,
                bool *related)
{
    const struct icmp_header *icmp = data;

    if (OVS_UNLIKELY(size < ICMP_HEADER_LEN)) {
        return false;
    }

    switch (icmp->icmp_type) {
    case ICMP_ECHO_REQUEST:
    case ICMP_ECHO_REPLY:
    case ICMP_TIMESTAMP:
    case ICMP_TIMESTAMPREPLY:
    case ICMP_INFOREQUEST:
    case ICMP_INFOREPLY:
        /* Separate ICMP connection: identified using id */
        key->src.port = key->dst.port = icmp->icmp_fields.echo.id;
        break;
    case ICMP_DST_UNREACH:
    case ICMP_TIME_EXCEEDED:
    case ICMP_PARAM_PROB:
    case ICMP_SOURCEQUENCH:
    case ICMP_REDIRECT: {
        /* ICMP packet part of another connection. We should
         * extract the key from embedded packet header */
        struct conn_key inner_key = { .dl_type = htons(ETH_TYPE_IP) };
        const char *l3 = (const char *) (icmp + 1);
        const char *tail = (const char *) data + size;
        const char *l4;
        bool ok;

        if (!related) {
            return false;
        }
        *related = true;

        memset(&inner_key, 0, sizeof inner_key);
        /* XXX if frag throw away */
        ok = extract_l3_ipv4(&inner_key, l3, tail - l3, &l4);
        if (!ok) {
            return false;
        }

        /* pf doesn't do this, but it seems a good idea */
        if (inner_key.src.addr.ipv4_aligned != key->dst.addr.ipv4_aligned
            || inner_key.dst.addr.ipv4_aligned != key->src.addr.ipv4_aligned) {
            return false;
        }

        key->src = inner_key.src;
        key->dst = inner_key.dst;
        key->nw_proto = inner_key.nw_proto;

        ok = extract_l4(key, l4, tail - l4, NULL);
        if (ok) {
            conn_key_reverse(key);
        }
        return ok;
    }
    default:
        return false;
    }

    return true;
}

static inline bool
extract_l4_icmp6(struct conn_key *key, const void *data, size_t size,
                 bool *related)
{
    const struct icmp6_header *icmp6 = data;

    /* All the messages that we support need at least 4 bytes after
     * the header */
    if (size < sizeof *icmp6 + 4) {
        return false;
    }

    switch (icmp6->icmp6_type) {
    case ICMP6_ECHO_REQUEST:
    case ICMP6_ECHO_REPLY:
        /* Separate ICMP connection: identified using id */
        key->src.port = key->dst.port = *(ovs_be16 *) (icmp6 + 1);
        break;
    case ICMP6_DST_UNREACH:
    case ICMP6_PACKET_TOO_BIG:
    case ICMP6_TIME_EXCEEDED:
    case ICMP6_PARAM_PROB:{
        /* ICMP packet part of another connection. We should
         * extract the key from embedded packet header */
        struct conn_key inner_key = { .dl_type = htons(ETH_TYPE_IPV6) };
        const char *l3 = (const char *) icmp6 + 8;
        const char *tail = (const char *) data + size;
        const char *l4;
        bool ok;

        if (!related) {
            return false;
        }
        *related = true;

        ok = extract_l3_ipv6(&inner_key, l3, tail - l3, &l4);
        if (!ok) {
            return false;
        }

        /* pf doesn't do this, but it seems a good idea */
        if (!ipv6_addr_equals(&inner_key.src.addr.ipv6_aligned,
                              &key->dst.addr.ipv6_aligned)
            || !ipv6_addr_equals(&inner_key.dst.addr.ipv6_aligned,
                                 &key->src.addr.ipv6_aligned)) {
            return false;
        }

        key->src = inner_key.src;
        key->dst = inner_key.dst;
        key->nw_proto = inner_key.nw_proto;

        ok = extract_l4(key, l4, tail - l4, NULL);
        if (ok) {
            conn_key_reverse(key);
        }
        return ok;
    }
    default:
        return false;
    }

    return true;
}

static inline bool
extract_l4(struct conn_key *key, const void *data, size_t size, bool *related)
{
    if (key->nw_proto == IPPROTO_TCP) {
        return extract_l4_tcp(key, data, size)
               && (!related || check_l4_tcp(data, size));
    } else if (key->nw_proto == IPPROTO_UDP) {
        return extract_l4_udp(key, data, size);
    } else if (key->dl_type == htons(ETH_TYPE_IP)
               && key->nw_proto == IPPROTO_ICMP) {
        return extract_l4_icmp(key, data, size, related);
    } else if (key->dl_type == htons(ETH_TYPE_IPV6)
               && key->nw_proto == IPPROTO_ICMPV6) {
        return extract_l4_icmp6(key, data, size, related);
    } else {
        /* XXX support sctp? */
        return false;
    }
}

static void
conn_key_extract(struct dp_packet *pkt, struct conn_key_lookup *key,
                 uint16_t zone)
{
    const struct ip_header *l3 = dp_packet_l3(pkt);
    const char *l4 = dp_packet_l4(pkt);
    const char *tail = dp_packet_tail(pkt);
    bool ok;

    memset(key, 0, sizeof *key);

    if (!l3 || !l4) {
        return;
    }

    key->key.zone = zone;

    /* IPv4 or IPv6 */
    if (IP_VER(l3->ip_ihl_ver) == IP_VERSION) {
        key->key.dl_type = htons(ETH_TYPE_IP);
        ok = extract_l3_ipv4(&key->key, l3, tail - (char *) l3, NULL);
    } else if (IP_VER(l3->ip_ihl_ver) == 6) {
        key->key.dl_type = htons(ETH_TYPE_IPV6);
        ok = extract_l3_ipv6(&key->key, l3, tail - (char *) l3, NULL);
    } else {
        ok = false;
    }

    if (ok) {
        key->key_ok = extract_l4(&key->key, l4, tail - l4, &key->related);
    }
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
    /* Postponed, as a pointer to the connection can be stored in a packet */
    ovsrcu_postpone(free, conn);
}

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
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>

#include "bitmap.h"
#include "conntrack-private.h"
#include "dp-packet.h"
#include "flow.h"
#include "hmap.h"
#include "netdev.h"
#include "odp-netlink.h"
#include "openvswitch/vlog.h"
#include "ovs-rcu.h"
#include "random.h"
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
};

static bool conn_key_extract(struct conntrack *, struct dp_packet *,
                             struct conn_key_lookup *, uint16_t zone);
static uint32_t conn_key_hash(const struct conn_key *, uint32_t basis);
static void conn_key_reverse(struct conn_key *);
static void conn_keys_lookup(struct conntrack *, struct conn_key_lookup *keys,
                             unsigned long maps, unsigned bucket,
                             long long now);
static bool valid_new(struct dp_packet *pkt, struct conn_key *);
static struct conn *new_conn(struct dp_packet *pkt, struct conn_key *,
                             long long now);
static void delete_conn(struct conn *);
static enum ct_update_res conn_update(struct conn *, struct dp_packet*,
                                      bool reply, long long now);
static bool conn_expired(struct conn *, long long now);
static void set_mark(struct dp_packet *, struct conn *,
                     uint32_t val, uint32_t mask);
static void set_label(struct dp_packet *, struct conn *,
                      const struct ovs_key_ct_label *val,
                      const struct ovs_key_ct_label *mask);

static struct ct_l4_proto *l4_protos[] = {
    [IPPROTO_TCP] = &ct_proto_tcp,
    [IPPROTO_UDP] = &ct_proto_other,
    [IPPROTO_ICMP] = &ct_proto_other,
};

void
conntrack_init(struct conntrack *ct)
{
    unsigned i;

    for (i = 0; i < CONNTRACK_BUCKETS; i++) {
        ovs_mutex_init(&ct->mutex[i]);
        ovs_mutex_lock(&ct->mutex[i]);
        hmap_init(&ct->connections[i]);
        ovs_mutex_unlock(&ct->mutex[i]);
    }
    ct->hash_basis = random_uint32();
    ct->purge_bucket = 0;
    ct->purge_inner_bucket = 0;
    ct->purge_inner_offset = 0;
}

void
conntrack_destroy(struct conntrack *ct)
{
    unsigned i;

    for (i = 0; i < CONNTRACK_BUCKETS; i++) {
        struct conn *conn, *next;

        ovs_mutex_lock(&ct->mutex[i]);
        HMAP_FOR_EACH_SAFE(conn, next, node, &ct->connections[i]) {
            hmap_remove(&ct->connections[i], &conn->node);
            delete_conn(conn);
        }
        hmap_destroy(&ct->connections[i]);
        ovs_mutex_unlock(&ct->mutex[i]);
        ovs_mutex_destroy(&ct->mutex[i]);
    }
}

static void
write_ct_md(struct dp_packet *pkt, uint8_t state, uint16_t zone,
            uint32_t mark, ovs_u128 label)
{
    pkt->md.ct_state = state | OVS_CS_F_TRACKED;
    pkt->md.ct_zone = zone;
    pkt->md.ct_mark = mark;
    pkt->md.ct_label = label;
}

static struct conn *
conn_not_found(struct conntrack *ct, struct dp_packet *pkt,
               struct conn_key_lookup *key, uint8_t *state, bool commit,
               long long now)
{
    unsigned bucket = key->hash % CONNTRACK_BUCKETS;
    struct conn *nc = NULL;

    if (!valid_new(pkt, &key->key)) {
        *state |= OVS_CS_F_INVALID;
        return nc;
    }

    *state |= OVS_CS_F_NEW;

    if (commit) {
        nc = new_conn(pkt, &key->key, now);

        memcpy(&nc->rev_key, &key->key, sizeof nc->rev_key);

        conn_key_reverse(&nc->rev_key);
        hmap_insert(&ct->connections[bucket], &nc->node, key->hash);
    }

    return nc;
}

static struct conn *
process_one(struct conntrack *ct, struct dp_packet *pkt,
            struct conn_key_lookup *key, uint16_t zone,
            bool commit, long long now)
{
    unsigned bucket = key->hash % CONNTRACK_BUCKETS;
    struct conn *conn = key->conn;
    uint8_t state = 0;

    if (conn) {
        /* XXX if this has already been tracked on the same zone
         * (and with the same helper?) do not update.  It was also
         * a waste to extract the key. */

        if (key->related) {
            state |= OVS_CS_F_RELATED;
            if (key->reply) {
                state |= OVS_CS_F_REPLY_DIR;
            }
        } else {
            enum ct_update_res res;

            res = conn_update(conn, pkt, key->reply, now);

            switch (res) {
            case CT_UPDATE_VALID:
                state |= OVS_CS_F_ESTABLISHED;
                if (key->reply) {
                    state |= OVS_CS_F_REPLY_DIR;
                }
                break;
            case CT_UPDATE_INVALID:
                state |= OVS_CS_F_INVALID;
                break;
            case CT_UPDATE_NEW:
                hmap_remove(&ct->connections[bucket], &conn->node);
                delete_conn(conn);
                conn = conn_not_found(ct, pkt, key, &state, commit, now);
                break;
            }
        }

        pkt->md.ct_label = conn->label;
        pkt->md.ct_mark = conn->mark;
        write_ct_md(pkt, state, zone, conn->mark, conn->label);
    } else {
        conn = conn_not_found(ct, pkt, key, &state, commit, now);
        write_ct_md(pkt, state, zone, 0, (ovs_u128) {{0}});
    }

    return conn;
}

int
conntrack_execute(struct conntrack *ct, struct dp_packet **pkts, size_t cnt,
                  bool commit, uint16_t zone, const uint32_t *setmark,
                  const struct ovs_key_ct_label *setlabel,
                  const char *helper OVS_UNUSED)
{
#if !defined(__CHECKER__) && !defined(_WIN32)
    const size_t KEY_ARRAY_SIZE = cnt;
#else
    enum { KEY_ARRAY_SIZE = NETDEV_MAX_BURST };
#endif
    struct conn_key_lookup keys[KEY_ARRAY_SIZE];
    int8_t bucket_list[CONNTRACK_BUCKETS];
    struct {
        unsigned bucket;
        unsigned long maps;
    } arr[KEY_ARRAY_SIZE];
    long long now = time_msec();
    size_t i = 0;
    uint8_t arrcnt = 0;

    memset(bucket_list, INT8_C(-1), sizeof bucket_list);
    for (i = 0; i < cnt; i++) {
        unsigned bucket;

        if (!conn_key_extract(ct, pkts[i], &keys[i], zone)) {
            write_ct_md(pkts[i], OVS_CS_F_INVALID, zone, 0, (ovs_u128){{0}});
            continue;
        }

        bucket = keys[i].hash % CONNTRACK_BUCKETS;
        if (bucket_list[bucket] == INT8_C(-1)) {
            bucket_list[bucket] = arrcnt;

            arr[arrcnt].maps = 0;
            ULLONG_SET1(arr[arrcnt].maps, i);
            arr[arrcnt++].bucket = bucket;
        } else {
            ULLONG_SET1(arr[bucket_list[bucket]].maps, i);
            arr[bucket_list[bucket]].maps |= 1UL << i;
        }
    }

    for (i = 0; i < arrcnt; i++) {
        size_t j;

        ovs_mutex_lock(&ct->mutex[arr[i].bucket]);
        conn_keys_lookup(ct, keys, arr[i].maps, arr[i].bucket, now);

        ULLONG_FOR_EACH_1(j, arr[i].maps) {
            struct conn *conn;

            conn = process_one(ct, pkts[j], &keys[j], zone, commit, now);

            if (conn && setmark) {
                set_mark(pkts[j], conn, setmark[0], setmark[1]);
            }

            if (conn && setlabel) {
                set_label(pkts[j], conn, &setlabel[0], &setlabel[1]);
            }
        }
        ovs_mutex_unlock(&ct->mutex[arr[i].bucket]);
    }

    return 0;
}

static void
set_mark(struct dp_packet *pkt, struct conn *conn, uint32_t val, uint32_t mask)
{
    pkt->md.ct_mark = val | (pkt->md.ct_mark & ~(mask));
    conn->mark = pkt->md.ct_mark;
}

static void
set_label(struct dp_packet *pkt, struct conn *conn,
          const struct ovs_key_ct_label *val,
          const struct ovs_key_ct_label *mask)
{
    ovs_u128 v, m;

    memcpy(&v, val, sizeof v);
    memcpy(&m, mask, sizeof m);

    pkt->md.ct_label.u64.lo = v.u64.lo
                              | (pkt->md.ct_label.u64.lo & ~(m.u64.lo));
    pkt->md.ct_label.u64.hi = v.u64.hi
                              | (pkt->md.ct_label.u64.hi & ~(m.u64.hi));
    conn->label = pkt->md.ct_label;
}

#define CONNTRACK_PURGE_NUM 256

static void
sweep_bucket(struct hmap *bucket, uint32_t *inner_bucket,
             uint32_t *inner_offset, unsigned *left, long long now)
{
    while (*left != 0) {
        struct hmap_node *node;
        struct conn *conn;

        node = hmap_at_position(bucket, inner_bucket, inner_offset);

        if (!node) {
            hmap_shrink(bucket);
            break;
        }

        INIT_CONTAINER(conn, node, node);
        if (conn_expired(conn, now)) {
            hmap_remove(bucket, &conn->node);
            delete_conn(conn);
            (*left)--;
        }
    }
}

void
conntrack_run(struct conntrack *ct)
{
    unsigned bucket = ct->purge_bucket % CONNTRACK_BUCKETS;
    uint32_t inner_bucket = ct->purge_inner_bucket,
             inner_offset = ct->purge_inner_offset;
    unsigned left = CONNTRACK_PURGE_NUM;
    long long now = time_msec();

    while (bucket < CONNTRACK_BUCKETS) {
        ovs_mutex_lock(&ct->mutex[bucket]);
        sweep_bucket(&ct->connections[bucket],
                     &inner_bucket, &inner_offset,
                     &left, now);
        ovs_mutex_unlock(&ct->mutex[bucket]);

        if (left == 0) {
            break;
        } else {
            bucket++;
        }
    }

    ct->purge_bucket = bucket;
    ct->purge_inner_bucket = inner_bucket;
    ct->purge_inner_offset = inner_offset;
}

/* Key extraction */

/* The function stores a pointer to the first byte after the header in
 * '*new_data', if 'new_data' is not NULL.  If it is NULL, the caller is
 * not interested in the header's tail,  meaning that the header has
 * already been parsed (e.g. by flow_extract): we take this as a hint to
 * save a few checks. */
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

/* The function stores a pointer to the first byte after the header in
 * '*new_data', if 'new_data' is not NULL.  If it is NULL, the caller is
 * not interested in the header's tail,  meaning that the header has
 * already been parsed (e.g. by flow_extract): we take this as a hint to
 * save a few checks. */
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

/* If 'related' is not NULL and the function is processing an ICMP
 * error packet, extract the l3 and l4 fields from the nested header
 * instead and set *related to true.  If 'related' is NULL we're
 * already processing a nested header and no such recursion is
 * possible */
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
        struct conn_key inner_key;
        const char *l3 = (const char *) (icmp + 1);
        const char *tail = (const char *) data + size;
        const char *l4;
        bool ok;

        if (!related) {
            return false;
        }
        *related = true;

        memset(&inner_key, 0, sizeof inner_key);
        inner_key.dl_type = htons(ETH_TYPE_IP);
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

/* If 'related' is not NULL and the function is processing an ICMP
 * error packet, extract the l3 and l4 fields from the nested header
 * instead and set *related to true.  If 'related' is NULL we're
 * already processing a nested header and no such recursion is
 * possible */
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
        struct conn_key inner_key;
        const char *l3 = (const char *) icmp6 + 8;
        const char *tail = (const char *) data + size;
        const char *l4;
        bool ok;

        if (!related) {
            return false;
        }
        *related = true;

        memset(&inner_key, 0, sizeof inner_key);
        inner_key.dl_type = htons(ETH_TYPE_IPV6);
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

/* Extract l4 fields into 'key', which must already contain valid l3
 * members.  If 'related' is not NULL and an ICMP error packet is being
 * processed, the function will extract the key from the packet nested
 * in the ICMP paylod and set '*related' to true.  If 'related' is NULL,
 * nested parsing isn't allowed.  This is necessary to limit the
 * recursion level. */
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

static bool
conn_key_extract(struct conntrack *ct, struct dp_packet *pkt,
                 struct conn_key_lookup *key, uint16_t zone)
{
    const struct eth_header *l2 = dp_packet_l2(pkt);
    const struct ip_header *l3 = dp_packet_l3(pkt);
    const char *l4 = dp_packet_l4(pkt);
    const char *tail = dp_packet_tail(pkt);
    bool ok;

    memset(key, 0, sizeof *key);

    if (!l2 || !l3 || !l4) {
        return false;
    }

    key->key.zone = zone;

    /* XXX In this function we parse the packet (again, it has already
     * gone through miniflow_extract()) for two reasons:
     *
     * 1) To extract the l3 addresses and l4 ports.
     *    We already have the l3 and l4 headers' pointers.  Extracting
     *    the l3 addresses and the l4 ports is really cheap, since they
     *    can be found at fixed locations.
     * 2) To extract the l3 and l4 types.
     *    Extracting the l3 and l4 types (especially the l3[1]) on the
     *    other hand is quite expensive, because they're not at a
     *    fixed location.
     *
     * Here's a way to avoid (2) with the help of the datapath.
     * The datapath doesn't keep the packet's extracted flow[2], so
     * using that is not an option.  We could use the packet's matching
     * megaflow, but we have to make sure that the l3 and l4 types
     * are unwildcarded.  This means either:
     *
     * a) dpif-netdev unwildcards the l3 (and l4) types when a new flow
     *    is installed if the actions contains ct().  This is what the
     *    kernel datapath does.  It is not so straightforward, though.
     *
     * b) ofproto-dpif-xlate unwildcards the l3 (and l4) types when
     *    translating a ct() action.  This is already done in different
     *    actions and since both the userspace and the kernel datapath
     *    would benefit from it, it seems an appropriate place to do
     *    it.  We could add another netlink attribute
     *    (OVS_CT_ATTR_L3_TYPE) to enforce this semantic.
     *
     * ---
     * [1] A simple benchmark (running only the connection tracker
     *     over and over on the same packets) shows that if the
     *     l3 type is already provided we are 15% faster (running the
     *     connection tracker over a couple of DPDK devices with a
     *     stream of UDP 64-bytes packets shows that we are 4% faster).
     *
     * [2] The reasons for this are that keeping the flow increases
     *     (slightly) the cache footprint and increases computation
     *     time as we move the packet around. Most importantly the flow
     *     should be updated by the actions and this can be slow, as
     *     we use a sparse representation (miniflow).
     *
     */
    key->key.dl_type = parse_dl_type(l2, (char *) l3 - (char *) l2);
    if (key->key.dl_type == htons(ETH_TYPE_IP)) {
        ok = extract_l3_ipv4(&key->key, l3, tail - (char *) l3, NULL);
    } else if (key->key.dl_type == htons(ETH_TYPE_IPV6)) {
        ok = extract_l3_ipv6(&key->key, l3, tail - (char *) l3, NULL);
    } else {
        ok = false;
    }

    if (ok) {
        if (extract_l4(&key->key, l4, tail - l4, &key->related)) {
            key->hash = conn_key_hash(&key->key, ct->hash_basis);
            return true;
        }
    }

    return false;
}

/* Symmetric */
static uint32_t
conn_key_hash(const struct conn_key *key, uint32_t basis)
{
    uint32_t hsrc, hdst, hash;
    int i;

    hsrc = hdst = basis;

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
conn_keys_lookup(struct conntrack *ct,
                 struct conn_key_lookup *keys,
                 unsigned long maps,
                 unsigned bucket,
                 long long now)
{
    size_t i;

    ULLONG_FOR_EACH_1(i, maps) {
        struct conn *conn, *found = NULL;
        uint32_t hash = keys[i].hash;
        bool reply;

        HMAP_FOR_EACH_WITH_HASH(conn, node, hash, &ct->connections[bucket]) {
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
    }
}

static enum ct_update_res
conn_update(struct conn *conn, struct dp_packet *pkt, bool reply,
            long long now)
{
    return l4_protos[conn->key.nw_proto]->conn_update(conn, pkt, reply, now);
}

static bool
conn_expired(struct conn *conn, long long now)
{
    return now >= conn->expiration;
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
    /* XXX the above comment is not true anymore...should we free immediately?
     * */
    ovsrcu_postpone(free, conn);
}

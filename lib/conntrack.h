/*
 * Copyright (c) 2015, 2016 Nicira, Inc.
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
#include "odp-netlink.h"
#include "openvswitch/thread.h"
#include "openvswitch/types.h"


struct dp_packet;

/* Userspace connection tracker
 * ============================
 *
 * This is a connection tracking module that keeps all the state in userspace.
 *
 * Usage
 * =====
 *
 *     struct conntract ct;
 *
 * Initialization:
 *
 *     conntrack_init(&ct);
 *
 * It is necessary to periodically issue a call to
 *
 *     conntrack_run(&ct);
 *
 * to allow the module to clean up expired connections.
 *
 * To send a group of packets through the connection tracker:
 *
 *     conntrack_execute(&ct, pkts, n_pkts, ...);
 *
 * Thread-safety
 * =============
 *
 * conntrack_execute() can be called by multiple threads simultaneoulsy.
 */

struct conntrack;

void conntrack_init(struct conntrack *);
void conntrack_run(struct conntrack *);
void conntrack_destroy(struct conntrack *);

int conntrack_execute(struct conntrack *, struct dp_packet **, size_t,
                      bool commit, uint16_t zone, const uint32_t *setmark,
                      const struct ovs_key_ct_labels *setlabel,
                      const char *helper);

/* 'struct ct_lock' is a wrapper for an adaptive mutex.  It's useful to try
 * different types of locks (e.g. spinlocks) */

struct OVS_LOCKABLE ct_lock {
    struct ovs_mutex lock;
};

static inline void ct_lock_init(struct ct_lock *lock)
{
    ovs_mutex_init_adaptive(&lock->lock);
}

static inline void ct_lock_lock(struct ct_lock *lock)
    OVS_ACQUIRES(lock)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    ovs_mutex_lock(&lock->lock);
}

static inline void ct_lock_unlock(struct ct_lock *lock)
    OVS_RELEASES(lock)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    ovs_mutex_unlock(&lock->lock);
}

static inline void ct_lock_destroy(struct ct_lock *lock)
{
    ovs_mutex_destroy(&lock->lock);
}

#define CONNTRACK_BUCKETS_SHIFT 8
#define CONNTRACK_BUCKETS (1 << CONNTRACK_BUCKETS_SHIFT)

struct conntrack {
    /* Each lock guards a 'connections' bucket */
    struct ct_lock locks[CONNTRACK_BUCKETS];
    struct hmap connections[CONNTRACK_BUCKETS] OVS_GUARDED;
    uint32_t hash_basis;
    unsigned purge_bucket;
    uint32_t purge_inner_bucket;
    uint32_t purge_inner_offset;
};

#endif /* conntrack.h */

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

#include "conntrack-private.h"
#include "dp-packet.h"

enum other_state {
    OTHERS_FIRST,
    OTHERS_MULTIPLE,
    OTHERS_BIDIR,
};

struct conn_other {
    struct conn up;
    enum other_state state;
};

static const long long other_timeouts[] = {
    [OTHERS_FIRST] = 60 * 1000,
    [OTHERS_MULTIPLE] = 60 * 1000,
    [OTHERS_BIDIR] = 30 * 1000,
};

static struct conn_other *
conn_other_cast(struct conn *conn)
{
    return CONTAINER_OF(conn, struct conn_other, up);
}

static void
update_expiration(struct conn_other *conn, long long now)
{
    conn->up.expiration = now + other_timeouts[conn->state];
}

static enum ct_update_res
other_conn_update(struct conn *conn_, struct dp_packet *pkt OVS_UNUSED,
                bool reply, long long now)
{
    struct conn_other *conn = conn_other_cast(conn_);

    if (reply && conn->state != OTHERS_BIDIR) {
        conn->state = OTHERS_BIDIR;
    } else if (conn->state == OTHERS_FIRST) {
        conn->state = OTHERS_MULTIPLE;
    }

    update_expiration(conn, now);

    return CT_UPDATE_VALID;
}

static bool
other_valid_new(struct dp_packet *pkt OVS_UNUSED)
{
    return true;
}

static struct conn *
other_new_conn(struct dp_packet *pkt OVS_UNUSED, long long now)
{
    struct conn_other *conn;

    conn = xzalloc(sizeof(struct conn_other));
    conn->state = OTHERS_FIRST;

    update_expiration(conn, now);

    return &conn->up;
}

struct ct_l4_proto ct_proto_other = {
    .new_conn = other_new_conn,
    .valid_new = other_valid_new,
    .conn_update = other_conn_update,
};

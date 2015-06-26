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

#include "dp-packet.h"
#include "ovstest.h"
#include "timeval.h"

/* This is generated from a hex payload with
 * python -c 'd="50540000000a50540000000908004500001c00000000001100000a0101010a0101020001000200080000"; print("".join([ "\\x"+a+b for a,b in zip(d,d[1:])[::2]]))'
 */

static const char payload[] = "\x50\x54\x00\x00\x00\x0a\x50\x54\x00\x00\x00\x09\x08\x00\x45\x00\x00\x1c\x00\x00\x00\x00\x00\x11\x00\x00\x0a\x01\x01\x01\x0a\x01\x01\x02\x00\x01\x00\x02\x00\x08\x00\x00";

static void
test_benchmark(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    long long start;
    struct conntrack ct;
    struct dp_packet *pkt;
    unsigned int i, n_pkts;

    n_pkts = strtoul(ctx->argv[1], NULL, 0);

    pkt = dp_packet_new(sizeof payload);
    memcpy(dp_packet_data(pkt), payload, sizeof payload);
    conntrack_init(&ct);

    start = time_msec();

    for (i = 0; i < n_pkts; i++) {
        conntrack(&ct, &pkt, 1, true, 0, NULL);
    }
    printf("conntrack:  %5lld ms\n", time_msec() - start);

    dp_packet_delete(pkt);
    conntrack_destroy(&ct);
}

static const struct ovs_cmdl_command commands[] = {
    /* Connection tracker tests. */
    {"benchmark", NULL, 1, 1, test_benchmark},

    {NULL, NULL, 0, 0, NULL},
};

static void
test_conntrack_main(int argc, char *argv[])
{
    struct ovs_cmdl_context ctx = {
        .argc = argc - 1,
        .argv = argv + 1,
    };
    set_program_name(argv[0]);
    ovs_cmdl_run_command(&ctx, commands);
}

OVSTEST_REGISTER("test-conntrack", test_conntrack_main);
